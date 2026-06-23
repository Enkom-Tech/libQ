//! BabyBear STARK prover/verifier config (Arm B, build-spec step 6) — the BabyBear analogue of
//! `stark.rs` (which uses `ConfigVal = Complex<Mersenne31>`).
//!
//! Key structural difference from Arm A: BabyBear (31 bits) is far too small to double as the FRI
//! challenge field, so the challenge field is the **degree-5 extension**
//! `BinomialExtensionField<BabyBear, 5>` = `GF(q^5)` (~155 bits) — chosen so the Fiat–Shamir/DEEP
//! soundness clears **128-bit post-quantum** (see `docs/membership-arm-b-soundness-params.md`). And
//! because BabyBear *is* `PrimeField32` (unlike Arm A's complex field), the challenger is
//! `Shake256Challenger32<BabyBear>` directly — no `ComplexFieldChallenger` wrapper.
//!
//! FRI `log_blowup = 4` (blowup 16, rate ρ = 1/16): the degree-7 Poseidon2 S-box gives quotient
//! degree 6 (needs blowup ≥ 8 ⇒ log_blowup ≥ 3), and blowup 16 clears 128-bit on the provable
//! list-decoding bound too. `num_queries = 96`, `proof_of_work_bits = 20`. (Arm A's membership
//! config uses log_blowup 3 for its degree-5 S-box; both bind on the SHAKE256 commitment at 128.)
//!
//! Tier RED: a passing prove→verify roundtrip shows the construction is a WORKING STARK; it does
//! NOT establish the parameters' cryptographic soundness (obligation packet).

extern crate alloc;

use alloc::vec::Vec;

use lib_q_random::Kt128Rng;
use lib_q_stark::{
    Proof as StarkProof,
    ProverError,
    StarkConfig,
    prove,
    verify,
};
use lib_q_stark_baby_bear::{
    BabyBear,
    BabyBearDft,
};
use lib_q_stark_challenger::Shake256Challenger32;
use lib_q_stark_commit::ExtensionMmcs;
use lib_q_stark_field::extension::BinomialExtensionField;
use lib_q_stark_field::{
    PrimeCharacteristicRing,
    PrimeField32,
};
use lib_q_stark_fri::{
    FriParameters,
    HidingFriPcs,
    TwoAdicFriPcs,
};
use lib_q_stark_merkle::{
    MerkleTreeHidingMmcs,
    MerkleTreeMmcs,
};
use lib_q_stark_shake256::Shake256Hash;
use lib_q_stark_symmetric::{
    CompressionFunctionFromHasher,
    SerializingHasher,
};

use crate::air::unlinkable_membership_baby_bear::{
    CTX_ELEMS,
    SECRET_T_ELEMS,
    UnlinkableMembershipBbAir,
    generate_membership_trace_bb,
    membership_nullifier_bb,
    membership_public_values_bb,
};
use crate::air::wide_merkle_path_baby_bear::WideDigestBb;
use crate::air::wide_sponge_baby_bear::WIDE_DIGEST_ELEMS;

/// STARK value (trace) field.
pub type BbVal = BabyBear;
/// FRI challenge field: the degree-**5** extension `F_{p^5}` (~155 bits). Upgraded from degree-4
/// (~124 bits) so the Fiat–Shamir/DEEP soundness clears **128-bit post-quantum** — the deg-4 field
/// capped proof soundness at ~116-bit conjectured / ~99-bit provable (see
/// `docs/membership-arm-b-soundness-params.md`).
pub type BbChallenge = BinomialExtensionField<BabyBear, 5>;
/// Main-trace Merkle commitment (SHAKE256, NIST-track hash).
///
/// The leaf type is the **scalar** `BabyBear`, not `<BabyBear as Field>::Packing`. On the default
/// (no-SIMD) build `Packing == BabyBear`, so this is identical; under `+avx2`/`+neon`, `Packing`
/// is a SIMD vector (`PackedMontyField31{AVX2,Neon}`) which is deliberately **not** a `Field`, so
/// `SerializingHasher`'s `CryptographicHasher<F: Field>` impl does not apply to it — that is the
/// architecture-dependent build break. We commit over the scalar field instead: SHAKE256 is a
/// serial sponge with **no SIMD-vectorized hashing**, so packed Merkle leaves buy nothing here
/// (packing only helps Poseidon2-style compressors, which is why Plonky3 defaults to it). The
/// Merkle commitment is independent of the leaf-packing width, so proofs are unchanged. This makes
/// the config build identically on every target architecture.
pub type BbValMmcs = MerkleTreeMmcs<
    BabyBear,
    u8,
    SerializingHasher<Shake256Hash>,
    CompressionFunctionFromHasher<Shake256Hash, 2, 32>,
    32,
>;
/// Challenge-field Merkle commitment.
pub type BbChallengeMmcs = ExtensionMmcs<BabyBear, BbChallenge, BbValMmcs>;
/// Two-adic FRI polynomial-commitment scheme over BabyBear.
pub type BbPcs = TwoAdicFriPcs<BabyBear, BabyBearDft, BbValMmcs, BbChallengeMmcs>;
/// Fiat–Shamir challenger (SHAKE256 over BabyBear; samples the degree-5 challenge field).
pub type BbChallenger = Shake256Challenger32<BabyBear>;
/// Transparent BabyBear STARK config.
pub type BbConfig = StarkConfig<BbPcs, BbChallenge, BbChallenger>;

/// Construct the transparent BabyBear STARK config — tuned for **128-bit post-quantum** soundness
/// (`log_blowup = 4`, `num_queries = 96`, `proof_of_work_bits = 20`, degree-5 challenge field).
pub fn default_config_bb() -> BbConfig {
    let shake = Shake256Hash {};
    let hash = SerializingHasher::new(shake);
    let compress = CompressionFunctionFromHasher::new(shake);
    let val_mmcs = BbValMmcs::new(hash, compress);
    let challenge_mmcs = BbChallengeMmcs::new(val_mmcs.clone());
    let dft = BabyBearDft::default();
    // 128-bit-PQ FRI parameters (see `docs/membership-arm-b-soundness-params.md`,
    // `tools/fri_soundness.py`). The membership AIR is degree 7 (x⁷ S-box, degree-7 optimized) →
    // quotient degree 6 → needs blowup ≥ 8 (log_blowup ≥ 3); we use **log_blowup = 4** (blowup 16,
    // FRI rate ρ = 1/16) so the query phase clears 128-bit even under the provable list-decoding
    // bound. **num_queries = 96** (96·4 = 384-bit conjectured query soundness; provable-Johnson
    // 192-bit) and **proof_of_work_bits = 20** (Grover-halved to 10 under quantum). Combined with
    // the degree-5 challenge field (~155 bits ⇒ FS/DEEP ~144-bit) and the SHAKE256 Merkle
    // commitment (128-bit collision), the binding soundness is ~128-bit PQ.
    let fri_params = FriParameters {
        log_blowup: 4,
        log_final_poly_len: 0,
        num_queries: 96,
        proof_of_work_bits: 20,
        mmcs: challenge_mmcs,
    };
    let pcs = BbPcs::new(dft, val_mmcs, fri_params);
    let challenger = BbChallenger::from_hasher(Vec::new(), Shake256Hash {});
    StarkConfig::new(pcs, challenger)
}

/// Prove an unlinkable-membership statement (transparent). `path_bits.len()` (the tree depth)
/// must be a power of two (it becomes the trace height). Returns the nullifier and the proof.
pub fn prove_membership_bb(
    config: &BbConfig,
    t: &[BabyBear; SECRET_T_ELEMS],
    ctx: &[BabyBear; CTX_ELEMS],
    path_bits: &[bool],
    siblings: &[WideDigestBb],
    root: &WideDigestBb,
) -> Result<(WideDigestBb, StarkProof<BbConfig>), ProverError> {
    let trace = generate_membership_trace_bb(t, ctx, path_bits, siblings);
    let nullifier = membership_nullifier_bb(t, ctx);
    let pubs = membership_public_values_bb(root, ctx, &nullifier);
    let proof = prove(config, &UnlinkableMembershipBbAir, trace, &pubs)?;
    Ok((nullifier, proof))
}

/// Verify an unlinkable-membership proof against the public `(root, ctx, nullifier)`.
pub fn verify_membership_bb(
    config: &BbConfig,
    proof: &StarkProof<BbConfig>,
    root: &WideDigestBb,
    ctx: &[BabyBear; CTX_ELEMS],
    nullifier: &WideDigestBb,
) -> bool {
    let pubs = membership_public_values_bb(root, ctx, nullifier);
    verify(config, &UnlinkableMembershipBbAir, proof, &pubs).is_ok()
}

// ============================= ZK / hiding variant ==============================

/// Hiding (ZK) main-trace Merkle commitment: salts each leaf with a `Kt128Rng` so the proof
/// reveals nothing about the witness trace. Scalar `BabyBear` leaf type — see [`BbValMmcs`] for
/// why (SHAKE256 is not SIMD-vectorized; arch-independent build).
pub type ZkBbValMmcs = MerkleTreeHidingMmcs<
    BabyBear,
    u8,
    SerializingHasher<Shake256Hash>,
    CompressionFunctionFromHasher<Shake256Hash, 2, 32>,
    Kt128Rng,
    32,
    4,
>;
/// Hiding challenge-field commitment.
pub type ZkBbChallengeMmcs = ExtensionMmcs<BabyBear, BbChallenge, ZkBbValMmcs>;
/// Hiding FRI PCS (randomized openings + blinded trace).
pub type ZkBbPcs = HidingFriPcs<BabyBear, BabyBearDft, ZkBbValMmcs, ZkBbChallengeMmcs, Kt128Rng>;
/// Zero-knowledge BabyBear STARK config.
pub type ZkBbConfig = StarkConfig<ZkBbPcs, BbChallenge, BbChallenger>;

/// Minimum ZK trace depth (rows) — the hiding randomization needs enough rows; mirrors Arm A.
pub const MIN_ZK_DEPTH: usize = 8;

/// Construct a ZK/hiding BabyBear config. `val_seed` (MMCS leaf salts) and `pcs_seed` (FRI
/// blinding) MUST be independent 32-byte CSPRNG seeds in production.
pub fn zk_config_bb(
    log_blowup: usize,
    num_queries: usize,
    proof_of_work_bits: usize,
    val_seed: [u8; 32],
    pcs_seed: [u8; 32],
) -> ZkBbConfig {
    let shake = Shake256Hash {};
    let hash = SerializingHasher::new(shake);
    let compress = CompressionFunctionFromHasher::new(shake);
    let val_mmcs = ZkBbValMmcs::new(hash, compress, Kt128Rng::from_seed_bytes(val_seed));
    let challenge_mmcs = ZkBbChallengeMmcs::new(val_mmcs.clone());
    let dft = BabyBearDft::default();
    let fri_params = FriParameters {
        log_blowup,
        log_final_poly_len: 0,
        num_queries,
        proof_of_work_bits,
        mmcs: challenge_mmcs,
    };
    let pcs = ZkBbPcs::new(
        dft,
        val_mmcs,
        fri_params,
        4,
        Kt128Rng::from_seed_bytes(pcs_seed),
    );
    let challenger = BbChallenger::from_hasher(Vec::new(), Shake256Hash {});
    StarkConfig::new(pcs, challenger)
}

/// Default ZK config — **128-bit-PQ** parameters matching [`default_config_bb`]: `log_blowup = 4`,
/// `num_queries = 96`, `proof_of_work_bits = 20` (degree-5 challenge field).
pub fn default_zk_config_bb(val_seed: [u8; 32], pcs_seed: [u8; 32]) -> ZkBbConfig {
    zk_config_bb(4, 96, 20, val_seed, pcs_seed)
}

/// Prove an unlinkable-membership statement in zero knowledge. `path_bits.len()` must be a
/// power of two and `>= MIN_ZK_DEPTH` (the trace height).
pub fn prove_membership_bb_zk(
    config: &ZkBbConfig,
    t: &[BabyBear; SECRET_T_ELEMS],
    ctx: &[BabyBear; CTX_ELEMS],
    path_bits: &[bool],
    siblings: &[WideDigestBb],
    root: &WideDigestBb,
) -> Result<(WideDigestBb, StarkProof<ZkBbConfig>), ProverError> {
    let trace = generate_membership_trace_bb(t, ctx, path_bits, siblings);
    let nullifier = membership_nullifier_bb(t, ctx);
    let pubs = membership_public_values_bb(root, ctx, &nullifier);
    let proof = prove(config, &UnlinkableMembershipBbAir, trace, &pubs)?;
    Ok((nullifier, proof))
}

/// Verify a ZK unlinkable-membership proof.
pub fn verify_membership_bb_zk(
    config: &ZkBbConfig,
    proof: &StarkProof<ZkBbConfig>,
    root: &WideDigestBb,
    ctx: &[BabyBear; CTX_ELEMS],
    nullifier: &WideDigestBb,
) -> bool {
    let pubs = membership_public_values_bb(root, ctx, nullifier);
    verify(config, &UnlinkableMembershipBbAir, proof, &pubs).is_ok()
}

// ===================== Wire / FFI statement-bytes codec (tag 0x02) =====================
//
// The Arm B public statement serializes as `root ‖ ctx ‖ N`, each BabyBear cell as its canonical
// little-endian `u32` (4 bytes). The 1-byte instantiation tag (`0x02`; Arm A = `0x01`) lives in
// the CONSUMING envelope, not here — this module exposes the statement bytes + a byte-decoding
// verify entry (the FFI surface). Decode is **canonical-checked** (rejects any limb ≥ p), so the
// 36‖16‖36-byte fields are injective — avoiding the non-canonical `from_int` hazard the ADR-113
// review flagged in Arm A's legacy single-element decoder.

/// BabyBear cell byte width (canonical LE `u32`).
pub const BB_CELL_BYTES: usize = 4;
/// A wide digest = 9 cells = 36 bytes.
pub const BB_WIDE_DIGEST_BYTES: usize = WIDE_DIGEST_ELEMS * BB_CELL_BYTES; // 36
/// `ctx` = 4 cells = 16 bytes.
pub const BB_CTX_BYTES: usize = CTX_ELEMS * BB_CELL_BYTES; // 16
/// Full public statement `root(36) ‖ ctx(16) ‖ N(36)` = 88 bytes.
pub const BB_PUBLIC_STATEMENT_BYTES: usize = 2 * BB_WIDE_DIGEST_BYTES + BB_CTX_BYTES; // 88

#[inline]
fn bb_cell_to_bytes(x: BabyBear, out: &mut Vec<u8>) {
    out.extend_from_slice(&x.as_canonical_u32().to_le_bytes());
}

/// Canonical-checked decode of one BabyBear cell from 4 LE bytes: rejects any value ≥ p
/// (`0x78000001`) so the encoding is injective (no silent modular reduction).
#[inline]
fn bb_cell_from_bytes(b: &[u8]) -> Option<BabyBear> {
    let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    // BabyBear p = 2^31 - 2^27 + 1 = 0x78000001.
    if v < 0x7800_0001 {
        Some(BabyBear::new(v))
    } else {
        None
    }
}

fn bb_decode_cells<const N: usize>(bytes: &[u8]) -> Option<[BabyBear; N]> {
    if bytes.len() < N * BB_CELL_BYTES {
        return None;
    }
    let mut out = [BabyBear::ZERO; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = bb_cell_from_bytes(&bytes[i * BB_CELL_BYTES..(i + 1) * BB_CELL_BYTES])?;
    }
    Some(out)
}

/// Serialize the Arm B public statement `root ‖ ctx ‖ N` to its 88 canonical bytes.
pub fn membership_statement_bytes_bb(
    root: &WideDigestBb,
    ctx: &[BabyBear; CTX_ELEMS],
    nullifier: &WideDigestBb,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(BB_PUBLIC_STATEMENT_BYTES);
    for &c in root.iter().chain(ctx.iter()).chain(nullifier.iter()) {
        bb_cell_to_bytes(c, &mut out);
    }
    out
}

/// Canonical-checked decode of `(root, ctx, N)` from the 88-byte statement. Returns `None` if the
/// length is wrong or any limb is ≥ p (non-canonical) — the injective-decode guarantee.
#[allow(clippy::type_complexity)]
pub fn membership_statement_from_bytes_bb(
    bytes: &[u8],
) -> Option<(WideDigestBb, [BabyBear; CTX_ELEMS], WideDigestBb)> {
    if bytes.len() != BB_PUBLIC_STATEMENT_BYTES {
        return None;
    }
    let root: WideDigestBb = bb_decode_cells::<WIDE_DIGEST_ELEMS>(&bytes[..BB_WIDE_DIGEST_BYTES])?;
    let ctx: [BabyBear; CTX_ELEMS] = bb_decode_cells::<CTX_ELEMS>(
        &bytes[BB_WIDE_DIGEST_BYTES..BB_WIDE_DIGEST_BYTES + BB_CTX_BYTES],
    )?;
    let nullifier: WideDigestBb =
        bb_decode_cells::<WIDE_DIGEST_ELEMS>(&bytes[BB_WIDE_DIGEST_BYTES + BB_CTX_BYTES..])?;
    Some((root, ctx, nullifier))
}

/// FFI-friendly verify: canonical-checked-decode the 88-byte statement and verify `proof` against
/// it. Returns `false` on any malformed/non-canonical statement (no panic across the FFI boundary).
pub fn verify_membership_bb_bytes(
    config: &BbConfig,
    proof: &StarkProof<BbConfig>,
    statement_bytes: &[u8],
) -> bool {
    match membership_statement_from_bytes_bb(statement_bytes) {
        Some((root, ctx, nullifier)) => {
            verify_membership_bb(config, proof, &root, &ctx, &nullifier)
        }
        None => false,
    }
}

// ============================ Arm B wire envelope (tag 0x02) ============================
//
// The Arm A analogue lives in `membership.rs` (`MEMBERSHIP_ENVELOPE_*`, tag 0x01). Arm B's proofs
// are bare `StarkProof<…>` (no metadata-carrying `ZkpProof` wrapper), so this envelope transports
// the `(tree_depth, digest_width, zk)` a byte-only consumer needs, with the **instantiation tag
// `0x02`** in the version byte that distinguishes Arm B from Arm A on the wire (the downgrade guard).

/// Version / instantiation-tag byte of the Arm B membership envelope (`0x02`; Arm A = `0x01`).
pub const BB_ENVELOPE_VERSION: u8 = 0x02;
/// Fixed header: `version(1) ‖ tree_depth(1) ‖ digest_width(1) ‖ flags(1) ‖ proof_len(u32 LE)`.
pub const BB_ENVELOPE_HEADER_BYTES: usize = 8;
/// `flags` bit 0: set iff the proof was produced with the hiding (zero-knowledge) PCS.
pub const BB_ENVELOPE_FLAG_ZK: u8 = 0x01;

fn encode_env_bb(body: &[u8], tree_depth: u8, zk: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(BB_ENVELOPE_HEADER_BYTES + body.len());
    out.push(BB_ENVELOPE_VERSION);
    out.push(tree_depth);
    out.push(WIDE_DIGEST_ELEMS as u8); // 9
    out.push(if zk { BB_ENVELOPE_FLAG_ZK } else { 0 });
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// Encode a **transparent** Arm B membership proof into the 0x02 wire envelope (header ‖
/// `postcard(proof)`). `tree_depth` is `path_bits.len()` (carried so the consumer can size things).
pub fn encode_membership_envelope_bb(proof: &StarkProof<BbConfig>, tree_depth: u8) -> Vec<u8> {
    let body = postcard::to_allocvec(proof).unwrap_or_default();
    encode_env_bb(&body, tree_depth, false)
}

/// Encode a **hiding (ZK)** Arm B membership proof into the 0x02 wire envelope (flag bit 0 set).
pub fn encode_membership_envelope_bb_zk(proof: &StarkProof<ZkBbConfig>, tree_depth: u8) -> Vec<u8> {
    let body = postcard::to_allocvec(proof).unwrap_or_default();
    encode_env_bb(&body, tree_depth, true)
}

/// **Byte-only FFI verify.** Verify an Arm B membership proof from frozen wire bytes alone — the
/// 88-byte public statement (`root(36) ‖ ctx(16) ‖ N(36)`, [`membership_statement_bytes_bb`]) and a
/// 0x02 envelope. Returns `true` iff the proof verifies against the canonical root in the statement.
/// **Never panics**; any malformed input (wrong tag, reserved flag, wrong digest width, length
/// mismatch, undecodable proof, non-canonical statement) → `false`. The verifier reconstructs the
/// production config; the ZK verifier needs no prover entropy (fixed dummy seeds, matching FRI
/// params). RED — underlying soundness/ZK claims pending human sign-off.
pub fn verify_membership_envelope_bb(statement_bytes: &[u8], envelope: &[u8]) -> bool {
    if envelope.len() < BB_ENVELOPE_HEADER_BYTES || envelope[0] != BB_ENVELOPE_VERSION {
        return false;
    }
    let digest_width = envelope[2];
    let flags = envelope[3];
    if flags & !BB_ENVELOPE_FLAG_ZK != 0 || digest_width as usize != WIDE_DIGEST_ELEMS {
        return false;
    }
    let mut len_b = [0u8; 4];
    len_b.copy_from_slice(&envelope[4..8]);
    let proof_len = u32::from_le_bytes(len_b) as usize;
    let Some(expected) = BB_ENVELOPE_HEADER_BYTES.checked_add(proof_len) else {
        return false;
    };
    if envelope.len() != expected {
        return false;
    }
    let body = &envelope[BB_ENVELOPE_HEADER_BYTES..];
    if flags & BB_ENVELOPE_FLAG_ZK != 0 {
        // ZK verify needs only matching FRI params, not the prover's hiding seeds.
        let cfg = default_zk_config_bb([0u8; 32], [1u8; 32]);
        match postcard::from_bytes::<StarkProof<ZkBbConfig>>(body) {
            Ok(proof) => match membership_statement_from_bytes_bb(statement_bytes) {
                Some((root, ctx, null)) => {
                    verify_membership_bb_zk(&cfg, &proof, &root, &ctx, &null)
                }
                None => false,
            },
            Err(_) => false,
        }
    } else {
        let cfg = default_config_bb();
        match postcard::from_bytes::<StarkProof<BbConfig>>(body) {
            Ok(proof) => verify_membership_bb_bytes(&cfg, &proof, statement_bytes),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use lib_q_stark_field::PrimeCharacteristicRing;

    use super::*;
    use crate::air::unlinkable_membership_baby_bear::membership_leaf_bb;
    use crate::air::wide_merkle_path_baby_bear::compress_bb;

    const P: u32 = 2_013_265_921;

    fn t_from_seed(seed: u32) -> [BabyBear; SECRET_T_ELEMS] {
        let mut x = seed.wrapping_mul(40_503).wrapping_add(11);
        core::array::from_fn(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            BabyBear::new(x % P)
        })
    }
    fn ctx_from_seed(seed: u32) -> [BabyBear; CTX_ELEMS] {
        let mut x = seed.wrapping_mul(2_246_822_519).wrapping_add(5);
        core::array::from_fn(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            BabyBear::new(x % P)
        })
    }
    fn digest_from_seed(seed: u32) -> WideDigestBb {
        let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(7);
        core::array::from_fn(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            BabyBear::new(x % P)
        })
    }
    /// Synthesize a depth-`depth` authentication path directly (no full `2^depth` tree — that
    /// would OOM at depth 32): pick arbitrary sibling digests and direction bits, hash the leaf
    /// up to a root. The membership statement only needs a consistent leaf→root path. `seed`
    /// varies the siblings/directions.
    fn path_for(
        leaf: WideDigestBb,
        depth: usize,
        seed: usize,
    ) -> (Vec<bool>, Vec<WideDigestBb>, WideDigestBb) {
        let (mut bits, mut sibs) = (Vec::new(), Vec::new());
        let mut running = leaf;
        for level in 0..depth {
            let sib = digest_from_seed((seed as u32).wrapping_mul(1009) + level as u32 + 1);
            let dir = ((seed + level) & 1) == 1;
            bits.push(dir);
            sibs.push(sib);
            let (l, r) = if dir { (sib, running) } else { (running, sib) };
            running = compress_bb(&l, &r);
        }
        (bits, sibs, running)
    }

    #[test]
    fn membership_transparent_prove_verify_roundtrip() {
        let config = default_config_bb();
        let depth = 4; // power-of-two trace height
        let t = t_from_seed(1);
        let ctx = ctx_from_seed(2);
        let leaf = membership_leaf_bb(&t);
        let (bits, sibs, root) = path_for(leaf, depth, 3);

        let (nullifier, proof) =
            prove_membership_bb(&config, &t, &ctx, &bits, &sibs, &root).expect("prove");
        assert!(
            verify_membership_bb(&config, &proof, &root, &ctx, &nullifier),
            "honest proof verifies"
        );

        // Tampered public nullifier must be rejected.
        let mut bad = nullifier;
        bad[0] = bad[0] + BabyBear::ONE;
        assert!(
            !verify_membership_bb(&config, &proof, &root, &ctx, &bad),
            "tampered nullifier rejected"
        );
    }

    /// Measurement harness for Arm B (run: `cargo test -p lib-q-zkp --release --lib
    /// stark_baby_bear::tests::measure_arm_b -- --ignored --nocapture`). Prints prove/verify
    /// wall-clock and serialized proof size at several depths, transparent + ZK.
    #[test]
    #[ignore]
    fn measure_arm_b() {
        use std::time::Instant;

        use crate::air::unlinkable_membership_baby_bear::MEMBERSHIP_ROW_WIDTH;

        let reps = 5usize;
        println!(
            "ARM_B,mode,depth,trace_w,trace_h,total_cells,prove_ms_median,verify_ms_median,proof_bytes"
        );
        let tcfg = default_config_bb();
        for depth in [4usize, 8, 16, 32] {
            let t = t_from_seed(depth as u32);
            let ctx = ctx_from_seed(depth as u32 + 1);
            let leaf = membership_leaf_bb(&t);
            let (bits, sibs, root) = path_for(leaf, depth, (1 << depth) / 3);

            let mut pv = Vec::new();
            let mut vv = Vec::new();
            let mut bytes = 0usize;
            for _ in 0..reps {
                let t0 = Instant::now();
                let (null, proof) =
                    prove_membership_bb(&tcfg, &t, &ctx, &bits, &sibs, &root).unwrap();
                pv.push(t0.elapsed().as_secs_f64() * 1e3);
                bytes = postcard::to_allocvec(&proof).unwrap().len();
                let t1 = Instant::now();
                assert!(verify_membership_bb(&tcfg, &proof, &root, &ctx, &null));
                vv.push(t1.elapsed().as_secs_f64() * 1e3);
            }
            pv.sort_by(|a, b| a.partial_cmp(b).unwrap());
            vv.sort_by(|a, b| a.partial_cmp(b).unwrap());
            println!(
                "ARM_B,transparent,{depth},{},{depth},{},{:.1},{:.1},{bytes}",
                MEMBERSHIP_ROW_WIDTH,
                MEMBERSHIP_ROW_WIDTH * depth,
                pv[reps / 2],
                vv[reps / 2]
            );
        }
        for depth in [8usize, 16, 32] {
            let zcfg = default_zk_config_bb([1u8; 32], [2u8; 32]);
            let t = t_from_seed(depth as u32 + 50);
            let ctx = ctx_from_seed(depth as u32 + 60);
            let leaf = membership_leaf_bb(&t);
            let (bits, sibs, root) = path_for(leaf, depth, (1 << depth) / 3);
            let mut pv = Vec::new();
            let mut vv = Vec::new();
            let mut bytes = 0usize;
            for _ in 0..reps {
                let t0 = Instant::now();
                let (null, proof) =
                    prove_membership_bb_zk(&zcfg, &t, &ctx, &bits, &sibs, &root).unwrap();
                pv.push(t0.elapsed().as_secs_f64() * 1e3);
                bytes = postcard::to_allocvec(&proof).unwrap().len();
                let t1 = Instant::now();
                assert!(verify_membership_bb_zk(&zcfg, &proof, &root, &ctx, &null));
                vv.push(t1.elapsed().as_secs_f64() * 1e3);
            }
            pv.sort_by(|a, b| a.partial_cmp(b).unwrap());
            vv.sort_by(|a, b| a.partial_cmp(b).unwrap());
            println!(
                "ARM_B,zk,{depth},{},{depth},{},{:.1},{:.1},{bytes}",
                MEMBERSHIP_ROW_WIDTH,
                MEMBERSHIP_ROW_WIDTH * depth,
                pv[reps / 2],
                vv[reps / 2]
            );
        }
    }

    /// Arm A measurement (run: `cargo test -p lib-q-zkp --release --lib
    /// stark_baby_bear::tests::measure_arm_a -- --ignored --nocapture`). Builds a real Arm A
    /// witness and times prove/verify; wraps prove in `catch_unwind` to surface whether Arm A's
    /// `default_config` (log_blowup 2) actually supports its degree-10 membership AIR.
    #[test]
    #[ignore]
    fn measure_arm_a() {
        use std::time::Instant;

        use lib_q_poseidon::PoseidonField;
        use lib_q_stark_field::extension::Complex;
        use lib_q_stark_mersenne31::Mersenne31;

        use crate::air::unlinkable_membership::{
            CTX_ELEMS as A_CTX,
            SECRET_T_ELEMS as A_T,
            membership_leaf,
        };
        use crate::air::wide_hash::WideDigest as AWideDigest;
        use crate::membership::{
            MembershipWitness,
            prove_unlinkable_membership,
            prove_unlinkable_membership_zk,
            verify_unlinkable_membership,
            verify_unlinkable_membership_zk,
        };
        use crate::merkle::wide_node_hash;

        let m31p = 2_147_483_647u32; // 2^31 - 1
        let fe = |x: u32| Complex::<Mersenne31>::from(Mersenne31::new(x % m31p));
        let secret = |s: u32| -> [PoseidonField; A_T] {
            let mut x = s.wrapping_add(1);
            core::array::from_fn(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                fe(x)
            })
        };
        let ctx_of = |s: u32| -> [PoseidonField; A_CTX] {
            let mut x = s.wrapping_add(99);
            core::array::from_fn(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                fe(x)
            })
        };
        let digest_of = |s: u32| -> AWideDigest {
            let mut x = s.wrapping_add(7);
            core::array::from_fn(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                fe(x)
            })
        };
        // Synthesize a depth-`depth` authentication path DIRECTLY (no `2^depth` tree — depths 16/32
        // would OOM): pick arbitrary sibling digests + direction bits and fold the leaf up to a
        // root with the same `wide_node_hash` compressor the prover/verifier use. The membership
        // AIR only ever sees (leaf, path bits, siblings → root); a synthesized path produces an
        // IDENTICAL trace shape to a tree-derived one, so timing/size are fully representative.
        // All measured depths (4,8,16,32) are powers of two ⇒ the prover applies no padding, so
        // the synthesized root below is exactly the root the verifier checks against. Mirrors the
        // Arm B harness `path_for` for an apples-to-apples comparison.
        let path_for_a = |leaf: AWideDigest,
                          depth: usize,
                          seed: u32|
         -> (Vec<bool>, Vec<AWideDigest>, AWideDigest) {
            let (mut bits, mut sibs) = (Vec::new(), Vec::new());
            let mut running = leaf;
            for level in 0..depth {
                let sib = digest_of(seed.wrapping_mul(1009).wrapping_add(level as u32 + 1));
                let dir = ((seed as usize + level) & 1) == 1;
                bits.push(dir);
                sibs.push(sib);
                running = if dir {
                    wide_node_hash(&sib, &running)
                } else {
                    wide_node_hash(&running, &sib)
                };
            }
            (bits, sibs, running)
        };

        let reps = 5usize;
        let trace_w = 17_152usize;
        let median = |mut v: Vec<f64>| -> f64 {
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            v[v.len() / 2]
        };
        println!(
            "ARM_A,mode,depth,trace_w,trace_h,total_cells,prove_ms_median,verify_ms_median,proof_bytes"
        );

        // Transparent: depths 4, 8, 16, 32.
        for depth in [4usize, 8, 16, 32] {
            let t = secret(depth as u32);
            let c = ctx_of(depth as u32);
            let leaf = membership_leaf(&t);
            let (path_bits, siblings, root) = path_for_a(leaf, depth, depth as u32 * 7 + 1);
            let witness = MembershipWitness {
                t,
                ctx: c,
                path_bits,
                siblings,
            };

            let (mut pv, mut vv) = (Vec::new(), Vec::new());
            let mut bytes = 0usize;
            let mut ok_all = true;
            for _ in 0..reps {
                let t0 = Instant::now();
                let (null, proof) =
                    prove_unlinkable_membership(&witness).expect("arm A transparent prove");
                pv.push(t0.elapsed().as_secs_f64() * 1e3);
                bytes = proof.data.len();
                let t1 = Instant::now();
                ok_all &= verify_unlinkable_membership(&proof, &root, &c, &null).unwrap_or(false);
                vv.push(t1.elapsed().as_secs_f64() * 1e3);
            }
            assert!(ok_all, "Arm A transparent depth {depth} must verify");
            println!(
                "ARM_A,transparent,{depth},{trace_w},{depth},{},{:.1},{:.1},{bytes}",
                trace_w * depth,
                median(pv),
                median(vv)
            );
        }

        // ZK (hiding): depths 8, 16, 32 (mirrors the Arm B ZK rows; MIN_ZK_DEPTH = 8).
        for depth in [8usize, 16, 32] {
            let t = secret(depth as u32 + 50);
            let c = ctx_of(depth as u32 + 60);
            let leaf = membership_leaf(&t);
            let (path_bits, siblings, root) = path_for_a(leaf, depth, depth as u32 * 13 + 5);
            let witness = MembershipWitness {
                t,
                ctx: c,
                path_bits,
                siblings,
            };

            let (mut pv, mut vv) = (Vec::new(), Vec::new());
            let mut bytes = 0usize;
            let mut ok_all = true;
            for _ in 0..reps {
                let t0 = Instant::now();
                let (null, proof) = prove_unlinkable_membership_zk(&witness, [1u8; 32], [2u8; 32])
                    .expect("arm A zk prove");
                pv.push(t0.elapsed().as_secs_f64() * 1e3);
                bytes = proof.data.len();
                let t1 = Instant::now();
                ok_all &=
                    verify_unlinkable_membership_zk(&proof, &root, &c, &null).unwrap_or(false);
                vv.push(t1.elapsed().as_secs_f64() * 1e3);
            }
            assert!(ok_all, "Arm A zk depth {depth} must verify");
            println!(
                "ARM_A,zk,{depth},{trace_w},{depth},{},{:.1},{:.1},{bytes}",
                trace_w * depth,
                median(pv),
                median(vv)
            );
        }
    }

    #[test]
    fn membership_zk_prove_verify_roundtrip() {
        let val_seed = [7u8; 32];
        let pcs_seed = [42u8; 32]; // independent of val_seed
        let config = default_zk_config_bb(val_seed, pcs_seed);
        let depth = MIN_ZK_DEPTH; // 8 = power of two, no path padding needed
        let t = t_from_seed(5);
        let ctx = ctx_from_seed(6);
        let leaf = membership_leaf_bb(&t);
        let (bits, sibs, root) = path_for(leaf, depth, 11);

        let (nullifier, proof) =
            prove_membership_bb_zk(&config, &t, &ctx, &bits, &sibs, &root).expect("zk prove");
        assert!(
            verify_membership_bb_zk(&config, &proof, &root, &ctx, &nullifier),
            "honest ZK proof verifies"
        );

        let mut bad = nullifier;
        bad[0] = bad[0] + BabyBear::ONE;
        assert!(
            !verify_membership_bb_zk(&config, &proof, &root, &ctx, &bad),
            "tampered ZK nullifier rejected"
        );
    }

    #[test]
    fn statement_bytes_roundtrip_and_canonical_decode() {
        let t = t_from_seed(77);
        let ctx = ctx_from_seed(88);
        let root = membership_leaf_bb(&t); // any 9-cell digest works for the codec test
        let null = membership_nullifier_bb(&t, &ctx);

        let bytes = membership_statement_bytes_bb(&root, &ctx, &null);
        assert_eq!(bytes.len(), BB_PUBLIC_STATEMENT_BYTES);
        assert_eq!(bytes.len(), 88);
        let (r2, c2, n2) = membership_statement_from_bytes_bb(&bytes).expect("decode");
        assert_eq!(r2, root);
        assert_eq!(c2, ctx);
        assert_eq!(n2, null);

        // Non-canonical limb (== p) is rejected (injective decode).
        let mut bad = bytes.clone();
        bad[0..4].copy_from_slice(&0x7800_0001u32.to_le_bytes());
        assert!(
            membership_statement_from_bytes_bb(&bad).is_none(),
            "limb == p rejected"
        );
        // 0xFFFFFFFF (>> p) rejected.
        let mut bad2 = bytes.clone();
        bad2[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(
            membership_statement_from_bytes_bb(&bad2).is_none(),
            "limb 0xFFFFFFFF rejected"
        );
        // Wrong length rejected.
        assert!(
            membership_statement_from_bytes_bb(&bytes[..87]).is_none(),
            "short rejected"
        );
    }

    #[test]
    fn verify_from_bytes_roundtrip_and_tamper() {
        let config = default_config_bb();
        let t = t_from_seed(21);
        let ctx = ctx_from_seed(22);
        let leaf = membership_leaf_bb(&t);
        let (bits, sibs, root) = path_for(leaf, 4, 5);
        let (null, proof) = prove_membership_bb(&config, &t, &ctx, &bits, &sibs, &root).unwrap();

        let stmt = membership_statement_bytes_bb(&root, &ctx, &null);
        assert!(
            verify_membership_bb_bytes(&config, &proof, &stmt),
            "honest statement verifies"
        );
        // Tampered statement byte → reject.
        let mut bad = stmt.clone();
        bad[0] ^= 0x01;
        assert!(
            !verify_membership_bb_bytes(&config, &proof, &bad),
            "tampered statement rejected"
        );
        // Malformed length → false, no panic across the FFI boundary.
        assert!(
            !verify_membership_bb_bytes(&config, &proof, &stmt[..50]),
            "short statement rejected"
        );
    }

    /// Arm B wire **envelope** (tag 0x02): byte-only encode → verify, plus the malformed-input
    /// rejections (wrong instantiation tag, tampered statement, length mismatch, reserved flag).
    #[test]
    fn envelope_roundtrip_and_tamper_bb() {
        let config = default_config_bb();
        let t = t_from_seed(31);
        let ctx = ctx_from_seed(32);
        let leaf = membership_leaf_bb(&t);
        let (bits, sibs, root) = path_for(leaf, 4, 5);
        let (null, proof) = prove_membership_bb(&config, &t, &ctx, &bits, &sibs, &root).unwrap();
        let stmt = membership_statement_bytes_bb(&root, &ctx, &null);

        let env = encode_membership_envelope_bb(&proof, bits.len() as u8);
        assert_eq!(env[0], BB_ENVELOPE_VERSION, "instantiation tag 0x02");
        assert_eq!(env[2] as usize, WIDE_DIGEST_ELEMS, "digest_width = 9");
        assert!(
            verify_membership_envelope_bb(&stmt, &env),
            "honest envelope verifies"
        );

        // Wrong instantiation tag (Arm A's 0x01) → reject (downgrade guard).
        let mut bad_ver = env.clone();
        bad_ver[0] = 0x01;
        assert!(
            !verify_membership_envelope_bb(&stmt, &bad_ver),
            "wrong tag rejected"
        );
        // Tampered statement → reject.
        let mut bad_stmt = stmt.clone();
        bad_stmt[0] ^= 0x01;
        assert!(
            !verify_membership_envelope_bb(&bad_stmt, &env),
            "tampered statement rejected"
        );
        // Length mismatch (truncated) → reject, no panic.
        assert!(
            !verify_membership_envelope_bb(&stmt, &env[..env.len() - 1]),
            "short envelope rejected"
        );
        // Reserved flag bit set → reject.
        let mut bad_flag = env.clone();
        bad_flag[3] = 0x02;
        assert!(
            !verify_membership_envelope_bb(&stmt, &bad_flag),
            "reserved flag rejected"
        );
    }

    // ===================== Negative-proof matrix (real prove/verify) =====================
    //
    // Cross-config (transparent ↔ ZK) confusion is prevented at COMPILE TIME, not runtime:
    // `verify_membership_bb` takes `StarkProof<BbConfig>` and `verify_membership_bb_zk` takes
    // `StarkProof<ZkBbConfig>` — distinct types, so a transparent proof cannot even be passed to
    // the ZK verifier (or vice versa). No runtime test is possible; the type system is the guard.

    /// An honest proof must be REJECTED against any wrong public input (root / ctx / each
    /// nullifier cell). The verifier binds all three; flipping any one breaks verification.
    #[test]
    fn negative_wrong_public_inputs_rejected() {
        let config = default_config_bb();
        let t = t_from_seed(31);
        let ctx = ctx_from_seed(32);
        let leaf = membership_leaf_bb(&t);
        let (bits, sibs, root) = path_for(leaf, 4, 5);
        let (null, proof) = prove_membership_bb(&config, &t, &ctx, &bits, &sibs, &root).unwrap();
        assert!(
            verify_membership_bb(&config, &proof, &root, &ctx, &null),
            "honest verifies"
        );

        let wrong_root = digest_from_seed(987_654);
        assert!(
            !verify_membership_bb(&config, &proof, &wrong_root, &ctx, &null),
            "wrong root rejected"
        );
        let wrong_ctx = ctx_from_seed(123_456);
        assert!(
            !verify_membership_bb(&config, &proof, &root, &wrong_ctx, &null),
            "wrong ctx rejected"
        );
        for i in 0..WIDE_DIGEST_ELEMS {
            let mut bad = null;
            bad[i] = bad[i] + BabyBear::ONE;
            assert!(
                !verify_membership_bb(&config, &proof, &root, &ctx, &bad),
                "wrong nullifier cell {i} rejected"
            );
        }
    }

    /// Cross-instance: a proof for witness A must not verify against witness B's statement
    /// (transparent API and the FFI bytes API).
    #[test]
    fn negative_cross_instance_rejected() {
        let config = default_config_bb();
        let (ta, ca) = (t_from_seed(1), ctx_from_seed(1));
        let (tb, cb) = (t_from_seed(2), ctx_from_seed(2));
        let (ba, sa, ra) = path_for(membership_leaf_bb(&ta), 4, 3);
        let (bb_, sb, rb) = path_for(membership_leaf_bb(&tb), 4, 9);
        let (na, pa) = prove_membership_bb(&config, &ta, &ca, &ba, &sa, &ra).unwrap();
        let (nb, _pb) = prove_membership_bb(&config, &tb, &cb, &bb_, &sb, &rb).unwrap();

        assert!(
            verify_membership_bb(&config, &pa, &ra, &ca, &na),
            "A honest verifies"
        );
        assert!(
            !verify_membership_bb(&config, &pa, &rb, &cb, &nb),
            "A proof under B's full statement rejected"
        );
        assert!(
            !verify_membership_bb(&config, &pa, &ra, &ca, &nb),
            "A proof with B's nullifier rejected"
        );
        // FFI bytes path, cross-instance.
        let stmt_b = membership_statement_bytes_bb(&rb, &cb, &nb);
        assert!(
            !verify_membership_bb_bytes(&config, &pa, &stmt_b),
            "A proof vs B statement bytes rejected"
        );
    }

    /// Soundness-adjacent: a root INCONSISTENT with the authentication path is unprovable —
    /// the prover either errors/panics, or yields a proof that fails to verify. Never a false
    /// accept. (The membership AIR's boundary constraint pins the folded path output to the
    /// public root.)
    #[test]
    fn negative_forged_root_unprovable() {
        let config = default_config_bb();
        let t = t_from_seed(7);
        let ctx = ctx_from_seed(8);
        let leaf = membership_leaf_bb(&t);
        let (bits, sibs, _real_root) = path_for(leaf, 4, 5);
        let forged_root = digest_from_seed(424_242); // not the path's actual root
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_membership_bb(&config, &t, &ctx, &bits, &sibs, &forged_root)
        }));
        if let Ok(Ok((null, proof))) = res {
            assert!(
                !verify_membership_bb(&config, &proof, &forged_root, &ctx, &null),
                "forged-root proof must not verify"
            );
        }
        // Err(_) (prover panicked) or Ok(Err(_)) (prover refused) ⇒ also unprovable: pass.
    }

    /// Flipping a single byte of the serialized proof must cause rejection (or a clean decode
    /// failure) — never a false accept.
    #[test]
    fn negative_tampered_proof_bytes_rejected() {
        let config = default_config_bb();
        let t = t_from_seed(11);
        let ctx = ctx_from_seed(12);
        let leaf = membership_leaf_bb(&t);
        let (bits, sibs, root) = path_for(leaf, 4, 5);
        let (null, proof) = prove_membership_bb(&config, &t, &ctx, &bits, &sibs, &root).unwrap();
        let bytes = postcard::to_allocvec(&proof).unwrap();
        let mut tampered = bytes.clone();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0x01;
        match postcard::from_bytes::<StarkProof<BbConfig>>(&tampered) {
            Ok(p2) => assert!(
                !verify_membership_bb(&config, &p2, &root, &ctx, &null),
                "tampered-byte proof rejected"
            ),
            Err(_) => { /* decode failure is also a rejection */ }
        }
    }

    /// ZK variant: wrong root / wrong ctx rejected (mirrors the transparent matrix).
    #[test]
    fn negative_zk_wrong_public_inputs_rejected() {
        let config = default_zk_config_bb([3u8; 32], [9u8; 32]);
        let t = t_from_seed(15);
        let ctx = ctx_from_seed(16);
        let leaf = membership_leaf_bb(&t);
        let (bits, sibs, root) = path_for(leaf, MIN_ZK_DEPTH, 7);
        let (null, proof) = prove_membership_bb_zk(&config, &t, &ctx, &bits, &sibs, &root).unwrap();
        assert!(
            verify_membership_bb_zk(&config, &proof, &root, &ctx, &null),
            "honest ZK verifies"
        );
        let wrong_root = digest_from_seed(321);
        assert!(
            !verify_membership_bb_zk(&config, &proof, &wrong_root, &ctx, &null),
            "ZK wrong root rejected"
        );
        let wrong_ctx = ctx_from_seed(999);
        assert!(
            !verify_membership_bb_zk(&config, &proof, &root, &wrong_ctx, &null),
            "ZK wrong ctx rejected"
        );
    }

    /// Determinism: the transparent prover is a pure function of the witness (deterministic
    /// Shake256 Fiat-Shamir challenger, non-hiding PCS) — identical inputs ⇒ byte-identical proof.
    #[test]
    fn transparent_proof_is_deterministic() {
        let config = default_config_bb();
        let t = t_from_seed(55);
        let ctx = ctx_from_seed(66);
        let leaf = membership_leaf_bb(&t);
        let (bits, sibs, root) = path_for(leaf, 4, 5);
        let (n1, p1) = prove_membership_bb(&config, &t, &ctx, &bits, &sibs, &root).unwrap();
        let (n2, p2) = prove_membership_bb(&config, &t, &ctx, &bits, &sibs, &root).unwrap();
        assert_eq!(n1, n2, "nullifier is deterministic");
        assert_eq!(
            postcard::to_allocvec(&p1).unwrap(),
            postcard::to_allocvec(&p2).unwrap(),
            "transparent proof bytes are deterministic"
        );
    }

    /// The ZK prover is reproducible GIVEN its blinding seeds, but two DIFFERENT seed pairs yield
    /// different proofs — i.e. the hiding randomness actually varies the proof (it is not a no-op),
    /// and either proof still verifies (the verifier needs no prover seed).
    #[test]
    fn zk_proof_reproducible_in_seeds_but_varies_across_seeds() {
        let t = t_from_seed(70);
        let ctx = ctx_from_seed(71);
        let leaf = membership_leaf_bb(&t);
        let (bits, sibs, root) = path_for(leaf, MIN_ZK_DEPTH, 9);

        let cfg_a1 = default_zk_config_bb([1u8; 32], [2u8; 32]);
        let cfg_a2 = default_zk_config_bb([1u8; 32], [2u8; 32]); // identical seeds
        let cfg_b = default_zk_config_bb([9u8; 32], [8u8; 32]); // different seeds

        let (_, pa1) = prove_membership_bb_zk(&cfg_a1, &t, &ctx, &bits, &sibs, &root).unwrap();
        let (_, pa2) = prove_membership_bb_zk(&cfg_a2, &t, &ctx, &bits, &sibs, &root).unwrap();
        let (_, pb) = prove_membership_bb_zk(&cfg_b, &t, &ctx, &bits, &sibs, &root).unwrap();
        let ba1 = postcard::to_allocvec(&pa1).unwrap();
        let ba2 = postcard::to_allocvec(&pa2).unwrap();
        let bb = postcard::to_allocvec(&pb).unwrap();
        assert_eq!(
            ba1, ba2,
            "ZK proof reproducible for identical blinding seeds"
        );
        assert_ne!(
            ba1, bb,
            "ZK proof varies across blinding seeds (hiding randomness is active)"
        );

        let null = membership_nullifier_bb(&t, &ctx);
        let vcfg = default_zk_config_bb([1u8; 32], [2u8; 32]);
        assert!(
            verify_membership_bb_zk(&vcfg, &pa1, &root, &ctx, &null),
            "seed-A proof verifies"
        );
        assert!(
            verify_membership_bb_zk(&vcfg, &pb, &root, &ctx, &null),
            "seed-B proof verifies"
        );
    }
}
