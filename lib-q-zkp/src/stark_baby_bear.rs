//! BabyBear STARK prover/verifier config (Arm B, build-spec step 6) — the BabyBear analogue of
//! `stark.rs` (which uses `ConfigVal = Complex<Mersenne31>`).
//!
//! Key structural difference from Arm A: Arm A's value field `Complex<Mersenne31>` (62 bits)
//! doubles as the FRI **challenge** field. BabyBear (31 bits) is far too small for that, so the
//! challenge field is the **degree-4 extension** `BinomialExtensionField<BabyBear, 4>` (~124 bits)
//! — a soundness improvement. And because BabyBear *is* `PrimeField32` (unlike a complex field),
//! the challenger is `Shake256Challenger32<BabyBear>` directly — no `ComplexFieldChallenger` wrapper.
//!
//! FRI `log_blowup = 3` (blowup 8): the degree-7 Poseidon2 S-box gives quotient degree 6, so the
//! LDE blowup must be ≥ 8 (vs Arm A's `log_blowup = 2` for its degree-5 S-box) — the spec's
//! "degree 5 → 7 raises the FRI blowup". `num_queries = 100`, `proof_of_work_bits = 16`.
//!
//! Tier RED: a passing prove→verify roundtrip shows the construction is a WORKING STARK; it does
//! NOT establish the parameters' cryptographic soundness (obligation packet).

extern crate alloc;

use alloc::vec::Vec;

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
use lib_q_stark_field::Field;
use lib_q_stark_field::extension::BinomialExtensionField;
use lib_q_random::Kt128Rng;
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

/// STARK value (trace) field.
pub type BbVal = BabyBear;
/// FRI challenge field: the degree-4 extension (~124 bits).
pub type BbChallenge = BinomialExtensionField<BabyBear, 4>;
/// Main-trace Merkle commitment (SHAKE256, NIST-track hash).
pub type BbValMmcs = MerkleTreeMmcs<
    <BabyBear as Field>::Packing,
    u8,
    SerializingHasher<Shake256Hash>,
    CompressionFunctionFromHasher<Shake256Hash, 2, 32>,
    32,
>;
/// Challenge-field Merkle commitment.
pub type BbChallengeMmcs = ExtensionMmcs<BabyBear, BbChallenge, BbValMmcs>;
/// Two-adic FRI polynomial-commitment scheme over BabyBear.
pub type BbPcs = TwoAdicFriPcs<BabyBear, BabyBearDft, BbValMmcs, BbChallengeMmcs>;
/// Fiat–Shamir challenger (SHAKE256 over BabyBear; samples the degree-4 challenge field).
pub type BbChallenger = Shake256Challenger32<BabyBear>;
/// Transparent BabyBear STARK config.
pub type BbConfig = StarkConfig<BbPcs, BbChallenge, BbChallenger>;

/// Construct the transparent BabyBear STARK config. `log_blowup = 3` for the degree-7 S-box.
pub fn default_config_bb() -> BbConfig {
    let shake = Shake256Hash {};
    let hash = SerializingHasher::new(shake);
    let compress = CompressionFunctionFromHasher::new(shake);
    let val_mmcs = BbValMmcs::new(hash, compress);
    let challenge_mmcs = BbChallengeMmcs::new(val_mmcs.clone());
    let dft = BabyBearDft::default();
    // log_blowup = 4 (blowup 16): the membership AIR's max constraint degree is 14 — the
    // Merkle direction-select `left = running + dir·(sibling−running)` is degree 2, and feeding
    // it into the degree-7 S-box gives degree 14 (quotient degree 13 → blowup ≥ 16). A pure
    // hash AIR (leaf/nullifier, degree-1 inputs) needs only log_blowup = 3. Storing the
    // direction-selected node input in witness columns would drop the membership AIR to degree
    // 7 / log_blowup 3 — a measured optimization, noted for the measurement table.
    let fri_params = FriParameters {
        log_blowup: 4,
        log_final_poly_len: 0,
        num_queries: 100,
        proof_of_work_bits: 16,
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
/// reveals nothing about the witness trace.
pub type ZkBbValMmcs = MerkleTreeHidingMmcs<
    <BabyBear as Field>::Packing,
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
    let pcs = ZkBbPcs::new(dft, val_mmcs, fri_params, 4, Kt128Rng::from_seed_bytes(pcs_seed));
    let challenger = BbChallenger::from_hasher(Vec::new(), Shake256Hash {});
    StarkConfig::new(pcs, challenger)
}

/// Default ZK config: `log_blowup = 4` (membership max degree 14), `num_queries = 100`,
/// `proof_of_work_bits = 16`.
pub fn default_zk_config_bb(val_seed: [u8; 32], pcs_seed: [u8; 32]) -> ZkBbConfig {
    zk_config_bb(4, 100, 16, val_seed, pcs_seed)
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
        assert!(verify_membership_bb(&config, &proof, &root, &ctx, &nullifier), "honest proof verifies");

        // Tampered public nullifier must be rejected.
        let mut bad = nullifier;
        bad[0] = bad[0] + BabyBear::ONE;
        assert!(!verify_membership_bb(&config, &proof, &root, &ctx, &bad), "tampered nullifier rejected");
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
        println!("ARM_B,mode,depth,trace_w,trace_h,total_cells,prove_ms_median,verify_ms_median,proof_bytes");
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
                let (null, proof) = prove_membership_bb(&tcfg, &t, &ctx, &bits, &sibs, &root).unwrap();
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
                MEMBERSHIP_ROW_WIDTH, MEMBERSHIP_ROW_WIDTH * depth, pv[reps / 2], vv[reps / 2]
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
                let (null, proof) = prove_membership_bb_zk(&zcfg, &t, &ctx, &bits, &sibs, &root).unwrap();
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
                MEMBERSHIP_ROW_WIDTH, MEMBERSHIP_ROW_WIDTH * depth, pv[reps / 2], vv[reps / 2]
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
        use crate::membership::{
            MembershipWitness,
            prove_unlinkable_membership,
            verify_unlinkable_membership,
        };
        use crate::merkle::WidePoseidonMerkleTree;

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

        println!("ARM_A,mode,depth,trace_w,result");
        for depth in [4usize, 8] {
            let n = 1usize << depth;
            let secrets: Vec<_> = (0..n as u32).map(secret).collect();
            let leaves: Vec<_> = secrets.iter().map(membership_leaf).collect();
            let tree = WidePoseidonMerkleTree::from_leaf_digests(&leaves).expect("tree");
            let idx = n / 3;
            let (path_bits, siblings) = tree.path(idx).expect("path");
            let root = tree.root();
            let c = ctx_of(depth as u32);
            let witness = MembershipWitness { t: secrets[idx], ctx: c, path_bits, siblings };

            let t0 = Instant::now();
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                prove_unlinkable_membership(&witness)
            }));
            match res {
                Ok(Ok((null, proof))) => {
                    let prove_ms = t0.elapsed().as_secs_f64() * 1e3;
                    let bytes = proof.data.len();
                    let t1 = Instant::now();
                    let ok = verify_unlinkable_membership(&proof, &root, &c, &null).unwrap_or(false);
                    let verify_ms = t1.elapsed().as_secs_f64() * 1e3;
                    println!(
                        "ARM_A,transparent,{depth},17152,OK prove_ms={:.1} verify_ms={:.1} proof_bytes={bytes} verify_ok={ok}",
                        prove_ms, verify_ms
                    );
                }
                Ok(Err(e)) => println!("ARM_A,transparent,{depth},17152,PROVE_ERR {:?}", e),
                Err(_) => println!(
                    "ARM_A,transparent,{depth},17152,PANIC (default_config log_blowup=2 insufficient for degree-10 membership AIR)"
                ),
            }
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
}
