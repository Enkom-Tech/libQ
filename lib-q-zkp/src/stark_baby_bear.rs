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
use lib_q_stark_fri::{
    FriParameters,
    TwoAdicFriPcs,
};
use lib_q_stark_merkle::MerkleTreeMmcs;
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
    fn path_for(
        leaf: WideDigestBb,
        depth: usize,
        idx0: usize,
    ) -> (Vec<bool>, Vec<WideDigestBb>, WideDigestBb) {
        let n = 1usize << depth;
        let mut level: Vec<WideDigestBb> =
            (0..n as u32).map(|i| if i as usize == idx0 { leaf } else { digest_from_seed(i + 100) }).collect();
        let mut idx = idx0;
        let (mut bits, mut sibs) = (Vec::new(), Vec::new());
        while level.len() > 1 {
            sibs.push(level[idx ^ 1]);
            bits.push((idx & 1) == 1);
            let mut next = Vec::with_capacity(level.len() / 2);
            let mut j = 0;
            while j < level.len() {
                next.push(compress_bb(&level[j], &level[j + 1]));
                j += 2;
            }
            level = next;
            idx /= 2;
        }
        (bits, sibs, level[0])
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
}
