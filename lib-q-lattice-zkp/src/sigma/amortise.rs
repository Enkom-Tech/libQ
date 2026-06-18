//! BLNS-style batching: single challenge over a transcript of per-attribute masks.

use alloc::boxed::Box;
use alloc::vec::Vec;

use lib_q_ring::constants::FIELD_MODULUS;
use lib_q_ring::{
    ModuleMatrix,
    ModuleVec,
    Poly,
    try_uniform_coeff_mod_q_from_u32,
};
use lib_q_sha3::{
    ExtendableOutput,
    Shake256,
    Update,
    XofReader,
};
use rand_core::{
    CryptoRng,
    Rng,
};
use zeroize::Zeroize;

use crate::commitment::{
    AjtaiCommitment,
    AjtaiCommitmentKey,
    AjtaiOpening,
};
use crate::error::{
    ProofError,
    VerifyError,
};
use crate::serialize::write_module_vec;
use crate::sigma::opening;
use crate::sigma::opening::OpeningProof;
#[cfg(feature = "hardened")]
use crate::sigma::secrets::{
    MaskedWitness,
    zeroize_poly_vec,
};
use crate::sigma::secrets::{
    ProverMaskScratch,
    SecretMaskVec,
    SecretWitnessVec,
};
use crate::util::{
    canonicalize_polys_mod_q,
    module_add,
    module_norm_within_bound,
    module_ring_mul_challenge,
    polys_ct_eq,
};

/// Accumulates `(w_i, com_i)` data for a batched presentation.
#[derive(Clone, Debug)]
pub struct BatchPresentationState {
    pub(crate) buf: Vec<u8>,
    pub(crate) attributes: usize,
}

impl BatchPresentationState {
    /// Domain separation label.
    #[must_use]
    pub fn new(label: &[u8]) -> Self {
        let mut buf = Vec::new();
        buf.extend_from_slice(label);
        Self { buf, attributes: 0 }
    }

    /// Absorb serialized mask `w_i` and commitment `com_i`.
    pub fn absorb_attribute(&mut self, w_bytes: &[u8], com_bytes: &[u8]) {
        self.buf
            .extend_from_slice(&(w_bytes.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(w_bytes);
        self.buf
            .extend_from_slice(&(com_bytes.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(com_bytes);
        self.attributes = self.attributes.saturating_add(1);
    }

    /// Final XOF seed for the batch challenge.
    #[must_use]
    pub fn challenge_seed(&self) -> [u8; 32] {
        let mut h = lib_q_sha3::Shake256::default();
        lib_q_sha3::Update::update(&mut h, &self.buf);
        let mut reader = lib_q_sha3::ExtendableOutput::finalize_xof(h);
        let mut s = [0u8; 32];
        lib_q_sha3::XofReader::read(&mut reader, &mut s);
        s
    }
}

/// Aggregated proof bundle (single verification equation).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmortisedProof {
    /// Full batch transcript bytes.
    pub transcript: Box<[u8]>,
    /// Per-attribute XOF-derived scalars, uniform in `{1, …, q − 1}` (no `u32 % q` bias).
    pub r_scalars: Vec<u32>,
    /// `Σ_i r_i · z_i` (coefficient-wise, per witness slot).
    pub agg_z: ModuleVec,
    /// `Σ_i r_i · w_i` (same shape as `w_i` — `k` polynomials).
    pub agg_w: ModuleVec,
}

/// Construct a BLNS-style aggregated opening proof with a single batch challenge.
#[allow(clippy::too_many_arguments)]
pub fn amortise<R: Rng + CryptoRng>(
    rng: &mut R,
    key: &AjtaiCommitmentKey,
    openings: &[AjtaiOpening],
    commitments: &[AjtaiCommitment],
    label: &[u8],
    tau: usize,
    z_inf_bound: i32,
) -> Result<AmortisedProof, ProofError> {
    let p = &key.params;
    if openings.len() != commitments.len() {
        return Err(ProofError::InvalidParameters);
    }
    let matrix = ModuleMatrix::expand_from_seed(&key.seed, p.module_rank, p.witness_len());

    let mut state = BatchPresentationState::new(label);
    let mut scratch = ProverMaskScratch::new();
    let mut w_list = Vec::with_capacity(openings.len());
    for (opening_i, commitment_i) in openings.iter().zip(commitments.iter()) {
        if opening_i.message.0.len() != p.module_rank ||
            opening_i.randomness.0.len() != p.randomness_dimension ||
            commitment_i.value.0.len() != p.module_rank
        {
            return Err(ProofError::InvalidParameters);
        }
        let witness_i = opening::witness_vec(opening_i);
        let expected_com = matrix.mul_vec_polys(&witness_i);
        if expected_com.0.len() != commitment_i.value.0.len() ||
            !bool::from(polys_ct_eq(&expected_com.0, &commitment_i.value.0))
        {
            return Err(ProofError::InvalidParameters);
        }

        let y_i = SecretMaskVec::new(
            (0..p.witness_len())
                .map(|_| opening::sample_uniform_poly(rng))
                .collect(),
        );
        let w_i = matrix.mul_vec_polys(y_i.as_slice());
        state.absorb_attribute(
            &write_module_vec(&w_i.0),
            &write_module_vec(&commitment_i.value.0),
        );

        #[cfg(not(feature = "hardened"))]
        scratch.push_attribute(y_i, SecretWitnessVec::new(witness_i));
        #[cfg(feature = "hardened")]
        scratch.push_attribute_masked(
            y_i,
            MaskedWitness::split(SecretWitnessVec::new(witness_i), rng, &key.seed, label),
        );
        w_list.push(w_i);
    }

    let r_scalars = derive_scalars_from_transcript(&state.buf, openings.len());

    // Compute `agg_w = Σ rᵢ·wᵢ` first so it can be bound into the challenge `c`. This is
    // independent of `c`; only `agg_z` below depends on `c`.
    let mut agg_w_polys: Vec<Poly> = (0..p.module_rank).map(|_| Poly::zero()).collect();
    for i in 0..scratch.len() {
        let ri = r_scalars[i];
        let w_i = &w_list[i];
        for (acc_w, w_poly) in agg_w_polys.iter_mut().zip(w_i.0.iter()) {
            let scaled = scalar_mul_poly(ri, w_poly);
            add_assign_poly(acc_w, &scaled);
        }
    }
    canonicalize_polys_mod_q(&mut agg_w_polys);

    // Bind `agg_w` into the batch challenge (matches `verify_aggregate`).
    let c = batch_challenge_bound(&state.buf, &agg_w_polys, tau);

    let mut agg_z_polys: Vec<Poly> = (0..p.witness_len()).map(|_| Poly::zero()).collect();
    // `i` indexes the parallel `scratch` accessors (mask/witness/masked_witness) as well as
    // `r_scalars`, so a range loop keeps the per-instance lookups aligned.
    #[allow(clippy::needless_range_loop)]
    for i in 0..scratch.len() {
        let y_i = scratch.mask(i);
        let ri = r_scalars[i];
        #[cfg(not(feature = "hardened"))]
        let wit_i = scratch.witness(i);
        #[cfg(feature = "hardened")]
        let mut cw_i = scratch.masked_witness(i).ring_mul_challenge(&c);
        for (slot, (acc_z, y_poly)) in agg_z_polys.iter_mut().zip(y_i.iter()).enumerate() {
            let mut z_i = y_poly.clone();
            #[cfg(not(feature = "hardened"))]
            z_i.add_assign(&crate::util::ring_mul(&c, &wit_i[slot]));
            #[cfg(feature = "hardened")]
            z_i.add_assign(&cw_i[slot]);
            let scaled = scalar_mul_poly(ri, &z_i);
            add_assign_poly(acc_z, &scaled);
            z_i.zeroize();
        }
        #[cfg(feature = "hardened")]
        zeroize_poly_vec(&mut cw_i);
    }

    canonicalize_polys_mod_q(&mut agg_z_polys);

    let agg_z = ModuleVec(agg_z_polys);
    if !bool::from(module_norm_within_bound(&agg_z.0, z_inf_bound)) {
        return Err(ProofError::RejectionLimit);
    }

    Ok(AmortisedProof {
        transcript: state.buf.into_boxed_slice(),
        r_scalars,
        agg_z,
        agg_w: ModuleVec(agg_w_polys),
    })
}

/// Domain separator binding `agg_w` into the batch Fiat–Shamir challenge.
const AGG_W_FS_DOMAIN: &[u8] = b"lattice-zkp/amortise/agg-w/v0";

/// Derive the batch challenge `c`, binding the aggregated commitment `agg_w` into the seed.
///
/// Soundness fix: previously `c = sample_in_ball(H(transcript))` and `agg_w` was supplied
/// by the prover but never checked, so a malicious prover could substitute any `agg_w`.
/// Binding `agg_w` into the challenge (`c = sample_in_ball(H(transcript ‖ agg_w))`) means a
/// forged `agg_w` changes `c`, which then fails the verification equation
/// `A·agg_z = agg_w + c·Σ rᵢ·comᵢ`. The canonical [`write_module_vec`] encoding of `agg_w`
/// is absorbed identically on the prover and verifier sides.
fn batch_challenge_bound(transcript: &[u8], agg_w: &[Poly], tau: usize) -> Poly {
    let mut h = Shake256::default();
    Update::update(&mut h, transcript);
    Update::update(&mut h, AGG_W_FS_DOMAIN);
    Update::update(&mut h, &write_module_vec(agg_w));
    let mut reader = ExtendableOutput::finalize_xof(h);
    let mut challenge_seed = [0u8; 32];
    XofReader::read(&mut reader, &mut challenge_seed);
    lib_q_ring::sample_in_ball(&challenge_seed, tau)
}

fn derive_scalars_from_transcript(transcript: &[u8], count: usize) -> Vec<u32> {
    let mut h = Shake256::default();
    Update::update(&mut h, transcript);
    let mut seed_reader = ExtendableOutput::finalize_xof(h);
    let mut seed = [0u8; 32];
    XofReader::read(&mut seed_reader, &mut seed);

    let mut hx = Shake256::default();
    Update::update(&mut hx, &seed);
    Update::update(&mut hx, &(count as u64).to_le_bytes());
    let mut reader = ExtendableOutput::finalize_xof(hx);
    let q = FIELD_MODULUS as u32;
    let mut r_scalars = Vec::with_capacity(count);
    for _ in 0..count {
        let ri = loop {
            let mut rb = [0u8; 4];
            XofReader::read(&mut reader, &mut rb);
            let word = u32::from_le_bytes(rb);
            if let Some(c) = try_uniform_coeff_mod_q_from_u32(q, word) &&
                c != 0
            {
                break c as u32;
            }
        };
        r_scalars.push(ri);
    }
    r_scalars
}

fn scalar_mul_poly(r: u32, p: &Poly) -> Poly {
    debug_assert!(r > 0 && (r as i64) < FIELD_MODULUS as i64);
    p.scalar_mul_by_u32_mod_q(r)
}

fn add_assign_poly(a: &mut Poly, b: &Poly) {
    a.add_assign(b);
}

/// Combine individual opening proofs using scalars derived from the batch transcript (XOF).
#[must_use]
pub fn aggregate_proofs(
    state: &BatchPresentationState,
    proofs: &[OpeningProof],
    witness_len: usize,
    k: usize,
) -> AmortisedProof {
    assert_eq!(
        state.attributes,
        proofs.len(),
        "attribute/proof count mismatch"
    );
    let r_scalars = derive_scalars_from_transcript(&state.buf, proofs.len());

    let mut agg_z_polys: Vec<Poly> = (0..witness_len).map(|_| Poly::zero()).collect();
    let mut agg_w_polys: Vec<Poly> = (0..k).map(|_| Poly::zero()).collect();

    for (proof, &ri) in proofs.iter().zip(r_scalars.iter()) {
        assert_eq!(proof.z.0.len(), witness_len, "witness length mismatch");
        assert_eq!(proof.w.0.len(), k, "module-rank length mismatch");
        for (acc, z) in agg_z_polys.iter_mut().zip(proof.z.0.iter()) {
            let scaled = scalar_mul_poly(ri, z);
            add_assign_poly(acc, &scaled);
        }
        for (acc, w) in agg_w_polys.iter_mut().zip(proof.w.0.iter()) {
            let scaled = scalar_mul_poly(ri, w);
            add_assign_poly(acc, &scaled);
        }
    }

    AmortisedProof {
        transcript: state.buf.clone().into_boxed_slice(),
        r_scalars,
        agg_z: ModuleVec(agg_z_polys),
        agg_w: ModuleVec(agg_w_polys),
    }
}

/// Verify a batched aggregation equation:
/// `A*agg_z = agg_w + c * Σ_i(r_i * com_i)` with a single challenge `c`.
pub fn verify_aggregate(
    key: &AjtaiCommitmentKey,
    commitments: &[AjtaiCommitment],
    proof: &AmortisedProof,
    tau: usize,
    z_inf_bound: i32,
) -> Result<(), VerifyError> {
    let p = &key.params;
    if proof.agg_w.0.len() != p.module_rank ||
        proof.agg_z.0.len() != p.witness_len() ||
        commitments.len() != proof.r_scalars.len()
    {
        return Err(VerifyError::InvalidFormat);
    }
    if !bool::from(module_norm_within_bound(&proof.agg_z.0, z_inf_bound)) {
        return Err(VerifyError::Rejected);
    }

    let expected_scalars = derive_scalars_from_transcript(&proof.transcript, commitments.len());
    if expected_scalars != proof.r_scalars {
        return Err(VerifyError::Rejected);
    }

    let mut weighted_com = alloc::vec![Poly::zero(); p.module_rank];
    for (com, &r) in commitments.iter().zip(proof.r_scalars.iter()) {
        if com.value.0.len() != p.module_rank {
            return Err(VerifyError::InvalidFormat);
        }
        for (acc, cpoly) in weighted_com.iter_mut().zip(com.value.0.iter()) {
            let scaled = scalar_mul_poly(r, cpoly);
            add_assign_poly(acc, &scaled);
        }
    }

    // Bind `agg_w` into the challenge so a forged `agg_w` changes `c` and fails the equation.
    // Canonicalize `agg_w` identically to the prover before absorbing it into the seed.
    let mut agg_w_canon = proof.agg_w.0.clone();
    canonicalize_polys_mod_q(&mut agg_w_canon);
    let c = batch_challenge_bound(&proof.transcript, &agg_w_canon, tau);

    let matrix = ModuleMatrix::expand_from_seed(&key.seed, p.module_rank, p.witness_len());
    let lhs = matrix.mul_vec(&proof.agg_z);
    let rhs = module_add(
        &proof.agg_w.0,
        &module_ring_mul_challenge(&c, &weighted_com),
    )?;
    let mut lhs_canon = lhs.0.clone();
    let mut rhs_canon = rhs.clone();
    canonicalize_polys_mod_q(&mut lhs_canon);
    canonicalize_polys_mod_q(&mut rhs_canon);
    if lhs.0.len() != rhs.len() || !bool::from(polys_ct_eq(&lhs_canon, &rhs_canon)) {
        return Err(VerifyError::Rejected);
    }
    Ok(())
}

#[cfg(all(test, feature = "hardened"))]
mod hardened_tests {
    use lib_q_random::new_deterministic_rng;

    use super::*;
    use crate::commitment::{
        AjtaiCommitmentKey,
        AjtaiOpening,
        commit,
    };
    use crate::sigma::opening;
    use crate::sigma::secrets::{
        MaskedWitness,
        SecretWitnessVec,
    };
    use crate::util::ring_mul;

    fn test_seed32(tag: u64) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&tag.to_le_bytes());
        s
    }

    #[test]
    fn masked_cw_matches_direct_for_amortise_fixture() {
        let params = crate::params::AjtaiParameters::new(2, 1);
        let key = AjtaiCommitmentKey {
            seed: [21u8; 32],
            params,
        };

        let mut m1 = alloc::vec![Poly::zero(), Poly::zero()];
        m1[0].coeffs[0] = 2;
        let mut r1 = alloc::vec![Poly::zero()];
        r1[0].coeffs[0] = 9;
        let o1 = AjtaiOpening {
            message: ModuleVec(m1),
            randomness: ModuleVec(r1),
        };

        let mut m2 = alloc::vec![Poly::zero(), Poly::zero()];
        m2[1].coeffs[0] = 3;
        let mut r2 = alloc::vec![Poly::zero()];
        r2[0].coeffs[0] = 7;
        let o2 = AjtaiOpening {
            message: ModuleVec(m2),
            randomness: ModuleVec(r2),
        };

        let c1 = commit(&key, &o1);
        let c2 = commit(&key, &o2);
        let commitments = alloc::vec![c1, c2];
        let openings = alloc::vec![o1, o2];

        let mut rng = new_deterministic_rng(test_seed32(0xA5515EED));
        let proof = amortise(
            &mut rng,
            &key,
            &openings,
            &commitments,
            b"batch-ctx",
            39,
            100_000_000,
        )
        .expect("amortise");

        // Challenge is bound to `agg_w` (soundness fix); recompute it the same way.
        let mut agg_w_canon = proof.agg_w.0.clone();
        canonicalize_polys_mod_q(&mut agg_w_canon);
        let c = batch_challenge_bound(&proof.transcript, &agg_w_canon, 39);

        let mut rng2 = new_deterministic_rng(test_seed32(0xA5515EED));
        for opening_i in &openings {
            for _ in 0..key.params.witness_len() {
                let _ = opening::sample_uniform_poly(&mut rng2);
            }
            let witness_i = opening::witness_vec(opening_i);
            let masked = MaskedWitness::split(
                SecretWitnessVec::new(witness_i.clone()),
                &mut rng2,
                &key.seed,
                b"batch-ctx",
            );
            let masked_cw = masked.ring_mul_challenge(&c);
            for (slot, w) in witness_i.iter().enumerate() {
                let direct = ring_mul(&c, w);
                assert_eq!(direct, masked_cw[slot], "slot {slot}");
            }
        }
    }
}
