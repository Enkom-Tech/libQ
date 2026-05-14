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
use crate::util::{
    module_add,
    module_infinity_norm,
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
    let mut witness_cache = Vec::with_capacity(openings.len());
    let mut masks = Vec::with_capacity(openings.len());
    let mut w_list = Vec::with_capacity(openings.len());
    for (opening_i, commitment_i) in openings.iter().zip(commitments.iter()) {
        if opening_i.message.0.len() != p.module_rank ||
            opening_i.randomness.0.len() != p.randomness_dimension ||
            commitment_i.value.0.len() != p.module_rank
        {
            return Err(ProofError::InvalidParameters);
        }
        let witness_i = opening::witness_vec(opening_i);
        let expected_com = matrix.mul_vec(&ModuleVec(witness_i.clone()));
        if expected_com.0.len() != commitment_i.value.0.len() ||
            !bool::from(polys_ct_eq(&expected_com.0, &commitment_i.value.0))
        {
            return Err(ProofError::InvalidParameters);
        }

        let y_i: Vec<Poly> = (0..p.witness_len())
            .map(|_| opening::sample_uniform_poly(rng))
            .collect();
        let w_i = matrix.mul_vec(&ModuleVec(y_i.clone()));
        state.absorb_attribute(
            &write_module_vec(&w_i.0),
            &write_module_vec(&commitment_i.value.0),
        );

        witness_cache.push(witness_i);
        masks.push(y_i);
        w_list.push(w_i);
    }

    let challenge_seed = state.challenge_seed();
    let c = lib_q_ring::sample_in_ball(&challenge_seed, tau);
    let r_scalars = derive_scalars_from_transcript(&state.buf, openings.len());

    let mut agg_z_polys: Vec<Poly> = (0..p.witness_len()).map(|_| Poly::zero()).collect();
    let mut agg_w_polys: Vec<Poly> = (0..p.module_rank).map(|_| Poly::zero()).collect();
    for ((y_i, wit_i), (&ri, w_i)) in masks
        .iter()
        .zip(witness_cache.iter())
        .zip(r_scalars.iter().zip(w_list.iter()))
    {
        for ((acc_z, y_poly), wit_poly) in agg_z_polys.iter_mut().zip(y_i.iter()).zip(wit_i.iter())
        {
            let mut z_i = y_poly.clone();
            z_i.add_assign(&crate::util::ring_mul(&c, wit_poly));
            let scaled = scalar_mul_poly(ri, &z_i);
            add_assign_poly(acc_z, &scaled);
        }
        for (acc_w, w_poly) in agg_w_polys.iter_mut().zip(w_i.0.iter()) {
            let scaled = scalar_mul_poly(ri, w_poly);
            add_assign_poly(acc_w, &scaled);
        }
    }

    let agg_z = ModuleVec(agg_z_polys);
    if module_infinity_norm(&agg_z.0) > z_inf_bound {
        return Err(ProofError::RejectionLimit);
    }

    Ok(AmortisedProof {
        transcript: state.buf.into_boxed_slice(),
        r_scalars,
        agg_z,
        agg_w: ModuleVec(agg_w_polys),
    })
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
    let q = FIELD_MODULUS as i64;
    debug_assert!(r > 0 && (r as i64) < q);
    let rr = (r % FIELD_MODULUS as u32) as i64;
    let mut out = p.clone();
    for c in &mut out.coeffs {
        let v = ((*c as i64 * rr) % q + q) % q;
        *c = v as i32;
    }
    out
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
    if module_infinity_norm(&proof.agg_z.0) > z_inf_bound {
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

    let mut h = Shake256::default();
    Update::update(&mut h, &proof.transcript);
    let mut reader = ExtendableOutput::finalize_xof(h);
    let mut challenge_seed = [0u8; 32];
    XofReader::read(&mut reader, &mut challenge_seed);
    let c = lib_q_ring::sample_in_ball(&challenge_seed, tau);

    let matrix = ModuleMatrix::expand_from_seed(&key.seed, p.module_rank, p.witness_len());
    let lhs = matrix.mul_vec(&proof.agg_z);
    let rhs = module_add(
        &proof.agg_w.0,
        &module_ring_mul_challenge(&c, &weighted_com),
    )?;
    if lhs.0.len() != rhs.len() || !bool::from(polys_ct_eq(&lhs.0, &rhs)) {
        return Err(VerifyError::Rejected);
    }
    Ok(())
}
