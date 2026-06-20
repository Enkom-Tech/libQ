//! Dealerless DKG via a **binding** lattice VSS over BDLOP commitments.
//!
//! Each party acts as a dealer running a verifiable secret sharing of a fresh contribution: it
//! samples a degree-`t-1` polynomial over `R_q`, publishes BDLOP commitments to its coefficients
//! (message-in-the-clear, statistically binding — see [`crate::lattice::bdlop`]), and privately
//! sends each recipient `j` the evaluation `f(j)` **together with a Fiat–Shamir proof of correct
//! sharing**. Unlike a bare-Ajtai commitment, the proof binds the share *value* (not merely its
//! coset), so the adaptive-dealer kernel-injection attack `f(j) + κ` (`A·κ ≡ 0`) is rejected:
//!
//! ```text
//! commit(f(j)) == Σ_i  jⁱ · C_i          (homomorphic opening — consistency)
//! +  proof that  s_j = f(j)              (FS proof of correct sharing — binding)
//! ```
//!
//! The group secret is never reconstructed: each party's final signing share is the sum of the
//! sub-shares it received from the qualified dealer set, and the verification-key set is the
//! homomorphic sum of the qualified dealers' coefficient commitments. Because BDLOP binds an
//! arbitrary (non-short) `R_q` message, there is **no `(n, t)` regime restriction** — the legacy
//! verify-time norm bound is gone.

extern crate alloc;

use alloc::vec::Vec;

use rand_core::{
    CryptoRng,
    Rng,
};
use zeroize::Zeroizing;

use crate::error::DkgError;
use crate::lattice::bdlop::{
    self,
    Commitment,
    KAPPA,
    ShareProof,
};
use crate::lattice::ring::{
    Q,
    Rq,
    ring_add,
    rq_from_le_bytes,
    rq_to_le_bytes,
    sample_secret_poly,
    sample_uniform_poly,
    scalar_mul,
};
use crate::lattice::rngbuf::BufRng;
use crate::profile::{
    DkgProfileV1,
    PROFILE_ID_V1,
    PROFILE_MAX_PARTIES_V1,
};

/// Gaussian width for the secret constant term `a_0` (the group signing key contribution). Short, so
/// the reconstructed group secret is a valid lattice signing key for a downstream Raccoon-family
/// signer; the BDLOP commitment binds it regardless of size. The secret is sampled with the
/// **constant-time** CDT base sampler ([`crate::lattice::ring::sample_secret_poly`]); this value
/// must equal [`crate::lattice::gaussian::CT_SECRET_WIDTH`].
pub const SECRET_KEY_WIDTH: f64 = 8.0;

/// A dealer's secret degree-`t-1` polynomial.
///
/// `coeffs[i]` is the `i`-th coefficient (constant term `coeffs[0]` is this dealer's contribution);
/// `rho[i]` is the BDLOP commitment randomness for `coeffs[i]` (the proof witness).
pub struct SecretPolynomial {
    /// Dealer / party index `1..=n`.
    pub party: u8,
    /// Reconstruction threshold `t` (polynomial degree is `t-1`).
    pub threshold: u8,
    coeffs: Vec<Rq>,
    rho: Vec<[Rq; KAPPA]>,
}

impl SecretPolynomial {
    /// Number of coefficients (`= threshold`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.coeffs.len()
    }

    /// True if the polynomial carries no coefficients (never the case after a valid round 1).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.coeffs.is_empty()
    }
}

impl Drop for SecretPolynomial {
    fn drop(&mut self) {
        for c in &mut self.coeffs {
            c.coeffs.fill(0);
        }
        for block in &mut self.rho {
            for r in block {
                r.coeffs.fill(0);
            }
        }
    }
}

/// Public coefficient commitments broadcast by a dealer in round 1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoeffCommitments {
    /// Dealer / party index `1..=n`.
    pub party: u8,
    /// Reconstruction threshold `t`.
    pub threshold: u8,
    /// BDLOP commitments `C_0 .. C_{t-1}`.
    pub commitments: Vec<Commitment>,
}

/// A polynomial evaluation `f(j)` sent privately to recipient `j`, with its binding proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareEvaluation {
    /// Dealer that produced this share.
    pub dealer: u8,
    /// Recipient index `j`.
    pub recipient: u8,
    /// Threshold of the dealer's polynomial.
    pub threshold: u8,
    /// The evaluated share value `f(j)` (a single `R_q` element; non-short).
    pub value: Rq,
    /// The combined opening randomness `f_ρ(j) = Σ_i jⁱ·ρ_i` (`KAPPA` ring elements; non-short).
    pub rand: Vec<Rq>,
    /// Fiat–Shamir proof that `value = f(j)` (binds the share value).
    pub proof: ShareProof,
}

/// A publicly verifiable accusation that `dealer` sent `recipient` an inconsistent share.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Complaint {
    /// Accused dealer.
    pub dealer: u8,
    /// Recipient that raised the complaint.
    pub recipient: u8,
    /// The disputed share (disclosed so any verifier can recompute).
    pub share: ShareEvaluation,
}

/// A party's finalized signing share (sum of qualified dealers' sub-shares).
///
/// `share_bytes` encodes `value ‖ rand` (`1 + KAPPA` `R_q` elements). Shape mirrors
/// `lib-q-threshold-sig::SecretShare`; see `LIBQ_API.md` for the 1:1 mapping.
#[derive(Clone)]
pub struct SigningShare {
    /// Party index `1..=n`.
    pub index: u8,
    /// Reconstruction threshold `t`.
    pub threshold: u8,
    /// Canonical encoding of `value ‖ rand`.
    pub share_bytes: Zeroizing<Vec<u8>>,
}

/// Per-party verification key: the public BDLOP commitment to the party's share, serialized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareVerifier {
    /// Party index `1..=n`.
    pub index: u8,
    /// Serialized commitment image (`MU` `t0` elements followed by `t1`).
    pub verifying_key: Vec<u8>,
}

/// The verification-key set assembled from the qualified dealers' commitments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationKeySet {
    /// Reconstruction threshold `t`.
    pub threshold: u8,
    /// Group public key `Σ_dealer C_{dealer,0}` serialized (commitment to the group secret).
    pub group_key: Vec<u8>,
    /// Per-party verification keys.
    pub share_verifiers: Vec<ShareVerifier>,
}

/// Output of [`dkg_run_honest`]: shape mirrors `lib-q-threshold-sig::KeygenSharesOutput`.
#[derive(Clone)]
pub struct KeygenSharesOutput {
    /// The verification-key set (analog of `ThresholdSigPublicKey`).
    pub public_key: VerificationKeySet,
    /// One signing share per party.
    pub secret_shares: Vec<SigningShare>,
}

/// Round-1 output of a change-of-committee resharing (dealerless; no key reconstruction).
#[derive(Clone)]
pub struct ReshareRound1 {
    /// Old holder acting as resharing dealer.
    pub dealer: u8,
    /// Commitments to the resharing polynomial (constant term = `lagrange · old share`).
    pub commitments: CoeffCommitments,
    /// Sub-shares (each with a binding proof) for each new committee member.
    pub shares: Vec<ShareEvaluation>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Round 1: sample a degree-`t-1` polynomial and commit to its coefficients (BDLOP).
pub fn dkg_round1_commit<R: CryptoRng + Rng>(
    profile: &DkgProfileV1,
    n: u8,
    t: u8,
    party: u8,
    rng: &mut R,
) -> Result<(SecretPolynomial, CoeffCommitments), DkgError> {
    validate_profile(profile)?;
    validate_n_t(n, t)?;
    if party == 0 || party > n {
        return Err(DkgError::InvalidParty { index: party });
    }
    let key = bdlop::key();
    let mut br = BufRng::new(rng);
    let mut coeffs = Vec::with_capacity(usize::from(t));
    let mut rho = Vec::with_capacity(usize::from(t));
    let mut commitments = Vec::with_capacity(usize::from(t));
    for i in 0..t {
        // The constant term (this dealer's secret contribution) is sampled **short** so the
        // reconstructed group secret is a valid lattice signing key (Module-LWE-style). BDLOP binds
        // an arbitrary message, so the blinding coefficients can stay uniform for maximal hiding of
        // the sharing polynomial — only the secret `f(0) = a_0` must be short.
        let a = if i == 0 {
            // Constant-time CDT sampler at the fixed secret width (see lattice::gaussian).
            sample_secret_poly(&mut br)
        } else {
            sample_uniform_poly(&mut br)
        };
        let r = bdlop::sample_randomness(&mut br);
        commitments.push(bdlop::commit(key, &a, &r));
        coeffs.push(a);
        rho.push(r);
    }
    Ok((
        SecretPolynomial {
            party,
            threshold: t,
            coeffs,
            rho,
        },
        CoeffCommitments {
            party,
            threshold: t,
            commitments,
        },
    ))
}

/// Evaluate the dealer's polynomial at recipient `j`, producing the share `f(j)` and its binding
/// proof. Needs an RNG (the proof uses Fiat–Shamir-with-aborts masking).
pub fn dkg_eval_share<R: CryptoRng + Rng>(
    poly: &SecretPolynomial,
    j: u8,
    rng: &mut R,
) -> Result<ShareEvaluation, DkgError> {
    if j == 0 {
        return Err(DkgError::InvalidRecipient { index: j });
    }
    let key = bdlop::key();
    let t = usize::from(poly.threshold);
    // value = Σ_i jⁱ·a_i ; rand = Σ_i jⁱ·ρ_i (column-wise).
    let mut value = Rq::zero();
    let mut rand: Vec<Rq> = (0..KAPPA).map(|_| Rq::zero()).collect();
    for i in 0..t {
        let p = bdlop::pow_mod_q(j, i);
        value = ring_add(&value, &scalar_mul(&poly.coeffs[i], p));
        for (acc, rho_slot) in rand.iter_mut().zip(poly.rho[i].iter()) {
            *acc = ring_add(acc, &scalar_mul(rho_slot, p));
        }
    }
    // Reconstruct the public commitments (deterministic) for the proof transcript.
    let commitments: Vec<Commitment> = (0..t)
        .map(|i| bdlop::commit(key, &poly.coeffs[i], &poly.rho[i]))
        .collect();
    let mut br = BufRng::new(rng);
    let proof = bdlop::prove_share(
        &mut br,
        key,
        poly.party,
        j,
        poly.threshold,
        &commitments,
        &poly.rho,
        &value,
    )
    .ok_or(DkgError::ProofExhausted)?;
    Ok(ShareEvaluation {
        dealer: poly.party,
        recipient: j,
        threshold: poly.threshold,
        value,
        rand,
        proof,
    })
}

/// No-dealer **binding** check: the homomorphic opening holds **and** the proof of correct sharing
/// verifies. The proof is what binds the share *value* against a kernel-injection dealer; the
/// opening check additionally pins the disclosed randomness for the verification-key bookkeeping.
///
/// Returns `false` for any share inconsistent with the committed polynomial, an index mismatch, a
/// commitment list whose length disagrees with the threshold, or a malformed share.
#[must_use]
pub fn dkg_verify_share(
    commitments: &CoeffCommitments,
    dealer: u8,
    recipient: u8,
    share: &ShareEvaluation,
) -> bool {
    if commitments.party != dealer ||
        share.dealer != dealer ||
        share.recipient != recipient ||
        recipient == 0 ||
        commitments.commitments.len() != usize::from(commitments.threshold) ||
        share.threshold != commitments.threshold ||
        share.rand.len() != KAPPA
    {
        return false;
    }
    let key = bdlop::key();
    // Homomorphic opening: commit(value; rand) == Σ_i jⁱ·C_i.
    let rand: [Rq; KAPPA] = match clone_into_array(&share.rand) {
        Some(a) => a,
        None => return false,
    };
    let lhs = bdlop::commit(key, &share.value, &rand);
    let rhs = bdlop::eval_commitments(&commitments.commitments, recipient);
    if lhs != rhs {
        return false;
    }
    // Binding: the FS proof forces value = f(j).
    bdlop::verify_share(
        key,
        dealer,
        recipient,
        commitments.threshold,
        &commitments.commitments,
        &share.value,
        &share.proof,
    )
}

/// Package a disputed share into a [`Complaint`] (data only; validity is decided by
/// [`dkg_check_complaint`]).
#[must_use]
pub fn dkg_build_complaint(dealer: u8, recipient: u8, share: &ShareEvaluation) -> Complaint {
    Complaint {
        dealer,
        recipient,
        share: share.clone(),
    }
}

/// Publicly verify a complaint from the dealer's commitments alone (no private state).
///
/// Returns `true` iff the complaint is **upheld** — the revealed share fails the binding check.
#[must_use]
pub fn dkg_check_complaint(commitments: &CoeffCommitments, c: &Complaint) -> bool {
    !dkg_verify_share(commitments, c.dealer, c.recipient, &c.share)
}

/// Combine the sub-shares a recipient received from the qualified dealer set into its signing
/// share. All inputs must share one recipient and one threshold.
pub fn dkg_finalize_share(qualified: &[ShareEvaluation]) -> Result<SigningShare, DkgError> {
    let first = qualified.first().ok_or(DkgError::EmptyQualifiedSet)?;
    let recipient = first.recipient;
    let threshold = first.threshold;
    if qualified
        .iter()
        .any(|s| s.recipient != recipient || s.threshold != threshold || s.rand.len() != KAPPA)
    {
        return Err(DkgError::Mismatch);
    }
    let mut value = Rq::zero();
    let mut rand: Vec<Rq> = (0..KAPPA).map(|_| Rq::zero()).collect();
    for s in qualified {
        value = ring_add(&value, &s.value);
        for (acc, sr) in rand.iter_mut().zip(s.rand.iter()) {
            *acc = ring_add(acc, sr);
        }
    }
    Ok(SigningShare {
        index: recipient,
        threshold,
        share_bytes: Zeroizing::new(encode_value_rand(&value, &rand)),
    })
}

/// Assemble the verification-key set from the qualified dealers' commitments.
///
/// `parties` is the committee size `n`; per-party keys are produced for `1..=parties`.
pub fn dkg_assemble_vk_set(
    qualified: &[CoeffCommitments],
    parties: u8,
) -> Result<VerificationKeySet, DkgError> {
    let first = qualified.first().ok_or(DkgError::EmptyQualifiedSet)?;
    let threshold = first.threshold;
    if parties == 0 || parties > PROFILE_MAX_PARTIES_V1 {
        return Err(DkgError::InvalidPartyCount);
    }
    if qualified
        .iter()
        .any(|c| c.threshold != threshold || c.commitments.len() != usize::from(threshold))
    {
        return Err(DkgError::Mismatch);
    }

    // Group key = Σ_dealer C_{dealer,0}.
    let mut group = bdlop::commit_zero();
    for c in qualified {
        group = bdlop::commit_add(&group, &c.commitments[0]);
    }

    let mut share_verifiers = Vec::with_capacity(usize::from(parties));
    for j in 1..=parties {
        let mut vk = bdlop::commit_zero();
        for c in qualified {
            vk = bdlop::commit_add(&vk, &bdlop::eval_commitments(&c.commitments, j));
        }
        share_verifiers.push(ShareVerifier {
            index: j,
            verifying_key: encode_commitment(&vk),
        });
    }

    Ok(VerificationKeySet {
        threshold,
        group_key: encode_commitment(&group),
        share_verifiers,
    })
}

/// Change-of-committee resharing: the old holder reshares its current share to a new committee
/// without reconstructing the group key.
///
/// `lagrange` is the holder's Lagrange coefficient at zero (see [`lagrange_coeff_at_zero`]) for the
/// chosen reconstruction subset. The resharing polynomial's constant term is `lagrange · old_value`,
/// committed with **fresh** ternary randomness, so the reshared sub-shares are themselves fully
/// **binding-verifiable** (every coefficient has a short BDLOP opening) — an improvement over the
/// bare-Ajtai design. The group *secret* is preserved (summing the new committee's finalized shares
/// over the subset reconstructs the same message); the group-key *commitment* is re-randomized, so a
/// fresh verification-key set is published. See `LIBQ_API.md` for the resharing security notes.
pub fn dkg_reshare<R: CryptoRng + Rng>(
    old: &SigningShare,
    lagrange: i64,
    new_committee: &[u8],
    new_t: u8,
    rng: &mut R,
) -> Result<ReshareRound1, DkgError> {
    if new_committee.is_empty() || new_committee.len() > usize::from(PROFILE_MAX_PARTIES_V1) {
        return Err(DkgError::InvalidPartyCount);
    }
    if new_t == 0 || usize::from(new_t) > new_committee.len() {
        return Err(DkgError::InvalidThreshold);
    }
    if new_committee.contains(&0) {
        return Err(DkgError::InvalidRecipient { index: 0 });
    }
    let (old_value, _old_rand) = decode_value_rand(&old.share_bytes)?;
    let key = bdlop::key();
    let mut br = BufRng::new(rng);

    let mut coeffs = Vec::with_capacity(usize::from(new_t));
    let mut rho = Vec::with_capacity(usize::from(new_t));
    let mut commitments = Vec::with_capacity(usize::from(new_t));
    // Constant term: lagrange · old_value (full-Z_q message, fresh short randomness).
    coeffs.push(scalar_mul(&old_value, lagrange));
    for _ in 1..new_t {
        coeffs.push(sample_uniform_poly(&mut br));
    }
    for a in &coeffs {
        let r = bdlop::sample_randomness(&mut br);
        commitments.push(bdlop::commit(key, a, &r));
        rho.push(r);
    }

    let poly = SecretPolynomial {
        party: old.index,
        threshold: new_t,
        coeffs,
        rho,
    };
    let mut shares = Vec::with_capacity(new_committee.len());
    for &m in new_committee {
        shares.push(dkg_eval_share(&poly, m, &mut br)?);
    }
    Ok(ReshareRound1 {
        dealer: old.index,
        commitments: CoeffCommitments {
            party: old.index,
            threshold: new_t,
            commitments,
        },
        shares,
    })
}

/// Convenience: run the full honest `t`-of-`n` protocol (every party deals to every party, all
/// dealers qualified) and return shape-compatible keygen output.
pub fn dkg_run_honest<R: CryptoRng + Rng>(
    profile: &DkgProfileV1,
    n: u8,
    t: u8,
    rng: &mut R,
) -> Result<KeygenSharesOutput, DkgError> {
    validate_profile(profile)?;
    validate_n_t(n, t)?;

    let mut polys = Vec::with_capacity(usize::from(n));
    let mut all_commitments = Vec::with_capacity(usize::from(n));
    for party in 1..=n {
        let (poly, comms) = dkg_round1_commit(profile, n, t, party, rng)?;
        polys.push(poly);
        all_commitments.push(comms);
    }

    let mut secret_shares = Vec::with_capacity(usize::from(n));
    for recipient in 1..=n {
        let mut received = Vec::with_capacity(usize::from(n));
        for (dealer_idx, poly) in polys.iter().enumerate() {
            let share = dkg_eval_share(poly, recipient, rng)?;
            debug_assert!(dkg_verify_share(
                &all_commitments[dealer_idx],
                poly.party,
                recipient,
                &share,
            ));
            received.push(share);
        }
        secret_shares.push(dkg_finalize_share(&received)?);
    }

    let public_key = dkg_assemble_vk_set(&all_commitments, n)?;
    Ok(KeygenSharesOutput {
        public_key,
        secret_shares,
    })
}

/// Recompute the public verification key `commit(share_value; share_rand)` for a finalized signing
/// share, encoded the same way as [`ShareVerifier::verifying_key`]. A holder can compare this
/// against the published verification-key set to confirm its share matches.
pub fn signing_share_commitment(share: &SigningShare) -> Result<Vec<u8>, DkgError> {
    let (value, rand) = decode_value_rand(&share.share_bytes)?;
    let key = bdlop::key();
    let rand_arr: [Rq; KAPPA] = clone_into_array(&rand).ok_or(DkgError::Encoding)?;
    Ok(encode_commitment(&bdlop::commit(key, &value, &rand_arr)))
}

/// Lagrange coefficient `λ_i = Π_{j≠i} x_j / (x_j − x_i)` evaluated at zero, in `Z_q`, for the
/// reconstruction subset `subset` and member `i ∈ subset`.
pub fn lagrange_coeff_at_zero(subset: &[u8], i: u8) -> Result<i64, DkgError> {
    if !subset.contains(&i) {
        return Err(DkgError::InvalidParty { index: i });
    }
    let q = Q as u128;
    let mut num = 1u128;
    let mut den = 1u128;
    let xi = u128::from(i) % q;
    for &xj_u8 in subset {
        if xj_u8 == i {
            continue;
        }
        let xj = u128::from(xj_u8) % q;
        if xj == xi {
            return Err(DkgError::Mismatch);
        }
        num = num * xj % q;
        let diff = (xj + q - xi) % q;
        den = den * diff % q;
    }
    let den_inv = mod_inv(den, q).ok_or(DkgError::Mismatch)?;
    Ok((num * den_inv % q) as i64)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn validate_profile(profile: &DkgProfileV1) -> Result<(), DkgError> {
    if profile.id != PROFILE_ID_V1 || profile.max_parties != PROFILE_MAX_PARTIES_V1 {
        return Err(DkgError::InvalidProfile);
    }
    Ok(())
}

fn validate_n_t(n: u8, t: u8) -> Result<(), DkgError> {
    if n == 0 || n > PROFILE_MAX_PARTIES_V1 {
        return Err(DkgError::InvalidPartyCount);
    }
    if t == 0 || t > n {
        return Err(DkgError::InvalidThreshold);
    }
    Ok(())
}

fn clone_into_array(v: &[Rq]) -> Option<[Rq; KAPPA]> {
    if v.len() != KAPPA {
        return None;
    }
    Some(core::array::from_fn(|i| v[i].clone()))
}

fn mod_inv(a: u128, q: u128) -> Option<u128> {
    if a.is_multiple_of(q) {
        return None;
    }
    Some(mod_pow(a % q, q - 2, q))
}

fn mod_pow(mut base: u128, mut exp: u128, q: u128) -> u128 {
    let mut acc = 1u128 % q;
    base %= q;
    while exp != 0 {
        if exp & 1 == 1 {
            acc = acc * base % q;
        }
        base = base * base % q;
        exp >>= 1;
    }
    acc
}

/// Serialize a commitment: `MU` `t0` elements followed by `t1`.
fn encode_commitment(c: &Commitment) -> Vec<u8> {
    let mut out = Vec::new();
    for p in &c.t0 {
        out.extend_from_slice(&rq_to_le_bytes(p));
    }
    out.extend_from_slice(&rq_to_le_bytes(&c.t1));
    out
}

/// Encode `value ‖ rand` (`1 + KAPPA` ring elements) for a finalized share.
fn encode_value_rand(value: &Rq, rand: &[Rq]) -> Vec<u8> {
    let mut out = rq_to_le_bytes(value);
    for r in rand {
        out.extend_from_slice(&rq_to_le_bytes(r));
    }
    out
}

fn decode_value_rand(bytes: &[u8]) -> Result<(Rq, Vec<Rq>), DkgError> {
    use crate::lattice::ring::RQ_BYTES;
    if bytes.len() != RQ_BYTES * (1 + KAPPA) {
        return Err(DkgError::Encoding);
    }
    let value = rq_from_le_bytes(&bytes[..RQ_BYTES]).ok_or(DkgError::Encoding)?;
    let mut rand = Vec::with_capacity(KAPPA);
    for k in 0..KAPPA {
        let start = RQ_BYTES * (1 + k);
        rand.push(rq_from_le_bytes(&bytes[start..start + RQ_BYTES]).ok_or(DkgError::Encoding)?);
    }
    Ok((value, rand))
}

#[cfg(test)]
mod tests {
    use lib_q_random::new_deterministic_rng;

    use super::*;
    use crate::profile::setup;

    #[test]
    fn lagrange_reconstructs_constant_term() {
        // For subset {1,2,3} the Lagrange weights at 0 must satisfy Σ λ_i · iⁱ-style identity:
        // reconstruct f(0) from f(1),f(2),f(3) of a known low-degree poly over Z_q.
        let subset = [1u8, 2, 3];
        // f(x) = 5 + 7x + 9x² (mod q). f(0) = 5.
        let f = |x: i64| -> i64 {
            let q = Q;
            (((5 + 7 * x + 9 * x * x) % q) + q) % q
        };
        let q = Q as i128;
        let mut acc = 0i128;
        for &i in &subset {
            let lam = lagrange_coeff_at_zero(&subset, i).expect("lagrange") as i128;
            acc = (acc + lam * f(i64::from(i)) as i128) % q;
        }
        assert_eq!(acc as i64, 5);
    }

    #[test]
    fn out_of_range_params_rejected() {
        let profile = setup();
        let mut rng = new_deterministic_rng([0x01u8; 32]);
        assert!(matches!(
            dkg_round1_commit(&profile, 5, 6, 1, &mut rng),
            Err(DkgError::InvalidThreshold)
        ));
        assert!(matches!(
            dkg_round1_commit(&profile, 0, 1, 1, &mut rng),
            Err(DkgError::InvalidPartyCount)
        ));
    }
}
