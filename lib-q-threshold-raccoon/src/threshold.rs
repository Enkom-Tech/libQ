//! Distributed **t-of-n** threshold signing — no party ever reconstructs the key.
//!
//! Following Threshold-Raccoon (del Pino–Katsumata–Reichle–Takemure, CRYPTO 2024). The obstruction
//! with Shamir-over-`Z_q` is that a partial response `z_r,i = y_r,i + c·λ_i·rand(i)` is **non-short**
//! (the Lagrange weight `λ_i` is a full `Z_q` scalar), so it cannot be broadcast directly. The fix is
//! **additive zero-sharing**: each signer adds a uniform mask `m_i` with `Σ_{i∈S} m_i = 0`, which
//! hides each `z_r,i` in transit yet cancels on aggregation — leaving the short, clean
//! `z_r = Y_r + c·r_grp` (the non-short `λ_i` terms collapse via `Σ_{i∈S} λ_i·rand(i) = r_grp`). The
//! message part `z_s,i = y_s,i + c·λ_i·value(i)` needs no zero-share: a uniform `y_s,i` floods it.
//!
//! The output is a standard [`Signature`] accepted by [`crate::verify`]. The protocol is three
//! rounds (commit → reveal → respond) plus a one-time pairwise-seed setup for the zero-sharing.
//!
//! **Scope (research-grade):** masks use noise flooding (no rejection), so `z_r` statistically hides
//! `r_grp` only up to a Rényi bound — giving a **per-key signature budget** of `Q_s ≈ 2^20`
//! signatures (worst case `t = 2, n = 16`; up to `≈2^23` at `t = 16`) at 128-bit ZK (adequate for
//! rarely-signing long-lived keys). A deployment **MUST** enforce this as a per-key counter — see
//! [`crate::signer::MAX_SIGNATURES_PER_KEY`]. Raise `S_SIGN` (≈∝√Q_s) to extend it. Threshold
//! unforgeability is proven by reduction to BDLOP binding + Module-LWE in `SECURITY_ANALYSIS.md` §7
//! (with the Threshold-Raccoon TS-UF-1 mapping). See also `LIBQ_API.md` §3a/§7.

extern crate alloc;

use alloc::vec::Vec;

use lib_q_dkg::lattice::bdlop::{
    self,
    Commitment,
    KAPPA,
};
use lib_q_dkg::lattice::ring::{
    N,
    Q,
    Rq,
    centered_coeffs,
    ring_add,
    ring_mul,
    ring_sub,
    sample_discrete_gaussian_block,
    sample_uniform_poly,
    scalar_mul,
};
use lib_q_sha3::{
    ExtendableOutput,
    Update,
    XofReader,
};
use rand_core::{
    CryptoRng,
    Rng,
};

use crate::SecretShare;
use crate::error::RaccoonError;
use crate::signer::{
    S_SIGN,
    Signature,
    challenge,
};

/// Symmetric pairwise seeds for additive zero-sharing (one per unordered party pair).
///
/// In a deployment these are established via pairwise key agreement during/after the DKG; here a
/// helper samples them for testing. `seed(i, j) == seed(j, i)`.
#[derive(Clone)]
pub struct ZeroShareSeeds {
    entries: Vec<(u8, u8, [u8; 32])>,
}

impl ZeroShareSeeds {
    /// Sample fresh pairwise seeds for parties `1..=parties`.
    pub fn setup<R: CryptoRng + Rng>(parties: u8, rng: &mut R) -> Self {
        let mut entries = Vec::new();
        for i in 1..=parties {
            for j in (i + 1)..=parties {
                let mut s = [0u8; 32];
                rng.fill_bytes(&mut s);
                entries.push((i, j, s));
            }
        }
        Self { entries }
    }

    fn seed(&self, a: u8, b: u8) -> Option<&[u8; 32]> {
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        self.entries
            .iter()
            .find(|(i, j, _)| *i == lo && *j == hi)
            .map(|(_, _, s)| s)
    }
}

/// Per-party secret state from round 1 (the masking).
pub struct Round1State {
    /// Party index `1..=n`.
    pub index: u8,
    y_s: Rq,
    y_r: [Rq; KAPPA],
    w: Commitment,
}

/// Round-1 broadcast: a hiding commitment to the party's first message `w_i` (prevents rushing).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Round1Commit {
    /// Party index.
    pub index: u8,
    /// `H(w_i)`.
    pub com: [u8; 32],
}

/// Round-2 broadcast: the opened first message `w_i`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Round1Reveal {
    /// Party index.
    pub index: u8,
    /// The first message `w_i = commit(y_s,i; y_r,i)`.
    pub w: Commitment,
}

/// Round-3 broadcast: the masked partial signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialSignature {
    /// Party index.
    pub index: u8,
    /// `z_s,i = y_s,i + c·λ_i·value(i)` (uniform; safe to broadcast).
    pub z_s: Rq,
    /// `z_r,i + m_i` — the short response masked by a zero-share (uniform; safe to broadcast).
    pub z_r_masked: Vec<Rq>,
}

/// Round 1: sample the masking and commit to the first message.
pub fn sign_round1<R: CryptoRng + Rng>(index: u8, rng: &mut R) -> (Round1State, Round1Commit) {
    let key = bdlop::key();
    let y_s = sample_uniform_poly(rng);
    let y_r: [Rq; KAPPA] = sample_discrete_gaussian_block::<_, KAPPA>(rng, S_SIGN);
    let w = bdlop::commit(key, &y_s, &y_r);
    let com = hash_commitment(&w);
    (
        Round1State { index, y_s, y_r, w },
        Round1Commit { index, com },
    )
}

/// Round 2: reveal the first message.
#[must_use]
pub fn sign_round1_reveal(state: &Round1State) -> Round1Reveal {
    Round1Reveal {
        index: state.index,
        w: state.w.clone(),
    }
}

/// Aggregate the revealed first messages into `W = Σ w_i`, checking each opening against its
/// round-1 commitment. `commits` and `reveals` must cover the same signer set.
pub fn aggregate_commitment(
    commits: &[Round1Commit],
    reveals: &[Round1Reveal],
) -> Result<Commitment, RaccoonError> {
    if commits.len() != reveals.len() || commits.is_empty() {
        return Err(RaccoonError::InvalidSignerSet);
    }
    let mut w = bdlop::commit_zero();
    for r in reveals {
        let c = commits
            .iter()
            .find(|c| c.index == r.index)
            .ok_or(RaccoonError::InvalidSignerSet)?;
        if hash_commitment(&r.w) != c.com {
            return Err(RaccoonError::Encoding);
        }
        w = bdlop::commit_add(&w, &r.w);
    }
    Ok(w)
}

/// Round 3: produce this party's masked partial signature.
///
/// `subset` is the signing set (all participating indices, including this party). `t` is the group
/// key, `w` the aggregated first message from [`aggregate_commitment`].
#[allow(clippy::too_many_arguments)]
pub fn sign_round2(
    state: &Round1State,
    share: &SecretShare,
    subset: &[u8],
    t: &Commitment,
    msg: &[u8],
    w: &Commitment,
    seeds: &ZeroShareSeeds,
) -> Result<PartialSignature, RaccoonError> {
    if state.index != share.index {
        return Err(RaccoonError::InvalidIndex { index: state.index });
    }
    if !subset.contains(&state.index) {
        return Err(RaccoonError::InvalidSignerSet);
    }
    let c = challenge(t, msg, w);
    let lambda = lib_q_dkg::lagrange_coeff_at_zero(subset, state.index)
        .map_err(|_| RaccoonError::InvalidSignerSet)?;
    let (value, rand) = crate::decode_value_rand(&share.share_bytes)?;
    if rand.len() != KAPPA {
        return Err(RaccoonError::Encoding);
    }

    // z_s,i = y_s,i + c·λ_i·value(i)  (uniform y_s floods the non-short term).
    let cl_value = ring_mul(&c, &scalar_mul(&value, lambda));
    let z_s = ring_add(&state.y_s, &cl_value);

    // z_r,i = y_r,i + c·λ_i·rand(i)  (non-short) ; mask with a zero-share m_i.
    let session = session_bytes(t, msg, w);
    let m = zero_share(seeds, state.index, subset, &session)?;
    let mut z_r_masked = Vec::with_capacity(KAPPA);
    for slot in 0..KAPPA {
        let cl = ring_mul(&c, &scalar_mul(&rand[slot], lambda));
        let z_ri = ring_add(&state.y_r[slot], &cl);
        z_r_masked.push(ring_add(&z_ri, &m[slot]));
    }
    Ok(PartialSignature {
        index: state.index,
        z_s,
        z_r_masked,
    })
}

/// Aggregate the masked partials into a standard [`Signature`]. The zero-shares cancel, yielding the
/// clean, short `z_r`.
pub fn aggregate(
    partials: &[PartialSignature],
    subset: &[u8],
    t: &Commitment,
    msg: &[u8],
    w: &Commitment,
) -> Result<Signature, RaccoonError> {
    if partials.len() != subset.len() || partials.is_empty() {
        return Err(RaccoonError::InvalidSignerSet);
    }
    let c = challenge(t, msg, w);
    let mut z_s = Rq::zero();
    let mut z_r: Vec<Rq> = (0..KAPPA).map(|_| Rq::zero()).collect();
    for p in partials {
        if !subset.contains(&p.index) || p.z_r_masked.len() != KAPPA {
            return Err(RaccoonError::InvalidSignerSet);
        }
        z_s = ring_add(&z_s, &p.z_s);
        for (acc, zi) in z_r.iter_mut().zip(p.z_r_masked.iter()) {
            *acc = ring_add(acc, zi);
        }
    }
    Ok(Signature { c, z_s, z_r })
}

// ---------------------------------------------------------------------------

fn hash_commitment(c: &Commitment) -> [u8; 32] {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(b"lib-q-threshold-raccoon/round1-commit/v1");
    absorb_commitment(&mut h, c);
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

fn session_bytes(t: &Commitment, msg: &[u8], w: &Commitment) -> [u8; 32] {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(b"lib-q-threshold-raccoon/session/v1");
    absorb_commitment(&mut h, t);
    h.update(&(msg.len() as u64).to_le_bytes());
    h.update(msg);
    absorb_commitment(&mut h, w);
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

fn absorb_commitment(h: &mut lib_q_sha3::Shake256, c: &Commitment) {
    for p in &c.t0 {
        for x in centered_coeffs(p) {
            h.update(&x.to_le_bytes());
        }
    }
    for x in centered_coeffs(&c.t1) {
        h.update(&x.to_le_bytes());
    }
}

/// Additive zero-share for party `i` over `subset`, bound to `session`:
/// `m_i = Σ_{j∈S, j≠i} ε(i,j)·PRF(seed_{ij}, session)` with `ε(i,j) = +1 if i<j else −1`, so
/// `Σ_{i∈S} m_i = 0`. Uniform over `R_q^KAPPA`, hiding the non-short `z_r,i`.
fn zero_share(
    seeds: &ZeroShareSeeds,
    i: u8,
    subset: &[u8],
    session: &[u8; 32],
) -> Result<[Rq; KAPPA], RaccoonError> {
    let mut m: [Rq; KAPPA] = core::array::from_fn(|_| Rq::zero());
    for &j in subset {
        if j == i {
            continue;
        }
        let seed = seeds.seed(i, j).ok_or(RaccoonError::InvalidSignerSet)?;
        let contrib = prf_rq_block(seed, session);
        for slot in 0..KAPPA {
            m[slot] = if i < j {
                ring_add(&m[slot], &contrib[slot])
            } else {
                ring_sub(&m[slot], &contrib[slot])
            };
        }
    }
    Ok(m)
}

/// Deterministic uniform `R_q^KAPPA` from `(seed, session)` via SHAKE-256 rejection sampling.
fn prf_rq_block(seed: &[u8; 32], session: &[u8; 32]) -> [Rq; KAPPA] {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(b"lib-q-threshold-raccoon/zero-share-prf/v1");
    h.update(seed);
    h.update(session);
    let mut rd = h.finalize_xof();
    let q = Q as u64;
    let zone = u64::MAX - (u64::MAX % q);
    core::array::from_fn(|_| {
        let mut coeffs = [0i64; N];
        for cf in &mut coeffs {
            let v = loop {
                let mut b = [0u8; 8];
                XofReader::read(&mut rd, &mut b);
                let r = u64::from_le_bytes(b);
                if r < zone {
                    break r % q;
                }
            };
            *cf = v as i64;
        }
        Rq::from_coeffs(coeffs)
    })
}

#[cfg(test)]
mod tests {
    use lib_q_random::new_deterministic_rng;

    use super::*;

    #[test]
    fn zero_shares_cancel() {
        let mut rng = new_deterministic_rng([0x01u8; 32]);
        let seeds = ZeroShareSeeds::setup(5, &mut rng);
        let subset = [1u8, 3, 4];
        let session = [0x7u8; 32];
        let mut sum: [Rq; KAPPA] = core::array::from_fn(|_| Rq::zero());
        for &i in &subset {
            let m = zero_share(&seeds, i, &subset, &session).expect("zero share");
            for slot in 0..KAPPA {
                sum[slot] = ring_add(&sum[slot], &m[slot]);
            }
        }
        for s in &sum {
            assert!(
                centered_coeffs(s).iter().all(|&v| v == 0),
                "zero-shares must sum to 0"
            );
        }
    }
}
