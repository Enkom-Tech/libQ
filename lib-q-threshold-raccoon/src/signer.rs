//! The core Raccoon-family lattice signature: a Fiat–Shamir proof of knowledge of the **short
//! opening** `(s, r)` of the group key `T = commit(s; r) = (B0·r, ⟨b1, r⟩ + s)`.
//!
//! Because the group randomness `r` is short (a sum of ternary constant-term randomness from the
//! [`lib_q_dkg`] sharing), `T` binds `s` (statistical binding) and hides it (Module-LWE). The signing
//! key is `(s, r)`; a threshold of holders recovers it by Lagrange at zero (the "combine" step). A
//! signature is then:
//!
//! ```text
//! W = commit(y_s; y_r) ;  c = H(T, msg, W) ;  z_s = y_s + c·s ,  z_r = y_r + c·r
//! verify:  commit(z_s; z_r) − c·T == W   and   ‖z_r‖∞ ≤ BETA_R
//! ```
//!
//! `y_s` is uniform over `R_q` (perfect hiding of the non-short `s`); `y_r` is Gaussian and
//! rejection-sampled so `z_r` is short and witness-independent (Lyubashevsky). The verifier norm
//! bound on `z_r` forces a short extracted `r`, so unforgeability reduces to binding + Module-LWE.
//!
//! **Scope (research-grade).** This is a sound single-signer construction; the threshold *combine*
//! is a caller-side Lagrange sum (see [`crate::combine_opening`]). A fully threshold-native signing
//! round with distributed short-response aggregation (Threshold-Raccoon, additive sharing + clearing
//! factor) is the documented next phase — see `LIBQ_API.md` §7.

extern crate alloc;

use alloc::vec::Vec;

use lib_q_dkg::lattice::bdlop::{
    self,
    Commitment,
    KAPPA,
    TAU,
};
use lib_q_dkg::lattice::ring::{
    N,
    Rq,
    centered_coeffs,
    ring_add,
    ring_mul,
    ring_sub,
    sample_discrete_gaussian_block,
    sample_in_ball,
    sample_uniform_poly,
};
use lib_q_dkg::lattice::rngbuf::BufRng;
use lib_q_sha3::{
    ExtendableOutput,
    Update,
    XofReader,
};
use rand_core::{
    CryptoRng,
    Rng,
};

/// Gaussian width for the randomness mask `y_r`.
///
/// Sized for the **distributed** (rejection-free) path: `S_SIGN` is a flooding security parameter,
/// not a convenience number. With `Q_s ∝ S_SIGN²`, this value certifies a per-key signature budget
/// of `Q_s ≈ 2^20` at the worst case (threshold `t = 2`, committee `n = 16`) for 128-bit ZK — see
/// [`MAX_SIGNATURES_PER_KEY`] and `SECURITY_ANALYSIS.md` §4. (The single-signer [`sign`] uses the
/// same width via rejection; an over-wide mask there only pushes the acceptance rate toward 1.)
///
/// Raised 268 000 → 290 000 alongside `KAPPA` 8→9: the group randomness `r_grp ∈ R_q^KAPPA` grows
/// with `KAPPA`, so `‖c·r_grp‖` rose and the worst-case Rényi budget would have slipped to `2^19.8`.
/// `Q_s ∝ S_SIGN²`, so this restores the certified worst case to `2^20.07 ≥ 2^20` — Q_s is **not**
/// traded down to pay for the hiding bits.
pub const S_SIGN: f64 = 290_000.0;
/// Verifier infinity-norm bound on `z_r` (`= 14·S_SIGN`, far below `q/2 ≈ 2^47`).
///
/// The factor 14 (not 12) gives completeness headroom for the rejection-free distributed path: an
/// honest aggregated `z_r` at `t = 16` has per-coordinate σ ≈ `S_SIGN·√t/√(2π)`, and the bound must
/// hold across all `≈ 2^33` coordinate samples in the `Q_s` budget (≈ 6.8σ tail). With `KAPPA = 9`
/// (raised from 8 to reach ≥128-bit quantum hiding) the statistical binding margin is `≈ 7.0` bits
/// (GH `2^36.5` vs extractor gap `2^29.5`) — still `≈ 2^-64500` kernel-collision probability.
pub const BETA_R: i64 = 4_060_000;
/// Rejection-sampling tail factor.
pub const REJECT_KAPPA: f64 = 12.0;
/// Max FS-with-aborts attempts.
pub const MAX_ATTEMPTS: usize = 800;

/// Certified per-key signature budget for the **distributed** (rejection-free / flooding) path.
///
/// The distributed protocol's zero-knowledge rests on noise flooding rather than rejection, so the
/// number of signatures produced under one key is a security parameter (Rényi divergence over the
/// query budget). At the frozen params the certified worst-case (threshold `t = 2`, committee
/// `n = 16`) is `2^20.07`, so the enforced counter `2^20` sits at-or-below the certified budget;
/// larger thresholds tolerate more (≈`2^23` at `t = 16`). A deployment
/// **MUST** enforce this as a per-key counter — it is stateful and therefore lives in the caller, not
/// in these stateless protocol functions. The single-signer [`sign`] path is rejection-sampled and
/// is **not** subject to this budget. See `SECURITY_ANALYSIS.md` §4.
pub const MAX_SIGNATURES_PER_KEY: u64 = 1 << 20;

/// A signature: challenge + masked responses for the message and randomness parts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    /// Sparse challenge `c`.
    pub c: Rq,
    /// Response `z_s = y_s + c·s` (one ring element; uniform).
    pub z_s: Rq,
    /// Response `z_r = y_r + c·r` (`KAPPA` ring elements; short).
    pub z_r: Vec<Rq>,
}

/// `c · T` where `c` is a ring element (component-wise ring multiply).
fn ring_scale_commitment(c: &Rq, t: &Commitment) -> Commitment {
    Commitment {
        t0: t.t0.iter().map(|p| ring_mul(c, p)).collect(),
        t1: ring_mul(c, &t.t1),
    }
}

/// Fiat–Shamir challenge bound to the group key, message, and first message `w`. Shared with the
/// distributed protocol ([`crate::threshold`]) so all parties derive the same `c`.
pub fn challenge(t: &Commitment, msg: &[u8], w: &Commitment) -> Rq {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(b"lib-q-threshold-raccoon/sign/v1");
    h.update(&bdlop::COMMIT_MATRIX_SEED);
    absorb_commitment(&mut h, t);
    h.update(&(msg.len() as u64).to_le_bytes());
    h.update(msg);
    absorb_commitment(&mut h, w);
    let mut seed = [0u8; 32];
    let mut rd = h.finalize_xof();
    XofReader::read(&mut rd, &mut seed);
    sample_in_ball(&seed, TAU)
}

fn absorb_commitment(h: &mut lib_q_sha3::Shake256, c: &Commitment) {
    for p in &c.t0 {
        absorb_poly(h, p);
    }
    absorb_poly(h, &c.t1);
}

fn absorb_poly(h: &mut lib_q_sha3::Shake256, p: &Rq) {
    for c in centered_coeffs(p) {
        h.update(&c.to_le_bytes());
    }
}

fn inner(a: &[Rq], b: &[Rq]) -> i128 {
    let mut acc = 0i128;
    for (ai, bi) in a.iter().zip(b.iter()) {
        let ca = centered_coeffs(ai);
        let cb = centered_coeffs(bi);
        for t in 0..N {
            acc += i128::from(ca[t]) * i128::from(cb[t]);
        }
    }
    acc
}

fn l2_sq(v: &[Rq]) -> f64 {
    let mut acc = 0.0;
    for vi in v {
        for c in centered_coeffs(vi) {
            acc += (c as f64) * (c as f64);
        }
    }
    acc
}

fn uniform_unit<R: Rng>(rng: &mut R) -> f64 {
    let mut b = [0u8; 8];
    rng.fill_bytes(&mut b);
    ((u64::from_le_bytes(b) >> 11) as f64) * (1.0 / ((1u64 << 53) as f64))
}

fn infinity_norm(v: &[Rq]) -> i64 {
    v.iter()
        .flat_map(centered_coeffs)
        .map(i64::abs)
        .max()
        .unwrap_or(0)
}

/// Sign `msg` with the short group opening `(s, r)` of `t = commit(s; r)`. Returns `None` if
/// rejection sampling exhausts `MAX_ATTEMPTS`.
pub fn sign<R: CryptoRng + Rng>(
    rng: &mut R,
    t: &Commitment,
    s: &Rq,
    r: &[Rq; KAPPA],
    msg: &[u8],
) -> Option<Signature> {
    let key = bdlop::key();
    let mut br = BufRng::new(rng);
    let rng = &mut br;
    let s2 = S_SIGN * S_SIGN;
    let r_slice: Vec<Rq> = r.to_vec();
    for _ in 0..MAX_ATTEMPTS {
        let y_s = sample_uniform_poly(rng);
        let y_r: [Rq; KAPPA] = sample_discrete_gaussian_block::<_, KAPPA>(rng, S_SIGN);
        let w = bdlop::commit(key, &y_s, &y_r);
        let c = challenge(t, msg, &w);

        let z_s = ring_add(&y_s, &ring_mul(&c, s));
        let v: Vec<Rq> = r_slice.iter().map(|ri| ring_mul(&c, ri)).collect();
        let z_r: Vec<Rq> = y_r
            .iter()
            .zip(v.iter())
            .map(|(yi, vi)| ring_add(yi, vi))
            .collect();

        let norm_v_sq = l2_sq(&v);
        let norm_v = norm_v_sq.sqrt();
        let zv = inner(&z_r, &v) as f64;
        let log_ratio = -core::f64::consts::PI * (2.0 * zv - norm_v_sq) / s2;
        let log_m = REJECT_KAPPA * norm_v * (2.0 * core::f64::consts::PI).sqrt() / S_SIGN;
        let accept = (log_ratio - log_m).exp().min(1.0);
        // Isochronous accept/abort: both predicates are always evaluated (no `&&` short-circuit), so
        // each iteration does identical work regardless of outcome. The residual side channel is the
        // *number* of iterations (inherent to Lyubashevsky rejection) and the float `exp`; secret-key
        // signing under a timing adversary must use the rejection-free distributed path. See
        // `SECURITY_ANALYSIS.md` §8.
        let prob_ok = uniform_unit(rng) < accept;
        let norm_ok = infinity_norm(&z_r) <= BETA_R;
        if prob_ok & norm_ok {
            return Some(Signature { c, z_s, z_r });
        }
    }
    None
}

/// Verify a signature against the group key `t` and message.
#[must_use]
pub fn verify(t: &Commitment, msg: &[u8], sig: &Signature) -> bool {
    if sig.z_r.len() != KAPPA {
        return false;
    }
    if infinity_norm(&sig.z_r) > BETA_R {
        return false;
    }
    let key = bdlop::key();
    let z_r: [Rq; KAPPA] = core::array::from_fn(|i| sig.z_r[i].clone());
    let lhs = bdlop::commit(key, &sig.z_s, &z_r);
    let ct = ring_scale_commitment(&sig.c, t);
    let w = Commitment {
        t0: lhs
            .t0
            .iter()
            .zip(ct.t0.iter())
            .map(|(a, b)| ring_sub(a, b))
            .collect(),
        t1: ring_sub(&lhs.t1, &ct.t1),
    };
    let c = challenge(t, msg, &w);
    centered_coeffs(&c) == centered_coeffs(&sig.c)
}

#[cfg(test)]
mod tests {
    use lib_q_random::new_deterministic_rng;

    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let mut rng = new_deterministic_rng([0xE1u8; 32]);
        let key = bdlop::key();
        let s = sample_uniform_poly(&mut rng);
        let r = bdlop::sample_randomness(&mut rng);
        let t = bdlop::commit(key, &s, &r);
        let sig = sign(&mut rng, &t, &s, &r, b"hello").expect("sign");
        assert!(verify(&t, b"hello", &sig));
        assert!(!verify(&t, b"other", &sig), "wrong message must fail");
        let mut bad = sig.clone();
        bad.z_s.coeffs[0] ^= 1;
        assert!(!verify(&t, b"hello", &bad), "tampered signature must fail");
    }
}
