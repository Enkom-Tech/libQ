//! BDLOP commitment + Fiat–Shamir proof of correct sharing — the **binding** no-dealer check.
//!
//! ## Why a plain Ajtai commitment is not enough
//!
//! The dealerless DKG verifies Shamir evaluations `f(j) = Σ_i jⁱ·aᵢ`. The `jⁱ` span all of `Z_q`,
//! so `f(j)` is **non-short**. A bare Ajtai commitment `com = A·x` binds only short witnesses `x`,
//! so the homomorphic relation `com(f(j)) == Σ_i jⁱ·Cᵢ` is a *linear-consistency* check, not a
//! binding one: an adaptive dealer can add a non-short kernel vector `κ` (`A·κ ≡ 0`, trivial to
//! find) to a victim's share, keeping the commitment image while corrupting the share value.
//!
//! ## The fix (BDLOP / Baum-style, statistically binding here)
//!
//! Each coefficient is committed with the message **in the clear**:
//!
//! ```text
//! C = (t0, t1) = (B0·ρ ,  ⟨b1, ρ⟩ + a)        ρ ternary (short)
//! ```
//!
//! `t1` binds an *arbitrary* `R_q` message `a` while `ρ` stays short. At this instance
//! (`N = 1024`, `q ≈ 2^48`, `MU = 6`, `KAPPA = 9`) the shortest nonzero vector of the kernel lattice
//! `{x : B0·x ≡ 0}` is `≈ 2^36.5` (Gaussian heuristic), far above the worst-case extractable opening
//! difference (`≈ 2^29.5`, ℓ∞-enforced). The commitment is therefore **statistically binding** — the
//! chance a shorter kernel vector exists scales as `(2^-7.0)^(κ·N) ≈ 2^-64500`, so the kernel
//! attack is defeated with no computational assumption. Hiding of `a` rests on Module-LWE (recovering
//! the unique short `ρ` from `t0`; the malb lattice-estimator gives BKZ blocksize β = 636 ⇒ core-SVP
//! ≈ 186-bit classical / 169-bit quantum). See `SECURITY_ANALYSIS.md` §1–§2 and `LIBQ_API.md` §3.
//!
//! ## Binding the *share*, not just the coefficients
//!
//! Linearity gives `Σ_i jⁱ·Cᵢ = (B0·f_ρ(j), ⟨b1, f_ρ(j)⟩ + f(j))` with `f_ρ(j) = Σ_i jⁱ·ρᵢ` —
//! but `f_ρ(j)` is non-short, so the dealer still has free randomness to satisfy the relation with a
//! wrong share. To remove that freedom each share carries a Fiat–Shamir-with-aborts proof of
//! knowledge of **short** `{ρᵢ}` such that, for recipient `j`,
//!
//! ```text
//! (A)  B0·ρᵢ = t0ᵢ              for all i            (pins ρᵢ to the committed, short value)
//! (B)  ⟨b1, Σ_i jⁱ·ρᵢ⟩ = (Σ_i jⁱ·t1ᵢ) − s_j        (forces s_j = f(j))
//! ```
//!
//! Soundness then forces `s_j = f(j)` (relaxed by an invertible challenge-difference factor), so a
//! kernel-injected `s_j + κ` is rejected. The proof is HVZK (rejection sampling), so reusing the
//! same `{ρᵢ}` across every recipient's proof leaks nothing about the secret coefficients.

extern crate alloc;

use alloc::vec::Vec;

use lib_q_sha3::{
    ExtendableOutput,
    Update,
    XofReader,
};
use rand_core::{
    CryptoRng,
    Rng,
};

use super::ring::{
    N,
    Q,
    Rq,
    centered_coeffs,
    ring_add,
    ring_mul,
    ring_sub,
    sample_discrete_gaussian_block,
    sample_in_ball,
    sample_ternary_poly,
    scalar_mul,
};

/// Binding rows of `B0` (height of the `t0` part of a commitment).
///
/// `MU = 6` with `KAPPA = 9` gives an ≈7.0-bit statistical-binding margin (GH shortest kernel vector
/// `≈ 2^36.5` vs the worst-case extractor gap `≈ 2^29.5`) while keeping `κ−μ = 3` ring elements of
/// hiding redundancy. The malb lattice-estimator (the gate, not a hand estimate) reports Module-LWE
/// recovery of `ρ` at BKZ blocksize β = 636 ⇒ ≈186-bit classical / **169-bit quantum** core-SVP.
/// These params clear the ≥128-bit **quantum** core-SVP bar with headroom (κ=8 gives only 98-bit
/// quantum; κ=9 is the smallest module rank that clears 128 at this ring) while keeping the serialized
/// signature ≤ 128 KiB (66 KiB) and the per-key signature budget Q_s = 2^20 (BETA_R held fixed, so
/// the bits are bought with module rank, not by trading Q_s down) — see the estimator sweep in
/// `SECURITY_ANALYSIS.md` §1–§2 / §5–§6 (reproduce via `sweep_qs_preserving.py`).
pub const MU: usize = 6;
/// Commitment randomness width (`ρ ∈ R_q^KAPPA`).
pub const KAPPA: usize = 9;
/// Sparse challenge Hamming weight: `|C| = 2^τ·C(N,τ) ≈ 2^171` ⇒ ≫128-bit knowledge soundness.
pub const TAU: usize = 22;
/// Rejection-sampling tail factor (standard deviations covered by the mask).
pub const REJECT_KAPPA: f64 = 12.0;
/// Max FS-with-aborts attempts before giving up a share proof (vanishingly unlikely to exhaust).
pub const MAX_ATTEMPTS: usize = 800;

/// Nothing-up-my-sleeve seed expanding the BDLOP commitment matrices `(B0, b1)` (public CRS).
pub const COMMIT_MATRIX_SEED: [u8; 32] = *b"lib-q-dkg/bdlop/crs/v1\0\0\0\0\0\0\0\0\0\0";

/// Masking width `s_y(t) ≈ 11·‖c·ρ‖₂` (grows with the degree `t-1` polynomial's witness size).
#[must_use]
pub fn mask_width(threshold: usize) -> f64 {
    11.0 * ((threshold * KAPPA * N * TAU) as f64).sqrt()
}

/// Verifier infinity-norm bound on each response coordinate (`≈ 12·s_y`, far below `q/2 ≈ 2^47`).
#[must_use]
pub fn response_bound(threshold: usize) -> i64 {
    (12.0 * mask_width(threshold)) as i64
}

/// Public BDLOP commitment key `(B0 ∈ R_q^{MU×KAPPA}, b1 ∈ R_q^{KAPPA})`, expanded from the CRS.
pub struct CommitKey {
    /// Row-major `B0` (`MU·KAPPA` ring elements).
    b0: Vec<Rq>,
    /// Message row `b1` (`KAPPA` ring elements).
    b1: Vec<Rq>,
}

/// A BDLOP commitment `C = (t0, t1)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commitment {
    /// Binding part `t0 = B0·ρ` (`MU` ring elements).
    pub t0: Vec<Rq>,
    /// Message part `t1 = ⟨b1, ρ⟩ + a`.
    pub t1: Rq,
}

/// A Fiat–Shamir proof of correct sharing for one recipient (compressed: challenge + response).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareProof {
    /// Sparse challenge `c`.
    pub c: Rq,
    /// Response `z = y + c·ρ`, flattened to `threshold·KAPPA` ring elements (block `i` = coeff `i`).
    pub z: Vec<Rq>,
}

/// Process-wide cached commitment key (the CRS matrices are deterministic, so expand once).
#[must_use]
pub fn key() -> &'static CommitKey {
    use std::sync::OnceLock;
    static K: OnceLock<CommitKey> = OnceLock::new();
    K.get_or_init(commit_key)
}

/// Expand the public commitment key from [`COMMIT_MATRIX_SEED`].
#[must_use]
pub fn commit_key() -> CommitKey {
    let mut b0 = Vec::with_capacity(MU * KAPPA);
    for r in 0..MU {
        for c in 0..KAPPA {
            b0.push(expand_cell(b"B0", r, c));
        }
    }
    let mut b1 = Vec::with_capacity(KAPPA);
    for c in 0..KAPPA {
        b1.push(expand_cell(b"b1", 0, c));
    }
    CommitKey { b0, b1 }
}

/// Expand one uniform `R_q` matrix cell from the CRS seed, domain-separated by `(label, row, col)`.
fn expand_cell(label: &[u8], row: usize, col: usize) -> Rq {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(&COMMIT_MATRIX_SEED);
    h.update(label);
    h.update(&(row as u32).to_le_bytes());
    h.update(&(col as u32).to_le_bytes());
    let mut rd = h.finalize_xof();
    let q = Q as u64;
    let zone = u64::MAX - (u64::MAX % q);
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
    Rq { coeffs }
}

/// Sample fresh ternary commitment randomness `ρ ∈ R_q^KAPPA`.
pub fn sample_randomness<R: CryptoRng + Rng>(rng: &mut R) -> [Rq; KAPPA] {
    core::array::from_fn(|_| sample_ternary_poly(rng))
}

/// `B0·ρ` (`MU` ring elements).
fn b0_apply(key: &CommitKey, rho: &[Rq]) -> Vec<Rq> {
    debug_assert_eq!(rho.len(), KAPPA);
    let mut out = Vec::with_capacity(MU);
    for r in 0..MU {
        let mut acc = Rq::zero();
        for (c, rc) in rho.iter().enumerate() {
            acc = ring_add(&acc, &ring_mul(&key.b0[r * KAPPA + c], rc));
        }
        out.push(acc);
    }
    out
}

/// `⟨b1, ρ⟩` (one ring element).
fn b1_apply(key: &CommitKey, rho: &[Rq]) -> Rq {
    debug_assert_eq!(rho.len(), KAPPA);
    let mut acc = Rq::zero();
    for (c, rc) in rho.iter().enumerate() {
        acc = ring_add(&acc, &ring_mul(&key.b1[c], rc));
    }
    acc
}

/// Commit to message `a` with randomness `ρ`: `C = (B0·ρ, ⟨b1, ρ⟩ + a)`.
#[must_use]
pub fn commit(key: &CommitKey, a: &Rq, rho: &[Rq; KAPPA]) -> Commitment {
    Commitment {
        t0: b0_apply(key, rho),
        t1: ring_add(&b1_apply(key, rho), a),
    }
}

/// The zero commitment (identity for [`commit_add`]).
#[must_use]
pub fn commit_zero() -> Commitment {
    Commitment {
        t0: (0..MU).map(|_| Rq::zero()).collect(),
        t1: Rq::zero(),
    }
}

/// Homomorphic sum `C_a + C_b`.
#[must_use]
pub fn commit_add(a: &Commitment, b: &Commitment) -> Commitment {
    Commitment {
        t0: a
            .t0
            .iter()
            .zip(b.t0.iter())
            .map(|(x, y)| ring_add(x, y))
            .collect(),
        t1: ring_add(&a.t1, &b.t1),
    }
}

/// Homomorphic integer scaling `k·C` (used for the `jⁱ` weights of the Feldman relation).
#[must_use]
pub fn commit_scale(c: &Commitment, k: i64) -> Commitment {
    Commitment {
        t0: c.t0.iter().map(|x| scalar_mul(x, k)).collect(),
        t1: scalar_mul(&c.t1, k),
    }
}

/// `Σ_i jⁱ·C_i` — the homomorphic combination the verifier compares against.
#[must_use]
pub fn eval_commitments(commitments: &[Commitment], j: u8) -> Commitment {
    let mut acc = commit_zero();
    for (i, c) in commitments.iter().enumerate() {
        acc = commit_add(&acc, &commit_scale(c, pow_mod_q(j, i)));
    }
    acc
}

/// `jⁱ mod q` (centered into `[0, q)`); `j ≤ 255`, `i` small.
#[must_use]
pub fn pow_mod_q(j: u8, i: usize) -> i64 {
    let q = Q as u128;
    let base = u128::from(j) % q;
    let mut acc = 1u128 % q;
    for _ in 0..i {
        acc = acc * base % q;
    }
    acc as i64
}

// ---------------------------------------------------------------------------
// Fiat–Shamir proof of correct sharing
// ---------------------------------------------------------------------------

/// `Φ_j(blocks) = (B0·ρ_0, …, B0·ρ_{t-1}, ⟨b1, Σ_i jⁱ·ρ_i⟩)` — `t·MU + 1` ring elements.
fn phi(key: &CommitKey, blocks: &[[Rq; KAPPA]], powers: &[i64]) -> Vec<Rq> {
    let t = blocks.len();
    let mut out = Vec::with_capacity(t * MU + 1);
    for block in blocks {
        out.extend(b0_apply(key, block));
    }
    // Σ_i jⁱ·ρ_i  (column-wise over the KAPPA randomness slots).
    // Heap-backed (`Vec`, not `[Rq; KAPPA]`): each `Rq` is `[i64; N=1024]` ≈ 8 KiB, so an inline
    // `[Rq; KAPPA]` is a ~72 KiB stack temporary that is *live across* the deep `b0_apply`/`ring_mul`/
    // `ntt` call chain. Keeping the BDLOP working set on the heap is what lets the DKG ceremony run on
    // a normal thread stack (retires the 64 MiB dedicated-thread band-aid). `b1_apply` takes `&[Rq]`,
    // so the `Vec` derefs without any signature change; arithmetic and RNG draw order are unchanged.
    let mut combined: Vec<Rq> = (0..KAPPA).map(|_| Rq::zero()).collect();
    for (i, block) in blocks.iter().enumerate() {
        for (slot, bc) in block.iter().enumerate() {
            combined[slot] = ring_add(&combined[slot], &scalar_mul(bc, powers[i]));
        }
    }
    out.push(b1_apply(key, &combined));
    out
}

/// Recompute the prover's first message from the response: `w' = Φ_j(z) − c·u_j`, where
/// `u_j = (t0_0, …, t0_{t-1}, (Σ_i jⁱ·t1_i) − s_j)`.
fn recompute_w(
    key: &CommitKey,
    commitments: &[Commitment],
    powers: &[i64],
    s_j: &Rq,
    c: &Rq,
    z: &[Rq],
) -> Vec<Rq> {
    let t = commitments.len();
    let mut out = Vec::with_capacity(t * MU + 1);
    // First t·MU components: B0·z_i − c·t0_i.
    for (i, com) in commitments.iter().enumerate() {
        let zi = &z[i * KAPPA..(i + 1) * KAPPA];
        let b0z = b0_apply(key, zi);
        for (r, b0zr) in b0z.into_iter().enumerate() {
            out.push(ring_sub(&b0zr, &ring_mul(c, &com.t0[r])));
        }
    }
    // Last component: ⟨b1, Σ_i jⁱ·z_i⟩ − c·(T1_j − s_j).
    // Heap-backed for the same reason as in `phi`: avoid a ~72 KiB inline `[Rq; KAPPA]` stack
    // temporary on the verify hot path. `b1_apply` takes `&[Rq]`; the `Vec` derefs unchanged.
    let mut combined: Vec<Rq> = (0..KAPPA).map(|_| Rq::zero()).collect();
    for (i, _) in commitments.iter().enumerate() {
        let zi = &z[i * KAPPA..(i + 1) * KAPPA];
        for (slot, zc) in zi.iter().enumerate() {
            combined[slot] = ring_add(&combined[slot], &scalar_mul(zc, powers[i]));
        }
    }
    let b1z = b1_apply(key, &combined);
    let mut t1j = Rq::zero();
    for (i, com) in commitments.iter().enumerate() {
        t1j = ring_add(&t1j, &scalar_mul(&com.t1, powers[i]));
    }
    let target_last = ring_sub(&t1j, s_j);
    out.push(ring_sub(&b1z, &ring_mul(c, &target_last)));
    out
}

/// Fiat–Shamir challenge bound to the CRS, dealer/recipient/threshold, all commitments, the claimed
/// share, and the prover's first message `w`.
fn challenge(
    dealer: u8,
    recipient: u8,
    threshold: u8,
    commitments: &[Commitment],
    s_j: &Rq,
    w: &[Rq],
) -> Rq {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(b"lib-q-dkg/bdlop/share-proof/v1");
    h.update(&COMMIT_MATRIX_SEED);
    h.update(&[dealer, recipient, threshold]);
    for com in commitments {
        for p in &com.t0 {
            absorb_poly(&mut h, p);
        }
        absorb_poly(&mut h, &com.t1);
    }
    absorb_poly(&mut h, s_j);
    for p in w {
        absorb_poly(&mut h, p);
    }
    let mut seed = [0u8; 32];
    let mut rd = h.finalize_xof();
    XofReader::read(&mut rd, &mut seed);
    sample_in_ball(&seed, TAU)
}

fn absorb_poly(h: &mut lib_q_sha3::Shake256, p: &Rq) {
    for c in centered_coeffs(p) {
        h.update(&c.to_le_bytes());
    }
}

/// Centered integer inner product over a slice of ring elements.
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

/// Prove that `s_j = f(j)` is the correct evaluation, given the dealer's secret coefficient
/// randomness `rho_coeffs[i]` (the witness). Returns `None` if rejection sampling exhausts
/// `MAX_ATTEMPTS` (vanishingly unlikely).
#[allow(clippy::too_many_arguments)]
pub fn prove_share<R: CryptoRng + Rng>(
    rng: &mut R,
    key: &CommitKey,
    dealer: u8,
    recipient: u8,
    threshold: u8,
    commitments: &[Commitment],
    rho_coeffs: &[[Rq; KAPPA]],
    s_j: &Rq,
) -> Option<ShareProof> {
    let t = usize::from(threshold);
    debug_assert_eq!(commitments.len(), t);
    debug_assert_eq!(rho_coeffs.len(), t);
    let s_y = mask_width(t);
    let beta = response_bound(t);
    let powers: Vec<i64> = (0..t).map(|i| pow_mod_q(recipient, i)).collect();

    // v_i = c·ρ_i depends on the challenge; the witness ρ flattened for inner products.
    let rho_flat: Vec<Rq> = rho_coeffs.iter().flatten().cloned().collect();
    let s2 = s_y * s_y;

    for _ in 0..MAX_ATTEMPTS {
        // Mask y: t blocks of KAPPA Gaussian ring elements.
        let y_blocks: Vec<[Rq; KAPPA]> = (0..t)
            .map(|_| sample_discrete_gaussian_block::<R, KAPPA>(rng, s_y))
            .collect();
        let w = phi(key, &y_blocks, &powers);
        let c = challenge(dealer, recipient, threshold, commitments, s_j, &w);

        // z = y + c·ρ.
        let y_flat: Vec<Rq> = y_blocks.iter().flatten().cloned().collect();
        let v: Vec<Rq> = rho_flat.iter().map(|ri| ring_mul(&c, ri)).collect();
        let z: Vec<Rq> = y_flat
            .iter()
            .zip(v.iter())
            .map(|(yi, vi)| ring_add(yi, vi))
            .collect();

        // Lyubashevsky rejection: accepted z ~ D_{s_y} independent of ρ.
        let norm_v_sq = l2_sq(&v);
        let norm_v = norm_v_sq.sqrt();
        let zv = inner(&z, &v) as f64;
        let log_ratio = -core::f64::consts::PI * (2.0 * zv - norm_v_sq) / s2;
        let log_m = REJECT_KAPPA * norm_v * (2.0 * core::f64::consts::PI).sqrt() / s_y;
        let accept = (log_ratio - log_m).exp().min(1.0);
        // Isochronous accept/abort: evaluate both predicates every iteration (no `&&` short-circuit).
        // The proof of correct sharing is HVZK and the witness ρ is short ternary, but the iteration
        // count and the float `exp` remain data-dependent — see `SECURITY_ANALYSIS.md` §8.
        let prob_ok = uniform_unit(rng) < accept;
        let norm_ok = infinity_norm(&z) <= beta;
        if prob_ok & norm_ok {
            return Some(ShareProof { c, z });
        }
    }
    None
}

/// Verify a proof of correct sharing: `s_j` is bound to `f(j)` of the committed polynomial.
#[must_use]
pub fn verify_share(
    key: &CommitKey,
    dealer: u8,
    recipient: u8,
    threshold: u8,
    commitments: &[Commitment],
    s_j: &Rq,
    proof: &ShareProof,
) -> bool {
    let t = usize::from(threshold);
    if commitments.len() != t || proof.z.len() != t * KAPPA {
        return false;
    }
    if infinity_norm(&proof.z) > response_bound(t) {
        return false;
    }
    let powers: Vec<i64> = (0..t).map(|i| pow_mod_q(recipient, i)).collect();
    let w = recompute_w(key, commitments, &powers, s_j, &proof.c, &proof.z);
    let c = challenge(dealer, recipient, threshold, commitments, s_j, &w);
    centered_coeffs(&c) == centered_coeffs(&proof.c)
}

#[cfg(test)]
mod tests {
    use lib_q_random::new_deterministic_rng;

    use super::*;
    use crate::lattice::ring::const_poly;

    /// Build a degree-`t-1` polynomial (coeffs + randomness) and its commitments.
    fn deal<R: CryptoRng + Rng>(
        rng: &mut R,
        key: &CommitKey,
        coeffs: &[Rq],
    ) -> (Vec<[Rq; KAPPA]>, Vec<Commitment>) {
        let rhos: Vec<[Rq; KAPPA]> = coeffs.iter().map(|_| sample_randomness(rng)).collect();
        let comms: Vec<Commitment> = coeffs
            .iter()
            .zip(rhos.iter())
            .map(|(a, r)| commit(key, a, r))
            .collect();
        (rhos, comms)
    }

    fn eval(coeffs: &[Rq], j: u8) -> Rq {
        let mut acc = Rq::zero();
        for (i, a) in coeffs.iter().enumerate() {
            acc = ring_add(&acc, &scalar_mul(a, pow_mod_q(j, i)));
        }
        acc
    }

    #[test]
    fn commitment_is_homomorphic() {
        let mut rng = new_deterministic_rng([0x01u8; 32]);
        let key = commit_key();
        let a = const_poly(12345);
        let b = const_poly(67890);
        let ra = sample_randomness(&mut rng);
        let rb = sample_randomness(&mut rng);
        let ca = commit(&key, &a, &ra);
        let cb = commit(&key, &b, &rb);
        // commit_add corresponds to message a+b with randomness ra+rb.
        let sum_rho: [Rq; KAPPA] = core::array::from_fn(|i| ring_add(&ra[i], &rb[i]));
        let direct = commit(&key, &ring_add(&a, &b), &sum_rho);
        assert_eq!(commit_add(&ca, &cb), direct);
    }

    #[test]
    fn honest_share_proof_verifies() {
        let mut rng = new_deterministic_rng([0x02u8; 32]);
        let key = commit_key();
        let coeffs = [const_poly(7), const_poly(11), const_poly(13)]; // t = 3
        let (rhos, comms) = deal(&mut rng, &key, &coeffs);
        for recipient in 1u8..=5 {
            let s_j = eval(&coeffs, recipient);
            let proof =
                prove_share(&mut rng, &key, 1, recipient, 3, &comms, &rhos, &s_j).expect("prove");
            assert!(verify_share(&key, 1, recipient, 3, &comms, &s_j, &proof));
        }
    }

    #[test]
    fn kernel_injected_share_is_rejected() {
        let mut rng = new_deterministic_rng([0x03u8; 32]);
        let key = commit_key();
        let coeffs = [const_poly(7), const_poly(11), const_poly(13)];
        let (rhos, comms) = deal(&mut rng, &key, &coeffs);
        let recipient = 2u8;
        let s_j = eval(&coeffs, recipient);
        let proof =
            prove_share(&mut rng, &key, 1, recipient, 3, &comms, &rhos, &s_j).expect("prove");
        // A different claimed share with the SAME proof must be rejected (no valid proof exists for
        // a wrong value; the recomputed challenge will not match).
        let wrong = ring_add(&s_j, &const_poly(1));
        assert!(!verify_share(&key, 1, recipient, 3, &comms, &wrong, &proof));
    }

    #[test]
    fn proof_does_not_transfer_across_recipients() {
        let mut rng = new_deterministic_rng([0x04u8; 32]);
        let key = commit_key();
        let coeffs = [const_poly(2), const_poly(3), const_poly(5)];
        let (rhos, comms) = deal(&mut rng, &key, &coeffs);
        let s1 = eval(&coeffs, 1);
        let proof1 = prove_share(&mut rng, &key, 1, 1, 3, &comms, &rhos, &s1).expect("prove");
        // The recipient-1 proof must not verify the (correct) recipient-2 share.
        let s2 = eval(&coeffs, 2);
        assert!(!verify_share(&key, 1, 2, 3, &comms, &s2, &proof1));
    }
}
