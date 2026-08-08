//! R3 relation **assembly** (design §4.1) — the ciphertext public-input binding.
//!
//! Turns the *ring* statement the KEM encryption satisfies,
//! ```text
//!     p_k = Σ_r B0_{r,k}·e_r + f_k                 (mod X^N+1),   k = 0..KAPPA
//!     v   = Σ_r t0_r·e_r + g + encode(μ)           (mod X^N+1)
//! ```
//! into the *scalar* `Z_q` relations that [`crate::zq::RelationCheckAir`] proves, by pairing the
//! already-reduced residual with a public random vector `κ ∈ Z_q^N` drawn from the statement.
//!
//! For R3a column `k`, write the residual `D_{p_k} = Σ_r B0_{r,k}·e_r + f_k − p_k ∈ R_q` (reduced).
//! The claim `D_{p_k} = 0` is tested as `⟨D_{p_k}, κ⟩ = 0`, and [`corr_negacyclic`] turns the
//! convolution into a linear form over the witness with PUBLIC coefficients:
//! ```text
//!     Σ_r ⟨e_r, ψ_{r,k}⟩ + ⟨f_k, κ⟩ − ⟨p_k, κ⟩ = 0   (in Z_q),  ψ_{r,k} = corr_negacyclic(B0_{r,k}, κ)
//! ```
//! In the canonical `Σ_j a_j·w_j + c ≡ 0 (mod q)` form (all coefficients `∈ [0,q)`, negatives folded
//! as `q − x`), every witness term enters with weight 1:
//! ```text
//!     a = [ 1, …, 1 (the MU e_r folds),  1 (F_k) ]
//!     w = [ ⟨e_0, ψ_{0,k}⟩, …,           ⟨f_k, κ⟩ ]
//!     c = q − ⟨p_k, κ⟩
//! ```
//! and the analogous R3b for `v` (extra `⟨g, κ⟩` and `⟨encode(μ), κ⟩` terms). The `KAPPA + 1`
//! relations of one challenge are ρ-BATCHED into a single check (see
//! [`combine_public_multipliers`]), which is also what keeps the `MU` `e_r` folds shared across them.
//!
//! **What is public vs. witness.** `κ`, `ρ`, every `ψ`, `a` and `c` are computed by the VERIFIER from
//! public data (the DKG matrix `B0`, the ciphertext `p_k`/`v`, the public key `t0`) — nothing here is
//! prover-supplied. The witness contributes only the coefficient columns `e`, `f`, `g` and `μ`, each
//! pinned by the byte-provenance layer's COEFF buses. **There is no quotient and no free fold.**
//!
//! ## What this replaced, and why (card `t_a73aaed2`)
//! The superseded design lifted each ring identity to `Z_q[X]`, wrote `D(X) = H(X)·(X^N+1)`, and
//! evaluated at a scalar Fiat-Shamir point `ζ`. Evaluation-at-`ζ` is a ring homomorphism on
//! `Z_q[X]/(X^N+1)` only when `ζ^N = −1`, so the reduction had to be witnessed by the quotient `H` —
//! a free, prover-chosen coefficient column committed AFTER `ζ` was fixed by the statement, entering
//! the relation with the nonzero public coefficient `−(ζ^N+1)`. The prover could therefore always set
//! `H(ζ) := D(ζ)/(ζ^N+1)`, making the check **vacuous for every ciphertext**. Confirmed by exploit at
//! every tier, including the "complete closure" tier at production FRI parameters with both `m = 1`
//! and `m = 3` challenges. Schwartz-Zippel never applied: it requires the polynomial to be fixed
//! BEFORE the evaluation point is drawn.
//!
//! This module is pure `Z_q` arithmetic (no AIR); it feeds [`crate::zq::generate_relation_trace`]
//! (public `a`,`c` + witness `w`) and the join-3 boundary opening. [`rq_coeffs_zq`] extracts real `Rq`
//! ring elements into the coefficient vectors these functions consume. The path is validated against
//! the real KEM: `real_ciphertext_functionals_vanish_at_every_challenge` builds a genuine
//! `Ciphertext`, re-derives the witness, and confirms every R3a column + R3b functional vanishes at
//! `N = 1024` — which passes only if this module's negacyclic sign table agrees with the KEM's NTT
//! ring multiplication.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use lib_q_dkg::lattice::ring::Rq;
use lib_q_sha3::{
    ExtendableOutput,
    Update,
    XofReader,
};

use crate::zq::Q;

/// Domain separator for the `κ` random-linear-functional challenge vectors (card `t_a73aaed2`).
pub const DOM_KAPPA: &[u8] = b"lib-q-zk-encryption-proof/r3-kappa/v1";

/// Domain separator for the `ρ` relation-batching scalars. **Must** differ from [`DOM_KAPPA`]: the
/// soundness bound treats `ρ` and `κ` as independent draws, and a shared tag would make them a
/// single correlated stream.
pub const DOM_RHO: &[u8] = b"lib-q-zk-encryption-proof/r3-rho/v1";

/// Rejection-sample `count` uniform `Z_q` elements from `SHAKE-256(dom ‖ statement)`: 48-bit draws,
/// reject `≥ Q`, so the output is uniform on `[0, Q)` with no modulo bias.
fn derive_zq_elements(dom: &[u8], statement: &[u8], count: usize) -> Vec<u64> {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(dom);
    h.update(statement);
    let mut rd = h.finalize_xof();
    let mut out = Vec::with_capacity(count);
    let mut buf = [0u8; 6]; // 48-bit draws (Q < 2^48)
    while out.len() < count {
        rd.read(&mut buf);
        let v = u64::from(buf[0]) |
            (u64::from(buf[1]) << 8) |
            (u64::from(buf[2]) << 16) |
            (u64::from(buf[3]) << 24) |
            (u64::from(buf[4]) << 32) |
            (u64::from(buf[5]) << 40);
        if v < Q {
            out.push(v);
        }
    }
    out
}

/// The `m` independent random-linear-functional challenge vectors `κ_0..κ_{m−1} ∈ Z_q^n` of the
/// statement `(pk_digest ‖ ct_bytes)`.
///
/// Absorbing `pk_digest` alongside the ciphertext gives multi-target separation; the verifier
/// recomputes these identically from `(t0, ct)`, so they are never prover-supplied. One XOF stream is
/// split into `m` consecutive length-`n` blocks — consecutive SHAKE output blocks are independent, so
/// no per-index tag is needed *within* `κ` (the tag that matters is [`DOM_KAPPA`] vs [`DOM_RHO`]).
#[must_use]
pub fn statement_kappas(
    pk_digest: &[u8; 32],
    ct_bytes: &[u8],
    m: usize,
    n: usize,
) -> Vec<Vec<u64>> {
    let stmt = statement_bytes(pk_digest, ct_bytes);
    let flat = derive_zq_elements(DOM_KAPPA, &stmt, m * n);
    flat.chunks_exact(n).map(<[u64]>::to_vec).collect()
}

/// The `m` sets of `k` relation-batching scalars `ρ` of the statement `(pk_digest ‖ ct_bytes)`, drawn
/// under [`DOM_RHO`] so they are independent of the [`statement_kappas`] draw.
#[must_use]
pub fn statement_rhos(pk_digest: &[u8; 32], ct_bytes: &[u8], m: usize, k: usize) -> Vec<Vec<u64>> {
    let stmt = statement_bytes(pk_digest, ct_bytes);
    let flat = derive_zq_elements(DOM_RHO, &stmt, m * k);
    flat.chunks_exact(k).map(<[u64]>::to_vec).collect()
}

/// `pk_digest ‖ ct_bytes` — the statement every challenge derivation absorbs.
fn statement_bytes(pk_digest: &[u8; 32], ct_bytes: &[u8]) -> Vec<u8> {
    let mut stmt = Vec::with_capacity(32 + ct_bytes.len());
    stmt.extend_from_slice(pk_digest);
    stmt.extend_from_slice(ct_bytes);
    stmt
}

/// The **negacyclic correlation** `ψ_b = Σ_a u_a · s(a,b) · κ_{(a+b) mod n}`, with the negacyclic sign
/// `s(a,b) = +1` when `a+b < n` and `−1` otherwise.
///
/// This is the whole of the soundness fix for card `t_a73aaed2`, so it is worth stating why.
/// Evaluating a `Z_q[X]/(X^N+1)` identity at a point `ζ` is a ring homomorphism **only** when
/// `ζ^N = −1`; for a generic `ζ` the reduction has to be witnessed by a quotient polynomial `H`, and
/// `H` is a free prover-chosen trace committed *after* `ζ` is fixed by the statement — so the prover
/// simply solves the relation for `H(ζ)` and the check proves nothing. (Confirmed by exploit at every
/// tier, at production FRI parameters.)
///
/// Instead, test the *already reduced* residual `D ∈ R_q` with a random **additive** functional
/// `⟨D, κ⟩`. The identity below is what makes that cheap: for the negacyclic product
/// `(u ⊛ w)_i = Σ_{a+b=i} u_a w_b − Σ_{a+b=i+n} u_a w_b`,
///
/// ```text
/// ⟨u ⊛ w, κ⟩ = Σ_b w_b · ψ_b
/// ```
///
/// so when `u` is PUBLIC (`t0_r`, `B0_{r,k}`) the whole convolution collapses to a **linear form in
/// the witness `w`'s coefficients with publicly computable coefficients**. No quotient exists to be
/// free, and every operand of the fold is a coefficient column already pinned by the byte-provenance
/// COEFF buses. Soundness is then `Pr_κ[⟨D,κ⟩ = 0 | D ≠ 0] = 1/q` per challenge (`q` prime), against
/// the `(2N−2)/q` the superseded design claimed but did not achieve.
///
/// The sign table is load-bearing: dropping `s(a,b)` yields a *cyclic* correlation, which is a
/// different (wrong) form — see `corr_negacyclic_sign_is_load_bearing`.
///
/// `u` and `κ` are truncated / zero-extended to length `n`.
#[must_use]
pub fn corr_negacyclic(u: &[u64], kappa: &[u64], n: usize) -> Vec<u64> {
    let qq = u128::from(Q);
    let mut psi = alloc::vec![0u128; n];
    for (a, &ua) in u.iter().take(n).enumerate() {
        let ua = u128::from(ua % Q);
        if ua == 0 {
            continue;
        }
        for (b, out) in psi.iter_mut().enumerate() {
            let idx = a + b;
            let k = u128::from(kappa.get(idx % n).copied().unwrap_or(0) % Q);
            let term = (ua * k) % qq;
            *out = if idx < n {
                (*out + term) % qq
            } else {
                (*out + qq - term) % qq
            };
        }
    }
    psi.into_iter().map(|x| x as u64).collect()
}

/// `Σ_i a_i·b_i (mod q)` — the public side of a `⟨·, κ⟩` pairing (used for `⟨v, κ⟩`, `⟨p_k, κ⟩`).
#[must_use]
pub fn dot_zq(a: &[u64], b: &[u64]) -> u64 {
    let qq = u128::from(Q);
    let mut acc: u128 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        acc = (acc + (u128::from(x % Q) * u128::from(y % Q)) % qq) % qq;
    }
    acc as u64
}

/// `a + Σ_k ρ_k·b_k (mod q)`, coefficient-wise over length-`n` vectors — the `ρ`-batching of the
/// public multiplier polynomials, applied BEFORE the correlation. Correctness relies on
/// [`corr_negacyclic`] being linear in `u`, which is what lets the `MU` `e_r` folds stay shared across
/// a challenge's `KAPPA + 1` relations instead of needing one fold per relation.
#[must_use]
pub fn combine_public_multipliers(a: &[u64], rhos: &[u64], b: &[&[u64]], n: usize) -> Vec<u64> {
    let qq = u128::from(Q);
    let mut out: Vec<u128> = (0..n)
        .map(|i| u128::from(a.get(i).copied().unwrap_or(0) % Q))
        .collect();
    for (&rho, bk) in rhos.iter().zip(b.iter()) {
        let r = u128::from(rho % Q);
        for (i, o) in out.iter_mut().enumerate() {
            *o = (*o + r * u128::from(bk.get(i).copied().unwrap_or(0) % Q)) % qq;
        }
    }
    out.into_iter().map(|x| x as u64).collect()
}

/// Negacyclic product `a ⊛ b` in `Z_q[X]/(X^n+1)` — the reference the `ψ` correlation is cross-checked
/// against in tests, and the multiplication the KEM itself performs.
#[must_use]
pub fn negacyclic_mul(a: &[u64], b: &[u64], n: usize) -> Vec<u64> {
    reduce_cyclotomic(&poly_mul_full(a, b), n)
}

/// Extract a ring element's coefficients as `Z_q` values in `[0, Q)`, low-order first. `Rq` already
/// stores non-negative canonical coefficients (`[i64; N]`, each `∈ [0, Q)`), so this is a straight
/// widening. This is the entry point for the ciphertext public-input binding: `B0`, `t0`, `p`, `v`
/// (and the witness `e`/`f`/`g`/`encode(μ)`) are all `Rq`, and the relation assembly consumes their
/// coefficient vectors.
#[must_use]
pub fn rq_coeffs_zq(rq: &Rq) -> Vec<u64> {
    rq.coeffs.iter().map(|&c| c as u64).collect()
}

/// Horner evaluation of a `Z_q` polynomial (`coeffs` low-order first, each `< q`) at `ζ`, mod `q`.
pub fn poly_eval_zq(coeffs: &[u64], zeta: u64) -> u64 {
    let qq = u128::from(Q);
    let z = u128::from(zeta % Q);
    let mut acc: u128 = 0;
    for &c in coeffs.iter().rev() {
        acc = (acc * z + u128::from(c % Q)) % qq;
    }
    acc as u64
}

/// Full (un-reduced) schoolbook product of two `Z_q` polynomials — degree `len(a)+len(b)−2`.
fn poly_mul_full(a: &[u64], b: &[u64]) -> Vec<u64> {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    let qq = u128::from(Q);
    let mut out = alloc::vec![0u128; a.len() + b.len() - 1];
    for (i, &ai) in a.iter().enumerate() {
        let ai = u128::from(ai % Q);
        for (j, &bj) in b.iter().enumerate() {
            out[i + j] = (out[i + j] + ai * u128::from(bj % Q)) % qq;
        }
    }
    out.into_iter().map(|x| x as u64).collect()
}

/// Reduce a polynomial mod `X^N + 1` over `Z_q` (`X^N ≡ −1`, so coefficient `i` folds to `i mod N`
/// with sign `(−1)^(i div N)`), yielding a length-`n` polynomial.
pub fn reduce_cyclotomic(poly: &[u64], n: usize) -> Vec<u64> {
    let qq = u128::from(Q);
    let mut out = alloc::vec![0u128; n];
    for (i, &c) in poly.iter().enumerate() {
        let slot = i % n;
        if (i / n).is_multiple_of(2) {
            out[slot] = (out[slot] + u128::from(c % Q)) % qq;
        } else {
            // subtract: add q − c
            out[slot] = (out[slot] + qq - u128::from(c % Q)) % qq;
        }
    }
    out.into_iter().map(|x| x as u64).collect()
}

#[cfg(test)]
mod tests {
    use lib_q_dkg::lattice::bdlop::{
        KAPPA,
        MU,
        key,
    };
    use lib_q_dkg::lattice::ring::{
        N,
        Rq,
    };
    use lib_q_threshold_kem_lattice::kem::{
        encapsulate_derand,
        encode_msg,
        fo_expand_witness,
        pk_digest_of,
    };

    use super::*;

    /// A deterministic pseudo-random `Z_q` vector — test data only, not a challenge derivation.
    fn prand(seed: u64, n: usize) -> Vec<u64> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                // xorshift64*, reduced into [0, Q).
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 8) % Q
            })
            .collect()
    }

    /// The **defining property** of [`corr_negacyclic`]: pairing the negacyclic product `u ⊛ w`
    /// with `κ` equals pairing `w` alone with the public correlation `ψ = corr(u, κ)`. This is what
    /// lets the `t0`/`B0` side of every R3 relation stay public while only the witness is folded.
    #[test]
    fn corr_negacyclic_matches_the_negacyclic_product() {
        for (trial, n) in [(0u64, 1usize), (1, 2), (2, 3), (3, 8), (4, 17), (5, 32)] {
            let u = prand(trial * 7 + 1, n);
            let w = prand(trial * 7 + 2, n);
            let kappa = prand(trial * 7 + 3, n);
            let lhs = dot_zq(&negacyclic_mul(&u, &w, n), &kappa);
            let rhs = dot_zq(&w, &corr_negacyclic(&u, &kappa, n));
            assert_eq!(lhs, rhs, "correlation identity must hold at n = {n}");
        }
    }

    /// **Positive control for the test above.** The negacyclic sign `s(a,b)` is load-bearing: the
    /// same computation with a *cyclic* correlation (sign dropped) must NOT match the negacyclic
    /// product. Without this, `corr_negacyclic_matches_the_negacyclic_product` could be passing for
    /// a reason that has nothing to do with the sign table.
    #[test]
    fn corr_negacyclic_sign_is_load_bearing() {
        let n = 8usize;
        let mut mismatches = 0;
        for trial in 0..16u64 {
            let u = prand(trial * 11 + 1, n);
            let w = prand(trial * 11 + 2, n);
            let kappa = prand(trial * 11 + 3, n);
            // Cyclic (WRONG) correlation: same expression with s(a,b) ≡ +1.
            let cyclic: Vec<u64> = (0..n)
                .map(|b| {
                    let mut acc: u128 = 0;
                    for (a, &ua) in u.iter().enumerate() {
                        acc =
                            (acc + u128::from(ua) * u128::from(kappa[(a + b) % n])) % u128::from(Q);
                    }
                    acc as u64
                })
                .collect();
            if dot_zq(&negacyclic_mul(&u, &w, n), &kappa) != dot_zq(&w, &cyclic) {
                mismatches += 1;
            }
        }
        assert_eq!(
            mismatches, 16,
            "a sign-less (cyclic) correlation must disagree with the negacyclic product on every \
             trial; if it agrees, the identity test proves nothing"
        );
    }

    /// `corr_negacyclic` is linear in its PUBLIC argument. ρ-batching depends on this: the assembly
    /// combines `t0_r + Σ_k ρ_k·B0_{r,k}` FIRST and correlates ONCE, which is only equal to
    /// correlating each term separately if this holds — and it is what keeps the `MU` `e_r` folds
    /// shared across a challenge's `KAPPA + 1` relations.
    #[test]
    fn corr_negacyclic_is_linear_in_the_public_multiplier() {
        let n = 16usize;
        let kappa = prand(101, n);
        let base = prand(102, n);
        let b: Vec<Vec<u64>> = (0..3).map(|i| prand(200 + i, n)).collect();
        let b_ref: Vec<&[u64]> = b.iter().map(|v| v.as_slice()).collect();
        let rhos = prand(103, 3);

        let combined = combine_public_multipliers(&base, &rhos, &b_ref, n);
        let once = corr_negacyclic(&combined, &kappa, n);

        let mut separately = corr_negacyclic(&base, &kappa, n);
        for (i, bk) in b.iter().enumerate() {
            let ck = corr_negacyclic(bk, &kappa, n);
            for (s, c) in separately.iter_mut().zip(ck.iter()) {
                *s = ((u128::from(*s) + u128::from(rhos[i]) * u128::from(*c)) % u128::from(Q))
                    as u64;
            }
        }
        assert_eq!(
            once, separately,
            "corr must be linear in its public argument"
        );
    }

    /// Challenges are deterministic in the statement, canonical (`< Q`), statement-separated, and
    /// `κ`/`ρ` are drawn under different domain tags so they are not the same stream.
    #[test]
    fn statement_challenges_are_deterministic_and_domain_separated() {
        let pk = [0x5Au8; 32];
        let ct = b"a serialized ciphertext";
        let k1 = statement_kappas(&pk, ct, 2, 8);
        let k2 = statement_kappas(&pk, ct, 2, 8);
        assert_eq!(k1, k2, "κ must be deterministic in the statement");
        assert_eq!(k1.len(), 2);
        assert!(k1.iter().all(|v| v.len() == 8 && v.iter().all(|&x| x < Q)));
        assert_ne!(k1[0], k1[1], "the m blocks must be independent draws");

        let r1 = statement_rhos(&pk, ct, 2, 8);
        assert_eq!(r1, statement_rhos(&pk, ct, 2, 8));
        assert_ne!(
            r1[0], k1[0],
            "ρ and κ must come from separated domains, not one shared stream"
        );

        assert_ne!(k1, statement_kappas(&pk, b"a different ciphertext", 2, 8));
        assert_ne!(k1, statement_kappas(&[0x5Bu8; 32], ct, 2, 8));
    }

    /// **The KEM cross-check, and the reason this module can be trusted at all.** For a GENUINE
    /// ciphertext, the R3b and R3a linear functionals must vanish at every derived challenge:
    ///
    /// ```text
    ///   Σ_r ⟨e_r, corr(t0_r, κ)⟩ + ⟨g, κ⟩ + ⟨encode(μ), κ⟩ − ⟨v, κ⟩            ≡ 0
    ///   Σ_r ⟨e_r, corr(B0_{r,k}, κ)⟩ + ⟨f_k, κ⟩ − ⟨p_k, κ⟩                     ≡ 0
    /// ```
    ///
    /// This passes only if `corr_negacyclic`'s sign table agrees with the ring multiplication the
    /// KEM's NTT actually performs — an independent implementation, at the production `N = 1024`.
    #[test]
    fn real_ciphertext_functionals_vanish_at_every_challenge() {
        let t0: Vec<Rq> = (0..MU)
            .map(|r| {
                let mut c = [0i64; N];
                for (i, ci) in c.iter_mut().enumerate() {
                    *ci = (i as i64 * 29 + r as i64 * 11) % Q as i64;
                }
                Rq::from_coeffs(c)
            })
            .collect();
        let mu = [0xC3u8; 32];
        let ct = encapsulate_derand(&t0, &mu);
        let w = fo_expand_witness(&t0, &mu);
        let pk_digest = pk_digest_of(&t0);
        let b0 = key().b0();

        let e_lifts: Vec<Vec<u64>> = w.e.iter().map(rq_coeffs_zq).collect();
        let g_z = rq_coeffs_zq(&w.g);
        let encode_z = rq_coeffs_zq(&encode_msg(&mu));
        let v_z = rq_coeffs_zq(&ct.v);
        let t0_cols: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();

        let kappas = statement_kappas(&pk_digest, &ct.to_bytes(), 3, N);
        assert_eq!(kappas.len(), 3);

        for kappa in &kappas {
            // R3b.
            let qq = u128::from(Q);
            let mut acc: u128 = 0;
            for (e, t) in e_lifts.iter().zip(t0_cols.iter()) {
                acc = (acc + u128::from(dot_zq(e, &corr_negacyclic(t, kappa, N)))) % qq;
            }
            acc = (acc + u128::from(dot_zq(&g_z, kappa))) % qq;
            acc = (acc + u128::from(dot_zq(&encode_z, kappa))) % qq;
            acc = (acc + qq - u128::from(dot_zq(&v_z, kappa))) % qq;
            assert_eq!(
                acc, 0,
                "R3b functional must vanish for a genuine ciphertext"
            );

            // R3a, every column.
            for k in 0..KAPPA {
                let mut acc: u128 = 0;
                for (r, e) in e_lifts.iter().enumerate() {
                    let b0_rk = rq_coeffs_zq(&b0[r * KAPPA + k]);
                    acc = (acc + u128::from(dot_zq(e, &corr_negacyclic(&b0_rk, kappa, N)))) % qq;
                }
                let f_k = rq_coeffs_zq(&w.f[k]);
                let p_k = rq_coeffs_zq(&ct.p[k]);
                acc = (acc + u128::from(dot_zq(&f_k, kappa))) % qq;
                acc = (acc + qq - u128::from(dot_zq(&p_k, kappa))) % qq;
                assert_eq!(acc, 0, "R3a column {k} functional must vanish");
            }
        }
    }

    /// **The soundness direction, and the property the superseded design did not have.** Perturb one
    /// ciphertext coefficient and the R3b functional becomes non-zero at every challenge — with NO
    /// free term anywhere for a prover to solve for. Under the old evaluation-at-ζ relation the same
    /// tamper was absorbed by the quotient fold, which is exactly the break this replaced.
    #[test]
    fn tampered_ciphertext_functional_is_nonzero() {
        let t0: Vec<Rq> = (0..MU)
            .map(|r| {
                let mut c = [0i64; N];
                for (i, ci) in c.iter_mut().enumerate() {
                    *ci = (i as i64 * 31 + r as i64 * 7) % Q as i64;
                }
                Rq::from_coeffs(c)
            })
            .collect();
        let mu = [0x6Bu8; 32];
        let mut ct = encapsulate_derand(&t0, &mu);
        let w = fo_expand_witness(&t0, &mu);
        let pk_digest = pk_digest_of(&t0);
        ct.v.coeffs[0] = (ct.v.coeffs[0] + 1) % (Q as i64);

        let e_lifts: Vec<Vec<u64>> = w.e.iter().map(rq_coeffs_zq).collect();
        let g_z = rq_coeffs_zq(&w.g);
        let encode_z = rq_coeffs_zq(&encode_msg(&mu));
        let v_z = rq_coeffs_zq(&ct.v);
        let t0_cols: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();

        let qq = u128::from(Q);
        for kappa in &statement_kappas(&pk_digest, &ct.to_bytes(), 3, N) {
            let mut acc: u128 = 0;
            for (e, t) in e_lifts.iter().zip(t0_cols.iter()) {
                acc = (acc + u128::from(dot_zq(e, &corr_negacyclic(t, kappa, N)))) % qq;
            }
            acc = (acc + u128::from(dot_zq(&g_z, kappa))) % qq;
            acc = (acc + u128::from(dot_zq(&encode_z, kappa))) % qq;
            acc = (acc + qq - u128::from(dot_zq(&v_z, kappa))) % qq;
            assert_ne!(
                acc, 0,
                "a tampered ciphertext must break the functional (chance of a false pass: 1/q ≈ 2^-48)"
            );
        }
    }

    /// `reduce_cyclotomic` implements `X^N ≡ −1`: coefficient `i + n` folds into slot `i` with a
    /// sign flip.
    #[test]
    fn reduce_cyclotomic_negates_the_wrapped_half() {
        let n = 4usize;
        // 1 + 2X + 3X^2 + 4X^3 + 5X^4  ⇒  (1−5) + 2X + 3X^2 + 4X^3
        let poly = [1u64, 2, 3, 4, 5];
        let red = reduce_cyclotomic(&poly, n);
        assert_eq!(red, [(Q - 4) % Q, 2, 3, 4]);
    }

    /// `dot_zq` truncates to the shorter operand and reduces mod q.
    #[test]
    fn dot_zq_is_a_mod_q_inner_product() {
        assert_eq!(dot_zq(&[2, 3, 5], &[7, 11, 13]), 2 * 7 + 3 * 11 + 5 * 13);
        assert_eq!(
            dot_zq(&[Q - 1], &[2]),
            (2 * (Q as u128 - 1) % Q as u128) as u64
        );
        assert_eq!(
            dot_zq(&[1, 1, 1], &[4]),
            4,
            "pairs only over the common prefix"
        );
    }
}
