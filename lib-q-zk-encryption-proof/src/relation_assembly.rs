//! R3 relation **assembly** (design §4.1) — the ciphertext public-input binding.
//!
//! Turns the *ring* statement the KEM encryption satisfies,
//! ```text
//!     p_k = Σ_r B0_{r,k}·e_r + f_k                 (mod X^N+1),   k = 0..KAPPA
//!     v   = Σ_r t0_r·e_r + g + encode(μ)           (mod X^N+1)
//! ```
//! into the *scalar* `Z_q` relations that [`crate::zq::RelationCheckAir`] proves at a public
//! Fiat-Shamir challenge `ζ`. The reduction mod `X^N+1` is witnessed by **quotient** polynomials: the
//! polynomial identity (BEFORE the ring reduction) is
//! ```text
//!     Σ_r B0_{r,k}(X)·e_r(X) + f_k(X) − p_k(X) = (X^N+1)·H_k(X)
//! ```
//! for a quotient `H_k` of degree ≤ N−2 (the LHS is divisible by `X^N+1` because its reduction mod
//! `X^N+1` is `p_k − p_k = 0`). Evaluating at `ζ`:
//! ```text
//!     Σ_r B0_{r,k}(ζ)·E_r + F_k − p_k(ζ) − (ζ^N+1)·H_k(ζ) = 0        (in Z_q)
//! ```
//! with `E_r = e_r(ζ)`, `F_k = f_k(ζ)`, `HK_k = H_k(ζ)` the witness fold values ([`crate::zq`] Horner
//! folds), and `B0_{r,k}(ζ)`, `p_k(ζ)`, `ζ^N+1` public. In the canonical `Σ_j a_j·w_j + c ≡ 0 (mod q)`
//! form (all coefficients `∈ [0,q)`, negatives folded as `q − x`):
//! ```text
//!     a = [ B0_{0,k}(ζ), …, B0_{MU-1,k}(ζ),  1 (F_k),  q − (ζ^N+1) (HK_k) ]
//!     w = [ E_0,          …, E_{MU-1},        F_k,       HK_k              ]
//!     c = q − p_k(ζ)
//! ```
//! and the analogous R3b for `v` (extra `+G` and `+E_encode` terms, `a = 1` each).
//!
//! **What is public vs. witness.** `a` and `c` are computed by the VERIFIER from public data (the
//! DKG matrix `B0`, the ciphertext `p_k`/`v`, the public key `t0`, and `ζ`) — the
//! `*_public_coeffs` functions. The quotient `H_k` is a PROVER witness (it depends on the secret
//! `e`/`f`), folded to `HK_k = H_k(ζ)` — the `*_quotient_poly` functions. `ζ` is a **Fiat-Shamir
//! challenge on the statement** ([`derive_zetas`]): `SHAKE-256(DOM_ZETA ‖ ciphertext)`, which the
//! verifier recomputes and checks against the folds' `ζ` public values. Because `ζ` depends on the
//! ciphertext (which already commits to the witness) and NOT on the trace commitments, no two-phase
//! commitment is needed.
//!
//! This module is pure `Z_q` polynomial arithmetic (no AIR); it feeds
//! [`crate::zq::generate_relation_trace`] (public `a`,`c` + witness `w`) and the join-3 boundary
//! opening. [`rq_coeffs_zq`] extracts real `Rq` ring elements (`B0`, `t0`, `p`, `v`, and the witness)
//! into the coefficient vectors these functions consume; [`derive_zetas`] derives the FS challenges.
//! The whole path is validated against the real KEM: a test builds a genuine `Ciphertext` with
//! `encapsulate_derand`, re-derives the witness with `fo_expand_witness`, derives `ζ` from the
//! ciphertext bytes, and confirms every R3a column + R3b holds at each FS `ζ` at N=1024 (which passes
//! only if this module's schoolbook `poly_mul_full` + `reduce_cyclotomic` agree with the KEM's NTT ring
//! multiplication). **Remaining integration (#26):** assembling all instances into ONE `prove_batch`
//! over real ciphertext data at production FRI params (the `prove`/`verify` entry points).

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use lib_q_dkg::lattice::ring::Rq;
use lib_q_sha3::{
    ExtendableOutput,
    Update,
    XofReader,
};

use crate::zq::Q;

/// Domain separator for the R3 Fiat-Shamir evaluation-challenge derivation. Versioned (`.v0`).
pub const DOM_ZETA: &[u8] = b"lib-q-zk-encryption-proof/r3-zeta/v0";

/// Derive `m` independent Fiat-Shamir evaluation challenges `ζ_0..ζ_{m-1} ∈ [0, Q)` from the public
/// `statement` (the serialized ciphertext — and any other public inputs the caller binds), by
/// rejection sampling from `SHAKE-256(DOM_ZETA ‖ statement)` (48-bit draws, reject `≥ Q` ⇒ uniform in
/// `[0, Q)`, no modulo bias).
///
/// **Soundness (Fiat-Shamir on the statement).** The R3 relation-at-`ζ` argument has error
/// `≤ (2N−2)/q ≈ 2^-37` per challenge (a false polynomial identity of degree `≤ 2N−2` vanishes at a
/// random `ζ` with at most that probability); `m` independent challenges give `≤ ((2N−2)/q)^m`
/// (`m = 4 ⇒ ~2^-148`). `ζ` is a deterministic function of the FIXED statement, so the prover cannot
/// grind it, and — because the witness `(e,f,g)` is itself determined by the ciphertext (the FO
/// expansion the ciphertext commits to) — this is the standard "challenge from a hash of the statement"
/// pattern. **Composition obligation:** the VERIFIER MUST recompute these `ζ` from the ciphertext and
/// check they equal the fold/relation instances' `ζ` public values (analogous to the sponge pk-wiring)
/// — never accept prover-supplied `ζ`. Because `ζ` is a public function of the ciphertext (not of the
/// trace commitments), the fold/relation traces can be built at these `ζ` and committed in one shot; no
/// two-phase commitment is required.
pub fn derive_zetas(statement: &[u8], m: usize) -> Vec<u64> {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(DOM_ZETA);
    h.update(statement);
    let mut rd = h.finalize_xof();
    let mut out = Vec::with_capacity(m);
    let mut buf = [0u8; 6]; // 48-bit draws (Q < 2^48)
    while out.len() < m {
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

/// Extract a ring element's coefficients as `Z_q` values in `[0, Q)`, low-order first. `Rq` already
/// stores non-negative canonical coefficients (`[i64; N]`, each `∈ [0, Q)`), so this is a straight
/// widening. This is the entry point for the ciphertext public-input binding: `B0`, `t0`, `p`, `v`
/// (and the witness `e`/`f`/`g`/`encode(μ)`) are all `Rq`, and the relation assembly consumes their
/// coefficient vectors.
#[must_use]
pub fn rq_coeffs_zq(rq: &Rq) -> Vec<u64> {
    rq.coeffs.iter().map(|&c| c as u64).collect()
}

/// Modular exponentiation `base^exp mod q` (for `ζ^N`).
fn pow_mod(base: u64, exp: u64, q: u64) -> u64 {
    let mut acc: u128 = 1;
    let b = u128::from(base % q);
    let qq = u128::from(q);
    let mut e = exp;
    let mut cur = b;
    while e > 0 {
        if e & 1 == 1 {
            acc = (acc * cur) % qq;
        }
        cur = (cur * cur) % qq;
        e >>= 1;
    }
    acc as u64
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

/// Add `b` into `a` (in place, `Z_q`), growing `a` as needed.
fn poly_add_assign(a: &mut Vec<u64>, b: &[u64]) {
    if a.len() < b.len() {
        a.resize(b.len(), 0);
    }
    for (ai, &bi) in a.iter_mut().zip(b.iter()) {
        *ai = ((u128::from(*ai) + u128::from(bi)) % u128::from(Q)) as u64;
    }
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

/// Divide `d` (assumed exactly divisible) by `X^N + 1` over `Z_q`, returning the quotient `H`
/// (degree ≤ N−2, length `n−1`). Because `D = (X^N+1)·H` with `deg H ≤ N−2`, one has `D_i = H_i` for
/// `i < N−1` (and `D_{N-1} = 0`, `D_{i+N} = H_i` are the divisibility consistency conditions). Returns
/// `None` if the divisibility consistency fails.
pub fn divide_by_cyclotomic(d: &[u64], n: usize) -> Option<Vec<u64>> {
    // H_i = D_i for i in 0..n-1  (n-1 coefficients).
    let mut h = alloc::vec![0u64; n.saturating_sub(1)];
    for (i, hi) in h.iter_mut().enumerate() {
        *hi = *d.get(i).unwrap_or(&0) % Q;
    }
    // consistency: D_{n-1} == 0 and D_{i+n} == H_i for all i.
    let d_top = *d.get(n - 1).unwrap_or(&0);
    if !d_top.is_multiple_of(Q) {
        return None;
    }
    for (i, &hi) in h.iter().enumerate() {
        if *d.get(i + n).unwrap_or(&0) % Q != hi {
            return None;
        }
    }
    Some(h)
}

/// The public coefficients `(a, c)` of the R3a relation for column `k`:
/// `Σ_r B0_{r,k}(ζ)·E_r + F_k − (ζ^N+1)·HK_k − p_k(ζ) ≡ 0`. `b0_cols_k[r]` is `B0_{r,k}`'s `Z_q`
/// coefficients (low-order first); `p_k` is `p_k`'s coefficients; `n` is the ring degree `N`. Returns
/// `a` (length `MU + 2`: the `MU` `B0` evals, then `1` for `F_k`, then `q − (ζ^N+1)` for the quotient)
/// and `c = q − p_k(ζ)`.
pub fn r3a_public_coeffs(
    b0_cols_k: &[&[u64]],
    p_k: &[u64],
    zeta: u64,
    n: usize,
) -> (Vec<u64>, u64) {
    let mut a: Vec<u64> = b0_cols_k.iter().map(|b| poly_eval_zq(b, zeta)).collect();
    a.push(1); // F_k coefficient
    let zeta_n1 = (pow_mod(zeta, n as u64, Q) + 1) % Q;
    a.push((Q - zeta_n1) % Q); // −(ζ^N+1) folded
    let c = (Q - poly_eval_zq(p_k, zeta)) % Q;
    (a, c)
}

/// The R3a quotient polynomial `H_k = (Σ_r B0_{r,k}·e_r + f_k − p_k) / (X^N+1)` (prover witness).
/// `e_lifts[r]` are `e_r`'s mod-q-lifted `Z_q` coefficients. Returns `None` if the numerator is not
/// divisible by `X^N+1` (i.e. the inputs are not a valid encryption).
pub fn r3a_quotient_poly(
    b0_cols_k: &[&[u64]],
    e_lifts: &[&[u64]],
    f_k: &[u64],
    p_k: &[u64],
    n: usize,
) -> Option<Vec<u64>> {
    // D = Σ_r B0_{r,k}·e_r (full) + f_k − p_k.
    let mut d: Vec<u64> = Vec::new();
    for (b0, e) in b0_cols_k.iter().zip(e_lifts.iter()) {
        poly_add_assign(&mut d, &poly_mul_full(b0, e));
    }
    poly_add_assign(&mut d, f_k);
    // subtract p_k: add (q − p_k[i]).
    let neg_p: Vec<u64> = p_k.iter().map(|&x| (Q - x % Q) % Q).collect();
    poly_add_assign(&mut d, &neg_p);
    divide_by_cyclotomic(&d, n)
}

/// The public coefficients `(a, c)` of the R3b relation for `v`:
/// `Σ_r t0_r(ζ)·E_r + G + E_encode − (ζ^N+1)·HK_b − v(ζ) ≡ 0`. `t0[r]` is `t0_r`'s `Z_q` coefficients.
/// Returns `a` (length `MU + 3`: the `MU` `t0` evals, then `1` for `G`, `1` for `E_encode`, then
/// `q − (ζ^N+1)` for the quotient) and `c = q − v(ζ)`.
pub fn r3b_public_coeffs(t0: &[&[u64]], v: &[u64], zeta: u64, n: usize) -> (Vec<u64>, u64) {
    let mut a: Vec<u64> = t0.iter().map(|t| poly_eval_zq(t, zeta)).collect();
    a.push(1); // G coefficient
    a.push(1); // E_encode coefficient
    let zeta_n1 = (pow_mod(zeta, n as u64, Q) + 1) % Q;
    a.push((Q - zeta_n1) % Q); // −(ζ^N+1) folded
    let c = (Q - poly_eval_zq(v, zeta)) % Q;
    (a, c)
}

/// The R3b quotient `H_b = (Σ_r t0_r·e_r + g + encode(μ) − v) / (X^N+1)` (prover witness). `g` and
/// `encode` are the `Z_q` coefficients of the noise and the message embedding. Returns `None` if the
/// numerator is not divisible by `X^N+1`.
pub fn r3b_quotient_poly(
    t0: &[&[u64]],
    e_lifts: &[&[u64]],
    g: &[u64],
    encode: &[u64],
    v: &[u64],
    n: usize,
) -> Option<Vec<u64>> {
    let mut d: Vec<u64> = Vec::new();
    for (t, e) in t0.iter().zip(e_lifts.iter()) {
        poly_add_assign(&mut d, &poly_mul_full(t, e));
    }
    poly_add_assign(&mut d, g);
    poly_add_assign(&mut d, encode);
    let neg_v: Vec<u64> = v.iter().map(|&x| (Q - x % Q) % Q).collect();
    poly_add_assign(&mut d, &neg_v);
    divide_by_cyclotomic(&d, n)
}

#[cfg(test)]
mod tests {
    use lib_q_plonky_lookup::debug_util::{
        LookupDebugInstance,
        check_lookups,
    };
    use lib_q_stark_matrix::dense::RowMajorMatrix;
    use lib_q_zkp::stark::ConfigVal;

    use super::*;
    use crate::logup_join::FOLD_E_BUS;
    use crate::zq::{
        RelationCheckAir,
        generate_horner_trace,
        generate_relation_trace,
        horner_e_send_lookups_at,
    };

    /// Reduce a signed integer into `[0, Q)`.
    fn lift(x: i64) -> u64 {
        x.rem_euclid(Q as i64) as u64
    }

    #[test]
    fn cyclotomic_divide_roundtrips() {
        // H arbitrary (deg ≤ n-2); D = (X^n+1)·H; divide back must recover H.
        let n = 8usize;
        let h: Vec<u64> = [3u64, 1, 4, 1, 5, 9, 2].to_vec(); // length n-1 = 7
        // D = H·X^n + H.
        let mut d = alloc::vec![0u64; 2 * n - 1];
        for (i, &hi) in h.iter().enumerate() {
            d[i] = (d[i] + hi) % Q;
            d[i + n] = (d[i + n] + hi) % Q;
        }
        assert_eq!(divide_by_cyclotomic(&d, n).expect("divisible"), h);
        // reduce(D) mod X^n+1 must be 0 (D divisible).
        assert!(reduce_cyclotomic(&d, n).iter().all(|&c| c == 0));
    }

    #[test]
    fn poly_eval_matches_manual() {
        // (2 + 3X + 5X^2) at ζ=10 = 2 + 30 + 500 = 532.
        assert_eq!(poly_eval_zq(&[2, 3, 5], 10), 532);
    }

    /// **End-to-end R3a on a synthetic instance (MU=2, N=4).** Build a valid encryption column
    /// `p_0 = Σ_r B0_{r,0}·e_r + f_0 (mod X^4+1)`, assemble the public `(a,c)` + the quotient witness,
    /// confirm the scalar relation holds (via `generate_relation_trace`, which rejects a non-relation),
    /// and confirm the fold results `E_r`,`F_0`,`HK_0` bind to the relation's `w` through join 3.
    #[test]
    fn r3a_synthetic_relation_holds_and_binds() {
        let n = 4usize;
        let mu = 2usize;

        // Public B0 column (2 ring polynomials of degree < 4), arbitrary Z_q coeffs.
        let b0_0: Vec<u64> = [11u64, 22, 33, 44].to_vec();
        let b0_1: Vec<u64> = [55u64, 66, 77, 88].to_vec();
        let b0_cols: [&[u64]; 2] = [&b0_0, &b0_1];

        // Secret e (ternary, lifted) and f (small bounded, lifted).
        let e0_s: [i64; 4] = [1, -1, 0, 1];
        let e1_s: [i64; 4] = [0, 1, 1, -1];
        let e0: Vec<u64> = e0_s.iter().map(|&x| lift(x)).collect();
        let e1: Vec<u64> = e1_s.iter().map(|&x| lift(x)).collect();
        let e_lifts: [&[u64]; 2] = [&e0, &e1];
        let f0_s: [i64; 4] = [7, -3, 2, -5];
        let f0: Vec<u64> = f0_s.iter().map(|&x| lift(x)).collect();

        // p_0 = reduce(Σ_r B0_{r,0}·e_r) + f_0   (mod X^4+1).
        let mut acc: Vec<u64> = Vec::new();
        for (b0, e) in b0_cols.iter().zip(e_lifts.iter()) {
            poly_add_assign(&mut acc, &poly_mul_full(b0, e));
        }
        let mut p0 = reduce_cyclotomic(&acc, n);
        poly_add_assign(&mut p0, &f0);

        let zeta = 1_234_567u64;

        // Public coefficients + quotient witness.
        let (a, c) = r3a_public_coeffs(&b0_cols, &p0, zeta, n);
        let hq =
            r3a_quotient_poly(&b0_cols, &e_lifts, &f0, &p0, n).expect("valid encryption divisible");

        // Witness fold values.
        let e_fold0 = poly_eval_zq(&e0, zeta);
        let e_fold1 = poly_eval_zq(&e1, zeta);
        let f_fold = poly_eval_zq(&f0, zeta);
        let h_fold = poly_eval_zq(&hq, zeta);
        let w = [e_fold0, e_fold1, f_fold, h_fold];
        assert_eq!(a.len(), mu + 2);
        assert_eq!(w.len(), mu + 2);

        // The scalar relation Σ a_j·w_j + c ≡ 0 (mod q) must hold — generate_relation_trace enforces it.
        let (relation, _pubs) =
            generate_relation_trace(&a, &w, c).expect("assembled R3a relation must hold mod q");
        let air = RelationCheckAir { num_terms: a.len() };

        // Join 3: each fold's result binds to the matching relation term.
        let (fold_e0, _) = generate_horner_trace(&e0, zeta).unwrap();
        let (fold_e1, _) = generate_horner_trace(&e1, zeta).unwrap();
        let (fold_f, _) = generate_horner_trace(&f0, zeta).unwrap();
        let (fold_h, _) = generate_horner_trace(&hq, zeta).unwrap();

        let recv = air.relation_w_receive_lookups_at(FOLD_E_BUS, 0);
        let none: Option<RowMajorMatrix<ConfigVal>> = None;

        let send0 = horner_e_send_lookups_at(FOLD_E_BUS, 0, 0, 0);
        let send1 = horner_e_send_lookups_at(FOLD_E_BUS, 0, 1, 0);
        let send2 = horner_e_send_lookups_at(FOLD_E_BUS, 0, 2, 0);
        let send3 = horner_e_send_lookups_at(FOLD_E_BUS, 0, 3, 0);

        let balanced = {
            let prev = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_| {}));
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                check_lookups(&[
                    LookupDebugInstance {
                        main_trace: &fold_e0,
                        preprocessed_trace: &none,
                        public_values: &[],
                        lookups: &send0,
                        permutation_challenges: &[],
                    },
                    LookupDebugInstance {
                        main_trace: &fold_e1,
                        preprocessed_trace: &none,
                        public_values: &[],
                        lookups: &send1,
                        permutation_challenges: &[],
                    },
                    LookupDebugInstance {
                        main_trace: &fold_f,
                        preprocessed_trace: &none,
                        public_values: &[],
                        lookups: &send2,
                        permutation_challenges: &[],
                    },
                    LookupDebugInstance {
                        main_trace: &fold_h,
                        preprocessed_trace: &none,
                        public_values: &[],
                        lookups: &send3,
                        permutation_challenges: &[],
                    },
                    LookupDebugInstance {
                        main_trace: &relation,
                        preprocessed_trace: &none,
                        public_values: &[],
                        lookups: &recv,
                        permutation_challenges: &[],
                    },
                ]);
            }));
            std::panic::set_hook(prev);
            r.is_ok()
        };
        assert!(
            balanced,
            "all four fold results (E_0,E_1,F_0,HK_0) must bind to the assembled R3a relation"
        );
    }

    /// **End-to-end R3b on a synthetic instance (MU=2, N=4).** Build a valid `v = Σ_r t0_r·e_r + g +
    /// encode(μ) (mod X^4+1)`, assemble the public `(a,c)` + the quotient witness, and confirm the
    /// scalar relation `Σ a_j·w_j + c ≡ 0 (mod q)` holds (via `generate_relation_trace`).
    #[test]
    fn r3b_synthetic_relation_holds() {
        let n = 4usize;
        let t0_0: Vec<u64> = [13u64, 21, 34, 55].to_vec();
        let t0_1: Vec<u64> = [89u64, 144, 233, 377].to_vec();
        let t0: [&[u64]; 2] = [&t0_0, &t0_1];
        let e0: Vec<u64> = [1i64, 0, -1, 1].iter().map(|&x| lift(x)).collect();
        let e1: Vec<u64> = [-1i64, 1, 0, 1].iter().map(|&x| lift(x)).collect();
        let e_lifts: [&[u64]; 2] = [&e0, &e1];
        let g: Vec<u64> = [4i64, -2, 6, -1].iter().map(|&x| lift(x)).collect();
        let encode: Vec<u64> = [100u64, 0, 200, 0].to_vec(); // synthetic message embedding

        // v = reduce(Σ t0_r·e_r) + g + encode   (mod X^4+1).
        let mut acc: Vec<u64> = Vec::new();
        for (t, e) in t0.iter().zip(e_lifts.iter()) {
            poly_add_assign(&mut acc, &poly_mul_full(t, e));
        }
        let mut v = reduce_cyclotomic(&acc, n);
        poly_add_assign(&mut v, &g);
        poly_add_assign(&mut v, &encode);

        let zeta = 7_654_321u64;
        let (a, c) = r3b_public_coeffs(&t0, &v, zeta, n);
        let hb = r3b_quotient_poly(&t0, &e_lifts, &g, &encode, &v, n).expect("valid v divisible");

        let w = [
            poly_eval_zq(&e0, zeta),
            poly_eval_zq(&e1, zeta),
            poly_eval_zq(&g, zeta),
            poly_eval_zq(&encode, zeta),
            poly_eval_zq(&hb, zeta),
        ];
        assert_eq!(a.len(), 5); // MU + 3
        generate_relation_trace(&a, &w, c).expect("assembled R3b relation must hold mod q");
    }

    /// **Real `B0`, full dimension (N=1024, MU=6, KAPPA=9).** Uses the genuine BDLOP CRS matrix from
    /// `lib-q-dkg` and its real negacyclic-NTT `B0ᵀ·e`, then assembles R3a for column 0 from the
    /// extracted `B0` cells + `p_0 = (B0ᵀe)_0 + f_0`. The quotient exists **only if** this module's
    /// schoolbook `poly_mul_full` + `reduce_cyclotomic` agree with the KEM's NTT ring multiplication
    /// (and both crates' `q` agree) — so this cross-checks the assembly arithmetic against the real KEM
    /// at production scale, and confirms `Σ_r B0_{r,0}(ζ)·E_r + F_0 − (ζ^N+1)·HK_0 − p_0(ζ) ≡ 0 (mod q)`.
    #[test]
    fn r3a_real_b0_relation_holds_at_full_dimension() {
        use lib_q_dkg::lattice::bdlop::{
            KAPPA,
            MU,
            b0_transpose_apply,
            key,
        };
        use lib_q_dkg::lattice::ring::{
            N,
            Rq,
        };

        let ck = key();
        let b0 = ck.b0(); // row-major MU×KAPPA
        assert_eq!(b0.len(), MU * KAPPA);

        // Valid secret e ∈ R_q^MU (ternary) — a fixed deterministic pattern in {-1,0,1}.
        let e_rq: Vec<Rq> = (0..MU)
            .map(|r| {
                let mut c = [0i64; N];
                for (i, ci) in c.iter_mut().enumerate() {
                    let t = ((i + r) % 3) as i64 - 1; // ∈ {-1, 0, 1}
                    *ci = t.rem_euclid(Q as i64);
                }
                Rq::from_coeffs(c)
            })
            .collect();
        let e_lifts: Vec<Vec<u64>> = e_rq.iter().map(rq_coeffs_zq).collect();

        // Error f_0 (bounded-ish, small centered values), for p-column k = 0.
        let mut fc = [0i64; N];
        for (i, ci) in fc.iter_mut().enumerate() {
            let v = ((i as i64 * 37) % 2049) - 1024;
            *ci = v.rem_euclid(Q as i64);
        }
        let f0 = Rq::from_coeffs(fc);
        let f0_z = rq_coeffs_zq(&f0);

        // p_0 = (B0ᵀe)_0 + f_0, using the KEM's real negacyclic-NTT matrix arithmetic.
        let b0te = b0_transpose_apply(ck, &e_rq); // KAPPA ring elements
        let qq = Q as u128;
        let p0_z: Vec<u64> = rq_coeffs_zq(&b0te[0])
            .iter()
            .zip(f0_z.iter())
            .map(|(&x, &y)| ((x as u128 + y as u128) % qq) as u64)
            .collect();

        // B0 column 0 cells: B0_{r,0} = b0[r·KAPPA + 0].
        let k = 0usize;
        let b0_cols_owned: Vec<Vec<u64>> =
            (0..MU).map(|r| rq_coeffs_zq(&b0[r * KAPPA + k])).collect();
        let b0_cols: Vec<&[u64]> = b0_cols_owned.iter().map(|v| v.as_slice()).collect();
        let e_ref: Vec<&[u64]> = e_lifts.iter().map(|v| v.as_slice()).collect();

        let zeta = 987_654_321u64;
        let (a, c) = r3a_public_coeffs(&b0_cols, &p0_z, zeta, N);
        let hq = r3a_quotient_poly(&b0_cols, &e_ref, &f0_z, &p0_z, N)
            .expect("real encryption numerator must be divisible by X^N+1");

        let mut w: Vec<u64> = e_lifts.iter().map(|e| poly_eval_zq(e, zeta)).collect();
        w.push(poly_eval_zq(&f0_z, zeta)); // F_0
        w.push(poly_eval_zq(&hq, zeta)); // HK_0
        assert_eq!(a.len(), MU + 2);
        assert_eq!(w.len(), MU + 2);

        generate_relation_trace(&a, &w, c).expect("real-B0 R3a relation must hold mod q at N=1024");
    }

    /// **REAL end-to-end: a genuine KEM ciphertext, all relations.** Encapsulate a real `Ciphertext`
    /// with `encapsulate_derand(t0, μ)`, re-derive the prover witness `(e, f, g)` with the KEM's own
    /// `fo_expand_witness`, and assemble **every** R3a column (`k = 0..KAPPA`) + R3b for `v` from the
    /// real `B0`/`t0`/`p`/`v`/`encode(μ)`. Each relation must (a) have a divisible numerator (quotient
    /// exists ⇔ this module's arithmetic agrees with the KEM's NTT ring mult) and (b) hold mod q under
    /// `generate_relation_trace`. This closes the R3 assembly on a REAL ciphertext at production
    /// dimensions — the "ciphertext public-input binding" against the actual KEM.
    #[test]
    fn real_ciphertext_all_relations_hold() {
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
        };

        // A group key t0 ∈ R_q^MU (arbitrary here — the relations hold for any t0 the ciphertext used).
        let t0: Vec<Rq> = (0..MU)
            .map(|r| {
                let mut c = [0i64; N];
                for (i, ci) in c.iter_mut().enumerate() {
                    *ci = (i as i64 * 13 + r as i64 * 7) % Q as i64;
                }
                Rq::from_coeffs(c)
            })
            .collect();
        let mu = [0x5Au8; 32];

        let ct = encapsulate_derand(&t0, &mu);
        let witness = fo_expand_witness(&t0, &mu);
        assert_eq!(witness.e.len(), MU);
        assert_eq!(witness.f.len(), KAPPA);
        assert_eq!(ct.p.len(), KAPPA);

        let b0 = key().b0();
        let e_lifts: Vec<Vec<u64>> = witness.e.iter().map(rq_coeffs_zq).collect();
        let e_ref: Vec<&[u64]> = e_lifts.iter().map(|v| v.as_slice()).collect();
        let zeta = 555_123_457u64;
        let e_folds: Vec<u64> = e_lifts.iter().map(|e| poly_eval_zq(e, zeta)).collect();

        // Every R3a column: Σ_r B0_{r,k}(ζ)·E_r + F_k − (ζ^N+1)·HK_k − p_k(ζ) ≡ 0.
        for k in 0..KAPPA {
            let b0_cols_owned: Vec<Vec<u64>> =
                (0..MU).map(|r| rq_coeffs_zq(&b0[r * KAPPA + k])).collect();
            let b0_cols: Vec<&[u64]> = b0_cols_owned.iter().map(|v| v.as_slice()).collect();
            let p_k = rq_coeffs_zq(&ct.p[k]);
            let f_k = rq_coeffs_zq(&witness.f[k]);

            let (a, c) = r3a_public_coeffs(&b0_cols, &p_k, zeta, N);
            let hq = r3a_quotient_poly(&b0_cols, &e_ref, &f_k, &p_k, N)
                .expect("real R3a numerator must be divisible by X^N+1");

            let mut w = e_folds.clone();
            w.push(poly_eval_zq(&f_k, zeta)); // F_k
            w.push(poly_eval_zq(&hq, zeta)); // HK_k
            generate_relation_trace(&a, &w, c)
                .unwrap_or_else(|_| panic!("real R3a column {k} must hold mod q"));
        }

        // R3b for v: Σ_r t0_r(ζ)·E_r + G + E_encode − (ζ^N+1)·HK_b − v(ζ) ≡ 0.
        let t0_cols_owned: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();
        let t0_cols: Vec<&[u64]> = t0_cols_owned.iter().map(|v| v.as_slice()).collect();
        let v_z = rq_coeffs_zq(&ct.v);
        let g_z = rq_coeffs_zq(&witness.g);
        let encode_z = rq_coeffs_zq(&encode_msg(&mu));

        let (a, c) = r3b_public_coeffs(&t0_cols, &v_z, zeta, N);
        let hb = r3b_quotient_poly(&t0_cols, &e_ref, &g_z, &encode_z, &v_z, N)
            .expect("real R3b numerator must be divisible by X^N+1");
        let mut w = e_folds.clone();
        w.push(poly_eval_zq(&g_z, zeta)); // G
        w.push(poly_eval_zq(&encode_z, zeta)); // E_encode
        w.push(poly_eval_zq(&hb, zeta)); // HK_b
        generate_relation_trace(&a, &w, c).expect("real R3b relation must hold mod q");
    }

    #[test]
    fn derive_zetas_deterministic_and_canonical() {
        let stmt = b"a serialized ciphertext";
        let z1 = derive_zetas(stmt, 4);
        let z2 = derive_zetas(stmt, 4);
        assert_eq!(z1, z2, "ζ derivation must be deterministic");
        assert_eq!(z1.len(), 4);
        for &z in &z1 {
            assert!(z < Q, "each ζ must be canonical (< Q)");
        }
        // Overwhelmingly likely distinct, and a different statement yields different challenges.
        assert_ne!(z1[0], z1[1]);
        assert_ne!(z1, derive_zetas(b"a different statement", 4));
    }

    /// **FS-ζ end-to-end on a real ciphertext (multi-challenge).** Derive the evaluation challenges from
    /// the genuine ciphertext bytes via [`derive_zetas`] and confirm R3a (column 0) and R3b hold at
    /// EVERY derived ζ — the Fiat-Shamir instantiation the full proof uses (verifier recomputes ζ from
    /// the ciphertext, checks the folds' ζ public values). `m = 3 ⇒ soundness ≈ 2^-111`.
    #[test]
    fn real_ciphertext_relations_hold_at_fs_zetas() {
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
        };

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
        let witness = fo_expand_witness(&t0, &mu);

        let b0 = key().b0();
        let e_lifts: Vec<Vec<u64>> = witness.e.iter().map(rq_coeffs_zq).collect();
        let e_ref: Vec<&[u64]> = e_lifts.iter().map(|v| v.as_slice()).collect();

        // Fiat-Shamir challenges from the ciphertext bytes.
        let zetas = derive_zetas(&ct.to_bytes(), 3);
        assert_eq!(zetas.len(), 3);

        for &zeta in &zetas {
            let e_folds: Vec<u64> = e_lifts.iter().map(|e| poly_eval_zq(e, zeta)).collect();

            // R3a column 0.
            let b0_cols_owned: Vec<Vec<u64>> =
                (0..MU).map(|r| rq_coeffs_zq(&b0[r * KAPPA])).collect();
            let b0_cols: Vec<&[u64]> = b0_cols_owned.iter().map(|v| v.as_slice()).collect();
            let p0 = rq_coeffs_zq(&ct.p[0]);
            let f0 = rq_coeffs_zq(&witness.f[0]);
            let (a, c) = r3a_public_coeffs(&b0_cols, &p0, zeta, N);
            let hq = r3a_quotient_poly(&b0_cols, &e_ref, &f0, &p0, N).expect("R3a divisible");
            let mut w = e_folds.clone();
            w.push(poly_eval_zq(&f0, zeta));
            w.push(poly_eval_zq(&hq, zeta));
            generate_relation_trace(&a, &w, c).expect("R3a must hold at the FS ζ");

            // R3b.
            let t0_cols_owned: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();
            let t0_cols: Vec<&[u64]> = t0_cols_owned.iter().map(|v| v.as_slice()).collect();
            let v_z = rq_coeffs_zq(&ct.v);
            let g_z = rq_coeffs_zq(&witness.g);
            let encode_z = rq_coeffs_zq(&encode_msg(&mu));
            let (a, c) = r3b_public_coeffs(&t0_cols, &v_z, zeta, N);
            let hb = r3b_quotient_poly(&t0_cols, &e_ref, &g_z, &encode_z, &v_z, N)
                .expect("R3b divisible");
            let mut w = e_folds;
            w.push(poly_eval_zq(&g_z, zeta));
            w.push(poly_eval_zq(&encode_z, zeta));
            w.push(poly_eval_zq(&hb, zeta));
            generate_relation_trace(&a, &w, c).expect("R3b must hold at the FS ζ");
        }
    }

    /// A tampered ciphertext column `p_0` (not a valid encryption) makes the numerator indivisible by
    /// `X^N+1` ⇒ no quotient ⇒ the prover cannot assemble the relation.
    #[test]
    fn r3a_invalid_ciphertext_has_no_quotient() {
        let n = 4usize;
        let b0_0: Vec<u64> = [11u64, 22, 33, 44].to_vec();
        let b0_1: Vec<u64> = [55u64, 66, 77, 88].to_vec();
        let b0_cols: [&[u64]; 2] = [&b0_0, &b0_1];
        let e0: Vec<u64> = [1i64, -1, 0, 1].iter().map(|&x| lift(x)).collect();
        let e1: Vec<u64> = [0i64, 1, 1, -1].iter().map(|&x| lift(x)).collect();
        let e_lifts: [&[u64]; 2] = [&e0, &e1];
        let f0: Vec<u64> = [7i64, -3, 2, -5].iter().map(|&x| lift(x)).collect();

        let mut acc: Vec<u64> = Vec::new();
        for (b0, e) in b0_cols.iter().zip(e_lifts.iter()) {
            poly_add_assign(&mut acc, &poly_mul_full(b0, e));
        }
        let mut p0 = reduce_cyclotomic(&acc, n);
        poly_add_assign(&mut p0, &f0);
        // Tamper one coefficient of p_0 (no longer a valid encryption of this (e,f)).
        p0[1] = (p0[1] + 1) % Q;

        assert!(
            r3a_quotient_poly(&b0_cols, &e_lifts, &f0, &p0, n).is_none(),
            "a tampered ciphertext column must not be divisible by X^N+1"
        );
    }
}
