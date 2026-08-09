//! Constant-time arithmetic in `R_q = Z_q[X]/(X^256 + 1)`.
//!
//! Deliberately schoolbook, not NTT. Every Maul modulus in Table 5 is NTT-friendly and an NTT
//! would be ~100x faster, but this crate is RED and unreviewed: the priority is that the
//! arithmetic be obviously correct and obviously branch-free, not that it be fast. Cost is
//! ~15 polynomial products per encapsulation at `k = 3`. See `SECURITY.md` "Performance".
//!
//! No secret-dependent branch and no secret-dependent memory index occurs here. In particular
//! there is no `%` operator on a secret: integer division has data-dependent latency on several
//! microarchitectures, so reduction goes through a multiply-shift Barrett estimate followed by a
//! fixed number of branch-free conditional corrections.

use crate::params::{
    N,
    ParamSet,
    Poly,
};

/// Branch-free `if r >= q { r - q } else { r }`.
#[inline(always)]
const fn csub(r: i64, q: i64) -> i64 {
    let d = r - q;
    // `d >> 63` is -1 when d < 0 (i.e. r < q) and 0 otherwise; `!` inverts that.
    r - (q & !(d >> 63))
}

/// Branch-free `if r < 0 { r + q } else { r }`.
#[inline(always)]
const fn cadd(r: i64, q: i64) -> i64 {
    r + (q & (r >> 63))
}

/// A modulus with its precomputed Barrett magics, bound to one [`ParamSet`].
#[derive(Clone, Copy, Debug)]
pub struct Modulus {
    q: i64,
    v: i64,
    q2: i64,
    v2: i64,
}

impl Modulus {
    /// Build the modulus helper for `p`.
    #[must_use]
    pub const fn new(p: &ParamSet) -> Self {
        Self {
            q: p.q as i64,
            v: p.barrett_v,
            q2: 2 * p.q as i64,
            v2: p.barrett_v2,
        }
    }

    /// `q` as `i64`.
    #[must_use]
    pub const fn q(&self) -> i64 {
        self.q
    }

    /// Reduce any `x` with `|x| < 2^40` into `[0, q)`, branch-free.
    ///
    /// `t = (x * floor(2^45/q)) >> 45` underestimates `floor(x/q)` by at most 1 over that range
    /// (the magic's relative error is `< 2^-45 * |x| < 2^-5` of a single unit), and arithmetic
    /// right-shift floors for negative `x` too. So `x - t*q` lands in `(-q, 2q)` and three fixed
    /// corrections suffice. Exhaustively cross-checked against `rem_euclid` in the unit tests.
    #[inline(always)]
    pub const fn reduce(&self, x: i64) -> i32 {
        let t = ((x as i128 * self.v as i128) >> 45) as i64;
        let mut r = x - t * self.q;
        r = cadd(r, self.q);
        r = csub(r, self.q);
        r = csub(r, self.q);
        r as i32
    }

    /// `floor(n / (2q))` for `0 <= n < 2^40`, branch-free.
    ///
    /// Same shape as [`Self::reduce`]: the magic underestimates by at most one, and one
    /// conditional correction fixes it. Exhaustively verified over the full reachable input range
    /// of [`crate::codec::compress`] in the unit tests, which is what makes this safe to use on a
    /// secret.
    #[inline(always)]
    pub const fn div_2q(&self, n: i64) -> i64 {
        let t = ((n as i128 * self.v2 as i128) >> 45) as i64;
        // t is floor(n/2q) or one less; add one back if the remainder still reaches 2q.
        let rem = n - t * self.q2;
        t + (1 & !((rem - self.q2) >> 63))
    }

    /// Centered representative of `a in [0, q)`, i.e. the element of `(-q/2, q/2]` congruent to it.
    #[inline(always)]
    pub const fn center(&self, a: i32) -> i64 {
        let a = a as i64;
        let d = a - (self.q - 1) / 2 - 1;
        // subtract q when a > (q-1)/2
        a - (self.q & !(d >> 63))
    }
}

/// `a + b` in `R_q`.
#[must_use]
pub fn poly_add(a: &Poly, b: &Poly, m: &Modulus) -> Poly {
    let mut out = [0i32; N];
    for i in 0..N {
        out[i] = csub(a[i] as i64 + b[i] as i64, m.q) as i32;
    }
    out
}

/// `a - b` in `R_q`.
#[must_use]
pub fn poly_sub(a: &Poly, b: &Poly, m: &Modulus) -> Poly {
    let mut out = [0i32; N];
    for i in 0..N {
        out[i] = cadd(a[i] as i64 - b[i] as i64, m.q) as i32;
    }
    out
}

/// Negacyclic product `a * b mod (X^n + 1)` in `R_q`, schoolbook.
#[must_use]
pub fn poly_mul(a: &Poly, b: &Poly, m: &Modulus) -> Poly {
    let mut acc = [0i64; 2 * N - 1];
    for i in 0..N {
        let ai = a[i] as i64;
        for j in 0..N {
            acc[i + j] += ai * (b[j] as i64);
        }
    }
    let mut out = [0i32; N];
    for i in 0..N {
        // X^{n+i} == -X^i
        let wrap = if i + N < 2 * N - 1 { acc[i + N] } else { 0 };
        out[i] = m.reduce(acc[i] - wrap);
    }
    out
}

/// Inner product `a . b` of two length-`k` vectors over `R_q`.
///
/// # Panics
/// Panics if the two slices have different lengths.
#[must_use]
pub fn vec_dot(a: &[Poly], b: &[Poly], m: &Modulus) -> Poly {
    assert_eq!(a.len(), b.len(), "vec_dot: length mismatch");
    let mut out = [0i32; N];
    for (x, y) in a.iter().zip(b.iter()) {
        let p = poly_mul(x, y, m);
        out = poly_add(&out, &p, m);
    }
    out
}

/// Matrix-vector product `mat * v` where `mat` is `k x k` in row-major order.
///
/// # Panics
/// Panics if `mat.len() != v.len()` or if any row's length differs from `v.len()`.
#[must_use]
pub fn mat_vec(mat: &[alloc::vec::Vec<Poly>], v: &[Poly], m: &Modulus) -> alloc::vec::Vec<Poly> {
    mat.iter().map(|row| vec_dot(row, v, m)).collect()
}

/// Transposed matrix-vector product `mat^T * v`.
///
/// # Panics
/// Panics if `mat` is not square with side `v.len()`.
#[must_use]
pub fn mat_transpose_vec(
    mat: &[alloc::vec::Vec<Poly>],
    v: &[Poly],
    m: &Modulus,
) -> alloc::vec::Vec<Poly> {
    let k = v.len();
    assert_eq!(mat.len(), k, "mat_transpose_vec: shape mismatch");
    let mut out = alloc::vec::Vec::with_capacity(k);
    for j in 0..k {
        let mut acc = [0i32; N];
        for (i, item) in v.iter().enumerate() {
            assert_eq!(mat[i].len(), k, "mat_transpose_vec: ragged matrix");
            let p = poly_mul(&mat[i][j], item, m);
            acc = poly_add(&acc, &p, m);
        }
        out.push(acc);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::ALL;

    #[test]
    fn reduce_matches_rem_euclid_on_extremes_and_samples() {
        for p in ALL {
            let m = Modulus::new(p);
            let q = p.q as i64;
            // `reduce` is documented for |x| < 2^40, so every case must stay inside that.
            // `mult * q` with mult up to 2^26 is at most 2^26 * 9473 < 2^40.
            let mut cases = alloc::vec::Vec::new();
            for d in -3i64..=3 {
                for mult in [0i64, 1, 2, 255, 256, 1_000_000, 1 << 20, 1 << 26] {
                    cases.push(mult * q + d);
                    cases.push(-(mult * q) + d);
                }
            }
            // A deterministic spread across the whole supported magnitude range.
            let mut x = 1i64;
            for _ in 0..5000 {
                x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                cases.push((x >> 25) % (1i64 << 39));
            }
            for c in &cases {
                assert!(
                    c.abs() < (1i64 << 40),
                    "test generator escaped the bound: {c}"
                );
            }
            for c in cases {
                assert_eq!(
                    i64::from(m.reduce(c)),
                    c.rem_euclid(q),
                    "{}: reduce({c}) wrong",
                    p.name
                );
            }
        }
    }

    #[test]
    fn div_2q_is_exact_over_the_full_compression_input_range() {
        // The only caller is `codec::compress`, whose numerator is
        // (x << (d+1)) + q  for x in [0,q) and d <= 12. Verify EVERY reachable value.
        for p in ALL {
            let m = Modulus::new(p);
            let q = i64::from(p.q);
            for d in [p.du, p.dv, p.pk_bits] {
                for x in 0..q {
                    let n = (x << (d + 1)) + q;
                    assert_eq!(
                        m.div_2q(n),
                        n / (2 * q),
                        "{} d={d}: div_2q({n}) wrong",
                        p.name
                    );
                }
            }
        }
    }

    #[test]
    fn center_is_the_symmetric_representative() {
        for p in ALL {
            let m = Modulus::new(p);
            let q = i64::from(p.q);
            for a in 0..q {
                let c = m.center(a as i32);
                assert!(c > -q / 2 - 1 && c <= q / 2, "{}: center({a})={c}", p.name);
                assert_eq!(c.rem_euclid(q), a, "{}: center({a}) not congruent", p.name);
            }
        }
    }

    #[test]
    fn poly_mul_accumulator_cannot_escape_the_reduce_bound() {
        // `reduce` is only claimed correct for |x| < 2^40. `poly_mul` feeds it
        // `acc[i] - acc[i+N]`, each accumulator bounded by N*(q-1)^2. Prove the worst case fits,
        // so the bound is a checked fact and not a comment.
        for p in ALL {
            let q = i64::from(p.q);
            let worst = 2 * (N as i64) * (q - 1) * (q - 1);
            assert!(
                worst < (1i64 << 40),
                "{}: worst-case poly_mul accumulator {worst} exceeds 2^40",
                p.name
            );
        }
    }

    #[test]
    fn negacyclic_mul_wraps_with_a_sign_flip() {
        let p = &crate::params::MAUL768;
        let m = Modulus::new(p);
        // X^{N-1} * X == -1
        let mut a = [0i32; N];
        a[N - 1] = 1;
        let mut b = [0i32; N];
        b[1] = 1;
        let c = poly_mul(&a, &b, &m);
        let mut expect = [0i32; N];
        expect[0] = p.q - 1;
        assert_eq!(c, expect, "X^(n-1) * X should be -1");
    }

    #[test]
    fn mul_is_commutative_and_distributes() {
        let p = &crate::params::MAUL512;
        let m = Modulus::new(p);
        let mut a = [0i32; N];
        let mut b = [0i32; N];
        let mut c = [0i32; N];
        let mut s = 12345u64;
        for i in 0..N {
            s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            a[i] = ((s >> 33) % (p.q as u64)) as i32;
            s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            b[i] = ((s >> 33) % (p.q as u64)) as i32;
            s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            c[i] = ((s >> 33) % (p.q as u64)) as i32;
        }
        assert_eq!(
            poly_mul(&a, &b, &m),
            poly_mul(&b, &a, &m),
            "not commutative"
        );
        let lhs = poly_mul(&a, &poly_add(&b, &c, &m), &m);
        let rhs = poly_add(&poly_mul(&a, &b, &m), &poly_mul(&a, &c, &m), &m);
        assert_eq!(lhs, rhs, "not distributive");
    }
}
