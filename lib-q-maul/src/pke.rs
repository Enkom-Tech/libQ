//! `Maul_PKE` — the `[IND-CPA, IND-CPA]`-secure 2K2M-PKE of ePrint 2025/1755 **Fig. 8** (§5.2, p19).
//!
//! Transcribed from the figure, unchanged:
//!
//! ```text
//! Setup():      A <-$ U(R_q^{k x k})
//! KeygenL(A):   (s_L, e_L) <-$ B^{2k};  t_L <- A s_L + e_L
//! KeygenR(A):   (s_R, e_R) <-$ B^{2k};  t_R <- A s_R + e_R
//! Encr(A, t_L, t_R, (m_L, m_R)):
//!     (s_C, e_C) <-$ B^{2k};  (f_L, f_R) <-$ D^2
//!     c_C <- Comp_(q,du)( A^T s_C + e_C )
//!     c_L <- Comp_(q,dv)( s_C^T t_L + f_L + ceil(q/2) m_L )
//!     c_R <- Comp_(q,dv)( s_C^T t_R + f_R + ceil(q/2) m_R )
//! Decr(A, s_L, s_R, (c_C, c_L, c_R)):
//!     m'_L <- Decomp_(q,dv)(c_L) - Decomp_(q,du)(c_C)^T s_L
//!     m'_R <- Decomp_(q,dv)(c_R) - Decomp_(q,du)(c_C)^T s_R
//! ```
//!
//! **The whole point of the construction is in the shapes.** `c_C` is a `k`-vector (1056 bytes at
//! `k = 3, du = 11`); `c_L` and `c_R` are single scalars (192 bytes each at `dv = 6`). One large
//! shared component carries the ephemeral randomness for BOTH encryptions; each small component
//! carries one message. `m_L` is recoverable only with `s_L` and `m_R` only with `s_R` — neither
//! secret key is redundant, because neither scalar can be opened with the other's key.

use alloc::vec::Vec;

use crate::arith::{
    self,
    Modulus,
};
use crate::params::{
    N,
    ParamSet,
    Poly,
};
use crate::{
    codec,
    sample,
};

/// Public parameters: the seed for `A` and the expanded matrix.
#[derive(Clone, Debug)]
pub struct PublicParams {
    /// The parameter set these public parameters instantiate.
    pub params: &'static ParamSet,
    /// Seed from which `A` is expanded.
    pub rho: [u8; 32],
    /// The `k x k` public matrix, row-major.
    pub a: Vec<Vec<Poly>>,
    /// Cached modulus helper.
    pub m: Modulus,
}

impl PublicParams {
    /// `Setup()` from an explicit seed.
    #[must_use]
    pub fn from_seed(params: &'static ParamSet, rho: [u8; 32]) -> Self {
        let a = sample::expand_a(params, &rho);
        Self {
            params,
            rho,
            a,
            m: Modulus::new(params),
        }
    }

    /// The nothing-up-my-sleeve public parameters for `params`.
    ///
    /// `rho = SHAKE256("libq.maul.v1.standard-public-parameters" || name)`; no operator input, so
    /// there is no trapdoor to plant in `A`.
    #[must_use]
    pub fn standard(params: &'static ParamSet) -> Self {
        Self::from_seed(params, crate::hash::standard_pp_seed(params))
    }
}

/// A `Maul_PKE` public key `t = A s + e`, with its canonical byte encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PkeKey {
    /// The public vector `t`.
    pub t: Vec<Poly>,
    /// Canonical encoding: `rho || pack(t, ceil(log2 q))`.
    pub bytes: Vec<u8>,
}

/// A `Maul_PKE` secret key. Only `s` is needed for decryption (`e` is discarded after keygen).
#[derive(Clone, Debug)]
pub struct PkeSecret {
    /// The secret vector `s`.
    pub s: Vec<Poly>,
}

impl zeroize::Zeroize for PkeSecret {
    fn zeroize(&mut self) {
        for poly in &mut self.s {
            poly.zeroize();
        }
    }
}

impl Drop for PkeSecret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

/// `Keygen(pp)` from a 32-byte seed. `KeygenL` and `KeygenR` are the same algorithm in Fig. 8;
/// the left/right distinction lives in the KEM's type system, not here.
#[must_use]
pub fn keygen(pp: &PublicParams, seed: &[u8; 32]) -> (PkeKey, PkeSecret) {
    let p = pp.params;
    let (s, e) = sample::keygen_noise(p, seed, &pp.m);
    let as_ = arith::mat_vec(&pp.a, &s, &pp.m);
    let t: Vec<Poly> = as_
        .iter()
        .zip(e.iter())
        .map(|(x, y)| arith::poly_add(x, y, &pp.m))
        .collect();

    let mut bytes = Vec::with_capacity(p.public_key_size());
    bytes.extend_from_slice(&pp.rho);
    for poly in &t {
        let vals: Vec<u32> = poly.iter().map(|c| c.cast_unsigned()).collect();
        codec::pack_bits(&vals, p.pk_bits, &mut bytes);
    }
    debug_assert_eq!(bytes.len(), p.public_key_size());
    (PkeKey { t, bytes }, PkeSecret { s })
}

/// A `Maul_PKE` ciphertext in compressed-coefficient form (before byte packing).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PkeCiphertext {
    /// The shared vector component `c_C`, `k` polynomials of `du`-bit values.
    pub c_c: Vec<[u32; N]>,
    /// The left scalar component `c_L`, `dv`-bit values.
    pub c_l: [u32; N],
    /// The right scalar component `c_R`, `dv`-bit values.
    pub c_r: [u32; N],
}

/// `Encr(pp, t_L, t_R, (m_L, m_R); r_C, r_L, r_R)` — Fig. 8, fully derandomised.
///
/// Both scalar components are produced in one call because they share `s_C`; that sharing IS the
/// construction. Deterministic in `(r_C, r_L, r_R)` so that CK-FO's re-encryption check can
/// reproduce it exactly.
/// Arity matches Fig. 8's `Encr` plus its three derandomising seeds; see [`crate::hash::h_key`]
/// for why figure-fidelity beats bundling here.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn encrypt(
    pp: &PublicParams,
    t_l: &[Poly],
    t_r: &[Poly],
    rc: &[u8; 32],
    rl: &[u8; 32],
    rr: &[u8; 32],
    m_l: &[u8; 32],
    m_r: &[u8; 32],
) -> PkeCiphertext {
    let p = pp.params;
    let m = &pp.m;

    let (s_c, e_c) = sample::rc_noise(p, rc, m);
    // c_C <- Comp( A^T s_C + e_C )
    let ats = arith::mat_transpose_vec(&pp.a, &s_c, m);
    let c_c: Vec<[u32; N]> = ats
        .iter()
        .zip(e_c.iter())
        .map(|(x, y)| codec::compress_poly(&arith::poly_add(x, y, m), p.du, m))
        .collect();

    let scal = |t: &[Poly], r: &[u8; 32], side: u8, msg: &[u8; 32]| -> [u32; N] {
        let f = sample::f_noise(p, r, side, m);
        let dot = arith::vec_dot(&s_c, t, m);
        let enc = codec::message_to_poly(msg, p);
        let v = arith::poly_add(&arith::poly_add(&dot, &f, m), &enc, m);
        codec::compress_poly(&v, p.dv, m)
    };

    PkeCiphertext {
        c_c,
        c_l: scal(t_l, rl, 0, m_l),
        c_r: scal(t_r, rr, 1, m_r),
    }
}

/// One side of `Decr`: `round(2 * (Decomp(c_scal) - Decomp(c_C)^T s) / q)`.
///
/// Takes only the secret vector for ITS OWN side, which is what makes the "you cannot open the
/// right scalar with the left key" property mechanical rather than aspirational.
#[must_use]
pub fn decrypt_side(
    pp: &PublicParams,
    s: &PkeSecret,
    c_c: &[[u32; N]],
    c_scal: &[u32; N],
) -> [u8; 32] {
    let p = pp.params;
    let m = &pp.m;
    let u: Vec<Poly> = c_c
        .iter()
        .map(|c| codec::decompress_poly(c, p.du, m))
        .collect();
    let v = codec::decompress_poly(c_scal, p.dv, m);
    let dot = arith::vec_dot(&u, &s.s, m);
    let diff = arith::poly_sub(&v, &dot, m);
    codec::poly_to_message(&diff, p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{
        MAUL512,
        MAUL768,
    };

    fn setup(p: &'static ParamSet) -> (PublicParams, PkeKey, PkeSecret, PkeKey, PkeSecret) {
        let pp = PublicParams::standard(p);
        let (kl, sl) = keygen(&pp, &[1u8; 32]);
        let (kr, sr) = keygen(&pp, &[2u8; 32]);
        (pp, kl, sl, kr, sr)
    }

    #[test]
    fn pke_round_trips_both_messages() {
        for p in [&MAUL512, &MAUL768] {
            let (pp, kl, sl, kr, sr) = setup(p);
            let m_l = [0x5Au8; 32];
            let m_r = [0xA5u8; 32];
            let ct = encrypt(
                &pp, &kl.t, &kr.t, &[7u8; 32], &[8u8; 32], &[9u8; 32], &m_l, &m_r,
            );
            assert_eq!(decrypt_side(&pp, &sl, &ct.c_c, &ct.c_l), m_l, "{}", p.name);
            assert_eq!(decrypt_side(&pp, &sr, &ct.c_c, &ct.c_r), m_r, "{}", p.name);
        }
    }

    #[test]
    fn the_left_key_cannot_open_the_right_scalar() {
        // The PKE-level statement of the property the deleted lib-q-double-kem lost.
        let p = &MAUL768;
        let (pp, kl, sl, kr, sr) = setup(p);
        let m_l = [0x11u8; 32];
        let m_r = [0x22u8; 32];
        let ct = encrypt(
            &pp, &kl.t, &kr.t, &[7u8; 32], &[8u8; 32], &[9u8; 32], &m_l, &m_r,
        );
        // Right scalar, LEFT secret: must not yield m_R.
        let wrong = decrypt_side(&pp, &sl, &ct.c_c, &ct.c_r);
        assert_ne!(wrong, m_r, "left key opened the right scalar");
        // ...and symmetrically.
        let wrong2 = decrypt_side(&pp, &sr, &ct.c_c, &ct.c_l);
        assert_ne!(wrong2, m_l, "right key opened the left scalar");
    }

    #[test]
    fn the_shared_component_really_is_shared() {
        // Same r_C, same m_L, DIFFERENT m_R: c_C and c_L must be byte-identical and only c_R may
        // move. This is the "one u, two v" factoring, tested directly.
        let p = &MAUL768;
        let (pp, kl, _sl, kr, _sr) = setup(p);
        let a = encrypt(
            &pp,
            &kl.t,
            &kr.t,
            &[7u8; 32],
            &[8u8; 32],
            &[9u8; 32],
            &[0x11u8; 32],
            &[0x22u8; 32],
        );
        let b = encrypt(
            &pp,
            &kl.t,
            &kr.t,
            &[7u8; 32],
            &[8u8; 32],
            &[9u8; 32],
            &[0x11u8; 32],
            &[0x33u8; 32],
        );
        assert_eq!(a.c_c, b.c_c, "c_C is not shared across the two messages");
        assert_eq!(a.c_l, b.c_l, "c_L moved when only m_R changed");
        assert_ne!(a.c_r, b.c_r, "c_R did not move when m_R changed");
    }

    #[test]
    fn encryption_is_deterministic_in_its_randomness() {
        let p = &MAUL512;
        let (pp, kl, _sl, kr, _sr) = setup(p);
        let args = (&[7u8; 32], &[8u8; 32], &[9u8; 32], &[1u8; 32], &[2u8; 32]);
        let a = encrypt(&pp, &kl.t, &kr.t, args.0, args.1, args.2, args.3, args.4);
        let b = encrypt(&pp, &kl.t, &kr.t, args.0, args.1, args.2, args.3, args.4);
        assert_eq!(a, b, "Encr is not a function of its randomness");
        let c = encrypt(
            &pp, &kl.t, &kr.t, &[6u8; 32], args.1, args.2, args.3, args.4,
        );
        assert_ne!(a.c_c, c.c_c, "c_C ignores r_C");
    }

    #[test]
    fn correctness_holds_over_many_independent_messages() {
        // delta is 2^-196 at Maul768; a decapsulation failure here would mean the noise budget is
        // wrong, not that we got unlucky.
        let p = &MAUL768;
        let (pp, kl, sl, kr, sr) = setup(p);
        for i in 0..24u8 {
            let m_l = [i.wrapping_mul(7).wrapping_add(1); 32];
            let m_r = [i.wrapping_mul(13).wrapping_add(5); 32];
            let ct = encrypt(
                &pp,
                &kl.t,
                &kr.t,
                &[i; 32],
                &[i ^ 0x40; 32],
                &[i ^ 0x80; 32],
                &m_l,
                &m_r,
            );
            assert_eq!(
                decrypt_side(&pp, &sl, &ct.c_c, &ct.c_l),
                m_l,
                "iter {i} left"
            );
            assert_eq!(
                decrypt_side(&pp, &sr, &ct.c_c, &ct.c_r),
                m_r,
                "iter {i} right"
            );
        }
    }

    #[test]
    fn public_key_encoding_has_the_documented_length() {
        for p in crate::params::ALL {
            let pp = PublicParams::standard(p);
            let (k, _s) = keygen(&pp, &[3u8; 32]);
            assert_eq!(k.bytes.len(), p.public_key_size(), "{}", p.name);
        }
    }
}
