//! Domain-separated, length-prefixed transcripts for the four CK-FO oracles.
//!
//! Every absorbed field — including the domain label and the parameter-set name — is prefixed
//! with its length as an 8-byte little-endian integer. Nothing is ever concatenated raw.
//!
//! This is not decoration. On 2026-08-08 `lib-q-ring-sig` shipped a real transcript collision
//! caused by unlength-prefixed concatenation (fixed at 275bf59): two different field sequences
//! whose bytes concatenated to the same string. Maul's `H_key` absorbs seven variable-position
//! fields including two public keys and three ciphertext components, so the same failure would be
//! available here. With a length prefix on every field the encoding is injective, which is exactly
//! what ePrint 2025/1755 §2 requires: "we implicitly refer to an injective concatenation of
//! `x_1, ..., x_n`, meaning that the original components can be unambiguously recovered from it".

use lib_q_sha3::{
    ExtendableOutput,
    Shake256,
    Update,
    XofReader,
};

use crate::params::ParamSet;

/// `H_rand(pk_L, pk_R, m_L, m_R) -> (r_C, r_L, r_R)`, Fig. 6.
const DOM_RAND: &str = "libq.maul.v1.H_rand";
/// `H_key(pk_L, pk_R, m_L, m_R, c_C, c_L, c_R^OTP) -> k`, Fig. 6.
const DOM_KEY: &str = "libq.maul.v1.H_key";
/// `H_OTP(m_L) -> mask`, Fig. 6.
const DOM_OTP: &str = "libq.maul.v1.H_OTP";
/// `H_rej(pk_L, pk_R, s_L, s_R, c_C, c_L, c_R^OTP) -> k'`, Fig. 6 implicit rejection.
const DOM_REJ: &str = "libq.maul.v1.H_rej";
/// Expansion of the public matrix `A` from the public-parameter seed.
const DOM_MATRIX: &str = "libq.maul.v1.expandA";
/// Expansion of a key-generation noise pair `(s, e)` from a seed.
const DOM_KEY_NOISE: &str = "libq.maul.v1.noise.keygen";
/// Expansion of the shared encryption randomness `(s_C, e_C)` from `r_C`.
const DOM_RC_NOISE: &str = "libq.maul.v1.noise.rC";
/// Expansion of a scalar noise term `f` from `r_L` / `r_R`.
const DOM_F_NOISE: &str = "libq.maul.v1.noise.f";
/// Nothing-up-my-sleeve derivation of the standard public parameters.
const DOM_STD_PP: &str = "libq.maul.v1.standard-public-parameters";

/// A SHAKE256 transcript in which every field is length-prefixed.
pub struct Transcript(Shake256);

impl Transcript {
    /// Start a transcript bound to `label` and to the parameter set.
    ///
    /// The parameter-set name is absorbed second so that an identical field sequence under
    /// Maul512 and Maul768 can never produce the same output.
    #[must_use]
    pub fn new(label: &str, p: &ParamSet) -> Self {
        let mut t = Self(Shake256::default());
        t.field(label.as_bytes());
        t.field(p.name.as_bytes());
        t
    }

    /// Absorb one length-prefixed field.
    pub fn field(&mut self, data: &[u8]) -> &mut Self {
        self.0.update(&(data.len() as u64).to_le_bytes());
        self.0.update(data);
        self
    }

    /// Absorb a length-prefixed 4-byte integer field (used for matrix indices).
    pub fn u32_field(&mut self, v: u32) -> &mut Self {
        self.field(&v.to_le_bytes())
    }

    /// Finalise and squeeze `out.len()` bytes. Consumes the transcript.
    pub fn squeeze(self, out: &mut [u8]) {
        let mut reader = self.0.finalize_xof();
        reader.read(out);
    }
}

fn oracle(label: &str, p: &ParamSet, fields: &[&[u8]], out: &mut [u8]) {
    let mut t = Transcript::new(label, p);
    for f in fields {
        t.field(f);
    }
    t.squeeze(out);
}

/// `H_rand(pk_L, pk_R, m_L, m_R)`, returning the three 32-byte seeds `(r_C, r_L, r_R)`.
#[must_use]
pub fn h_rand(
    p: &ParamSet,
    pk_l: &[u8],
    pk_r: &[u8],
    m_l: &[u8; 32],
    m_r: &[u8; 32],
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut buf = [0u8; 96];
    oracle(DOM_RAND, p, &[pk_l, pk_r, m_l, m_r], &mut buf);
    let mut rc = [0u8; 32];
    let mut rl = [0u8; 32];
    let mut rr = [0u8; 32];
    rc.copy_from_slice(&buf[0..32]);
    rl.copy_from_slice(&buf[32..64]);
    rr.copy_from_slice(&buf[64..96]);
    (rc, rl, rr)
}

/// `H_key(pk_L, pk_R, m_L, m_R, c_C, c_L, c_R^OTP)`.
///
/// The argument list is Fig. 6's, one parameter per absorbed field. Bundling them into a struct
/// would hide exactly the correspondence a reviewer needs to check against the figure, so the
/// arity lint is suppressed here rather than the signature changed.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn h_key(
    p: &ParamSet,
    pk_l: &[u8],
    pk_r: &[u8],
    m_l: &[u8; 32],
    m_r: &[u8; 32],
    c_c: &[u8],
    c_l: &[u8],
    c_r_otp: &[u8],
) -> [u8; 32] {
    let mut out = [0u8; 32];
    oracle(
        DOM_KEY,
        p,
        &[pk_l, pk_r, m_l, m_r, c_c, c_l, c_r_otp],
        &mut out,
    );
    out
}

/// `H_OTP(m_L)`, expanded to the byte length of one encoded scalar ciphertext component.
#[must_use]
pub fn h_otp(p: &ParamSet, m_l: &[u8; 32]) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec![0u8; p.c_scal_size()];
    oracle(DOM_OTP, p, &[m_l], &mut out);
    out
}

/// `H_rej(pk_L, pk_R, s_L, s_R, c_C, c_L, c_R^OTP)` — the implicit-rejection key.
///
/// Arity matches Fig. 6; see [`h_key`] for why the lint is suppressed rather than the shape changed.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn h_rej(
    p: &ParamSet,
    pk_l: &[u8],
    pk_r: &[u8],
    s_l: &[u8],
    s_r: &[u8],
    c_c: &[u8],
    c_l: &[u8],
    c_r_otp: &[u8],
) -> [u8; 32] {
    let mut out = [0u8; 32];
    oracle(
        DOM_REJ,
        p,
        &[pk_l, pk_r, s_l, s_r, c_c, c_l, c_r_otp],
        &mut out,
    );
    out
}

/// XOF stream for matrix entry `A[i][j]`.
#[must_use]
pub fn matrix_xof(p: &ParamSet, rho: &[u8; 32], i: u32, j: u32, len: usize) -> alloc::vec::Vec<u8> {
    let mut t = Transcript::new(DOM_MATRIX, p);
    t.field(rho).u32_field(i).u32_field(j);
    let mut out = alloc::vec![0u8; len];
    t.squeeze(&mut out);
    out
}

/// XOF stream for keygen noise `(s, e)` from `seed`.
#[must_use]
pub fn keygen_noise_xof(p: &ParamSet, seed: &[u8; 32], len: usize) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec![0u8; len];
    oracle(DOM_KEY_NOISE, p, &[seed], &mut out);
    out
}

/// XOF stream for the shared encryption randomness `(s_C, e_C)` from `r_C`.
#[must_use]
pub fn rc_noise_xof(p: &ParamSet, rc: &[u8; 32], len: usize) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec![0u8; len];
    oracle(DOM_RC_NOISE, p, &[rc], &mut out);
    out
}

/// XOF stream for a scalar noise term `f` from `r_L` or `r_R`.
///
/// `side` (0 for left, 1 for right) is absorbed so that the two terms differ even in the
/// pathological case `r_L == r_R`.
#[must_use]
pub fn f_noise_xof(p: &ParamSet, r: &[u8; 32], side: u8, len: usize) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec![0u8; len];
    oracle(DOM_F_NOISE, p, &[r, &[side]], &mut out);
    out
}

/// Nothing-up-my-sleeve seed for the standard public parameters of `p`.
#[must_use]
pub fn standard_pp_seed(p: &ParamSet) -> [u8; 32] {
    let mut out = [0u8; 32];
    oracle(DOM_STD_PP, p, &[], &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{
        MAUL512,
        MAUL768,
    };

    #[test]
    fn length_prefixing_separates_a_field_boundary_shift() {
        // The exact collision shape that bit lib-q-ring-sig: moving a byte across a field
        // boundary leaves the raw concatenation identical. With length prefixes it must not.
        let p = &MAUL768;
        let a = h_key(p, b"abc", b"de", &[0u8; 32], &[0u8; 32], b"x", b"y", b"z");
        let b = h_key(p, b"ab", b"cde", &[0u8; 32], &[0u8; 32], b"x", b"y", b"z");
        assert_ne!(a, b, "field boundary shift collided");

        let c = h_key(p, b"abc", b"de", &[0u8; 32], &[0u8; 32], b"xy", b"", b"z");
        let d = h_key(p, b"abc", b"de", &[0u8; 32], &[0u8; 32], b"x", b"y", b"z");
        assert_ne!(c, d, "ciphertext field boundary shift collided");
    }

    #[test]
    fn each_oracle_has_its_own_domain() {
        let p = &MAUL768;
        let k = h_key(p, b"a", b"b", &[1u8; 32], &[2u8; 32], b"c", b"d", b"e");
        let r = h_rej(p, b"a", b"b", &[1u8; 32], &[2u8; 32], b"c", b"d", b"e");
        assert_ne!(k, r, "H_key and H_rej share a domain");
        let (rc, rl, rr) = h_rand(p, b"a", b"b", &[1u8; 32], &[2u8; 32]);
        assert_ne!(rc, rl, "r_C and r_L are the same 32 bytes");
        assert_ne!(rl, rr, "r_L and r_R are the same 32 bytes");
        assert_ne!(rc, k, "H_rand and H_key share a domain");
    }

    #[test]
    fn parameter_sets_are_separated() {
        let a = standard_pp_seed(&MAUL512);
        let b = standard_pp_seed(&MAUL768);
        assert_ne!(a, b, "parameter sets share a public-parameter seed");
        let ka = h_key(
            &MAUL512, b"a", b"b", &[1u8; 32], &[2u8; 32], b"c", b"d", b"e",
        );
        let kb = h_key(
            &MAUL768, b"a", b"b", &[1u8; 32], &[2u8; 32], b"c", b"d", b"e",
        );
        assert_ne!(ka, kb, "parameter sets share an H_key");
    }

    #[test]
    fn f_noise_sides_differ_even_for_an_identical_seed() {
        let p = &MAUL768;
        let l = f_noise_xof(p, &[7u8; 32], 0, 64);
        let r = f_noise_xof(p, &[7u8; 32], 1, 64);
        assert_ne!(l, r, "left and right scalar noise coincide");
    }

    #[test]
    fn matrix_entries_are_index_separated() {
        let p = &MAUL768;
        let a01 = matrix_xof(p, &[0u8; 32], 0, 1, 32);
        let a10 = matrix_xof(p, &[0u8; 32], 1, 0, 32);
        assert_ne!(a01, a10, "A[0][1] and A[1][0] share a stream");
    }
}
