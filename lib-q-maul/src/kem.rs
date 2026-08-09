//! `Maul` — the `[IND-CK-CCA, IND-CCA]` 2K-KEM obtained by applying the CK-FO transform of
//! ePrint 2025/1755 **Fig. 6** (§4.2, pp16-17) to [`crate::pke`]'s `Maul_PKE`.
//!
//! Transcribed from the figure, unchanged:
//!
//! ```text
//! dEncaps(pp, pk_L, pk_R):
//!     m_L <-$ M_L ; m_R <-$ M_R
//!     (r_C, r_L, r_R) <- H_rand(pk_L, pk_R, m_L, m_R)
//!     (c_C, c_L) = Encr_L(pp, pk_L, m_L; r_C, r_L)
//!     (c_C, c_R) = Encr_R(pp, pk_R, m_R; r_C, r_R)
//!     c_R^OTP <- c_R XOR H_OTP(m_L)
//!     k <- H_key(pk_L, pk_R, m_L, m_R, c_C, c_L, c_R^OTP)
//!     return (k, (c_C, c_L, c_R^OTP))
//!
//! dDecaps(pk_L, pk_R, (sk_L, s_L), (sk_R, s_R), (c_C, c_L, c_R^OTP)):
//!     k' <- H_rej(pk_L, pk_R, s_L, s_R, c_C, c_L, c_R^OTP)
//!     m'_L <- Decr_L(pp, sk_L, (c_C, c_L))
//!     c_R  <- c_R^OTP XOR H_OTP(m'_L)
//!     m'_R <- Decr_R(pp, sk_R, (c_C, c_R))
//!     (r'_C, r'_L, r'_R) <- H_rand(pk_L, pk_R, m'_L, m'_R)
//!     if Encr_L(...) != (c_C, c_L) then return k'
//!     if Encr_R(...) != (c_C, c_R) then return k'
//!     return H_key(pk_L, pk_R, m'_L, m'_R, c_C, c_L, c_R^OTP)
//! ```
//!
//! ## Why both secret keys are load-bearing
//!
//! `k = H_key(pk_L, pk_R, m_L, m_R, ...)`. `m_R` enters the key derivation, and the only route to
//! `m_R` is `Decr_R`, which consumes `sk_R`. Nothing transmitted determines `m_R`: `c_R` is an
//! `Maul_PKE` encryption of it under `t_R`, and (§5.2, Theorem 5) recovering it from
//! `(c_C, c_R, t_R)` is the Hint-MLWE problem. So the second leg is not decoration and not a
//! second copy of the first leg's entropy — it is a second, independent hardness assumption whose
//! output is mixed into the session key.
//!
//! This is precisely the property libQ's withdrawn `lib-q-double-kem` did not have: there `ct_b`
//! was computed and thrown away, and `ss_b` was re-derived by hashing wire bytes together with
//! the PUBLIC `ek_b`, so the second leg contributed no secrecy at all. The regression tests in
//! `tests/both_legs_contribute.rs` reproduce that exact attack and require it to fail here — and
//! include a deliberately broken control construction against which the same attack succeeds, so
//! the test is known to be able to detect the defect it exists to catch.
//!
//! ## The one-time pad is well defined
//!
//! Fig. 6 footnote 20: "we assume that the set of right ciphertexts is contained in the binary
//! space `{0,1}^tau` and choose `H_OTP` to have range `{0,1}^tau`". Here `c_R` encodes as exactly
//! `n * dv` bits with every `dv`-bit value a legal compressed coefficient, so the encoding is a
//! bijection onto `{0,1}^(n*dv)` and XOR is a permutation of the ciphertext space. Checked by
//! `otp_masking_is_an_involution_over_the_whole_space`.

use alloc::vec::Vec;

use rand_core::{
    CryptoRng,
    Rng,
};
use subtle::{
    Choice,
    ConditionallySelectable,
    ConstantTimeEq,
};
use zeroize::Zeroize;

use crate::error::MaulError;
use crate::params::N;
use crate::pke::{
    self,
    PkeKey,
    PkeSecret,
    PublicParams,
};
use crate::{
    codec,
    hash,
};

/// The left public key. Distinct from [`RightPublicKey`] so the two cannot be swapped by accident:
/// the CK-FO transform is **asymmetric** (only the right ciphertext is masked, and only the left
/// side gets chosen-key security), so a swap is a real security bug, not a relabelling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeftPublicKey(pub PkeKey);

/// The right public key. See [`LeftPublicKey`] for why the sides are distinct types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RightPublicKey(pub PkeKey);

/// The left decapsulation key: the PKE secret plus the CK-FO implicit-rejection seed `s_L`.
pub struct LeftSecretKey {
    pke: PkeSecret,
    fo_seed: Vec<u8>,
}

/// The right decapsulation key: the PKE secret plus the CK-FO implicit-rejection seed `s_R`.
pub struct RightSecretKey {
    pke: PkeSecret,
    fo_seed: Vec<u8>,
}

macro_rules! secret_key_impl {
    ($ty:ty) => {
        impl $ty {
            /// The underlying `Maul_PKE` secret.
            #[must_use]
            pub fn pke_secret(&self) -> &PkeSecret {
                &self.pke
            }

            /// The CK-FO implicit-rejection seed.
            #[must_use]
            pub fn fo_seed(&self) -> &[u8] {
                &self.fo_seed
            }

            /// Replace the underlying PKE secret. Exists for the mutation tests that must show a
            /// perturbed key changes the decapsulated secret; there is no production use.
            pub fn set_pke_secret_for_testing(&mut self, s: PkeSecret) {
                self.pke = s;
            }
        }

        impl Drop for $ty {
            fn drop(&mut self) {
                self.fo_seed.zeroize();
            }
        }
    };
}
secret_key_impl!(LeftSecretKey);
secret_key_impl!(RightSecretKey);

/// A Maul encapsulation: `c_C || c_L || c_R^OTP`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    bytes: Vec<u8>,
    c_c_len: usize,
    c_scal_len: usize,
}

impl Ciphertext {
    /// The full wire encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The shared vector component `c_C`.
    #[must_use]
    pub fn c_c_bytes(&self) -> &[u8] {
        &self.bytes[..self.c_c_len]
    }

    /// The left scalar component `c_L`.
    #[must_use]
    pub fn c_l_bytes(&self) -> &[u8] {
        &self.bytes[self.c_c_len..self.c_c_len + self.c_scal_len]
    }

    /// The masked right scalar component `c_R^OTP`.
    #[must_use]
    pub fn c_r_otp_bytes(&self) -> &[u8] {
        &self.bytes[self.c_c_len + self.c_scal_len..]
    }

    /// Parse a wire encoding for `pp`'s parameter set.
    ///
    /// # Errors
    /// [`MaulError::CiphertextLength`] if `bytes` is not exactly
    /// [`crate::params::ParamSet::ciphertext_size`] long.
    pub fn from_bytes(pp: &PublicParams, bytes: &[u8]) -> Result<Self, MaulError> {
        let p = pp.params;
        if bytes.len() != p.ciphertext_size() {
            return Err(MaulError::CiphertextLength {
                expected: p.ciphertext_size(),
                got: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            c_c_len: p.c_c_size(),
            c_scal_len: p.c_scal_size(),
        })
    }
}

/// A 32-byte shared secret.
#[derive(Clone, Debug)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// The raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ConstantTimeEq for SharedSecret {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for SharedSecret {}

/// `dKeygen^FO_L(pp)` — left key pair from a PKE seed and a `nu`-bit rejection seed.
#[must_use]
pub fn keygen_left(
    pp: &PublicParams,
    pke_seed: &[u8; 32],
    fo_seed: &[u8],
) -> (LeftPublicKey, LeftSecretKey) {
    let (k, s) = pke::keygen(pp, pke_seed);
    (
        LeftPublicKey(k),
        LeftSecretKey {
            pke: s,
            fo_seed: fo_seed.to_vec(),
        },
    )
}

/// `dKeygen^FO_R(pp)` — right key pair.
#[must_use]
pub fn keygen_right(
    pp: &PublicParams,
    pke_seed: &[u8; 32],
    fo_seed: &[u8],
) -> (RightPublicKey, RightSecretKey) {
    let (k, s) = pke::keygen(pp, pke_seed);
    (
        RightPublicKey(k),
        RightSecretKey {
            pke: s,
            fo_seed: fo_seed.to_vec(),
        },
    )
}

/// Sample a left key pair, drawing both the PKE seed and the `nu`-bit rejection seed from `rng`.
pub fn generate_left<R: CryptoRng + Rng>(
    pp: &PublicParams,
    rng: &mut R,
) -> (LeftPublicKey, LeftSecretKey) {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let mut fo = alloc::vec![0u8; pp.params.nu_bytes()];
    rng.fill_bytes(&mut fo);
    let out = keygen_left(pp, &seed, &fo);
    seed.zeroize();
    fo.zeroize();
    out
}

/// Sample a right key pair.
pub fn generate_right<R: CryptoRng + Rng>(
    pp: &PublicParams,
    rng: &mut R,
) -> (RightPublicKey, RightSecretKey) {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let mut fo = alloc::vec![0u8; pp.params.nu_bytes()];
    rng.fill_bytes(&mut fo);
    let out = keygen_right(pp, &seed, &fo);
    seed.zeroize();
    fo.zeroize();
    out
}

fn pack_ciphertext(pp: &PublicParams, ct: &pke::PkeCiphertext) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let p = pp.params;
    let mut c_c = Vec::with_capacity(p.c_c_size());
    for poly in &ct.c_c {
        codec::pack_bits(poly, p.du, &mut c_c);
    }
    let mut c_l = Vec::with_capacity(p.c_scal_size());
    codec::pack_bits(&ct.c_l, p.dv, &mut c_l);
    let mut c_r = Vec::with_capacity(p.c_scal_size());
    codec::pack_bits(&ct.c_r, p.dv, &mut c_r);
    (c_c, c_l, c_r)
}

fn xor_into(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// `dEncaps^FO(pp, pk_L, pk_R)` with the two messages supplied explicitly.
///
/// Derandomised entry point. Used by the KAT vectors and by the evidence tests, which must pin
/// `(m_L, m_R)` to reason about what an adversary can and cannot reconstruct. Production callers
/// want [`encapsulate`], which draws both messages from a CSPRNG.
#[must_use]
pub fn encapsulate_with_messages(
    pp: &PublicParams,
    pk_l: &LeftPublicKey,
    pk_r: &RightPublicKey,
    m_l: &[u8; 32],
    m_r: &[u8; 32],
) -> (Ciphertext, SharedSecret) {
    let p = pp.params;
    let (rc, rl, rr) = hash::h_rand(p, &pk_l.0.bytes, &pk_r.0.bytes, m_l, m_r);
    let pke_ct = pke::encrypt(pp, &pk_l.0.t, &pk_r.0.t, &rc, &rl, &rr, m_l, m_r);
    let (c_c, c_l, c_r) = pack_ciphertext(pp, &pke_ct);
    let c_r_otp = xor_into(&c_r, &hash::h_otp(p, m_l));
    let k = hash::h_key(
        p,
        &pk_l.0.bytes,
        &pk_r.0.bytes,
        m_l,
        m_r,
        &c_c,
        &c_l,
        &c_r_otp,
    );

    let mut bytes = Vec::with_capacity(p.ciphertext_size());
    bytes.extend_from_slice(&c_c);
    bytes.extend_from_slice(&c_l);
    bytes.extend_from_slice(&c_r_otp);
    debug_assert_eq!(bytes.len(), p.ciphertext_size());

    (
        Ciphertext {
            bytes,
            c_c_len: p.c_c_size(),
            c_scal_len: p.c_scal_size(),
        },
        SharedSecret(k),
    )
}

/// `dEncaps^FO(pp, pk_L, pk_R)`.
pub fn encapsulate<R: CryptoRng + Rng>(
    pp: &PublicParams,
    pk_l: &LeftPublicKey,
    pk_r: &RightPublicKey,
    rng: &mut R,
) -> (Ciphertext, SharedSecret) {
    let mut m_l = [0u8; 32];
    let mut m_r = [0u8; 32];
    rng.fill_bytes(&mut m_l);
    rng.fill_bytes(&mut m_r);
    let out = encapsulate_with_messages(pp, pk_l, pk_r, &m_l, &m_r);
    m_l.zeroize();
    m_r.zeroize();
    out
}

/// `dDecaps^FO` — never fails; a malformed ciphertext yields the implicit-rejection key `k'`.
///
/// # Errors
/// [`MaulError::CiphertextLength`] only if `ct` was built for a different parameter set.
pub fn decapsulate(
    pp: &PublicParams,
    pk_l: &LeftPublicKey,
    pk_r: &RightPublicKey,
    sk_l: &LeftSecretKey,
    sk_r: &RightSecretKey,
    ct: &Ciphertext,
) -> Result<SharedSecret, MaulError> {
    let p = pp.params;
    if ct.bytes.len() != p.ciphertext_size() {
        return Err(MaulError::CiphertextLength {
            expected: p.ciphertext_size(),
            got: ct.bytes.len(),
        });
    }
    let c_c_b = ct.c_c_bytes();
    let c_l_b = ct.c_l_bytes();
    let c_r_otp_b = ct.c_r_otp_bytes();

    // k' <- H_rej(...) -- computed first and unconditionally, exactly as in Fig. 6.
    let k_rej = hash::h_rej(
        p,
        &pk_l.0.bytes,
        &pk_r.0.bytes,
        sk_l.fo_seed(),
        sk_r.fo_seed(),
        c_c_b,
        c_l_b,
        c_r_otp_b,
    );

    let c_c = unpack_vec(c_c_b, p.du, p.k).ok_or(MaulError::CiphertextLength {
        expected: p.ciphertext_size(),
        got: ct.bytes.len(),
    })?;
    let c_l = unpack_poly(c_l_b, p.dv).ok_or(MaulError::CiphertextLength {
        expected: p.ciphertext_size(),
        got: ct.bytes.len(),
    })?;

    // m'_L <- Decr_L(sk_L, (c_C, c_L))
    let m_l = pke::decrypt_side(pp, sk_l.pke_secret(), &c_c, &c_l);
    // c_R <- c_R^OTP XOR H_OTP(m'_L)
    let c_r_b = xor_into(c_r_otp_b, &hash::h_otp(p, &m_l));
    let c_r = unpack_poly(&c_r_b, p.dv).ok_or(MaulError::CiphertextLength {
        expected: p.ciphertext_size(),
        got: ct.bytes.len(),
    })?;
    // m'_R <- Decr_R(sk_R, (c_C, c_R))  -- THE step that requires the second secret key.
    let m_r = pke::decrypt_side(pp, sk_r.pke_secret(), &c_c, &c_r);

    // Re-encrypt under the re-derived randomness and compare.
    let (rc, rl, rr) = hash::h_rand(p, &pk_l.0.bytes, &pk_r.0.bytes, &m_l, &m_r);
    let re = pke::encrypt(pp, &pk_l.0.t, &pk_r.0.t, &rc, &rl, &rr, &m_l, &m_r);
    let (re_c, re_l, re_r) = pack_ciphertext(pp, &re);

    // Constant-time: the comparison is on values derived from the secret keys.
    let ok = re_c.ct_eq(c_c_b) & re_l.ct_eq(c_l_b) & re_r.ct_eq(&c_r_b);

    let k_ok = hash::h_key(
        p,
        &pk_l.0.bytes,
        &pk_r.0.bytes,
        &m_l,
        &m_r,
        c_c_b,
        c_l_b,
        c_r_otp_b,
    );

    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::conditional_select(&k_rej[i], &k_ok[i], ok);
    }
    Ok(SharedSecret(out))
}

fn unpack_poly(src: &[u8], bits: u32) -> Option<[u32; N]> {
    let v = codec::unpack_bits(src, bits, N)?;
    let mut out = [0u32; N];
    out.copy_from_slice(&v);
    Some(out)
}

fn unpack_vec(src: &[u8], bits: u32, k: usize) -> Option<Vec<[u32; N]>> {
    let per = N * (bits as usize) / 8;
    (0..k)
        .map(|i| unpack_poly(src.get(i * per..(i + 1) * per)?, bits))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{
        ALL,
        MAUL512,
        MAUL768,
        ParamSet,
    };

    struct Fixture {
        pp: PublicParams,
        pk_l: LeftPublicKey,
        sk_l: LeftSecretKey,
        pk_r: RightPublicKey,
        sk_r: RightSecretKey,
    }

    fn fixture(p: &'static ParamSet) -> Fixture {
        let pp = PublicParams::standard(p);
        let fo_l = alloc::vec![0x11u8; p.nu_bytes()];
        let fo_r = alloc::vec![0x22u8; p.nu_bytes()];
        let (pk_l, sk_l) = keygen_left(&pp, &[1u8; 32], &fo_l);
        let (pk_r, sk_r) = keygen_right(&pp, &[2u8; 32], &fo_r);
        Fixture {
            pp,
            pk_l,
            sk_l,
            pk_r,
            sk_r,
        }
    }

    #[test]
    fn encaps_decaps_round_trips_on_every_parameter_set() {
        for p in ALL {
            let f = fixture(p);
            let (ct, ss) =
                encapsulate_with_messages(&f.pp, &f.pk_l, &f.pk_r, &[0x5Au8; 32], &[0xA5u8; 32]);
            let got =
                decapsulate(&f.pp, &f.pk_l, &f.pk_r, &f.sk_l, &f.sk_r, &ct).expect("decapsulate");
            assert_eq!(got, ss, "{}: round trip failed", p.name);
        }
    }

    #[test]
    fn ciphertext_length_matches_table_5() {
        // Table 5 |ct| column: 896 / 1440 / 1856.
        for (p, want) in [
            (&MAUL512, 896usize),
            (&MAUL768, 1440),
            (&crate::params::MAUL1024, 1856),
        ] {
            let f = fixture(p);
            let (ct, _) =
                encapsulate_with_messages(&f.pp, &f.pk_l, &f.pk_r, &[1u8; 32], &[2u8; 32]);
            assert_eq!(ct.as_bytes().len(), want, "{} |ct|", p.name);
            assert_eq!(p.ciphertext_size(), want, "{} declared |ct|", p.name);
        }
    }

    #[test]
    fn a_corrupted_ciphertext_yields_the_rejection_key_not_the_real_one() {
        let f = fixture(&MAUL768);
        let (ct, ss) =
            encapsulate_with_messages(&f.pp, &f.pk_l, &f.pk_r, &[0x5Au8; 32], &[0xA5u8; 32]);
        for pos in [0usize, 500, 1055, 1056, 1247, 1248, 1439] {
            let mut bad = ct.as_bytes().to_vec();
            bad[pos] ^= 0x01;
            let ct2 = Ciphertext::from_bytes(&f.pp, &bad).expect("parse");
            let got =
                decapsulate(&f.pp, &f.pk_l, &f.pk_r, &f.sk_l, &f.sk_r, &ct2).expect("decapsulate");
            assert_ne!(
                got, ss,
                "flipping byte {pos} still produced the real secret"
            );
        }
    }

    #[test]
    fn otp_masking_is_an_involution_over_the_whole_space() {
        // Fig. 6 footnote 20 requires the right-ciphertext space to BE {0,1}^tau. dv-bit packing
        // makes it so: every dv-bit value is a legal compressed coefficient. Demonstrate by
        // showing an arbitrary bit pattern unpacks, repacks, and survives masking unchanged.
        for p in ALL {
            let mask = hash::h_otp(p, &[0x77u8; 32]);
            assert_eq!(mask.len(), p.c_scal_size(), "{} mask length", p.name);
            let arbitrary: Vec<u8> = (0..p.c_scal_size()).map(|i| (i * 31 + 7) as u8).collect();
            let masked = xor_into(&arbitrary, &mask);
            assert_eq!(
                xor_into(&masked, &mask),
                arbitrary,
                "{} not involutive",
                p.name
            );
            let poly = unpack_poly(&masked, p.dv).expect("every bit pattern must decode");
            let mut re = Vec::new();
            codec::pack_bits(&poly, p.dv, &mut re);
            assert_eq!(re, masked, "{} packing is not a bijection", p.name);
        }
    }

    #[test]
    fn wrong_ciphertext_length_is_rejected() {
        let f = fixture(&MAUL512);
        let err = Ciphertext::from_bytes(&f.pp, &[0u8; 10]).unwrap_err();
        assert!(matches!(err, MaulError::CiphertextLength { .. }), "{err:?}");
    }

    #[test]
    fn different_message_pairs_give_different_secrets_and_ciphertexts() {
        let f = fixture(&MAUL512);
        let (c1, s1) = encapsulate_with_messages(&f.pp, &f.pk_l, &f.pk_r, &[1u8; 32], &[2u8; 32]);
        let (c2, s2) = encapsulate_with_messages(&f.pp, &f.pk_l, &f.pk_r, &[1u8; 32], &[3u8; 32]);
        assert_ne!(s1, s2, "changing only m_R left the secret unchanged");
        assert_ne!(
            c1.as_bytes(),
            c2.as_bytes(),
            "changing only m_R left the wire unchanged"
        );
    }
}
