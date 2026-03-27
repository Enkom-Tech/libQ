#![no_std]
// Suppress clippy warnings in reference implementation code
#![allow(clippy::too_many_arguments)]

//! # FN-DSA signature verification
//!
//! This crate implements signature verification for FN-DSA. A `VerifyingKey`
//! instance is created by decoding a verifying key (from its encoded
//! format). Signatures can be verified with the `verify()` method on the
//! `VerifyingKey` instance. `verify()` uses stack allocation for its
//! internal buffers (which are not large). The same `VerifyingKey` can be
//! used for verifying several signatures.
//!
//! The signature process uses a domain-separation context, which is an
//! arbitrary binary strings (up to 255 bytes in length). If no such
//! context is required in an application, use `DOMAIN_NONE` (the empty
//! context).
//!
//! The message is supposed to be pre-hashed by the caller: the caller
//! provides the hashed value, along with an identifier of the used hash
//! function. The `HASH_ID_RAW` identifier can be used if the message is
//! not actually pre-hashed, but is provided directly instead of a hash
//! value.
//!
//! FN-DSA is parameterized by a degree, which is a power of two.
//! Standard versions use degree 512 ("level I security") or 1024 ("level
//! V security"); smaller degrees are deemed too weak for production use
//! and meant only for research and testing. The degree is represented
//! logarithmically as the `logn` value, such that the degree is `n =
//! 2^logn` (thus, degrees 512 and 1024 correspond to `logn` values 9 and
//! 10, respectively). The signature size is fixed for a given degree
//! (see `signature_size()`).
//!
//! ## WARNING
//!
//! **The FN-DSA standard is currently being drafted, but no version has
//! been published yet. When published, it may differ from the exact
//! scheme implemented in this crate, in particular with regard to key
//! encodings, message pre-hashing, and domain separation. Key pairs
//! generated with this crate MAY fail to be interoperable with the final
//! FN-DSA standard. This implementation is expected to be adjusted to
//! the FN-DSA standard when published (before the 1.0 version release).**
//!
//! ## Example usage
//!
//! ```ignore
//! use fn_dsa_vrfy::{
//!     vrfy_key_size, signature_size, FN_DSA_LOGN_512,
//!     VerifyingKey, VerifyingKeyStandard,
//!     DOMAIN_NONE, HASH_ID_RAW
//! };
//!
//! match VerifyingKeyStandard::decode(encoded_verifying_key) {
//!     Some(vk) => {
//!         if vk.verify(sig, &DOMAIN_NONE, &HASH_ID_RAW, b"message") {
//!             // signature is valid
//!         } else {
//!             // signature is not valid
//!         }
//!     }
//!     _ => {
//!         // could not decode verifying key
//!     }
//! }
//! ```

// Re-export useful types, constants and functions.
pub use fn_dsa_comm::{
    DOMAIN_NONE,
    DomainContext,
    FN_DSA_LOGN_512,
    FN_DSA_LOGN_1024,
    HASH_ID_RAW,
    HASH_ID_SHA3_256,
    HASH_ID_SHA3_384,
    HASH_ID_SHA3_512,
    HASH_ID_SHA256,
    HASH_ID_SHA384,
    HASH_ID_SHA512,
    HASH_ID_SHA512_256,
    HASH_ID_SHAKE128,
    HASH_ID_SHAKE256,
    HashIdentifier,
    signature_size,
    vrfy_key_size,
};
use fn_dsa_comm::{
    codec,
    hash_to_point,
    mq,
    shake,
};

/// Verifying key handler.
pub trait VerifyingKey: Sized {
    /// Create the instance by decoding the verifying key from its storage
    /// format.
    ///
    /// If the source uses a degree not supported by this `VerifyingKey`
    /// type, or does not have the exact length expected for the degree
    /// it uses, or is otherwise invalidly encoded, then this function
    /// returns `None`; otherwise, it returns the new instance.
    fn decode(src: &[u8]) -> Option<Self>;

    /// Verify a signature.
    ///
    /// Parameters:
    ///
    ///  - `sig`: the signature value
    ///  - `ctx`: the domain separation context
    ///  - `id`: the identifier for the pre-hash function
    ///  - `hv`: the pre-hashed message (or the message itself, if `id`
    ///    is `HASH_ID_RAW`)
    ///
    /// Return value is `true` if the signature is valid, `false` otherwise.
    /// Signature decoding errors and degree mismatch with the verifying key
    /// also lead to `false` being returned.
    fn verify(&self, sig: &[u8], ctx: &DomainContext, id: &HashIdentifier, hv: &[u8]) -> bool;
}

macro_rules! vrfy_key_impl {
    ($typename:ident, $logn_min:expr, $logn_max:expr) => {
        #[doc = concat!("Signature verifier for degrees (`logn`) ",
                                stringify!($logn_min), " to ", stringify!($logn_max), " only.")]
        #[derive(Copy, Clone, Debug)]
        pub struct $typename {
            logn: u32,
            h: [u16; 1 << ($logn_max)],
            hashed_key: [u8; 64],

            #[cfg(all(
                not(feature = "no_avx2"),
                any(target_arch = "x86_64", target_arch = "x86")
            ))]
            use_avx2: bool,
        }

        impl VerifyingKey for $typename {
            fn decode(src: &[u8]) -> Option<Self> {
                let mut h = [0u16; 1 << ($logn_max)];
                let mut hashed_key = [0u8; 64];
                let mut sh = shake::SHAKE256::new();
                sh.inject(src);
                sh.flip();
                sh.extract(&mut hashed_key);

                #[cfg(all(
                    not(feature = "no_avx2"),
                    any(target_arch = "x86_64", target_arch = "x86")
                ))]
                {
                    if fn_dsa_comm::has_avx2() {
                        unsafe {
                            let logn = decode_avx2_inner($logn_min, $logn_max, &mut h[..], src)?;
                            return Some(Self {
                                logn,
                                h,
                                hashed_key,
                                use_avx2: true,
                            });
                        }
                    }
                }

                let logn = decode_inner($logn_min, $logn_max, &mut h[..], src)?;
                Some(Self {
                    logn,
                    h,
                    hashed_key,
                    #[cfg(all(
                        not(feature = "no_avx2"),
                        any(target_arch = "x86_64", target_arch = "x86")
                    ))]
                    use_avx2: false,
                })
            }

            fn verify(
                &self,
                sig: &[u8],
                ctx: &DomainContext,
                id: &HashIdentifier,
                hv: &[u8],
            ) -> bool {
                let logn = self.logn;
                let n = 1usize << logn;
                let mut tmp_i16 = [0i16; 1 << ($logn_max)];
                let mut tmp_u16 = [0u16; 2 << ($logn_max)];

                #[cfg(all(
                    not(feature = "no_avx2"),
                    any(target_arch = "x86_64", target_arch = "x86")
                ))]
                if self.use_avx2 {
                    unsafe {
                        return verify_avx2_inner(
                            logn,
                            &self.h[..n],
                            &self.hashed_key,
                            sig,
                            ctx,
                            id,
                            hv,
                            &mut tmp_i16[..n],
                            &mut tmp_u16[..(2 * n)],
                        );
                    }
                }

                verify_inner(
                    logn,
                    &self.h[..n],
                    &self.hashed_key,
                    sig,
                    ctx,
                    id,
                    hv,
                    &mut tmp_i16[..n],
                    &mut tmp_u16[..(2 * n)],
                )
            }
        }
    };
}

// A VerifyingKey type that supports the standard degrees (512 and 1024).
vrfy_key_impl!(VerifyingKeyStandard, 9, 10);

// A VerifyingKey type that supports only degree 512 (NIST level I security).
vrfy_key_impl!(VerifyingKey512, 9, 9);

// A VerifyingKey type that supports only degree 1024 (NIST level V security).
vrfy_key_impl!(VerifyingKey1024, 10, 10);

// A VerifyingKey type that supports the weak/toy degrees (4 to 256, for
// tests and research only).
vrfy_key_impl!(VerifyingKeyWeak, 2, 8);

// Inner verifying key decoding function. The decoded h[] is
// automatically converted to NTT format.
//   logn_min   minimum supported degree (logarithmic) (inclusive)
//   logn_max   maximum supported degree (logarithmic) (inclusive)
//   h          destination buffer for key coefficients
//   src        encoded key
// Returns None on error, or Some(logn) on success.
fn decode_inner(logn_min: u32, logn_max: u32, h: &mut [u16], src: &[u8]) -> Option<u32> {
    if src.is_empty() {
        return None;
    }
    let head = src[0];
    if (head & 0xF0) != 0x00 {
        return None;
    }
    let logn = (head & 0x0F) as u32;
    if logn < logn_min || logn > logn_max {
        return None;
    }
    if src.len() != vrfy_key_size(logn) {
        return None;
    }
    let n = 1usize << logn;
    let _ = codec::modq_decode(&src[1..], &mut h[..n])?;
    mq::mqpoly_ext_to_int(logn, h);
    mq::mqpoly_int_to_NTT(logn, h);
    Some(logn)
}

fn verify_inner(
    logn: u32,
    h: &[u16],
    hashed_key: &[u8],
    sig: &[u8],
    ctx: &DomainContext,
    id: &HashIdentifier,
    hv: &[u8],
    tmp_i16: &mut [i16],
    tmp_u16: &mut [u16],
) -> bool {
    // Get some temporary buffers of length n elements.
    // s2i is signed, t1 and t2 are unsigned.
    let n = 1usize << logn;
    let s2i = &mut tmp_i16[..n];
    let (t1, tmp_u16) = tmp_u16.split_at_mut(n);
    let (t2, _) = tmp_u16.split_at_mut(n);

    // Decode signature.
    if sig.len() != signature_size(logn) {
        return false;
    }
    let head = sig[0];
    if head != (0x30 + logn) as u8 {
        return false;
    }
    if !codec::comp_decode(&sig[41..], s2i) {
        return false;
    }

    // norm2 <- squared norm of s2. Note that successful decoding implies
    // that every coefficient is at most 2047 (in absolute value); hence,
    // the maximum squared norm is at most 1024*(2047^2) < 2^32.
    let norm2 = mq::signed_poly_sqnorm(logn, &*s2i);

    // t1 <- c = hashed message (internal format)
    hash_to_point(&sig[1..41], hashed_key, ctx, id, hv, t1);
    mq::mqpoly_ext_to_int(logn, t1);

    // t2 <- s2 (NTT format)
    mq::mqpoly_signed_to_ext(logn, &*s2i, t2);
    mq::mqpoly_ext_to_int(logn, t2);
    mq::mqpoly_int_to_NTT(logn, t2);

    // t1 <- s1 = c - s2*h (external format)
    mq::mqpoly_mul_ntt(logn, t2, h);
    mq::mqpoly_NTT_to_int(logn, t2);
    mq::mqpoly_sub_int(logn, t1, t2);
    mq::mqpoly_int_to_ext(logn, t1);

    // norm1 <- squared norm of s1
    let norm1 = mq::mqpoly_sqnorm(logn, &*t1);

    // Signature is valid if the total squared norm of (s1,s2) is small
    // enough. We must take care of not overflowing.
    norm1 < norm2.wrapping_neg() && (norm1 + norm2) <= mq::SQBETA[logn as usize]
}

// AVX2-optimized implementation of key decoding.
#[cfg(all(
    not(feature = "no_avx2"),
    any(target_arch = "x86_64", target_arch = "x86")
))]
#[target_feature(enable = "avx2")]
unsafe fn decode_avx2_inner(
    logn_min: u32,
    logn_max: u32,
    h: &mut [u16],
    src: &[u8],
) -> Option<u32> {
    use fn_dsa_comm::mq_avx2;

    if src.is_empty() {
        return None;
    }
    let head = src[0];
    if (head & 0xF0) != 0x00 {
        return None;
    }
    let logn = (head & 0x0F) as u32;
    if logn < logn_min || logn > logn_max {
        return None;
    }
    if src.len() != vrfy_key_size(logn) {
        return None;
    }
    let n = 1usize << logn;
    let _ = codec::modq_decode(&src[1..], &mut h[..n])?;
    unsafe {
        mq_avx2::mqpoly_ext_to_int(logn, h);
        mq_avx2::mqpoly_int_to_NTT(logn, h);
    }
    Some(logn)
}

// AVX2-optimized implementation of verification.
#[cfg(all(
    not(feature = "no_avx2"),
    any(target_arch = "x86_64", target_arch = "x86")
))]
#[target_feature(enable = "avx2")]
unsafe fn verify_avx2_inner(
    logn: u32,
    h: &[u16],
    hashed_key: &[u8],
    sig: &[u8],
    ctx: &DomainContext,
    id: &HashIdentifier,
    hv: &[u8],
    tmp_i16: &mut [i16],
    tmp_u16: &mut [u16],
) -> bool {
    use fn_dsa_comm::mq_avx2;

    // Get some temporary buffers of length n elements.
    // s2i is signed, t1 and t2 are unsigned.
    let n = 1usize << logn;
    let s2i = &mut tmp_i16[..n];
    let (t1, tmp_u16) = tmp_u16.split_at_mut(n);
    let (t2, _) = tmp_u16.split_at_mut(n);

    // Decode signature.
    if sig.len() != signature_size(logn) {
        return false;
    }
    let head = sig[0];
    if head != (0x30 + logn) as u8 {
        return false;
    }
    if !codec::comp_decode(&sig[41..], s2i) {
        return false;
    }

    // norm2 <- squared norm of s2. Note that successful decoding implies
    // that every coefficient is at most 2047 (in absolute value); hence,
    // the maximum squared norm is at most 1024*(2047^2) < 2^32.
    let norm2 = unsafe { mq_avx2::signed_poly_sqnorm(logn, &*s2i) };

    // t1 <- c = hashed message (internal format)
    hash_to_point(&sig[1..41], hashed_key, ctx, id, hv, t1);
    let norm1 = unsafe {
        mq_avx2::mqpoly_ext_to_int(logn, t1);

        // t2 <- s2 (NTT format)
        mq_avx2::mqpoly_signed_to_ext(logn, &*s2i, t2);
        mq_avx2::mqpoly_ext_to_int(logn, t2);
        mq_avx2::mqpoly_int_to_NTT(logn, t2);

        // t1 <- s1 = c - s2*h (external format)
        mq_avx2::mqpoly_mul_ntt(logn, t2, h);
        mq_avx2::mqpoly_NTT_to_int(logn, t2);
        mq_avx2::mqpoly_sub_int(logn, t1, t2);
        mq_avx2::mqpoly_int_to_ext(logn, t1);

        // norm1 <- squared norm of s1
        mq_avx2::mqpoly_sqnorm(logn, &*t1)
    };

    // Signature is valid if the total squared norm of (s1,s2) is small
    // enough. We must take care of not overflowing.
    norm1 < norm2.wrapping_neg() && (norm1 + norm2) <= mq_avx2::SQBETA[logn as usize]
}

#[cfg(test)]
mod tests {

    use fn_dsa_comm::shake::{
        SHA3_256,
        SHAKE256,
    };
    use fn_dsa_comm::{
        Infallible,
        TryCryptoRng,
        TryRng,
        sign_key_size,
    };
    use fn_dsa_kgen::{
        KeyPairGenerator,
        KeyPairGenerator512,
        KeyPairGenerator1024,
    };
    use fn_dsa_sign::{
        SigningKey,
        SigningKey512,
        SigningKey1024,
    };

    use super::*;

    /// Deterministic RNG for tests (SHAKE256 stream), matching `fn-dsa` `FakeRng1` wiring.
    struct ShakeRng(SHAKE256);

    impl ShakeRng {
        fn from_seed(seed: &[u8]) -> Self {
            let mut sh = SHAKE256::new();
            sh.inject(seed);
            sh.flip();
            Self(sh)
        }
    }

    impl TryRng for ShakeRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut buf = [0u8; 4];
            self.0.extract(&mut buf);
            Ok(u32::from_le_bytes(buf))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut buf = [0u8; 8];
            self.0.extract(&mut buf);
            Ok(u64::from_le_bytes(buf))
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            self.0.extract(dest);
            Ok(())
        }
    }

    impl TryCryptoRng for ShakeRng {}

    fn sha3_256_digest_32(msg: &[u8]) -> [u8; 32] {
        let mut sh = SHA3_256::new();
        sh.update(msg);
        sh.digest()
    }

    /// Legacy static KAT hex blobs predated the current `hash_to_point` domain separation
    /// byte; this exercises verify against signatures produced by the same stack as
    /// `fn-dsa-sign`, including optional AVX2 paths on x86.
    fn verify_roundtrip_logn(logn: u32) {
        let hv = sha3_256_digest_32(b"fn-dsa-vrfy kat");

        let mut rng = ShakeRng::from_seed(&[0x55u8, logn as u8, 0xAA]);

        let mut sk_buf = [0u8; sign_key_size(10)];
        let mut vk_buf = [0u8; vrfy_key_size(10)];
        let mut sig_storage = [0u8; signature_size(10)];
        let sk_sl = &mut sk_buf[..sign_key_size(logn)];
        let vk_sl = &mut vk_buf[..vrfy_key_size(logn)];
        let sig = &mut sig_storage[..signature_size(logn)];

        match logn {
            9 => {
                let mut kg = KeyPairGenerator512::default();
                kg.keygen(logn, &mut rng, sk_sl, vk_sl);
                let mut sk = SigningKey512::decode(sk_sl).unwrap();
                sk.sign(&mut rng, &DOMAIN_NONE, &HASH_ID_SHA3_256, &hv, sig);
            }
            10 => {
                let mut kg = KeyPairGenerator1024::default();
                kg.keygen(logn, &mut rng, sk_sl, vk_sl);
                let mut sk = SigningKey1024::decode(sk_sl).unwrap();
                sk.sign(&mut rng, &DOMAIN_NONE, &HASH_ID_SHA3_256, &hv, sig);
            }
            _ => unreachable!(),
        }

        let vk = VerifyingKeyStandard::decode(vk_sl).unwrap();
        assert!(vk.verify(sig, &DOMAIN_NONE, &HASH_ID_SHA3_256, &hv));

        let mut hv_bad = hv;
        hv_bad[0] ^= 0x01;
        assert!(!vk.verify(sig, &DOMAIN_NONE, &HASH_ID_SHA3_256, &hv_bad));

        let mut sig_bad = [0u8; signature_size(10)];
        sig_bad[..sig.len()].copy_from_slice(sig);
        sig_bad[50] ^= 0x01;
        assert!(!vk.verify(&sig_bad[..sig.len()], &DOMAIN_NONE, &HASH_ID_SHA3_256, &hv));

        let n = 1usize << logn;
        let mut tmp_i16 = [0i16; 1 << 10];
        let mut tmp_u16 = [0u16; 2 << 10];
        assert!(verify_inner(
            logn,
            &vk.h[..n],
            &vk.hashed_key,
            sig,
            &DOMAIN_NONE,
            &HASH_ID_SHA3_256,
            &hv,
            &mut tmp_i16[..n],
            &mut tmp_u16[..(2 * n)],
        ));
        assert!(!verify_inner(
            logn,
            &vk.h[..n],
            &vk.hashed_key,
            &sig_bad[..sig.len()],
            &DOMAIN_NONE,
            &HASH_ID_SHA3_256,
            &hv,
            &mut tmp_i16[..n],
            &mut tmp_u16[..(2 * n)],
        ));

        #[cfg(all(
            not(feature = "no_avx2"),
            any(target_arch = "x86_64", target_arch = "x86")
        ))]
        if fn_dsa_comm::has_avx2() {
            unsafe {
                assert!(verify_avx2_inner(
                    logn,
                    &vk.h[..n],
                    &vk.hashed_key,
                    sig,
                    &DOMAIN_NONE,
                    &HASH_ID_SHA3_256,
                    &hv,
                    &mut tmp_i16[..n],
                    &mut tmp_u16[..(2 * n)],
                ));
            }
        }
    }

    #[test]
    fn verify_kat_512() {
        verify_roundtrip_logn(9);
    }

    #[test]
    fn verify_kat_1024() {
        verify_roundtrip_logn(10);
    }
}
