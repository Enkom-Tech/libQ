#![no_std]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(clippy::too_many_arguments)]

//! # FN-DSA signature generation
//!
//! This crate implements signature generation for FN-DSA. A `SigningKey`
//! instance is created by decoding a signing key (from its encoded
//! format). Signatures can be generated with the `sign()` method on the
//! `SigningKey` instance. `sign()` uses the instance mutably because the
//! process uses relatively large RAM buffers which are part of the
//! instance (to avoid oversized stack allocation on embedded systems).
//! The same `SigningKey` can be used for generating several signatures;
//! this even allows CPU savings since some computations depend only on
//! the key and can be reused for several signatures.
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
//! use rand_core::OsRng;
//! use fn_dsa_sign::{
//!     sign_key_size, signature_size, FN_DSA_LOGN_512,
//!     SigningKey, SigningKeyStandard,
//!     DOMAIN_NONE, HASH_ID_RAW,
//! };
//!
//! let mut sk = SigningKeyStandard::decode(encoded_signing_key)?;
//! let mut sig = vec![0u8; signature_size(sk.get_logn())];
//! sk.sign(&mut OsRng, &DOMAIN_NONE, &HASH_ID_RAW, b"message", &mut sig);
//! ```

mod flr;
mod poly;
mod sampler;

// Re-export useful types, constants and functions.
pub use fn_dsa_comm::{
    CryptoRng,
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
    Rng,
    RngError,
    sign_key_size,
    signature_size,
    vrfy_key_size,
};
use fn_dsa_comm::{
    PRNG,
    codec,
    hash_to_point,
    mq,
    shake,
};
use zeroize::{
    Zeroize,
    ZeroizeOnDrop,
};

/// Signing key handler and temporary buffers.
///
/// Signature generation uses relatively large temporary buffers (about
/// 42 or 84 kB, for the two standard degrees), which is why they are
/// part of the `SigningKey` instance instead of being allocated on the
/// stack. An instance can be used for several successive signature
/// generations. Implementations of this trait are expected to handle
/// automatic zeroization (overwrite of all contained secret values when
/// the object is released).
pub trait SigningKey: Sized {
    /// Create the instance by decoding the signing key from its storage
    /// format.
    ///
    /// If the source uses a degree not supported by this `SigningKey`
    /// type, or does not have the exact length expected for the degree
    /// it uses, or is otherwise invalidly encoded, then this function
    /// returns `None`; otherwise, it returns the new instance.
    fn decode(sec: &[u8]) -> Option<Self>;

    /// Get the degree associated with this key.
    ///
    /// The degree is returned in a logarithmic scale (`logn`, value ranges
    /// from 2 to 10).
    fn get_logn(&self) -> u32;

    /// Encode the public (verifying) key into the provided buffer.
    ///
    /// The output buffer must have the exact size of the verifying key.
    fn to_verifying_key(&self, vrfy_key: &mut [u8]);

    /// Generate a signature.
    ///
    /// Parameters:
    ///
    ///  - `rng`: a cryptographically secure random source
    ///  - `ctx`: the domain separation context
    ///  - `id`: the identifier for the pre-hash function
    ///  - `hv`: the pre-hashed message (or the message itself, if `id`
    ///    is `HASH_ID_RAW`)
    ///  - `sig`: the output slice for the generated signature; its size
    ///    MUST be exactly that expected for the key degree (see
    ///    `signature_size()`).
    fn sign<T: CryptoRng + Rng>(
        &mut self,
        rng: &mut T,
        ctx: &DomainContext,
        id: &HashIdentifier,
        hv: &[u8],
        sig: &mut [u8],
    );
}

macro_rules! sign_key_impl {
    ($typename:ident, $logn_min:expr, $logn_max:expr) => {
        #[doc = concat!("Signature generator for degrees (`logn`) ",
                                stringify!($logn_min), " to ", stringify!($logn_max), " only.")]
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $typename {
            f: [i8; 1 << ($logn_max)],
            g: [i8; 1 << ($logn_max)],
            F: [i8; 1 << ($logn_max)],
            G: [i8; 1 << ($logn_max)],
            vrfy_key: [u8; vrfy_key_size($logn_max)],
            hashed_vrfy_key: [u8; 64],
            tmp_i16: [i16; 1 << ($logn_max)],
            tmp_u16: [u16; 2 << ($logn_max)],
            tmp_flr: [flr::Flr; 9 << ($logn_max)],

            // Basis B = [[g, -f], [G, -F]], in FFT format.
            #[cfg(not(feature = "small_context"))]
            basis: [flr::Flr; 4 << ($logn_max)],

            logn: u32,

            // On x86_64, we use AVX2 if available, which is dynamically
            // tested. We do not do that on plain x86, because plain x86 uses
            // the emulated floating-point, not the native types (on 32-bit
            // x86, native floating-point is x87, not SSE2).
            #[cfg(all(not(feature = "no_avx2"), target_arch = "x86_64"))]
            use_avx2: bool,
        }

        impl $typename {
            fn decode_key(&mut self, src: &[u8]) -> Option<u32> {
                #[cfg(all(not(feature = "no_avx2"), target_arch = "x86_64"))]
                if self.use_avx2 {
                    unsafe {
                        return sign_avx2::decode_avx2_inner(
                            $logn_min,
                            $logn_max,
                            &mut self.f[..],
                            &mut self.g[..],
                            &mut self.F[..],
                            &mut self.G[..],
                            &mut self.vrfy_key[..],
                            &mut self.hashed_vrfy_key[..],
                            &mut self.tmp_u16[..],
                            src,
                        );
                    }
                }

                decode_inner(
                    $logn_min,
                    $logn_max,
                    &mut self.f[..],
                    &mut self.g[..],
                    &mut self.F[..],
                    &mut self.G[..],
                    &mut self.vrfy_key[..],
                    &mut self.hashed_vrfy_key[..],
                    &mut self.tmp_u16[..],
                    src,
                )
            }

            #[cfg(not(feature = "small_context"))]
            fn compute_basis(&mut self) {
                let n = 1usize << self.logn;

                #[cfg(all(not(feature = "no_avx2"), target_arch = "x86_64"))]
                if self.use_avx2 {
                    unsafe {
                        sign_avx2::compute_basis_avx2_inner(
                            self.logn,
                            &self.f[..n],
                            &self.g[..n],
                            &self.F[..n],
                            &self.G[..n],
                            &mut self.basis[..(4 * n)],
                        );
                    }
                    return;
                }

                compute_basis_inner(
                    self.logn,
                    &self.f[..n],
                    &self.g[..n],
                    &self.F[..n],
                    &self.G[..n],
                    &mut self.basis[..(4 * n)],
                );
            }
        }

        impl SigningKey for $typename {
            fn decode(src: &[u8]) -> Option<Self> {
                let f = [0i8; 1 << ($logn_max)];
                let g = [0i8; 1 << ($logn_max)];
                let F = [0i8; 1 << ($logn_max)];
                let G = [0i8; 1 << ($logn_max)];
                let vrfy_key = [0u8; vrfy_key_size($logn_max)];
                let hashed_vrfy_key = [0u8; 64];
                let tmp_i16 = [0i16; 1 << ($logn_max)];
                let tmp_u16 = [0u16; 2 << ($logn_max)];
                let tmp_flr = [flr::Flr::ZERO; 9 << ($logn_max)];

                #[cfg(not(feature = "small_context"))]
                let basis = [flr::Flr::ZERO; 4 << ($logn_max)];

                let mut sk = Self {
                    f,
                    g,
                    F,
                    G,
                    vrfy_key,
                    hashed_vrfy_key,
                    tmp_i16,
                    tmp_u16,
                    tmp_flr,
                    #[cfg(not(feature = "small_context"))]
                    basis,
                    logn: 0,
                    #[cfg(all(not(feature = "no_avx2"), target_arch = "x86_64"))]
                    use_avx2: fn_dsa_comm::has_avx2(),
                };
                sk.logn = sk.decode_key(src)?;

                #[cfg(not(feature = "small_context"))]
                sk.compute_basis();

                Some(sk)
            }

            fn get_logn(&self) -> u32 {
                self.logn
            }

            fn to_verifying_key(&self, vrfy_key: &mut [u8]) {
                let len = vrfy_key_size(self.logn);
                assert!(vrfy_key.len() == len);
                vrfy_key.copy_from_slice(&self.vrfy_key[..len]);
            }

            fn sign<T: CryptoRng + Rng>(
                &mut self,
                rng: &mut T,
                ctx: &DomainContext,
                id: &HashIdentifier,
                hv: &[u8],
                sig: &mut [u8],
            ) {
                let n = 1usize << self.logn;

                #[cfg(all(not(feature = "no_avx2"), target_arch = "x86_64"))]
                if self.use_avx2 {
                    unsafe {
                        #[cfg(feature = "shake256x4")]
                        sign_avx2::sign_avx2_inner::<T, shake::SHAKE256x4>(
                            self.logn,
                            rng,
                            &self.f[..n],
                            &self.g[..n],
                            &self.F[..n],
                            &self.G[..n],
                            &self.hashed_vrfy_key,
                            ctx,
                            id,
                            hv,
                            sig,
                            #[cfg(not(feature = "small_context"))]
                            &self.basis[..(4 * n)],
                            &mut self.tmp_i16,
                            &mut self.tmp_u16,
                            &mut self.tmp_flr,
                        );

                        #[cfg(not(feature = "shake256x4"))]
                        sign_avx2::sign_avx2_inner::<T, shake::SHAKE256_PRNG>(
                            self.logn,
                            rng,
                            &self.f[..n],
                            &self.g[..n],
                            &self.F[..n],
                            &self.G[..n],
                            &self.hashed_vrfy_key,
                            ctx,
                            id,
                            hv,
                            sig,
                            #[cfg(not(feature = "small_context"))]
                            &self.basis[..(4 * n)],
                            &mut self.tmp_i16,
                            &mut self.tmp_u16,
                            &mut self.tmp_flr,
                        );
                    }
                    return;
                }

                #[cfg(feature = "shake256x4")]
                sign_inner::<T, shake::SHAKE256x4>(
                    self.logn,
                    rng,
                    &self.f[..n],
                    &self.g[..n],
                    &self.F[..n],
                    &self.G[..n],
                    &self.hashed_vrfy_key,
                    ctx,
                    id,
                    hv,
                    sig,
                    #[cfg(not(feature = "small_context"))]
                    &self.basis[..(4 * n)],
                    &mut self.tmp_i16,
                    &mut self.tmp_u16,
                    &mut self.tmp_flr,
                );

                #[cfg(not(feature = "shake256x4"))]
                sign_inner::<T, shake::SHAKE256_PRNG>(
                    self.logn,
                    rng,
                    &self.f[..n],
                    &self.g[..n],
                    &self.F[..n],
                    &self.G[..n],
                    &self.hashed_vrfy_key,
                    ctx,
                    id,
                    hv,
                    sig,
                    #[cfg(not(feature = "small_context"))]
                    &self.basis[..(4 * n)],
                    &mut self.tmp_i16,
                    &mut self.tmp_u16,
                    &mut self.tmp_flr,
                );
            }
        }
    };
}

// A SigningKey type that supports the standard degrees (512 and 1024).
sign_key_impl!(SigningKeyStandard, 9, 10);

// A SigningKey type that supports only degree 512. It uses less RAM than
// SigningKeyStandard.
sign_key_impl!(SigningKey512, 9, 9);

// A SigningKey type that supports only degree 1024. It uses as much RAM as
// SigningKeyStandard but enforces the level V security variant.
sign_key_impl!(SigningKey1024, 10, 10);

// A SigningKey type that supports only weak/toy degrees (4 to 256). It is
// meant only for research and testing purposes.
sign_key_impl!(SigningKeyWeak, 2, 8);

#[cfg(all(not(feature = "no_avx2"), target_arch = "x86_64"))]
mod sign_avx2;

// Decode a private key.
fn decode_inner(
    logn_min: u32,
    logn_max: u32,
    f: &mut [i8],
    g: &mut [i8],
    F: &mut [i8],
    G: &mut [i8],
    vrfy_key: &mut [u8],
    hashed_vrfy_key: &mut [u8],
    tmp_u16: &mut [u16],
    src: &[u8],
) -> Option<u32> {
    if src.is_empty() {
        return None;
    }
    let head = src[0];
    if (head & 0xF0) != 0x50 {
        return None;
    }
    let logn = (head & 0x0F) as u32;
    if logn < logn_min || logn > logn_max {
        return None;
    }
    if src.len() != sign_key_size(logn) {
        return None;
    }
    let n = 1usize << logn;
    assert!(f.len() >= n);
    assert!(g.len() >= n);
    assert!(F.len() >= n);
    assert!(G.len() >= n);
    assert!(vrfy_key.len() >= vrfy_key_size(logn));
    assert!(hashed_vrfy_key.len() == 64);
    let f = &mut f[..n];
    let g = &mut g[..n];
    let F = &mut F[..n];
    let G = &mut G[..n];
    let vk = &mut vrfy_key[..vrfy_key_size(logn)];

    // Coefficients of (f,g) use a number of bits that depends on logn.
    let nbits_fg = match logn {
        2..=5 => 8,
        6..=7 => 7,
        8..=9 => 6,
        _ => 5,
    };
    let j = 1 + codec::trim_i8_decode(&src[1..], f, nbits_fg)?;
    let j = j + codec::trim_i8_decode(&src[j..], g, nbits_fg)?;
    let j = j + codec::trim_i8_decode(&src[j..], F, 8)?;
    // We already checked the length of src; any mismatch at this point
    // is an implementation bug.
    assert!(j == src.len());

    // Compute G from f, g and F. This might fail if the decoded f turns
    // out to be non-invertible modulo X^n+1 and q, or if the recomputed G
    // is out of the allowed range (its coefficients should all be in
    // the [-127,+127] range).
    // Method:
    //   f*G - g*F = q = 0 mod q
    // thus:
    //   G = g*F/f mod q
    // We also compute the public key h = g/f mod q.
    let (w0, w1) = tmp_u16.split_at_mut(n);

    // w0 <- g/f  (NTT)
    mq::mqpoly_small_to_int(logn, &*g, w0);
    mq::mqpoly_small_to_int(logn, &*f, w1);
    mq::mqpoly_int_to_NTT(logn, w0);
    mq::mqpoly_int_to_NTT(logn, w1);
    if !mq::mqpoly_div_ntt(logn, w0, w1) {
        // f is not invertible
        return None;
    }

    // w1 <- h*F = g*F/f = G  (NTT)
    mq::mqpoly_small_to_int(logn, &*F, w1);
    mq::mqpoly_int_to_NTT(logn, w1);
    mq::mqpoly_mul_ntt(logn, w1, w0);

    // Convert back h to external representation and encode it.
    mq::mqpoly_NTT_to_int(logn, w0);
    mq::mqpoly_int_to_ext(logn, w0);
    vk[0] = logn as u8;
    let j = 1 + codec::modq_encode(&w0[..n], &mut vk[1..]);
    assert!(j == vk.len());
    let mut sh = shake::SHAKE256::new();
    sh.inject(vk);
    sh.flip();
    sh.extract(hashed_vrfy_key);

    // Convert back G to external representation and check that all
    // elements are small.
    mq::mqpoly_NTT_to_int(logn, w1);
    if !mq::mqpoly_int_to_small(logn, w1, G) {
        return None;
    }

    // Decoding succeeded.
    Some(logn)
}

fn compute_basis_inner(logn: u32, f: &[i8], g: &[i8], F: &[i8], G: &[i8], basis: &mut [flr::Flr]) {
    let n = 1usize << logn;

    // Lattice basis is B = [[g, -f], [G, -F]].
    let (b00, work) = basis.split_at_mut(n);
    let (b01, work) = work.split_at_mut(n);
    let (b10, work) = work.split_at_mut(n);
    let (b11, _) = work.split_at_mut(n);

    poly::poly_set_small(logn, b01, f);
    poly::poly_set_small(logn, b00, g);
    poly::poly_set_small(logn, b11, F);
    poly::poly_set_small(logn, b10, G);
    poly::FFT(logn, b01);
    poly::FFT(logn, b00);
    poly::FFT(logn, b11);
    poly::FFT(logn, b10);
    poly::poly_neg(logn, b01);
    poly::poly_neg(logn, b11);
}

// 1/12289
const INV_Q: flr::Flr = flr::Flr::scaled(6004310871091074, -66);

fn sign_inner<T: CryptoRng + Rng, P: PRNG>(
    logn: u32,
    rng: &mut T,
    f: &[i8],
    g: &[i8],
    F: &[i8],
    G: &[i8],
    hashed_vrfy_key: &[u8],
    ctx: &DomainContext,
    id: &HashIdentifier,
    hv: &[u8],
    sig: &mut [u8],
    #[cfg(not(feature = "small_context"))] basis: &[flr::Flr],
    tmp_i16: &mut [i16],
    tmp_u16: &mut [u16],
    tmp_flr: &mut [flr::Flr],
) {
    let n = 1usize << logn;
    assert!(f.len() == n);
    assert!(g.len() == n);
    assert!(F.len() == n);
    assert!(G.len() == n);
    assert!(sig.len() == signature_size(logn));

    // Original Falcon support removed for security - always use proper FN-DSA

    // Hash the message with a 40-byte random nonce, to produce the
    // hashed message.
    let mut nonce = [0u8; 40];
    let mut first = true;

    // Usually the signature generation works at the first attempt, but
    // occasionally we need to try again because the obtained signature
    // is not a short enough vector, or cannot be encoded in the target
    // signature size.
    loop {
        let hm = &mut tmp_u16[0..n];
        // We must generate a random 40-byte nonce, and hash the
        // message to a polynomial hm[].
        // In FN-DSA, message hashing is done at each loop restart for security
        if first {
            rng.fill_bytes(&mut nonce);
            hash_to_point(&nonce, hashed_vrfy_key, ctx, id, hv, hm);
            first = false;
        }

        // We initialize the PRNG with a 56-byte seed, to match the
        // practice from the C code (it makes it simpler to reproduce
        // test vectors). Any seed of at least 32 bytes would be fine.
        let mut seed = [0u8; 56];
        rng.fill_bytes(&mut seed);
        let mut samp = sampler::Sampler::<P>::new(logn, &seed);

        // Lattice basis is B = [[g, -f], [G, -F]]. We need it in FFT
        // format, then we compute the Gram matrix G = B*adj(B).
        // Formulas are:
        //   g00 = b00*adj(b00) + b01*adj(b01)
        //   g01 = b00*adj(b10) + b01*adj(b11)
        //   g10 = b10*adj(b00) + b11*adj(b01)
        //   g11 = b10*adj(b10) + b11*adj(b11)
        //
        // For historical reasons, this implementation uses g00,
        // g01 and g11 (upper triangle), and omits g10, which is
        // equal to adj(g01).
        //
        // We need the following in tmp_flr:
        //   g00 g01 g11 b11 b01

        #[cfg(feature = "small_context")]
        {
            // We do not have a precomputed basis, we recompute it.
            compute_basis_inner(logn, f, g, F, G, tmp_flr);

            let (b00, work) = tmp_flr.split_at_mut(n);
            let (b01, work) = work.split_at_mut(n);
            let (b10, work) = work.split_at_mut(n);
            let (b11, work) = work.split_at_mut(n);
            let (t0, work) = work.split_at_mut(n);
            let (t1, _) = work.split_at_mut(n);

            // t0 <- b01*adj(b01)
            t0.copy_from_slice(&*b01);
            poly::poly_mulownadj_fft(logn, t0);

            // t1 <- b00*adj(b10)
            t1.copy_from_slice(&*b00);
            poly::poly_muladj_fft(logn, t1, b10);

            // b00 <- b00*adj(b00)
            poly::poly_mulownadj_fft(logn, b00);

            // b00 <- g00
            poly::poly_add(logn, b00, t0);

            // Save b01 into t0.
            t0.copy_from_slice(b01);

            // b01 <- g01
            poly::poly_muladj_fft(logn, b01, b11);
            poly::poly_add(logn, b01, t1);

            // b10 <- b10*adj(b10)
            poly::poly_mulownadj_fft(logn, b10);

            // b10 <- g11
            t1.copy_from_slice(b11);
            poly::poly_mulownadj_fft(logn, t1);
            poly::poly_add(logn, b10, t1);
        }

        #[cfg(not(feature = "small_context"))]
        {
            // We have the precomputed basis B in FFT format.
            let (b00, work) = basis.split_at(n);
            let (b01, work) = work.split_at(n);
            let (b10, work) = work.split_at(n);
            let (b11, _) = work.split_at(n);

            let (g00, work) = tmp_flr.split_at_mut(n);
            let (g01, work) = work.split_at_mut(n);
            let (g11, work) = work.split_at_mut(n);
            let (t0, work) = work.split_at_mut(n);
            let (t1, _) = work.split_at_mut(n);

            g00.copy_from_slice(b00);
            poly::poly_mulownadj_fft(logn, g00);
            t0.copy_from_slice(b01);
            poly::poly_mulownadj_fft(logn, t0);
            poly::poly_add(logn, g00, t0);

            g01.copy_from_slice(b00);
            poly::poly_muladj_fft(logn, g01, b10);
            t0.copy_from_slice(b01);
            poly::poly_muladj_fft(logn, t0, b11);
            poly::poly_add(logn, g01, t0);

            g11.copy_from_slice(b10);
            poly::poly_mulownadj_fft(logn, g11);
            t0.copy_from_slice(b11);
            poly::poly_mulownadj_fft(logn, t0);
            poly::poly_add(logn, g11, t0);

            t0.copy_from_slice(b11);
            t1.copy_from_slice(b01);
        }

        // Memory layout at this point:
        //   g00 g01 g11 b11 b01

        {
            let (_, work) = tmp_flr.split_at_mut(3 * n);
            let (b11, work) = work.split_at_mut(n);
            let (b01, work) = work.split_at_mut(n);
            let (t0, work) = work.split_at_mut(n);
            let (t1, _) = work.split_at_mut(n);

            // Set the target (t0,t1) to [hm, 0].
            // (t1 is not actually set; subsequent computations take into
            // account that it is conceptually zero)
            for i in 0..n {
                t0[i] = flr::Flr::from_i32(hm[i] as i32);
            }

            // Apply the lattice basis to obtain the real target vector
            // (after normalization with regard to the modulus).
            poly::FFT(logn, t0);
            t1.copy_from_slice(t0);
            poly::poly_mul_fft(logn, t1, b01);
            poly::poly_mulconst(logn, t1, -INV_Q);
            poly::poly_mul_fft(logn, t0, b11);
            poly::poly_mulconst(logn, t0, INV_Q);
        }

        // b01 and b11 can now be discarded; we move back (t0, t1).
        tmp_flr.copy_within((5 * n)..(7 * n), 3 * n);

        // Memory layout at this point:
        //   g00 g01 g11 t0 t1

        {
            // Apply sampling.
            let (g00, work) = tmp_flr.split_at_mut(n);
            let (g01, work) = work.split_at_mut(n);
            let (g11, work) = work.split_at_mut(n);
            let (t0, work) = work.split_at_mut(n);
            let (t1, work) = work.split_at_mut(n);
            samp.ffsamp_fft(t0, t1, g00, g01, g11, work);
        }

        // Rearrange layout back to:
        //   b00 b01 b10 b11 t0 t1
        tmp_flr.copy_within((3 * n)..(5 * n), 4 * n);

        #[cfg(feature = "small_context")]
        compute_basis_inner(logn, f, g, F, G, tmp_flr);

        #[cfg(not(feature = "small_context"))]
        tmp_flr[..(4 * n)].copy_from_slice(&basis[..(4 * n)]);

        let (b00, work) = tmp_flr.split_at_mut(n);
        let (b01, work) = work.split_at_mut(n);
        let (b10, work) = work.split_at_mut(n);
        let (b11, work) = work.split_at_mut(n);
        let (t0, work) = work.split_at_mut(n);
        let (t1, work) = work.split_at_mut(n);
        let (tx, work) = work.split_at_mut(n);
        let (ty, _) = work.split_at_mut(n);

        // Get the lattice point corresponding to the sampled vector.
        tx.copy_from_slice(t0);
        ty.copy_from_slice(t1);
        poly::poly_mul_fft(logn, tx, b00);
        poly::poly_mul_fft(logn, ty, b10);
        poly::poly_add(logn, tx, ty);
        ty.copy_from_slice(t0);
        poly::poly_mul_fft(logn, ty, b01);
        t0.copy_from_slice(tx);
        poly::poly_mul_fft(logn, t1, b11);
        poly::poly_add(logn, t1, ty);
        poly::iFFT(logn, t0);
        poly::iFFT(logn, t1);

        // We compute s1, then s2 into buffer s2 (s1 is not retained).
        // We accumulate their squared norm in sqn, with an "overflow"
        // flag in ng. Since every value is coerced to the i16 type,
        // a squared norm going over 2^31-1 necessarily implies at some
        // point that the high bit of sqn is set, which will show up
        // as the high bit of ng being set.
        let mut sqn = 0u32;
        let mut ng = 0;
        for i in 0..n {
            let z = (hm[i] as i32) - (t0[i].rint() as i32);
            let z = (z as i16) as i32;
            sqn = sqn.wrapping_add((z * z) as u32);
            ng |= sqn;
        }

        // With standard degrees (512 and 1024), it is very improbable that
        // the computed vector is not short enough; however, it may happen
        // for smaller degrees in test/toy versions (e.g. degree 16). We
        // need to loop in these cases.
        let s2 = &mut tmp_i16[..n];
        for i in 0..n {
            let sz = (-t1[i].rint()) as i16;
            let z = sz as i32;
            sqn = sqn.wrapping_add((z * z) as u32);
            ng |= sqn;
            s2[i] = sz;
        }

        // If the squared norm exceeded 2^31-1 at some point, then the
        // high bit of ng is set. We saturate sqn to 2^32-1 in that case
        // (which will be enough to make the value too large, and force
        // a new loop iteration).
        sqn |= ((ng as i32) >> 31) as u32;
        if sqn > mq::SQBETA[logn as usize] {
            continue;
        }

        // We have a candidate signature; we must encode it. This may
        // fail, since encoding is variable-size and might not fit in the
        // target size.
        if codec::comp_encode(s2, &mut sig[41..]) {
            sig[0] = 0x30 + (logn as u8);
            sig[1..41].copy_from_slice(&nonce);
            return;
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use fn_dsa_comm::shake::SHAKE256;
    // We need SHAKE256x4 for some tests (because test vectors were
    // originally built with that PRNG). If we are not using it in
    // the main code, then we must define a custom one here.
    #[cfg(feature = "shake256x4")]
    pub(crate) use fn_dsa_comm::shake::SHAKE256x4;
    use fn_dsa_comm::{
        Infallible,
        TryCryptoRng,
        TryRng,
    };

    use super::*;

    #[cfg(not(feature = "shake256x4"))]
    #[derive(Copy, Clone, Debug)]
    pub(crate) struct SHAKE256x4 {
        sh: [SHAKE256; 4],
        buf: [u8; 4 * 136],
        ptr: usize,
    }

    #[cfg(not(feature = "shake256x4"))]
    impl SHAKE256x4 {
        pub fn new(seed: &[u8]) -> Self {
            let mut sh = [
                SHAKE256::new(),
                SHAKE256::new(),
                SHAKE256::new(),
                SHAKE256::new(),
            ];
            for (i, item) in sh.iter_mut().enumerate() {
                item.inject(seed);
                item.inject(&[i as u8]);
                item.flip();
            }
            Self {
                sh,
                buf: [0u8; 4 * 136],
                ptr: 4 * 136,
            }
        }

        fn refill(&mut self) {
            self.ptr = 0;
            for i in 0..(4 * 136 / 32) {
                for j in 0..4 {
                    let k = 32 * i + 8 * j;
                    self.sh[j].extract(&mut self.buf[k..(k + 8)]);
                }
            }
        }

        pub fn next_u8(&mut self) -> u8 {
            if self.ptr >= 4 * 136 {
                self.refill();
            }
            let x = self.buf[self.ptr];
            self.ptr += 1;
            x
        }

        pub fn next_u16(&mut self) -> u16 {
            if self.ptr >= 4 * 136 - 1 {
                self.refill();
            }
            let x = u16::from_le_bytes(
                *<&[u8; 2]>::try_from(&self.buf[self.ptr..self.ptr + 2]).unwrap(),
            );
            self.ptr += 2;
            x
        }

        pub fn next_u64(&mut self) -> u64 {
            if self.ptr >= 4 * 136 - 7 {
                self.refill();
            }
            let x = u64::from_le_bytes(
                *<&[u8; 8]>::try_from(&self.buf[self.ptr..self.ptr + 8]).unwrap(),
            );
            self.ptr += 8;
            x
        }
    }

    #[cfg(not(feature = "shake256x4"))]
    impl fn_dsa_comm::PRNG for SHAKE256x4 {
        fn new(seed: &[u8]) -> Self {
            SHAKE256x4::new(seed)
        }

        fn next_u8(&mut self) -> u8 {
            SHAKE256x4::next_u8(self)
        }

        fn next_u16(&mut self) -> u16 {
            SHAKE256x4::next_u16(self)
        }

        fn next_u64(&mut self) -> u64 {
            SHAKE256x4::next_u64(self)
        }
    }

    // PRNG implementation based on ChaCha20, used to mimic the reference
    // C code to get reproducible behaviour. The seed MUST have length
    // 56 bytes exactly (this is how it is used in sign_inner()).
    #[derive(Clone, Copy, Debug)]
    struct ChaCha20PRNG {
        buf: [u8; 512],
        state: [u8; 256],
        ptr: usize,
    }

    const CW: [u32; 4] = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574];

    impl ChaCha20PRNG {
        fn refill(&mut self) {
            let mut cc = u64::from_le_bytes(*<&[u8; 8]>::try_from(&self.state[48..56]).unwrap());
            for i in 0..8 {
                let mut state = [0u32; 16];
                state[0..4].copy_from_slice(&CW);
                for j in 0..12 {
                    state[4 + j] = u32::from_le_bytes(
                        *<&[u8; 4]>::try_from(&self.state[(4 * j)..(4 * j + 4)]).unwrap(),
                    );
                }
                state[14] ^= cc as u32;
                state[15] ^= (cc >> 32) as u32;
                for _ in 0..10 {
                    fn qround(st: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
                        st[a] = st[a].wrapping_add(st[b]);
                        st[d] ^= st[a];
                        st[d] = st[d].rotate_left(16);
                        st[c] = st[c].wrapping_add(st[d]);
                        st[b] ^= st[c];
                        st[b] = st[b].rotate_left(12);
                        st[a] = st[a].wrapping_add(st[b]);
                        st[d] ^= st[a];
                        st[d] = st[d].rotate_left(8);
                        st[c] = st[c].wrapping_add(st[d]);
                        st[b] ^= st[c];
                        st[b] = st[b].rotate_left(7);
                    }
                    qround(&mut state, 0, 4, 8, 12);
                    qround(&mut state, 1, 5, 9, 13);
                    qround(&mut state, 2, 6, 10, 14);
                    qround(&mut state, 3, 7, 11, 15);
                    qround(&mut state, 0, 5, 10, 15);
                    qround(&mut state, 1, 6, 11, 12);
                    qround(&mut state, 2, 7, 8, 13);
                    qround(&mut state, 3, 4, 9, 14);
                }

                for j in 0..4 {
                    state[j] = state[j].wrapping_add(CW[j]);
                }
                for j in 0..10 {
                    state[4 + j] = state[4 + j].wrapping_add(u32::from_le_bytes(
                        *<&[u8; 4]>::try_from(&self.state[(4 * j)..(4 * j + 4)]).unwrap(),
                    ));
                }
                state[14] = state[14].wrapping_add(
                    u32::from_le_bytes(*<&[u8; 4]>::try_from(&self.state[40..44]).unwrap()) ^
                        (cc as u32),
                );
                state[15] = state[15].wrapping_add(
                    u32::from_le_bytes(*<&[u8; 4]>::try_from(&self.state[44..48]).unwrap()) ^
                        ((cc >> 32) as u32),
                );
                cc += 1;

                for (j, item) in state.iter().enumerate() {
                    let k = (j << 2) + (i << 6);
                    self.buf[k..(k + 4)].copy_from_slice(&item.to_le_bytes());
                }
            }
            self.state[48..56].copy_from_slice(&cc.to_le_bytes());
            self.ptr = 0;
        }
    }

    impl PRNG for ChaCha20PRNG {
        fn new(seed: &[u8]) -> Self {
            let mut p = Self {
                buf: [0u8; 512],
                state: [0u8; 256],
                ptr: 0,
            };
            p.state[..56].copy_from_slice(seed);
            p.refill();
            p
        }

        fn next_u8(&mut self) -> u8 {
            if self.ptr == self.buf.len() {
                self.refill();
            }
            let x = self.buf[self.ptr];
            self.ptr += 1;
            x
        }

        fn next_u16(&mut self) -> u16 {
            let x0 = self.next_u8();
            let x1 = self.next_u8();
            (x0 as u16) | ((x1 as u16) << 1)
        }

        fn next_u64(&mut self) -> u64 {
            let mut i = self.ptr;
            if i >= (self.buf.len() - 9) {
                self.refill();
                i = 0;
            }
            self.ptr = i + 8;
            u64::from_le_bytes(*<&[u8; 8]>::try_from(&self.buf[i..(i + 8)]).unwrap())
        }
    }

    // Regenerated after ChaCha20PRNG buffer layout fix (sequential blocks).
    const KAT_RNG_1: [u64; 128] = [
        10118206865980352844,
        4186416994968924572,
        14407813434015218568,
        17999928204308794618,
        1281202863493570580,
        1215293592670952135,
        2662650687309711127,
        4950968403807295904,
        5162758428151459972,
        10844832002478462889,
        2152372350175039333,
        16663510599184623250,
        11748879267894739645,
        9315153642897576389,
        843976972260730699,
        1261701354592092221,
        8105821303884592444,
        7529634954489570079,
        575133564673458827,
        2093472206215043609,
        833393031138418875,
        7733850010291114247,
        13481871314116322223,
        11415547815848461648,
        2199402011451572558,
        8665283947099910497,
        8526838622528653153,
        9480927610656828044,
        2180302049036012308,
        12374959167662158686,
        12395725852717209259,
        2285950573032359990,
        3178894720812991391,
        13715355236500543103,
        13935188584178984125,
        9490268222115631411,
        15412630661220207885,
        9945702784445615473,
        17532343938726239310,
        8849181786919164502,
        14389227774839945492,
        11188424208367267411,
        8723730469410215675,
        6156120820198785454,
        5156565809544156914,
        2688897825680180598,
        15035334635217652153,
        17533008619055607030,
        8880420601663548525,
        1115094350924961784,
        2267453663324806620,
        8948565336726581792,
        9125975625518420122,
        15274140373700820667,
        7478801077138445484,
        1035450160594676773,
        11986213120279998009,
        17673958146477577562,
        12305459440141111064,
        14326368158202311078,
        1177814005100640761,
        8747661500288216167,
        2797765342783346840,
        4107359898270585920,
        11518238704365557048,
        6175352564507757509,
        4396475331278281679,
        3201421582953741656,
        11784142549909733272,
        5585412854666709543,
        2582853516077978199,
        9205210792867691364,
        12534618484258612970,
        7622943502960284153,
        11584269409789615882,
        8189573375121423581,
        9571905452515233284,
        716665414398392180,
        17528004569390045241,
        9235922718509541131,
        5829593106852634271,
        8814208540816662228,
        16133232462179240583,
        3305531072799582200,
        3517553763672608175,
        5072453735837072731,
        3087432279719960851,
        12018757166060582929,
        10295016195294092532,
        6915694762732032156,
        17598328482254484633,
        15636110532633868232,
        8803774359075619886,
        1830932215338098894,
        3962629290033382627,
        1916769747115319947,
        5482878565058858052,
        11823245115937445404,
        16582018945468735060,
        5447126734922287710,
        3807845955673994450,
        15934143589856303631,
        12266592860318918671,
        8383600949465076579,
        18303263099619098259,
        17645551392386460660,
        6749439027928258396,
        485438119962767056,
        3481957153076147354,
        3223851328808479444,
        8253146295282414289,
        4299195855338690944,
        6444506233343653792,
        9395364228380005075,
        11300796530137268589,
        10287453355807248725,
        14083145503895752763,
        17601794799780907610,
        3675357623818277351,
        5319896027624671966,
        5019668621475045549,
        3230679923130437320,
        3350076208214283281,
        3311388483548165406,
        14196905744269899417,
        12248417052101335070,
        14418418964481725733,
        9434739643424308990,
    ];

    // Regenerated after ChaCha20PRNG buffer layout fix (sequential blocks).
    const KAT_RNG_2: [u8; 1024] = [
        7, 158, 53, 113, 114, 156, 140, 81, 188, 91, 102, 38, 11, 146, 21, 239, 105, 43, 133, 93,
        181, 57, 86, 237, 155, 76, 95, 232, 181, 119, 86, 59, 73, 176, 65, 210, 48, 182, 222, 115,
        240, 148, 33, 189, 23, 204, 251, 207, 46, 31, 53, 47, 64, 226, 127, 184, 198, 239, 254, 44,
        100, 83, 32, 160, 142, 35, 123, 157, 59, 227, 240, 49, 127, 125, 124, 149, 86, 69, 73, 148,
        35, 93, 16, 146, 43, 170, 83, 52, 5, 127, 120, 153, 185, 181, 61, 93, 41, 50, 156, 125,
        124, 4, 45, 182, 213, 9, 24, 120, 166, 207, 193, 50, 228, 122, 97, 154, 37, 139, 126, 146,
        212, 192, 4, 216, 143, 89, 178, 79, 35, 52, 122, 200, 17, 170, 89, 164, 93, 96, 224, 73,
        194, 208, 94, 149, 215, 220, 220, 248, 59, 176, 186, 31, 72, 58, 215, 203, 125, 43, 52,
        176, 112, 213, 61, 254, 223, 94, 76, 59, 124, 141, 30, 3, 62, 116, 12, 204, 163, 199, 39,
        135, 74, 140, 104, 27, 154, 81, 33, 205, 226, 90, 53, 136, 138, 23, 218, 123, 102, 172,
        170, 158, 21, 196, 86, 71, 196, 109, 0, 221, 96, 94, 237, 31, 188, 248, 88, 95, 150, 154,
        51, 151, 54, 45, 86, 233, 130, 39, 138, 56, 130, 246, 16, 228, 21, 177, 26, 232, 115, 178,
        190, 115, 201, 69, 188, 196, 119, 97, 30, 112, 91, 219, 159, 11, 57, 91, 108, 89, 162, 151,
        10, 120, 133, 217, 45, 173, 126, 141, 104, 60, 19, 147, 120, 194, 33, 178, 25, 39, 62, 208,
        77, 179, 98, 233, 189, 206, 36, 194, 90, 233, 25, 18, 20, 120, 148, 206, 144, 212, 114,
        183, 152, 95, 172, 142, 68, 81, 91, 103, 163, 37, 237, 194, 196, 165, 156, 71, 207, 232,
        89, 140, 16, 197, 43, 25, 173, 177, 202, 43, 105, 94, 84, 111, 32, 249, 133, 33, 93, 24,
        183, 183, 205, 73, 168, 94, 201, 184, 4, 114, 77, 133, 42, 248, 238, 131, 170, 42, 41, 226,
        35, 12, 189, 202, 35, 58, 145, 178, 69, 237, 246, 96, 151, 25, 100, 103, 223, 158, 118,
        237, 56, 107, 180, 148, 43, 243, 124, 73, 53, 189, 177, 231, 25, 159, 119, 21, 0, 67, 180,
        82, 146, 185, 72, 210, 152, 41, 144, 201, 210, 112, 211, 48, 103, 81, 105, 251, 116, 193,
        12, 128, 43, 187, 135, 79, 86, 183, 9, 108, 223, 253, 112, 105, 33, 61, 12, 227, 74, 152,
        212, 183, 73, 132, 61, 8, 220, 205, 154, 155, 253, 153, 12, 134, 116, 75, 130, 251, 67,
        240, 201, 159, 216, 70, 81, 252, 150, 69, 137, 13, 129, 205, 78, 68, 192, 60, 69, 137, 211,
        18, 188, 252, 173, 67, 92, 4, 122, 220, 192, 114, 172, 53, 168, 71, 196, 59, 250, 115, 62,
        27, 17, 85, 104, 26, 21, 151, 152, 91, 56, 122, 163, 200, 188, 30, 26, 132, 56, 27, 49, 33,
        56, 238, 194, 19, 105, 12, 2, 248, 252, 79, 97, 91, 69, 192, 66, 198, 133, 40, 184, 130,
        95, 121, 87, 88, 141, 47, 191, 67, 116, 35, 210, 30, 171, 235, 232, 111, 146, 119, 35, 29,
        61, 6, 147, 51, 138, 42, 128, 103, 35, 79, 7, 155, 2, 178, 21, 58, 198, 29, 116, 47, 116,
        51, 228, 228, 151, 250, 53, 205, 99, 2, 33, 208, 230, 242, 30, 47, 148, 66, 108, 27, 96,
        124, 97, 163, 12, 99, 130, 149, 87, 47, 40, 176, 61, 209, 182, 202, 78, 58, 120, 226, 52,
        173, 214, 42, 129, 196, 19, 130, 54, 61, 55, 245, 48, 61, 71, 137, 178, 37, 145, 25, 186,
        180, 224, 161, 130, 147, 145, 144, 196, 38, 112, 200, 161, 31, 123, 146, 118, 197, 250, 22,
        159, 250, 20, 47, 154, 23, 0, 203, 124, 185, 195, 161, 197, 177, 179, 140, 225, 40, 44, 71,
        89, 97, 79, 108, 255, 113, 67, 152, 253, 78, 34, 176, 156, 116, 5, 78, 207, 14, 239, 123,
        177, 176, 202, 40, 210, 87, 98, 182, 91, 158, 75, 165, 179, 125, 194, 190, 143, 252, 142,
        150, 108, 83, 213, 155, 96, 136, 16, 52, 39, 72, 48, 83, 244, 252, 241, 241, 152, 154, 2,
        62, 143, 127, 13, 160, 23, 207, 225, 146, 253, 237, 189, 133, 9, 41, 63, 206, 111, 204, 3,
        185, 47, 209, 165, 53, 57, 235, 124, 13, 113, 74, 78, 194, 230, 91, 51, 127, 90, 45, 206,
        5, 167, 63, 132, 62, 116, 29, 146, 25, 8, 2, 54, 178, 232, 211, 175, 172, 34, 113, 248,
        153, 116, 92, 221, 240, 91, 77, 221, 98, 111, 163, 161, 32, 202, 203, 17, 232, 54, 225,
        105, 255, 129, 232, 213, 214, 95, 121, 160, 28, 36, 244, 3, 213, 174, 150, 73, 126, 74,
        104, 84, 179, 1, 207, 204, 4, 61, 24, 213, 15, 152, 3, 49, 153, 109, 161, 234, 228, 157,
        103, 135, 77, 75, 75, 197, 172, 74, 50, 55, 150, 247, 115, 244, 114, 45, 176, 128, 50, 209,
        120, 206, 207, 7, 167, 174, 200, 87, 13, 246, 97, 21, 188, 219, 12, 108, 43, 109, 146, 112,
        39, 141, 8, 169, 216, 156, 13, 158, 151, 196, 19, 56, 13, 14, 106, 157, 73, 114, 203, 69,
        198, 228, 70, 46, 198, 158, 174, 105, 181, 233, 36, 207, 29, 115, 127, 188, 173, 178, 52,
        42, 225, 114, 104, 254, 174, 69, 140, 203, 178, 152, 235, 197, 42, 121, 128, 164, 215, 163,
        117, 71, 0, 130, 136, 182, 18, 234, 71, 252, 210, 1, 232, 84, 60, 76, 238, 129, 250, 3,
        174, 190, 112, 147, 186, 168, 113, 65, 225, 131, 66, 88, 4, 156, 3, 30, 41, 24, 124, 108,
        132, 252, 71, 99, 195, 91, 172, 115, 34, 215, 96, 220, 208, 152, 185, 69, 85, 220, 187, 10,
        91, 61, 180, 85, 50, 218, 127, 6, 117, 237, 23, 204, 42, 136, 111,
    ];

    #[test]
    fn chacha20_prng() {
        let mut sh = SHAKE256::new();
        sh.inject(&b"rng"[..]);
        sh.flip();
        let mut seed = [0u8; 56];
        sh.extract(&mut seed);
        let mut p = ChaCha20PRNG::new(&seed);

        #[allow(clippy::needless_range_loop)]
        for i in 0..KAT_RNG_1.len() {
            assert!(p.next_u64() == KAT_RNG_1[i]);
        }
        #[allow(clippy::needless_range_loop)]
        for i in 0..KAT_RNG_2.len() {
            assert!(p.next_u8() == KAT_RNG_2[i]);
        }
    }

    // Fake CryptoRng that returns only predefined data, for test purposes.
    struct FakeCryptoRng(usize);
    impl TryRng for FakeCryptoRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&KAT_512_RND[self.0..(self.0 + 4)]);
            self.0 += 4;
            Ok(u32::from_le_bytes(buf))
        }
        fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&KAT_512_RND[self.0..(self.0 + 8)]);
            self.0 += 8;
            Ok(u64::from_le_bytes(buf))
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), Self::Error> {
            dest.copy_from_slice(&KAT_512_RND[self.0..(self.0 + dest.len())]);
            self.0 += dest.len();
            Ok(())
        }
    }
    impl TryCryptoRng for FakeCryptoRng {}

    /// Verifies that Rng::fill_bytes() consumes bytes identically to direct
    /// try_fill_bytes for 40-byte and 56-byte buffers (nonce and seed sizes).
    #[test]
    fn test_fill_bytes_consumption_pattern() {
        use fn_dsa_comm::Rng;
        let mut rng = FakeCryptoRng(0);
        let mut nonce = [0u8; 40];
        rng.fill_bytes(&mut nonce);
        assert_eq!(
            nonce[..],
            KAT_512_RND[0..40],
            "nonce must match first 40 bytes"
        );
        let mut seed = [0u8; 56];
        rng.fill_bytes(&mut seed);
        assert_eq!(
            seed[..],
            KAT_512_RND[40..96],
            "seed must match bytes 40..96"
        );
    }

    #[test]
    fn sign_512() {
        // We use a fake random source that returns some predefined bytes.
        let mut rng = FakeCryptoRng(0);

        // Sign a specific message with the private key.
        let mut tmp_i16 = [0i16; 2 << 9];
        let mut tmp_u16 = [0u16; 2 << 9];
        let mut tmp_flr = [flr::Flr::ZERO; 9 << 9];
        let mut sig = [0u8; signature_size(9)];

        // We are using the original Falcon rules; public key does not
        // actually matter.
        let mut hvk = [0u8; 64];
        let mut sh = shake::SHAKE256::new();
        sh.inject(&KAT_512_VK);
        sh.flip();
        sh.extract(&mut hvk);

        #[cfg(not(feature = "small_context"))]
        let basis = {
            let mut basis = [flr::Flr::ZERO; 4 << 9];
            compute_basis_inner(
                9, &KAT_512_f, &KAT_512_g, &KAT_512_F, &KAT_512_G, &mut basis,
            );
            basis
        };

        sign_inner::<FakeCryptoRng, ChaCha20PRNG>(
            9,
            &mut rng,
            &KAT_512_f,
            &KAT_512_g,
            &KAT_512_F,
            &KAT_512_G,
            &hvk,
            &DOMAIN_NONE,
            &HASH_ID_SHA3_256,
            &b"data1"[..],
            &mut sig,
            #[cfg(not(feature = "small_context"))]
            &basis,
            &mut tmp_i16,
            &mut tmp_u16,
            &mut tmp_flr,
        );

        // Check that the signature value (s2) is exactly the one which
        // was expected.
        assert!(sig[0] == 0x39);
        assert!(sig[1..41] == KAT_512_RND[0..40]);
        let mut sig_raw = [0i16; 512];
        assert!(codec::comp_decode(&sig[41..], &mut sig_raw[..]));
        assert_eq!(sig_raw, KAT_512_sig_raw);
    }

    #[cfg(all(not(feature = "no_avx2"), target_arch = "x86_64"))]
    #[test]
    fn sign_avx2_512() {
        if !fn_dsa_comm::has_avx2() {
            return;
        }
        // We use a fake random source that returns some predefined bytes.
        let mut rng = FakeCryptoRng(0);

        // Sign a specific message with the private key.
        let mut tmp_i16 = [0i16; 2 << 9];
        let mut tmp_u16 = [0u16; 2 << 9];
        let mut tmp_flr = [flr::Flr::ZERO; 9 << 9];
        let mut sig = [0u8; signature_size(9)];

        // We are using the original Falcon rules; public key does not
        // actually matter.
        let mut hvk = [0u8; 64];
        let mut sh = shake::SHAKE256::new();
        sh.inject(&KAT_512_VK);
        sh.flip();
        sh.extract(&mut hvk);

        #[cfg(not(feature = "small_context"))]
        let basis = {
            let mut basis = [flr::Flr::ZERO; 4 << 9];
            unsafe {
                sign_avx2::compute_basis_avx2_inner(
                    9, &KAT_512_f, &KAT_512_g, &KAT_512_F, &KAT_512_G, &mut basis,
                );
            }
            basis
        };

        unsafe {
            sign_avx2::sign_avx2_inner::<FakeCryptoRng, ChaCha20PRNG>(
                9,
                &mut rng,
                &KAT_512_f,
                &KAT_512_g,
                &KAT_512_F,
                &KAT_512_G,
                &hvk,
                &DOMAIN_NONE,
                &HASH_ID_SHA3_256,
                &b"data1"[..],
                &mut sig,
                #[cfg(not(feature = "small_context"))]
                &basis,
                &mut tmp_i16,
                &mut tmp_u16,
                &mut tmp_flr,
            );
        }

        // Check that the signature value (s2) is exactly the one which
        // was expected.
        assert!(sig[0] == 0x39);
        assert!(sig[1..41] == KAT_512_RND[0..40]);
        let mut sig_raw = [0i16; 512];
        assert!(codec::comp_decode(&sig[41..], &mut sig_raw[..]));
        assert_eq!(sig_raw, KAT_512_sig_raw);
    }

    const KAT_512_f: [i8; 512] = [
        -4, -2, -5, -1, 4, -2, 0, -3, -1, 1, -2, -2, -6, -3, 3, -5, -1, 4, -3, -8, 4, -1, 2, -1,
        -8, 5, -6, -3, 6, 0, -2, 4, 5, -6, 2, 3, 6, 4, 2, 3, 3, 7, 0, 1, 5, -3, -1, -9, -1, 6, -2,
        -5, 4, 0, 4, -2, 10, -4, -3, 4, -7, -1, -7, -2, -1, -6, 5, -1, -9, 3, 2, -5, 4, -2, 2, -4,
        4, -3, -1, 0, 5, 2, 2, -1, -9, -7, -2, -1, 0, 3, 1, 0, -1, -2, -5, 4, -1, -1, 3, -1, 1, 4,
        -3, 2, -5, -2, 2, -4, 3, 6, 3, 9, 1, -2, 4, -1, -1, -6, -2, -2, 4, 5, -1, 0, 10, -2, 1, -2,
        -3, 0, -4, -4, -1, 0, 1, -5, -3, -7, -2, -1, 2, -6, 3, 0, 0, 4, -4, 0, 0, -5, -2, 5, -8, 8,
        5, 4, 10, -4, 3, 8, 5, 1, -7, 0, -5, 0, -4, 3, -4, -2, 2, -2, 6, 8, 2, -1, 4, -4, -2, 1, 0,
        3, 7, 0, 9, -3, 1, 4, -3, 2, -1, 5, -8, 4, -1, 1, -8, 2, 4, -9, -3, 1, 3, -1, -7, 5, 5, 4,
        -3, 0, -7, -3, -1, -6, -7, 0, -3, 0, 3, -3, 0, -3, 1, 3, 4, -6, -6, -3, 6, 0, 2, -5, 1, -3,
        -6, -6, -1, -7, -2, -4, 3, 0, -4, -1, 2, 7, -7, -2, 4, 2, 0, 1, -1, -3, 2, 1, 8, -1, 1, -2,
        1, -1, 1, 4, 0, -4, 4, 3, -2, 6, -3, -2, 1, 2, 3, 6, 5, -4, -7, -6, 4, 3, -4, 3, -3, 3, -3,
        2, -1, 1, 5, -2, 2, 1, 0, -7, 0, 0, -1, 4, -3, 2, 1, -3, 5, 4, -6, -1, -3, 2, -1, -8, 4, 2,
        4, 0, 1, -5, 8, 5, 4, -3, -1, -2, 4, 0, 2, -2, 0, -2, -1, -7, 5, 0, 1, 2, 1, -2, 2, -1, 1,
        -4, 1, 0, 4, -4, 0, 5, 1, 4, -5, -2, -3, -2, 1, 3, 1, 2, 5, 12, 0, -1, 4, -6, 1, -4, 3, -5,
        -4, 4, 2, -2, -6, 1, 1, 3, -1, 0, -4, -4, -4, 6, -2, 4, -3, 0, -2, -1, 0, -6, -3, -2, 0, 6,
        5, -5, -5, 3, 0, 3, -3, -2, 5, 7, -3, 1, -1, 0, 3, 0, 3, -7, 2, -4, -4, 1, 1, 1, 0, -3, -8,
        3, 6, 1, -2, -7, 3, 3, 4, -1, -2, -5, 9, 7, 1, 2, -4, 4, 0, -11, 3, 0, -3, -5, 5, -1, -1,
        7, 6, -1, 6, 3, 9, 5, -2, -3, -3, 1, -2, 0, -1, 1, -2, 2, 0, -5, -1, -4, -2, 2, -1, -3, 0,
        -3, 0, 1, 3, -3, 2, 5, 8, -2, 3, -4, -7, 0, 4, -8, 1, 8, -2, 1, -1, 2, 0, -2, 1, 3, 3, 4,
        -2, -4, 3, -4, 2, 3, -2, -4, 1, -4, 10, 2,
    ];
    const KAT_512_g: [i8; 512] = [
        -1, 5, -7, -1, -4, 6, 4, -1, -4, -13, -1, -5, -2, -8, 2, 1, 4, 2, 0, 0, 2, 0, -1, 2, 5, -5,
        -8, 8, 1, 11, 0, -8, -4, 1, 1, -6, -4, 1, -3, 0, -10, -4, -6, -3, -2, 1, 6, 2, 8, -2, 2,
        -2, 1, 3, -4, 2, -1, -1, -2, -2, -3, 0, -3, 2, -3, 2, -3, -4, 2, 3, 4, -5, 6, -3, -2, -1,
        -1, -6, -2, 1, -4, -7, 8, 0, 2, -2, 2, 0, 1, 0, 4, 9, 7, 0, -1, -1, 4, -3, -2, 6, 6, 0, 1,
        7, -6, -5, 5, 1, 4, -1, 0, -2, 3, -4, 1, -1, -3, -2, 0, -1, -7, -8, -1, 2, 0, -5, 0, 1, -4,
        6, -5, 6, 4, 1, -4, -5, 8, -1, 1, -2, 1, 1, 1, 3, 0, -1, 1, 1, -4, -5, -4, 2, -3, 2, -2, 3,
        7, -4, 4, -1, -2, 4, -4, -5, 2, 6, -7, 5, -1, 1, 3, 0, -5, -5, 3, -2, -3, -1, -6, 0, 2, 3,
        2, 7, -3, -2, -2, 1, -5, 3, 3, -7, 0, 4, 4, -1, 2, -3, 1, 3, -1, -1, 0, -7, -6, -3, 7, -3,
        5, -5, 1, -2, 0, 9, -2, 3, -1, -5, -3, -5, 3, 1, -4, -3, 2, -2, 2, 8, -1, 0, 5, -3, -2, -6,
        4, 0, 3, -3, -3, 4, -1, 0, 0, -2, -1, 3, 7, 4, 5, -1, 8, 0, -1, -6, -3, 4, 3, -3, 5, 2, -1,
        -2, 1, -1, 3, -2, -6, 4, 0, 0, -4, 1, 6, 2, 0, 10, 9, 2, -2, 0, 2, 1, -3, -1, -1, 3, 2, 1,
        1, -3, -2, 7, 2, -1, 5, -3, -2, 1, -2, 2, -2, -4, 3, 2, 1, -4, 1, 4, 3, -7, -4, 2, -5, -2,
        5, -3, 1, -4, -5, 1, 0, 0, 0, 7, -5, -1, 2, 2, -3, 6, -6, 4, -3, -5, -6, -7, -4, 3, -2, -2,
        -10, -3, 2, -1, -6, -4, 1, 2, 2, 1, 4, 1, -5, -10, -2, 2, -4, 4, 4, -2, 1, 4, -3, 0, -6,
        -3, 1, 5, -7, -6, -4, 8, -1, 0, -1, 6, -3, -2, -2, 6, 2, 3, -3, -3, 5, -2, 1, 1, -4, -4, 8,
        0, 3, 2, 3, 7, 4, 3, 2, -6, -9, 0, -8, 11, -2, 2, -2, -2, 3, 0, -6, 2, -1, 4, 2, -2, 0, -3,
        -7, -1, -1, 0, -1, -4, -2, -5, 3, -4, 2, 2, -1, -1, 7, -1, 3, 6, -7, 1, -5, 0, -7, 4, 3,
        -5, -1, 0, 3, -4, 1, 2, -7, 1, -2, -8, -2, -5, -5, 1, -4, -4, 4, -3, -2, 2, -4, -8, -1, 0,
        -9, 5, -1, -2, 3, 2, 6, -1, 1, -1, -5, 5, 9, 3, -6, -5, 1, -6, 0, 2, -4, 6, 2, 7, 2, 15, 0,
        -2, 9, 0, 1, 6, 4, -1, -1, -6, -3, 3, 1, -6, -3, 2, 2, -2,
    ];
    const KAT_512_F: [i8; 512] = [
        0, -25, -39, 21, 7, -5, -10, 4, -1, -38, -9, -1, 4, -23, 15, -1, 8, 1, -38, 41, 29, 22, 9,
        12, -46, 0, 9, -17, -19, 32, 38, -3, 14, 6, 2, -6, -18, -1, 23, 80, -12, -20, 24, 22, -31,
        -38, -11, 8, 17, 18, 19, -10, 0, -1, 28, -5, -28, -33, 4, -31, -33, -8, -9, -44, 46, -11,
        -5, -21, -22, -7, 1, -11, 33, -8, 12, -7, -6, 63, 17, 12, -49, -11, -31, -8, 7, -28, 33,
        -28, -19, 8, 46, -73, 9, 32, 18, 7, -43, 0, -6, -4, 8, -39, -17, 11, 15, -25, -9, -28, -2,
        24, -23, 10, -15, 4, 41, 46, 18, 2, -3, -29, 11, -3, 20, 35, 21, 23, 5, -8, -3, -27, -69,
        0, 26, -29, -24, 8, 19, 6, -14, -18, 47, 5, 21, -50, 17, -44, -36, 24, 9, 16, -38, -5, -54,
        34, 13, 31, -2, 9, 8, -12, -14, -17, 28, -59, -20, 19, 31, 14, 14, 7, -32, 37, 5, -3, -7,
        -6, 21, -29, -33, 23, -25, -23, 14, 38, -29, -33, -9, 23, -43, 18, -12, 2, 30, 32, -28,
        -21, 42, 1, 6, -6, 58, 34, -22, 1, 5, -2, -8, 14, -19, -4, -6, 10, -3, -3, 32, 18, -19,
        -12, 49, 13, 4, -18, 57, 37, -19, 25, 14, 18, -51, 13, 4, 4, 17, -37, -2, 1, 41, -36, -8,
        -13, 49, -6, 9, 46, -36, -6, -20, -18, -6, -29, -42, -21, -25, -29, 5, -41, 51, 49, -20,
        -22, -9, 3, -6, -52, 10, 41, 12, -27, -20, 31, -17, -23, -16, 3, 44, -3, -5, -2, 0, -22,
        14, -30, -41, 3, -27, 3, 18, 38, 10, 49, 45, -13, -27, -4, -10, -67, -1, -17, -2, 72, 46,
        20, 24, 22, 16, 25, 6, -6, -31, 2, 0, -13, -14, 9, 4, 31, 18, 22, 12, 59, -1, -3, -24, -47,
        -10, 48, 37, -34, -32, -4, 18, -2, 52, -8, -7, 34, -44, -14, -21, -49, -35, 41, -4, 31, 3,
        23, 9, 8, 0, -24, 38, -9, -9, 4, -10, -55, -19, 21, 27, 22, 41, 6, -23, 41, -2, 28, -46,
        20, 52, 16, 20, 32, 18, 2, -3, 9, 16, 33, -18, 12, 6, -9, -19, 1, -5, -15, -17, 6, -3, 4,
        -22, 30, -34, 43, -4, 9, -3, -33, -43, -5, -13, -56, 38, 16, 11, -36, 11, -4, -56, 2, 0,
        -19, -45, -8, -34, 16, 31, -3, 16, 27, -16, -9, 8, 45, -51, -20, 62, -17, -4, 4, 17, -45,
        4, -15, -19, 39, 39, 15, 17, -19, 2, 45, 36, -22, 16, -23, 28, 34, 12, 5, 10, -7, 28, -35,
        17, -37, -50, -28, 19, -25, 9, 45, -6, -7, -16, 57, 27, 50, -30, 2, -10, -1, -57, -49, -23,
        0, -9, -36, -4, -3, 32, -6, -25, 67, -27, -19, 25, -6, 1, -17, -14, 0, 29, 26, -12, -20,
        44, 14, 10, 8, -11, -18, -53, 22, 25, 27, 35, 6, -16, 12, 71, -8,
    ];
    const KAT_512_G: [i8; 512] = [
        27, 6, 12, -3, -31, -42, 27, 17, 11, 8, 34, 6, -3, 2, 11, -11, 18, 48, 1, 21, -7, -6, 9,
        33, -18, -40, -55, -9, -71, -50, 32, -36, 11, 4, 29, 33, 10, -19, -43, -10, 22, -36, -23,
        -21, -14, -47, 25, -4, -14, 30, 16, -18, -11, 6, -37, -27, -12, 6, 7, 33, -36, 33, -2, 12,
        -21, 1, 16, 49, -11, -16, -41, 15, 11, 8, 20, -15, 26, -8, 11, -43, -36, 28, 2, -47, -30,
        -47, -1, 1, 48, -6, -22, 24, -20, -3, -1, -15, -12, 62, 12, 7, -9, 15, -71, 49, 22, 27, 20,
        -8, -28, -13, -31, 18, 28, 54, 29, 5, 0, 33, -5, -22, -21, -12, -14, -2, 11, -24, 32, -26,
        -71, 21, -15, -20, -12, 36, -5, 35, 46, 13, -34, -8, 10, -10, 10, 40, -52, 8, 0, 18, -33,
        -10, 8, 43, -8, -6, -31, -17, 19, 30, 12, -9, 8, -19, -32, -18, -1, -37, 4, 43, 27, 14, -6,
        -14, -44, -34, -8, 16, -39, 13, 6, -32, 8, 17, -12, 23, -44, -25, -66, -12, -31, 30, 14,
        -9, -5, -10, 44, -12, -2, -43, -22, -18, -7, -9, -15, -7, -21, -27, -5, 1, -13, -10, 8, -8,
        29, 21, 64, 47, -28, -9, -28, 25, -47, -34, -3, -14, -26, -12, -5, -10, -27, -9, -14, -23,
        -2, -31, 28, 17, -4, -30, 31, 3, -15, 25, 9, -32, 0, -6, -22, 20, -37, 3, 12, -19, -17, 13,
        30, 11, -15, 15, 50, 66, -31, -31, 16, 2, 3, -8, 40, -21, -31, -2, 41, -29, -12, 9, 14, -4,
        9, 8, -20, 28, 12, 20, -10, 5, -6, -33, 6, 21, 51, 30, 9, 3, 8, 7, 19, -53, 19, 15, 4, -38,
        19, 29, 18, 6, 19, 3, -17, -32, 16, 3, 46, -6, -3, 47, 3, -66, 3, 25, -6, -6, 21, -24, -9,
        28, -39, -42, 42, -6, -19, -14, 6, -8, 9, 28, -4, 23, 12, -17, -13, 3, 3, 6, 44, 6, -5, 38,
        -4, -16, 12, -15, 8, -11, 45, 1, -16, 37, -35, 20, 26, 9, 13, 34, 25, -3, -10, -2, -42,
        -23, -22, -56, -56, 6, 17, -9, 0, 36, 20, 6, -58, 12, 0, -3, -29, -49, -24, -12, -13, 5,
        -39, -8, 36, -9, 44, 35, -64, -22, -12, 26, -15, 41, 36, -19, -37, -20, 46, 35, 9, 32, -5,
        27, 21, -36, -51, 19, 10, -23, 28, 46, 28, 8, 22, -31, 18, 2, -16, -9, 1, -22, -22, 31, 14,
        5, 44, -3, 38, 0, -12, 50, -23, -19, 1, 42, 15, 1, 13, 32, 45, 37, 15, 11, -9, -23, -6,
        -23, 36, 4, -34, -14, -14, -37, -28, 19, 20, 14, 24, -48, -34, -27, -34, -12, 9, -20, -30,
        25, 28, -51, -13, 11, -20, -1, -3, 6, -38, -46, -15, 28, 10, -4, 3, -1, 4, -40, 16, 61, 31,
        28, 8, -2, 21, -3, -25, -12, -32, -15, -38, 20, -7, -35, 28, 29, 9, -27,
    ];
    const KAT_512_VK: [u8; 897] = [
        0x09, 0x02, 0xCE, 0x21, 0x6B, 0xE4, 0x2C, 0xD0, 0x4F, 0xC8, 0x4C, 0x24, 0xC7, 0x1D, 0x13,
        0x07, 0x8E, 0xCA, 0x07, 0x97, 0x6E, 0xE4, 0xAD, 0xBA, 0x2C, 0x98, 0x23, 0x46, 0xD8, 0x78,
        0xC0, 0x94, 0x76, 0x7F, 0xE2, 0x9C, 0x34, 0x5C, 0xE2, 0xFA, 0x87, 0x4B, 0xEE, 0x23, 0x9E,
        0xA6, 0x0B, 0xDF, 0xA7, 0x27, 0xA5, 0x16, 0x82, 0xC3, 0xDF, 0x06, 0xA2, 0x68, 0x49, 0xC3,
        0xF7, 0x26, 0x46, 0x2A, 0x59, 0xE9, 0xC4, 0x16, 0x63, 0x87, 0xBA, 0x89, 0x56, 0xDF, 0xC9,
        0xFA, 0x62, 0x20, 0x95, 0x20, 0xED, 0x65, 0x39, 0xCA, 0xDD, 0xA8, 0xF9, 0xE8, 0x11, 0xA6,
        0x8E, 0xD8, 0x69, 0x70, 0x13, 0x5A, 0xD5, 0x02, 0x6D, 0xBD, 0x16, 0xF1, 0x59, 0x97, 0xA4,
        0xBB, 0xBE, 0x35, 0x68, 0x38, 0xD7, 0x5C, 0x7A, 0x91, 0x34, 0xED, 0xB8, 0xBF, 0x25, 0xBC,
        0xBA, 0x0A, 0x03, 0x13, 0x77, 0xEB, 0xF0, 0x11, 0x0D, 0x54, 0x73, 0xC8, 0x46, 0x82, 0x7B,
        0x25, 0x6B, 0x9A, 0xB4, 0xD0, 0x26, 0x1E, 0x41, 0xC8, 0xDB, 0xF1, 0xA4, 0x24, 0xB6, 0xDA,
        0x1F, 0x21, 0xD0, 0xE2, 0x1A, 0x89, 0xBD, 0x29, 0x94, 0x07, 0x4F, 0xA5, 0x36, 0x5E, 0xA7,
        0x70, 0x0E, 0xEB, 0xD2, 0x26, 0x94, 0x7C, 0xFA, 0x7B, 0xE1, 0xA7, 0x65, 0xF4, 0xD7, 0xF9,
        0x27, 0x50, 0x02, 0x3D, 0xF2, 0x68, 0x94, 0x51, 0x2E, 0x79, 0x48, 0xC5, 0x64, 0x69, 0xE8,
        0x81, 0xD1, 0x99, 0xDA, 0x81, 0x35, 0xAF, 0xC1, 0x6E, 0x52, 0x3A, 0xF8, 0xA2, 0x3F, 0xD5,
        0x80, 0x22, 0xAE, 0x22, 0x9A, 0xC9, 0x5C, 0xFF, 0x09, 0x5D, 0x6F, 0xF3, 0x2C, 0x89, 0x0D,
        0xB2, 0x29, 0x41, 0x19, 0x21, 0x90, 0x5B, 0x3B, 0xA5, 0x2D, 0x54, 0xB5, 0x0D, 0xEC, 0xB4,
        0x4D, 0xC3, 0xD7, 0xC8, 0x99, 0x66, 0x79, 0xE8, 0x28, 0xA4, 0x3B, 0x8D, 0x06, 0x87, 0xE8,
        0xBD, 0xE0, 0x60, 0xC5, 0x10, 0x15, 0xAA, 0x9E, 0x00, 0x0C, 0x92, 0x59, 0x8F, 0x05, 0xB8,
        0x70, 0xA9, 0x4B, 0x29, 0x01, 0xA9, 0xE1, 0x2A, 0xE9, 0xAB, 0xF2, 0x0A, 0x51, 0x71, 0x4A,
        0x03, 0x6A, 0x85, 0x1C, 0xCE, 0x89, 0x15, 0x42, 0xD1, 0xEB, 0x52, 0x7E, 0x73, 0x10, 0x76,
        0xD4, 0xFF, 0x2F, 0x09, 0xBA, 0x68, 0x94, 0xA2, 0x09, 0x03, 0xCA, 0x6F, 0xA7, 0x6E, 0x13,
        0xD1, 0x2D, 0xC0, 0xAB, 0xA6, 0xB9, 0x26, 0xED, 0x6E, 0x89, 0x54, 0x84, 0x1D, 0xC0, 0x52,
        0x4A, 0x55, 0xE3, 0x65, 0x6C, 0x9C, 0x19, 0x88, 0x5E, 0xAB, 0x65, 0x4D, 0x86, 0x94, 0x93,
        0x51, 0xFB, 0x8B, 0x02, 0xEA, 0x32, 0xAE, 0x71, 0x5F, 0x09, 0x8B, 0xE2, 0x4E, 0x83, 0xD2,
        0xE2, 0x71, 0xCC, 0x8C, 0x24, 0x14, 0x8E, 0x7B, 0xD5, 0x92, 0x59, 0x28, 0x38, 0xFA, 0x55,
        0xB8, 0x8A, 0xDB, 0x89, 0x7B, 0xE5, 0xD9, 0x96, 0x97, 0xE3, 0xFC, 0xAC, 0xFA, 0xC0, 0x25,
        0xB4, 0x51, 0xF6, 0x2B, 0x6C, 0x35, 0x62, 0xC9, 0xEF, 0x90, 0x71, 0x44, 0x57, 0xA2, 0xF6,
        0x49, 0x22, 0x5F, 0x70, 0x20, 0xE9, 0xAF, 0xDB, 0xB9, 0x2A, 0xE2, 0xBE, 0xDB, 0xA6, 0x19,
        0x33, 0xB9, 0x05, 0xCF, 0xD4, 0x1A, 0x03, 0x08, 0x2B, 0xD6, 0xDF, 0x8B, 0x24, 0x27, 0xEC,
        0x7B, 0xFC, 0xAB, 0x2A, 0xDE, 0x16, 0x78, 0x9C, 0x09, 0x67, 0x45, 0x67, 0xDE, 0x11, 0x29,
        0xC1, 0xB2, 0xF6, 0x9E, 0x9C, 0x0F, 0x8F, 0xB2, 0x37, 0xC5, 0x5D, 0x05, 0xCF, 0x8F, 0x69,
        0xAD, 0x8B, 0xB7, 0x27, 0xA2, 0x08, 0x9A, 0x43, 0x71, 0x1E, 0xC6, 0xCA, 0x54, 0xB6, 0x12,
        0xC1, 0xD7, 0x2F, 0xA0, 0x2B, 0x66, 0x40, 0x98, 0x78, 0x6D, 0x08, 0x53, 0xD1, 0xBC, 0x98,
        0xE1, 0x4A, 0x57, 0x90, 0xB2, 0xCA, 0xC6, 0xC7, 0xD2, 0x48, 0x57, 0xD0, 0xFB, 0x44, 0xF5,
        0xD9, 0x5F, 0x34, 0x21, 0x33, 0x96, 0x86, 0xE8, 0xAF, 0xA5, 0xBA, 0x92, 0x4B, 0xBA, 0x94,
        0xF0, 0x73, 0xC9, 0x09, 0xE9, 0xFB, 0x8A, 0xD0, 0xA4, 0x62, 0x24, 0xD6, 0xF8, 0x1B, 0x22,
        0xA2, 0x01, 0xAE, 0xDB, 0xA8, 0x94, 0xC2, 0xAA, 0x44, 0xBA, 0xD6, 0x87, 0x4D, 0x6E, 0x24,
        0xCE, 0x1B, 0xB8, 0x3F, 0x51, 0xE6, 0x9F, 0x34, 0xA1, 0x40, 0xAD, 0x88, 0x55, 0x4F, 0x6C,
        0x47, 0x48, 0xFF, 0x9F, 0x64, 0x6F, 0x0D, 0xDB, 0xD3, 0xA4, 0x85, 0xD0, 0xBA, 0xD8, 0x05,
        0xFA, 0x29, 0xEB, 0x99, 0x68, 0x18, 0x51, 0x71, 0x45, 0x05, 0xE3, 0x71, 0xA6, 0x4A, 0x7B,
        0xCF, 0x68, 0x97, 0x95, 0x81, 0x44, 0x91, 0xDC, 0x9D, 0xC5, 0x27, 0x52, 0xE9, 0xA2, 0x7F,
        0x96, 0xF4, 0x6C, 0xE8, 0xF8, 0xA4, 0x27, 0x95, 0xC7, 0x10, 0x7E, 0xC1, 0x86, 0x78, 0x92,
        0x49, 0x6C, 0x91, 0xA1, 0x77, 0xFB, 0x80, 0x95, 0x0D, 0x69, 0x3B, 0xD4, 0xAD, 0xDE, 0x30,
        0x2E, 0x90, 0x3C, 0x41, 0x32, 0xEC, 0x95, 0x38, 0x86, 0x8D, 0xE8, 0xCF, 0x80, 0x5F, 0x5A,
        0x21, 0x92, 0x96, 0x7F, 0xA6, 0xC3, 0x50, 0x6A, 0x1A, 0xAB, 0x3C, 0x11, 0xA1, 0x5F, 0x1E,
        0x47, 0xB3, 0xB4, 0x6E, 0x64, 0x97, 0xB1, 0x5A, 0x88, 0x2E, 0x2C, 0xC8, 0x49, 0xA1, 0xB4,
        0x42, 0x49, 0xE9, 0x7F, 0x61, 0xF1, 0x6B, 0xD0, 0xEC, 0xEA, 0xD5, 0x47, 0xDD, 0x71, 0xC5,
        0xDD, 0xA5, 0xAA, 0x8A, 0x56, 0xFE, 0x36, 0x31, 0x22, 0x15, 0x85, 0x2E, 0x78, 0xDA, 0x98,
        0x5D, 0x55, 0xA4, 0xA4, 0xD8, 0xF7, 0x14, 0x8E, 0x45, 0x67, 0xD1, 0xE4, 0x67, 0x87, 0xC2,
        0x23, 0x87, 0xCA, 0x4A, 0x85, 0xF0, 0x11, 0xE3, 0x75, 0xC4, 0x5C, 0xCA, 0x0C, 0xE0, 0xA1,
        0x5B, 0xCD, 0x13, 0x37, 0xBD, 0xC9, 0x27, 0x1B, 0xFA, 0x84, 0x73, 0xE1, 0x88, 0x2F, 0x33,
        0x85, 0x58, 0x69, 0x7D, 0x9A, 0xAF, 0x07, 0x5A, 0x90, 0x78, 0x33, 0x5A, 0x1F, 0xB8, 0xA1,
        0xB3, 0xB6, 0xE9, 0xD9, 0xCF, 0x43, 0x62, 0x84, 0x06, 0x7C, 0x58, 0xC5, 0xA4, 0x8E, 0x04,
        0x7A, 0x40, 0x08, 0xD0, 0x2B, 0x7C, 0x85, 0x07, 0xC2, 0xEE, 0x6F, 0x88, 0xDA, 0x4C, 0x97,
        0xF6, 0x0F, 0x75, 0x44, 0x4C, 0x78, 0x84, 0x96, 0x67, 0x84, 0x32, 0xC9, 0x5F, 0x3A, 0x92,
        0x08, 0xB4, 0xA8, 0xC1, 0xCB, 0xC6, 0xE2, 0xD4, 0xDA, 0x61, 0x25, 0x3D, 0xA0, 0x81, 0x27,
        0x5E, 0x8F, 0x34, 0xDB, 0xE4, 0xA1, 0xEC, 0xC2, 0x22, 0x24, 0xC3, 0x08, 0x00, 0xA7, 0x75,
        0x35, 0x74, 0xC8, 0x95, 0x86, 0x95, 0x66, 0x6C, 0x28, 0x95, 0xB3, 0x5C, 0xCE, 0x07, 0x89,
        0x44, 0xA3, 0x10, 0x41, 0xA5, 0x23, 0x83, 0x7C, 0xED, 0x72, 0x17, 0x69, 0x0F, 0xA1, 0x7C,
        0x36, 0xCB, 0x45, 0x92, 0x63, 0x35, 0xE6, 0x7B, 0x18, 0x04, 0x95, 0x9D,
    ];

    const KAT_512_RND: [u8; 40 + 56] = [
        // nonce: 40 bytes
        0x16, 0xC1, 0x25, 0x15, 0x25, 0x80, 0x93, 0x79, 0x99, 0x56, 0x36, 0x8C, 0xDF, 0xC1, 0x82,
        0xC1, 0xCA, 0x4A, 0x34, 0xF0, 0x77, 0xE9, 0x24, 0x44, 0x16, 0xA8, 0xC4, 0xC1, 0x3F, 0xB0,
        0xCA, 0x24, 0x1E, 0x8B, 0x7A, 0xC1, 0x71, 0x2D, 0x28, 0xEB,
        // seed for the ChaCha20 PRNG: 56 bytes
        0xFF, 0xD8, 0x57, 0xF1, 0x49, 0x5C, 0xA5, 0x98, 0xDB, 0x2C, 0x88, 0x64, 0xAF, 0x31, 0xFA,
        0x8F, 0x37, 0xBC, 0x73, 0x8D, 0xCD, 0xB6, 0xDD, 0xAA, 0xFD, 0x25, 0x4A, 0xBF, 0xE3, 0x01,
        0xB7, 0x91, 0x9B, 0x7E, 0x9B, 0x9F, 0xEC, 0xEA, 0x4E, 0xF0, 0x01, 0xC9, 0x62, 0x9B, 0x96,
        0x6B, 0x58, 0xD6, 0x81, 0x25, 0x2F, 0xF3, 0x38, 0x9E, 0x81, 0x6B,
    ];
    // KAT vectors regenerated after fixing ChaCha20PRNG buffer layout to sequential
    // (j<<2)+(i<<6) for correct little-endian block output; matches rand_core 0.10 behavior.
    const KAT_512_sig_raw: [i16; 512] = [
        -26, 98, -55, 235, 202, 440, 43, 53, -313, -11, 25, -155, -45, -34, 28, 136, -47, 68, 176,
        -165, 174, -196, -133, -74, 85, -5, -166, -15, 249, -125, 120, -62, 155, -153, 79, -82,
        -318, 63, -311, 69, 292, 40, 43, -164, 122, -91, 92, -11, 18, -7, 184, 10, -304, 364, 9,
        324, -374, -7, -85, 30, -36, 24, -106, -160, 71, -24, 78, 155, -281, 378, -64, -37, -122,
        2, 28, -26, -36, 98, -331, 110, -250, 51, 98, -6, -188, 223, -144, 200, -71, -5, -36, -53,
        -44, -11, -340, -2, -7, 136, -301, -3, -198, 308, -169, -33, 31, 43, -345, 145, 66, 97, 71,
        185, 99, -79, 261, -19, -146, -89, -85, 41, 164, -78, -18, 19, 74, 210, -113, 373, 1, 237,
        -255, 216, -25, 37, 278, -195, -2, 57, 137, 183, 28, -170, 57, -5, -28, 98, 17, 5, 60,
        -203, -122, 113, -274, 7, -30, -139, 76, 32, -103, -30, 205, 37, -98, -111, -44, -54, 75,
        -121, -344, 99, 374, -41, 189, -141, 10, -2, -329, -147, 4, -155, 255, 100, 71, -235, -421,
        169, 239, -113, 30, 138, 62, -242, 49, 1, 56, -147, 24, 88, -93, -344, -9, 328, -131, -218,
        44, -197, -12, -172, -273, 13, -102, -146, -8, 259, 193, -172, -11, -99, -232, -167, 140,
        125, 27, 31, -63, 126, -113, -222, 213, -164, -171, 150, -214, -191, -10, -77, -280, -39,
        -178, 136, -46, 170, -104, 167, -102, 89, 1, -94, 97, 36, 287, 222, 49, -106, 191, 3, 108,
        204, -385, -106, -101, 70, 178, -45, 381, -285, -254, -31, 77, 7, -12, 182, -206, 80, -93,
        -3, 85, 95, 112, 147, -141, 53, -30, 269, 172, 56, -143, -173, -139, 298, -242, 58, 136,
        -49, -269, 151, -64, 273, -139, 32, 179, -387, -249, 157, -92, -128, 109, -126, -51, -150,
        140, -117, -52, 306, -367, -117, -342, 141, 86, -303, 55, -296, 270, 44, 186, -30, -78,
        -69, 43, -173, -100, -61, -6, 136, 331, 188, 41, 121, -169, -250, 91, 112, -77, -153, -194,
        -237, -42, 118, -238, 14, 61, -90, 9, 208, -9, -24, 168, -123, 211, 124, 211, -103, 196, 1,
        70, -42, 223, 11, 81, 79, 112, -19, 45, 199, -50, 187, -88, 99, -56, -250, -72, 43, 103,
        -174, 208, 148, -138, 7, 3, -3, 471, 32, 260, -28, 172, 204, 23, -181, -196, 47, -57, 20,
        228, 212, -160, -345, -106, 138, 217, 52, 425, 319, 68, -170, 58, 203, 233, 90, 12, -36,
        -1, 46, -166, 207, 101, -177, 63, -83, 10, -45, -125, -66, -142, 165, -46, 51, 38, 17, 61,
        421, 5, -59, 89, -147, 169, 295, 48, 147, -162, 159, -136, 103, 107, -187, 39, 103, 267,
        -346, 12, 95, 98, -122, 115, 320, -122, 87, -19, 49, -143, -56, -45, 224, 314, 167, 14,
        -168, -11, -89, -47, -190, 188, 196, 62, 130, 6, 98, -18, 331, -65, 144, -195, -310, 238,
        186, 55, 186, 108, -49, -66, -3, -286, 143, 333, -242, -187, 161, 411, -136, 186, 107, 136,
        -201,
    ];
}
