#![no_std]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(clippy::too_many_arguments)]

//! # FN-DSA key pair generation
//!
//! This crate implements key pair generation for FN-DSA. The process
//! uses some temporary buffers which are held in an instance that
//! follows the trait `KeyPairGenerator`, on which the `keygen()` method
//! can be called. A cryptographically secure random source (e.g.
//! [`OsRng`]) must be provided as parameter; the generator will extract
//! an initial seed from it, then work deterministically from that seed.
//! The output is a signing (private) key and a verifying (public) key,
//! both encoded as a sequence of bytes with a given fixed length.
//!
//! FN-DSA is parameterized by a degree, which is a power of two.
//! Standard versions use degree 512 ("level I security") or 1024 ("level
//! V security"); smaller degrees are deemed too weak for production use
//! and meant only for research and testing. The degree is provided
//! logarithmically as the `logn` parameter, such that the degree is `n =
//! 2^logn` (thus, degrees 512 and 1024 correspond to `logn` values 9 and
//! 10, respectively).
//!
//! Each `KeyPairGenerator` instance supports only a specific range of
//! degrees:
//!
//!  - `KeyPairGeneratorStandard`: degrees 512 and 1024 only
//!  - `KeyPairGenerator512`: degree 512 only
//!  - `KeyPairGenerator1024`: degree 1024 only
//!  - `KeyPairGeneratorWeak`: degrees 4 to 256 only
//!
//! Given `logn`, the `sign_key_size()` and `vrfy_key_size()` constant
//! functions yield the sizes of the signing and verifying keys (in
//! bytes).
//!
//! ## Standards alignment
//!
//! This crate implements FN-DSA, the signature scheme NIST **selected** for
//! standardization as FIPS 206. FIPS 206 has **not been published** — there is no
//! finalized standard, and no public draft, to be "compliant" with. Key encodings,
//! message pre-hashing, and domain separation follow the FN-DSA design as tracked by
//! the upstream `fn-dsa` reference implementation; if and when NIST publishes FIPS 206,
//! releases of this crate may need to adjust for wire interoperability.
//!
//! ## Example usage
//!
//! ```ignore
//! use rand_core::OsRng;
//! use fn_dsa_kgen::{
//!     sign_key_size, vrfy_key_size, FN_DSA_LOGN_512,
//!     KeyPairGenerator, KeyPairGeneratorStandard,
//! };
//!
//! let mut kg = KeyPairGeneratorStandard::default();
//! let mut sign_key = [0u8; sign_key_size(FN_DSA_LOGN_512)];
//! let mut vrfy_key = [0u8; vrfy_key_size(FN_DSA_LOGN_512)];
//! kg.keygen(FN_DSA_LOGN_512, &mut OsRng, &mut sign_key, &mut vrfy_key);
//! ```
//!
//! [`OsRng`]: https://docs.rs/rand_core/0.6.4/rand_core/struct.OsRng.html

mod fxp;
mod gauss;
mod mp31;
mod ntru;
mod poly;
mod vect;
mod zint31;

#[cfg(all(
    not(feature = "no_avx2"),
    any(target_arch = "x86_64", target_arch = "x86")
))]
mod ntru_avx2;

#[cfg(all(
    not(feature = "no_avx2"),
    any(target_arch = "x86_64", target_arch = "x86")
))]
mod poly_avx2;

#[cfg(all(
    not(feature = "no_avx2"),
    any(target_arch = "x86_64", target_arch = "x86")
))]
mod vect_avx2;

#[cfg(all(
    not(feature = "no_avx2"),
    any(target_arch = "x86_64", target_arch = "x86")
))]
mod zint31_avx2;

#[cfg(not(feature = "shake256x4"))]
use fn_dsa_comm::PRNG;
// Re-export useful types, constants and functions.
pub use fn_dsa_comm::{
    CryptoRng,
    FN_DSA_LOGN_512,
    FN_DSA_LOGN_1024,
    Rng,
    RngError,
    sign_key_size,
    vrfy_key_size,
};
use fn_dsa_comm::{
    codec,
    mq,
    shake,
};
use zeroize::{
    Zeroize,
    ZeroizeOnDrop,
};

/// Key pair generator and temporary buffers.
///
/// Key pair generation uses relatively large temporary buffers (about 25
/// or 50 kB, for the two standard degrees), which is why they are part
/// of the `KeyPairGenerator` instance instead of being allocated on the
/// stack. An instance can be used for several successive key pair
/// generations. Implementations of this trait are expected to handle
/// automatic zeroization (overwrite of all contained secret values when
/// the object is released).
pub trait KeyPairGenerator: Default {
    /// Generate a new key pair.
    ///
    /// The random source `rng` MUST be cryptographically secure. The
    /// degree (`logn`) must be supported by the instance; a panic is
    /// triggered otherwise. The new signing and verifying keys are
    /// written into `sign_key` and `vrfy_key`, respectively; these
    /// destination slices MUST have the exact size for their respective
    /// contents (see the `sign_key_size()` and `vrfy_key_size()`
    /// functions).
    fn keygen<T: CryptoRng + Rng>(
        &mut self,
        logn: u32,
        rng: &mut T,
        sign_key: &mut [u8],
        vrfy_key: &mut [u8],
    );
}

macro_rules! kgen_impl {
    ($typename:ident, $logn_min:expr, $logn_max:expr) => {
        #[doc = concat!("Key pair generator for degrees (`logn`) ",
                                stringify!($logn_min), " to ", stringify!($logn_max), " only.")]
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $typename {
            tmp_i8: [i8; 4 * (1 << ($logn_max))],
            tmp_u16: [u16; 2 * (1 << ($logn_max))],
            tmp_u32: [u32; 6 * (1 << ($logn_max))],
            tmp_fxr: [fxp::Fxr; 5 * (1 << (($logn_max) - 1))],
        }

        impl KeyPairGenerator for $typename {
            fn keygen<T: CryptoRng + Rng>(
                &mut self,
                logn: u32,
                rng: &mut T,
                sign_key: &mut [u8],
                vrfy_key: &mut [u8],
            ) {
                // Enforce minimum and maximum degree.
                assert!(($logn_min..=$logn_max).contains(&logn));
                keygen_inner(
                    logn,
                    rng,
                    sign_key,
                    vrfy_key,
                    &mut self.tmp_i8,
                    &mut self.tmp_u16,
                    &mut self.tmp_u32,
                    &mut self.tmp_fxr,
                );
            }
        }

        impl Default for $typename {
            fn default() -> Self {
                Self {
                    tmp_i8: [0i8; 4 * (1 << ($logn_max))],
                    tmp_u16: [0u16; 2 * (1 << ($logn_max))],
                    tmp_u32: [0u32; 6 * (1 << ($logn_max))],
                    tmp_fxr: [fxp::Fxr::ZERO; 5 * (1 << (($logn_max) - 1))],
                }
            }
        }
    };
}

// An FN-DSA key pair generator for the standard degrees (512 and 1024,
// for logn = 9 or 10, respectively). Attempts at creating a lower degree
// key pair trigger a panic.
kgen_impl!(KeyPairGeneratorStandard, 9, 10);

// An FN-DSA key pair generator specialized for degree 512 (logn = 9).
// It differs from KeyPairGeneratorStandard in that it does not support
// degree 1024, but it also uses only half as much RAM. It is intended
// to be used embedded systems with severe RAM constraints.
kgen_impl!(KeyPairGenerator512, 9, 9);

// An FN-DSA key pair generator specialized for degree 1024 (logn = 10).
// It differs from KeyPairGeneratorStandard in that it does not support
// degree 512. It is intended for applications that want to enforce use
// of the level V security variant.
kgen_impl!(KeyPairGenerator1024, 10, 10);

// An FN-DSA key pair generator for the weak/toy degrees (4 to 256,
// for logn = 2 to 8). Such smaller degrees are intended only for testing
// and research purposes; they are not standardized.
kgen_impl!(KeyPairGeneratorWeak, 2, 8);

// Generate a new key pair, using the provided random generator as
// source for the initial entropy. The degree is n = 2^logn, with
// 2 <= logn <= 10 (normal keys use logn = 9 or 10, for degrees 512
// and 1024, respectively; smaller degrees are toy versions for tests).
// The provided output slices must have the correct lengths for
// the requested degrees.
// Minimum sizes for temporaries (in number of elements):
//   tmp_i8:  4*n
//   tmp_u16: 2*n
//   tmp_u32: 6*n
//   tmp_fxr: 2.5*n
fn keygen_inner<T: CryptoRng + Rng>(
    logn: u32,
    rng: &mut T,
    sign_key: &mut [u8],
    vrfy_key: &mut [u8],
    tmp_i8: &mut [i8],
    tmp_u16: &mut [u16],
    tmp_u32: &mut [u32],
    tmp_fxr: &mut [fxp::Fxr],
) {
    assert!((2..=10).contains(&logn));
    assert!(sign_key.len() == sign_key_size(logn));
    assert!(vrfy_key.len() == vrfy_key_size(logn));

    let n = 1usize << logn;

    // Get a new seed. Everything is generated deterministically from
    // the seed.
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    // Make f, g, F and G.
    // Keygen is slow enough that the runtime cost for AVX2 detection
    // is negligible. If we are on x86 and AVX2 is available then we
    // can use the specialized implementation.
    let (f, tmp_i8) = tmp_i8.split_at_mut(n);
    let (g, tmp_i8) = tmp_i8.split_at_mut(n);
    let (F, tmp_i8) = tmp_i8.split_at_mut(n);
    let (G, _) = tmp_i8.split_at_mut(n);
    let (h, t16) = tmp_u16.split_at_mut(n);

    #[cfg(all(
        not(feature = "no_avx2"),
        any(target_arch = "x86_64", target_arch = "x86")
    ))]
    if fn_dsa_comm::has_avx2() {
        unsafe {
            keygen_from_seed_avx2(logn, &seed, f, g, F, G, t16, tmp_u32, tmp_fxr);
            fn_dsa_comm::mq_avx2::mqpoly_div_small(logn, f, g, h, t16);
        }
    } else {
        keygen_from_seed(logn, &seed, f, g, F, G, t16, tmp_u32, tmp_fxr);
        mq::mqpoly_div_small(logn, f, g, h, t16);
    }

    #[cfg(not(all(
        not(feature = "no_avx2"),
        any(target_arch = "x86_64", target_arch = "x86")
    )))]
    {
        keygen_from_seed(logn, &seed, f, g, F, G, t16, tmp_u32, tmp_fxr);
        mq::mqpoly_div_small(logn, f, g, h, t16);
    }

    // Encode the signing key (f, g and F, in that order).
    sign_key[0] = 0x50 + (logn as u8);
    let nbits_fg = match logn {
        2..=5 => 8,
        6..=7 => 7,
        8..=9 => 6,
        _ => 5,
    };
    let j = 1 + codec::trim_i8_encode(f, nbits_fg, &mut sign_key[1..]);
    let j = j + codec::trim_i8_encode(g, nbits_fg, &mut sign_key[j..]);
    let j = j + codec::trim_i8_encode(F, 8, &mut sign_key[j..]);
    assert!(j == sign_key.len());

    // Encode the verifying key.
    vrfy_key[0] = logn as u8;
    let j = 1 + codec::modq_encode(h, &mut vrfy_key[1..]);
    assert!(j == vrfy_key.len());
}

// Internal keygen function:
//  - processing is deterministic from the provided seed;
//  - the f, g, F and G polynomials are not encoded, but provided in
//    raw format (arrays of signed integers);
//  - the public key h = g/f is not computed (but the function checks
//    that it is computable, i.e. that f is invertible mod X^n+1 mod q).
// Minimum sizes for temporaries (in number of elements):
//   tmp_u16: n
//   tmp_u32: 6*n
//   tmp_fxr: 2.5*n
fn keygen_from_seed(
    logn: u32,
    seed: &[u8],
    f: &mut [i8],
    g: &mut [i8],
    F: &mut [i8],
    G: &mut [i8],
    tmp_u16: &mut [u16],
    tmp_u32: &mut [u32],
    tmp_fxr: &mut [fxp::Fxr],
) {
    // Check the parameters.
    assert!((2..=10).contains(&logn));
    let n = 1usize << logn;
    assert!(f.len() == n);
    assert!(g.len() == n);
    assert!(F.len() == n);
    assert!(G.len() == n);

    #[cfg(feature = "shake256x4")]
    let mut rng = shake::SHAKE256x4::new(seed);

    #[cfg(not(feature = "shake256x4"))]
    let mut rng = <shake::SHAKE256_PRNG as PRNG>::new(seed);

    loop {
        // Generate f and g with the right parity.
        gauss::sample_f(logn, &mut rng, f);
        gauss::sample_f(logn, &mut rng, g);

        // Ensure that ||(g, -f)|| < 1.17*sqrt(q). We compute the
        // squared norm; (1.17*sqrt(q))^2 = 16822.4121
        let mut sn = 0;
        for i in 0..n {
            let xf = f[i] as i32;
            let xg = g[i] as i32;
            sn += xf * xf + xg * xg;
        }
        if sn >= 16823 {
            continue;
        }

        // f must be invertible modulo X^n+1 modulo q.
        if !mq::mqpoly_small_is_invertible(logn, &*f, tmp_u16) {
            continue;
        }

        // (f,g) must have an acceptable orthogonalized norm.
        if !ntru::check_ortho_norm(logn, &*f, &*g, tmp_fxr) {
            continue;
        }

        // Solve the NTRU equation.
        if ntru::solve_NTRU(logn, &*f, &*g, F, G, tmp_u32, tmp_fxr) {
            // We found a solution.
            break;
        }
    }
}

// keygen_from_seed() variant, with AVX2 optimizations.
#[cfg(all(
    not(feature = "no_avx2"),
    any(target_arch = "x86_64", target_arch = "x86")
))]
#[target_feature(enable = "avx2")]
unsafe fn keygen_from_seed_avx2(
    logn: u32,
    seed: &[u8],
    f: &mut [i8],
    g: &mut [i8],
    F: &mut [i8],
    G: &mut [i8],
    tmp_u16: &mut [u16],
    tmp_u32: &mut [u32],
    tmp_fxr: &mut [fxp::Fxr],
) {
    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;
        use core::mem::transmute;

        use fn_dsa_comm::mq_avx2;

        // Check the parameters.
        assert!((2..=10).contains(&logn));
        let n = 1usize << logn;
        assert!(f.len() == n);
        assert!(g.len() == n);
        assert!(F.len() == n);
        assert!(G.len() == n);

        #[cfg(feature = "shake256x4")]
        let mut rng = shake::SHAKE256x4::new(seed);

        #[cfg(not(feature = "shake256x4"))]
        let mut rng = <shake::SHAKE256_PRNG as PRNG>::new(seed);

        loop {
            // Generate f and g with the right parity.
            gauss::sample_f(logn, &mut rng, f);
            gauss::sample_f(logn, &mut rng, g);

            // Ensure that ||(g, -f)|| < 1.17*sqrt(q). We compute the
            // squared norm; (1.17*sqrt(q))^2 = 16822.4121
            if logn >= 4 {
                let fp: *const __m128i = transmute(f.as_ptr());
                let gp: *const __m128i = transmute(g.as_ptr());
                let mut ys = _mm256_setzero_si256();
                let mut ov = _mm256_setzero_si256();
                for i in 0..(1usize << (logn - 4)) {
                    let xf = _mm_loadu_si128(fp.wrapping_add(i));
                    let xg = _mm_loadu_si128(gp.wrapping_add(i));
                    let yf = _mm256_cvtepi8_epi16(xf);
                    let yg = _mm256_cvtepi8_epi16(xg);
                    let yf = _mm256_mullo_epi16(yf, yf);
                    let yg = _mm256_mullo_epi16(yg, yg);
                    let yt = _mm256_add_epi16(yf, yg);

                    // Since source values are in [-127,+127], any individual
                    // 16-bit product in yt is at most 2*127^2 = 32258, which
                    // is less than 2^15; thus, any overflow in the addition
                    // necessarily implies that the corresponding high bit will
                    // be set at some point in the loop.
                    ys = _mm256_add_epi16(ys, yt);
                    ov = _mm256_or_si256(ov, ys);
                }
                ys = _mm256_add_epi16(ys, _mm256_srli_epi32(ys, 16));
                ov = _mm256_or_si256(ov, ys);
                ys = _mm256_and_si256(
                    ys,
                    _mm256_setr_epi16(-1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0),
                );
                ys = _mm256_add_epi32(ys, _mm256_srli_epi64(ys, 32));
                ys = _mm256_add_epi32(ys, _mm256_bsrli_epi128(ys, 8));
                let xs = _mm_add_epi32(_mm256_castsi256_si128(ys), _mm256_extracti128_si256(ys, 1));
                let r = _mm256_movemask_epi8(ov) as u32;
                if (r & 0xAAAAAAAA) != 0 {
                    continue;
                }
                let sn = _mm_cvtsi128_si32(xs) as u32;
                if sn >= 16823 {
                    continue;
                }
            } else {
                let mut sn = 0;
                for i in 0..n {
                    let xf = f[i] as i32;
                    let xg = g[i] as i32;
                    sn += xf * xf + xg * xg;
                }
                if sn >= 16823 {
                    continue;
                }
            }

            // f must be invertible modulo X^n+1 modulo q.
            if !mq_avx2::mqpoly_small_is_invertible(logn, &*f, tmp_u16) {
                continue;
            }

            // (f,g) must have an acceptable orthogonalized norm.
            if !ntru_avx2::check_ortho_norm(logn, &*f, &*g, tmp_fxr) {
                continue;
            }

            // Solve the NTRU equation.
            if ntru_avx2::solve_NTRU(logn, &*f, &*g, F, G, tmp_u32, tmp_fxr) {
                // We found a solution.
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use lib_q_sha3::{
        Digest,
        Sha3_256,
    };

    use super::*;

    // For degrees 256, 512, and 1024, 100 key pairs have been generated
    // with falcon.py from ntrugen; this implementation is supposed to be
    // able to reproduce them exactly, from the same seeds. Since testing
    // all the keys in debug mode is slow, only a few keys for each
    // degree are actually retested in the tests; the pins for the other
    // key pairs are not kept.

    #[cfg(feature = "shake256x4")]
    static KAT_KG256: [&str; 10] = [
        "0cb7f79db3452466b4eeabe2e7c3a2dcad603c24a946df14e15a0fd10ef766d7",
        "9965c726bbf3ec625f56c122e726b250f84338b9d56073e1a784e41476e43ffc",
        "da3da315977ba22508e3a12e6372de5bb2e64371eaab29937ccf4115e1cbd4a6",
        "8192757871a2b04d28f15aefde87651321e23ad957311ddb5022b25788aa3e2b",
        "42abf4579645e6e6ef442c0b1ee1840847a9491d996fff7228b4760e7ee5f125",
        "180bb436f1a7f3eb8e21cd90252a2e837d1e63b44bb35ec5588ac1321d910876",
        "3e2699414efb62d34040b5926bc0436d77a04b1176cfd05fc364b1196ed94031",
        "9e2574a0c71ed40fab0b26eb4174997b43197fd6526b53c77449fe7b553ead01",
        "0bb821c5d8fd8915d3f93d0e6237cf26deb3d93d00bbb097fb3c3e33b2eb3efc",
        "b020da1072f1f31d594c0c3ff7cf4997696d3a8a0a0c05a307fd96723963d3fa",
    ];

    #[cfg(feature = "shake256x4")]
    static KAT_KG512: [&str; 5] = [
        "c11c935dd6163f8d2155a1dad59292a282df73f5f1ea10f6b2c551111103193d",
        "11c84c565af922c8a03f17f62e10e855c8c565b024a275168bcb656a5bd01ddb",
        "07fddc9d2b9781f7bf7511ccf52c1caf925c1e0ad476b0eeaa58826940b41a3e",
        "85d442fb9004391ddc9ffcd2d8dc3420bc76fad3bd065b55e9a3a81d3b80312a",
        "974f5a28de66e3eef74ac4f1e544a3c2fadbac83abd3131a4d4a410dbf1e02cb",
    ];

    #[cfg(feature = "shake256x4")]
    static KAT_KG1024: [&str; 2] = [
        "a19574a3497d91a9894779a0ba698aa349c4b231f4fc73956ab503d62446d1cc",
        "de74b42b454488086a0adef6d5ed1526c3c84cc621a799db6562bb24513902ba",
    ];

    #[cfg(not(feature = "shake256x4"))]
    static KAT_KG256: [&str; 10] = [
        "1ff32f3ff906b2199446e946189cd542367fede7e10defe114f91a05a5b5787d",
        "e9bf589a2305c3bb16b70ad4485f88af16d93b0720e2c6f7bfac7d5cb0cdf22a",
        "f85c7120ef48c0f06fdc55e3e26f69d8292c8801f247956bbc75e6251c821195",
        "dcaa28523a3272b33cee5a3b0b06bf77e8e258ec9ed0bb6e56d82cb2728d7bb9",
        "a85b266e185b38f15e88f1bede9d1c09159ebe654e82daf2e63568434ba9a571",
        "a32d7bd2f4ee56bd8abcc952b2582fc72f658c10068bc0d84a7eebc2e957f204",
        "f081f8d9b51fa277cf6d58fc5647cf9a0c7a4803bbeb2defe47b31ddd3d3d422",
        "1e147363eb5b0d3e7a78710d2a74e62c9ee3992867185957d19afdfc651fa736",
        "3c3e2b12759f3207463784d36ed70f7d6539f5c1ea6f77d32eede3f687b0fec3",
        "e01cf3e349f84d9f78e32e15a3c0a702dd6ffda8cf373051cbbf729a4f6c84c8",
    ];

    #[cfg(not(feature = "shake256x4"))]
    static KAT_KG512: [&str; 5] = [
        "e2437711024c444cee51d364a9a05a3e8a5af4f7bd41cbbf6681cbad66efcbc7",
        "c90eccf3cdb4a0a72e9d5e32fde7fad84fa628c575b5dd671e7358ff264172ec",
        "bb17d8edcd7ca93ad5a6961874f08827afe074be9fdd21d723cf845e501fe320",
        "866b3de9bef684e8cdcabf2156d0e06b32ca9f7818b6ebeac0e7fe79f8833f54",
        "f4361b091ffdd259d546383e778e2011abe1dd469936602603a8c6166b9dfc9a",
    ];

    #[cfg(not(feature = "shake256x4"))]
    static KAT_KG1024: [&str; 2] = [
        "6d1eb9167b68577ca24e29b42756c0241d77fbbd4e019576a2e43d99f78ecb6b",
        "33ec79dd94314ccf0e16313faeab4d48bc0d08258f0e0b0dd5c54cec837c75b5",
    ];

    fn inner_keygen_ref(logn: u32, rh: &[&str]) {
        let n = 1usize << logn;
        let mut f = [0i8; 1024];
        let mut g = [0i8; 1024];
        let mut F = [0i8; 1024];
        let mut G = [0i8; 1024];
        let mut th = [0u8; 4 * 1024];
        let mut t16 = [0u16; 1024];
        let mut t32 = [0u32; 6 * 1024];
        let mut tfx = [fxp::Fxr::ZERO; 5 * 512];
        #[allow(clippy::needless_range_loop)]
        for i in 0..rh.len() {
            let mut seed = [0u8; 10];
            seed[..4].copy_from_slice(&b"test"[..]);
            let seed_len = if i < 10 {
                seed[4] = (0x30 + i) as u8;
                5
            } else {
                seed[4] = (0x30 + (i / 10)) as u8;
                seed[5] = (0x30 + (i % 10)) as u8;
                6
            };
            let seed = &seed[..seed_len];
            keygen_from_seed(
                logn,
                seed,
                &mut f[..n],
                &mut g[..n],
                &mut F[..n],
                &mut G[..n],
                &mut t16,
                &mut t32,
                &mut tfx,
            );
            for j in 0..n {
                th[j] = f[j] as u8;
                th[j + n] = g[j] as u8;
                th[j + 2 * n] = F[j] as u8;
                th[j + 3 * n] = G[j] as u8;
            }
            let mut sh = Sha3_256::new();
            sh.update(&th[..(4 * n)]);
            let hv = sh.finalize();
            assert!(hv[..] == hex::decode(rh[i]).unwrap());

            #[cfg(all(
                not(feature = "no_avx2"),
                any(target_arch = "x86_64", target_arch = "x86")
            ))]
            if fn_dsa_comm::has_avx2() {
                unsafe {
                    keygen_from_seed_avx2(
                        logn,
                        seed,
                        &mut f[..n],
                        &mut g[..n],
                        &mut F[..n],
                        &mut G[..n],
                        &mut t16,
                        &mut t32,
                        &mut tfx,
                    );
                }
                for j in 0..n {
                    assert!(th[j] == (f[j] as u8));
                    assert!(th[j + n] == (g[j] as u8));
                    assert!(th[j + 2 * n] == (F[j] as u8));
                    assert!(th[j + 3 * n] == (G[j] as u8));
                }
            }
        }
    }

    /// Full keygen KATs (degrees 256 / 512 / 1024). Previously `#[ignore]`d as "too slow
    /// for routine `cargo test`" -- that was an artifact of the portable `poly_sub_scaled` bug
    /// fixed in commit e101182 (n=2 unrolled arm), which made NTRU keygen livelock (never
    /// terminate) on any non-AVX2 build; x86 CI never noticed because it always took the AVX2
    /// path. Post-fix this runs in well under a second in every profile (dev and release, with
    /// and without `no_avx2`); see `poly::tests::poly_sub_scaled_arms_match_general` for the
    /// direct regression guard on that bug.
    #[test]
    fn test_keygen_ref_full_kat() {
        inner_keygen_ref(8, &KAT_KG256);
        inner_keygen_ref(9, &KAT_KG512);
        inner_keygen_ref(10, &KAT_KG1024);
    }

    /// NTRU identity check (all supported `logn`). Previously `#[ignore]`d for the same reason as
    /// `test_keygen_ref_full_kat` above (portable keygen livelock, now fixed); runs in well under
    /// a second post-fix.
    #[test]
    fn test_keygen_self() {
        for logn in 2..11 {
            let n = 1usize << logn;
            let mut f = [0i8; 1024];
            let mut g = [0i8; 1024];
            let mut F = [0i8; 1024];
            let mut G = [0i8; 1024];
            let mut r = [0i32; 2 * 1024];
            let mut t16 = [0u16; 1024];
            let mut t32 = [0u32; 6 * 1024];
            let mut tfx = [fxp::Fxr::ZERO; 5 * 512];
            for t in 0..2 {
                let seed = [logn as u8, t];
                keygen_from_seed(
                    logn,
                    &seed,
                    &mut f[..n],
                    &mut g[..n],
                    &mut F[..n],
                    &mut G[..n],
                    &mut t16,
                    &mut t32,
                    &mut tfx,
                );
                #[allow(clippy::needless_range_loop)]
                for i in 0..(2 * n) {
                    r[i] = 0;
                }
                for i in 0..n {
                    let xf = f[i] as i32;
                    let xg = g[i] as i32;
                    for j in 0..n {
                        let xF = F[j] as i32;
                        let xG = G[j] as i32;
                        r[i + j] += xf * xG - xg * xF;
                    }
                }
                for i in 0..n {
                    r[i] -= r[i + n];
                }
                assert!(r[0] == 12289);
                #[allow(clippy::needless_range_loop)]
                for i in 1..n {
                    assert!(r[i] == 0);
                }

                #[cfg(all(
                    not(feature = "no_avx2"),
                    any(target_arch = "x86_64", target_arch = "x86")
                ))]
                if fn_dsa_comm::has_avx2() {
                    let mut f2 = [0i8; 1024];
                    let mut g2 = [0i8; 1024];
                    let mut F2 = [0i8; 1024];
                    let mut G2 = [0i8; 1024];
                    unsafe {
                        keygen_from_seed_avx2(
                            logn,
                            &seed,
                            &mut f2[..n],
                            &mut g2[..n],
                            &mut F2[..n],
                            &mut G2[..n],
                            &mut t16,
                            &mut t32,
                            &mut tfx,
                        );
                    }
                    assert!(f[..n] == f2[..n]);
                    assert!(g[..n] == g2[..n]);
                    assert!(F[..n] == F2[..n]);
                    assert!(G[..n] == G2[..n]);
                }
            }
        }
    }
}
