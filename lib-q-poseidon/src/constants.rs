//! Poseidon constants: MDS matrices and round constants
//!
//! These constants are generated for Complex<Mersenne31> field to ensure
//! cryptographic security while maintaining efficiency in STARK proofs.
//!
//! # Round Constant Generation
//!
//! Round constants are generated using SHAKE256 (NIST FIPS 202) with a fixed seed
//! to provide "nothing up my sleeve" numbers. This ensures:
//! - Reproducibility: Same constants every time
//! - Verifiability: Anyone can regenerate constants from the seed
//! - Post-quantum security: SHAKE256 is NIST-approved
//!
//! Generation method:
//! 1. Seed = SHAKE256("Poseidon128_Mersenne31_v1") or "Poseidon256_Mersenne31_v1"
//! 2. For each constant: read 8 bytes (4 for real, 4 for imag)
//! 3. Interpret as u32 mod P (Mersenne31 prime = 2^31 - 1)
//! 4. Construct Complex<Mersenne31> from (real, imag) pair

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use digest::{
    ExtendableOutput,
    Update,
    XofReader,
};
use lib_q_sha3::Shake256;
use lib_q_stark_field::extension::Complex;
use lib_q_stark_field::{
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_mersenne31::Mersenne31;

/// Field type for constants
type F = Complex<Mersenne31>;

/// Mersenne31 prime: P = 2^31 - 1
const P: u32 = (1 << 31) - 1;

/// Build an n×n Cauchy MDS matrix over F. Every square submatrix has nonzero determinant.
/// M[i][j] = 1/(x_i + y_j) with x_i = i+1, y_j = n+j+1 (all distinct, sums never zero).
#[cfg(feature = "alloc")]
fn cauchy_mds(n: usize) -> Vec<Vec<F>> {
    let xs: Vec<F> = (0..n)
        .map(|i| F::from(Mersenne31::new((i + 1) as u32)))
        .collect();
    let ys: Vec<F> = (0..n)
        .map(|j| F::from(Mersenne31::new((n + j + 1) as u32)))
        .collect();
    (0..n)
        .map(|i| (0..n).map(|j| (xs[i] + ys[j]).inverse()).collect())
        .collect()
}

/// MDS matrix for state width 5 (Poseidon-128 over Complex<Mersenne31>).
/// Cauchy construction so every square submatrix has nonzero determinant.
#[cfg(feature = "alloc")]
pub fn mds_matrix_5x5() -> Vec<Vec<F>> {
    cauchy_mds(5)
}

/// MDS matrix for state width 7 (Poseidon-256 over Complex<Mersenne31>).
#[cfg(feature = "alloc")]
pub fn mds_matrix_7x7() -> Vec<Vec<F>> {
    cauchy_mds(7)
}

/// Round constants for Poseidon-128 (64 rounds total: 8 full + 56 partial)
/// State width 5 for 128-bit security over Complex<Mersenne31> (capacity 3 × ~62 bits ≥ 128).
///
/// Total constants: 64 rounds × 5 elements = 320 constants
/// Seed: "Poseidon128_Mersenne31_v1_w5"
#[cfg(feature = "alloc")]
pub fn round_constants_128() -> Vec<F> {
    generate_round_constants("Poseidon128_Mersenne31_v1_w5", 320)
}

/// Round constants for Poseidon-256 (68 rounds total: 8 full + 60 partial)
/// State width 7 for 256-bit security over Complex<Mersenne31> (capacity 5 × ~62 bits ≥ 256).
///
/// Total constants: 68 rounds × 7 elements = 476 constants
/// Seed: "Poseidon256_Mersenne31_v1_w7"
#[cfg(feature = "alloc")]
pub fn round_constants_256() -> Vec<F> {
    generate_round_constants("Poseidon256_Mersenne31_v1_w7", 476)
}

/// Generate round constants using SHAKE256
///
/// # Arguments
///
/// * `seed` - The seed string for SHAKE256 (e.g., "Poseidon128_Mersenne31_v1")
/// * `count` - Number of constants to generate (each constant is Complex = 2 field elements)
///
/// # Returns
///
/// Vector of `count` Complex<Mersenne31> constants
#[cfg(feature = "alloc")]
fn generate_round_constants(seed: &str, count: usize) -> Vec<F> {
    // Initialize SHAKE256 with seed
    let mut hasher = Shake256::default();
    hasher.update(seed.as_bytes());
    let mut reader = hasher.finalize_xof();

    // Each Complex<Mersenne31> needs 8 bytes (4 for real, 4 for imag)
    // Total bytes needed: count * 8
    let mut bytes = alloc::vec![0u8; count * 8];
    reader.read(&mut bytes);

    let mut constants = Vec::with_capacity(count);
    for i in 0..count {
        // Extract real part (4 bytes) and imag part (4 bytes)
        let real_bytes = [
            bytes[i * 8],
            bytes[i * 8 + 1],
            bytes[i * 8 + 2],
            bytes[i * 8 + 3],
        ];
        let imag_bytes = [
            bytes[i * 8 + 4],
            bytes[i * 8 + 5],
            bytes[i * 8 + 6],
            bytes[i * 8 + 7],
        ];

        // Reduce to [0, P-1]; P = 2^31-1 so % P never yields P (zero in field)
        let real_u32 = u32::from_le_bytes(real_bytes) % P;
        let imag_u32 = u32::from_le_bytes(imag_bytes) % P;

        // Create Mersenne31 elements (they handle mod P internally)
        let real = Mersenne31::new(real_u32);
        let imag = Mersenne31::new(imag_u32);

        // Construct Complex field element using new_complex
        constants.push(Complex::new_complex(real, imag));
    }

    debug_assert!(
        constants.iter().all(|c| *c != F::ZERO),
        "round constant must not be zero"
    );
    constants
}

/// S-box function: x^5
///
/// This is the power function used in Poseidon's non-linear layer.
/// For Complex<Mersenne31>, we compute x^5 efficiently.
#[inline]
pub fn sbox(x: F) -> F {
    use lib_q_stark_field::PrimeCharacteristicRing;
    // x^5 = x^4 * x = (x^2)^2 * x
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}
