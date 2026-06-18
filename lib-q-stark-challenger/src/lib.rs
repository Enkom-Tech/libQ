//! Utilities for generating Fiat-Shamir challenges based on an IOP's transcript.

#![no_std]

extern crate alloc;

mod complex_field_challenger;
mod duplex_challenger;
mod grinding_challenger;
mod hash_challenger;
mod serializing_challenger;

use alloc::vec::Vec;
use core::array;

pub use complex_field_challenger::ComplexFieldChallenger;
pub use duplex_challenger::*;
pub use grinding_challenger::*;
pub use hash_challenger::*;
use lib_q_stark_field::{
    Algebra,
    BasedVectorSpace,
    Field,
};
use lib_q_stark_sha3_256::Sha3_256Hash;
// Convenience type aliases for hash-based challengers
use lib_q_stark_shake128::Shake128Hash;
use lib_q_stark_shake256::Shake256Hash;
pub use serializing_challenger::*;

/// A SHAKE128-based challenger for 32-bit prime fields.
///
/// This is a NIST-approved, post-quantum secure challenger suitable for production use.
/// It uses SHAKE128 (SHA-3 family) for Fiat-Shamir challenge generation.
/// SHAKE128 provides 128-bit security level, making it a lighter option than SHAKE256.
pub type Shake128Challenger32<F> = SerializingChallenger32<F, HashChallenger<u8, Shake128Hash, 32>>;

/// A SHAKE128-based challenger for 64-bit prime fields.
///
/// This is a NIST-approved, post-quantum secure challenger suitable for production use.
/// It uses SHAKE128 (SHA-3 family) for Fiat-Shamir challenge generation.
/// SHAKE128 provides 128-bit security level, making it a lighter option than SHAKE256.
pub type Shake128Challenger64<F> = SerializingChallenger64<F, HashChallenger<u8, Shake128Hash, 32>>;

/// A SHAKE256-based challenger for 32-bit prime fields.
///
/// This is a NIST-approved, post-quantum secure challenger suitable for production use.
/// It uses SHAKE256 (SHA-3 family) for Fiat-Shamir challenge generation.
/// SHAKE256 provides 256-bit security level and is the recommended default.
///
/// # Modular Architecture
///
/// The challenger architecture is generic over hash functions. To use a different NIST-approved
/// hash function, implement `CryptographicHasher<u8, [u8; N]>` for your hash type and use:
/// ```ignore
/// use lib_q_stark_challenger::{SerializingChallenger32, HashChallenger};
/// type MyChallenger<F> =
///     SerializingChallenger32<F, HashChallenger<u8, MyHash, N>>;
/// ```
///
/// Available hash options:
/// - [`Shake128Challenger32`] - SHAKE128 (128-bit security, lighter)
/// - [`Shake256Challenger32`] - SHAKE256 (256-bit security, recommended)
/// - [`Sha3_256Challenger32`] - SHA3-256 (256-bit security, fixed-length)
pub type Shake256Challenger32<F> = SerializingChallenger32<F, HashChallenger<u8, Shake256Hash, 32>>;

/// A SHAKE256-based challenger for 64-bit prime fields.
///
/// This is a NIST-approved, post-quantum secure challenger suitable for production use.
/// It uses SHAKE256 (SHA-3 family) for Fiat-Shamir challenge generation.
/// SHAKE256 provides 256-bit security level and is the recommended default.
///
/// # Modular Architecture
///
/// See [`Shake256Challenger32`] for details on the modular hash architecture.
pub type Shake256Challenger64<F> = SerializingChallenger64<F, HashChallenger<u8, Shake256Hash, 32>>;

/// A SHA3-256-based challenger for 32-bit prime fields.
///
/// This is a NIST-approved, post-quantum secure challenger suitable for production use.
/// It uses SHA3-256 (SHA-3 family) for Fiat-Shamir challenge generation.
/// SHA3-256 provides 256-bit security level with fixed-length output (unlike XOF functions).
pub type Sha3_256Challenger32<F> = SerializingChallenger32<F, HashChallenger<u8, Sha3_256Hash, 32>>;

/// A SHA3-256-based challenger for 64-bit prime fields.
///
/// This is a NIST-approved, post-quantum secure challenger suitable for production use.
/// It uses SHA3-256 (SHA-3 family) for Fiat-Shamir challenge generation.
/// SHA3-256 provides 256-bit security level with fixed-length output (unlike XOF functions).
pub type Sha3_256Challenger64<F> = SerializingChallenger64<F, HashChallenger<u8, Sha3_256Hash, 32>>;

/// A generic trait for absorbing elements into the transcript.
///
/// Absorbed elements update the internal sponge state,
/// preparing it to deterministically produce future challenges.
pub trait CanObserve<T> {
    /// Absorb a single value into the transcript.
    fn observe(&mut self, value: T);

    /// Absorb a slice of values into the transcript.
    fn observe_slice(&mut self, values: &[T])
    where
        T: Clone,
    {
        for value in values {
            self.observe(value.clone());
        }
    }
}

/// A trait for sampling challenge elements from the Fiat-Shamir transcript.
///
/// Sampling produces pseudo-random elements deterministically derived
/// from the absorbed inputs and the sponge state.
pub trait CanSample<T> {
    /// Sample a single challenge value from the transcript.
    fn sample(&mut self) -> T;

    /// Sample an array of `N` challenge values from the transcript.
    fn sample_array<const N: usize>(&mut self) -> [T; N] {
        array::from_fn(|_| self.sample())
    }

    /// Sample a `Vec` of `n` challenge values from the transcript.
    fn sample_vec(&mut self, n: usize) -> Vec<T> {
        (0..n).map(|_| self.sample()).collect()
    }
}

/// A trait for sampling random bitstrings from the Fiat-Shamir transcript.
pub trait CanSampleBits<T> {
    /// Sample a random `bits`-bit integer from the transcript.
    ///
    /// The distribution should be reasonably close to uniform.
    /// (In practice, a small bias may arise when bit-decomposing a uniformly
    /// sampled field element)
    ///
    /// Guarantees that the returned value fits within the requested bit width.
    fn sample_bits(&mut self, bits: usize) -> T;
}

/// A high-level trait combining observation and sampling over a finite field.
pub trait FieldChallenger<F: Field>:
    CanObserve<F> + CanSample<F> + CanSampleBits<usize> + Sync
{
    /// Absorb an element from a vector space over the base field.
    ///
    /// Decomposes the element into its basis coefficients and absorbs each.
    fn observe_algebra_element<A: BasedVectorSpace<F>>(&mut self, alg_elem: A) {
        self.observe_slice(alg_elem.as_basis_coefficients_slice());
    }

    /// Sample an element of a vector space over the base field.
    ///
    /// Constructs the element by sampling basis coefficients.
    fn sample_algebra_element<A: BasedVectorSpace<F>>(&mut self) -> A {
        A::from_basis_coefficients_fn(|_| self.sample())
    }

    /// Observe base field elements as extension field elements for recursion-friendly transcripts.
    ///
    /// This simplifies recursive verifier circuits by using a uniform extension field challenger.
    /// Instead of observing a mix of base and extension field elements, we convert all base field
    /// observations (metadata, public values) to extension field elements before passing to the challenger.
    ///
    /// # Recursion Benefits
    ///
    /// In recursive proof systems, the verifier circuit needs to verify the inner proof. Since STARK
    /// verification operates entirely in the extension field (challenges, opened values, constraint
    /// evaluation), having a challenger that only observes extension field elements significantly
    /// simplifies the recursive circuit implementation.
    #[inline]
    fn observe_base_as_algebra_element<EF>(&mut self, val: F)
    where
        EF: Algebra<F> + BasedVectorSpace<F>,
    {
        self.observe_algebra_element(EF::from(val));
    }
}

impl<C, T> CanObserve<T> for &mut C
where
    C: CanObserve<T>,
{
    #[inline(always)]
    fn observe(&mut self, value: T) {
        (*self).observe(value);
    }

    #[inline(always)]
    fn observe_slice(&mut self, values: &[T])
    where
        T: Clone,
    {
        (*self).observe_slice(values);
    }
}

impl<C, T> CanSample<T> for &mut C
where
    C: CanSample<T>,
{
    #[inline(always)]
    fn sample(&mut self) -> T {
        (*self).sample()
    }

    #[inline(always)]
    fn sample_array<const N: usize>(&mut self) -> [T; N] {
        (*self).sample_array()
    }

    #[inline(always)]
    fn sample_vec(&mut self, n: usize) -> Vec<T> {
        (*self).sample_vec(n)
    }
}

impl<C, T> CanSampleBits<T> for &mut C
where
    C: CanSampleBits<T>,
{
    #[inline(always)]
    fn sample_bits(&mut self, bits: usize) -> T {
        (*self).sample_bits(bits)
    }
}

impl<C, F: Field> FieldChallenger<F> for &mut C
where
    C: FieldChallenger<F>,
{
    #[inline(always)]
    fn observe_algebra_element<EF: BasedVectorSpace<F>>(&mut self, ext: EF) {
        (*self).observe_algebra_element(ext);
    }

    #[inline(always)]
    fn sample_algebra_element<EF: BasedVectorSpace<F>>(&mut self) -> EF {
        (*self).sample_algebra_element()
    }

    #[inline(always)]
    fn observe_base_as_algebra_element<EF>(&mut self, val: F)
    where
        EF: Algebra<F> + BasedVectorSpace<F>,
    {
        (*self).observe_base_as_algebra_element::<EF>(val);
    }
}
