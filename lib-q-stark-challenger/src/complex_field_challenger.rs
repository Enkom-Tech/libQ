//! Challenger wrapper that implements `FieldChallenger<Complex<Mersenne31>>` by
//! delegating to a base field challenger and using algebra element methods.
//!
//! Used so that STARK prover/verifier can use a single extension-field challenger
//! (`Complex<Mersenne31>`) for transcript consistency while the underlying hash
//! operates on the base field.

extern crate alloc;

use lib_q_stark_field::BasedVectorSpace;
use lib_q_stark_field::extension::{
    BinomialExtensionField,
    Complex,
};
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_stark_symmetric::Hash;

use crate::{
    CanObserve,
    CanSample,
    CanSampleBits,
    FieldChallenger,
    GrindingChallenger,
};

/// Wrapper challenger that implements `FieldChallenger<Complex<Mersenne31>>`
/// by delegating to a base field challenger and using algebra element methods.
#[derive(Clone)]
pub struct ComplexFieldChallenger<BaseChallenger> {
    base: BaseChallenger,
}

impl<BaseChallenger> ComplexFieldChallenger<BaseChallenger> {
    /// Create a new complex field challenger wrapping the given base challenger.
    pub fn new(base: BaseChallenger) -> Self {
        Self { base }
    }
}

impl<BaseChallenger> CanObserve<Complex<Mersenne31>> for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: FieldChallenger<Mersenne31>,
{
    fn observe(&mut self, value: Complex<Mersenne31>) {
        self.base.observe_algebra_element(value);
    }

    fn observe_slice(&mut self, values: &[Complex<Mersenne31>])
    where
        Complex<Mersenne31>: Clone + Copy,
    {
        for value in values {
            self.observe(*value);
        }
    }
}

impl<BaseChallenger> CanSample<Complex<Mersenne31>> for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: FieldChallenger<Mersenne31>,
    Complex<Mersenne31>: BasedVectorSpace<Mersenne31>,
{
    fn sample(&mut self) -> Complex<Mersenne31> {
        self.base.sample_algebra_element()
    }

    fn sample_array<const N: usize>(&mut self) -> [Complex<Mersenne31>; N] {
        core::array::from_fn(|_| self.sample())
    }

    fn sample_vec(&mut self, n: usize) -> alloc::vec::Vec<Complex<Mersenne31>> {
        (0..n).map(|_| self.sample()).collect()
    }
}

impl<BaseChallenger> CanSampleBits<usize> for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: FieldChallenger<Mersenne31>,
{
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.base.sample_bits(bits)
    }
}

impl<BaseChallenger> FieldChallenger<Complex<Mersenne31>> for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: FieldChallenger<Mersenne31> + Clone + Send + Sync,
    Complex<Mersenne31>: BasedVectorSpace<Mersenne31>,
{
}

// ---------------------------------------------------------------------------
// Degree-3 extension OVER `Complex<Mersenne31>` (the FRI challenge field for the 128-bit Arm A
// config ⇒ `GF(p^6)` ~186 bits). Since `ComplexFieldChallenger` is itself a
// `FieldChallenger<Complex<Mersenne31>>`, it can sample/observe a `BasedVectorSpace<Complex>` by
// delegating to the algebra-element methods over the `Complex` layer (which in turn draw from the
// base `Mersenne31` challenger). This lets the STARK use a challenge field strictly larger than the
// ~62-bit value field without a bespoke challenger. (Concrete D = 3: the bridge
// `Complex<Mersenne31>: BinomiallyExtendable<3>` only exists for D ∈ {2,3}, so this is not generic.)
type ChallengeExt3 = BinomialExtensionField<Complex<Mersenne31>, 3>;

impl<BaseChallenger> CanObserve<ChallengeExt3> for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: FieldChallenger<Mersenne31> + Clone + Send + Sync,
    Complex<Mersenne31>: BasedVectorSpace<Mersenne31>,
{
    fn observe(&mut self, value: ChallengeExt3) {
        // Disambiguate: observe `value` as an algebra element OVER the `Complex` layer (self also
        // implements FieldChallenger<ChallengeExt3>, so an unqualified call is ambiguous).
        <Self as FieldChallenger<Complex<Mersenne31>>>::observe_algebra_element(self, value);
    }

    fn observe_slice(&mut self, values: &[ChallengeExt3])
    where
        ChallengeExt3: Clone + Copy,
    {
        for value in values {
            self.observe(*value);
        }
    }
}

impl<BaseChallenger> CanSample<ChallengeExt3> for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: FieldChallenger<Mersenne31> + Clone + Send + Sync,
    Complex<Mersenne31>: BasedVectorSpace<Mersenne31>,
{
    fn sample(&mut self) -> ChallengeExt3 {
        // Sample as an algebra element OVER the `Complex` layer (disambiguate from the
        // FieldChallenger<ChallengeExt3> impl on self).
        <Self as FieldChallenger<Complex<Mersenne31>>>::sample_algebra_element(self)
    }

    fn sample_array<const N: usize>(&mut self) -> [ChallengeExt3; N] {
        core::array::from_fn(|_| self.sample())
    }

    fn sample_vec(&mut self, n: usize) -> alloc::vec::Vec<ChallengeExt3> {
        (0..n).map(|_| self.sample()).collect()
    }
}

impl<BaseChallenger> FieldChallenger<ChallengeExt3> for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: FieldChallenger<Mersenne31> + Clone + Send + Sync,
    Complex<Mersenne31>: BasedVectorSpace<Mersenne31>,
{
}

// Forward CanObserve for Hash commitment types by observing through base challenger
impl<BaseChallenger, F, const DIGEST_ELEMS: usize> CanObserve<Hash<F, u8, DIGEST_ELEMS>>
    for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: CanObserve<Hash<Mersenne31, u8, DIGEST_ELEMS>>,
{
    fn observe(&mut self, value: Hash<F, u8, DIGEST_ELEMS>) {
        let array: [u8; DIGEST_ELEMS] = value.into();
        let mersenne_hash = Hash::<Mersenne31, u8, DIGEST_ELEMS>::from(array);
        self.base.observe(mersenne_hash);
    }

    fn observe_slice(&mut self, values: &[Hash<F, u8, DIGEST_ELEMS>])
    where
        Hash<F, u8, DIGEST_ELEMS>: Clone,
    {
        for value in values {
            self.observe(value.clone());
        }
    }
}

// Poseidon digest: Hash<Complex, Complex, 1> — observe the single field element
impl<BaseChallenger> CanObserve<Hash<Complex<Mersenne31>, Complex<Mersenne31>, 1>>
    for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: FieldChallenger<Mersenne31>,
{
    fn observe(&mut self, value: Hash<Complex<Mersenne31>, Complex<Mersenne31>, 1>) {
        let arr: [Complex<Mersenne31>; 1] = value.into();
        self.observe(arr[0]);
    }

    fn observe_slice(&mut self, values: &[Hash<Complex<Mersenne31>, Complex<Mersenne31>, 1>])
    where
        Hash<Complex<Mersenne31>, Complex<Mersenne31>, 1>: Clone,
    {
        for value in values {
            self.observe(*value);
        }
    }
}

impl<BaseChallenger> GrindingChallenger for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: GrindingChallenger<Witness = Mersenne31>
        + FieldChallenger<Mersenne31>
        + Clone
        + Send
        + Sync,
{
    type Witness = Complex<Mersenne31>;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        use lib_q_stark_field::integers::QuotientMap;

        const P: u32 = (1 << 31) - 1; // Mersenne31 prime
        assert!(bits < (usize::BITS as usize));
        assert!((1 << bits) < P as usize);

        let witness = (0..P)
            .map(|i| {
                let base = Mersenne31::from_int(i);
                Complex::<Mersenne31>::from(base)
            })
            .find(|witness| self.clone().check_witness(bits, *witness))
            .expect("failed to find witness");

        assert!(self.check_witness(bits, witness));
        witness
    }

    fn check_witness(&mut self, bits: usize, witness: Self::Witness) -> bool {
        self.observe(witness);
        self.sample_bits(bits) == 0
    }
}
