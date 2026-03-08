use core::borrow::Borrow;
extern crate alloc;

use lib_q_random::DeterministicRng;
use lib_q_stark::{
    StarkConfig,
    prove,
    verify,
};
use lib_q_stark_air::{
    Air,
    AirBuilder,
    AirBuilderWithPublicValues,
    BaseAir,
};
use lib_q_stark_challenger::{
    CanObserve,
    CanSample,
    CanSampleBits,
    FieldChallenger,
    GrindingChallenger,
    Shake256Challenger32,
};
use lib_q_stark_commit::ExtensionMmcs;
use lib_q_stark_field::extension::Complex;
use lib_q_stark_field::integers::QuotientMap;
use lib_q_stark_field::{
    BasedVectorSpace,
    Field,
    PrimeCharacteristicRing,
    PrimeField32,
};
use lib_q_stark_fri::{
    HidingFriPcs,
    TwoAdicFriPcs,
    create_test_fri_params,
};
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_merkle::{
    MerkleTreeHidingMmcs,
    MerkleTreeMmcs,
};
use lib_q_stark_mersenne31::{
    Mersenne31,
    Mersenne31ComplexRadix2Dit,
};
use lib_q_stark_rayon::prelude::*;
use lib_q_stark_shake256::Shake256Hash;
use lib_q_stark_symmetric::{
    CompressionFunctionFromHasher,
    Hash,
    SerializingHasher,
};

/// For testing the public values feature
pub struct FibonacciAir {}

impl<F> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        NUM_FIBONACCI_COLS
    }
}

impl<AB: AirBuilderWithPublicValues> Air<AB> for FibonacciAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let pis = builder.public_values();

        let a = pis[0];
        let b = pis[1];
        let x = pis[2];

        let (local, next) = (
            main.row_slice(0).expect("Matrix is empty?"),
            main.row_slice(1).expect("Matrix only has 1 row?"),
        );
        let local: &FibonacciRow<AB::Var> = (*local).borrow();
        let next: &FibonacciRow<AB::Var> = (*next).borrow();

        let mut when_first_row = builder.when_first_row();

        when_first_row.assert_eq(local.left.clone(), a);
        when_first_row.assert_eq(local.right.clone(), b);

        let mut when_transition = builder.when_transition();

        // a' <- b
        when_transition.assert_eq(local.right.clone(), next.left.clone());

        // b' <- a + b
        when_transition.assert_eq(local.left.clone() + local.right.clone(), next.right.clone());

        builder.when_last_row().assert_eq(local.right.clone(), x);
    }
}

pub fn generate_trace_rows<F: Field>(a: u64, b: u64, n: usize) -> RowMajorMatrix<F> {
    assert!(n.is_power_of_two());

    let mut trace = RowMajorMatrix::new(F::zero_vec(n * NUM_FIBONACCI_COLS), NUM_FIBONACCI_COLS);

    // SAFETY: align_to_mut is safe when the slice is properly aligned and sized.
    // FibonacciRow is a repr(C) struct that matches the memory layout of NUM_FIBONACCI_COLS field elements.
    let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<FibonacciRow<F>>() };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), n);

    rows[0] = FibonacciRow::new(F::from_u64(a), F::from_u64(b));

    for i in 1..n {
        rows[i].left = rows[i - 1].right;
        rows[i].right = rows[i - 1].left + rows[i - 1].right;
    }

    trace
}

const NUM_FIBONACCI_COLS: usize = 2;

pub struct FibonacciRow<F> {
    pub left: F,
    pub right: F,
}

impl<F> FibonacciRow<F> {
    const fn new(left: F, right: F) -> Self {
        Self { left, right }
    }
}

impl<F> Borrow<FibonacciRow<F>> for [F] {
    fn borrow(&self) -> &FibonacciRow<F> {
        debug_assert_eq!(self.len(), NUM_FIBONACCI_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<FibonacciRow<F>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

/// Wrapper challenger that implements FieldChallenger<Complex<Mersenne31>>
/// by delegating to a base field challenger and using algebra element methods
#[derive(Clone)]
struct ComplexFieldChallenger<BaseChallenger> {
    base: BaseChallenger,
}

impl<BaseChallenger> ComplexFieldChallenger<BaseChallenger> {
    fn new(base: BaseChallenger) -> Self {
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
        Complex<Mersenne31>: Clone,
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

    fn sample_vec(&mut self, n: usize) -> Vec<Complex<Mersenne31>> {
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

// Implement GrindingChallenger by delegating to base challenger
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
        assert!(bits < (usize::BITS as usize));
        assert!((1 << bits) < Mersenne31::ORDER_U32 as usize);

        // Search for a Complex witness using the wrapper's check_witness
        // This ensures transcript consistency with the verifier
        let witness = (0..Mersenne31::ORDER_U32)
            .into_par_iter()
            .map(|i| {
                let base = Mersenne31::from_int(i);
                Complex::<Mersenne31>::from(base)
            })
            .find_any(|witness| self.clone().check_witness(bits, *witness))
            .expect("failed to find witness");

        // Verify and update the original challenger's state
        assert!(self.check_witness(bits, witness));
        witness
    }

    fn check_witness(&mut self, bits: usize, witness: Self::Witness) -> bool {
        // Check witness by observing it and sampling bits
        self.observe(witness);
        self.sample_bits(bits) == 0
    }
}

// Forward CanObserve for Hash commitment types by observing through base challenger
// The base challenger can observe Hash<Mersenne31, u8, DIGEST_ELEMS>, so we need to
// convert or observe the commitment Hash which uses Packing::Value
impl<BaseChallenger, F, const DIGEST_ELEMS: usize> CanObserve<Hash<F, u8, DIGEST_ELEMS>>
    for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: CanObserve<Hash<Mersenne31, u8, DIGEST_ELEMS>>,
{
    fn observe(&mut self, value: Hash<F, u8, DIGEST_ELEMS>) {
        // Convert Hash<F, u8, DIGEST_ELEMS> to Hash<Mersenne31, u8, DIGEST_ELEMS>
        // by extracting the array and creating a new Hash with Mersenne31 marker
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

// Use Complex<Mersenne31> as base field (TWO_ADICITY = 32) for sufficient two-adicity
type Val = Complex<Mersenne31>;
// Use Complex<Mersenne31> directly as challenge field (no further extension needed)
// For further extension if needed, use BinomialExtensionField<Val, 2>
type Challenge = Val;
// Quantum-safe SHAKE256-based Merkle tree setup
type MyHash = SerializingHasher<Shake256Hash>;
type MyCompress = CompressionFunctionFromHasher<Shake256Hash, 2, 32>;
// Use u8 as width type for byte-based hashing (quantum-safe)
type ValMmcs = MerkleTreeMmcs<<Val as Field>::Packing, u8, MyHash, MyCompress, 32>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
// Use wrapper challenger that implements FieldChallenger<Complex<Mersenne31>>
type BaseChallenger = Shake256Challenger32<Mersenne31>;
type Challenger = ComplexFieldChallenger<BaseChallenger>;
// Use Mersenne31ComplexRadix2Dit for Complex<Mersenne31> field
type Dft = Mersenne31ComplexRadix2Dit;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// n-th Fibonacci number expected to be x
fn test_public_value_impl(n: usize, x: u64, log_final_poly_len: usize) {
    let shake256 = Shake256Hash {};
    let hash = MyHash::new(shake256);
    let compress = MyCompress::new(shake256);
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let trace = generate_trace_rows::<Val>(0, 1, n);
    let fri_params = create_test_fri_params(challenge_mmcs, log_final_poly_len);
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let challenger = Challenger::new(base_challenger);

    let config = MyConfig::new(pcs, challenger);
    let pis = vec![Val::ZERO, Val::ONE, Val::from_u64(x)];

    let proof = prove(&config, &FibonacciAir {}, trace, &pis);
    verify(&config, &FibonacciAir {}, &proof, &pis).expect("verification failed");
}

#[test]
fn test_zk() {
    // Quantum-safe SHAKE256-based Merkle tree setup
    let shake256 = Shake256Hash {};
    type MyHidingHash = SerializingHasher<Shake256Hash>;
    let hash = MyHidingHash::new(shake256);

    type MyHidingCompress = CompressionFunctionFromHasher<Shake256Hash, 2, 32>;
    let compress = MyHidingCompress::new(shake256);

    type ValHidingMmcs = MerkleTreeHidingMmcs<
        <Val as Field>::Packing,
        u8,
        MyHidingHash,
        MyHidingCompress,
        DeterministicRng,
        32,
        32,
    >;

    let rng = DeterministicRng::seed_from_u64(1);
    let val_mmcs = ValHidingMmcs::new(hash, compress, rng);

    // Use wrapper challenger that implements FieldChallenger<Complex<Mersenne31>>
    type BaseChallenger = Shake256Challenger32<Mersenne31>;
    type Challenger = ComplexFieldChallenger<BaseChallenger>;

    type ChallengeHidingMmcs = ExtensionMmcs<Val, Challenge, ValHidingMmcs>;
    type Dft = Mersenne31ComplexRadix2Dit;

    let n = 1 << 3;
    let x = 21;

    let challenge_mmcs = ChallengeHidingMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let trace = generate_trace_rows::<Val>(0, 1, n);
    let fri_params = create_test_fri_params(challenge_mmcs, 2);
    type HidingPcs = HidingFriPcs<Val, Dft, ValHidingMmcs, ChallengeHidingMmcs, DeterministicRng>;
    type MyHidingConfig = StarkConfig<HidingPcs, Challenge, Challenger>;
    let pcs = HidingPcs::new(
        dft,
        val_mmcs,
        fri_params,
        4,
        DeterministicRng::seed_from_u64(1),
    );
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let challenger = Challenger::new(base_challenger);
    let config = MyHidingConfig::new(pcs, challenger);
    let pis = vec![Val::ZERO, Val::ONE, Val::from_u64(x)];
    let proof = prove(&config, &FibonacciAir {}, trace, &pis);
    verify(&config, &FibonacciAir {}, &proof, &pis).expect("verification failed");
}

#[test]
fn test_one_row_trace() {
    test_public_value_impl(1, 1, 0);
}

#[test]
fn test_public_value() {
    test_public_value_impl(1 << 3, 21, 2);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "assertion `left == right` failed: constraints had nonzero value")]
fn test_incorrect_public_value() {
    let shake256 = Shake256Hash {};
    let hash = MyHash::new(shake256);
    let compress = MyCompress::new(shake256);
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = create_test_fri_params(challenge_mmcs, 1);
    let trace = generate_trace_rows::<Val>(0, 1, 1 << 3);
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let challenger = Challenger::new(base_challenger);
    let config = MyConfig::new(pcs, challenger);
    let pis = vec![
        Val::ZERO,
        Val::ONE,
        Val::from_u32(123_123), // incorrect result
    ];
    prove(&config, &FibonacciAir {}, trace, &pis);
}
