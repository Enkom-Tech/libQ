//! Minimal range-check example that reuses a bit-decomposition gadget via [`SubAirBuilder`].
//!
//! Column layout:
//! - `c[0]`: running sum owned by the parent AIR.
//! - `c[1]`: value that must stay in `[0, 2^NUM_RANGE_BITS)`.
//! - `c[2..]`: boolean limbs proving the decomposition of `c[1]`.
//!
//! The sub-AIR enforces the decomposition + booleanity over columns `1..`, while the parent AIR
//! never touches the bit columns and only reasons about the accumulated sum.

use core::marker::PhantomData;

use lib_q_stark::{
    StarkConfig,
    SubAirBuilder,
    SymbolicAirBuilder,
    prove,
    verify,
};
use lib_q_stark_air::{
    Air,
    AirBuilder,
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
use lib_q_stark_commit::testing::TrivialPcs;
use lib_q_stark_field::extension::Complex;
use lib_q_stark_field::integers::QuotientMap;
use lib_q_stark_field::{
    BasedVectorSpace,
    Field,
    PrimeCharacteristicRing,
    PrimeField32,
};
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::{
    Mersenne31,
    Mersenne31ComplexRadix2Dit,
};
use lib_q_stark_rayon::prelude::*;
use lib_q_stark_shake256::Shake256Hash;
use lib_q_stark_symmetric::Hash;

const NUM_RANGE_BITS: usize = 4;
const TRACE_WIDTH: usize = 2 + NUM_RANGE_BITS;

/// Range-check gadget: proves a value equals the sum of weighted boolean limbs.
#[derive(Copy, Clone)]
struct RangeDecompAir;

impl<F: Field> BaseAir<F> for RangeDecompAir {
    fn width(&self) -> usize {
        1 + NUM_RANGE_BITS
    }
}

impl<AB> Air<AB> for RangeDecompAir
where
    AB: AirBuilder,
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("matrix should have a local row");

        let value = local[0].clone();
        let bits = &local[1..];

        let mut recomposed = AB::Expr::ZERO;
        for (i, bit) in bits.iter().enumerate() {
            let weight = AB::F::from_u32(1 << i);
            recomposed += bit.clone() * weight;
            builder.assert_zero(bit.clone() * (bit.clone() - AB::Expr::ONE));
        }

        builder.assert_zero(value - recomposed);
    }
}

/// Parent AIR that reuses the range gadget but only reasons about the running sum.
#[derive(Copy, Clone)]
struct RangeCheckAir;

impl<F: Field> BaseAir<F> for RangeCheckAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }
}

impl<AB> Air<AB> for RangeCheckAir
where
    AB: AirBuilder,
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        // Declare the sub-AIR and evaluate it via `SubAirBuilder`
        let sub_air = RangeDecompAir;
        {
            let mut sub_builder =
                SubAirBuilder::<AB, RangeDecompAir, AB::Var>::new(builder, 1..TRACE_WIDTH);
            sub_air.eval(&mut sub_builder);
        }

        // Evaluate the parent AIR
        let main = builder.main();
        let local = main.row_slice(0).expect("matrix should have a local row");
        let next = main.row_slice(1).expect("matrix only has 1 row?");

        let accumulator = local[0].clone();
        let range_value = local[1].clone();
        let next_accumulator = next[0].clone();

        builder.when_first_row().assert_zero(accumulator.clone());
        builder
            .when_transition()
            .assert_eq(next_accumulator, accumulator + range_value);
    }
}

impl RangeCheckAir {
    fn generate_trace<F: Field>(&self, rows: usize) -> RowMajorMatrix<F> {
        assert!(
            rows.is_power_of_two(),
            "trace height must be a power of two"
        );
        let mut values = F::zero_vec(rows * TRACE_WIDTH);
        let mut accumulator = F::ZERO;
        for row in 0..rows {
            let base = row * TRACE_WIDTH;
            let raw_value = (row * 7) % (1 << NUM_RANGE_BITS);
            values[base] = accumulator;
            values[base + 1] = F::from_u32(raw_value as u32);
            let mut tmp = raw_value;
            for bit in 0..NUM_RANGE_BITS {
                values[base + 2 + bit] = F::from_u32((tmp & 1) as u32);
                tmp >>= 1;
            }
            accumulator += F::from_u32(raw_value as u32);
        }
        RowMajorMatrix::new(values, TRACE_WIDTH)
    }
}

// Ensures the range-check gadget stays scoped to its columns and the whole AIR proves.
#[test]
fn range_checked_sub_builder() {
    type Val = Complex<Mersenne31>;
    let air = RangeCheckAir;
    let mut builder = SymbolicAirBuilder::<Val>::new(0, TRACE_WIDTH, 0, 0, 0);
    air.eval(&mut builder);

    let constraints = builder.base_constraints();
    assert!(
        !constraints.is_empty(),
        "Range-check AIR should emit constraints"
    );

    prove_bb_trivial_deg4(&air, 3);
}

/// Wrapper challenger that implements FieldChallenger<Complex<Mersenne31>>
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
            self.observe(value.clone());
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

        let witness = (0..Mersenne31::ORDER_U32)
            .into_par_iter()
            .map(|i| {
                let base = Mersenne31::from_int(i);
                Complex::<Mersenne31>::from(base)
            })
            .find_any(|witness| self.clone().check_witness(bits, *witness))
            .expect("failed to find witness");

        assert!(self.check_witness(bits, witness));
        witness
    }

    fn check_witness(&mut self, bits: usize, witness: Self::Witness) -> bool {
        self.observe(witness);
        self.sample_bits(bits) == 0
    }
}

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

impl<BaseChallenger> CanObserve<Vec<Vec<Complex<Mersenne31>>>>
    for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: FieldChallenger<Mersenne31>,
{
    fn observe(&mut self, valuess: Vec<Vec<Complex<Mersenne31>>>) {
        for values in valuess {
            for value in values {
                self.observe(value);
            }
        }
    }
}

/// Tests the whole AIR on a trivial trace.
fn prove_bb_trivial_deg4(air: &RangeCheckAir, log_n: usize) {
    type Val = Complex<Mersenne31>;
    // Use Complex<Mersenne31> directly as challenge field
    type Challenge = Val;
    type Dft = Mersenne31ComplexRadix2Dit;
    type BaseChallenger = Shake256Challenger32<Mersenne31>;
    type Challenger = ComplexFieldChallenger<BaseChallenger>;
    type Pcs = TrivialPcs<Val, Dft>;
    type Config = StarkConfig<Pcs, Challenge, Challenger>;

    let rows = 1 << log_n;
    let trace = air.generate_trace::<Val>(rows);

    let dft = Dft::default();

    let pcs = Pcs {
        dft,
        log_n,
        _phantom: PhantomData,
    };
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let challenger = Challenger::new(base_challenger);
    let config = Config::new(pcs, challenger);

    let proof = prove(&config, air, trace, &[]);
    verify(&config, air, &proof, &[]).expect("verification failed");
}
