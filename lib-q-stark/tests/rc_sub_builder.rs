#![allow(clippy::clone_on_copy)]
//! Minimal range-check example that reuses a bit-decomposition gadget via [`SubAirBuilder`].
//!
//! Column layout:
//! - `c[0]`: running sum owned by the parent AIR.
//! - `c[1]`: value that must stay in `[0, 2^NUM_RANGE_BITS)`.
//! - `c[2..]`: boolean limbs proving the decomposition of `c[1]`.
//!
//! The sub-AIR enforces the decomposition + booleanity over columns `1..`, while the parent AIR
//! never touches the bit columns and only reasons about the accumulated sum.

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
    WindowAccess,
};
use lib_q_stark_challenger::{
    ComplexFieldChallenger,
    Shake256Challenger32,
};
use lib_q_stark_commit::ExtensionMmcs;
use lib_q_stark_field::extension::Complex;
use lib_q_stark_field::{
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_fri::{
    FriParameters,
    TwoAdicFriPcs,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_merkle::MerkleTreeMmcs;
use lib_q_stark_mersenne31::{
    Mersenne31,
    Mersenne31ComplexRadix2Dit,
};
use lib_q_stark_shake256::Shake256Hash;
use lib_q_stark_symmetric::{
    CompressionFunctionFromHasher,
    SerializingHasher,
};

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
        let local = main.current_slice();

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
        let local = main.current_slice();
        let next = main.next_slice();

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

    prove_bb_twoadic(&air, 6);
}

/// Tests the whole AIR with TwoAdicFriPcs (post-quantum).
fn prove_bb_twoadic(air: &RangeCheckAir, log_n: usize) {
    type Val = Complex<Mersenne31>;
    type Challenge = Val;
    type Dft = Mersenne31ComplexRadix2Dit;
    type BaseChallenger = Shake256Challenger32<Mersenne31>;
    type Challenger = ComplexFieldChallenger<BaseChallenger>;

    let shake256 = Shake256Hash {};
    type MyHash = SerializingHasher<Shake256Hash>;
    let hash = MyHash::new(shake256);

    type MyCompress = CompressionFunctionFromHasher<Shake256Hash, 2, 32>;
    let compress = MyCompress::new(shake256);

    type ValMmcs = MerkleTreeMmcs<<Val as Field>::Packing, u8, MyHash, MyCompress, 32>;
    let val_mmcs = ValMmcs::new(hash, compress);

    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let dft = Dft::default();

    let fri_params = FriParameters {
        log_blowup: 2,
        log_final_poly_len: 3,
        num_queries: 40,
        proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };
    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let challenger = Challenger::new(base_challenger);
    let config = StarkConfig::<Pcs, Challenge, Challenger>::new(pcs, challenger);

    let rows = 1 << log_n;
    let trace = air.generate_trace::<Val>(rows);

    let proof = prove(&config, air, trace, &[]).expect("prove");
    verify(&config, air, &proof, &[]).expect("verification failed");
}
