#![allow(clippy::clone_on_copy)]

use core::fmt::Debug;

use itertools::Itertools;
use lib_q_random::DeterministicRng;
use lib_q_stark::{
    PcsError,
    StarkConfig,
    StarkGenericConfig,
    Val,
    VerificationError,
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
// p3_circle::CirclePcs removed: non-NIST hash
use lib_q_stark_commit::ExtensionMmcs;
use lib_q_stark_field::extension::Complex;
use lib_q_stark_field::{
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_fri::{
    FriParameters,
    HidingFriPcs,
    TwoAdicFriPcs,
    create_test_fri_params_zk,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_merkle::{
    MerkleTreeHidingMmcs,
    MerkleTreeMmcs,
};
use lib_q_stark_mersenne31::{
    Mersenne31,
    Mersenne31ComplexRadix2Dit,
};
use lib_q_stark_shake256::Shake256Hash;
use lib_q_stark_symmetric::{
    CompressionFunctionFromHasher,
    SerializingHasher,
};
use rand::RngExt;
use rand::distr::{
    Distribution,
    StandardUniform,
};

/// How many `a * b = c` operations to do per row in the AIR.
const REPETITIONS: usize = 20; // This should be < 255 so it can fit into a u8.
const TRACE_WIDTH: usize = REPETITIONS * 3;

/*
In its basic form, asserts a^(self.degree-1) * b = c
(so that the total constraint degree is self.degree)


If `uses_transition_constraints`, checks that on transition rows, the first a = row number
*/
pub struct MulAir {
    degree: u64,
    uses_boundary_constraints: bool,
    uses_transition_constraints: bool,
}

impl Default for MulAir {
    fn default() -> Self {
        Self {
            degree: 3,
            uses_boundary_constraints: true,
            uses_transition_constraints: true,
        }
    }
}

impl MulAir {
    pub fn random_valid_trace<F: Field>(&self, rows: usize, valid: bool) -> RowMajorMatrix<F>
    where
        StandardUniform: Distribution<F>,
    {
        let mut rng = DeterministicRng::seed_from_u64(1);
        let mut trace_values = F::zero_vec(rows * TRACE_WIDTH);
        for (i, (a, b, c)) in trace_values.iter_mut().tuples().enumerate() {
            let row = i / REPETITIONS;
            *a = if self.uses_transition_constraints {
                F::from_usize(i)
            } else {
                rng.random()
            };
            *b = if self.uses_boundary_constraints && row == 0 {
                a.square() + F::ONE
            } else {
                rng.random()
            };
            *c = a.exp_u64(self.degree - 1) * *b;

            if !valid {
                // make it invalid
                *c *= F::TWO;
            }
        }
        RowMajorMatrix::new(trace_values, TRACE_WIDTH)
    }
}

impl<F> BaseAir<F> for MulAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for MulAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let main_local = main.current_slice();
        let main_next = main.next_slice();

        for i in 0..REPETITIONS {
            let start = i * 3;
            let a = main_local[start].clone();
            let b = main_local[start + 1].clone();
            let c = main_local[start + 2].clone();
            builder.assert_zero(a.clone().into().exp_u64(self.degree - 1) * b.clone() - c);
            if self.uses_boundary_constraints {
                builder
                    .when_first_row()
                    .assert_eq(a.clone() * a.clone() + AB::Expr::ONE, b);
            }
            if self.uses_transition_constraints {
                let next_a = main_next[start].clone();
                builder
                    .when_transition()
                    .assert_eq(a + AB::Expr::from_u8(REPETITIONS as u8), next_a);
            }
        }
    }
}

fn do_test<SC: StarkGenericConfig>(
    config: &SC,
    air: &MulAir,
    log_height: usize,
) -> Result<(), VerificationError<PcsError<SC>>>
where
    SC::Challenger: Clone,
    StandardUniform: Distribution<Val<SC>>,
{
    let trace = air.random_valid_trace(log_height, true);

    let proof = prove(config, air, trace, &[]).expect("prove");

    let serialized_proof = postcard::to_allocvec(&proof).expect("unable to serialize proof");
    tracing::debug!("serialized_proof len: {} bytes", serialized_proof.len());

    let deserialized_proof =
        postcard::from_bytes(&serialized_proof).expect("unable to deserialize proof");

    verify(config, air, &deserialized_proof, &[])
}

fn do_test_bb_twoadic(log_blowup: usize, degree: u64, log_n: usize) -> Result<(), impl Debug> {
    type Val = Complex<Mersenne31>;
    // Use Complex<Mersenne31> directly as challenge field
    type Challenge = Val;

    // Quantum-safe SHAKE256-based Merkle tree setup
    let shake256 = Shake256Hash {};
    type MyHash = SerializingHasher<Shake256Hash>;
    let hash = MyHash::new(shake256);

    type MyCompress = CompressionFunctionFromHasher<Shake256Hash, 2, 32>;
    let compress = MyCompress::new(shake256);

    // Use u8 as width type for byte-based hashing (quantum-safe)
    type ValMmcs = MerkleTreeMmcs<<Val as Field>::Packing, u8, MyHash, MyCompress, 32>;
    let val_mmcs = ValMmcs::new(hash, compress);

    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    type Dft = Mersenne31ComplexRadix2Dit;
    let dft = Dft::default();

    type BaseChallenger = Shake256Challenger32<Mersenne31>;
    type Challenger = ComplexFieldChallenger<BaseChallenger>;

    let fri_params = FriParameters {
        log_blowup,
        log_final_poly_len: 3,
        num_queries: 40,
        proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };
    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let challenger = Challenger::new(base_challenger);

    type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
    let config = MyConfig::new(pcs, challenger);

    let air = MulAir {
        degree,
        ..Default::default()
    };

    do_test(&config, &air, 1 << log_n)
}

#[test]
fn prove_bb_twoadic_deg2() -> Result<(), impl Debug> {
    do_test_bb_twoadic(1, 2, 5)
}

#[test]
fn prove_bb_twoadic_deg2_zk() -> Result<(), impl Debug> {
    type Val = Complex<Mersenne31>;
    // Use Complex<Mersenne31> directly as challenge field
    type Challenge = Val;

    // Quantum-safe SHAKE256-based Merkle tree setup
    let shake256 = Shake256Hash {};
    type MyHash = SerializingHasher<Shake256Hash>;
    let hash = MyHash::new(shake256);

    type MyCompress = CompressionFunctionFromHasher<Shake256Hash, 2, 32>;
    let compress = MyCompress::new(shake256);

    type ValMmcs = MerkleTreeHidingMmcs<
        <Val as Field>::Packing,
        u8,
        MyHash,
        MyCompress,
        DeterministicRng,
        32,
        4,
    >;

    let rng = DeterministicRng::seed_from_u64(1);
    let val_mmcs = ValMmcs::new(hash, compress, rng);

    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    type Dft = Mersenne31ComplexRadix2Dit;
    let dft = Dft::default();

    type BaseChallenger = Shake256Challenger32<Mersenne31>;
    type Challenger = ComplexFieldChallenger<BaseChallenger>;

    let fri_params = create_test_fri_params_zk(challenge_mmcs);
    type HidingPcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, DeterministicRng>;
    let pcs = HidingPcs::new(
        dft,
        val_mmcs,
        fri_params,
        4,
        DeterministicRng::seed_from_u64(1),
    );
    type MyConfig = StarkConfig<HidingPcs, Challenge, Challenger>;
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let challenger = Challenger::new(base_challenger);
    let config = MyConfig::new(pcs, challenger);

    let air = MulAir {
        degree: 3,
        ..Default::default()
    };
    do_test(&config, &air, 1 << 8)
}

#[test]
fn prove_bb_twoadic_deg3() -> Result<(), impl Debug> {
    do_test_bb_twoadic(1, 3, 5)
}

#[test]
fn prove_bb_twoadic_deg4() -> Result<(), impl Debug> {
    do_test_bb_twoadic(2, 4, 4)
}

#[test]
fn prove_bb_twoadic_deg5() -> Result<(), impl Debug> {
    do_test_bb_twoadic(2, 5, 4)
}

// Circle STARKs not integrated - commenting out CirclePcs tests
// fn do_test_m31_circle(log_blowup: usize, degree: u64, log_n: usize) -> Result<(), impl Debug> {
//     type Val = Mersenne31;
//     type Challenge = BinomialExtensionField<Val, 3>;
//
//     type ByteHash = Shake256Hash;
//     type FieldHash = SerializingHasher<ByteHash>;
//     let byte_hash = ByteHash {};
//     let field_hash = FieldHash::new(byte_hash);
//
//     type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
//     let compress = MyCompress::new(byte_hash);
//
//     type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
//     let val_mmcs = ValMmcs::new(field_hash, compress);
//
//     type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
//     let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
//
//     type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
//
//     let fri_params = FriParameters {
//         log_blowup,
//         log_final_poly_len: 0,
//         num_queries: 40,
//         proof_of_work_bits: 8,
//         mmcs: challenge_mmcs,
//     };
//
//     type Pcs = CirclePcs<Val, ValMmcs, ChallengeMmcs>;
//     let pcs = Pcs {
//         mmcs: val_mmcs,
//         fri_params,
//         _phantom: PhantomData,
//     };
//     let challenger = Challenger::from_hasher(vec![], byte_hash);
//
//     type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
//     let config = MyConfig::new(pcs, challenger);
//
//     let air = MulAir {
//         degree,
//         uses_boundary_constraints: true,
//         uses_transition_constraints: true,
//     };
//
//     do_test(config, air, 1 << log_n)
// }

// #[test]
// fn prove_m31_circle_deg2() -> Result<(), impl Debug> {
//     do_test_m31_circle(1, 2, 6)
// }

// #[test]
// fn prove_m31_circle_deg3() -> Result<(), impl Debug> {
//     do_test_m31_circle(1, 3, 7)
// }
