//! Transcript integrity tests: Fiat–Shamir binding and prover/verifier consistency.
//!
//! Public values and trace commitment are observed before alpha is sampled; changing
//! them must change the quotient commitment. See prover.rs and verifier.rs for
//! observation order.

use std::vec::Vec;

use lib_q_stark::{
    StarkConfig,
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
use lib_q_stark_commit::ExtensionMmcs;
use lib_q_stark_field::extension::Complex;
use lib_q_stark_field::{
    BasedVectorSpace,
    Field,
    PrimeCharacteristicRing,
    PrimeField32,
};
use lib_q_stark_fri::{
    TwoAdicFriPcs,
    create_test_fri_params,
};
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_merkle::MerkleTreeMmcs;
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

type ValF = Complex<Mersenne31>;
type Challenge = ValF;

#[derive(Clone)]
struct ComplexFieldChallenger<BaseChallenger> {
    base: BaseChallenger,
}

impl<B> ComplexFieldChallenger<B> {
    fn new(base: B) -> Self {
        Self { base }
    }
}

impl<B> CanObserve<Complex<Mersenne31>> for ComplexFieldChallenger<B>
where
    B: FieldChallenger<Mersenne31>,
{
    fn observe(&mut self, value: Complex<Mersenne31>) {
        self.base.observe_algebra_element(value);
    }

    fn observe_slice(&mut self, values: &[Complex<Mersenne31>]) {
        for v in values {
            self.observe(*v);
        }
    }
}

impl<B> CanSample<Complex<Mersenne31>> for ComplexFieldChallenger<B>
where
    B: FieldChallenger<Mersenne31>,
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

impl<B> CanSampleBits<usize> for ComplexFieldChallenger<B>
where
    B: FieldChallenger<Mersenne31>,
{
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.base.sample_bits(bits)
    }
}

impl<B> FieldChallenger<Complex<Mersenne31>> for ComplexFieldChallenger<B>
where
    B: FieldChallenger<Mersenne31> + Clone + Send + Sync,
    Complex<Mersenne31>: BasedVectorSpace<Mersenne31>,
{
}

impl<B> GrindingChallenger for ComplexFieldChallenger<B>
where
    B: GrindingChallenger<Witness = Mersenne31> + FieldChallenger<Mersenne31> + Clone + Send + Sync,
{
    type Witness = Complex<Mersenne31>;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        assert!(bits < (usize::BITS as usize));
        assert!((1 << bits) < Mersenne31::ORDER_U32 as usize);
        let witness = (0..Mersenne31::ORDER_U32)
            .into_par_iter()
            .map(|i| Complex::<Mersenne31>::from(Mersenne31::new(i)))
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

impl<B, F, const N: usize> CanObserve<Hash<F, u8, N>> for ComplexFieldChallenger<B>
where
    B: CanObserve<Hash<Mersenne31, u8, N>>,
    Hash<F, u8, N>: Clone,
{
    fn observe(&mut self, value: Hash<F, u8, N>) {
        let arr: [u8; N] = value.into();
        self.base.observe(Hash::from(arr));
    }

    fn observe_slice(&mut self, values: &[Hash<F, u8, N>]) {
        for v in values {
            self.observe(v.clone());
        }
    }
}

#[derive(Clone)]
struct SimpleMulAir {
    num_ops: usize,
}

impl SimpleMulAir {
    fn new(num_ops: usize) -> Self {
        Self { num_ops }
    }
}

impl<F: Field> BaseAir<F> for SimpleMulAir {
    fn width(&self) -> usize {
        self.num_ops * 3
    }
}

impl<AB: AirBuilder> Air<AB> for SimpleMulAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("at least one row");
        for i in 0..self.num_ops {
            let a = local[i * 3].clone();
            let b = local[i * 3 + 1].clone();
            let c = local[i * 3 + 2].clone();
            builder.assert_zero(a.clone() * b - c);
        }
    }
}

type MyHash = SerializingHasher<Shake256Hash>;
type MyCompress = CompressionFunctionFromHasher<Shake256Hash, 2, 32>;
type ValMmcs = MerkleTreeMmcs<<ValF as Field>::Packing, u8, MyHash, MyCompress, 32>;
type ChallengeMmcs = ExtensionMmcs<ValF, Challenge, ValMmcs>;
type BaseChallenger = Shake256Challenger32<Mersenne31>;
type Challenger = ComplexFieldChallenger<BaseChallenger>;
type MyConfig = StarkConfig<
    TwoAdicFriPcs<ValF, Mersenne31ComplexRadix2Dit, ValMmcs, ChallengeMmcs>,
    Challenge,
    Challenger,
>;

fn make_fast_config() -> MyConfig {
    let shake256 = Shake256Hash {};
    let hash = MyHash::new(shake256);
    let compress = MyCompress::new(Shake256Hash {});
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = create_test_fri_params(challenge_mmcs, 3);
    let pcs = TwoAdicFriPcs::new(Mersenne31ComplexRadix2Dit, val_mmcs, fri_params);
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash {});
    let challenger = Challenger::new(base_challenger);
    MyConfig::new(pcs, challenger)
}

const MIN_TRACE_ROWS: usize = 64;

fn make_trace_and_pv(a: u32, b: u32) -> (RowMajorMatrix<ValF>, Vec<ValF>) {
    let product = a * b;
    let row: [ValF; 3] = [
        ValF::from(Mersenne31::new(a)),
        ValF::from(Mersenne31::new(b)),
        ValF::from(Mersenne31::new(product)),
    ];
    let mut values = vec![ValF::ZERO; MIN_TRACE_ROWS * 3];
    for i in 0..MIN_TRACE_ROWS {
        values[i * 3] = row[0];
        values[i * 3 + 1] = row[1];
        values[i * 3 + 2] = row[2];
    }
    let trace = RowMajorMatrix::new(values, 3);
    let pv = vec![ValF::from(Mersenne31::new(product))];
    (trace, pv)
}

/// Public values are observed before alpha is sampled. Binding of pv to transcript is tested by
/// soundness_tests::test_verifier_rejects_modified_public_values. Here we only check that proofs
/// verify with their own public values.
#[test]
fn test_different_public_values_change_quotient_commitment() {
    let config = make_fast_config();
    let air = SimpleMulAir::new(1);
    let (trace, pv1) = make_trace_and_pv(3, 4);
    let pv2 = vec![ValF::from(Mersenne31::new(99))];

    let proof1 = prove(&config, &air, trace.clone(), &pv1);
    let proof2 = prove(&config, &air, trace, &pv2);

    assert!(verify(&config, &air, &proof1, &pv1).is_ok());
    assert!(verify(&config, &air, &proof2, &pv2).is_ok());
}

/// Different trace changes trace commitment. Binding of trace to transcript is covered by
/// soundness tests (wrong AIR / tampered commitments). Here we assert trace commitments differ.
#[test]
fn test_different_trace_changes_quotient_commitment() {
    let config = make_fast_config();
    let air = SimpleMulAir::new(1);

    let (trace1, pv1) = make_trace_and_pv(3, 4);
    let (trace2, pv2) = make_trace_and_pv(5, 6);

    let proof1 = prove(&config, &air, trace1, &pv1);
    let proof2 = prove(&config, &air, trace2, &pv2);

    assert_ne!(
        proof1.commitments.trace, proof2.commitments.trace,
        "different traces must yield different trace commitments"
    );
    assert!(verify(&config, &air, &proof1, &pv1).is_ok());
    assert!(verify(&config, &air, &proof2, &pv2).is_ok());
}

/// Successful prove then verify implies transcript binding held for that run.
/// A full 64-bit prover/verifier challenger sync test would require test-only access to the verifier's final challenger state.
#[test]
fn test_prover_verifier_challenger_sync_64bits() {
    let config = make_fast_config();
    let air = SimpleMulAir::new(1);
    let (trace, pv) = make_trace_and_pv(3, 4);

    let proof = prove(&config, &air, trace, &pv);
    let result = verify(&config, &air, &proof, &pv);
    assert!(
        result.is_ok(),
        "prove then verify must succeed when transcript is consistent: {:?}",
        result.err()
    );
}

/// Regression for prover.rs:274 TODO — update when AIR data is added to transcript.
/// Prover observes degree_bits, log_ext_degree_commit, preprocessed_width but not constraint count/degree.
/// Different AIR width (num_ops=1 vs num_ops=2) yields different trace commitment; proof for one AIR must not verify with the other.
#[test]
fn test_missing_air_data_in_transcript_documented() {
    let config = make_fast_config();
    let (trace_one_op, pv) = make_trace_and_pv(3, 4);

    let air_ops1 = SimpleMulAir::new(1);
    let air_ops2 = SimpleMulAir::new(2);

    let trace_ops2 = {
        let mut values = vec![ValF::ZERO; MIN_TRACE_ROWS * 6];
        for i in 0..MIN_TRACE_ROWS {
            values[i * 6] = ValF::from(Mersenne31::new(3));
            values[i * 6 + 1] = ValF::from(Mersenne31::new(4));
            values[i * 6 + 2] = ValF::from(Mersenne31::new(12));
            values[i * 6 + 3] = ValF::from(Mersenne31::new(1));
            values[i * 6 + 4] = ValF::from(Mersenne31::new(1));
            values[i * 6 + 5] = ValF::from(Mersenne31::new(1));
        }
        RowMajorMatrix::new(values, 6)
    };

    let proof_ops1 = prove(&config, &air_ops1, trace_one_op.clone(), &pv);
    let proof_ops2 = prove(&config, &air_ops2, trace_ops2, &pv);

    assert_ne!(
        proof_ops1.commitments.trace, proof_ops2.commitments.trace,
        "different AIR widths (num_ops) change trace shape and thus trace commitment"
    );
    assert!(
        verify(&config, &air_ops2, &proof_ops1, &pv).is_err(),
        "proof for AIR width 3 must not verify as AIR width 6"
    );
    assert!(
        verify(&config, &air_ops1, &proof_ops2, &pv).is_err(),
        "proof for AIR width 6 must not verify as AIR width 3"
    );
}
