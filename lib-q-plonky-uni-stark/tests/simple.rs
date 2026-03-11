//! Integration tests for uni-stark: round-trip prove/verify, wrong public values rejected,
//! and preprocessed columns.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use lib_q_plonky_uni_stark::{
    StarkConfig,
    prove,
    prove_with_preprocessed,
    setup_preprocessed,
    verify,
    verify_with_preprocessed,
};
use lib_q_stark_air::{
    Air,
    BaseAir,
    WindowAccess,
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
    PrimeField32,
};
use lib_q_stark_fri::{
    TwoAdicFriPcs,
    create_test_fri_params,
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
    Hash,
    SerializingHasher,
};

type Val = Complex<Mersenne31>;
type MyHash = SerializingHasher<Shake256Hash>;
type MyCompress = CompressionFunctionFromHasher<Shake256Hash, 2, 32>;
type ValMmcs = MerkleTreeMmcs<<Val as Field>::Packing, u8, MyHash, MyCompress, 32>;
type ChallengeMmcs = ExtensionMmcs<Val, Val, ValMmcs>;
type Dft = Mersenne31ComplexRadix2Dit;
type MyPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

#[derive(Clone)]
struct ComplexFieldChallenger<BaseChallenger> {
    base: BaseChallenger,
}

impl<BaseChallenger> ComplexFieldChallenger<BaseChallenger> {
    fn new(base: BaseChallenger) -> Self {
        Self { base }
    }
}

impl<BaseChallenger> CanObserve<Val> for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: FieldChallenger<Mersenne31>,
{
    fn observe(&mut self, value: Val) {
        self.base.observe_algebra_element(value);
    }

    fn observe_slice(&mut self, values: &[Val])
    where
        Val: Clone,
    {
        for value in values {
            self.observe(*value);
        }
    }
}

impl<BaseChallenger> CanSample<Val> for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: FieldChallenger<Mersenne31>,
    Val: BasedVectorSpace<Mersenne31>,
{
    fn sample(&mut self) -> Val {
        self.base.sample_algebra_element()
    }

    fn sample_array<const N: usize>(&mut self) -> [Val; N] {
        core::array::from_fn(|_| self.sample())
    }

    fn sample_vec(&mut self, n: usize) -> Vec<Val> {
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

impl<BaseChallenger> FieldChallenger<Val> for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: FieldChallenger<Mersenne31> + Clone + Send + Sync,
    Val: BasedVectorSpace<Mersenne31>,
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
    type Witness = Val;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        assert!(bits < (usize::BITS as usize));
        assert!((1 << bits) < Mersenne31::ORDER_U32 as usize);
        let witness = (0..Mersenne31::ORDER_U32)
            .find(|&i| {
                let w = Val::from(Mersenne31::from_int(i));
                self.clone().check_witness(bits, w)
            })
            .map(|i| Val::from(Mersenne31::from_int(i)))
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

type BaseChallenger = Shake256Challenger32<Mersenne31>;
type Challenger = ComplexFieldChallenger<BaseChallenger>;

fn make_config() -> StarkConfig<MyPcs, Val, Challenger> {
    let shake256 = Shake256Hash {};
    let hash = MyHash::new(shake256);
    let compress = MyCompress::new(shake256);
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = create_test_fri_params(challenge_mmcs, 2);
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let challenger = Challenger::new(base_challenger);
    StarkConfig::new(pcs, challenger)
}

#[derive(Clone)]
struct FibAir;

impl BaseAir<Val> for FibAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        3
    }
}

impl<AB: lib_q_stark_air::AirBuilder<F = Val>> Air<AB> for FibAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let is_first = builder.is_first_row();
        let is_last = builder.is_last_row();
        let is_trans = builder.is_transition_window(2);
        let pv0 = builder.public_values()[0].clone();
        let pv1 = builder.public_values()[1].clone();
        let pv2 = builder.public_values()[2].clone();
        let c0 = main.current_slice()[0].clone();
        let c1 = main.current_slice()[1].clone();
        let n0 = main.next_slice()[0].clone();
        let n1 = main.next_slice()[1].clone();
        builder.assert_zero((c0.clone().into() - pv0.into()) * is_first.clone());
        builder.assert_zero((c1.clone().into() - pv1.into()) * is_first);
        builder.assert_zero((c1.clone() - n0) * is_trans.clone());
        builder.assert_zero((c0 + c1 - n1) * is_trans);
        builder.assert_zero((c1.into() - pv2.into()) * is_last);
    }
}

fn generate_fib_trace(a: u64, b: u64, n: usize) -> RowMajorMatrix<Val> {
    let mut values = Vec::with_capacity(n * 2);
    let mut left = Val::from(Mersenne31::from_int(a as u32));
    let mut right = Val::from(Mersenne31::from_int(b as u32));
    values.push(left);
    values.push(right);
    for _ in 1..n {
        let (new_left, new_right) = (right, left + right);
        left = new_left;
        right = new_right;
        values.push(left);
        values.push(right);
    }
    RowMajorMatrix::new(values, 2)
}

#[test]
fn test_uni_stark_round_trip() {
    let config = make_config();
    let n = 1 << 4;
    let trace = generate_fib_trace(0, 1, n);
    let x = 987u64;
    let public_values = vec![
        Val::from(Mersenne31::from_int(0)),
        Val::from(Mersenne31::from_int(1)),
        Val::from(Mersenne31::from_int(x)),
    ];

    let air = FibAir;
    let proof = prove(&config, &air, trace.clone(), &public_values).expect("prove");
    verify(&config, &air, &proof, &public_values).expect("verify");
}

#[test]
fn test_wrong_public_values_rejected() {
    let config = make_config();
    let n = 1 << 4;
    let trace = generate_fib_trace(0, 1, n);
    let correct_public_values = vec![
        Val::from(Mersenne31::from_int(0)),
        Val::from(Mersenne31::from_int(1)),
        Val::from(Mersenne31::from_int(987)),
    ];
    let wrong_public_values = vec![
        Val::from(Mersenne31::from_int(0)),
        Val::from(Mersenne31::from_int(1)),
        Val::from(Mersenne31::from_int(988)),
    ];

    let air = FibAir;
    let proof = prove(&config, &air, trace, &correct_public_values).expect("prove");
    let res = verify(&config, &air, &proof, &wrong_public_values);
    assert!(res.is_err(), "verifier must reject wrong public values");
}

/// AIR with one main column and one preprocessed column (constant row index).
#[derive(Clone)]
struct AirWithPreprocessed;

impl BaseAir<Val> for AirWithPreprocessed {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        0
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        let n = 16;
        let row: Vec<Val> = (0..n)
            .map(|i| Val::from(Mersenne31::from_int((i % 4) as u32)))
            .collect();
        Some(RowMajorMatrix::new(row, 1))
    }
}

impl<AB: lib_q_stark_air::AirBuilder<F = Val>> Air<AB> for AirWithPreprocessed {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let prep = builder.preprocessed();
        let c = main.current_slice()[0].clone();
        let p = prep.current_slice()[0].clone();
        builder.assert_zero(c - p);
    }
}

#[test]
fn test_preprocessed_round_trip() {
    let config = make_config();
    let n = 16;
    let trace_values: Vec<Val> = (0..n)
        .map(|i| Val::from(Mersenne31::from_int((i % 4) as u32)))
        .collect();
    let trace = RowMajorMatrix::new(trace_values, 1);
    let public_values: Vec<Val> = vec![];

    let air = AirWithPreprocessed;
    let degree_bits = 4; // 2^4 = 16 rows
    let (prover_data, vk) =
        setup_preprocessed(&config, &air, degree_bits).expect("AIR has preprocessed columns");
    let proof = prove_with_preprocessed(
        &config,
        &air,
        trace.clone(),
        &public_values,
        Some(&prover_data),
    )
    .expect("prove_with_preprocessed");
    verify_with_preprocessed(&config, &air, &proof, &public_values, Some(&vk)).expect("verify");
}
