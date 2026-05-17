//! Round-trip test: prove_batch then verify_batch with a simple Fibonacci AIR (no lookups).

#![allow(clippy::clone_on_copy)]
#![allow(clippy::cloned_ref_to_slice_refs)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use lib_q_plonky_batch_stark::{
    ProverData,
    StarkInstance,
    prove_batch,
    verify_batch,
};
use lib_q_plonky_uni_stark::{
    StarkConfig,
    prove_with_preprocessed,
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
    PrimeCharacteristicRing,
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
type Challenge = Val;
type MyHash = SerializingHasher<Shake256Hash>;
type MyCompress = CompressionFunctionFromHasher<Shake256Hash, 2, 32>;
type ValMmcs = MerkleTreeMmcs<<Val as Field>::Packing, u8, MyHash, MyCompress, 32>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Dft = Mersenne31ComplexRadix2Dit;
type MyPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

/// Wrapper challenger that implements FieldChallenger<Complex<Mersenne31>>
/// by delegating to a base field challenger.
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
            .find(|&i| {
                let w = Complex::<Mersenne31>::from(Mersenne31::from_int(i));
                self.clone().check_witness(bits, w)
            })
            .map(|i| Complex::<Mersenne31>::from(Mersenne31::from_int(i)))
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
    let mut left = Val::from_u64(a);
    let mut right = Val::from_u64(b);
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
fn batch_prover_round_trip() {
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
    let config = StarkConfig::new(pcs, challenger);

    let n = 1 << 4; // 16 rows
    let trace = generate_fib_trace(0, 1, n);
    let x = 987u64; // fib(16) = last row's right column
    let public_values = vec![Val::from_u64(0), Val::from_u64(1), Val::from_u64(x)];

    let air = FibAir;
    let airs: Vec<FibAir> = vec![FibAir];
    let prover_data = ProverData::empty(1);
    let instance = StarkInstance {
        air: &air,
        trace: &trace,
        public_values: public_values.clone(),
        lookups: Vec::new(),
    };

    let proof = prove_batch(&config, &[instance], &prover_data).expect("prove_batch");
    verify_batch(
        &config,
        &airs,
        &proof,
        &[public_values.clone()],
        &prover_data.common,
    )
    .expect("verify_batch");
}

#[test]
fn batch_prover_wrong_public_values_rejected() {
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
    let config = StarkConfig::new(pcs, challenger);

    let n = 1 << 4;
    let trace = generate_fib_trace(0, 1, n);
    let correct_public_values = vec![Val::from_u64(0), Val::from_u64(1), Val::from_u64(987)];
    let wrong_public_values = vec![Val::from_u64(0), Val::from_u64(1), Val::from_u64(988)];

    let air = FibAir;
    let airs: Vec<FibAir> = vec![FibAir];
    let prover_data = ProverData::empty(1);
    let instance = StarkInstance {
        air: &air,
        trace: &trace,
        public_values: correct_public_values.clone(),
        lookups: Vec::new(),
    };

    let proof = prove_batch(&config, &[instance], &prover_data).expect("prove_batch");
    let res = verify_batch(
        &config,
        &airs,
        &proof,
        &[wrong_public_values],
        &prover_data.common,
    );
    assert!(res.is_err(), "verifier must reject wrong public values");
}

/// Single-instance round-trip via uni-stark to validate AIR and config.
#[test]
fn uni_stark_round_trip() {
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
    let config = StarkConfig::new(pcs, challenger);

    let n = 1 << 4;
    let trace = generate_fib_trace(0, 1, n);
    let x = 987u64; // fib(16)
    let public_values = vec![Val::from_u64(0), Val::from_u64(1), Val::from_u64(x)];

    let air = FibAir;
    let proof =
        prove_with_preprocessed(&config, &air, trace.clone(), &public_values, None).expect("prove");
    verify_with_preprocessed(&config, &air, &proof, &public_values, None).expect("verify");
}
