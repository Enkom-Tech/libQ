//! FRI soundness tests: verifier rejects invalid or tampered proofs.

use std::vec::Vec;

use lib_q_random::DeterministicRng;
use lib_q_stark_challenger::{
    CanObserve,
    CanSample,
    CanSampleBits,
    FieldChallenger,
    GrindingChallenger,
    Shake256Challenger32,
};
use lib_q_stark_commit::{
    ExtensionMmcs,
    Pcs,
};
use lib_q_stark_field::coset::TwoAdicMultiplicativeCoset;
use lib_q_stark_field::extension::Complex;
use lib_q_stark_field::integers::QuotientMap;
use lib_q_stark_field::{
    BasedVectorSpace,
    Field,
    PrimeCharacteristicRing,
    PrimeField32,
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
use lib_q_stark_rayon::prelude::*;
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
type BaseChallenger = Shake256Challenger32<Mersenne31>;
type MyPcs = TwoAdicFriPcs<Val, Mersenne31ComplexRadix2Dit, ValMmcs, ChallengeMmcs>;

#[derive(Clone)]
struct ComplexFieldChallenger<B>(B);

impl<B> ComplexFieldChallenger<B> {
    fn new(base: B) -> Self {
        Self(base)
    }
}

impl<B> CanObserve<Val> for ComplexFieldChallenger<B>
where
    B: FieldChallenger<Mersenne31>,
{
    fn observe(&mut self, value: Val) {
        self.0.observe_algebra_element(value);
    }
    fn observe_slice(&mut self, values: &[Val]) {
        for v in values {
            self.observe(*v);
        }
    }
}

impl<B> CanSample<Val> for ComplexFieldChallenger<B>
where
    B: FieldChallenger<Mersenne31>,
    Val: BasedVectorSpace<Mersenne31>,
{
    fn sample(&mut self) -> Val {
        self.0.sample_algebra_element()
    }
    fn sample_array<const N: usize>(&mut self) -> [Val; N] {
        core::array::from_fn(|_| self.sample())
    }
    fn sample_vec(&mut self, n: usize) -> Vec<Val> {
        (0..n).map(|_| self.sample()).collect()
    }
}

impl<B> CanSampleBits<usize> for ComplexFieldChallenger<B>
where
    B: FieldChallenger<Mersenne31>,
{
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.0.sample_bits(bits)
    }
}

impl<B> FieldChallenger<Val> for ComplexFieldChallenger<B>
where
    B: FieldChallenger<Mersenne31> + Clone + Send + Sync,
    Val: BasedVectorSpace<Mersenne31>,
{
}

impl<B> GrindingChallenger for ComplexFieldChallenger<B>
where
    B: GrindingChallenger<Witness = Mersenne31> + FieldChallenger<Mersenne31> + Clone + Send + Sync,
{
    type Witness = Val;
    fn grind(&mut self, bits: usize) -> Self::Witness {
        let witness = (0..Mersenne31::ORDER_U32)
            .into_par_iter()
            .map(|i| Val::from(Mersenne31::from_int(i)))
            .find_any(|w| self.clone().check_witness(bits, *w))
            .expect("grind");
        assert!(self.check_witness(bits, witness));
        witness
    }
    fn check_witness(&mut self, bits: usize, witness: Self::Witness) -> bool {
        self.observe(witness);
        self.0.sample_bits(bits) == 0
    }
}

impl<B, F, const N: usize> CanObserve<Hash<F, u8, N>> for ComplexFieldChallenger<B>
where
    B: CanObserve<Hash<Mersenne31, u8, N>>,
    Hash<F, u8, N>: Clone,
{
    fn observe(&mut self, value: Hash<F, u8, N>) {
        let a: [u8; N] = value.into();
        self.0.observe(Hash::from(a));
    }
    fn observe_slice(&mut self, values: &[Hash<F, u8, N>]) {
        for v in values {
            self.observe(v.clone());
        }
    }
}

type Challenger = ComplexFieldChallenger<BaseChallenger>;

fn get_ldt_for_testing(_rng: &mut DeterministicRng, log_final_poly_len: usize) -> MyPcs {
    let shake256 = Shake256Hash {};
    let hash = MyHash::new(shake256);
    let compress = MyCompress::new(shake256);
    let input_mmcs = ValMmcs::new(hash, compress.clone());
    let fri_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress));
    let fri_params = FriParameters {
        log_blowup: 1,
        log_final_poly_len,
        num_queries: 10,
        proof_of_work_bits: 8,
        mmcs: fri_mmcs,
    };
    MyPcs::new(
        Mersenne31ComplexRadix2Dit::default(),
        input_mmcs,
        fri_params,
    )
}

/// One commit/open cycle for a single polynomial. Returns (pcs, commitment, opened_values, opening_proof, zeta, val_sizes).
fn do_test_and_capture(
    rng: &mut DeterministicRng,
    log_size: u8,
    log_final_poly_len: usize,
) -> (
    MyPcs,
    <MyPcs as Pcs<Challenge, Challenger>>::Commitment,
    lib_q_stark_commit::OpenedValues<Challenge>,
    <MyPcs as Pcs<Challenge, Challenger>>::Proof,
    Challenge,
    Vec<Val>,
) {
    let pcs: MyPcs = get_ldt_for_testing(rng, log_final_poly_len);
    let val_sizes = vec![Val::from_u8(log_size)];
    let deg = 1 << log_size;

    let (commitment, opened_values, opening_proof, zeta) = {
        let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
        let mut challenger: Challenger = Challenger::new(base_challenger);
        challenger.observe_slice(&val_sizes);

        let domain = <MyPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, deg);
        let evaluations = RowMajorMatrix::<Val>::rand_nonzero(rng, deg, 16);
        let (commitment, prover_data) =
            <MyPcs as Pcs<Challenge, Challenger>>::commit(&pcs, vec![(domain, evaluations)]);

        challenger.observe(commitment.clone());
        let zeta: Challenge = challenger.sample_algebra_element();

        let open_data = vec![(&prover_data, vec![vec![zeta]])];
        let (opened_values, opening_proof) = pcs.open(open_data, &mut challenger);
        (commitment, opened_values, opening_proof, zeta)
    };

    (
        pcs,
        commitment,
        opened_values,
        opening_proof,
        zeta,
        val_sizes,
    )
}

fn build_verify_input(
    pcs: &MyPcs,
    commitment: &<MyPcs as Pcs<Challenge, Challenger>>::Commitment,
    opened_values: &lib_q_stark_commit::OpenedValues<Challenge>,
    zeta: Challenge,
    log_size: u8,
) -> Vec<(
    <MyPcs as Pcs<Challenge, Challenger>>::Commitment,
    Vec<(
        TwoAdicMultiplicativeCoset<Val>,
        Vec<(Challenge, Vec<Challenge>)>,
    )>,
)> {
    let deg = 1 << log_size;
    let domain = <MyPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(pcs, deg);
    let flat: Vec<Vec<Challenge>> = opened_values
        .iter()
        .flat_map(|r| r.iter().flat_map(|m| m.iter().cloned()))
        .collect();
    let points = flat
        .into_iter()
        .map(|values| (zeta, values))
        .collect::<Vec<_>>();
    vec![(commitment.clone(), vec![(domain, points)])]
}

#[test]
fn test_fri_rejects_wrong_opened_value() {
    let mut rng = DeterministicRng::seed_from_u64(0);
    let (pcs, commitment, opened_values, opening_proof, zeta, val_sizes) =
        do_test_and_capture(&mut rng, 6, 3);

    let mut wrong_opened = opened_values.clone();
    if let Some(round) = wrong_opened.get_mut(0) {
        if let Some(mat) = round.get_mut(0) {
            if let Some(pt) = mat.get_mut(0) {
                if let Some(v) = pt.get_mut(0) {
                    *v = *v + Challenge::ONE;
                }
            }
        }
    }
    let commitments_with_wrong = build_verify_input(&pcs, &commitment, &wrong_opened, zeta, 6);

    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let mut v_chal = Challenger::new(base_challenger);
    v_chal.observe_slice(&val_sizes);
    v_chal.observe(commitment.clone());
    let result = pcs.verify(commitments_with_wrong, &opening_proof, &mut v_chal);
    assert!(result.is_err());
}

#[test]
fn test_fri_rejects_wrong_final_polynomial() {
    let mut rng = DeterministicRng::seed_from_u64(1);
    let (pcs, commitment, opened_values, mut opening_proof, zeta, val_sizes) =
        do_test_and_capture(&mut rng, 6, 3);

    opening_proof.final_poly = vec![Challenge::ONE];

    let commitments = build_verify_input(&pcs, &commitment, &opened_values, zeta, 6);
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let mut v_chal = Challenger::new(base_challenger);
    v_chal.observe_slice(&val_sizes);
    v_chal.observe(commitment.clone());
    let result = pcs.verify(commitments, &opening_proof, &mut v_chal);
    assert!(result.is_err());
}

#[test]
fn test_fri_rejects_tampered_merkle_leaf() {
    let mut rng = DeterministicRng::seed_from_u64(2);
    let (pcs, commitment, opened_values, mut opening_proof, zeta, val_sizes) =
        do_test_and_capture(&mut rng, 6, 3);

    if let Some(qp) = opening_proof.query_proofs.get_mut(0) {
        if let Some(batch) = qp.input_proof.get_mut(0) {
            if let Some(sibling) = batch.opening_proof.get_mut(0) {
                sibling[0] = sibling[0].wrapping_add(1);
            }
        }
    }

    let commitments = build_verify_input(&pcs, &commitment, &opened_values, zeta, 6);
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let mut v_chal = Challenger::new(base_challenger);
    v_chal.observe_slice(&val_sizes);
    v_chal.observe(commitment.clone());
    let result = pcs.verify(commitments, &opening_proof, &mut v_chal);
    assert!(result.is_err());
}

#[test]
fn test_fri_rejects_tampered_merkle_sibling() {
    let mut rng = DeterministicRng::seed_from_u64(4);
    let (pcs, commitment, opened_values, mut opening_proof, zeta, val_sizes) =
        do_test_and_capture(&mut rng, 6, 3);

    if let Some(qp) = opening_proof.query_proofs.get_mut(0) {
        if let Some(batch) = qp.input_proof.get_mut(0) {
            if batch.opening_proof.len() > 1 {
                let sibling = &mut batch.opening_proof[1];
                sibling[0] = sibling[0].wrapping_add(1);
            } else {
                let sibling = batch.opening_proof.get_mut(0).unwrap();
                sibling[1] = sibling[1].wrapping_add(1);
            }
        }
    }

    let commitments = build_verify_input(&pcs, &commitment, &opened_values, zeta, 6);
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let mut v_chal = Challenger::new(base_challenger);
    v_chal.observe_slice(&val_sizes);
    v_chal.observe(commitment.clone());
    let result = pcs.verify(commitments, &opening_proof, &mut v_chal);
    assert!(result.is_err());
}

/// Commit to polynomial of size 1<<10; verify with claimed domain 1<<5. Verifier must reject.
#[test]
fn test_fri_rejects_high_degree_poly_claiming_low_degree() {
    let mut rng = DeterministicRng::seed_from_u64(5);
    let pcs: MyPcs = get_ldt_for_testing(&mut rng, 3);
    let log_actual = 10u8;
    let log_claimed = 5u8;
    let deg_actual = 1 << log_actual;
    let val_sizes_actual = vec![Val::from_u8(log_actual)];

    let (commitment, opened_values, opening_proof, zeta) = {
        let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
        let mut challenger = Challenger::new(base_challenger);
        challenger.observe_slice(&val_sizes_actual);

        let domain =
            <MyPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, deg_actual);
        let evaluations = RowMajorMatrix::<Val>::rand_nonzero(&mut rng, deg_actual, 16);
        let (commitment, prover_data) =
            <MyPcs as Pcs<Challenge, Challenger>>::commit(&pcs, vec![(domain, evaluations)]);

        challenger.observe(commitment.clone());
        let zeta: Challenge = challenger.sample_algebra_element();

        let open_data = vec![(&prover_data, vec![vec![zeta]])];
        let (opened_values, opening_proof) = pcs.open(open_data, &mut challenger);
        (commitment, opened_values, opening_proof, zeta)
    };

    let deg_claimed = 1 << log_claimed;
    let domain_claimed =
        <MyPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, deg_claimed);
    let val_sizes_claimed = vec![Val::from_u8(log_claimed)];
    let flat: Vec<Vec<Challenge>> = opened_values
        .iter()
        .flat_map(|r| r.iter().flat_map(|m| m.iter().cloned()))
        .collect();
    let points = flat
        .into_iter()
        .map(|values| (zeta, values))
        .collect::<Vec<_>>();
    let wrong_commitments = vec![(commitment, vec![(domain_claimed, points)])];

    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let mut v_chal = Challenger::new(base_challenger);
    v_chal.observe_slice(&val_sizes_claimed);
    v_chal.observe(commitment.clone());
    let result = pcs.verify(wrong_commitments, &opening_proof, &mut v_chal);
    assert!(result.is_err());
}

/// Full commit/open/verify cycle and transcript synchrony.
/// Same 8-bit sync check as fri.rs: after verify, both challengers must agree on sample_bits(8).
#[test]
fn test_fri_transcript_synchrony_32bits() {
    let mut rng = DeterministicRng::seed_from_u64(3);
    let (pcs, commitment, opened_values, opening_proof, zeta, val_sizes) =
        do_test_and_capture(&mut rng, 6, 3);

    let commitments = build_verify_input(&pcs, &commitment, &opened_values, zeta, 6);
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let mut v_chal = Challenger::new(base_challenger);
    v_chal.observe_slice(&val_sizes);
    v_chal.observe(commitment.clone());
    let _: Challenge = v_chal.sample_algebra_element();
    let res = pcs.verify(commitments.clone(), &opening_proof, &mut v_chal);
    assert!(
        res.is_ok(),
        "full commit/open/verify cycle must succeed: {:?}",
        res.err()
    );
    let bits_after = v_chal.sample_bits(8);
    let mut v_chal2 = Challenger::new(BaseChallenger::from_hasher(Vec::new(), Shake256Hash));
    v_chal2.observe_slice(&val_sizes);
    v_chal2.observe(commitment.clone());
    let _: Challenge = v_chal2.sample_algebra_element();
    let _ = pcs.verify(commitments, &opening_proof, &mut v_chal2);
    assert_eq!(
        bits_after,
        v_chal2.sample_bits(8),
        "prover and verifier transcript match"
    );
}
