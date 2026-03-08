use itertools::{
    Itertools,
    izip,
};
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
    PolynomialSpace,
};
use lib_q_stark_field::extension::Complex;
use lib_q_stark_field::integers::QuotientMap;
use lib_q_stark_field::{
    BasedVectorSpace,
    ExtensionField,
    Field,
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
use rand::distr::{
    Distribution,
    StandardUniform,
};
use rand::{
    Rng,
    RngExt,
};

fn seeded_rng() -> impl Rng {
    DeterministicRng::seed_from_u64(0)
}

/// Wrapper challenger that implements FieldChallenger<Complex<Mersenne31>>
#[derive(Clone)]
pub struct ComplexFieldChallenger<BaseChallenger> {
    base: BaseChallenger,
}

impl<BaseChallenger> ComplexFieldChallenger<BaseChallenger> {
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

fn do_test_fri_pcs<Val, Challenge, Challenger, P>(
    (pcs, challenger): &(P, Challenger),
    log_degrees_by_round: &[&[usize]],
) where
    P: Pcs<Challenge, Challenger>,
    P::Domain: PolynomialSpace<Val = Val>,
    Val: Field,
    StandardUniform: Distribution<Val>,
    Challenge: ExtensionField<Val>,
    Challenger: Clone + CanObserve<P::Commitment> + FieldChallenger<Val>,
{
    let num_rounds = log_degrees_by_round.len();
    let mut rng = seeded_rng();

    let mut p_challenger = challenger.clone();

    let domains_and_polys_by_round = log_degrees_by_round
        .iter()
        .map(|log_degrees| {
            log_degrees
                .iter()
                .map(|&log_degree| {
                    let d = 1 << log_degree;
                    // random width 5-15
                    let width = 5 + rng.random_range(0..=10);
                    (
                        pcs.natural_domain_for_degree(d),
                        RowMajorMatrix::<Val>::rand(&mut rng, d, width),
                    )
                })
                .collect_vec()
        })
        .collect_vec();

    let (commits_by_round, data_by_round): (Vec<_>, Vec<_>) = domains_and_polys_by_round
        .iter()
        .map(|domains_and_polys| pcs.commit(domains_and_polys.iter().cloned()))
        .unzip();
    assert_eq!(commits_by_round.len(), num_rounds);
    assert_eq!(data_by_round.len(), num_rounds);
    p_challenger.observe_slice(&commits_by_round);

    let zeta: Challenge = p_challenger.sample_algebra_element();

    let points_by_round = log_degrees_by_round
        .iter()
        .map(|log_degrees| vec![vec![zeta]; log_degrees.len()])
        .collect_vec();
    let data_and_points = data_by_round.iter().zip(points_by_round).collect();
    let (opening_by_round, proof) = pcs.open(data_and_points, &mut p_challenger);
    assert_eq!(opening_by_round.len(), num_rounds);

    // Verify the proof.
    let mut v_challenger = challenger.clone();
    v_challenger.observe_slice(&commits_by_round);
    let verifier_zeta: Challenge = v_challenger.sample_algebra_element();
    assert_eq!(verifier_zeta, zeta);

    let commits_and_claims_by_round = izip!(
        commits_by_round,
        domains_and_polys_by_round,
        opening_by_round
    )
    .map(|(commit, domains_and_polys, openings)| {
        let claims = domains_and_polys
            .iter()
            .zip(openings)
            .map(|((domain, _), mat_openings)| (*domain, vec![(zeta, mat_openings[0].clone())]))
            .collect_vec();
        (commit, claims)
    })
    .collect_vec();
    assert_eq!(commits_and_claims_by_round.len(), num_rounds);

    pcs.verify(commits_and_claims_by_round, &proof, &mut v_challenger)
        .unwrap();
}

// Set it up so we create tests inside a module for each pcs, so we get nice error reports
// specific to a failing PCS.
macro_rules! make_tests_for_pcs {
    ($p:expr) => {
        #[test]
        fn single() {
            let p = $p;
            for i in 3..6 {
                $crate::do_test_fri_pcs(&p, &[&[i]]);
            }
        }

        #[test]
        fn many_equal() {
            let p = $p;
            for i in 2..6 {
                $crate::do_test_fri_pcs(&p, &[&[i; 5]]);
                println!("{i} ok");
            }
        }

        #[test]
        fn many_different() {
            let p = $p;
            for i in 2..5 {
                let degrees = (3..3 + i).collect::<Vec<_>>();
                $crate::do_test_fri_pcs(&p, &[&degrees]);
            }
        }

        #[test]
        fn many_different_rev() {
            let p = $p;
            for i in 2..5 {
                let degrees = (3..3 + i).rev().collect::<Vec<_>>();
                $crate::do_test_fri_pcs(&p, &[&degrees]);
            }
        }

        #[test]
        fn multiple_rounds() {
            let p = $p;
            $crate::do_test_fri_pcs(&p, &[&[3]]);
            $crate::do_test_fri_pcs(&p, &[&[3], &[3]]);
            $crate::do_test_fri_pcs(&p, &[&[3], &[2]]);
            $crate::do_test_fri_pcs(&p, &[&[2], &[3]]);
            $crate::do_test_fri_pcs(&p, &[&[3, 4], &[3, 4]]);
            $crate::do_test_fri_pcs(&p, &[&[4, 2], &[4, 2]]);
            $crate::do_test_fri_pcs(&p, &[&[2, 2], &[3, 3]]);
            $crate::do_test_fri_pcs(&p, &[&[3, 3], &[2, 2]]);
            $crate::do_test_fri_pcs(&p, &[&[2], &[3, 3]]);
        }
    };
}

mod mersenne31_fri_pcs {
    use super::*;

    // Use Complex<Mersenne31> as base field (TWO_ADICITY = 32) for sufficient two-adicity
    type Val = Complex<Mersenne31>;
    // Use Complex<Mersenne31> directly as challenge field
    type Challenge = Val;

    // Quantum-safe SHAKE256-based Merkle tree setup
    type MyHash = SerializingHasher<Shake256Hash>;
    type MyCompress = CompressionFunctionFromHasher<Shake256Hash, 2, 32>;
    // Use u8 as width type for byte-based hashing (quantum-safe)
    type ValMmcs = MerkleTreeMmcs<<Val as Field>::Packing, u8, MyHash, MyCompress, 32>;
    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

    type Dft = Mersenne31ComplexRadix2Dit;
    type BaseChallenger = Shake256Challenger32<Mersenne31>;
    type Challenger = ComplexFieldChallenger<BaseChallenger>;
    type MyPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

    fn get_pcs(log_blowup: usize) -> (MyPcs, Challenger) {
        let shake256 = Shake256Hash {};
        let hash = MyHash::new(shake256);
        let compress = MyCompress::new(shake256);

        let val_mmcs = ValMmcs::new(hash, compress);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

        let fri_params = FriParameters {
            log_blowup,
            log_final_poly_len: 0,
            num_queries: 10,
            proof_of_work_bits: 8,
            mmcs: challenge_mmcs,
        };

        let pcs = MyPcs::new(Dft::default(), val_mmcs, fri_params);
        let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
        let challenger = Challenger::new(base_challenger);
        (pcs, challenger)
    }

    mod blowup_1 {
        make_tests_for_pcs!(super::get_pcs(1));
    }
    mod blowup_2 {
        make_tests_for_pcs!(super::get_pcs(2));
    }
}

// mod m31_fri_pcs {
//     use core::marker::PhantomData;
//
//     use lib_q_stark_challenger::{
//         HashChallenger,
//         SerializingChallenger32,
//     };
//     use lib_q_stark_mersenne31::{
//         Mersenne31,
//         TestPermutation,
//     };
//     // p3_circle::CirclePcs removed: non-NIST hash
//     use lib_q_stark_shake256::Shake256Hash;
//     use lib_q_stark_symmetric::{
//         CompressionFunctionFromHasher,
//         SerializingHasher,
//     };
//
//     use super::*;
//
//     type Val = Mersenne31;
//     type Challenge = BinomialExtensionField<Mersenne31, 3>;
//
//     type ByteHash = Shake256Hash;
//     type FieldHash = SerializingHasher<ByteHash>;
//
//     type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
//
//     type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
//
//     type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
//
//     type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
//
//     // CirclePcs not available - Circle STARKs not integrated
//     // type Pcs = CirclePcs<Val, ValMmcs, ChallengeMmcs>;
//
//     // fn get_pcs(log_blowup: usize) -> (Pcs, Challenger) {
//     //     let byte_hash = ByteHash {};
//     //     let field_hash = FieldHash::new(byte_hash);
//     //     let compress = MyCompress::new(byte_hash);
//     //     let val_mmcs = ValMmcs::new(field_hash, compress);
//     //     let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
//     //     let fri_params = FriParameters {
//     //         log_blowup,
//     //         log_final_poly_len: 0,
//     //         num_queries: 10,
//     //         proof_of_work_bits: 8,
//     //         mmcs: challenge_mmcs,
//     //     };
//     //     let pcs = Pcs {
//     //         mmcs: val_mmcs,
//     //         fri_params,
//     //         _phantom: PhantomData,
//     //     };
//     //     (pcs, Challenger::from_hasher(vec![], byte_hash))
//     // }
//
//     // mod blowup_1 {
//     //     make_tests_for_pcs!(super::get_pcs(1));
//     // }
//     // mod blowup_2 {
//     //     make_tests_for_pcs!(super::get_pcs(2));
//     // }
// }
