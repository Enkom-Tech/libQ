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
use rand::rngs::SmallRng;
use rand::{
    Rng,
    SeedableRng,
};

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
type BaseChallenger = Shake256Challenger32<Mersenne31>;
type Challenger = ComplexFieldChallenger<BaseChallenger>;
type MyPcs = TwoAdicFriPcs<Val, Mersenne31ComplexRadix2Dit, ValMmcs, ChallengeMmcs>;

/// Returns a FRI-pcs instance with quantum-safe SHAKE256 hashing.
fn get_ldt_for_testing<R: Rng>(_rng: &mut R, log_final_poly_len: usize) -> MyPcs {
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
    let dft = Mersenne31ComplexRadix2Dit::default();
    MyPcs::new(dft, input_mmcs, fri_params)
}

/// Check that the loop of `pcs.commit`, `pcs.open`, and `pcs.verify` work correctly.
///
/// We create a random polynomial of size `1 << log_size` for each size in `polynomial_log_sizes`.
/// We then commit to these polynomials using a `log_blowup` of `1`.
///
/// We open each polynomial at the same point `zeta` and run FRI to verify the openings, stopping
/// FRI at `log_final_poly_len`.
fn do_test_fri_ldt<R: Rng>(rng: &mut R, log_final_poly_len: usize, polynomial_log_sizes: &[u8]) {
    let pcs = get_ldt_for_testing(rng, log_final_poly_len);

    // Convert the polynomial_log_sizes into field elements so they can be observed.
    let val_sizes: Vec<Val> = polynomial_log_sizes
        .iter()
        .map(|&i| Val::from_u8(i))
        .collect();

    // --- Prover World ---
    let (commitment, opened_values, opening_proof, mut p_challenger) = {
        // Initialize the challenger and observe the `polynomial_log_sizes`.
        let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
        let mut challenger = Challenger::new(base_challenger);
        challenger.observe_slice(&val_sizes);

        // Generate random evaluation matrices for each polynomial degree.
        let evaluations: Vec<(TwoAdicMultiplicativeCoset<Val>, RowMajorMatrix<Val>)> =
            polynomial_log_sizes
                .iter()
                .map(|deg_bits| {
                    let deg = 1 << deg_bits;
                    (
                        // Get the TwoAdicSubgroup of this degree.
                        <MyPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, deg),
                        // Generate a random matrix of evaluations.
                        RowMajorMatrix::<Val>::rand_nonzero(rng, deg, 16),
                    )
                })
                .collect();

        let num_evaluations = evaluations.len();

        // Commit to all the evaluation matrices.
        let (commitment, prover_data) =
            <MyPcs as Pcs<Challenge, Challenger>>::commit(&pcs, evaluations);

        // Observe the commitment.
        challenger.observe(commitment);

        // Sample the challenge point zeta which all polynomials
        // will be opened at.
        let zeta: Challenge = challenger.sample_algebra_element();

        // Prepare the data into the form expected by `pcs.open`.
        let open_data = vec![(&prover_data, vec![vec![zeta]; num_evaluations])]; // open every chunk at zeta

        // Open all polynomials at zeta and produce the opening proof.
        let (opened_values, opening_proof) = pcs.open(open_data, &mut challenger);

        // Return the commitment, opened values, opening proof and challenger.
        // The first three of these are always passed to the verifier. The
        // last is to double check that the prover and verifiers challengers
        // agree at appropriate points.
        (commitment, opened_values, opening_proof, challenger)
    };

    // --- Verifier World ---
    let mut v_challenger = {
        // Initialize the verifier's challenger with SHAKE256.
        // Observe the `polynomial_log_sizes` and `commitment` in the same order
        // as the prover.
        let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
        let mut challenger = Challenger::new(base_challenger);
        challenger.observe_slice(&val_sizes);
        challenger.observe(commitment);

        // Sample the opening point.
        let zeta = challenger.sample_algebra_element();

        // Construct the expected initial polynomial domains.
        // Right now it doesn't matter what these are so long as the size
        // is correct.
        let domains = polynomial_log_sizes.iter().map(|&size| {
            <MyPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, 1 << size)
        });

        // Prepare the data into the form expected by `pcs.verify`.
        // Note that commitment and opened_values are always sent by
        // the prover.
        let commitments_with_opening_points = vec![(
            commitment,
            domains
                .into_iter()
                .zip(opened_values.into_iter().flatten().flatten())
                .map(|(domain, value)| (domain, vec![(zeta, value)]))
                .collect(),
        )];

        // Verify the opening proof.
        let verification = pcs.verify(
            commitments_with_opening_points,
            &opening_proof,
            &mut challenger,
        );
        assert!(verification.is_ok());
        challenger
    };

    // Check that the prover and verifier challengers agree.
    assert_eq!(
        p_challenger.sample_bits(8),
        v_challenger.sample_bits(8),
        "prover and verifier transcript have same state after FRI"
    );
}

/// Test that the FRI commit, open and verify process work correctly
/// for a range of `final_poly_degree` values.
#[test]
fn test_fri_ldt() {
    // Chosen to ensure there are both multiple polynomials
    // of the same size and that the array is not ordered.
    let polynomial_log_sizes = [5, 8, 10, 7, 5, 5, 7];
    for i in 0..5 {
        let mut rng = SmallRng::seed_from_u64(i as u64);
        do_test_fri_ldt(&mut rng, i, &polynomial_log_sizes);
    }
}

/// This test is expected to panic because there is a polynomial degree which
/// the prover commits too which is less than `final_poly_degree`.
#[test]
#[should_panic]
fn test_fri_ldt_should_panic() {
    // Chosen to ensure there are both multiple polynomials
    // of the same size and that the array is not ordered.
    let polynomial_log_sizes = [5, 8, 10, 7, 5, 5, 7];
    let mut rng = SmallRng::seed_from_u64(5);
    do_test_fri_ldt(&mut rng, 5, &polynomial_log_sizes);
}
