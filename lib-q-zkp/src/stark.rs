//! zk-STARK implementation
//!
//! This module provides a high-level interface to lib-Q's zk-STARK implementation.
//!
//! The STARK implementation is based on Plonky3, adapted for lib-Q's requirements:
//! - Uses SHAKE256 (NIST-approved post-quantum hash) instead of non-NIST hashes
//! - Supports Complex<Mersenne31> field for efficient arithmetic (TWO_ADICITY = 32)
//! - Implements the ethSTARK protocol for strong security guarantees

extern crate alloc;
use alloc::vec::Vec;
use core::result::Result;

use lib_q_stark::{
    Domain,
    Proof as StarkProof,
    StarkConfig,
    StarkGenericConfig,
    SymbolicAirBuilder,
    Val,
    VerificationError,
    get_log_num_quotient_chunks,
    prove,
    verify,
};
use lib_q_stark_air::Air;
use lib_q_stark_challenger::{
    CanObserve,
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
use lib_q_stark_field::{
    BasedVectorSpace,
    PrimeCharacteristicRing,
};
use lib_q_stark_fri::{
    FriDataExtractor,
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

// Concrete config type aliases (used as return types for config factory functions).
// Public so that pub type DefaultConfig/ZkConfig/PoseidonConfig satisfy private_interfaces.
pub type ConfigVal = Complex<Mersenne31>;
pub type ConfigDft = Mersenne31ComplexRadix2Dit;
pub type DefaultValMmcs = MerkleTreeMmcs<
    <ConfigVal as lib_q_stark_field::Field>::Packing,
    u8,
    SerializingHasher<Shake256Hash>,
    CompressionFunctionFromHasher<Shake256Hash, 2, 32>,
    32,
>;
pub type DefaultChallengeMmcs = ExtensionMmcs<ConfigVal, ConfigVal, DefaultValMmcs>;
pub type DefaultPcs = TwoAdicFriPcs<ConfigVal, ConfigDft, DefaultValMmcs, DefaultChallengeMmcs>;
pub type DefaultConfig =
    StarkConfig<DefaultPcs, ConfigVal, ComplexFieldChallenger<Shake256Challenger32<Mersenne31>>>;

#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark_merkle::PoseidonMmcs as PoseidonMmcsType;
#[cfg(feature = "recursive-proofs-experimental")]
pub type PoseidonChallengeMmcs = ExtensionMmcs<ConfigVal, ConfigVal, PoseidonMmcsType>;
#[cfg(feature = "recursive-proofs-experimental")]
pub type PoseidonPcs = TwoAdicFriPcs<ConfigVal, ConfigDft, PoseidonMmcsType, PoseidonChallengeMmcs>;
#[cfg(feature = "recursive-proofs-experimental")]
pub type PoseidonConfig =
    StarkConfig<PoseidonPcs, ConfigVal, ComplexFieldChallenger<Shake256Challenger32<Mersenne31>>>;

use lib_q_stark_fri::HidingFriPcs;
use lib_q_stark_merkle::MerkleTreeHidingMmcs;
pub type ZkValMmcs = MerkleTreeHidingMmcs<
    <ConfigVal as lib_q_stark_field::Field>::Packing,
    u8,
    SerializingHasher<Shake256Hash>,
    CompressionFunctionFromHasher<Shake256Hash, 2, 32>,
    lib_q_random::DeterministicRng,
    32,
    4,
>;
pub type ZkChallengeMmcs = ExtensionMmcs<ConfigVal, ConfigVal, ZkValMmcs>;
pub type ZkPcs =
    HidingFriPcs<ConfigVal, ConfigDft, ZkValMmcs, ZkChallengeMmcs, lib_q_random::DeterministicRng>;
pub type ZkConfig =
    StarkConfig<ZkPcs, ConfigVal, ComplexFieldChallenger<Shake256Challenger32<Mersenne31>>>;

/// FRI query parameters used when replaying the verifier (e.g. for recursive aggregation).
#[derive(Clone, Debug)]
pub struct FriQueryParams {
    pub num_queries: usize,
    pub log_blowup: usize,
    pub log_final_poly_len: usize,
    pub proof_of_work_bits: usize,
}

// Generic type aliases for StarkVerifier (require lazy_type_alias).
type PcsCommitment<C>
    = <C::Pcs as Pcs<C::Challenge, C::Challenger>>::Commitment
where
    C: StarkGenericConfig;

type CommitmentRounds<C>
    = Vec<(
    PcsCommitment<C>,
    Vec<(Domain<C>, Vec<(C::Challenge, Vec<C::Challenge>)>)>,
)>
where
    C: StarkGenericConfig;

type QuotientRounds<C>
    = Vec<(Domain<C>, Vec<(C::Challenge, Vec<C::Challenge>)>)>
where
    C: StarkGenericConfig;

/// zk-STARK prover
///
/// This is a high-level wrapper around the STARK proving functionality.
/// It provides a convenient interface for generating STARK proofs with a given configuration.
///
/// # Example
///
/// ```rust,ignore
/// use lib_q_zkp::stark::{StarkProver, default_config};
/// use Complex;
/// use Mersenne31;
///
/// type Val = Complex<Mersenne31>;
///
/// let config = default_config();
/// let prover = StarkProver::new(config);
/// // air: implements Air trait
/// // trace: RowMajorMatrix<Val>
/// // public_values: &[Val]
/// let proof = prover.prove(&air, trace, &public_values);
/// ```
pub struct StarkProver<C: StarkGenericConfig> {
    config: C,
}

impl<C: StarkGenericConfig> StarkProver<C> {
    /// Create a new zk-STARK prover with the given configuration
    pub fn new(config: C) -> Self {
        Self { config }
    }

    /// Generate a STARK proof for the given AIR, trace, and public values
    ///
    /// # Arguments
    ///
    /// * `air` - The Algebraic Intermediate Representation defining the constraints
    /// * `trace` - The witness trace matrix (contains secret data)
    /// * `public_values` - Public values known to both prover and verifier
    ///
    /// # Returns
    ///
    /// A STARK proof that can be verified without revealing the witness trace
    #[cfg(not(debug_assertions))]
    pub fn prove<A>(
        &self,
        air: &A,
        trace: RowMajorMatrix<Val<C>>,
        public_values: &[Val<C>],
    ) -> StarkProof<C>
    where
        A: Air<SymbolicAirBuilder<Val<C>>>
            + for<'a> Air<lib_q_stark::ProverConstraintFolder<'a, C>>,
    {
        prove(&self.config, air, trace, public_values)
    }

    #[cfg(debug_assertions)]
    pub fn prove<A>(
        &self,
        air: &A,
        trace: RowMajorMatrix<Val<C>>,
        public_values: &[Val<C>],
    ) -> StarkProof<C>
    where
        A: Air<SymbolicAirBuilder<Val<C>>>
            + for<'a> Air<lib_q_stark::ProverConstraintFolder<'a, C>>
            + for<'a> Air<lib_q_stark::DebugConstraintBuilder<'a, Val<C>>>,
    {
        prove(&self.config, air, trace, public_values)
    }

    /// Get a reference to the underlying configuration
    pub fn config(&self) -> &C {
        &self.config
    }
}

/// zk-STARK verifier
///
/// This is a high-level wrapper around the STARK verification functionality.
/// It provides a convenient interface for verifying STARK proofs with a given configuration.
///
/// # Example
///
/// ```rust,ignore
/// use lib_q_zkp::stark::{StarkVerifier, default_config};
/// use Complex;
/// use Mersenne31;
///
/// type Val = Complex<Mersenne31>;
///
/// let config = default_config();
/// let verifier = StarkVerifier::new(config);
/// // air: implements Air trait (same as used in proof generation)
/// // proof: StarkProof<Config>
/// // public_values: &[Val]
/// verifier.verify(&air, &proof, &public_values)?;
/// ```
pub struct StarkVerifier<C: StarkGenericConfig> {
    config: C,
}

impl<C: StarkGenericConfig> StarkVerifier<C> {
    /// Create a new zk-STARK verifier with the given configuration
    pub fn new(config: C) -> Self {
        Self { config }
    }

    /// Verify a STARK proof for the given AIR and public values
    ///
    /// # Arguments
    ///
    /// * `air` - The Algebraic Intermediate Representation that was used to generate the proof
    /// * `proof` - The STARK proof to verify
    /// * `public_values` - Public values that were used during proof generation
    ///
    /// # Returns
    ///
    /// `Ok(())` if the proof is valid, `Err(VerificationError)` otherwise
    pub fn verify<A>(
        &self,
        air: &A,
        proof: &StarkProof<C>,
        public_values: &[Val<C>],
    ) -> Result<(), VerificationError<lib_q_stark::PcsError<C>>>
    where
        A: Air<SymbolicAirBuilder<Val<C>>>
            + for<'a> Air<lib_q_stark::VerifierConstraintFolder<'a, C>>,
    {
        verify(&self.config, air, proof, public_values)
    }

    /// Derive Fiat–Shamir challenges by replaying the verifier transcript.
    ///
    /// Returns `(zeta, zeta_next, alpha, betas)` so that callers (e.g. aggregation)
    /// can serialize proofs with real challenges. Only supports proofs without
    /// preprocessed trace (`preprocessed_width == 0`).
    #[allow(clippy::type_complexity)]
    pub fn derive_challenges<A>(
        &self,
        air: &A,
        proof: &StarkProof<C>,
        public_values: &[Val<C>],
    ) -> Result<
        (
            C::Challenge,
            C::Challenge,
            C::Challenge,
            Vec<C::Challenge>,
        ),
        VerificationError<lib_q_stark::PcsError<C>>,
    >
    where
        A: Air<SymbolicAirBuilder<Val<C>>>
            + for<'a> Air<lib_q_stark::VerifierConstraintFolder<'a, C>>,
        <<C as StarkGenericConfig>::Pcs as Pcs<C::Challenge, C::Challenger>>::Proof:
            FriDataExtractor<Challenge = C::Challenge>,
        C::Challenger: CanObserve<Val<C>>
            + CanObserve<<C::Pcs as Pcs<C::Challenge, C::Challenger>>::Commitment>
            + CanObserve<
                <<<C as StarkGenericConfig>::Pcs as Pcs<C::Challenge, C::Challenger>>::Proof as FriDataExtractor>::Commitment,
            >,
    {
        let config = &self.config;
        let pcs = config.pcs();
        let commitments = &proof.commitments;
        let opened_values = &proof.opened_values;
        let opening_proof = &proof.opening_proof;
        let degree_bits = proof.degree_bits;

        let preprocessed_width = air
            .preprocessed_trace()
            .as_ref()
            .map(|m| m.width)
            .unwrap_or(0);
        if preprocessed_width > 0 {
            return Err(VerificationError::InvalidProofShape);
        }

        let degree = 1 << degree_bits;
        if degree == 0 {
            return Err(VerificationError::InvalidProofShape);
        }

        let trace_domain: Domain<C> = pcs.natural_domain_for_degree(degree);
        let init_trace_domain = pcs.natural_domain_for_degree(degree >> config.is_zk());

        let log_num_quotient_chunks = get_log_num_quotient_chunks::<Val<C>, A>(
            air,
            preprocessed_width,
            public_values.len(),
            config.is_zk(),
        );
        let num_quotient_chunks = 1 << (log_num_quotient_chunks + config.is_zk());

        if (opened_values.random.is_some() != C::Pcs::ZK) ||
            (commitments.random.is_some() != C::Pcs::ZK)
        {
            return Err(VerificationError::RandomizationError);
        }

        let air_width = A::width(air);
        let valid_shape = opened_values.trace_local.len() == air_width &&
            opened_values.trace_next.len() == air_width &&
            opened_values.quotient_chunks.len() == num_quotient_chunks &&
            opened_values
                .quotient_chunks
                .iter()
                .all(|qc| qc.len() == C::Challenge::DIMENSION) &&
            opened_values
                .random
                .as_ref()
                .is_none_or(|r| r.len() == C::Challenge::DIMENSION);
        if !valid_shape {
            return Err(VerificationError::InvalidProofShape);
        }

        let quotient_domain =
            trace_domain.create_disjoint_domain(1 << (degree_bits + log_num_quotient_chunks));
        let quotient_chunks_domains = quotient_domain.split_domains(num_quotient_chunks);
        let randomized_quotient_chunks_domains: Vec<Domain<C>> = quotient_chunks_domains
            .iter()
            .map(|d: &Domain<C>| pcs.natural_domain_for_degree(d.size() << config.is_zk()))
            .collect();

        let mut challenger = config.initialise_challenger();

        challenger.observe(Val::<C>::from_usize(degree_bits));
        challenger.observe(Val::<C>::from_usize(degree_bits - config.is_zk()));
        challenger.observe(Val::<C>::from_usize(preprocessed_width));
        challenger.observe(commitments.trace.clone());
        challenger.observe_slice(public_values);

        let alpha = challenger.sample_algebra_element();
        challenger.observe(commitments.quotient_chunks.clone());
        if let Some(ref r_commit) = commitments.random {
            challenger.observe(r_commit.clone());
        }

        let zeta = challenger.sample_algebra_element();
        let zeta_next = init_trace_domain
            .next_point(zeta)
            .ok_or(VerificationError::NextPointUnavailable)?;

        let mut coms_to_verify: CommitmentRounds<C> =
            if let Some(ref random_commit) = commitments.random {
                let random_values = opened_values
                    .random
                    .as_ref()
                    .ok_or(VerificationError::RandomizationError)?;
                alloc::vec![(
                    random_commit.clone(),
                    alloc::vec![(trace_domain, alloc::vec![(zeta, random_values.clone())],)],
                )]
            } else {
                alloc::vec![]
            };

        coms_to_verify.push((
            commitments.trace.clone(),
            alloc::vec![(
                trace_domain,
                alloc::vec![
                    (zeta, opened_values.trace_local.clone()),
                    (zeta_next, opened_values.trace_next.clone()),
                ],
            )],
        ));

        let quotient_rounds: QuotientRounds<C> = randomized_quotient_chunks_domains
            .iter()
            .zip(opened_values.quotient_chunks.iter())
            .map(|(domain, values)| (*domain, alloc::vec![(zeta, values.clone())]))
            .collect();
        coms_to_verify.push((commitments.quotient_chunks.clone(), quotient_rounds));

        for (_, round) in &coms_to_verify {
            for (_, mat) in round {
                for (_, point) in mat {
                    for opening in point {
                        challenger.observe_algebra_element(*opening);
                    }
                }
            }
        }

        let _alpha_fri = challenger.sample_algebra_element::<C::Challenge>();

        let betas: Vec<C::Challenge> = opening_proof
            .commit_phase_commits()
            .iter()
            .map(|comm| {
                challenger.observe(comm.clone());
                challenger.sample_algebra_element()
            })
            .collect();

        Ok((zeta, zeta_next, alpha, betas))
    }

    /// Derive FRI query positions by replaying the Fiat–Shamir challenger through commitments,
    /// FRI betas, final polynomial, and PoW, then sampling `num_queries` indices.
    ///
    /// Returns the same query indices the verifier would use when verifying the proof.
    /// Call with the same FRI params used to produce the proof (e.g. from config).
    pub fn derive_query_positions<A>(
        &self,
        air: &A,
        proof: &StarkProof<C>,
        public_values: &[Val<C>],
        fri_params: &FriQueryParams,
    ) -> Result<Vec<usize>, VerificationError<lib_q_stark::PcsError<C>>>
    where
        A: Air<SymbolicAirBuilder<Val<C>>>
            + for<'a> Air<lib_q_stark::VerifierConstraintFolder<'a, C>>,
        <<C as StarkGenericConfig>::Pcs as Pcs<C::Challenge, C::Challenger>>::Proof:
            FriDataExtractor<Challenge = C::Challenge>,
        C::Challenger: CanObserve<Val<C>>
            + CanObserve<<C::Pcs as Pcs<C::Challenge, C::Challenger>>::Commitment>
            + CanObserve<
                <<<C as StarkGenericConfig>::Pcs as Pcs<C::Challenge, C::Challenger>>::Proof as FriDataExtractor>::Commitment,
            >
            + GrindingChallenger<
                Witness = <<<C as StarkGenericConfig>::Pcs as Pcs<C::Challenge, C::Challenger>>::Proof as FriDataExtractor>::Witness,
            >,
        <<<C as StarkGenericConfig>::Pcs as Pcs<C::Challenge, C::Challenger>>::Proof as FriDataExtractor>::Witness: Clone,
    {
        let config = &self.config;
        let pcs = config.pcs();
        let commitments = &proof.commitments;
        let opened_values = &proof.opened_values;
        let opening_proof = &proof.opening_proof;
        let degree_bits = proof.degree_bits;

        let preprocessed_width = air
            .preprocessed_trace()
            .as_ref()
            .map(|m| m.width)
            .unwrap_or(0);
        if preprocessed_width > 0 {
            return Err(VerificationError::InvalidProofShape);
        }

        let degree = 1 << degree_bits;
        if degree == 0 {
            return Err(VerificationError::InvalidProofShape);
        }

        let log_num_quotient_chunks = get_log_num_quotient_chunks::<Val<C>, A>(
            air,
            preprocessed_width,
            public_values.len(),
            config.is_zk(),
        );
        let num_quotient_chunks = 1 << (log_num_quotient_chunks + config.is_zk());

        if (opened_values.random.is_some() != C::Pcs::ZK) ||
            (commitments.random.is_some() != C::Pcs::ZK)
        {
            return Err(VerificationError::RandomizationError);
        }

        let air_width = A::width(air);
        let valid_shape = opened_values.trace_local.len() == air_width &&
            opened_values.trace_next.len() == air_width &&
            opened_values.quotient_chunks.len() == num_quotient_chunks &&
            opened_values
                .quotient_chunks
                .iter()
                .all(|qc| qc.len() == C::Challenge::DIMENSION) &&
            opened_values
                .random
                .as_ref()
                .is_none_or(|r| r.len() == C::Challenge::DIMENSION);
        if !valid_shape {
            return Err(VerificationError::InvalidProofShape);
        }

        let trace_domain: Domain<C> = pcs.natural_domain_for_degree(degree);
        let init_trace_domain = pcs.natural_domain_for_degree(degree >> config.is_zk());
        let quotient_domain =
            trace_domain.create_disjoint_domain(1 << (degree_bits + log_num_quotient_chunks));
        let quotient_chunks_domains = quotient_domain.split_domains(num_quotient_chunks);
        let randomized_quotient_chunks_domains: Vec<Domain<C>> = quotient_chunks_domains
            .iter()
            .map(|d: &Domain<C>| pcs.natural_domain_for_degree(d.size() << config.is_zk()))
            .collect();

        let mut challenger = config.initialise_challenger();

        challenger.observe(Val::<C>::from_usize(degree_bits));
        challenger.observe(Val::<C>::from_usize(degree_bits - config.is_zk()));
        challenger.observe(Val::<C>::from_usize(preprocessed_width));
        challenger.observe(commitments.trace.clone());
        challenger.observe_slice(public_values);

        let _alpha: Val<C> = challenger.sample_algebra_element();
        challenger.observe(commitments.quotient_chunks.clone());
        if let Some(ref r_commit) = commitments.random {
            challenger.observe(r_commit.clone());
        }

        let zeta = challenger.sample_algebra_element();
        let _zeta_next = init_trace_domain
            .next_point(zeta)
            .ok_or(VerificationError::NextPointUnavailable)?;

        let mut coms_to_verify: CommitmentRounds<C> =
            if let Some(ref random_commit) = commitments.random {
                let random_values = opened_values
                    .random
                    .as_ref()
                    .ok_or(VerificationError::RandomizationError)?;
                alloc::vec![(
                    random_commit.clone(),
                    alloc::vec![(trace_domain, alloc::vec![(zeta, random_values.clone())],)],
                )]
            } else {
                alloc::vec![]
            };

        coms_to_verify.push((
            commitments.trace.clone(),
            alloc::vec![(
                trace_domain,
                alloc::vec![
                    (zeta, opened_values.trace_local.clone()),
                    (
                        init_trace_domain
                            .next_point(zeta)
                            .ok_or(VerificationError::NextPointUnavailable)?,
                        opened_values.trace_next.clone(),
                    ),
                ],
            )],
        ));

        let quotient_rounds: QuotientRounds<C> = randomized_quotient_chunks_domains
            .iter()
            .zip(opened_values.quotient_chunks.iter())
            .map(|(domain, values)| (*domain, alloc::vec![(zeta, values.clone())]))
            .collect();
        coms_to_verify.push((commitments.quotient_chunks.clone(), quotient_rounds));

        for (_, round) in &coms_to_verify {
            for (_, mat) in round {
                for (_, point) in mat {
                    for opening in point {
                        challenger.observe_algebra_element(*opening);
                    }
                }
            }
        }

        let _alpha_fri = challenger.sample_algebra_element::<C::Challenge>();

        for comm in opening_proof.commit_phase_commits() {
            challenger.observe(comm.clone());
            let _beta: C::Challenge = challenger.sample_algebra_element();
        }

        for coeff in opening_proof.final_poly() {
            challenger.observe_algebra_element(*coeff);
        }

        if !challenger.check_witness(
            fri_params.proof_of_work_bits,
            opening_proof.pow_witness().clone(),
        ) {
            return Err(VerificationError::InvalidProofShape);
        }

        let log_global_max_height = opening_proof.commit_phase_commits().len() +
            fri_params.log_blowup +
            fri_params.log_final_poly_len;
        const EXTRA_QUERY_INDEX_BITS: usize = 0;

        let mut positions = Vec::with_capacity(fri_params.num_queries);
        for _ in 0..fri_params.num_queries {
            let index = challenger.sample_bits(log_global_max_height + EXTRA_QUERY_INDEX_BITS);
            positions.push(index);
        }

        Ok(positions)
    }

    /// Get a reference to the underlying configuration
    pub fn config(&self) -> &C {
        &self.config
    }
}

/// Wrapper challenger that implements FieldChallenger<Complex<Mersenne31>>
/// by delegating to a base field challenger and using algebra element methods
#[derive(Clone)]
pub struct ComplexFieldChallenger<BaseChallenger> {
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
        Complex<Mersenne31>: Clone + Copy,
    {
        for value in values {
            self.observe(*value);
        }
    }
}

impl<BaseChallenger> lib_q_stark_challenger::CanSample<Complex<Mersenne31>>
    for ComplexFieldChallenger<BaseChallenger>
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

// Forward CanObserve for Hash commitment types by observing through base challenger
impl<BaseChallenger, F, const DIGEST_ELEMS: usize>
    CanObserve<lib_q_stark_symmetric::Hash<F, u8, DIGEST_ELEMS>>
    for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: CanObserve<lib_q_stark_symmetric::Hash<Mersenne31, u8, DIGEST_ELEMS>>,
{
    fn observe(&mut self, value: lib_q_stark_symmetric::Hash<F, u8, DIGEST_ELEMS>) {
        let array: [u8; DIGEST_ELEMS] = value.into();
        let mersenne_hash =
            lib_q_stark_symmetric::Hash::<Mersenne31, u8, DIGEST_ELEMS>::from(array);
        self.base.observe(mersenne_hash);
    }

    fn observe_slice(&mut self, values: &[lib_q_stark_symmetric::Hash<F, u8, DIGEST_ELEMS>])
    where
        lib_q_stark_symmetric::Hash<F, u8, DIGEST_ELEMS>: Clone,
    {
        for value in values {
            self.observe(value.clone());
        }
    }
}

// Poseidon digest: Hash<Complex, Complex, 1> — observe the single field element
#[cfg(feature = "recursive-proofs-experimental")]
impl<BaseChallenger>
    CanObserve<lib_q_stark_symmetric::Hash<Complex<Mersenne31>, Complex<Mersenne31>, 1>>
    for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: FieldChallenger<Mersenne31>,
{
    fn observe(
        &mut self,
        value: lib_q_stark_symmetric::Hash<Complex<Mersenne31>, Complex<Mersenne31>, 1>,
    ) {
        let arr: [Complex<Mersenne31>; 1] = value.into();
        self.observe(arr[0]);
    }

    fn observe_slice(
        &mut self,
        values: &[lib_q_stark_symmetric::Hash<Complex<Mersenne31>, Complex<Mersenne31>, 1>],
    ) where
        lib_q_stark_symmetric::Hash<Complex<Mersenne31>, Complex<Mersenne31>, 1>: Clone,
    {
        for value in values {
            self.observe(value.clone());
        }
    }
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
        use Mersenne31;
        use lib_q_stark_field::integers::QuotientMap;

        const P: u32 = (1 << 31) - 1; // Mersenne31 prime
        assert!(bits < (usize::BITS as usize));
        assert!((1 << bits) < P as usize);

        #[cfg(feature = "parallel")]
        let witness = {
            use lib_q_stark_rayon::prelude::*;
            (0..P)
                .into_par_iter()
                .map(|i| {
                    let base = Mersenne31::from_int(i);
                    Complex::<Mersenne31>::from(base)
                })
                .find_any(|witness| self.clone().check_witness(bits, *witness))
                .expect("failed to find witness")
        };

        #[cfg(not(feature = "parallel"))]
        let witness = (0..P)
            .map(|i| {
                let base = Mersenne31::from_int(i);
                Complex::<Mersenne31>::from(base)
            })
            .find(|witness| self.clone().check_witness(bits, *witness))
            .expect("failed to find witness");

        assert!(self.check_witness(bits, witness));
        witness
    }

    fn check_witness(&mut self, bits: usize, witness: Self::Witness) -> bool {
        use lib_q_stark_challenger::{
            CanObserve,
            CanSampleBits,
        };
        self.observe(witness);
        self.sample_bits(bits) == 0
    }
}

/// Creates a production-ready default STARK configuration
///
/// This configuration uses:
/// - **SHAKE256** for all hash operations (NIST-approved, post-quantum secure)
/// - **Complex<Mersenne31>** field (TWO_ADICITY = 32) for efficient arithmetic
/// - Production FRI parameters (100 queries, 16 proof-of-work bits)
///
/// # Example
///
/// ```rust,ignore
/// use lib_q_zkp::stark::{default_config, StarkProver, StarkVerifier};
///
/// let config = default_config();
/// let prover = StarkProver::new(config.clone());
/// let verifier = StarkVerifier::new(config);
/// ```
pub fn default_config() -> DefaultConfig {
    use lib_q_stark_fri::FriParameters;

    type ValMmcs = DefaultValMmcs;
    type ChallengeMmcs = DefaultChallengeMmcs;
    type Dft = ConfigDft;
    type Pcs = DefaultPcs;
    type MyHash = SerializingHasher<Shake256Hash>;
    type MyCompress = CompressionFunctionFromHasher<Shake256Hash, 2, 32>;
    type BaseChallenger = Shake256Challenger32<Mersenne31>;
    type Challenger = ComplexFieldChallenger<BaseChallenger>;

    let shake256 = Shake256Hash {};
    let hash = MyHash::new(shake256);
    let compress = MyCompress::new(shake256);
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters {
        log_blowup: 2,
        log_final_poly_len: 0,
        num_queries: 100,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let challenger = Challenger::new(base_challenger);

    StarkConfig::new(pcs, challenger)
}

/// STARK config that uses Poseidon-based Merkle trees (PoseidonMmcs).
/// Use this as the outer config when producing recursive proofs so that Merkle paths
/// are compatible with MerkleInclusionAir (Poseidon constraints in-circuit).
#[cfg(feature = "recursive-proofs-experimental")]
pub fn poseidon_config() -> PoseidonConfig {
    use lib_q_stark_fri::FriParameters;
    use lib_q_stark_merkle::{
        PoseidonMmcs,
        poseidon_mmcs_instance,
    };

    type ValMmcs = PoseidonMmcs;
    type ChallengeMmcs = PoseidonChallengeMmcs;
    type Dft = ConfigDft;
    type Pcs = PoseidonPcs;
    type BaseChallenger = Shake256Challenger32<Mersenne31>;
    type Challenger = ComplexFieldChallenger<BaseChallenger>;

    let (hash, compress) = poseidon_mmcs_instance();
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters {
        log_blowup: 2,
        log_final_poly_len: 0,
        num_queries: 100,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let challenger = Challenger::new(base_challenger);

    StarkConfig::new(pcs, challenger)
}

/// Default FRI parameters used by `default_config()` (for security parameter tests).
/// Returns (log_blowup, num_queries, proof_of_work_bits).
#[doc(hidden)]
pub const fn default_fri_params_for_tests() -> (usize, usize, usize) {
    (2, 100, 16)
}

/// ZK config for tests: uses HidingFriPcs so proofs are randomized (statistical ZK).
/// Not for production; uses test FRI params (few queries, low PoW).
pub fn zk_config() -> ZkConfig {
    zk_config_with_seeds(0, 1)
}

/// Same as `zk_config()` but with explicit RNG seeds (for tests that need distinct proofs).
#[doc(hidden)]
pub fn zk_config_with_seeds(val_mmcs_seed: u64, pcs_seed: u64) -> ZkConfig {
    use lib_q_stark_fri::create_test_fri_params_zk;

    type ValMmcs = ZkValMmcs;
    type ChallengeMmcs = ZkChallengeMmcs;
    type Dft = ConfigDft;
    type Pcs = ZkPcs;
    type MyHash = SerializingHasher<Shake256Hash>;
    type MyCompress = CompressionFunctionFromHasher<Shake256Hash, 2, 32>;
    type BaseChallenger = Shake256Challenger32<Mersenne31>;
    type Challenger = ComplexFieldChallenger<BaseChallenger>;

    let shake256 = Shake256Hash {};
    let hash = MyHash::new(shake256);
    let compress = MyCompress::new(shake256);
    let val_mmcs = ValMmcs::new(
        hash,
        compress,
        lib_q_random::DeterministicRng::seed_from_u64(val_mmcs_seed),
    );
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = create_test_fri_params_zk(challenge_mmcs);
    let pcs = Pcs::new(
        dft,
        val_mmcs,
        fri_params,
        4,
        lib_q_random::DeterministicRng::seed_from_u64(pcs_seed),
    );
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let challenger = Challenger::new(base_challenger);

    StarkConfig::new(pcs, challenger)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stark_prover_creation() {
        let config = default_config();
        let _prover = StarkProver::new(config);
        // Just verify that creation doesn't panic
    }

    #[test]
    fn test_stark_verifier_creation() {
        let config = default_config();
        let _verifier = StarkVerifier::new(config);
        // Just verify that creation doesn't panic
    }

    #[test]
    fn test_default_config() {
        let _config = default_config();
        // Just verify that config creation doesn't panic
    }
}
