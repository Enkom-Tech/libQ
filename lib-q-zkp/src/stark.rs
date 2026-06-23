//! zk-STARK implementation
//!
//! This module provides a high-level interface to lib-Q's zk-STARK implementation.
//!
//! The STARK implementation is based on Plonky3, adapted for lib-Q's requirements:
//! - Uses SHAKE256 (NIST-approved post-quantum hash) instead of non-NIST hashes
//! - Supports `Complex<Mersenne31>` field for efficient arithmetic (TWO_ADICITY = 32)
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
    ComplexFieldChallenger,
    FieldChallenger,
    GrindingChallenger,
    Shake256Challenger32,
};
use lib_q_stark_commit::{
    ExtensionMmcs,
    Pcs,
    PolynomialSpace,
};
use lib_q_stark_field::extension::{
    BinomialExtensionField,
    Complex,
};
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
/// FRI **challenge field**: the degree-3 extension over `Complex<Mersenne31>`, i.e. `GF(p^6)`
/// (~186 bits). Upgraded from using the value field itself (`Complex<Mersenne31>` = `GF(p^2)`,
/// ~62 bits) as the challenge field — ~62 bits was a hard ceiling on Fiat–Shamir/DEEP soundness far
/// below 128. Constants are Sage-verified in `lib-q-stark-mersenne31/src/extension.rs`
/// (`HasComplexBinomialExtension<3>`: `y^3 - 5i`). See `membership-arm-a-soundness-params.md`.
pub type ConfigChallenge = BinomialExtensionField<ConfigVal, 3>;
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

// ---------------------------------------------------------------------------
// Arm A **membership** config — 128-bit-PQ variant of `DefaultConfig` with a larger FRI challenge
// field. The shared `DefaultConfig` keeps the value field (`Complex<Mersenne31>`, ~62 bits) as its
// challenge field (the recursive-aggregation verifier in `air/recursive_types.rs` hardcodes that
// width); the membership prover/verifier instead use the degree-3 challenge extension `GF(p^6)`
// (~186 bits) so the unlinkable-membership proof clears 128-bit (FS/DEEP no longer the binder; the
// binding term is the SHAKE256 commitment at 128). Same value field, DFT, and Merkle commitment as
// `DefaultConfig`; only the challenge field + FRI params differ.
pub type MembershipChallengeMmcs = ExtensionMmcs<ConfigVal, ConfigChallenge, DefaultValMmcs>;
pub type MembershipPcs =
    TwoAdicFriPcs<ConfigVal, ConfigDft, DefaultValMmcs, MembershipChallengeMmcs>;
pub type MembershipConfig = StarkConfig<
    MembershipPcs,
    ConfigChallenge,
    ComplexFieldChallenger<Shake256Challenger32<Mersenne31>>,
>;

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
    lib_q_random::Kt128Rng,
    32,
    4,
>;
pub type ZkChallengeMmcs = ExtensionMmcs<ConfigVal, ConfigVal, ZkValMmcs>;
pub type ZkPcs =
    HidingFriPcs<ConfigVal, ConfigDft, ZkValMmcs, ZkChallengeMmcs, lib_q_random::Kt128Rng>;
pub type ZkConfig =
    StarkConfig<ZkPcs, ConfigVal, ComplexFieldChallenger<Shake256Challenger32<Mersenne31>>>;

/// Arm A **membership** hiding (ZK) config — 128-bit-PQ variant of [`ZkConfig`] with the degree-3
/// challenge field (`GF(p^6)` ~186 bits). See [`MembershipConfig`].
pub type MembershipZkChallengeMmcs = ExtensionMmcs<ConfigVal, ConfigChallenge, ZkValMmcs>;
pub type MembershipZkPcs =
    HidingFriPcs<ConfigVal, ConfigDft, ZkValMmcs, MembershipZkChallengeMmcs, lib_q_random::Kt128Rng>;
pub type MembershipZkConfig = StarkConfig<
    MembershipZkPcs,
    ConfigChallenge,
    ComplexFieldChallenger<Shake256Challenger32<Mersenne31>>,
>;

/// FRI query parameters used when replaying the verifier (e.g. for recursive aggregation).
#[derive(Clone, Debug)]
pub struct FriQueryParams {
    pub num_queries: usize,
    pub log_blowup: usize,
    pub log_final_poly_len: usize,
    pub proof_of_work_bits: usize,
}

// Generic type aliases for StarkVerifier (`C: StarkGenericConfig` on the alias is stable Rust).
type PcsCommitment<C: StarkGenericConfig> =
    <C::Pcs as Pcs<C::Challenge, C::Challenger>>::Commitment;

type CommitmentRounds<C: StarkGenericConfig> = Vec<(
    PcsCommitment<C>,
    Vec<(Domain<C>, Vec<(C::Challenge, Vec<C::Challenge>)>)>,
)>;

type QuotientRounds<C: StarkGenericConfig> =
    Vec<(Domain<C>, Vec<(C::Challenge, Vec<C::Challenge>)>)>;

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
    ) -> Result<StarkProof<C>, lib_q_stark::ProverError>
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
    ) -> Result<StarkProof<C>, lib_q_stark::ProverError>
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
        challenger.observe(Val::<C>::from_usize(A::width(air)));
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
        challenger.observe(Val::<C>::from_usize(A::width(air)));
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

/// Creates a production-ready default STARK configuration
///
/// This configuration uses:
/// - **SHAKE256** for all hash operations (NIST-approved, post-quantum secure)
/// - **`Complex<Mersenne31>`** field (TWO_ADICITY = 32) for efficient arithmetic
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

/// Construct the Arm A **membership** transparent config — 128-bit-PQ ([`MembershipConfig`]).
/// Identical to [`default_config`] except: (1) the FRI challenge field is the degree-3 extension
/// `GF(p^6)` (~186 bits) instead of the ~62-bit value field, and (2) FRI `log_blowup = 3`
/// (ρ = 1/8), `num_queries = 96`, `proof_of_work_bits = 20`. With the larger challenge field the
/// FS/DEEP term is no longer the binder; the binding soundness term is the SHAKE256 commitment at
/// 128 bits, and the query phase clears 128-bit on the conjectured (288) and provable-Johnson (144)
/// bounds. (The shared `default_config` stays ~62-bit because the recursive-aggregation verifier in
/// `air/recursive_types.rs` hardcodes the value-field challenge width; membership does not recurse.)
pub fn membership_config() -> MembershipConfig {
    use lib_q_stark_fri::FriParameters;

    let shake256 = Shake256Hash {};
    let hash = SerializingHasher::<Shake256Hash>::new(shake256);
    let compress = CompressionFunctionFromHasher::<Shake256Hash, 2, 32>::new(shake256);
    let val_mmcs = DefaultValMmcs::new(hash, compress);
    let challenge_mmcs = MembershipChallengeMmcs::new(val_mmcs.clone());
    let dft = ConfigDft::default();
    let fri_params = FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        num_queries: 96,
        proof_of_work_bits: 20,
        mmcs: challenge_mmcs,
    };
    let pcs = MembershipPcs::new(dft, val_mmcs, fri_params);
    let base_challenger = Shake256Challenger32::<Mersenne31>::from_hasher(Vec::new(), Shake256Hash);
    let challenger = ComplexFieldChallenger::new(base_challenger);
    StarkConfig::new(pcs, challenger)
}

/// STARK configuration for **tests and local development only**.
///
/// Same construction as [`default_config`], but FRI uses
/// [`lib_q_stark_fri::create_test_fri_params`] (2 queries, 1 proof-of-work bit) so proving
/// and verification complete quickly. **Do not use for production**; proofs are not
/// production-sound and are incompatible with verifiers configured for [`default_config`].
///
/// Soundness is far below production; do not use this config to assert that verification
/// **rejects** wrong public inputs (e.g. wrong Merkle root). For those negative tests, use
/// [`default_config`] on prover and verifier.
pub fn fast_proof_config() -> DefaultConfig {
    use lib_q_stark_fri::create_test_fri_params;

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
    let fri_params = create_test_fri_params(challenge_mmcs, 0);
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let challenger = Challenger::new(base_challenger);

    StarkConfig::new(pcs, challenger)
}

/// Fast (minimal-FRI) [`MembershipConfig`] for tests — the degree-3-challenge-field analogue of
/// [`fast_proof_config`]. Not sound for production; only for round-trip tests.
pub fn membership_fast_config() -> MembershipConfig {
    use lib_q_stark_fri::create_test_fri_params;

    let shake256 = Shake256Hash {};
    let hash = SerializingHasher::<Shake256Hash>::new(shake256);
    let compress = CompressionFunctionFromHasher::<Shake256Hash, 2, 32>::new(shake256);
    let val_mmcs = DefaultValMmcs::new(hash, compress);
    let challenge_mmcs = MembershipChallengeMmcs::new(val_mmcs.clone());
    let dft = ConfigDft::default();
    let fri_params = create_test_fri_params(challenge_mmcs, 0);
    let pcs = MembershipPcs::new(dft, val_mmcs, fri_params);
    let base_challenger = Shake256Challenger32::<Mersenne31>::from_hasher(Vec::new(), Shake256Hash);
    let challenger = ComplexFieldChallenger::new(base_challenger);
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

/// Same PCS and challenger construction as [`poseidon_config`], but FRI uses
/// [`lib_q_stark_fri::create_test_fri_params`] (2 queries, 1 proof-of-work bit) so recursive
/// aggregation tests finish quickly. **Not for production**; incompatible with verifiers
/// expecting [`poseidon_config`] FRI parameters.
#[cfg(feature = "recursive-proofs-experimental")]
pub fn poseidon_test_config() -> PoseidonConfig {
    use lib_q_stark_fri::create_test_fri_params;
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
    let fri_params = create_test_fri_params(challenge_mmcs, 0);
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
        lib_q_random::Kt128Rng::from_u64(val_mmcs_seed),
    );
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = create_test_fri_params_zk(challenge_mmcs);
    let pcs = Pcs::new(
        dft,
        val_mmcs,
        fri_params,
        4,
        lib_q_random::Kt128Rng::from_u64(pcs_seed),
    );
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let challenger = Challenger::new(base_challenger);

    StarkConfig::new(pcs, challenger)
}

/// ZK config with explicit FRI parameters and RNG seeds.
///
/// The hiding PCS LDEs the (randomized) trace at `log_blowup + 1`. High-degree AIRs (e.g. the
/// Poseidon `x⁵` S-box, constraint degree 5) need a LARGER `log_blowup` than low-degree AIRs so
/// the quotient-evaluation domain stays within the committed LDE — the hiding PCS's
/// extrapolation fallback for out-of-LDE domains is not implemented. For degree-5 AIRs use
/// `log_blowup >= 3`.
#[doc(hidden)]
pub fn zk_config_with_params(
    log_blowup: usize,
    num_queries: usize,
    proof_of_work_bits: usize,
    val_mmcs_seed: u64,
    pcs_seed: u64,
) -> ZkConfig {
    use lib_q_stark_fri::FriParameters;

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
        lib_q_random::Kt128Rng::from_u64(val_mmcs_seed),
    );
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters {
        log_blowup,
        log_final_poly_len: 0,
        num_queries,
        proof_of_work_bits,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(
        dft,
        val_mmcs,
        fri_params,
        4,
        lib_q_random::Kt128Rng::from_u64(pcs_seed),
    );
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let challenger = Challenger::new(base_challenger);

    StarkConfig::new(pcs, challenger)
}

/// Production ZK config seeded from **256-bit CSPRNG entropy** (the hiding secret). Use this
/// for real zero-knowledge proofs. `val_seed` (hiding-MMCS salts) and `pcs_seed` (blinding
/// polynomials) MUST be INDEPENDENT, fresh, unpredictable CSPRNG draws — sharing or predicting
/// them voids hiding. The KT128-backed [`lib_q_random::Kt128Rng`] expands each 256-bit seed
/// into a cryptographically pseudorandom stream (unlike the xorshift64 `DeterministicRng` used
/// by the `*_with_seeds`/`*_with_params` test helpers).
pub fn zk_config_with_seed_bytes(
    log_blowup: usize,
    num_queries: usize,
    proof_of_work_bits: usize,
    val_seed: [u8; 32],
    pcs_seed: [u8; 32],
) -> ZkConfig {
    use lib_q_stark_fri::FriParameters;

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
        lib_q_random::Kt128Rng::from_seed_bytes(val_seed),
    );
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters {
        log_blowup,
        log_final_poly_len: 0,
        num_queries,
        proof_of_work_bits,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(
        dft,
        val_mmcs,
        fri_params,
        4,
        lib_q_random::Kt128Rng::from_seed_bytes(pcs_seed),
    );
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let challenger = Challenger::new(base_challenger);

    StarkConfig::new(pcs, challenger)
}

/// Arm A **membership** hiding-PCS ZK config from 256-bit CSPRNG seeds — 128-bit-PQ
/// ([`MembershipZkConfig`], degree-3 challenge field). Mirrors [`zk_config_with_seed_bytes`].
pub fn membership_zk_config_with_seed_bytes(
    log_blowup: usize,
    num_queries: usize,
    proof_of_work_bits: usize,
    val_seed: [u8; 32],
    pcs_seed: [u8; 32],
) -> MembershipZkConfig {
    use lib_q_stark_fri::FriParameters;

    let shake256 = Shake256Hash {};
    let hash = SerializingHasher::<Shake256Hash>::new(shake256);
    let compress = CompressionFunctionFromHasher::<Shake256Hash, 2, 32>::new(shake256);
    let val_mmcs =
        ZkValMmcs::new(hash, compress, lib_q_random::Kt128Rng::from_seed_bytes(val_seed));
    let challenge_mmcs = MembershipZkChallengeMmcs::new(val_mmcs.clone());
    let dft = ConfigDft::default();
    let fri_params = FriParameters {
        log_blowup,
        log_final_poly_len: 0,
        num_queries,
        proof_of_work_bits,
        mmcs: challenge_mmcs,
    };
    let pcs = MembershipZkPcs::new(
        dft,
        val_mmcs,
        fri_params,
        4,
        lib_q_random::Kt128Rng::from_seed_bytes(pcs_seed),
    );
    let base_challenger = Shake256Challenger32::<Mersenne31>::from_hasher(Vec::new(), Shake256Hash);
    let challenger = ComplexFieldChallenger::new(base_challenger);
    StarkConfig::new(pcs, challenger)
}

/// Arm A **membership** ZK config with explicit FRI params + xorshift test seeds — 128-bit-PQ
/// ([`MembershipZkConfig`]). Mirrors [`zk_config_with_params`]; used by the verifier (FRI params
/// must match the prover; the verifier needs no hiding entropy).
#[doc(hidden)]
pub fn membership_zk_config_with_params(
    log_blowup: usize,
    num_queries: usize,
    proof_of_work_bits: usize,
    val_mmcs_seed: u64,
    pcs_seed: u64,
) -> MembershipZkConfig {
    use lib_q_stark_fri::FriParameters;

    let shake256 = Shake256Hash {};
    let hash = SerializingHasher::<Shake256Hash>::new(shake256);
    let compress = CompressionFunctionFromHasher::<Shake256Hash, 2, 32>::new(shake256);
    let val_mmcs = ZkValMmcs::new(hash, compress, lib_q_random::Kt128Rng::from_u64(val_mmcs_seed));
    let challenge_mmcs = MembershipZkChallengeMmcs::new(val_mmcs.clone());
    let dft = ConfigDft::default();
    let fri_params = FriParameters {
        log_blowup,
        log_final_poly_len: 0,
        num_queries,
        proof_of_work_bits,
        mmcs: challenge_mmcs,
    };
    let pcs = MembershipZkPcs::new(
        dft,
        val_mmcs,
        fri_params,
        4,
        lib_q_random::Kt128Rng::from_u64(pcs_seed),
    );
    let base_challenger = Shake256Challenger32::<Mersenne31>::from_hasher(Vec::new(), Shake256Hash);
    let challenger = ComplexFieldChallenger::new(base_challenger);
    StarkConfig::new(pcs, challenger)
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec;

    use super::*;
    use crate::air::{
        ArithmeticAir,
        TraceGenerator,
    };

    fn sample_arithmetic_proof() -> (ArithmeticAir, StarkProof<DefaultConfig>, Vec<ConfigVal>) {
        let air = ArithmeticAir::new(1).expect("ArithmeticAir");
        let input = vec![(ConfigVal::ONE, ConfigVal::ONE)];
        let trace = air.generate_trace(&input).expect("trace");
        let public_values = air.public_values(&input);
        let proof = StarkProver::new(default_config())
            .prove(&air, trace, &public_values)
            .expect("proof generation");
        (air, proof, public_values)
    }

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

    #[test]
    fn test_default_fri_params_for_tests_values() {
        let (log_blowup, num_queries, proof_of_work_bits) = default_fri_params_for_tests();
        assert_eq!(log_blowup, 2);
        assert_eq!(num_queries, 100);
        assert_eq!(proof_of_work_bits, 16);
    }

    #[test]
    fn test_zk_config_builders_create_zk_configs() {
        let zk_a = zk_config();
        let zk_b = zk_config_with_seeds(11, 29);
        assert_eq!(zk_a.is_zk(), 1);
        assert_eq!(zk_b.is_zk(), 1);
    }

    #[test]
    fn test_prover_and_verifier_config_accessors() {
        let prover = StarkProver::new(default_config());
        let verifier = StarkVerifier::new(default_config());
        assert_eq!(prover.config().is_zk(), 0);
        assert_eq!(verifier.config().is_zk(), 0);
    }

    #[test]
    fn test_stark_prove_and_verify_roundtrip() {
        let (air, proof, public_values) = sample_arithmetic_proof();
        let verifier = StarkVerifier::new(default_config());
        verifier
            .verify(&air, &proof, &public_values)
            .expect("proof should verify");
    }

    #[test]
    fn test_derive_challenges_and_query_positions() {
        let (air, proof, public_values) = sample_arithmetic_proof();
        let verifier = StarkVerifier::new(default_config());

        let (_zeta, _zeta_next, _alpha, betas) = verifier
            .derive_challenges(&air, &proof, &public_values)
            .expect("derive_challenges");

        let (log_blowup, num_queries, proof_of_work_bits) = default_fri_params_for_tests();
        assert!(betas.len() <= num_queries);
        let fri_params = FriQueryParams {
            num_queries,
            log_blowup,
            log_final_poly_len: 0,
            proof_of_work_bits,
        };
        let positions = verifier
            .derive_query_positions(&air, &proof, &public_values, &fri_params)
            .expect("derive_query_positions");
        assert_eq!(positions.len(), num_queries);
    }

    #[test]
    fn test_derive_query_positions_rejects_wrong_public_values_shape() {
        let (air, proof, _public_values) = sample_arithmetic_proof();
        let verifier = StarkVerifier::new(default_config());
        let (log_blowup, num_queries, proof_of_work_bits) = default_fri_params_for_tests();
        let fri_params = FriQueryParams {
            num_queries,
            log_blowup,
            log_final_poly_len: 0,
            proof_of_work_bits,
        };
        let wrong_public_values = vec![ConfigVal::ZERO; 2];
        let result =
            verifier.derive_query_positions(&air, &proof, &wrong_public_values, &fri_params);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_challenges_rejects_random_commitment_mismatch() {
        let (air, mut proof, public_values) = sample_arithmetic_proof();
        let verifier = StarkVerifier::new(default_config());

        proof.commitments.random = Some(proof.commitments.trace.clone());
        let result = verifier.derive_challenges(&air, &proof, &public_values);
        assert!(matches!(result, Err(VerificationError::RandomizationError)));
    }

    #[test]
    fn test_derive_challenges_rejects_random_values_mismatch() {
        let (air, mut proof, public_values) = sample_arithmetic_proof();
        let verifier = StarkVerifier::new(default_config());

        proof.opened_values.random = Some(vec![ConfigVal::ZERO]);
        let result = verifier.derive_challenges(&air, &proof, &public_values);
        assert!(matches!(result, Err(VerificationError::RandomizationError)));
    }

    #[test]
    fn test_derive_challenges_rejects_invalid_trace_shape() {
        let (air, mut proof, public_values) = sample_arithmetic_proof();
        let verifier = StarkVerifier::new(default_config());

        let _ = proof.opened_values.trace_local.pop();
        let result = verifier.derive_challenges(&air, &proof, &public_values);
        assert!(matches!(result, Err(VerificationError::InvalidProofShape)));
    }

    #[test]
    fn test_derive_challenges_rejects_invalid_quotient_chunk_shape() {
        let (air, mut proof, public_values) = sample_arithmetic_proof();
        let verifier = StarkVerifier::new(default_config());

        proof.opened_values.quotient_chunks.clear();
        let result = verifier.derive_challenges(&air, &proof, &public_values);
        assert!(matches!(result, Err(VerificationError::InvalidProofShape)));
    }

    #[test]
    fn test_derive_query_positions_rejects_random_commitment_mismatch() {
        let (air, mut proof, public_values) = sample_arithmetic_proof();
        let verifier = StarkVerifier::new(default_config());
        let (log_blowup, num_queries, proof_of_work_bits) = default_fri_params_for_tests();
        let fri_params = FriQueryParams {
            num_queries,
            log_blowup,
            log_final_poly_len: 0,
            proof_of_work_bits,
        };

        proof.commitments.random = Some(proof.commitments.trace.clone());
        let result = verifier.derive_query_positions(&air, &proof, &public_values, &fri_params);
        assert!(matches!(result, Err(VerificationError::RandomizationError)));
    }

    #[test]
    fn test_derive_query_positions_rejects_random_values_without_commitment() {
        let (air, mut proof, public_values) = sample_arithmetic_proof();
        let verifier = StarkVerifier::new(default_config());
        let (log_blowup, num_queries, proof_of_work_bits) = default_fri_params_for_tests();
        let fri_params = FriQueryParams {
            num_queries,
            log_blowup,
            log_final_poly_len: 0,
            proof_of_work_bits,
        };

        proof.opened_values.random = Some(vec![ConfigVal::ZERO]);
        let result = verifier.derive_query_positions(&air, &proof, &public_values, &fri_params);
        assert!(matches!(result, Err(VerificationError::RandomizationError)));
    }

    #[test]
    fn test_derive_query_positions_rejects_invalid_trace_shape() {
        let (air, mut proof, public_values) = sample_arithmetic_proof();
        let verifier = StarkVerifier::new(default_config());
        let (log_blowup, num_queries, proof_of_work_bits) = default_fri_params_for_tests();
        let fri_params = FriQueryParams {
            num_queries,
            log_blowup,
            log_final_poly_len: 0,
            proof_of_work_bits,
        };

        let _ = proof.opened_values.trace_next.pop();
        let result = verifier.derive_query_positions(&air, &proof, &public_values, &fri_params);
        assert!(matches!(result, Err(VerificationError::InvalidProofShape)));
    }

    #[test]
    fn test_derive_query_positions_rejects_invalid_pow_witness() {
        let (air, proof, public_values) = sample_arithmetic_proof();
        let verifier = StarkVerifier::new(default_config());
        let (log_blowup, num_queries, _proof_of_work_bits) = default_fri_params_for_tests();
        let fri_params = FriQueryParams {
            num_queries,
            log_blowup,
            log_final_poly_len: 0,
            // Tighten PoW bits while staying in-field (<= 30 for Mersenne31).
            proof_of_work_bits: 30,
        };

        let result = verifier.derive_query_positions(&air, &proof, &public_values, &fri_params);
        assert!(matches!(result, Err(VerificationError::InvalidProofShape)));
    }

    #[test]
    fn test_verify_rejects_invalid_trace_local_shape() {
        let (air, mut proof, public_values) = sample_arithmetic_proof();
        let verifier = StarkVerifier::new(default_config());
        let _ = proof.opened_values.trace_local.pop();
        let result = verifier.verify(&air, &proof, &public_values);
        assert!(matches!(result, Err(VerificationError::InvalidProofShape)));
    }

    #[test]
    fn test_verify_rejects_invalid_trace_next_shape() {
        let (air, mut proof, public_values) = sample_arithmetic_proof();
        let verifier = StarkVerifier::new(default_config());
        let _ = proof.opened_values.trace_next.pop();
        let result = verifier.verify(&air, &proof, &public_values);
        assert!(matches!(result, Err(VerificationError::InvalidProofShape)));
    }

    #[test]
    fn test_verify_rejects_invalid_quotient_chunk_shape() {
        let (air, mut proof, public_values) = sample_arithmetic_proof();
        let verifier = StarkVerifier::new(default_config());
        proof.opened_values.quotient_chunks.clear();
        let result = verifier.verify(&air, &proof, &public_values);
        assert!(matches!(result, Err(VerificationError::InvalidProofShape)));
    }

    #[test]
    fn test_verify_rejects_random_commitment_mismatch() {
        let (air, mut proof, public_values) = sample_arithmetic_proof();
        let verifier = StarkVerifier::new(default_config());
        proof.commitments.random = Some(proof.commitments.trace.clone());
        let result = verifier.verify(&air, &proof, &public_values);
        assert!(matches!(result, Err(VerificationError::RandomizationError)));
    }

    #[test]
    fn test_verify_rejects_random_values_mismatch() {
        let (air, mut proof, public_values) = sample_arithmetic_proof();
        let verifier = StarkVerifier::new(default_config());
        proof.opened_values.random = Some(vec![ConfigVal::ZERO]);
        let result = verifier.verify(&air, &proof, &public_values);
        assert!(matches!(result, Err(VerificationError::RandomizationError)));
    }
}
