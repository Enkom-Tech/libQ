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
    Proof as StarkProof,
    StarkConfig,
    StarkGenericConfig,
    SymbolicAirBuilder,
    Val,
    VerificationError,
    prove,
    verify,
};
use lib_q_stark_air::Air;
use lib_q_stark_matrix::dense::RowMajorMatrix;

/// zk-STARK prover
///
/// This is a high-level wrapper around the STARK proving functionality.
/// It provides a convenient interface for generating STARK proofs with a given configuration.
///
/// # Example
///
/// ```rust,ignore
/// use lib_q_zkp::stark::{StarkProver, default_config};
/// use lib_q_stark_field::extension::Complex;
/// use lib_q_stark_mersenne31::Mersenne31;
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
/// use lib_q_stark_field::extension::Complex;
/// use lib_q_stark_mersenne31::Mersenne31;
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

    /// Get a reference to the underlying configuration
    pub fn config(&self) -> &C {
        &self.config
    }
}

/// Wrapper challenger that implements FieldChallenger<Complex<Mersenne31>>
/// by delegating to a base field challenger and using algebra element methods
#[derive(Clone)]
struct ComplexFieldChallenger<BaseChallenger> {
    base: BaseChallenger,
}

impl<BaseChallenger> ComplexFieldChallenger<BaseChallenger> {
    fn new(base: BaseChallenger) -> Self {
        Self { base }
    }
}

impl<BaseChallenger>
    lib_q_stark_challenger::CanObserve<
        lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>,
    > for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: lib_q_stark_challenger::FieldChallenger<lib_q_stark_mersenne31::Mersenne31>,
{
    fn observe(
        &mut self,
        value: lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>,
    ) {
        self.base.observe_algebra_element(value);
    }

    fn observe_slice(
        &mut self,
        values: &[lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>],
    ) where
        lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>: Clone,
    {
        for value in values {
            self.observe(value.clone());
        }
    }
}

impl<BaseChallenger>
    lib_q_stark_challenger::CanSample<
        lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>,
    > for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: lib_q_stark_challenger::FieldChallenger<lib_q_stark_mersenne31::Mersenne31>,
    lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>:
        lib_q_stark_field::BasedVectorSpace<lib_q_stark_mersenne31::Mersenne31>,
{
    fn sample(
        &mut self,
    ) -> lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31> {
        self.base.sample_algebra_element()
    }

    fn sample_array<const N: usize>(
        &mut self,
    ) -> [lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>; N] {
        core::array::from_fn(|_| self.sample())
    }

    fn sample_vec(
        &mut self,
        n: usize,
    ) -> Vec<lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>> {
        (0..n).map(|_| self.sample()).collect()
    }
}

impl<BaseChallenger> lib_q_stark_challenger::CanSampleBits<usize>
    for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: lib_q_stark_challenger::FieldChallenger<lib_q_stark_mersenne31::Mersenne31>,
{
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.base.sample_bits(bits)
    }
}

impl<BaseChallenger>
    lib_q_stark_challenger::FieldChallenger<
        lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>,
    > for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: lib_q_stark_challenger::FieldChallenger<lib_q_stark_mersenne31::Mersenne31>
        + Clone
        + Send
        + Sync,
    lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>:
        lib_q_stark_field::BasedVectorSpace<lib_q_stark_mersenne31::Mersenne31>,
{
}

// Forward CanObserve for Hash commitment types by observing through base challenger
impl<BaseChallenger, F, const DIGEST_ELEMS: usize>
    lib_q_stark_challenger::CanObserve<lib_q_stark_symmetric::Hash<F, u8, DIGEST_ELEMS>>
    for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: lib_q_stark_challenger::CanObserve<
            lib_q_stark_symmetric::Hash<lib_q_stark_mersenne31::Mersenne31, u8, DIGEST_ELEMS>,
        >,
{
    fn observe(&mut self, value: lib_q_stark_symmetric::Hash<F, u8, DIGEST_ELEMS>) {
        let array: [u8; DIGEST_ELEMS] = value.into();
        let mersenne_hash = lib_q_stark_symmetric::Hash::<
            lib_q_stark_mersenne31::Mersenne31,
            u8,
            DIGEST_ELEMS,
        >::from(array);
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

impl<BaseChallenger> lib_q_stark_challenger::GrindingChallenger
    for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: lib_q_stark_challenger::GrindingChallenger<Witness = lib_q_stark_mersenne31::Mersenne31>
        + lib_q_stark_challenger::FieldChallenger<lib_q_stark_mersenne31::Mersenne31>
        + Clone
        + Send
        + Sync,
{
    type Witness = lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        use lib_q_stark_field::integers::QuotientMap;
        use lib_q_stark_mersenne31::Mersenne31;
        use lib_q_stark_rayon::prelude::*;

        const P: u32 = (1 << 31) - 1; // Mersenne31 prime
        assert!(bits < (usize::BITS as usize));
        assert!((1 << bits) < P as usize);

        let witness = (0..P)
            .into_par_iter()
            .map(|i| {
                let base = Mersenne31::from_int(i as u32);
                lib_q_stark_field::extension::Complex::<Mersenne31>::from(base)
            })
            .find_any(|witness| self.clone().check_witness(bits, *witness))
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

impl<BaseChallenger>
    lib_q_stark_challenger::CanObserve<
        Vec<Vec<lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>>>,
    > for ComplexFieldChallenger<BaseChallenger>
where
    BaseChallenger: lib_q_stark_challenger::FieldChallenger<lib_q_stark_mersenne31::Mersenne31>,
{
    fn observe(
        &mut self,
        valuess: Vec<
            Vec<lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>>,
        >,
    ) {
        for values in valuess {
            for value in values {
                self.observe(value);
            }
        }
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
pub fn default_config() -> StarkConfig<
    lib_q_stark_fri::TwoAdicFriPcs<
        lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>,
        lib_q_stark_mersenne31::Mersenne31ComplexRadix2Dit,
        lib_q_stark_merkle::MerkleTreeMmcs<
            <lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31> as lib_q_stark_field::Field>::Packing,
            u8,
            lib_q_stark_symmetric::SerializingHasher<lib_q_stark_shake256::Shake256Hash>,
            lib_q_stark_symmetric::CompressionFunctionFromHasher<lib_q_stark_shake256::Shake256Hash, 2, 32>,
            32,
        >,
        lib_q_stark_commit::ExtensionMmcs<
            lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>,
            lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>,
            lib_q_stark_merkle::MerkleTreeMmcs<
                <lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31> as lib_q_stark_field::Field>::Packing,
                u8,
                lib_q_stark_symmetric::SerializingHasher<lib_q_stark_shake256::Shake256Hash>,
                lib_q_stark_symmetric::CompressionFunctionFromHasher<lib_q_stark_shake256::Shake256Hash, 2, 32>,
                32,
            >,
        >,
    >,
    lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>,
    ComplexFieldChallenger<lib_q_stark_challenger::Shake256Challenger32<lib_q_stark_mersenne31::Mersenne31>>,
>{
    use lib_q_stark_challenger::Shake256Challenger32;
    use lib_q_stark_commit::ExtensionMmcs;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_fri::{
        TwoAdicFriPcs,
        create_benchmark_fri_params,
    };
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

    // Use Complex<Mersenne31> as base field (TWO_ADICITY = 32) for sufficient two-adicity
    type Val = Complex<Mersenne31>;
    // Use Complex<Mersenne31> directly as challenge field
    type Challenge = Val;
    // Quantum-safe SHAKE256-based Merkle tree setup
    type MyHash = SerializingHasher<Shake256Hash>;
    type MyCompress = CompressionFunctionFromHasher<Shake256Hash, 2, 32>;
    // Use u8 as width type for byte-based hashing (quantum-safe)
    type ValMmcs =
        MerkleTreeMmcs<<Val as lib_q_stark_field::Field>::Packing, u8, MyHash, MyCompress, 32>;
    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    // Use wrapper challenger that implements FieldChallenger<Complex<Mersenne31>>
    type BaseChallenger = Shake256Challenger32<Mersenne31>;
    type Challenger = ComplexFieldChallenger<BaseChallenger>;
    // Use Mersenne31ComplexRadix2Dit for Complex<Mersenne31> field
    type Dft = Mersenne31ComplexRadix2Dit;
    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

    let shake256 = Shake256Hash {};
    let hash = MyHash::new(shake256);
    let compress = MyCompress::new(shake256);
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = create_benchmark_fri_params(challenge_mmcs);
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let challenger = Challenger::new(base_challenger);

    StarkConfig::new(pcs, challenger)
}

#[cfg(test)]
mod tests {
    use lib_q_stark::StarkGenericConfig;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

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
