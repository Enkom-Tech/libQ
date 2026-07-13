#[cfg(not(feature = "std"))]
use alloc::string::String;
use core::fmt;

/// Errors produced by the encryption-proof prover and verifier.
#[non_exhaustive]
#[derive(Debug)]
pub enum EncProofError {
    /// Prover failed to generate a proof.
    Prover(String),
    /// Verifier rejected the proof.
    Verifier(String),
    /// The statement (public inputs) is structurally invalid.
    InvalidStatement(&'static str),
    /// Trace generation failed before the STARK prover was invoked.
    TraceGeneration(&'static str),
    /// The malformed-ciphertext gate refused: the encryption proof for the ciphertext did not verify,
    /// so partial decapsulation was denied before the share was touched (task #33).
    ProofRejected,
    /// The gated partial decapsulation itself failed (a `lib-q-threshold-kem-lattice` error, after the
    /// proof verified).
    Decap(lib_q_threshold_kem_lattice::ThresholdKemError),
}

impl fmt::Display for EncProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncProofError::Prover(msg) => write!(f, "prover error: {msg}"),
            EncProofError::Verifier(msg) => write!(f, "verifier rejection: {msg}"),
            EncProofError::InvalidStatement(msg) => write!(f, "invalid statement: {msg}"),
            EncProofError::TraceGeneration(msg) => write!(f, "trace generation error: {msg}"),
            EncProofError::ProofRejected => {
                write!(
                    f,
                    "malformed-ciphertext gate: encryption proof did not verify"
                )
            }
            EncProofError::Decap(e) => write!(f, "gated partial decapsulation failed: {e:?}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EncProofError {}
