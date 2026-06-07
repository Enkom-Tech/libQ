//! Wire/profile constants for MAUL v1 double-KEM.

/// MAUL-v1 target wire budget for one double encapsulation payload.
pub const WIRE_BUDGET_MAUL_ENCAP_BYTES: usize = 1260;

/// Baseline size of two raw ML-KEM-768 ciphertexts.
pub const BASELINE_DOUBLE_ML_KEM_768_CIPHERTEXT_BYTES: usize = 2176;

/// Hint size for MAUL-v1 compressed wire.
pub const MAUL_HINT_BYTES: usize = 172;

/// Ciphertext body size for MAUL-v1 compressed wire.
pub const MAUL_WIRE_BODY_BYTES: usize = 1088;

/// KAT schema identifier for this crate.
pub const DOUBLE_KEM_KAT_SCHEMA: &str = "double-kem-kat-v1";

/// Provisional profile descriptor for MAUL-v1.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MaulProfileV1;

impl MaulProfileV1 {
    /// Return expected wire size in bytes.
    #[must_use]
    pub const fn wire_bytes(self) -> usize {
        WIRE_BUDGET_MAUL_ENCAP_BYTES
    }

    /// Return baseline (uncompressed) two-ciphertext byte size.
    #[must_use]
    pub const fn baseline_bytes(self) -> usize {
        BASELINE_DOUBLE_ML_KEM_768_CIPHERTEXT_BYTES
    }
}
