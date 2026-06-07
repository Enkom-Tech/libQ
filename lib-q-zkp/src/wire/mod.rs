//! Wire codecs for recovery policy STARK proofs.

pub mod recovery_proof_v0;
pub mod recovery_proof_v1;

pub use recovery_proof_v0::{
    RECOVERY_ZK_MAX_ENVELOPE,
    RECOVERY_ZK_WIRE_VERSION,
    RecoveryZkProofV0,
    decode_recovery_zk_proof_v0,
    encode_recovery_zk_proof_v0,
};
pub use recovery_proof_v1::{
    RECOVERY_ZK_WIRE_VERSION_V1,
    RecoveryZkProofV1,
    decode_recovery_zk_proof_v1,
    encode_recovery_zk_proof_v1,
};
