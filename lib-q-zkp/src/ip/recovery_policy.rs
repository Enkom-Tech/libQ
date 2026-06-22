//! Recovery policy STARK prove/verify helpers.

extern crate alloc;

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use lib_q_core::Result;

use crate::air::{
    RecoveryPolicyAir,
    RecoveryPolicyInput,
    TraceGenerator,
};
use crate::stark::{
    StarkProver,
    StarkVerifier,
    default_config,
    fast_proof_config,
};
use crate::wire::{
    RecoveryZkProofV0,
    decode_recovery_zk_proof_v0,
    encode_recovery_zk_proof_v0,
};
use crate::{
    ProofMetadata,
    ZkpProof,
};

/// Prove recovery policy satisfaction.
pub fn prove_recovery_policy(input: &RecoveryPolicyInput) -> Result<(ZkpProof, Vec<u8>)> {
    let air = RecoveryPolicyAir::new(input.public.clone()).map_err(|e| {
        lib_q_core::Error::InternalError {
            operation: "RecoveryPolicyAir::new".into(),
            details: e.to_string(),
        }
    })?;
    let trace = air
        .generate_trace(input)
        .map_err(|e| lib_q_core::Error::InternalError {
            operation: "generate_trace".into(),
            details: e.to_string(),
        })?;
    let public_values = air.public_values(input);
    let config = default_config();
    let prover = StarkProver::new(config);
    let stark_proof = prover.prove(&air, trace, &public_values).map_err(|e| {
        lib_q_core::Error::InternalError {
            operation: "StarkProver::prove".into(),
            details: format!("{e:?}"),
        }
    })?;
    let metadata = ProofMetadata::RecoveryPolicy {
        key_count: input.public.key_count,
        air_id: input.public.crypto_suite_id as u8,
    };
    let zkp = ZkpProof::from_stark_proof(&stark_proof, metadata)?;
    let envelope =
        encode_recovery_zk_proof_v0(crate::air::RECOVERY_POLICY_AIR_ID, &input.public, &zkp.data)
            .map_err(|e| lib_q_core::Error::InternalError {
            operation: "encode_recovery_zk_proof_v0".into(),
            details: e.to_string(),
        })?;
    Ok((zkp, envelope))
}

/// Verify recovery policy proof from envelope bytes.
pub fn verify_recovery_policy_envelope(envelope: &[u8]) -> Result<()> {
    let decoded =
        decode_recovery_zk_proof_v0(envelope).map_err(|e| lib_q_core::Error::InternalError {
            operation: "decode_recovery_zk_proof_v0".into(),
            details: e.to_string(),
        })?;
    verify_recovery_policy_decoded(&decoded)
}

/// Verify decoded envelope.
pub fn verify_recovery_policy_decoded(decoded: &RecoveryZkProofV0) -> Result<()> {
    let air = RecoveryPolicyAir::new(decoded.public_inputs.clone()).map_err(|e| {
        lib_q_core::Error::InternalError {
            operation: "RecoveryPolicyAir::new".into(),
            details: e.to_string(),
        }
    })?;
    let metadata = ProofMetadata::RecoveryPolicy {
        key_count: decoded.public_inputs.key_count,
        air_id: decoded.air_id,
    };
    let zkp = ZkpProof {
        data: decoded.proof_bytes.clone(),
        proof_type: crate::ProofType::Stark,
        security_level: 1,
        metadata,
    };
    let stark_proof = zkp
        .to_stark_proof()
        .map_err(|e| lib_q_core::Error::InternalError {
            operation: "to_stark_proof".into(),
            details: format!("{e:?}"),
        })?;
    let dummy_input = RecoveryPolicyInput {
        public: decoded.public_inputs.clone(),
        keys: Vec::new(),
        policy_time_lock: decoded.public_inputs.time_lock_min,
    };
    let public_values = air.public_values(&dummy_input);
    let verifier = StarkVerifier::new(default_config());
    verifier
        .verify(&air, &stark_proof, &public_values)
        .map_err(|e| lib_q_core::Error::InternalError {
            operation: "StarkVerifier::verify".into(),
            details: format!("{e:?}"),
        })
}

/// Prove with fast config (tests / KAT generation).
pub fn prove_recovery_policy_fast(input: &RecoveryPolicyInput) -> Result<ZkpProof> {
    let air = RecoveryPolicyAir::new(input.public.clone()).map_err(|e| {
        lib_q_core::Error::InternalError {
            operation: "RecoveryPolicyAir::new".into(),
            details: e.to_string(),
        }
    })?;
    let trace = air
        .generate_trace(input)
        .map_err(|e| lib_q_core::Error::InternalError {
            operation: "generate_trace".into(),
            details: e.to_string(),
        })?;
    let public_values = air.public_values(input);
    let prover = StarkProver::new(fast_proof_config());
    let stark_proof = prover.prove(&air, trace, &public_values).map_err(|e| {
        lib_q_core::Error::InternalError {
            operation: "StarkProver::prove".into(),
            details: format!("{e:?}"),
        }
    })?;
    ZkpProof::from_stark_proof(
        &stark_proof,
        ProofMetadata::RecoveryPolicy {
            key_count: input.public.key_count,
            air_id: crate::air::RECOVERY_POLICY_AIR_ID,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::{
        RecoveryPolicyKey,
        RecoveryPolicyPublicInputs,
        policy_commitment,
    };

    fn sample_input() -> RecoveryPolicyInput {
        let keys = vec![
            RecoveryPolicyKey {
                key_id: 1,
                weight: 2,
                raw_vk_bytes: vec![0x11; 64],
            },
            RecoveryPolicyKey {
                key_id: 3,
                weight: 2,
                raw_vk_bytes: vec![0x22; 64],
            },
        ];
        let commit = policy_commitment(3, &keys).unwrap();
        let public = RecoveryPolicyPublicInputs {
            policy_commitment: commit,
            threshold: 3,
            key_count: 2,
            time_lock_min: 0,
            time_lock_max: 86_400,
            freshness_epoch: 1_700_000_000,
            crypto_suite_id: 1,
        };
        RecoveryPolicyInput {
            public,
            keys,
            policy_time_lock: 3600,
        }
    }

    #[test]
    fn prove_verify_roundtrip() {
        let input = sample_input();
        let (_zkp, envelope) = prove_recovery_policy(&input).unwrap();
        assert!(verify_recovery_policy_envelope(&envelope).is_ok());
    }
}
