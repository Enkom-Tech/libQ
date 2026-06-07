//! Recovery policy hybrid STARK prove/verify helpers (v1).

extern crate alloc;

use alloc::vec::Vec;

use lib_q_core::Result;

use crate::air::TraceGenerator;
use crate::air::recovery_policy_hybrid::{
    RECOVERY_POLICY_HYBRID_AIR_ID,
    RecoveryPolicyHybridAir,
    RecoveryPolicyHybridInput,
};
use crate::stark::{
    StarkProver,
    StarkVerifier,
    default_config,
    fast_proof_config,
};
use crate::wire::recovery_proof_v1::{
    RecoveryZkProofV1,
    decode_recovery_zk_proof_v1,
    encode_recovery_zk_proof_v1,
};
use crate::{
    ProofMetadata,
    ZkpProof,
};

pub fn prove_recovery_policy_hybrid(
    input: &RecoveryPolicyHybridInput,
) -> Result<(ZkpProof, Vec<u8>)> {
    let air = RecoveryPolicyHybridAir::new(input.public.clone()).map_err(|e| {
        lib_q_core::Error::InternalError {
            operation: "RecoveryPolicyHybridAir::new".into(),
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
    let prover = StarkProver::new(default_config());
    let stark_proof = prover.prove(&air, trace, &public_values).map_err(|e| {
        lib_q_core::Error::InternalError {
            operation: "StarkProver::prove".into(),
            details: format!("{e:?}"),
        }
    })?;
    let metadata = ProofMetadata::RecoveryPolicy {
        key_count: input.public.zk_key_count,
        air_id: RECOVERY_POLICY_HYBRID_AIR_ID,
    };
    let zkp = ZkpProof::from_stark_proof(&stark_proof, metadata)?;
    let envelope =
        encode_recovery_zk_proof_v1(RECOVERY_POLICY_HYBRID_AIR_ID, &input.public, &zkp.data)
            .map_err(|e| lib_q_core::Error::InternalError {
                operation: "encode_recovery_zk_proof_v1".into(),
                details: e.to_string(),
            })?;
    Ok((zkp, envelope))
}

pub fn verify_recovery_policy_hybrid_envelope(envelope: &[u8]) -> Result<()> {
    let decoded =
        decode_recovery_zk_proof_v1(envelope).map_err(|e| lib_q_core::Error::InternalError {
            operation: "decode_recovery_zk_proof_v1".into(),
            details: e.to_string(),
        })?;
    verify_recovery_policy_hybrid_decoded(&decoded)
}

pub fn verify_recovery_policy_hybrid_decoded(decoded: &RecoveryZkProofV1) -> Result<()> {
    let air = RecoveryPolicyHybridAir::new(decoded.public_inputs.clone()).map_err(|e| {
        lib_q_core::Error::InternalError {
            operation: "RecoveryPolicyHybridAir::new".into(),
            details: e.to_string(),
        }
    })?;
    let metadata = ProofMetadata::RecoveryPolicy {
        key_count: decoded.public_inputs.zk_key_count,
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
    let dummy_input = RecoveryPolicyHybridInput {
        public: decoded.public_inputs.clone(),
        zk_keys: Vec::new(),
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

pub fn prove_recovery_policy_hybrid_fast(input: &RecoveryPolicyHybridInput) -> Result<ZkpProof> {
    let air = RecoveryPolicyHybridAir::new(input.public.clone()).map_err(|e| {
        lib_q_core::Error::InternalError {
            operation: "RecoveryPolicyHybridAir::new".into(),
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
            key_count: input.public.zk_key_count,
            air_id: RECOVERY_POLICY_HYBRID_AIR_ID,
        },
    )
}
