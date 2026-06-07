//! Recovery policy STARK proof wire envelope (v0).

extern crate alloc;

use alloc::vec::Vec;

use crate::air::{
    AirError,
    RECOVERY_POLICY_AIR_ID,
    RECOVERY_PUBLIC_INPUTS_LEN,
    RecoveryPolicyPublicInputs,
};

/// Maximum envelope size (512 KiB).
pub const RECOVERY_ZK_MAX_ENVELOPE: usize = 524_288;

/// Wire version byte.
pub const RECOVERY_ZK_WIRE_VERSION: u8 = 0;

/// Decoded recovery proof envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryZkProofV0 {
    pub air_id: u8,
    pub public_inputs: RecoveryPolicyPublicInputs,
    pub proof_bytes: Vec<u8>,
}

/// Encode `recovery_zk_proof_v0` envelope.
pub fn encode_recovery_zk_proof_v0(
    air_id: u8,
    public_inputs: &RecoveryPolicyPublicInputs,
    proof_bytes: &[u8],
) -> Result<Vec<u8>, AirError> {
    if proof_bytes.len() > RECOVERY_ZK_MAX_ENVELOPE {
        return Err(AirError::ExceedsMaxSize {
            parameter: "proof_len".into(),
            max: RECOVERY_ZK_MAX_ENVELOPE,
            actual: proof_bytes.len(),
        });
    }
    let public_bytes = public_inputs.encode();
    let mut out = Vec::with_capacity(6 + public_bytes.len() + 4 + proof_bytes.len());
    out.push(RECOVERY_ZK_WIRE_VERSION);
    out.push(air_id);
    out.extend_from_slice(&(RECOVERY_PUBLIC_INPUTS_LEN as u16).to_le_bytes());
    out.extend_from_slice(&public_bytes);
    out.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(proof_bytes);
    if out.len() > RECOVERY_ZK_MAX_ENVELOPE {
        return Err(AirError::ExceedsMaxSize {
            parameter: "envelope".into(),
            max: RECOVERY_ZK_MAX_ENVELOPE,
            actual: out.len(),
        });
    }
    Ok(out)
}

/// Decode `recovery_zk_proof_v0` envelope.
pub fn decode_recovery_zk_proof_v0(bytes: &[u8]) -> Result<RecoveryZkProofV0, AirError> {
    if bytes.len() > RECOVERY_ZK_MAX_ENVELOPE {
        return Err(AirError::ExceedsMaxSize {
            parameter: "envelope".into(),
            max: RECOVERY_ZK_MAX_ENVELOPE,
            actual: bytes.len(),
        });
    }
    if bytes.len() < 6 + RECOVERY_PUBLIC_INPUTS_LEN + 4 {
        return Err(AirError::InvalidInput {
            reason: "envelope too short".into(),
        });
    }
    if bytes[0] != RECOVERY_ZK_WIRE_VERSION {
        return Err(AirError::InvalidInput {
            reason: alloc::format!("unsupported wire_version {}", bytes[0]),
        });
    }
    let air_id = bytes[1];
    if air_id != RECOVERY_POLICY_AIR_ID {
        return Err(AirError::InvalidInput {
            reason: alloc::format!("unsupported air_id {air_id}"),
        });
    }
    let public_len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    if public_len != RECOVERY_PUBLIC_INPUTS_LEN {
        return Err(AirError::InvalidInput {
            reason: alloc::format!("public_inputs_len must be {RECOVERY_PUBLIC_INPUTS_LEN}"),
        });
    }
    let public_start = 4;
    let public_end = public_start + public_len;
    let proof_len = u32::from_le_bytes([
        bytes[public_end],
        bytes[public_end + 1],
        bytes[public_end + 2],
        bytes[public_end + 3],
    ]) as usize;
    let proof_start = public_end + 4;
    let proof_end = proof_start + proof_len;
    if bytes.len() != proof_end {
        return Err(AirError::InvalidInput {
            reason: "envelope length mismatch".into(),
        });
    }
    let public_inputs = RecoveryPolicyPublicInputs::decode(&bytes[public_start..public_end])?;
    Ok(RecoveryZkProofV0 {
        air_id,
        public_inputs,
        proof_bytes: bytes[proof_start..proof_end].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_public() -> RecoveryPolicyPublicInputs {
        RecoveryPolicyPublicInputs {
            policy_commitment: [1u8; 32],
            threshold: 2,
            key_count: 2,
            time_lock_min: 0,
            time_lock_max: 86400,
            freshness_epoch: 100,
            crypto_suite_id: 1,
        }
    }

    #[test]
    fn roundtrip() {
        let proof = vec![0xAB; 64];
        let enc =
            encode_recovery_zk_proof_v0(RECOVERY_POLICY_AIR_ID, &sample_public(), &proof).unwrap();
        let dec = decode_recovery_zk_proof_v0(&enc).unwrap();
        assert_eq!(dec.proof_bytes, proof);
        assert_eq!(dec.public_inputs, sample_public());
    }

    #[test]
    fn rejects_oversize() {
        let huge = vec![0u8; RECOVERY_ZK_MAX_ENVELOPE + 1];
        assert!(decode_recovery_zk_proof_v0(&huge).is_err());
    }
}
