//! Recovery policy hybrid STARK proof wire envelope (v1).

extern crate alloc;

use alloc::vec::Vec;

use crate::air::AirError;
use crate::air::recovery_policy_hybrid::{
    RECOVERY_HYBRID_PUBLIC_INPUTS_LEN,
    RECOVERY_POLICY_HYBRID_AIR_ID,
    RecoveryPolicyHybridPublicInputs,
};
use crate::wire::RECOVERY_ZK_MAX_ENVELOPE;

/// Wire version byte for hybrid v1.
pub const RECOVERY_ZK_WIRE_VERSION_V1: u8 = 1;

/// Decoded hybrid recovery proof envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryZkProofV1 {
    pub air_id: u8,
    pub public_inputs: RecoveryPolicyHybridPublicInputs,
    pub proof_bytes: Vec<u8>,
}

pub fn encode_recovery_zk_proof_v1(
    air_id: u8,
    public_inputs: &RecoveryPolicyHybridPublicInputs,
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
    out.push(RECOVERY_ZK_WIRE_VERSION_V1);
    out.push(air_id);
    out.extend_from_slice(&(RECOVERY_HYBRID_PUBLIC_INPUTS_LEN as u16).to_le_bytes());
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

pub fn decode_recovery_zk_proof_v1(bytes: &[u8]) -> Result<RecoveryZkProofV1, AirError> {
    if bytes.len() > RECOVERY_ZK_MAX_ENVELOPE {
        return Err(AirError::ExceedsMaxSize {
            parameter: "envelope".into(),
            max: RECOVERY_ZK_MAX_ENVELOPE,
            actual: bytes.len(),
        });
    }
    if bytes.len() < 6 + RECOVERY_HYBRID_PUBLIC_INPUTS_LEN + 4 {
        return Err(AirError::InvalidInput {
            reason: "envelope too short".into(),
        });
    }
    if bytes[0] != RECOVERY_ZK_WIRE_VERSION_V1 {
        return Err(AirError::InvalidInput {
            reason: alloc::format!("unsupported wire_version {}", bytes[0]),
        });
    }
    let air_id = bytes[1];
    if air_id != RECOVERY_POLICY_HYBRID_AIR_ID {
        return Err(AirError::InvalidInput {
            reason: alloc::format!("unsupported air_id {air_id}"),
        });
    }
    let public_len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    if public_len != RECOVERY_HYBRID_PUBLIC_INPUTS_LEN {
        return Err(AirError::InvalidInput {
            reason: alloc::format!("public_inputs_len must be {RECOVERY_HYBRID_PUBLIC_INPUTS_LEN}"),
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
    // See `recovery_proof_v0.rs`: `proof_len` is an unvalidated wire `u32`, so on a 32-bit target
    // this add can overflow (`overflow-checks` panic / silent wrap).
    let proof_end = proof_start
        .checked_add(proof_len)
        .ok_or_else(|| AirError::InvalidInput {
            reason: "proof_len overflows usize".into(),
        })?;
    if bytes.len() != proof_end {
        return Err(AirError::InvalidInput {
            reason: "envelope length mismatch".into(),
        });
    }
    let public_inputs = RecoveryPolicyHybridPublicInputs::decode(&bytes[public_start..public_end])?;
    Ok(RecoveryZkProofV1 {
        air_id,
        public_inputs,
        proof_bytes: bytes[proof_start..proof_end].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_public() -> RecoveryPolicyHybridPublicInputs {
        RecoveryPolicyHybridPublicInputs {
            policy_commitment: [3u8; 32],
            threshold: 2,
            zk_key_count: 2,
            time_lock_min: 0,
            time_lock_max: 86400,
            freshness_epoch: 100,
            crypto_suite_id: 1,
            cleartext_key_count: 1,
            cleartext_weight_sum: 1,
        }
    }

    #[test]
    fn roundtrip() {
        let proof = alloc::vec![0xCD; 32];
        let enc =
            encode_recovery_zk_proof_v1(RECOVERY_POLICY_HYBRID_AIR_ID, &sample_public(), &proof)
                .unwrap();
        let dec = decode_recovery_zk_proof_v1(&enc).unwrap();
        assert_eq!(dec.proof_bytes, proof);
        assert_eq!(dec.public_inputs, sample_public());
    }

    /// F4 regression (v1 arm) — see `recovery_proof_v0.rs`'s copy of this test. Only RED on a
    /// 32-bit target (`wasm32-wasip1`), where `proof_start + u32::MAX` overflows `usize`.
    #[test]
    fn rejects_proof_len_that_overflows_usize() {
        let mut enc = encode_recovery_zk_proof_v1(
            RECOVERY_POLICY_HYBRID_AIR_ID,
            &sample_public(),
            &[0xCD; 8],
        )
        .unwrap();
        let public_end = 4 + RECOVERY_HYBRID_PUBLIC_INPUTS_LEN;
        enc[public_end..public_end + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            decode_recovery_zk_proof_v1(&enc).is_err(),
            "u32::MAX proof_len must be rejected, not added unchecked"
        );
    }
}
