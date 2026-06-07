//! Recovery Policy Hybrid AIR v1 — ZK-private keys + cleartext weight binding.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_field::{
    BasedVectorSpace,
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::Mersenne31;

use super::recovery_policy::{
    RecoveryPolicyKey,
    VK_COMMITMENT_SIZE,
    shake256_commit,
};
use super::{
    AirError,
    TraceGenerator,
    next_power_of_two,
    validate_trace_dimensions,
};

/// Maximum ZK-private recovery keys per hybrid proof.
pub const MAX_RECOVERY_HYBRID_KEYS: usize = 32;

/// Public inputs wire size (v1 hybrid).
pub const RECOVERY_HYBRID_PUBLIC_INPUTS_LEN: usize = 66;

/// Assigned `air_id` for hybrid v1.
pub const RECOVERY_POLICY_HYBRID_AIR_ID: u8 = 2;

/// Domain: hybrid policy commitment hash.
pub const RECOVERY_HYBRID_POLICY_COMMIT_DOMAIN: &[u8] = b"recovery-zk/policy-commit/v1";

/// Domain: per-key verification-key commitment (hybrid).
pub const RECOVERY_HYBRID_VK_COMMIT_DOMAIN: &[u8] = b"recovery-zk/vk-commit/v1";

const COL_KEY_ID: usize = 0;
const COL_WEIGHT: usize = 1;
const COL_RUNNING_SUM: usize = 2;
const COL_TIME_LOCK: usize = 3;
const COL_SLACK: usize = 4;
const COL_VK_COMMIT_START: usize = 5;
const TRACE_WIDTH: usize = COL_VK_COMMIT_START + VK_COMMITMENT_SIZE;

/// Public statement for hybrid recovery policy proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPolicyHybridPublicInputs {
    pub policy_commitment: [u8; 32],
    pub threshold: u32,
    pub zk_key_count: u32,
    pub time_lock_min: u32,
    pub time_lock_max: u32,
    pub freshness_epoch: u64,
    pub crypto_suite_id: u16,
    pub cleartext_key_count: u32,
    pub cleartext_weight_sum: u32,
}

impl RecoveryPolicyHybridPublicInputs {
    #[must_use]
    pub fn encode(&self) -> [u8; RECOVERY_HYBRID_PUBLIC_INPUTS_LEN] {
        let mut out = [0u8; RECOVERY_HYBRID_PUBLIC_INPUTS_LEN];
        out[..32].copy_from_slice(&self.policy_commitment);
        out[32..36].copy_from_slice(&self.threshold.to_le_bytes());
        out[36..40].copy_from_slice(&self.zk_key_count.to_le_bytes());
        out[40..44].copy_from_slice(&self.time_lock_min.to_le_bytes());
        out[44..48].copy_from_slice(&self.time_lock_max.to_le_bytes());
        out[48..56].copy_from_slice(&self.freshness_epoch.to_le_bytes());
        out[56..58].copy_from_slice(&self.crypto_suite_id.to_le_bytes());
        out[58..62].copy_from_slice(&self.cleartext_key_count.to_le_bytes());
        out[62..66].copy_from_slice(&self.cleartext_weight_sum.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AirError> {
        if bytes.len() != RECOVERY_HYBRID_PUBLIC_INPUTS_LEN {
            return Err(AirError::InvalidInput {
                reason: alloc::format!(
                    "hybrid public inputs must be {} bytes",
                    RECOVERY_HYBRID_PUBLIC_INPUTS_LEN
                ),
            });
        }
        let mut policy_commitment = [0u8; 32];
        policy_commitment.copy_from_slice(&bytes[..32]);
        Ok(Self {
            policy_commitment,
            threshold: u32::from_le_bytes(bytes[32..36].try_into().unwrap()),
            zk_key_count: u32::from_le_bytes(bytes[36..40].try_into().unwrap()),
            time_lock_min: u32::from_le_bytes(bytes[40..44].try_into().unwrap()),
            time_lock_max: u32::from_le_bytes(bytes[44..48].try_into().unwrap()),
            freshness_epoch: u64::from_le_bytes(bytes[48..56].try_into().unwrap()),
            crypto_suite_id: u16::from_le_bytes(bytes[56..58].try_into().unwrap()),
            cleartext_key_count: u32::from_le_bytes(bytes[58..62].try_into().unwrap()),
            cleartext_weight_sum: u32::from_le_bytes(bytes[62..66].try_into().unwrap()),
        })
    }
}

/// Full prover input for hybrid policy.
#[derive(Debug, Clone)]
pub struct RecoveryPolicyHybridInput {
    pub public: RecoveryPolicyHybridPublicInputs,
    pub zk_keys: Vec<RecoveryPolicyKey>,
    pub policy_time_lock: u32,
}

pub fn hybrid_policy_commitment(
    threshold: u32,
    keys: &[RecoveryPolicyKey],
) -> Result<[u8; 32], AirError> {
    let mut sorted: Vec<_> = keys.to_vec();
    sorted.sort_by_key(|k| k.key_id);
    for w in sorted.windows(2) {
        if w[0].key_id >= w[1].key_id {
            return Err(AirError::InvalidInput {
                reason: "duplicate or unsorted key_id".into(),
            });
        }
    }
    let mut out = Vec::new();
    out.extend_from_slice(&threshold.to_le_bytes());
    out.extend_from_slice(&(keys.len() as u32).to_le_bytes());
    for k in &sorted {
        out.extend_from_slice(&k.key_id.to_le_bytes());
        out.extend_from_slice(&k.weight.to_le_bytes());
        out.extend_from_slice(&k.raw_vk_bytes);
    }
    Ok(shake256_commit(RECOVERY_HYBRID_POLICY_COMMIT_DOMAIN, &out))
}

fn hybrid_vk_commitment(suite_id: u16, raw_vk: &[u8]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(2 + raw_vk.len());
    payload.extend_from_slice(&suite_id.to_le_bytes());
    payload.extend_from_slice(raw_vk);
    shake256_commit(RECOVERY_HYBRID_VK_COMMIT_DOMAIN, &payload)
}

/// AIR for hybrid recovery policy threshold proofs.
#[derive(Debug, Clone)]
pub struct RecoveryPolicyHybridAir {
    public: RecoveryPolicyHybridPublicInputs,
}

impl RecoveryPolicyHybridAir {
    pub fn new(public: RecoveryPolicyHybridPublicInputs) -> Result<Self, AirError> {
        if public.zk_key_count == 0 || public.zk_key_count as usize > MAX_RECOVERY_HYBRID_KEYS {
            return Err(AirError::InvalidInput {
                reason: alloc::format!("zk_key_count must be 1..={MAX_RECOVERY_HYBRID_KEYS}"),
            });
        }
        if public.time_lock_min > public.time_lock_max {
            return Err(AirError::InvalidInput {
                reason: "time_lock_min must be <= time_lock_max".into(),
            });
        }
        Ok(Self { public })
    }

    pub fn public_inputs(&self) -> &RecoveryPolicyHybridPublicInputs {
        &self.public
    }
}

impl<F: Field + BasedVectorSpace<Mersenne31>> BaseAir<F> for RecoveryPolicyHybridAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for RecoveryPolicyHybridAir
where
    AB::F: Field + BasedVectorSpace<Mersenne31> + PrimeCharacteristicRing,
{
    fn eval(&self, builder: &mut AB) {
        use lib_q_stark_field::PrimeCharacteristicRing;
        use lib_q_stark_field::integers::QuotientMap;

        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();

        let weight = local[COL_WEIGHT].into();
        let running_sum = local[COL_RUNNING_SUM].into();
        let slack = local[COL_SLACK].into();
        let next_weight = next[COL_WEIGHT].into();
        let next_running_sum = next[COL_RUNNING_SUM].into();

        {
            let mut b = builder.when_first_row();
            b.assert_zero(running_sum.clone() - weight.clone());
        }
        {
            let mut b = builder.when_transition();
            b.assert_zero(next_running_sum.clone() - (running_sum.clone() + next_weight));
        }
        {
            let effective_threshold = self
                .public
                .threshold
                .saturating_sub(self.public.cleartext_weight_sum);
            let threshold = AB::F::from_prime_subfield(
                <<AB::F as PrimeCharacteristicRing>::PrimeSubfield as QuotientMap<u32>>::from_int(
                    effective_threshold,
                ),
            );
            builder
                .when_last_row()
                .assert_zero(running_sum - AB::Expr::from(threshold) - slack.clone());
        }
    }
}

impl TraceGenerator<lib_q_stark_field::extension::Complex<Mersenne31>, RecoveryPolicyHybridInput>
    for RecoveryPolicyHybridAir
{
    fn generate_trace(
        &self,
        inputs: &RecoveryPolicyHybridInput,
    ) -> Result<RowMajorMatrix<lib_q_stark_field::extension::Complex<Mersenne31>>, AirError> {
        use lib_q_stark_field::extension::Complex;

        if inputs.zk_keys.len() != self.public.zk_key_count as usize {
            return Err(AirError::InvalidInput {
                reason: "zk_key_count mismatch".into(),
            });
        }
        if inputs.policy_time_lock < self.public.time_lock_min ||
            inputs.policy_time_lock > self.public.time_lock_max
        {
            return Err(AirError::InvalidInput {
                reason: "policy_time_lock out of bounds".into(),
            });
        }

        let mut sorted_keys = inputs.zk_keys.clone();
        sorted_keys.sort_by_key(|k| k.key_id);
        for w in sorted_keys.windows(2) {
            if w[0].key_id >= w[1].key_id {
                return Err(AirError::InvalidInput {
                    reason: "duplicate key_id".into(),
                });
            }
        }

        let mut zk_running: u32 = 0;
        for k in &sorted_keys {
            zk_running = zk_running.saturating_add(k.weight);
        }
        let total = zk_running.saturating_add(self.public.cleartext_weight_sum);
        if total < self.public.threshold {
            return Err(AirError::InvalidWitness {
                constraint: "hybrid weight sum below threshold".into(),
            });
        }

        let expected_commit = hybrid_policy_commitment(self.public.threshold, &sorted_keys)?;
        if expected_commit != self.public.policy_commitment {
            return Err(AirError::InvalidWitness {
                constraint: "policy_commitment mismatch".into(),
            });
        }

        let key_count = sorted_keys.len();
        let height = next_power_of_two(key_count);
        validate_trace_dimensions(TRACE_WIDTH, height)?;

        let mut trace_values = vec![Complex::<Mersenne31>::ZERO; height * TRACE_WIDTH];
        let mut acc: u32 = 0;
        let last_key_id = sorted_keys.last().map(|k| k.key_id).unwrap_or(0);
        let effective_threshold = self
            .public
            .threshold
            .saturating_sub(self.public.cleartext_weight_sum);

        for (row_idx, key) in sorted_keys.iter().enumerate() {
            acc = acc.saturating_add(key.weight);
            let vk_commit = hybrid_vk_commitment(self.public.crypto_suite_id, &key.raw_vk_bytes);
            let row_slack = acc.saturating_sub(effective_threshold);
            let base = row_idx * TRACE_WIDTH;
            trace_values[base + COL_KEY_ID] = Complex::<Mersenne31>::from_u32(key.key_id);
            trace_values[base + COL_WEIGHT] = Complex::<Mersenne31>::from_u32(key.weight);
            trace_values[base + COL_RUNNING_SUM] = Complex::<Mersenne31>::from_u32(acc);
            trace_values[base + COL_TIME_LOCK] =
                Complex::<Mersenne31>::from_u32(inputs.policy_time_lock);
            trace_values[base + COL_SLACK] = Complex::<Mersenne31>::from_u32(row_slack);
            for (i, &byte) in vk_commit.iter().enumerate() {
                trace_values[base + COL_VK_COMMIT_START + i] =
                    Complex::<Mersenne31>::from_u32(u32::from(byte));
            }
        }

        let final_acc = acc;
        let final_slack = final_acc.saturating_sub(effective_threshold);
        for pad_idx in key_count..height {
            let base = pad_idx * TRACE_WIDTH;
            let fake_id = last_key_id.saturating_add((pad_idx - key_count + 1) as u32);
            trace_values[base + COL_KEY_ID] = Complex::<Mersenne31>::from_u32(fake_id);
            trace_values[base + COL_WEIGHT] = Complex::<Mersenne31>::ZERO;
            trace_values[base + COL_RUNNING_SUM] = Complex::<Mersenne31>::from_u32(final_acc);
            trace_values[base + COL_TIME_LOCK] =
                Complex::<Mersenne31>::from_u32(inputs.policy_time_lock);
            trace_values[base + COL_SLACK] = Complex::<Mersenne31>::from_u32(final_slack);
            for i in 0..VK_COMMITMENT_SIZE {
                trace_values[base + COL_VK_COMMIT_START + i] = Complex::<Mersenne31>::ZERO;
            }
        }

        Ok(RowMajorMatrix::new(trace_values, TRACE_WIDTH))
    }

    fn public_values(
        &self,
        _inputs: &RecoveryPolicyHybridInput,
    ) -> Vec<lib_q_stark_field::extension::Complex<Mersenne31>> {
        use lib_q_stark_field::extension::Complex;
        let effective = self
            .public
            .threshold
            .saturating_sub(self.public.cleartext_weight_sum);
        vec![Complex::<Mersenne31>::from_u32(effective)]
    }
}
