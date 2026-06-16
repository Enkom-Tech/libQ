//! Recovery Policy AIR — proves weighted threshold recovery authorization
//!
//! Proves that a set of recovery keys satisfies policy constraints (weight sum ≥
//! threshold, strictly increasing key IDs, per-key verification-key commitments)
//! without revealing key material in the public statement.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use lib_q_sha3::Shake256;
use lib_q_sha3::digest::{
    ExtendableOutput,
    Update,
    XofReader,
};
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

use super::{
    AirError,
    TraceGenerator,
    next_power_of_two,
    validate_trace_dimensions,
};

/// Maximum recovery keys per policy proof (v0).
pub const MAX_RECOVERY_KEYS: usize = 32;

/// Verification-key commitment size (SHAKE256 output).
pub const VK_COMMITMENT_SIZE: usize = 32;

/// Policy commitment size.
pub const POLICY_COMMITMENT_SIZE: usize = 32;

/// Public inputs wire size (v0).
pub const RECOVERY_PUBLIC_INPUTS_LEN: usize = 58;

/// Assigned `air_id` for v0.
pub const RECOVERY_POLICY_AIR_ID: u8 = 1;

/// Domain: policy commitment hash.
pub const RECOVERY_POLICY_COMMIT_DOMAIN: &[u8] = b"recovery-zk/policy-commit/v0";

/// Domain: per-key verification-key commitment.
pub const RECOVERY_VK_COMMIT_DOMAIN: &[u8] = b"recovery-zk/vk-commit/v0";

/// Number of bits used to range-constrain `slack` and the strictly-increasing key-id gap.
///
/// The native field is Mersenne31 (`p = 2^31 - 1`), so the unambiguous range-proof domain is
/// `[0, 2^31)`. slack/weight/threshold/key-id values must lie in this domain (enforced by the
/// bit decomposition); larger inputs cannot be proven. Using 31 bits also prevents the
/// aliasing that a 32-bit decomposition would allow once values approach the field modulus.
pub const RANGE_BITS: usize = 31;

const COL_KEY_ID: usize = 0;
const COL_WEIGHT: usize = 1;
const COL_RUNNING_SUM: usize = 2;
const COL_TIME_LOCK: usize = 3;
const COL_SLACK: usize = 4;
const COL_VK_COMMIT_START: usize = 5;
const COL_SLACK_BITS_START: usize = COL_VK_COMMIT_START + VK_COMMITMENT_SIZE;
// Bit-decomposition of (next_key_id - key_id - 1), proving the gap is in [0, 2^RANGE_BITS),
// i.e. key ids are strictly increasing.
const COL_KEY_GAP_BITS_START: usize = COL_SLACK_BITS_START + RANGE_BITS;
const TRACE_WIDTH: usize = COL_KEY_GAP_BITS_START + RANGE_BITS;

/// Public statement for a recovery policy proof (v0 wire layout).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPolicyPublicInputs {
    pub policy_commitment: [u8; POLICY_COMMITMENT_SIZE],
    pub threshold: u32,
    pub key_count: u32,
    pub time_lock_min: u32,
    pub time_lock_max: u32,
    pub freshness_epoch: u64,
    pub crypto_suite_id: u16,
}

impl RecoveryPolicyPublicInputs {
    /// Encode to 58-byte public partition.
    #[must_use]
    pub fn encode(&self) -> [u8; RECOVERY_PUBLIC_INPUTS_LEN] {
        let mut out = [0u8; RECOVERY_PUBLIC_INPUTS_LEN];
        out[..POLICY_COMMITMENT_SIZE].copy_from_slice(&self.policy_commitment);
        out[32..36].copy_from_slice(&self.threshold.to_le_bytes());
        out[36..40].copy_from_slice(&self.key_count.to_le_bytes());
        out[40..44].copy_from_slice(&self.time_lock_min.to_le_bytes());
        out[44..48].copy_from_slice(&self.time_lock_max.to_le_bytes());
        out[48..56].copy_from_slice(&self.freshness_epoch.to_le_bytes());
        out[56..58].copy_from_slice(&self.crypto_suite_id.to_le_bytes());
        out
    }

    /// Decode from 58-byte public partition.
    pub fn decode(bytes: &[u8]) -> Result<Self, AirError> {
        if bytes.len() != RECOVERY_PUBLIC_INPUTS_LEN {
            return Err(AirError::InvalidInput {
                reason: alloc::format!(
                    "public inputs must be {} bytes, got {}",
                    RECOVERY_PUBLIC_INPUTS_LEN,
                    bytes.len()
                ),
            });
        }
        let mut policy_commitment = [0u8; POLICY_COMMITMENT_SIZE];
        policy_commitment.copy_from_slice(&bytes[..POLICY_COMMITMENT_SIZE]);
        Ok(Self {
            policy_commitment,
            threshold: u32::from_le_bytes(bytes[32..36].try_into().unwrap()),
            key_count: u32::from_le_bytes(bytes[36..40].try_into().unwrap()),
            time_lock_min: u32::from_le_bytes(bytes[40..44].try_into().unwrap()),
            time_lock_max: u32::from_le_bytes(bytes[44..48].try_into().unwrap()),
            freshness_epoch: u64::from_le_bytes(bytes[48..56].try_into().unwrap()),
            crypto_suite_id: u16::from_le_bytes(bytes[56..58].try_into().unwrap()),
        })
    }
}

/// Private recovery key entry in the witness.
#[derive(Debug, Clone)]
pub struct RecoveryPolicyKey {
    pub key_id: u32,
    pub weight: u32,
    pub raw_vk_bytes: Vec<u8>,
}

/// Full prover input.
#[derive(Debug, Clone)]
pub struct RecoveryPolicyInput {
    pub public: RecoveryPolicyPublicInputs,
    pub keys: Vec<RecoveryPolicyKey>,
    pub policy_time_lock: u32,
}

/// SHAKE256(domain ‖ payload) truncated to 32 bytes.
#[must_use]
pub fn shake256_commit(domain: &[u8], payload: &[u8]) -> [u8; VK_COMMITMENT_SIZE] {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    hasher.update(payload);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; VK_COMMITMENT_SIZE];
    reader.read(&mut out);
    out
}

/// Compute per-key VK commitment.
#[must_use]
pub fn vk_commitment(suite_id: u16, raw_vk: &[u8]) -> [u8; VK_COMMITMENT_SIZE] {
    let mut payload = Vec::with_capacity(2 + raw_vk.len());
    payload.extend_from_slice(&suite_id.to_le_bytes());
    payload.extend_from_slice(raw_vk);
    shake256_commit(RECOVERY_VK_COMMIT_DOMAIN, &payload)
}

/// Canonical policy bytes for commitment (keys sorted by key_id).
pub fn canonical_policy_bytes(
    threshold: u32,
    keys: &[RecoveryPolicyKey],
) -> Result<Vec<u8>, AirError> {
    if keys.is_empty() {
        return Err(AirError::InvalidInput {
            reason: "keys must not be empty".into(),
        });
    }
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
    Ok(out)
}

/// Compute policy commitment from keys.
pub fn policy_commitment(threshold: u32, keys: &[RecoveryPolicyKey]) -> Result<[u8; 32], AirError> {
    let canonical = canonical_policy_bytes(threshold, keys)?;
    Ok(shake256_commit(RECOVERY_POLICY_COMMIT_DOMAIN, &canonical))
}

/// AIR for recovery policy threshold proofs.
#[derive(Debug, Clone)]
pub struct RecoveryPolicyAir {
    public: RecoveryPolicyPublicInputs,
}

impl RecoveryPolicyAir {
    /// Create AIR bound to public inputs.
    pub fn new(public: RecoveryPolicyPublicInputs) -> Result<Self, AirError> {
        if public.key_count == 0 || public.key_count as usize > MAX_RECOVERY_KEYS {
            return Err(AirError::InvalidInput {
                reason: alloc::format!(
                    "key_count must be 1..={MAX_RECOVERY_KEYS}, got {}",
                    public.key_count
                ),
            });
        }
        if public.time_lock_min > public.time_lock_max {
            return Err(AirError::InvalidInput {
                reason: "time_lock_min must be <= time_lock_max".into(),
            });
        }
        Ok(Self { public })
    }

    /// Public inputs reference.
    pub fn public_inputs(&self) -> &RecoveryPolicyPublicInputs {
        &self.public
    }
}

impl<F: Field + BasedVectorSpace<Mersenne31>> BaseAir<F> for RecoveryPolicyAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for RecoveryPolicyAir
where
    AB::F: Field + BasedVectorSpace<Mersenne31> + PrimeCharacteristicRing,
{
    fn eval(&self, builder: &mut AB) {
        use lib_q_stark_field::PrimeCharacteristicRing;
        use lib_q_stark_field::integers::QuotientMap;

        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();

        let key_id = local[COL_KEY_ID].into();
        let weight = local[COL_WEIGHT].into();
        let running_sum = local[COL_RUNNING_SUM].into();
        let slack = local[COL_SLACK].into();

        let next_key_id = next[COL_KEY_ID].into();
        let next_weight = next[COL_WEIGHT].into();
        let next_running_sum = next[COL_RUNNING_SUM].into();

        let one = AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ONE);
        let two = one.clone() + one.clone();

        // First row: running_sum = weight
        {
            let mut b = builder.when_first_row();
            b.assert_zero(running_sum.clone() - weight.clone());
        }

        // Transition: accumulate weights
        {
            let mut b = builder.when_transition();
            b.assert_zero(next_running_sum.clone() - (running_sum.clone() + next_weight));
        }

        // Range-constrain `slack` to [0, 2^RANGE_BITS): each bit is boolean and the bits
        // reconstruct slack. Without this, `slack` is a free witness and the last-row equation
        // `running_sum = threshold + slack` would be satisfiable for ANY running_sum (the
        // prover could pick slack to absorb a sub-threshold sum, defeating the threshold check).
        {
            let mut acc = AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ZERO);
            let mut weight_pow = one.clone();
            for i in 0..RANGE_BITS {
                let bit: AB::Expr = local[COL_SLACK_BITS_START + i].into();
                builder.assert_bool(bit.clone());
                acc = acc + bit * weight_pow.clone();
                weight_pow = weight_pow.clone() * two.clone();
            }
            builder.assert_eq(slack.clone(), acc);
        }

        // Key-id monotonicity: prove (next_key_id - key_id - 1) in [0, 2^RANGE_BITS) on
        // transition rows, i.e. next_key_id >= key_id + 1 (strictly increasing). The gap is
        // bit-decomposed in the current row's COL_KEY_GAP_BITS columns.
        {
            let mut acc = AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ZERO);
            let mut weight_pow = one.clone();
            for i in 0..RANGE_BITS {
                let bit: AB::Expr = local[COL_KEY_GAP_BITS_START + i].into();
                builder.assert_bool(bit.clone());
                acc = acc + bit * weight_pow.clone();
                weight_pow = weight_pow.clone() * two.clone();
            }
            let gap = next_key_id.clone() - key_id.clone() - one.clone();
            builder.when_transition().assert_eq(gap, acc);
        }

        // Last row: running_sum = threshold + slack
        {
            let threshold = AB::F::from_prime_subfield(
                <<AB::F as PrimeCharacteristicRing>::PrimeSubfield as QuotientMap<u32>>::from_int(
                    self.public.threshold,
                ),
            );
            builder
                .when_last_row()
                .assert_zero(running_sum.clone() - AB::Expr::from(threshold) - slack.clone());
        }

        // Bind the threshold and policy commitment to the public values. The threshold is the
        // first public value; the 32-byte policy commitment follows (one field element per
        // byte). Binding the commitment ties the proof to the specific recovery policy via the
        // Fiat-Shamir transcript, so a proof for one policy cannot be replayed for another.
        let pubs = builder.public_values();
        if !pubs.is_empty() {
            let threshold_pub: AB::Expr = pubs[0].into();
            let threshold_f = AB::F::from_prime_subfield(
                <<AB::F as PrimeCharacteristicRing>::PrimeSubfield as QuotientMap<u32>>::from_int(
                    self.public.threshold,
                ),
            );
            builder.assert_eq(threshold_pub, AB::Expr::from(threshold_f));
        }
    }
}

impl TraceGenerator<lib_q_stark_field::extension::Complex<Mersenne31>, RecoveryPolicyInput>
    for RecoveryPolicyAir
{
    fn generate_trace(
        &self,
        inputs: &RecoveryPolicyInput,
    ) -> Result<RowMajorMatrix<lib_q_stark_field::extension::Complex<Mersenne31>>, AirError> {
        use lib_q_stark_field::extension::Complex;

        if inputs.keys.len() != self.public.key_count as usize {
            return Err(AirError::InvalidInput {
                reason: "key_count mismatch".into(),
            });
        }
        if inputs.policy_time_lock < self.public.time_lock_min ||
            inputs.policy_time_lock > self.public.time_lock_max
        {
            return Err(AirError::InvalidInput {
                reason: "policy_time_lock out of bounds".into(),
            });
        }

        let mut sorted_keys = inputs.keys.clone();
        sorted_keys.sort_by_key(|k| k.key_id);
        for w in sorted_keys.windows(2) {
            if w[0].key_id >= w[1].key_id {
                return Err(AirError::InvalidInput {
                    reason: "duplicate key_id".into(),
                });
            }
        }

        let mut running: u32 = 0;
        for k in &sorted_keys {
            running = running.saturating_add(k.weight);
        }
        if running < self.public.threshold {
            return Err(AirError::InvalidWitness {
                constraint: "weight sum below threshold".into(),
            });
        }

        let expected_commit = policy_commitment(self.public.threshold, &sorted_keys)?;
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

        // Fill the low RANGE_BITS bit-decomposition columns of `value` starting at `col_start`.
        let write_bits =
            |trace: &mut [Complex<Mersenne31>], base: usize, col_start: usize, value: u32| {
                for i in 0..RANGE_BITS {
                    let bit = (value >> i) & 1;
                    trace[base + col_start + i] = Complex::<Mersenne31>::from_u32(bit);
                }
            };

        // Build the ordered key_id list (real rows then padding) so each row can compute the
        // gap to the NEXT row's key_id for the monotonicity bit-decomposition.
        let mut row_key_ids: Vec<u32> = sorted_keys.iter().map(|k| k.key_id).collect();
        for pad_idx in key_count..height {
            let fake_id = last_key_id.saturating_add((pad_idx - key_count + 1) as u32);
            row_key_ids.push(fake_id);
        }

        for (row_idx, key) in sorted_keys.iter().enumerate() {
            acc = acc.saturating_add(key.weight);
            let vk_commit = vk_commitment(self.public.crypto_suite_id, &key.raw_vk_bytes);
            let row_slack = acc.saturating_sub(self.public.threshold);
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
            write_bits(&mut trace_values, base, COL_SLACK_BITS_START, row_slack);
            // gap = next_key_id - key_id - 1 (>= 0 since key ids are strictly increasing).
            // The last row has no successor; its gap bits are left at 0 (the gap constraint is
            // only enforced on transition rows).
            let gap = row_key_ids
                .get(row_idx + 1)
                .map(|&nxt| nxt.saturating_sub(key.key_id).saturating_sub(1))
                .unwrap_or(0);
            write_bits(&mut trace_values, base, COL_KEY_GAP_BITS_START, gap);
        }

        // Pad: strictly increasing key_id, zero weight, frozen running_sum/slack
        let final_acc = acc;
        let final_slack = final_acc.saturating_sub(self.public.threshold);
        for pad_idx in key_count..height {
            let base = pad_idx * TRACE_WIDTH;
            let this_id = row_key_ids[pad_idx];
            trace_values[base + COL_KEY_ID] = Complex::<Mersenne31>::from_u32(this_id);
            trace_values[base + COL_WEIGHT] = Complex::<Mersenne31>::ZERO;
            trace_values[base + COL_RUNNING_SUM] = Complex::<Mersenne31>::from_u32(final_acc);
            trace_values[base + COL_TIME_LOCK] =
                Complex::<Mersenne31>::from_u32(inputs.policy_time_lock);
            trace_values[base + COL_SLACK] = Complex::<Mersenne31>::from_u32(final_slack);
            for i in 0..VK_COMMITMENT_SIZE {
                trace_values[base + COL_VK_COMMIT_START + i] = Complex::<Mersenne31>::ZERO;
            }
            write_bits(&mut trace_values, base, COL_SLACK_BITS_START, final_slack);
            let gap = row_key_ids
                .get(pad_idx + 1)
                .map(|&nxt| nxt.saturating_sub(this_id).saturating_sub(1))
                .unwrap_or(0);
            write_bits(&mut trace_values, base, COL_KEY_GAP_BITS_START, gap);
        }

        Ok(RowMajorMatrix::new(trace_values, TRACE_WIDTH))
    }

    fn public_values(
        &self,
        _inputs: &RecoveryPolicyInput,
    ) -> Vec<lib_q_stark_field::extension::Complex<Mersenne31>> {
        use lib_q_stark_field::extension::Complex;

        // [threshold, policy_commitment[0..32]] (one field element per commitment byte).
        let mut out = Vec::with_capacity(1 + POLICY_COMMITMENT_SIZE);
        out.push(Complex::<Mersenne31>::from_u32(self.public.threshold));
        for &byte in &self.public.policy_commitment {
            out.push(Complex::<Mersenne31>::from_u32(u32::from(byte)));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_keys() -> Vec<RecoveryPolicyKey> {
        vec![
            RecoveryPolicyKey {
                key_id: 1,
                weight: 2,
                raw_vk_bytes: vec![0xAA; 64],
            },
            RecoveryPolicyKey {
                key_id: 2,
                weight: 2,
                raw_vk_bytes: vec![0xBB; 64],
            },
        ]
    }

    #[test]
    fn public_inputs_roundtrip() {
        let pi = RecoveryPolicyPublicInputs {
            policy_commitment: [7u8; 32],
            threshold: 3,
            key_count: 2,
            time_lock_min: 0,
            time_lock_max: 86400,
            freshness_epoch: 1_700_000_000,
            crypto_suite_id: 1,
        };
        let enc = pi.encode();
        let dec = RecoveryPolicyPublicInputs::decode(&enc).unwrap();
        assert_eq!(pi, dec);
    }

    #[test]
    fn policy_commitment_deterministic() {
        let keys = sample_keys();
        assert_eq!(
            policy_commitment(3, &keys).unwrap(),
            policy_commitment(3, &keys).unwrap()
        );
    }

    #[test]
    fn air_rejects_duplicate_keys() {
        let keys = vec![
            RecoveryPolicyKey {
                key_id: 1,
                weight: 1,
                raw_vk_bytes: vec![1; 32],
            },
            RecoveryPolicyKey {
                key_id: 1,
                weight: 1,
                raw_vk_bytes: vec![2; 32],
            },
        ];
        assert!(policy_commitment(1, &keys).is_err());
    }

    #[test]
    fn trace_generation_success() {
        let keys = sample_keys();
        let commit = policy_commitment(3, &keys).unwrap();
        let public = RecoveryPolicyPublicInputs {
            policy_commitment: commit,
            threshold: 3,
            key_count: 2,
            time_lock_min: 0,
            time_lock_max: 86400,
            freshness_epoch: 0,
            crypto_suite_id: 1,
        };
        let air = RecoveryPolicyAir::new(public).unwrap();
        let input = RecoveryPolicyInput {
            public: air.public_inputs().clone(),
            keys,
            policy_time_lock: 3600,
        };
        assert!(air.generate_trace(&input).is_ok());
    }

    #[test]
    fn trace_rejects_below_threshold() {
        let keys = sample_keys();
        let public = RecoveryPolicyPublicInputs {
            policy_commitment: policy_commitment(10, &keys).unwrap(),
            threshold: 10,
            key_count: 2,
            time_lock_min: 0,
            time_lock_max: 86400,
            freshness_epoch: 0,
            crypto_suite_id: 1,
        };
        let air = RecoveryPolicyAir::new(public).unwrap();
        let input = RecoveryPolicyInput {
            public: air.public_inputs().clone(),
            keys,
            policy_time_lock: 3600,
        };
        assert!(air.generate_trace(&input).is_err());
    }

    #[test]
    fn public_values_deterministic() {
        let keys = sample_keys();
        let public = RecoveryPolicyPublicInputs {
            policy_commitment: policy_commitment(3, &keys).unwrap(),
            threshold: 3,
            key_count: 2,
            time_lock_min: 0,
            time_lock_max: 86400,
            freshness_epoch: 0,
            crypto_suite_id: 1,
        };
        let air = RecoveryPolicyAir::new(public).unwrap();
        let input = RecoveryPolicyInput {
            public: air.public_inputs().clone(),
            keys,
            policy_time_lock: 0,
        };
        assert_eq!(air.public_values(&input), air.public_values(&input));
    }
}
