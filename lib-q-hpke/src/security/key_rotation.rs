//! Key rotation policies for HPKE
//!
//! This module provides key rotation mechanisms to enhance forward secrecy
//! and limit the impact of key compromise.

#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
use std::time::{
    Duration,
    SystemTime,
    UNIX_EPOCH,
};

use crate::error::HpkeError;
use crate::security::CryptoRng;

/// Key rotation policy configuration
#[derive(Debug, Clone)]
pub struct KeyRotationPolicy {
    /// Maximum number of messages before key rotation
    pub max_messages: u64,
    /// Maximum time duration before key rotation (in seconds)
    pub max_duration_secs: u64,
    /// Maximum data volume before key rotation (in bytes)
    pub max_data_bytes: u64,
    /// Whether to enforce strict rotation (fail if limits exceeded)
    pub strict_enforcement: bool,
}

impl Default for KeyRotationPolicy {
    fn default() -> Self {
        Self {
            max_messages: 1000,          // Rotate after 1000 messages
            max_duration_secs: 3600,     // Rotate after 1 hour
            max_data_bytes: 1024 * 1024, // Rotate after 1 MB
            strict_enforcement: true,
        }
    }
}

/// Key rotation state tracker
#[derive(Debug, Clone)]
pub struct KeyRotationState {
    /// Number of messages processed with current key
    pub message_count: u64,
    /// Timestamp when key was created (seconds since UNIX epoch)
    pub key_creation_time: u64,
    /// Total bytes processed with current key
    pub data_bytes_processed: u64,
    /// Whether rotation is required
    pub rotation_required: bool,
}

impl KeyRotationState {
    /// Create a new key rotation state
    pub fn new() -> Self {
        Self {
            message_count: 0,
            key_creation_time: current_timestamp(),
            data_bytes_processed: 0,
            rotation_required: false,
        }
    }

    /// Update state after processing a message
    pub fn update_after_message(&mut self, message_size: usize, policy: &KeyRotationPolicy) {
        self.message_count += 1;
        self.data_bytes_processed += message_size as u64;

        self.check_rotation_needed(policy);
    }

    /// Check if key rotation is needed based on policy
    pub fn check_rotation_needed(&mut self, policy: &KeyRotationPolicy) {
        let current_time = current_timestamp();
        let elapsed_time = current_time.saturating_sub(self.key_creation_time);

        self.rotation_required = self.message_count >= policy.max_messages ||
            elapsed_time >= policy.max_duration_secs ||
            self.data_bytes_processed >= policy.max_data_bytes;
    }

    /// Reset state after key rotation
    pub fn reset_after_rotation(&mut self) {
        self.message_count = 0;
        self.key_creation_time = current_timestamp();
        self.data_bytes_processed = 0;
        self.rotation_required = false;
    }

    /// Check if operation should be allowed based on policy
    pub fn should_allow_operation(&self, policy: &KeyRotationPolicy) -> Result<(), HpkeError> {
        if self.rotation_required && policy.strict_enforcement {
            return Err(HpkeError::CryptoError(
                "Key rotation required before processing more messages".into(),
            ));
        }
        Ok(())
    }
}

impl Default for KeyRotationState {
    fn default() -> Self {
        Self::new()
    }
}

/// Key rotation manager for HPKE contexts
pub struct KeyRotationManager {
    policy: KeyRotationPolicy,
    sender_state: KeyRotationState,
    receiver_state: KeyRotationState,
}

impl KeyRotationManager {
    /// Create a new key rotation manager
    pub fn new(policy: KeyRotationPolicy) -> Self {
        Self {
            policy,
            sender_state: KeyRotationState::new(),
            receiver_state: KeyRotationState::new(),
        }
    }

    /// Update sender state after sending a message
    pub fn update_sender_state(&mut self, message_size: usize) -> Result<(), HpkeError> {
        self.sender_state.should_allow_operation(&self.policy)?;
        self.sender_state
            .update_after_message(message_size, &self.policy);
        Ok(())
    }

    /// Update receiver state after receiving a message
    pub fn update_receiver_state(&mut self, message_size: usize) -> Result<(), HpkeError> {
        self.receiver_state.should_allow_operation(&self.policy)?;
        self.receiver_state
            .update_after_message(message_size, &self.policy);
        Ok(())
    }

    /// Check if sender key rotation is needed
    pub fn is_sender_rotation_needed(&self) -> bool {
        self.sender_state.rotation_required
    }

    /// Check if receiver key rotation is needed
    pub fn is_receiver_rotation_needed(&self) -> bool {
        self.receiver_state.rotation_required
    }

    /// Reset sender state after key rotation
    pub fn reset_sender_state(&mut self) {
        self.sender_state.reset_after_rotation();
    }

    /// Reset receiver state after key rotation
    pub fn reset_receiver_state(&mut self) {
        self.receiver_state.reset_after_rotation();
    }

    /// Get current policy
    pub fn policy(&self) -> &KeyRotationPolicy {
        &self.policy
    }

    /// Update policy
    pub fn update_policy(&mut self, new_policy: KeyRotationPolicy) {
        self.policy = new_policy;
        // Re-check rotation requirements with new policy
        self.sender_state.check_rotation_needed(&self.policy);
        self.receiver_state.check_rotation_needed(&self.policy);
    }
}

/// Generate a secure random key rotation schedule
pub fn generate_rotation_schedule(
    base_policy: &KeyRotationPolicy,
    randomness_factor: f64,
    rng: &mut dyn CryptoRng,
) -> Result<KeyRotationPolicy, HpkeError> {
    if !(0.0..=1.0).contains(&randomness_factor) {
        return Err(HpkeError::CryptoError(
            "Randomness factor must be between 0.0 and 1.0".into(),
        ));
    }

    let mut random_bytes = [0u8; 12]; // 3 * 4 bytes for 3 u32 values
    rng.fill_bytes(&mut random_bytes)?;

    // Convert bytes to u32 values for randomization
    let rand1 = u32::from_le_bytes([
        random_bytes[0],
        random_bytes[1],
        random_bytes[2],
        random_bytes[3],
    ]);
    let rand2 = u32::from_le_bytes([
        random_bytes[4],
        random_bytes[5],
        random_bytes[6],
        random_bytes[7],
    ]);
    let rand3 = u32::from_le_bytes([
        random_bytes[8],
        random_bytes[9],
        random_bytes[10],
        random_bytes[11],
    ]);

    // Apply randomization to base policy values
    let max_messages = apply_randomization(base_policy.max_messages, randomness_factor, rand1);
    let max_duration_secs =
        apply_randomization(base_policy.max_duration_secs, randomness_factor, rand2);
    let max_data_bytes = apply_randomization(base_policy.max_data_bytes, randomness_factor, rand3);

    Ok(KeyRotationPolicy {
        max_messages,
        max_duration_secs,
        max_data_bytes,
        strict_enforcement: base_policy.strict_enforcement,
    })
}

/// Apply randomization to a policy value
fn apply_randomization(base_value: u64, randomness_factor: f64, random_u32: u32) -> u64 {
    let variation = (base_value as f64 * randomness_factor) as u64;
    let random_offset = (random_u32 as u64 % (2 * variation + 1)).saturating_sub(variation);
    base_value.saturating_add(random_offset).max(1) // Ensure minimum value of 1
}

/// Get current timestamp (seconds since UNIX epoch)
fn current_timestamp() -> u64 {
    #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
    {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs()
    }
    // wasm32-unknown-unknown lacks a real clock (`SystemTime::now()` panics),
    // and no_std targets have no clock either. Both fall back to a fixed
    // timestamp; in practice an embedder would inject one.
    #[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::test_rng::TestRng;

    #[test]
    fn test_key_rotation_policy_default() {
        let policy = KeyRotationPolicy::default();
        assert_eq!(policy.max_messages, 1000);
        assert_eq!(policy.max_duration_secs, 3600);
        assert_eq!(policy.max_data_bytes, 1024 * 1024);
        assert!(policy.strict_enforcement);
    }

    #[test]
    fn test_key_rotation_state_update() {
        let mut state = KeyRotationState::new();
        let policy = KeyRotationPolicy {
            max_messages: 5,
            max_duration_secs: 3600,
            max_data_bytes: 1000,
            strict_enforcement: true,
        };

        // Should not require rotation initially
        assert!(!state.rotation_required);

        // Update with messages
        for i in 1..=4 {
            state.update_after_message(100, &policy);
            assert_eq!(state.message_count, i);
            assert_eq!(state.data_bytes_processed, i * 100);
        }

        // Should not require rotation yet
        assert!(!state.rotation_required);

        // One more message should trigger rotation
        state.update_after_message(100, &policy);
        assert!(state.rotation_required);
    }

    #[test]
    fn test_key_rotation_manager() {
        let policy = KeyRotationPolicy {
            max_messages: 3,
            max_duration_secs: 3600,
            max_data_bytes: 1000,
            strict_enforcement: false,
        };

        let mut manager = KeyRotationManager::new(policy);

        // Process messages
        for _ in 0..2 {
            assert!(manager.update_sender_state(100).is_ok());
            assert!(!manager.is_sender_rotation_needed());
        }

        // Third message should trigger rotation requirement
        assert!(manager.update_sender_state(100).is_ok());
        assert!(manager.is_sender_rotation_needed());

        // Reset and check
        manager.reset_sender_state();
        assert!(!manager.is_sender_rotation_needed());
    }

    #[test]
    fn test_strict_enforcement() {
        let policy = KeyRotationPolicy {
            max_messages: 2,
            max_duration_secs: 3600,
            max_data_bytes: 1000,
            strict_enforcement: true,
        };

        let mut manager = KeyRotationManager::new(policy);

        // Process messages up to limit
        assert!(manager.update_sender_state(100).is_ok());
        assert!(manager.update_sender_state(100).is_ok());

        // Should require rotation now
        assert!(manager.is_sender_rotation_needed());

        // Next message should fail with strict enforcement
        assert!(manager.update_sender_state(100).is_err());
    }

    #[test]
    fn test_generate_rotation_schedule() {
        let base_policy = KeyRotationPolicy::default();
        let mut rng = TestRng::new();

        let randomized_policy = generate_rotation_schedule(&base_policy, 0.1, &mut rng)
            .expect("Should generate randomized policy");

        // Values should be different but within reasonable range
        assert_ne!(randomized_policy.max_messages, base_policy.max_messages);
        assert!(randomized_policy.max_messages > 0);
        assert!(randomized_policy.max_duration_secs > 0);
        assert!(randomized_policy.max_data_bytes > 0);
    }
}
