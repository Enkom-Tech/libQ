//! Fuzzing support for HPKE implementation
//!
//! This module provides utilities for comprehensive fuzzing to discover
//! potential security vulnerabilities and edge cases.

#[cfg(feature = "alloc")]
use alloc::{
    boxed::Box,
    format,
    string::String,
    vec,
    vec::Vec,
};

use crate::security::CryptoRng;
use crate::types::*;

/// Fuzzing target configuration
#[derive(Debug, Clone)]
pub struct FuzzingConfig {
    /// Maximum input size for fuzzing
    pub max_input_size: usize,
    /// Minimum input size for fuzzing
    pub min_input_size: usize,
    /// Whether to include invalid inputs
    pub include_invalid_inputs: bool,
    /// Whether to test edge cases
    pub test_edge_cases: bool,
    /// Number of iterations per fuzzing session
    pub iterations: usize,
}

impl Default for FuzzingConfig {
    fn default() -> Self {
        Self {
            max_input_size: 4096,
            min_input_size: 0,
            include_invalid_inputs: true,
            test_edge_cases: true,
            iterations: 1000,
        }
    }
}

/// Fuzzing input generator
pub struct FuzzingInputGenerator {
    config: FuzzingConfig,
    rng: Box<dyn CryptoRng>,
}

impl FuzzingInputGenerator {
    /// Create a new fuzzing input generator
    pub fn new(config: FuzzingConfig, rng: Box<dyn CryptoRng>) -> Self {
        Self { config, rng }
    }

    /// Generate random bytes of specified length
    pub fn generate_random_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        let _ = self.rng.fill_bytes(&mut bytes); // Ignore error for fuzzing
        bytes
    }

    /// Generate random key material
    pub fn generate_random_key(&mut self, key_len: usize) -> Vec<u8> {
        self.generate_random_bytes(key_len)
    }

    /// Generate random nonce
    pub fn generate_random_nonce(&mut self, nonce_len: usize) -> Vec<u8> {
        self.generate_random_bytes(nonce_len)
    }

    /// Generate random plaintext
    pub fn generate_random_plaintext(&mut self) -> Vec<u8> {
        let len = self.random_length();
        self.generate_random_bytes(len)
    }

    /// Generate random AAD (Additional Authenticated Data)
    pub fn generate_random_aad(&mut self) -> Vec<u8> {
        let len = self.random_length();
        self.generate_random_bytes(len)
    }

    /// Generate random ciphertext
    pub fn generate_random_ciphertext(&mut self) -> Vec<u8> {
        let len = self.random_length();
        self.generate_random_bytes(len)
    }

    /// Generate edge case inputs
    pub fn generate_edge_case_inputs(&mut self) -> Vec<Vec<u8>> {
        let mut inputs = Vec::new();

        if self.config.test_edge_cases {
            // Empty input
            inputs.push(Vec::new());

            // Single byte inputs
            for i in 0..=255 {
                inputs.push(vec![i]);
            }

            // All zeros
            inputs.push(vec![0u8; 32]);
            inputs.push(vec![0u8; 64]);

            // All ones
            inputs.push(vec![0xFFu8; 32]);
            inputs.push(vec![0xFFu8; 64]);

            // Alternating patterns
            inputs.push(
                (0..32)
                    .map(|i| if i % 2 == 0 { 0x00 } else { 0xFF })
                    .collect(),
            );
            inputs.push((0..64).map(|i| (i % 256) as u8).collect());

            // Maximum size input
            inputs.push(vec![0x42u8; self.config.max_input_size]);
        }

        inputs
    }

    /// Generate invalid inputs for negative testing
    pub fn generate_invalid_inputs(&mut self) -> Vec<Vec<u8>> {
        let mut inputs = Vec::new();

        if self.config.include_invalid_inputs {
            // Oversized inputs
            inputs.push(vec![0u8; self.config.max_input_size + 1]);
            inputs.push(vec![0u8; self.config.max_input_size * 2]);

            // Malformed structures (simulated)
            inputs.push(vec![0xDEu8, 0xAD, 0xBE, 0xEF]); // Magic bytes
            inputs.push(vec![0xFF; 1000]); // Large all-ones
        }

        inputs
    }

    /// Generate a random length within configured bounds
    fn random_length(&mut self) -> usize {
        if self.config.max_input_size == self.config.min_input_size {
            return self.config.min_input_size;
        }

        let mut bytes = [0u8; 4];
        let _ = self.rng.fill_bytes(&mut bytes); // Ignore error for fuzzing
        let random_u32 = u32::from_le_bytes(bytes);

        let range = self.config.max_input_size - self.config.min_input_size;
        self.config.min_input_size + (random_u32 as usize % (range + 1))
    }
}

/// Fuzzing test harness for HPKE operations
pub struct HpkeFuzzingHarness {
    generator: FuzzingInputGenerator,
    results: FuzzingResults,
}

impl HpkeFuzzingHarness {
    /// Create a new fuzzing harness
    pub fn new(config: FuzzingConfig, rng: Box<dyn CryptoRng>) -> Self {
        Self {
            generator: FuzzingInputGenerator::new(config, rng),
            results: FuzzingResults::new(),
        }
    }

    /// Fuzz AEAD seal operation
    pub fn fuzz_aead_seal(&mut self, _aead: HpkeAead) -> FuzzingResults {
        // Use the stored results field instead of creating a new one
        self.results = FuzzingResults::new();

        for _ in 0..self.generator.config.iterations {
            let key = self.generator.generate_random_key(32); // Assume 32-byte key
            let nonce = self.generator.generate_random_nonce(16); // Assume 16-byte nonce
            let plaintext = self.generator.generate_random_plaintext();
            let aad = self.generator.generate_random_aad();

            // This would call the actual AEAD seal function
            // For now, we'll simulate the result
            let result = self.simulate_aead_operation(&key, &nonce, &plaintext, &aad);
            self.results.record_result(result);
        }

        // Test edge cases
        for input in self.generator.generate_edge_case_inputs() {
            let result = self.simulate_aead_operation(&input, &input, &input, &input);
            self.results.record_result(result);
        }

        // Test invalid inputs
        for input in self.generator.generate_invalid_inputs() {
            let result = self.simulate_aead_operation(&input, &input, &input, &input);
            self.results.record_result(result);
        }

        // Return a clone of the results
        self.results.clone()
    }

    /// Fuzz KEM operations
    pub fn fuzz_kem_operations(&mut self, kem: HpkeKem) -> FuzzingResults {
        let mut results = FuzzingResults::new();

        for _ in 0..self.generator.config.iterations {
            let public_key = self.generator.generate_random_key(kem.public_key_len());
            let secret_key = self.generator.generate_random_key(kem.secret_key_len());

            // Simulate KEM operations
            let encap_result = self.simulate_kem_encapsulate(&public_key);
            let decap_result = self.simulate_kem_decapsulate(&secret_key, &public_key);

            results.record_result(encap_result);
            results.record_result(decap_result);
        }

        results
    }

    /// Simulate AEAD operation for fuzzing
    fn simulate_aead_operation(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        _aad: &[u8],
    ) -> FuzzingResult {
        // Basic validation checks that would be performed in real implementation
        if key.is_empty() || nonce.is_empty() {
            return FuzzingResult::Error("Empty key or nonce".into());
        }

        if key.len() != 32 {
            return FuzzingResult::Error("Invalid key length".into());
        }

        if nonce.len() != 16 {
            return FuzzingResult::Error("Invalid nonce length".into());
        }

        if plaintext.len() > 1024 * 1024 {
            return FuzzingResult::Error("Plaintext too large".into());
        }

        FuzzingResult::Success
    }

    /// Simulate KEM encapsulation for fuzzing
    fn simulate_kem_encapsulate(&self, public_key: &[u8]) -> FuzzingResult {
        if public_key.is_empty() {
            return FuzzingResult::Error("Empty public key".into());
        }

        // Simulate validation
        if public_key.iter().all(|&b| b == 0) {
            return FuzzingResult::Error("All-zero public key".into());
        }

        FuzzingResult::Success
    }

    /// Simulate KEM decapsulation for fuzzing
    fn simulate_kem_decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> FuzzingResult {
        if secret_key.is_empty() || ciphertext.is_empty() {
            return FuzzingResult::Error("Empty secret key or ciphertext".into());
        }

        FuzzingResult::Success
    }
}

/// Fuzzing result for individual operations
#[derive(Debug, Clone)]
pub enum FuzzingResult {
    /// Operation completed successfully
    Success,
    /// Operation failed with an error
    Error(String),
    /// Operation caused a panic
    Panic(String),
}

/// Aggregated fuzzing results
#[derive(Debug, Clone)]
pub struct FuzzingResults {
    /// Total number of tests executed
    pub total_tests: usize,
    /// Number of successful operations
    pub successes: usize,
    /// Number of operations that failed with errors
    pub errors: usize,
    /// Number of operations that caused panics
    pub panics: usize,
    /// Collection of error messages from failed operations
    pub error_messages: Vec<String>,
}

impl FuzzingResults {
    /// Create new empty results
    pub fn new() -> Self {
        Self {
            total_tests: 0,
            successes: 0,
            errors: 0,
            panics: 0,
            error_messages: Vec::new(),
        }
    }

    /// Record a fuzzing result
    pub fn record_result(&mut self, result: FuzzingResult) {
        self.total_tests += 1;

        match result {
            FuzzingResult::Success => self.successes += 1,
            FuzzingResult::Error(msg) => {
                self.errors += 1;
                self.error_messages.push(msg);
            }
            FuzzingResult::Panic(msg) => {
                self.panics += 1;
                self.error_messages.push(format!("PANIC: {}", msg));
            }
        }
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        if self.total_tests == 0 {
            return 0.0;
        }
        self.successes as f64 / self.total_tests as f64
    }

    /// Check if any panics occurred
    pub fn has_panics(&self) -> bool {
        self.panics > 0
    }

    /// Get unique error messages
    pub fn unique_errors(&self) -> Vec<String> {
        let mut unique = self.error_messages.clone();
        unique.sort();
        unique.dedup();
        unique
    }
}

impl Default for FuzzingResults {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::test_rng::TestRng;

    #[test]
    fn test_fuzzing_config_default() {
        let config = FuzzingConfig::default();
        assert_eq!(config.max_input_size, 4096);
        assert_eq!(config.min_input_size, 0);
        assert!(config.include_invalid_inputs);
        assert!(config.test_edge_cases);
        assert_eq!(config.iterations, 1000);
    }

    #[test]
    fn test_fuzzing_input_generator() {
        let config = FuzzingConfig::default();
        let rng = Box::new(TestRng::new());
        let mut generator = FuzzingInputGenerator::new(config, rng);

        let key = generator.generate_random_key(32);
        assert_eq!(key.len(), 32);

        let nonce = generator.generate_random_nonce(16);
        assert_eq!(nonce.len(), 16);

        let plaintext = generator.generate_random_plaintext();
        assert!(plaintext.len() <= 4096);
    }

    #[test]
    fn test_edge_case_generation() {
        let config = FuzzingConfig::default();
        let rng = Box::new(TestRng::new());
        let mut generator = FuzzingInputGenerator::new(config, rng);

        let edge_cases = generator.generate_edge_case_inputs();
        assert!(!edge_cases.is_empty());

        // Should include empty input
        assert!(edge_cases.iter().any(|input| input.is_empty()));

        // Should include all-zero inputs
        assert!(edge_cases.iter().any(|input| input.iter().all(|&b| b == 0)));
    }

    #[test]
    fn test_fuzzing_results() {
        let mut results = FuzzingResults::new();

        results.record_result(FuzzingResult::Success);
        results.record_result(FuzzingResult::Error("Test error".into()));
        results.record_result(FuzzingResult::Success);

        assert_eq!(results.total_tests, 3);
        assert_eq!(results.successes, 2);
        assert_eq!(results.errors, 1);
        assert_eq!(results.panics, 0);
        assert_eq!(results.success_rate(), 2.0 / 3.0);
        assert!(!results.has_panics());
    }

    #[test]
    fn test_hpke_fuzzing_harness() {
        let config = FuzzingConfig {
            iterations: 10, // Small number for testing
            ..Default::default()
        };
        let rng = Box::new(TestRng::new());
        let mut harness = HpkeFuzzingHarness::new(config, rng);

        let results = harness.fuzz_aead_seal(HpkeAead::Saturnin256);
        assert!(results.total_tests > 0);
    }
}
