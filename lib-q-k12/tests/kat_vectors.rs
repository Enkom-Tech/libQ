//! Known Answer Tests (KATs) for KangarooTwelve
//!
//! These tests validate the KangarooTwelve implementation against known test vectors
//! loaded from external JSON files, following cryptographic testing best practices.

use lib_q_k12::{
    KangarooTwelve, KangarooTwelve256,
    digest::{ExtendableOutput, Update},
};
use serde::{Deserialize, Serialize};

/// KangarooTwelve test vector from JSON file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K12TestVector {
    pub count: u32,
    pub description: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub message_pattern: Option<String>,
    #[serde(default)]
    pub message_length: Option<usize>,
    #[serde(default)]
    pub customization: String,
    #[serde(default)]
    pub customization_pattern: Option<String>,
    #[serde(default)]
    pub customization_length: Option<usize>,
    pub output_length: usize,
    #[serde(default)]
    pub expected: Option<String>,
    #[serde(default)]
    pub expected_prefix: Option<String>,
    #[serde(default)]
    pub expected_suffix: Option<String>,
}

impl K12TestVector {
    /// Generates message bytes based on pattern or direct hex string
    fn get_message_bytes(&self) -> Vec<u8> {
        if let Some(pattern) = &self.message_pattern {
            match pattern.as_str() {
                "range_mod_251" => {
                    let len = self.message_length.unwrap_or(0);
                    (0..len).map(|j| (j % 251) as u8).collect()
                }
                _ => panic!("Unknown message pattern: {}", pattern),
            }
        } else if !self.message.is_empty() {
            hex::decode(&self.message).expect("Invalid hex in message")
        } else {
            vec![]
        }
    }

    /// Generates customization bytes based on pattern or direct hex string
    fn get_customization_bytes(&self) -> Vec<u8> {
        if let Some(pattern) = &self.customization_pattern {
            match pattern.as_str() {
                "range_mod_251" => {
                    let len = self.customization_length.unwrap_or(0);
                    (0..len).map(|j| (j % 251) as u8).collect()
                }
                _ => panic!("Unknown customization pattern: {}", pattern),
            }
        } else if !self.customization.is_empty() {
            hex::decode(&self.customization).expect("Invalid hex in customization")
        } else {
            vec![]
        }
    }

    /// Get expected output as bytes
    pub fn get_expected_output(&self) -> Option<Vec<u8>> {
        self.expected
            .as_ref()
            .map(|hex_str| hex::decode(hex_str).expect("Invalid hex in expected output"))
    }

    /// Get expected prefix as bytes
    pub fn get_expected_prefix(&self) -> Option<Vec<u8>> {
        self.expected_prefix
            .as_ref()
            .map(|hex_str| hex::decode(hex_str).expect("Invalid hex in expected prefix"))
    }

    /// Get expected suffix as bytes
    pub fn get_expected_suffix(&self) -> Option<Vec<u8>> {
        self.expected_suffix
            .as_ref()
            .map(|hex_str| hex::decode(hex_str).expect("Invalid hex in expected suffix"))
    }

    /// Runs the test vector for KT128
    pub fn run_test_kt128(&self) {
        println!("Running KT128 test {}: {}", self.count, self.description);

        let message = self.get_message_bytes();
        let customization = self.get_customization_bytes();

        let mut hasher = KangarooTwelve::new(&customization);
        hasher.update(&message);
        let result = hasher.finalize_boxed(self.output_length);

        if let Some(expected) = self.get_expected_output() {
            assert_eq!(
                result[..],
                expected[..],
                "KT128 test vector {} failed: {}",
                self.count,
                self.description
            );
        }
        if let Some(expected_prefix) = self.get_expected_prefix() {
            assert_eq!(
                result[..expected_prefix.len()],
                expected_prefix[..],
                "KT128 test vector {} prefix failed: {}",
                self.count,
                self.description
            );
        }
        if let Some(expected_suffix) = self.get_expected_suffix() {
            assert_eq!(
                result[result.len() - expected_suffix.len()..],
                expected_suffix[..],
                "KT128 test vector {} suffix failed: {}",
                self.count,
                self.description
            );
        }
    }

    /// Runs the test vector for KT256
    pub fn run_test_kt256(&self) {
        println!("Running KT256 test {}: {}", self.count, self.description);

        let message = self.get_message_bytes();
        let customization = self.get_customization_bytes();

        let mut hasher = KangarooTwelve256::new(&customization);
        hasher.update(&message);
        let result = hasher.finalize_boxed(self.output_length);

        if let Some(expected) = self.get_expected_output() {
            assert_eq!(
                result[..],
                expected[..],
                "KT256 test vector {} failed: {}",
                self.count,
                self.description
            );
        }
        if let Some(expected_prefix) = self.get_expected_prefix() {
            assert_eq!(
                result[..expected_prefix.len()],
                expected_prefix[..],
                "KT256 test vector {} prefix failed: {}",
                self.count,
                self.description
            );
        }
        if let Some(expected_suffix) = self.get_expected_suffix() {
            assert_eq!(
                result[result.len() - expected_suffix.len()..],
                expected_suffix[..],
                "KT256 test vector {} suffix failed: {}",
                self.count,
                self.description
            );
        }
    }
}

/// Container for all KangarooTwelve test vectors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K12TestVectors {
    pub algorithm: String,
    pub source: String,
    pub version: String,
    pub description: String,
    pub vectors: Vec<K12TestVector>,
    #[serde(default)]
    pub checksums: std::collections::HashMap<String, String>,
}

/// Load KT128 test vectors from JSON file
pub fn load_kt128_test_vectors() -> K12TestVectors {
    let json_data = include_str!("data/k12_kt128_vectors.json");
    serde_json::from_str(json_data).expect("Failed to parse KT128 test vectors JSON")
}

/// Load KT256 test vectors from JSON file
pub fn load_kt256_test_vectors() -> K12TestVectors {
    let json_data = include_str!("data/k12_kt256_vectors.json");
    serde_json::from_str(json_data).expect("Failed to parse KT256 test vectors JSON")
}

#[test]
fn test_kt128_official_vectors() {
    let test_vectors = load_kt128_test_vectors();

    println!(
        "Running {} {} test vectors from {} v{}",
        test_vectors.vectors.len(),
        test_vectors.algorithm,
        test_vectors.source,
        test_vectors.version
    );

    for vector in &test_vectors.vectors {
        vector.run_test_kt128();
    }
}

#[test]
fn test_kt256_official_vectors() {
    let test_vectors = load_kt256_test_vectors();

    println!(
        "Running {} {} test vectors from {} v{}",
        test_vectors.vectors.len(),
        test_vectors.algorithm,
        test_vectors.source,
        test_vectors.version
    );

    for vector in &test_vectors.vectors {
        vector.run_test_kt256();
    }
}

#[test]
fn test_kt128_empty_input_vectors() {
    let test_vectors = load_kt128_test_vectors();

    for vector in &test_vectors.vectors {
        if vector.description.contains("empty input") {
            vector.run_test_kt128();
        }
    }
}

#[test]
fn test_kt256_empty_input_vectors() {
    let test_vectors = load_kt256_test_vectors();

    for vector in &test_vectors.vectors {
        if vector.description.contains("empty input") {
            vector.run_test_kt256();
        }
    }
}

#[test]
fn test_kt128_pattern_message_vectors() {
    let test_vectors = load_kt128_test_vectors();

    for vector in &test_vectors.vectors {
        if vector.description.contains("pattern 0x00 to 0xFA")
            && !vector.description.contains("0xFF bytes")
        {
            vector.run_test_kt128();
        }
    }
}

#[test]
fn test_kt256_pattern_message_vectors() {
    let test_vectors = load_kt256_test_vectors();

    for vector in &test_vectors.vectors {
        if vector.description.contains("pattern 0x00 to 0xFA")
            && !vector.description.contains("0xFF bytes")
        {
            vector.run_test_kt256();
        }
    }
}

#[test]
fn test_kt128_customization_vectors() {
    let test_vectors = load_kt128_test_vectors();

    for vector in &test_vectors.vectors {
        if vector.description.contains("0xFF bytes") {
            vector.run_test_kt128();
        }
    }
}

#[test]
fn test_kt256_customization_vectors() {
    let test_vectors = load_kt256_test_vectors();

    for vector in &test_vectors.vectors {
        if vector.description.contains("0xFF bytes") {
            vector.run_test_kt256();
        }
    }
}

#[test]
fn test_kt128_xof_consistency_vectors() {
    let test_vectors = load_kt128_test_vectors();

    for vector in &test_vectors.vectors {
        if vector.description.contains("10032-byte output") {
            vector.run_test_kt128();
        }
    }
}

#[test]
fn test_kt256_xof_consistency_vectors() {
    let test_vectors = load_kt256_test_vectors();

    for vector in &test_vectors.vectors {
        if vector.description.contains("10064-byte output") {
            vector.run_test_kt256();
        }
    }
}

#[test]
#[ignore] // This test is for benchmarking large vectors, not for regular runs
fn benchmark_kt128_large_vectors() {
    let test_vectors = load_kt128_test_vectors();

    for vector in &test_vectors.vectors {
        if vector.message_length.unwrap_or(0) > 10000 {
            let start = std::time::Instant::now();
            vector.run_test_kt128();
            let elapsed = start.elapsed();
            println!(
                "KT128 Vector {}: {} - took {:?}",
                vector.count, vector.description, elapsed
            );
        }
    }
}

#[test]
#[ignore] // This test is for benchmarking large vectors, not for regular runs
fn benchmark_kt256_large_vectors() {
    let test_vectors = load_kt256_test_vectors();

    for vector in &test_vectors.vectors {
        if vector.message_length.unwrap_or(0) > 10000 {
            let start = std::time::Instant::now();
            vector.run_test_kt256();
            let elapsed = start.elapsed();
            println!(
                "KT256 Vector {}: {} - took {:?}",
                vector.count, vector.description, elapsed
            );
        }
    }
}
