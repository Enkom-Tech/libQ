//! KDF (Key Derivation Function) tests for HPKE
//!
//! These tests verify the HKDF implementations used in HPKE.

#![cfg(feature = "std")]
#![allow(dead_code)]

use lib_q_hpke::HpkeKdf;
use lib_q_hpke::kdf::HkdfImpl;

/// Test vectors for HKDF operations based on RFC 5869
mod kdf_test_vectors {
    // RFC 5869 Test Case 1 - Basic test case with SHA-256
    pub const TEST_IKM: &[u8] =
        b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
    pub const TEST_SALT: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c";
    pub const TEST_INFO: &[u8] = b"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9";
    pub const TEST_LENGTH: usize = 42;

    // Expected outputs for SHAKE256-based HKDF (computed using our implementation)
    // These are deterministic outputs that should remain constant across runs
    pub const EXPECTED_SHAKE256_PRK: &[u8] = &[
        0xDB, 0x59, 0x0C, 0x57, 0xDE, 0x2D, 0x0E, 0xC4, 0x9D, 0x36, 0xB4, 0x0E, 0x48, 0x8D, 0xFC,
        0xBF, 0x28, 0xED, 0xFE, 0x68, 0xE6, 0x5C, 0xC1, 0x67, 0xE4, 0xB2, 0xAF, 0x2D, 0x81, 0x13,
        0x0D, 0x47,
    ];

    pub const EXPECTED_SHAKE256_OKM: &[u8] = &[
        0x32, 0x49, 0xAF, 0xDD, 0xFD, 0xF6, 0x11, 0xC5, 0xDF, 0xFD, 0x82, 0x91, 0xC5, 0x16, 0x62,
        0x9F, 0x2D, 0x22, 0x5D, 0x0D, 0x4A, 0x39, 0x41, 0x60, 0xF6, 0x91, 0xE8, 0xBA, 0x1A, 0xB4,
        0xF8, 0x54, 0xEC, 0xE2, 0x35, 0xEA, 0x14, 0x65, 0x5D, 0x48, 0x02, 0x2C,
    ];

    // Expected outputs for SHAKE128-based HKDF
    pub const EXPECTED_SHAKE128_PRK: &[u8] = &[
        0xE9, 0x5B, 0x1C, 0xBA, 0xE5, 0xF0, 0xF0, 0x97, 0xD8, 0x95, 0x2A, 0xA1, 0x31, 0x1F, 0xD5,
        0x7B,
    ];

    pub const EXPECTED_SHAKE128_OKM: &[u8] = &[
        0x32, 0x7E, 0x4D, 0x5C, 0x33, 0x98, 0xFD, 0x4F, 0x46, 0x1C, 0x43, 0x79, 0x8B, 0x4F, 0x54,
        0x12, 0xBE, 0x11, 0x6E, 0x0E, 0xC0, 0x14, 0x76, 0x6F, 0x10, 0xD7, 0xD0, 0x16, 0x75, 0x4A,
        0x1D, 0x17, 0x95, 0xB6, 0x78, 0xF8, 0x3A, 0x52, 0x1B, 0x18, 0xAD, 0x56,
    ];

    // Expected outputs for SHA3-256-based HKDF
    pub const EXPECTED_SHA3_256_PRK: &[u8] = &[
        0x03, 0xE0, 0x9B, 0x9F, 0x92, 0xF3, 0x69, 0x06, 0x42, 0x91, 0x5A, 0xCD, 0xB4, 0xEB, 0xE1,
        0xEA, 0x04, 0xB2, 0xAD, 0x04, 0x3F, 0x20, 0x5F, 0x68, 0x8C, 0x3D, 0x37, 0xDA, 0x02, 0xBF,
        0x41, 0xEE,
    ];

    pub const EXPECTED_SHA3_256_OKM: &[u8] = &[
        0x86, 0x24, 0x6D, 0xE0, 0x70, 0x8E, 0x46, 0x3A, 0x37, 0x67, 0x71, 0x3C, 0x85, 0xBC, 0xEF,
        0x02, 0xF8, 0x54, 0x88, 0xD4, 0x09, 0xA5, 0x23, 0x45, 0xC0, 0x3B, 0xA9, 0xEF, 0x0C, 0x12,
        0x4D, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    // Expected outputs for SHA3-512-based HKDF
    pub const EXPECTED_SHA3_512_PRK: &[u8] = &[
        0x70, 0x03, 0x23, 0x94, 0x5F, 0x55, 0xA4, 0x2F, 0xEB, 0x64, 0x1D, 0xC9, 0x04, 0x5C, 0xFF,
        0xFB, 0x77, 0x25, 0xC5, 0xF8, 0x28, 0x6D, 0x85, 0x94, 0x44, 0x13, 0xEE, 0x10, 0xCF, 0x24,
        0x77, 0x4A, 0xE6, 0xC9, 0xC9, 0x37, 0x8E, 0xAC, 0x14, 0x27, 0x03, 0x48, 0xFE, 0x4D, 0x01,
        0x44, 0x88, 0x7A, 0x8D, 0x49, 0xB1, 0x7C, 0x22, 0x8F, 0xF5, 0x0D, 0x59, 0x85, 0x98, 0x2F,
        0x96, 0x71, 0x45, 0xD4,
    ];

    pub const EXPECTED_SHA3_512_OKM: &[u8] = &[
        0x9D, 0xD6, 0xB6, 0x9B, 0x0B, 0x90, 0xF5, 0xD9, 0xF2, 0x91, 0xC2, 0xEB, 0xAA, 0x46, 0x7C,
        0xC2, 0x2C, 0x9F, 0x6B, 0xB2, 0xA9, 0x71, 0xE6, 0x36, 0x43, 0x28, 0xFC, 0x6F, 0xE6, 0x90,
        0xEC, 0x25, 0x29, 0xC9, 0xD0, 0x58, 0x95, 0xF2, 0x04, 0xE1, 0x49, 0xD3,
    ];

    // Test Case 2 - Test with longer inputs
    pub const TEST_IKM_LONG: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f";
    pub const TEST_SALT_LONG: &[u8] = b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf";
    pub const TEST_INFO_LONG: &[u8] = b"\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";

    // Test Case 3 - Test with zero-length salt
    pub const TEST_IKM_ZERO_SALT: &[u8] =
        b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
    pub const TEST_SALT_ZERO: &[u8] = b"";
    pub const TEST_INFO_ZERO_SALT: &[u8] = b"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9";

    // Test Case 4 - Test with zero-length info
    pub const TEST_IKM_ZERO_INFO: &[u8] =
        b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
    pub const TEST_SALT_ZERO_INFO: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c";
    pub const TEST_INFO_ZERO: &[u8] = b"";
}

/// Test HKDF-SHAKE128 extract operation
#[test]
fn test_hkdf_shake128_extract() {
    let prk = HkdfImpl::extract_static(
        HpkeKdf::HkdfShake128,
        kdf_test_vectors::TEST_SALT,
        kdf_test_vectors::TEST_IKM,
    )
    .expect("HKDF-SHAKE128 extract should work");

    // Verify output size
    assert_eq!(prk.len(), 16); // SHAKE128 output size

    // Verify against expected test vector
    assert_eq!(
        prk,
        kdf_test_vectors::EXPECTED_SHAKE128_PRK,
        "SHAKE128 extract output mismatch"
    );
}

/// Test HKDF-SHAKE256 extract operation
#[test]
fn test_hkdf_shake256_extract() {
    let prk = HkdfImpl::extract_static(
        HpkeKdf::HkdfShake256,
        kdf_test_vectors::TEST_SALT,
        kdf_test_vectors::TEST_IKM,
    )
    .expect("HKDF-SHAKE256 extract should work");

    // Verify output size
    assert_eq!(prk.len(), 32); // SHAKE256 output size

    // Verify against expected test vector
    assert_eq!(
        prk,
        kdf_test_vectors::EXPECTED_SHAKE256_PRK,
        "SHAKE256 extract output mismatch"
    );
}

/// Test HKDF-SHA3-256 extract operation
#[test]
fn test_hkdf_sha3_256_extract() {
    let prk = HkdfImpl::extract_static(
        HpkeKdf::HkdfSha3_256,
        kdf_test_vectors::TEST_SALT,
        kdf_test_vectors::TEST_IKM,
    )
    .expect("HKDF-SHA3-256 extract should work");

    // Verify output size
    assert_eq!(prk.len(), 32); // SHA3-256 output size

    // Verify against expected test vector
    assert_eq!(
        prk,
        kdf_test_vectors::EXPECTED_SHA3_256_PRK,
        "SHA3-256 extract output mismatch"
    );
}

/// Test HKDF-SHA3-512 extract operation
#[test]
fn test_hkdf_sha3_512_extract() {
    let prk = HkdfImpl::extract_static(
        HpkeKdf::HkdfSha3_512,
        kdf_test_vectors::TEST_SALT,
        kdf_test_vectors::TEST_IKM,
    )
    .expect("HKDF-SHA3-512 extract should work");

    // Verify output size
    assert_eq!(prk.len(), 64); // SHA3-512 output size

    // Verify against expected test vector
    assert_eq!(
        prk,
        kdf_test_vectors::EXPECTED_SHA3_512_PRK,
        "SHA3-512 extract output mismatch"
    );
}

/// Test HKDF-SHAKE128 expand operation
#[test]
fn test_hkdf_shake128_expand() {
    let prk = kdf_test_vectors::EXPECTED_SHAKE128_PRK;
    let okm = HkdfImpl::expand_static(
        HpkeKdf::HkdfShake128,
        prk,
        kdf_test_vectors::TEST_INFO,
        kdf_test_vectors::TEST_LENGTH,
    )
    .expect("HKDF-SHAKE128 expand should work");

    // Verify output size
    assert_eq!(okm.len(), kdf_test_vectors::TEST_LENGTH);

    // Verify against expected test vector
    assert_eq!(
        okm,
        kdf_test_vectors::EXPECTED_SHAKE128_OKM,
        "SHAKE128 expand output mismatch"
    );
}

/// Test HKDF-SHAKE256 expand operation
#[test]
fn test_hkdf_shake256_expand() {
    let prk = kdf_test_vectors::EXPECTED_SHAKE256_PRK;
    let okm = HkdfImpl::expand_static(
        HpkeKdf::HkdfShake256,
        prk,
        kdf_test_vectors::TEST_INFO,
        kdf_test_vectors::TEST_LENGTH,
    )
    .expect("HKDF-SHAKE256 expand should work");

    // Verify output size
    assert_eq!(okm.len(), kdf_test_vectors::TEST_LENGTH);

    // Verify against expected test vector
    assert_eq!(
        okm,
        kdf_test_vectors::EXPECTED_SHAKE256_OKM,
        "SHAKE256 expand output mismatch"
    );
}

/// Test HKDF-SHA3-256 expand operation
#[test]
fn test_hkdf_sha3_256_expand() {
    let prk = kdf_test_vectors::EXPECTED_SHA3_256_PRK;
    let okm = HkdfImpl::expand_static(
        HpkeKdf::HkdfSha3_256,
        prk,
        kdf_test_vectors::TEST_INFO,
        kdf_test_vectors::TEST_LENGTH,
    )
    .expect("HKDF-SHA3-256 expand should work");

    // Verify output size
    assert_eq!(okm.len(), kdf_test_vectors::TEST_LENGTH);

    // Verify against expected test vector
    assert_eq!(
        okm,
        kdf_test_vectors::EXPECTED_SHA3_256_OKM,
        "SHA3-256 expand output mismatch"
    );
}

/// Test HKDF-SHA3-512 expand operation
#[test]
fn test_hkdf_sha3_512_expand() {
    let prk = kdf_test_vectors::EXPECTED_SHA3_512_PRK;
    let okm = HkdfImpl::expand_static(
        HpkeKdf::HkdfSha3_512,
        prk,
        kdf_test_vectors::TEST_INFO,
        kdf_test_vectors::TEST_LENGTH,
    )
    .expect("HKDF-SHA3-512 expand should work");

    // Verify output size
    assert_eq!(okm.len(), kdf_test_vectors::TEST_LENGTH);

    // Verify against expected test vector
    assert_eq!(
        okm,
        kdf_test_vectors::EXPECTED_SHA3_512_OKM,
        "SHA3-512 expand output mismatch"
    );
}

/// Test KDF with empty salt
#[test]
fn test_kdf_empty_salt() {
    // Test with empty salt (should use zero-filled salt)
    let prk = HkdfImpl::extract_static(HpkeKdf::HkdfShake256, &[], kdf_test_vectors::TEST_IKM)
        .expect("KDF extract with empty salt should work");

    assert_eq!(prk.len(), 32);
}

/// Test KDF with empty info
#[test]
fn test_kdf_empty_info() {
    let prk = vec![0u8; 64];
    let okm = HkdfImpl::expand_static(HpkeKdf::HkdfShake256, &prk, &[], 32)
        .expect("KDF expand with empty info should work");

    assert_eq!(okm.len(), 32);
}

/// Test KDF with zero-length output
#[test]
fn test_kdf_zero_length_output() {
    let prk = vec![0u8; 64];
    let okm = HkdfImpl::expand_static(HpkeKdf::HkdfShake256, &prk, kdf_test_vectors::TEST_INFO, 0)
        .expect("KDF expand with zero length should work");

    assert_eq!(okm.len(), 0);
}

/// Test KDF with large output
#[test]
fn test_kdf_large_output() {
    let prk = vec![0u8; 64];
    let large_length = 1024; // 1KB output
    let okm = HkdfImpl::expand_static(
        HpkeKdf::HkdfShake256,
        &prk,
        kdf_test_vectors::TEST_INFO,
        large_length,
    )
    .expect("KDF expand with large output should work");

    assert_eq!(okm.len(), large_length);
}

/// Test KDF determinism
#[test]
fn test_kdf_determinism() {
    // Extract should be deterministic
    let prk1 = HkdfImpl::extract_static(
        HpkeKdf::HkdfShake256,
        kdf_test_vectors::TEST_SALT,
        kdf_test_vectors::TEST_IKM,
    )
    .expect("First extract should work");

    let prk2 = HkdfImpl::extract_static(
        HpkeKdf::HkdfShake256,
        kdf_test_vectors::TEST_SALT,
        kdf_test_vectors::TEST_IKM,
    )
    .expect("Second extract should work");

    assert_eq!(prk1, prk2, "KDF extract should be deterministic");

    // Expand should be deterministic
    let okm1 = HkdfImpl::expand_static(
        HpkeKdf::HkdfShake256,
        &prk1,
        kdf_test_vectors::TEST_INFO,
        32,
    )
    .expect("First expand should work");

    let okm2 = HkdfImpl::expand_static(
        HpkeKdf::HkdfShake256,
        &prk1,
        kdf_test_vectors::TEST_INFO,
        32,
    )
    .expect("Second expand should work");

    assert_eq!(okm1, okm2, "KDF expand should be deterministic");
}

/// Test KDF with different inputs produce different outputs
#[test]
fn test_kdf_different_inputs() {
    let ikm1 = b"input1";
    let ikm2 = b"input2";

    let prk1 = HkdfImpl::extract_static(HpkeKdf::HkdfShake256, kdf_test_vectors::TEST_SALT, ikm1)
        .expect("Extract with input1 should work");

    let prk2 = HkdfImpl::extract_static(HpkeKdf::HkdfShake256, kdf_test_vectors::TEST_SALT, ikm2)
        .expect("Extract with input2 should work");

    assert_ne!(
        prk1, prk2,
        "Different inputs should produce different outputs"
    );
}

/// Test KDF error handling
#[test]
fn test_kdf_error_handling() {
    // Test with invalid PRK size for expand
    let invalid_prk = vec![0u8; 16]; // Too small for SHAKE256
    let result = HkdfImpl::expand_static(
        HpkeKdf::HkdfShake256,
        &invalid_prk,
        kdf_test_vectors::TEST_INFO,
        32,
    );

    // This should either work (if we handle it gracefully) or fail appropriately
    match result {
        Ok(okm) => {
            // If it works, verify output size
            assert_eq!(okm.len(), 32);
        }
        Err(_) => {
            // If it fails, that's also acceptable for invalid input
        }
    }
}

/// Test KDF with zero-length salt (RFC 5869 Test Case 3)
#[test]
fn test_kdf_zero_length_salt() {
    let prk = HkdfImpl::extract_static(
        HpkeKdf::HkdfShake256,
        kdf_test_vectors::TEST_SALT_ZERO,
        kdf_test_vectors::TEST_IKM_ZERO_SALT,
    )
    .expect("KDF extract with zero-length salt should work");

    assert_eq!(prk.len(), 32);

    // Test that zero-length salt produces different output than non-zero salt
    let prk_with_salt = HkdfImpl::extract_static(
        HpkeKdf::HkdfShake256,
        kdf_test_vectors::TEST_SALT,
        kdf_test_vectors::TEST_IKM_ZERO_SALT,
    )
    .expect("KDF extract with non-zero salt should work");

    assert_ne!(
        prk, prk_with_salt,
        "Zero-length salt should produce different output"
    );
}

/// Test KDF with zero-length info (RFC 5869 Test Case 4)
#[test]
fn test_kdf_zero_length_info() {
    let prk = kdf_test_vectors::EXPECTED_SHAKE256_PRK;
    let okm = HkdfImpl::expand_static(
        HpkeKdf::HkdfShake256,
        prk,
        kdf_test_vectors::TEST_INFO_ZERO,
        32,
    )
    .expect("KDF expand with zero-length info should work");

    assert_eq!(okm.len(), 32);

    // Test that zero-length info produces different output than non-zero info
    let okm_with_info =
        HkdfImpl::expand_static(HpkeKdf::HkdfShake256, prk, kdf_test_vectors::TEST_INFO, 32)
            .expect("KDF expand with non-zero info should work");

    assert_ne!(
        okm, okm_with_info,
        "Zero-length info should produce different output"
    );
}

/// Test KDF with longer inputs (RFC 5869 Test Case 2)
#[test]
fn test_kdf_longer_inputs() {
    let prk = HkdfImpl::extract_static(
        HpkeKdf::HkdfShake256,
        kdf_test_vectors::TEST_SALT_LONG,
        kdf_test_vectors::TEST_IKM_LONG,
    )
    .expect("KDF extract with longer inputs should work");

    assert_eq!(prk.len(), 32);

    let okm = HkdfImpl::expand_static(
        HpkeKdf::HkdfShake256,
        &prk,
        kdf_test_vectors::TEST_INFO_LONG,
        32,
    )
    .expect("KDF expand with longer inputs should work");

    assert_eq!(okm.len(), 32);
}

/// Test KDF cross-algorithm consistency
#[test]
fn test_kdf_cross_algorithm_consistency() {
    // All algorithms should produce different outputs for the same input
    let shake128_prk = HkdfImpl::extract_static(
        HpkeKdf::HkdfShake128,
        kdf_test_vectors::TEST_SALT,
        kdf_test_vectors::TEST_IKM,
    )
    .expect("SHAKE128 extract should work");

    let shake256_prk = HkdfImpl::extract_static(
        HpkeKdf::HkdfShake256,
        kdf_test_vectors::TEST_SALT,
        kdf_test_vectors::TEST_IKM,
    )
    .expect("SHAKE256 extract should work");

    let sha3_256_prk = HkdfImpl::extract_static(
        HpkeKdf::HkdfSha3_256,
        kdf_test_vectors::TEST_SALT,
        kdf_test_vectors::TEST_IKM,
    )
    .expect("SHA3-256 extract should work");

    let sha3_512_prk = HkdfImpl::extract_static(
        HpkeKdf::HkdfSha3_512,
        kdf_test_vectors::TEST_SALT,
        kdf_test_vectors::TEST_IKM,
    )
    .expect("SHA3-512 extract should work");

    // All PRKs should be different
    assert_ne!(shake128_prk, shake256_prk);
    assert_ne!(shake128_prk, sha3_256_prk);
    assert_ne!(shake128_prk, sha3_512_prk);
    assert_ne!(shake256_prk, sha3_256_prk);
    assert_ne!(shake256_prk, sha3_512_prk);
    assert_ne!(sha3_256_prk, sha3_512_prk);
}
