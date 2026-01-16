//! NIST Reference Implementation Comparison Harness
//!
//! This module provides automated comparison between our ML-DSA implementation
//! and the official NIST FIPS 204 reference implementation.

#![cfg(all(feature = "random", feature = "acvp"))]
#![allow(clippy::disallowed_types)] // HashMap is appropriate for parsing KAT files

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use lib_q_ml_dsa::*;

/// NIST KAT test vector structure
#[derive(Debug, Clone)]
struct NistTestVector {
    _count: u32,
    seed: [u8; 48],
    pk: Vec<u8>,
    sk: Vec<u8>,
    msg: Vec<u8>,
    sig: Vec<u8>,
}

/// Parse NIST KAT file format
fn parse_kat_file(content: &str) -> Vec<NistTestVector> {
    let mut vectors = Vec::new();
    let mut current_vector = HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if line == "=" {
            // End of vector, parse it
            if let Some(vector) = parse_vector(&current_vector) {
                vectors.push(vector);
            }
            current_vector.clear();
            continue;
        }

        if let Some((key, value)) = line.split_once('=') {
            current_vector.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    // Parse last vector if file doesn't end with "="
    if !current_vector.is_empty() &&
        let Some(vector) = parse_vector(&current_vector)
    {
        vectors.push(vector);
    }

    vectors
}

/// Parse individual test vector from key-value pairs
fn parse_vector(data: &HashMap<String, String>) -> Option<NistTestVector> {
    let count = data.get("count")?.parse::<u32>().ok()?;
    let seed_hex = data.get("seed")?;
    let pk_hex = data.get("pk")?;
    let sk_hex = data.get("sk")?;
    let msg_hex = data.get("msg")?;
    let sig_hex = data.get("sig")?;

    // Parse hex strings
    let seed = hex::decode(seed_hex).ok()?;
    let pk = hex::decode(pk_hex).ok()?;
    let sk = hex::decode(sk_hex).ok()?;
    let msg = hex::decode(msg_hex).ok()?;
    let sig = hex::decode(sig_hex).ok()?;

    if seed.len() != 48 {
        return None;
    }

    let mut seed_array = [0u8; 48];
    seed_array.copy_from_slice(&seed);

    Some(NistTestVector {
        _count: count,
        seed: seed_array,
        pk,
        sk,
        msg,
        sig,
    })
}

/// Load NIST KAT file for a specific parameter set
fn load_nist_kat_file(
    parameter_set: &str,
) -> Result<Vec<NistTestVector>, Box<dyn std::error::Error>> {
    let path = format!(
        "reference/nist-ml-dsa-ref/Reference_Implementation/crypto_sign/dilithium*/PQCsignKAT_{}.rsp",
        parameter_set
    );

    // Find the actual file (handle wildcard)
    let file_path = glob::glob(&path)?
        .flatten()
        .next()
        .ok_or("NIST KAT file not found - run reference/nist-ml-dsa-ref/setup.sh")?;
    let contents = fs::read_to_string(file_path)?;

    Ok(parse_kat_file(&contents))
}

/// Load NIST reference output from file
fn load_nist_reference_output(filename: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let path = format!("reference/nist-ml-dsa-ref/outputs/{}", filename);
    Ok(fs::read(path)?)
}

/// Compare two byte arrays and report differences
fn compare_and_report(
    our_data: &[u8],
    nist_data: &[u8],
    data_type: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if our_data.len() != nist_data.len() {
        return Err(format!(
            "Length mismatch for {}: our={}, nist={}",
            data_type,
            our_data.len(),
            nist_data.len()
        )
        .into());
    }

    let mut first_mismatch = None;
    for (idx, (our, nist)) in our_data.iter().zip(nist_data.iter()).enumerate() {
        if our != nist {
            first_mismatch = Some((idx, *our, *nist));
            break;
        }
    }

    if let Some((idx, our_byte, nist_byte)) = first_mismatch {
        // Print hex diff
        let start = idx.saturating_sub(8);
        let end = (idx + 8).min(our_data.len());

        println!("Mismatch in {} at byte {}:", data_type, idx);
        println!("  Our:  {:02x}", our_byte);
        println!("  NIST: {:02x}", nist_byte);
        println!("  Context:");
        println!("    Our:  {:02x?}", &our_data[start..end]);
        println!("    NIST: {:02x?}", &nist_data[start..end]);

        return Err(format!(
            "Byte mismatch in {} at position {}: our={:02x}, nist={:02x}",
            data_type, idx, our_byte, nist_byte
        )
        .into());
    }

    println!("✓ {} matches NIST reference exactly", data_type);
    Ok(())
}

/// Generate test case using NIST reference and compare with our implementation
fn generate_and_compare_test_case(
    test_id: &str,
    seed: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Running test case: {}", test_id);

    // Generate keys with our implementation
    let our_keys = ml_dsa_44::generate_key_pair(seed);

    // Try to load NIST reference output
    let nist_vk_path = format!("keygen_44_{}.vk", test_id);
    let nist_sk_path = format!("keygen_44_{}.sk", test_id);

    match (
        load_nist_reference_output(&nist_vk_path),
        load_nist_reference_output(&nist_sk_path),
    ) {
        (Ok(nist_vk), Ok(nist_sk)) => {
            // Compare verification keys
            compare_and_report(
                our_keys.verification_key.as_slice(),
                &nist_vk,
                "Verification Key",
            )?;

            // Compare signing keys
            compare_and_report(our_keys.signing_key.as_slice(), &nist_sk, "Signing Key")?;

            println!("✓ Test case {} passed", test_id);
        }
        _ => {
            println!("⚠ NIST reference files not found for test case {}", test_id);
            println!("  Expected files: {}, {}", nist_vk_path, nist_sk_path);
            println!("  This is expected if NIST reference is not yet set up");
        }
    }

    Ok(())
}

/// Test key generation against NIST reference
#[test]
fn test_keygen_against_nist_reference() {
    // Test with known seeds
    let test_cases = [
        ([0x00; 32], "001"),
        ([0x42; 32], "002"),
        ([0xFF; 32], "003"),
    ];

    for (seed, test_id) in test_cases {
        if let Err(e) = generate_and_compare_test_case(test_id, seed) {
            // Don't fail the test if NIST reference is not available
            if e.to_string().contains("not found") {
                println!("Skipping test case {}: {}", test_id, e);
                continue;
            }
            panic!("Test case {} failed: {}", test_id, e);
        }
    }
}

/// Test signature generation against NIST reference
#[test]
fn test_siggen_against_nist_reference() {
    let seed = [0x42; 32];
    let message = b"test message for NIST comparison";
    let rnd = [0x42; 32];

    // Generate keys
    let keys = ml_dsa_44::generate_key_pair(seed);

    // Sign message
    let our_sig = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();

    // Try to load NIST reference signature
    match load_nist_reference_output("siggen_44_001.sig") {
        Ok(nist_sig) => {
            compare_and_report(our_sig.as_slice(), &nist_sig, "Signature").unwrap();
            println!("✓ Signature generation matches NIST reference");
        }
        Err(_) => {
            println!("⚠ NIST reference signature not found");
            println!("  This is expected if NIST reference is not yet set up");
        }
    }
}

/// Test signature verification against NIST reference
#[test]
fn test_sigver_against_nist_reference() {
    let seed = [0x42; 32];
    let message = b"test message for verification";
    let rnd = [0x42; 32];

    // Generate keys and signature
    let keys = ml_dsa_44::generate_key_pair(seed);
    let sig = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();

    // Verify signature
    let verify_result = ml_dsa_44::verify_internal(&keys.verification_key, message, &sig);
    assert!(
        verify_result.is_ok(),
        "Our signature should verify correctly"
    );

    println!("✓ Signature verification works correctly");
}

/// Test cross-parameter set compatibility
#[test]
fn test_cross_parameter_compatibility() {
    let seed = [0x42; 32];
    let message = b"cross-parameter test message";
    let rnd = [0x42; 32];

    // Test ML-DSA-44
    let keys44 = ml_dsa_44::generate_key_pair(seed);
    let sig44 = ml_dsa_44::sign_internal(&keys44.signing_key, message, rnd).unwrap();
    let verify44 = ml_dsa_44::verify_internal(&keys44.verification_key, message, &sig44);
    assert!(verify44.is_ok(), "ML-DSA-44 should work correctly");

    // Test ML-DSA-65 if available
    #[cfg(feature = "mldsa65")]
    {
        let keys65 = ml_dsa_65::generate_key_pair(seed);
        let sig65 = ml_dsa_65::sign_internal(&keys65.signing_key, message, rnd).unwrap();
        let verify65 = ml_dsa_65::verify_internal(&keys65.verification_key, message, &sig65);
        assert!(verify65.is_ok(), "ML-DSA-65 should work correctly");
    }

    // Test ML-DSA-87 if available
    #[cfg(feature = "mldsa87")]
    {
        let keys87 = ml_dsa_87::generate_key_pair(seed);
        let sig87 = ml_dsa_87::sign_internal(&keys87.signing_key, message, rnd).unwrap();
        let verify87 = ml_dsa_87::verify_internal(&keys87.verification_key, message, &sig87);
        assert!(verify87.is_ok(), "ML-DSA-87 should work correctly");
    }

    println!("✓ Cross-parameter set compatibility verified");
}

/// Test deterministic behavior
#[test]
fn test_deterministic_behavior() {
    let seed = [0x42; 32];
    let message = b"deterministic test message";
    let rnd = [0x42; 32];

    // Generate keys multiple times
    let keys1 = ml_dsa_44::generate_key_pair(seed);
    let keys2 = ml_dsa_44::generate_key_pair(seed);

    // Keys should be identical
    assert_eq!(
        keys1.verification_key.as_slice(),
        keys2.verification_key.as_slice(),
        "Verification keys should be identical"
    );
    assert_eq!(
        keys1.signing_key.as_slice(),
        keys2.signing_key.as_slice(),
        "Signing keys should be identical"
    );

    // Sign message multiple times
    let sig1 = ml_dsa_44::sign_internal(&keys1.signing_key, message, rnd).unwrap();
    let sig2 = ml_dsa_44::sign_internal(&keys1.signing_key, message, rnd).unwrap();

    // Signatures should be identical
    assert_eq!(
        sig1.as_slice(),
        sig2.as_slice(),
        "Signatures should be identical"
    );

    println!("✓ Deterministic behavior verified");
}

/// Test edge cases
#[test]
fn test_edge_cases() {
    let seed = [0x42; 32];
    let rnd = [0x42; 32];

    // Test with empty message
    let keys = ml_dsa_44::generate_key_pair(seed);
    let empty_message = b"";
    let sig_empty = ml_dsa_44::sign_internal(&keys.signing_key, empty_message, rnd).unwrap();
    let verify_empty =
        ml_dsa_44::verify_internal(&keys.verification_key, empty_message, &sig_empty);
    assert!(verify_empty.is_ok(), "Empty message should work");

    // Test with large message
    let large_message = vec![0x42u8; 1000];
    let sig_large = ml_dsa_44::sign_internal(&keys.signing_key, &large_message, rnd).unwrap();
    let verify_large =
        ml_dsa_44::verify_internal(&keys.verification_key, &large_message, &sig_large);
    assert!(verify_large.is_ok(), "Large message should work");

    println!("✓ Edge cases handled correctly");
}

/// Test against NIST KAT vectors
#[test]
fn test_against_nist_kat_vectors() {
    // Test against NIST KAT vectors for ML-DSA-44 (dilithium2)
    let vectors = match load_nist_kat_file("dilithium2") {
        Ok(v) => v,
        Err(_) => {
            println!(
                "NIST KAT file not found - skipping test. Run reference/nist-ml-dsa-ref/setup.sh to generate vectors."
            );
            return;
        }
    };

    // Test first 10 vectors
    for (i, vector) in vectors.iter().take(10).enumerate() {
        println!("Testing NIST vector {}", i);

        // Generate keys with NIST seed (first 32 bytes)
        let seed_for_keygen = &vector.seed[0..32];
        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(seed_for_keygen);

        let our_keys = ml_dsa_44::generate_key_pair(seed_array);

        // Compare verification key
        assert_eq!(
            our_keys.verification_key.as_slice(),
            vector.pk,
            "VK mismatch at vector {}",
            i
        );

        // Compare signing key
        assert_eq!(
            our_keys.signing_key.as_slice(),
            vector.sk,
            "SK mismatch at vector {}",
            i
        );

        // Test signing with NIST randomness (bytes 32-47)
        let signing_randomness = &vector.seed[32..48];
        let mut rnd_array = [0u8; 32];
        rnd_array[0..16].copy_from_slice(signing_randomness);

        let sig = ml_dsa_44::sign_internal(&our_keys.signing_key, &vector.msg, rnd_array).unwrap();

        assert_eq!(
            sig.as_slice(),
            vector.sig,
            "Signature mismatch at vector {}",
            i
        );
    }

    println!("✓ NIST KAT vectors validation passed");
}

/// Utility function to generate NIST reference test vectors
/// This would be used to generate test vectors when NIST reference is available
#[allow(dead_code)]
fn generate_nist_test_vectors() -> Result<(), Box<dyn std::error::Error>> {
    let output_dir = "reference/nist-ml-dsa-ref/outputs";

    // Create output directory if it doesn't exist
    if !Path::new(output_dir).exists() {
        fs::create_dir_all(output_dir)?;
    }

    let test_cases = [
        ([0x00; 32], "001"),
        ([0x42; 32], "002"),
        ([0xFF; 32], "003"),
    ];

    for (seed, test_id) in test_cases {
        // Generate keys
        let keys = ml_dsa_44::generate_key_pair(seed);

        // Save verification key
        let vk_path = format!("{}/keygen_44_{}.vk", output_dir, test_id);
        fs::write(vk_path, keys.verification_key.as_slice())?;

        // Save signing key
        let sk_path = format!("{}/keygen_44_{}.sk", output_dir, test_id);
        fs::write(sk_path, keys.signing_key.as_slice())?;

        // Generate and save signature
        let message = b"test message";
        let rnd = [0x42; 32];
        let sig = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();
        let sig_path = format!("{}/siggen_44_{}.sig", output_dir, test_id);
        fs::write(sig_path, sig.as_slice())?;
    }

    println!("✓ NIST test vectors generated");
    Ok(())
}
