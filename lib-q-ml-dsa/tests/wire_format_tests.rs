//! Wire-format compatibility tests for cross-mode communication

use std::fs;

use lib_q_ml_dsa::*;

#[test]
fn test_verification_key_serialization_stable() {
    // Keys must serialize identically across modes
    let seed = [0x42; 32];
    let keys = ml_dsa_44::generate_key_pair(seed);

    let vk_bytes = keys.verification_key.as_slice();

    // Verification key format must be stable (ML-DSA-44 has 1312 byte verification key)
    assert_eq!(vk_bytes.len(), 1312);

    // Document current format for regression testing
    let vk_hex = hex::encode(vk_bytes);
    println!("VK format (first 32 bytes): {}", &vk_hex[..64]);
}

#[test]
fn test_signature_format_stable() {
    // Signatures must have stable wire format
    let seed = [0x42; 32];
    let message = b"wire format test";
    let context = b"";
    let randomness = [0x43; 32];

    let keys = ml_dsa_44::generate_key_pair(seed);
    let sig = ml_dsa_44::sign(&keys.signing_key, message, context, randomness).unwrap();

    let sig_bytes = sig.as_slice();

    // Signature format must be stable (ML-DSA-44 has 2420 byte signature)
    assert_eq!(sig_bytes.len(), 2420);

    // Document current format
    let sig_hex = hex::encode(sig_bytes);
    println!("Signature format (first 32 bytes): {}", &sig_hex[..64]);
}

#[test]
fn test_cross_mode_signature_verification() {
    // A signature created in one mode must verify in another
    let seed = [0x42; 32];
    let message = b"cross-mode verification test";
    let context = b"test";
    let randomness = [0x43; 32];

    let keys = ml_dsa_44::generate_key_pair(seed);
    let sig = ml_dsa_44::sign(&keys.signing_key, message, context, randomness).unwrap();

    // Verification must work regardless of mode features
    let verify = ml_dsa_44::verify(&keys.verification_key, message, context, &sig);
    assert!(verify.is_ok(), "Cross-mode verification must succeed");

    // Test with wrong message (must fail)
    let wrong_message = b"different message";
    let verify_fail = ml_dsa_44::verify(&keys.verification_key, wrong_message, context, &sig);
    assert!(verify_fail.is_err(), "Wrong message must fail verification");
}

#[test]
fn test_serialized_key_exchange() {
    // Simulate key exchange: compliance mode generates keys, production mode uses them
    let seed = [0x42; 32];
    let keys = ml_dsa_44::generate_key_pair(seed);

    // Serialize verification key (public key exchange)
    let vk_serialized = keys.verification_key.as_slice().to_vec();

    // Deserialize in "different system" (actually same, but simulates cross-mode)
    let vk_reconstructed = MLDSAVerificationKey::new(vk_serialized.as_slice().try_into().unwrap());

    // Sign with original key
    let message = b"key exchange test";
    let context = b"";
    let randomness = [0x43; 32];
    let sig = ml_dsa_44::sign(&keys.signing_key, message, context, randomness).unwrap();

    // Verify with reconstructed key
    let verify = ml_dsa_44::verify(&vk_reconstructed, message, context, &sig);
    assert!(verify.is_ok(), "Serialized key exchange must work");
}

#[test]
#[ignore] // Run manually to generate vectors
fn generate_interop_test_vectors() {
    let mut vectors = Vec::new();

    for i in 0..10 {
        let mut seed = [0u8; 32];
        seed[0] = i;

        let keys = ml_dsa_44::generate_key_pair(seed);

        let message = format!("test message {}", i).into_bytes();
        let context = b"interop";
        let mut randomness = [0u8; 32];
        randomness[0] = i + 10;

        let sig = ml_dsa_44::sign(&keys.signing_key, &message, context, randomness).unwrap();

        vectors.push(serde_json::json!({
            "test_id": i,
            "seed": hex::encode(seed),
            "verification_key": hex::encode(keys.verification_key.as_slice()),
            "message": hex::encode(&message),
            "context": hex::encode(context),
            "randomness": hex::encode(randomness),
            "signature": hex::encode(sig.as_slice()),
        }));
    }

    let json = serde_json::to_string_pretty(&vectors).unwrap();
    fs::write("tests/test_vectors/interop_vectors.json", json).unwrap();
    println!(
        "✓ Generated {} interoperability test vectors",
        vectors.len()
    );
}

#[test]
fn test_against_saved_interop_vectors() {
    let json = fs::read_to_string("tests/test_vectors/interop_vectors.json")
        .expect("Interop vectors not found - run generate_interop_test_vectors first");

    let vectors: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();

    for vector in &vectors {
        let seed = hex::decode(vector["seed"].as_str().unwrap()).unwrap();
        let expected_vk = hex::decode(vector["verification_key"].as_str().unwrap()).unwrap();
        let message = hex::decode(vector["message"].as_str().unwrap()).unwrap();
        let context = hex::decode(vector["context"].as_str().unwrap()).unwrap();
        let randomness = hex::decode(vector["randomness"].as_str().unwrap()).unwrap();
        let expected_sig = hex::decode(vector["signature"].as_str().unwrap()).unwrap();

        // Verify key generation produces same result
        let keys = ml_dsa_44::generate_key_pair(seed.as_slice().try_into().unwrap());
        assert_eq!(
            keys.verification_key.as_slice(),
            expected_vk.as_slice(),
            "VK mismatch - wire format changed!"
        );

        // Verify signing produces same result
        let sig = ml_dsa_44::sign(
            &keys.signing_key,
            &message,
            &context,
            randomness.as_slice().try_into().unwrap(),
        )
        .unwrap();
        assert_eq!(
            sig.as_slice(),
            expected_sig.as_slice(),
            "Signature mismatch - wire format changed!"
        );

        // Verify signature verification works
        let verify = ml_dsa_44::verify(&keys.verification_key, &message, &context, &sig);
        assert!(verify.is_ok(), "Verification must succeed");
    }

    println!(
        "✓ All {} saved vectors match current implementation",
        vectors.len()
    );
}
