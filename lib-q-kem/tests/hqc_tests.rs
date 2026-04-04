//! Tests for HQC KEM implementations (create_kem and Kem trait roundtrip).
//!
//! Run with: cargo test -p lib-q-kem --features "hqc,std,alloc"

#[cfg(all(feature = "hqc", feature = "std", feature = "alloc"))]
use lib_q_core::Error;
#[cfg(all(feature = "hqc", feature = "std", feature = "alloc"))]
use lib_q_kem::create_kem;

/// create_kem returns Ok for each HQC algorithm name.
#[test]
#[cfg(all(feature = "hqc", feature = "std", feature = "alloc"))]
fn test_hqc_create_kem_returns_ok() {
    let kem128 = create_kem("HQC-128");
    assert!(kem128.is_ok(), "create_kem(\"HQC-128\") should succeed");
    let kem192 = create_kem("HQC-192");
    assert!(kem192.is_ok(), "create_kem(\"HQC-192\") should succeed");
    let kem256 = create_kem("HQC-256");
    assert!(kem256.is_ok(), "create_kem(\"HQC-256\") should succeed");

    let kem128_lower = create_kem("hqc-128");
    assert!(
        kem128_lower.is_ok(),
        "create_kem(\"hqc-128\") should succeed"
    );
}

/// Roundtrip: keygen -> encapsulate -> decapsulate; shared secrets match.
#[test]
#[cfg(all(feature = "hqc", feature = "std", feature = "alloc"))]
fn test_hqc128_roundtrip() {
    let kem = create_kem("HQC-128").expect("create_kem HQC-128");
    let keypair = kem.generate_keypair().expect("generate_keypair");
    let (ciphertext, shared_secret) = kem.encapsulate(&keypair.public_key).expect("encapsulate");
    let decapsulated = kem
        .decapsulate(&keypair.secret_key, &ciphertext)
        .expect("decapsulate");
    assert_eq!(
        shared_secret, decapsulated,
        "HQC-128 shared secret should match after decapsulation"
    );
}

#[test]
#[cfg(all(feature = "hqc", feature = "std", feature = "alloc"))]
fn test_hqc192_roundtrip() {
    let kem = create_kem("HQC-192").expect("create_kem HQC-192");
    let keypair = kem.generate_keypair().expect("generate_keypair");
    let (ciphertext, shared_secret) = kem.encapsulate(&keypair.public_key).expect("encapsulate");
    let decapsulated = kem
        .decapsulate(&keypair.secret_key, &ciphertext)
        .expect("decapsulate");
    assert_eq!(
        shared_secret, decapsulated,
        "HQC-192 shared secret should match after decapsulation"
    );
}

#[test]
#[cfg(all(feature = "hqc", feature = "std", feature = "alloc"))]
fn test_hqc256_roundtrip() {
    let kem = create_kem("HQC-256").expect("create_kem HQC-256");
    let keypair = kem.generate_keypair().expect("generate_keypair");
    let (ciphertext, shared_secret) = kem.encapsulate(&keypair.public_key).expect("encapsulate");
    let decapsulated = kem
        .decapsulate(&keypair.secret_key, &ciphertext)
        .expect("decapsulate");
    assert_eq!(
        shared_secret, decapsulated,
        "HQC-256 shared secret should match after decapsulation"
    );
}

/// derive_public_key(sk) equals the public key from the keypair.
#[test]
#[cfg(all(feature = "hqc", feature = "std", feature = "alloc"))]
fn test_hqc_derive_public_key() {
    for name in ["HQC-128", "HQC-192", "HQC-256"] {
        let kem = create_kem(name).expect("create_kem");
        let keypair = kem.generate_keypair().expect("generate_keypair");
        let derived = kem
            .derive_public_key(&keypair.secret_key)
            .expect("derive_public_key");
        assert_eq!(
            derived.data, keypair.public_key.data,
            "derive_public_key should match keypair.public_key for {}",
            name
        );
    }
}

/// auth_encapsulate returns Err(NotImplemented).
#[test]
#[cfg(all(feature = "hqc", feature = "std", feature = "alloc"))]
fn test_hqc_auth_encapsulate_not_implemented() {
    let kem = create_kem("HQC-128").expect("create_kem HQC-128");
    let keypair = kem.generate_keypair().expect("generate_keypair");
    let sender_sk = &keypair.secret_key;
    let recipient_pk = &keypair.public_key;
    let result = kem.auth_encapsulate(sender_sk, recipient_pk);
    assert!(result.is_err());
    if let Err(Error::NotImplemented { feature }) = result {
        assert!(
            feature.contains("AuthEncap") || feature.contains("HPKE"),
            "Expected NotImplemented about AuthEncap/HPKE, got: {}",
            feature
        );
    } else {
        panic!("Expected Error::NotImplemented, got {:?}", result);
    }
}

/// auth_decapsulate returns Err(NotImplemented).
#[test]
#[cfg(all(feature = "hqc", feature = "std", feature = "alloc"))]
fn test_hqc_auth_decapsulate_not_implemented() {
    let kem = create_kem("HQC-128").expect("create_kem HQC-128");
    let keypair = kem.generate_keypair().expect("generate_keypair");
    let ct = vec![0u8; 64];
    let result = kem.auth_decapsulate(&keypair.secret_key, &ct, &keypair.public_key);
    assert!(result.is_err());
    if let Err(Error::NotImplemented { feature }) = result {
        assert!(
            feature.contains("AuthDecap") || feature.contains("HPKE"),
            "Expected NotImplemented about AuthDecap/HPKE, got: {}",
            feature
        );
    } else {
        panic!("Expected Error::NotImplemented, got {:?}", result);
    }
}
