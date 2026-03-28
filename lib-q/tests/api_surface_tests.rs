//! Integration smoke tests for the umbrella `libq` crate (`all-algorithms` only).

use libq::{
    Algorithm,
    LibQCbKemProvider,
    Utils,
    available_algorithms,
    create_hash_context,
    create_kem_context,
    create_signature,
    create_signature_context,
    init,
    sig_available_algorithms,
    supported_algorithms,
    version,
};

#[test]
fn umbrella_init_version_and_supported() {
    assert!(init().is_ok());
    assert!(!version().is_empty());
    let list = supported_algorithms();
    assert!(!list.is_empty());
}

#[test]
fn umbrella_hash_kem_sig_helpers() {
    let mut hash = create_hash_context();
    let _ = hash.hash(Algorithm::Sha3_256, b"surface-test");
    let _kem = create_kem_context();
    let _sig = create_signature_context();
}

#[test]
fn umbrella_utils_hex() {
    let hex = Utils::bytes_to_hex(b"\x00\xff");
    assert_eq!(hex, "00ff");
}

#[test]
fn umbrella_kem_and_sig_algorithm_lists() {
    let kem = available_algorithms();
    assert!(!kem.is_empty());
    let sig = sig_available_algorithms();
    assert!(!sig.is_empty());
}

#[test]
fn umbrella_cb_kem_provider_new() {
    let _provider = LibQCbKemProvider::new().expect("LibQCbKemProvider");
}

#[test]
fn umbrella_create_signature_ml_dsa() {
    let _sig = create_signature("ML-DSA-65").expect("ML-DSA instance");
}

#[test]
fn umbrella_zkp_reexports_constructible() {
    use libq::zkp::{
        ProofType,
        ZkpProver,
    };
    assert_eq!(ProofType::Stark, ProofType::Stark);
    let _prover = ZkpProver::new();
}

#[test]
fn umbrella_aead_context_smoke() {
    let ctx = libq::aead::context();
    assert!(ctx.provider().is_some());
}
