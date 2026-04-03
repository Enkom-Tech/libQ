//! Integration smoke tests for the umbrella `libq` crate (`all-algorithms` only).

use lib_q_core::KemOperations;
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
fn umbrella_hqc_provider_new() {
    let _provider = libq::LibQHqcProvider::new().expect("LibQHqcProvider");
}

#[test]
fn umbrella_hqc_kem_roundtrip_via_lib_q_kem_provider() {
    use libq::{
        Algorithm,
        LibQKemProvider,
    };
    let p = LibQKemProvider::new().expect("LibQKemProvider");
    let kp = p
        .generate_keypair(Algorithm::Hqc128, None)
        .expect("HQC-128 keygen");
    let (ct, s1) = p
        .encapsulate(Algorithm::Hqc128, &kp.public_key, None)
        .expect("encap");
    let s2 = p
        .decapsulate(Algorithm::Hqc128, &kp.secret_key, &ct)
        .expect("decap");
    assert_eq!(s1, s2);
    assert!(available_algorithms().contains(&"HQC-128"));
}

#[test]
fn umbrella_create_signature_ml_dsa() {
    let _sig = create_signature("ML-DSA-65").expect("ML-DSA instance");
}

#[test]
fn umbrella_create_signature_slh_dsa_aliases() {
    for name in [
        "SLH-DSA-SHA256-128f-Robust",
        "SLH-DSA-SHAKE256-256f-Robust",
        "slh-dsa-shake256-192f-robust",
    ] {
        let _ =
            create_signature(name).unwrap_or_else(|e| panic!("create_signature({name}): {e:?}"));
    }
}

#[test]
fn umbrella_signature_ml_dsa_roundtrip_via_create_signature_context() {
    let mut ctx = create_signature_context();
    let keypair = ctx
        .generate_keypair(Algorithm::MlDsa65, None)
        .expect("ML-DSA-65 keygen");
    let msg = b"umbrella sig roundtrip";
    let sig = ctx
        .sign(Algorithm::MlDsa65, keypair.secret_key(), msg, None)
        .expect("sign");
    assert!(
        ctx.verify(
            Algorithm::MlDsa65,
            keypair.public_key(),
            msg,
            sig.as_slice()
        )
        .expect("verify")
    );
}

#[test]
fn umbrella_signature_fn_dsa512_roundtrip() {
    let mut ctx = create_signature_context();
    let keypair = ctx
        .generate_keypair(Algorithm::FnDsa512, None)
        .expect("FN-DSA-512 keygen");
    let msg = b"fn-dsa umbrella";
    let sig = ctx
        .sign(Algorithm::FnDsa512, keypair.secret_key(), msg, None)
        .expect("sign");
    assert!(
        ctx.verify(
            Algorithm::FnDsa512,
            keypair.public_key(),
            msg,
            sig.as_slice()
        )
        .expect("verify")
    );
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
