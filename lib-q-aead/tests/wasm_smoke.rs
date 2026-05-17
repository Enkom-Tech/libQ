//! wasm-bindgen-test smoke for wasm32 builds (AEAD crate links with wasm feature set in CI).

#[cfg(target_arch = "wasm32")]
use lib_q_aead::create_aead;
#[cfg(target_arch = "wasm32")]
use lib_q_aead::security::timing::TimingProtection;
#[cfg(target_arch = "wasm32")]
use lib_q_core::{
    AeadKey,
    Algorithm,
    Nonce,
};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test]
fn aead_wasm_smoke() {
    let aead = create_aead(Algorithm::Saturnin).expect("create saturnin");
    let key = AeadKey::new(vec![0x11; 32]);
    let nonce = Nonce::new(vec![0x22; 16]);
    let plaintext = b"wasm-aead-smoke";
    let aad = b"aad";

    let ciphertext = aead
        .encrypt(&key, &nonce, plaintext, Some(aad))
        .expect("encrypt");
    let decrypted = aead
        .decrypt(&key, &nonce, &ciphertext, Some(aad))
        .expect("decrypt");
    assert_eq!(decrypted, plaintext);

    let mut bad_ct = ciphertext.clone();
    bad_ct[0] ^= 0x01;
    assert!(
        aead.decrypt(&key, &nonce, &bad_ct, Some(aad)).is_err(),
        "decrypt must reject corrupted ciphertext"
    );

    let wrong_key = AeadKey::new(vec![0x33; 16]);
    assert!(
        aead.encrypt(&wrong_key, &nonce, plaintext, Some(aad))
            .is_err(),
        "invalid key length must fail"
    );
}

/// [`TimingProtection`] must use a real high-resolution clock on wasm32+`wasm`
/// (not the legacy tick counter), so sub-millisecond `target_duration_ns` maps
/// to wall-clock padding.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test]
fn timing_protection_uses_performance_clock() {
    let protection = TimingProtection {
        enabled: true,
        target_duration_ns: 500_000,
    };
    let (_value, elapsed) = protection.protect_with_timing(|| ());
    assert!(
        elapsed >= 400_000,
        "expected >=400µs wall-clock elapsed with 500µs target, got {elapsed}"
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
