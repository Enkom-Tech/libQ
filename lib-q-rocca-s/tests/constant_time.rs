//! Smoke tests for the authentication-failure path.
//!
//! These do not attempt to *measure* timing (that needs a dedicated harness);
//! they confirm the API always performs the full bulk decryption and tag check
//! and never leaks plaintext on a bad tag — the structural prerequisite for the
//! constant-time decrypt contract documented in `SECURITY.md`.

use lib_q_rocca_s::{
    Aead,
    AeadDecryptSemantic,
    AeadKey,
    DecryptSemanticOutcome,
    Nonce,
    RoccaSAead,
};

#[test]
fn bad_tag_never_yields_plaintext() {
    let a = RoccaSAead::new();
    let key = AeadKey::new(vec![0x5A; 32]);
    let nonce = Nonce::new(vec![0xC3; 16]);
    let pt = b"plaintext that must never leak on auth failure";
    let ct = a.encrypt(&key, &nonce, pt, Some(b"ad")).unwrap();

    // Flip every byte position once; every corruption must be rejected with no
    // plaintext returned via either decrypt layer.
    for i in 0..ct.len() {
        let mut bad = ct.clone();
        bad[i] ^= 0xFF;
        assert!(a.decrypt(&key, &nonce, &bad, Some(b"ad")).is_err());
        assert_eq!(
            a.decrypt_semantic(&key, &nonce, &bad, Some(b"ad")).unwrap(),
            DecryptSemanticOutcome::AuthenticationFailed
        );
    }
}

/// Structural (non-timing) proof that the constant-time hardware AES backend is
/// actually *wired in* by default on architectures that have one — finding F4 /
/// card t_3d6e8d50. This does NOT measure wall-clock timing (that is unmeasurable in
/// a unit test and explicitly out of scope per card t_043571b4); it checks the
/// compile-time feature selection, which is exactly what the wiring bug broke:
/// `simd` was not in `default` and `lib-q-aead`'s `rocca-s` feature never enabled it,
/// so every consumer silently got the non-constant-time scalar S-box table
/// (`round.rs::SBOX`) even on AES-NI hardware.
///
/// This test FAILS if that regresses: strip `simd`/`simd-aesni`/`simd-neon` from a
/// `std` build on x86/x86_64/aarch64 (e.g. `cargo test -p lib-q-rocca-s --no-default-features
/// --features std,aead,alloc`) and it will report the wiring gap instead of passing silently.
#[test]
fn simd_backend_is_wired_on_hardware_capable_targets() {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    {
        assert!(
            lib_q_rocca_s::_internals::simd_feature_wired(),
            "std build on a hardware-AES-capable target ({}) does not have the `simd` \
             feature wired in — every caller will run the non-constant-time scalar AES \
             S-box table unconditionally (see round.rs doc comment, finding F4).",
            std::env::consts::ARCH
        );
    }
}

#[test]
fn good_tag_succeeds_after_full_schedule() {
    let a = RoccaSAead::new();
    let key = AeadKey::new(vec![1; 32]);
    let nonce = Nonce::new(vec![2; 16]);
    let ct = a.encrypt(&key, &nonce, b"ok", Some(b"")).unwrap();
    assert_eq!(a.decrypt(&key, &nonce, &ct, Some(b"")).unwrap(), b"ok");
}
