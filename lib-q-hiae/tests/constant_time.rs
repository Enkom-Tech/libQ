//! Structural (non-timing) checks for the constant-time contract in SECURITY.md.
//!
//! Timing itself is not measured here. These tests check that the `simd`
//! feature really compiles the hardware backend in, and that a failed
//! verification never releases plaintext. Both backends are constant-time; the
//! hardware one is the fast one.

#[cfg(feature = "simd")]
#[test]
fn simd_feature_compiles_the_hardware_backend_in() {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    assert!(
        lib_q_hiae::_internals::simd_feature_wired(),
        "`simd` is enabled on {} but no hardware AES backend is compiled in",
        std::env::consts::ARCH
    );
}

#[test]
fn failed_verification_wipes_the_buffer() {
    use lib_q_hiae::Hiae;
    let (k, n) = ([9u8; 32], [8u8; 16]);
    let mut buf = *b"secret that must not survive a bad tag";
    let mut tag = Hiae::encrypt_in_place_detached(&k, &n, b"ad", &mut buf).unwrap();
    tag[0] ^= 1;
    assert!(Hiae::decrypt_in_place_detached(&k, &n, b"ad", &mut buf, &tag).is_err());
    assert!(buf.iter().all(|&b| b == 0));
}
