//! NIST SP 800-90A CTR_DRBG integration KATs; run with feature `nist-aes-rng` or `cbkem8192128f`.

#![cfg(feature = "nist-aes-rng")]
#![allow(clippy::needless_range_loop)]

use lib_q_cb_kem::{
    AesState,
    MAX_BYTES_PER_REQUEST,
    NistDrbgError,
    RESEED_INTERVAL,
    SEEDLEN,
};

#[test]
fn instantiate_first_generate() {
    let mut rng = AesState::new();
    let mut entropy = [0u8; SEEDLEN];
    for i in 0..SEEDLEN {
        entropy[i] = i as u8;
    }
    rng.instantiate(entropy, None).expect("instantiate");
    let mut out = [0u8; 32];
    rng.try_fill_bytes_with_additional_input(&mut out, None)
        .expect("first generate");
    let expected_first: [u8; 32] = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7,
    ];
    assert_eq!(out, expected_first, "first 32 bytes must match KAT");
}

#[test]
fn reseed_then_generate() {
    let mut rng = AesState::new();
    let mut e1 = [0u8; SEEDLEN];
    for i in 0..SEEDLEN {
        e1[i] = i as u8;
    }
    rng.instantiate(e1, None).expect("instantiate");
    let mut discard = [0u8; 32];
    rng.try_fill_bytes_with_additional_input(&mut discard, None)
        .expect("first generate");
    let mut e2 = [0u8; SEEDLEN];
    for i in 0..SEEDLEN {
        e2[i] = (i + 10) as u8;
    }
    rng.reseed(e2, None).expect("reseed");
    let mut out = [0u8; 32];
    rng.try_fill_bytes_with_additional_input(&mut out, None)
        .expect("generate after reseed");
    assert_ne!(out, [0u8; 32], "output after reseed must not be all zeros");
}

#[test]
fn reseed_interval() {
    let mut rng = AesState::new();
    let mut entropy = [0u8; SEEDLEN];
    for i in 0..SEEDLEN {
        entropy[i] = i as u8;
    }
    rng.instantiate(entropy, None).expect("instantiate");
    rng.reseed_counter = RESEED_INTERVAL + 1;
    let mut out = [0u8; 32];
    let err = rng
        .try_fill_bytes_with_additional_input(&mut out, None)
        .expect_err("must require reseed");
    assert_eq!(err, NistDrbgError::ReseedRequired);
    rng.reseed(entropy, None).expect("reseed");
    rng.try_fill_bytes_with_additional_input(&mut out, None)
        .expect("generate after reseed must succeed");
}

#[test]
fn request_too_long() {
    let mut rng = AesState::new();
    let mut entropy = [0u8; SEEDLEN];
    for i in 0..SEEDLEN {
        entropy[i] = i as u8;
    }
    rng.instantiate(entropy, None).expect("instantiate");
    let mut buf = [0u8; MAX_BYTES_PER_REQUEST + 1];
    let err = rng
        .try_fill_bytes_with_additional_input(&mut buf[..], None)
        .expect_err("request too long must error");
    assert_eq!(err, NistDrbgError::RequestTooLong);
}
