//! Buffer-oriented and round-trip tests.

#![cfg(feature = "std")]

use aead::generic_array::GenericArray;
use aead::{
    AeadInPlace,
    KeyInit,
};
use lib_q_romulus::{
    RomulusM,
    RomulusN,
};

#[test]
fn empty_pt_empty_ad_roundtrip_n() {
    let key = GenericArray::from([0u8; 16]);
    let nonce = GenericArray::from([1u8; 16]);
    let c = RomulusN::new(&key);
    let mut buf = vec![];
    let tag = c.encrypt_in_place_detached(&nonce, b"", &mut buf).unwrap();
    assert_eq!(buf.len(), 0);
    c.decrypt_in_place_detached(&nonce, b"", &mut buf, &tag)
        .unwrap();
}

#[test]
fn empty_pt_nonempty_ad_roundtrip_n() {
    let key = GenericArray::from([2u8; 16]);
    let nonce = GenericArray::from([3u8; 16]);
    let c = RomulusN::new(&key);
    let mut buf = vec![];
    let ad = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let tag = c.encrypt_in_place_detached(&nonce, &ad, &mut buf).unwrap();
    c.decrypt_in_place_detached(&nonce, &ad, &mut buf, &tag)
        .unwrap();
}

#[test]
fn multi_block_plaintext_n() {
    let key = GenericArray::from([0xABu8; 16]);
    let nonce = GenericArray::from([0xCDu8; 16]);
    let c = RomulusN::new(&key);
    let mut buf = vec![0x5Au8; 48];
    let tag = c
        .encrypt_in_place_detached(&nonce, b"hdr", &mut buf)
        .unwrap();
    c.decrypt_in_place_detached(&nonce, b"hdr", &mut buf, &tag)
        .unwrap();
    assert!(buf.iter().all(|&x| x == 0x5A));
}

#[test]
fn romulus_m_roundtrip_multi_block() {
    let key = GenericArray::from([0x11u8; 16]);
    let nonce = GenericArray::from([0x22u8; 16]);
    let c = RomulusM::new(&key);
    let mut buf: Vec<u8> = (0u8..=63).collect();
    let tag = c
        .encrypt_in_place_detached(&nonce, b"associated", &mut buf)
        .unwrap();
    c.decrypt_in_place_detached(&nonce, b"associated", &mut buf, &tag)
        .unwrap();
    let expected: Vec<u8> = (0u8..=63).collect();
    assert_eq!(buf, expected);
}

/// Romulus-N requires fresh nonces for confidentiality; Romulus-M tolerates nonce reuse for integrity.
#[test]
fn nonce_reuse_documentation_distinction() {
    let key = GenericArray::from([0xEEu8; 16]);
    let nonce = GenericArray::from([0xFFu8; 16]);
    let c_n = RomulusN::new(&key);
    let mut a = b"one".to_vec();
    let t1 = c_n.encrypt_in_place_detached(&nonce, b"", &mut a).unwrap();
    let mut b = b"two".to_vec();
    let _t2 = c_n.encrypt_in_place_detached(&nonce, b"", &mut b).unwrap();
    // Same nonce gives different ciphertexts (stream XOR) but this is insecure for N — we only assert decrypt of first works
    let mut ct1 = a.clone();
    c_n.decrypt_in_place_detached(&nonce, b"", &mut ct1, &t1)
        .unwrap();
    assert_eq!(ct1, b"one");

    let c_m = RomulusM::new(&key);
    let mut m1 = b"alpha".to_vec();
    let g1 = c_m.encrypt_in_place_detached(&nonce, b"", &mut m1).unwrap();
    let mut m2 = b"beta".to_vec();
    let g2 = c_m.encrypt_in_place_detached(&nonce, b"", &mut m2).unwrap();
    assert_ne!(g1.as_slice(), g2.as_slice());
    let mut x = m1.clone();
    c_m.decrypt_in_place_detached(&nonce, b"", &mut x, &g1)
        .unwrap();
    assert_eq!(x, b"alpha");
}

#[cfg(feature = "alloc")]
use aead::{
    Aead,
    Payload,
};

#[cfg(feature = "alloc")]
#[test]
fn allocating_aead_encrypt_decrypt_n() {
    let key = GenericArray::from([0x33u8; 16]);
    let nonce = GenericArray::from([0x44u8; 16]);
    let c = RomulusN::new(&key);
    let ct = c
        .encrypt(
            &nonce,
            Payload {
                msg: b"plain",
                aad: b"ad",
            },
        )
        .expect("alloc encrypt");
    let pt = c
        .decrypt(
            &nonce,
            Payload {
                msg: ct.as_slice(),
                aad: b"ad",
            },
        )
        .expect("alloc decrypt");
    assert_eq!(pt, b"plain");
}
