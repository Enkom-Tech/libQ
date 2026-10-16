//! Public API behaviour shared by every AEAD type in the crate.

use lib_q_aegis::{
    Aead,
    AeadDecryptSemantic,
    AeadKey,
    DecryptSemanticOutcome,
    Error,
    Nonce,
};

fn exercise<A: Aead + AeadDecryptSemantic>(a: A, key_len: usize, nonce_len: usize, tag_len: usize) {
    let key = AeadKey::new(vec![0x33; key_len]);
    let nonce = Nonce::new(vec![0x77; nonce_len]);

    for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 255, 256, 257, 1500] {
        let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let ad: Vec<u8> = (0..len % 19).map(|i| (i as u8) ^ 0xA5).collect();
        let ct = a.encrypt(&key, &nonce, &pt, Some(&ad)).unwrap();
        assert_eq!(ct.len(), len + tag_len);
        assert_eq!(
            a.decrypt(&key, &nonce, &ct, Some(&ad)).unwrap(),
            pt,
            "len {len}"
        );
        // `None` and empty associated data are the same input.
        if ad.is_empty() {
            assert_eq!(a.decrypt(&key, &nonce, &ct, None).unwrap(), pt);
        }
    }

    let ct = a.encrypt(&key, &nonce, b"payload", Some(b"ad")).unwrap();
    for i in 0..ct.len() {
        let mut bad = ct.clone();
        bad[i] ^= 0x80;
        assert!(matches!(
            a.decrypt(&key, &nonce, &bad, Some(b"ad")),
            Err(Error::VerificationFailed { .. })
        ));
        assert_eq!(
            a.decrypt_semantic(&key, &nonce, &bad, Some(b"ad")).unwrap(),
            DecryptSemanticOutcome::AuthenticationFailed
        );
    }
    assert!(
        a.decrypt(&key, &nonce, &ct, Some(b"ae")).is_err(),
        "wrong AD"
    );
    let other_key = AeadKey::new(vec![0x34; key_len]);
    assert!(
        a.decrypt(&other_key, &nonce, &ct, Some(b"ad")).is_err(),
        "wrong key"
    );
    let other_nonce = Nonce::new(vec![0x78; nonce_len]);
    assert!(
        a.decrypt(&key, &other_nonce, &ct, Some(b"ad")).is_err(),
        "wrong nonce"
    );

    assert!(matches!(
        a.encrypt(&AeadKey::new(vec![0; key_len - 1]), &nonce, b"x", None),
        Err(Error::InvalidKeySize { .. })
    ));
    assert!(matches!(
        a.encrypt(&key, &Nonce::new(vec![0; nonce_len + 1]), b"x", None),
        Err(Error::InvalidNonceSize { .. })
    ));
    assert!(
        a.decrypt(&key, &nonce, &vec![0u8; tag_len - 1], None)
            .is_err()
    );
}

#[test]
fn aegis256_api() {
    use lib_q_aegis::{
        Aegis256,
        Aegis256Tag128,
    };
    exercise(Aegis256::new(), 32, 32, 32);
    exercise(Aegis256Tag128::new(), 32, 32, 16);
    assert_eq!(Aegis256::TAG_SIZE, 32);
    assert_eq!(Aegis256Tag128::TAG_SIZE, 16);
}

#[test]
fn tag_lengths_are_domain_separated() {
    // The 128-bit tag is not a prefix of the 256-bit tag (RFC 10032 Section 4.9).
    use lib_q_aegis::{
        Aegis256,
        Aegis256Tag128,
    };
    let (k, n) = ([1u8; 32], [2u8; 32]);
    let mut a = *b"abc";
    let mut b = *b"abc";
    let t256 = Aegis256::encrypt_in_place_detached(&k, &n, b"", &mut a).unwrap();
    let t128 = Aegis256Tag128::encrypt_in_place_detached(&k, &n, b"", &mut b).unwrap();
    assert_eq!(a, b, "same keystream");
    assert_ne!(&t256[..16], &t128[..]);
}
