//! API surface often skipped by KAT-style tests: factory dispatch, hash introspection, optional modes.

#![cfg(feature = "alloc")]

#[cfg(feature = "aead")]
#[test]
fn create_saturnin_full_aead_roundtrip() -> lib_q_core::Result<()> {
    use lib_q_core::{
        Aead,
        AeadKey,
        Nonce,
    };
    use lib_q_saturnin::create_saturnin;

    let aead = create_saturnin("aead").expect("aead mode");
    let key = AeadKey::new(vec![0u8; 32]);
    let nonce = Nonce::new(vec![0u8; 16]);
    let ct = Aead::encrypt(&*aead, &key, &nonce, b"p", None)?;
    let pt = Aead::decrypt(&*aead, &key, &nonce, &ct, None)?;
    assert_eq!(pt, b"p");
    Ok(())
}

#[cfg(feature = "aead-short")]
#[test]
fn create_saturnin_short_roundtrip() -> lib_q_core::Result<()> {
    use lib_q_core::{
        Aead,
        AeadKey,
        Nonce,
    };
    use lib_q_saturnin::create_saturnin;

    let aead = create_saturnin("aead-short").expect("aead-short mode");
    let key = AeadKey::new(vec![0u8; 32]);
    let nonce = Nonce::new(vec![0u8; 16]);
    let ct = Aead::encrypt(&*aead, &key, &nonce, b"q", None)?;
    let pt = Aead::decrypt(&*aead, &key, &nonce, &ct, None)?;
    assert_eq!(pt, b"q");
    Ok(())
}

#[cfg(feature = "hash")]
#[test]
fn saturnin_hash_core_matches_documented_parameters() {
    use lib_q_saturnin::SaturninHash;

    let h = SaturninHash::new();
    assert_eq!(h.output_size(), 32);
    assert_eq!(h.core().domain(), 7);
    assert_eq!(h.core().num_rounds(), 16);
}
