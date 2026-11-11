//! Regression test: `SaturninStream` and `SaturninAead` must not share a keystream for the same
//! `(key, nonce)`.
//!
//! # The defect this pins
//!
//! Before `src/stream.rs`'s `STREAM_DOMAIN` constant existed, `SaturninStream::new` and
//! `SaturninAead`'s CTR-Cascade core (`aead.rs`'s `SaturninAeadCores::d1`) both built
//! `SaturninCore::new(10, 1)` and both derived their per-block keystream input the same way —
//! `nonce ‖ 0x80 ‖ 0* ‖ counter_be` — differing only in where the counter starts (`SaturninStream`
//! at 0, `SaturninAead`'s CTR pass at 1). That made the two types' keystreams the *same sequence*,
//! offset by one block: `SaturninStream`'s block at counter `c` was byte-for-byte
//! `SaturninAead`'s CTR block at counter `c`. A caller who fed the same key and nonce to both
//! types — e.g. one component using `SaturninStream` for bulk keystream and another using
//! `SaturninAead` for authenticated records — would leak plaintext by XORing the two outputs.
//!
//! This file proves the fix two ways: a general inequality over an aligned keystream window, and
//! a targeted check of the exact block pair (`SaturninStream` counter 1 vs `SaturninAead` counter
//! 1) that collided before the fix.

#![cfg(all(feature = "alloc", feature = "aead", feature = "stream"))]

extern crate alloc;

use lib_q_saturnin::{Aead, AeadKey, Nonce, Result, SaturninAead, SaturninStream};

/// `SaturninAead::encrypt`'s ciphertext is `CTR(plaintext) ‖ tag(32 bytes)`. For an all-zero
/// plaintext, `CTR(0) == keystream`, so stripping the trailing 32-byte tag recovers the raw
/// CTR-Cascade keystream directly, the same trick `stream.rs`'s own
/// `test_generate_keystream_matches_ctr_encrypt_of_zeros_across_avx2_batch_and_tail` uses.
fn aead_ctr_keystream(key: &[u8], nonce: &[u8], len: usize) -> Result<Vec<u8>> {
    let aead = SaturninAead::new();
    let zero_plaintext = vec![0u8; len];
    let mut ciphertext = aead.encrypt(
        &AeadKey::new(key.to_vec()),
        &Nonce::new(nonce.to_vec()),
        &zero_plaintext,
        None,
    )?;
    ciphertext.truncate(len); // drop the 32-byte tag
    Ok(ciphertext)
}

#[test]
fn stream_and_aead_keystreams_differ_for_same_key_and_nonce() -> Result<()> {
    let key = vec![0x42u8; 32];
    let nonce = vec![0x24u8; 16];

    // Three 32-byte blocks: stream counters 0,1,2; AEAD CTR counters 1,2,3.
    let len = 96;
    let stream = SaturninStream::new();
    let stream_keystream = stream.generate_keystream(&key, &nonce, len)?;
    let aead_keystream = aead_ctr_keystream(&key, &nonce, len)?;

    assert_ne!(
        stream_keystream.as_slice(),
        aead_keystream.as_slice(),
        "SaturninStream and SaturninAead must not produce the same keystream for the same key+nonce"
    );

    // The exact pre-fix collision: SaturninStream's block at counter 1 (bytes 32..64 of its
    // keystream, since its first block is counter 0) must differ from SaturninAead's block at
    // counter 1 (bytes 0..32 of its CTR keystream, since its first block is counter 1). Under the
    // old shared-domain-1 construction these were byte-for-byte identical.
    assert_ne!(
        &stream_keystream[32..64],
        &aead_keystream[0..32],
        "SaturninStream(counter=1) must not equal SaturninAead's CTR(counter=1) block \
         (this is the exact one-block-shifted collision the domain separation fixes)"
    );

    // And every other aligned block pair, for good measure — not just the one hand-picked above.
    for i in 0..3 {
        assert_ne!(
            &stream_keystream[i * 32..(i + 1) * 32],
            &aead_keystream[i * 32..(i + 1) * 32],
            "block {i} must differ between SaturninStream and SaturninAead's CTR keystream"
        );
    }

    Ok(())
}

#[test]
fn stream_and_aead_keystreams_differ_across_many_key_nonce_pairs() -> Result<()> {
    // Guard against a coincidental pass on one fixed key/nonce pair: sweep a handful of
    // distinct (key, nonce) pairs and require divergence on every one.
    for seed in 0u8..8 {
        let key = vec![seed; 32];
        let nonce = vec![seed.wrapping_add(1); 16];
        let len = 32;

        let stream = SaturninStream::new();
        let stream_block0 = stream.generate_keystream(&key, &nonce, len)?;
        let aead_block1 = aead_ctr_keystream(&key, &nonce, len)?;

        assert_ne!(
            stream_block0.as_slice(),
            aead_block1.as_slice(),
            "seed {seed}: SaturninStream and SaturninAead keystreams collided"
        );
    }

    Ok(())
}
