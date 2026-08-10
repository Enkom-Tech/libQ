//! Must-reject coverage for Classic McEliece decapsulation.
//!
//! The audit lens under card `t_f0d676d1` recorded that HQC and Classic McEliece "parse
//! attacker-supplied ciphertexts with zero must-reject cases". `constant_time.rs` already checks
//! that the valid and invalid decapsulation paths take the *same time*, but nothing checked that
//! they produce a *different answer*. Those are independent properties, and the timing test
//! passes just as happily if decapsulation returns the genuine shared secret for a tampered
//! ciphertext, which would be a total CCA break.
//!
//! What a KEM with Fujisaki-Okamoto-style implicit rejection must do is never signal failure and
//! never return the real shared secret: a tampered ciphertext yields a deterministic
//! secret-derived pseudorandom value instead. So the assertion here is not "decapsulation errors"
//! (it must not) but "decapsulation does not reproduce the genuine shared secret".
//!
//! Ciphertext bytes are attacker-supplied and decapsulation is the entry point, so this is the
//! boundary where a must-reject case belongs.

use lib_q_cb_kem::{
    CRYPTO_BYTES,
    CRYPTO_CIPHERTEXTBYTES,
    CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES,
    Ciphertext,
    LibQRng,
    decapsulate,
    encapsulate,
    keypair,
};

/// `SecretKey` borrows its buffer, so the caller owns the storage and this fills it in place.
/// Keygen dominates the cost for Classic McEliece, so each test does exactly one.
macro_rules! setup {
    ($pk_buf:ident, $sk_buf:ident, $ss_buf:ident, $valid:ident, $genuine:ident, $sk:ident) => {
        let mut rng = LibQRng::new_deterministic(0x1234_5678_9ABC_DEF0);
        let mut $pk_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
        let mut $sk_buf = [0u8; CRYPTO_SECRETKEYBYTES];
        let (pk, $sk) = keypair(&mut $pk_buf, &mut $sk_buf, &mut rng);

        let mut $ss_buf = [0u8; CRYPTO_BYTES];
        let (valid_ct, genuine_ss) = encapsulate(&pk, &mut $ss_buf, &mut rng);
        let $valid: [u8; CRYPTO_CIPHERTEXTBYTES] = *valid_ct.as_array();
        let $genuine: [u8; CRYPTO_BYTES] = *genuine_ss.as_array();
    };
}

/// Baseline. Without this the whole file could pass because decapsulation is broken for every
/// input, genuine ones included, which would make "the tampered result differs" meaningless.
#[test]
fn genuine_ciphertext_decapsulates_to_the_encapsulated_secret() {
    setup!(pk_buf, sk_buf, ss_buf, valid_bytes, genuine_ss, sk);
    let mut out = [0u8; CRYPTO_BYTES];
    let recovered = decapsulate(&Ciphertext::from(valid_bytes), &sk, &mut out);
    assert_eq!(
        recovered.as_array(),
        &genuine_ss,
        "the unmodified ciphertext must decapsulate to the shared secret encapsulation produced; \
         if this fails, every other assertion in this file is vacuous"
    );
}

/// Flipping any single bit of the ciphertext must not yield the genuine shared secret.
///
/// Every byte position is covered rather than a sampled few: the ciphertext is a syndrome, and a
/// decoder bug that mishandles one region (a final partial byte, a length boundary) is exactly
/// what a sampled test walks past.
#[test]
fn every_single_bit_flip_fails_to_recover_the_genuine_secret() {
    setup!(pk_buf, sk_buf, ss_buf, valid_bytes, genuine_ss, sk);
    let mut out = [0u8; CRYPTO_BYTES];

    let mut checked = 0usize;
    for byte_index in 0..CRYPTO_CIPHERTEXTBYTES {
        for bit in 0..8u8 {
            let mut tampered = valid_bytes;
            tampered[byte_index] ^= 1 << bit;

            let recovered = decapsulate(&Ciphertext::from(tampered), &sk, &mut out);
            assert_ne!(
                recovered.as_array(),
                &genuine_ss,
                "flipping bit {bit} of ciphertext byte {byte_index} still recovered the genuine \
                 shared secret. Implicit rejection is not engaging, so a tampered ciphertext is \
                 accepted as authentic."
            );
            checked += 1;
        }
    }

    assert_eq!(
        checked,
        CRYPTO_CIPHERTEXTBYTES * 8,
        "expected to cover every bit of the ciphertext"
    );
}

/// Implicit rejection must be deterministic: the same rejected ciphertext must always give the
/// same value under the same key. A rejection path that returned fresh randomness would be
/// distinguishable from a genuine decapsulation by simply calling it twice.
#[test]
fn implicit_rejection_is_deterministic_for_a_fixed_key_and_ciphertext() {
    setup!(pk_buf, sk_buf, ss_buf, valid_bytes, _genuine_ss, sk);
    let mut tampered = valid_bytes;
    tampered[0] ^= 0x01;
    let ct = Ciphertext::from(tampered);

    let mut out_a = [0u8; CRYPTO_BYTES];
    let first = *decapsulate(&ct, &sk, &mut out_a).as_array();
    let mut out_b = [0u8; CRYPTO_BYTES];
    let second = *decapsulate(&ct, &sk, &mut out_b).as_array();

    assert_eq!(
        first, second,
        "the implicit-rejection value must be a deterministic function of (key, ciphertext); \
         differing results across calls means the fallback is drawing fresh randomness, which is \
         itself an oracle"
    );
}

/// Two different rejected ciphertexts must not collapse to one constant. A fallback that ignored
/// the ciphertext (returning, say, only a hash of the secret seed) would pass the determinism
/// test above while leaking that both inputs were rejected.
#[test]
fn distinct_rejected_ciphertexts_give_distinct_values() {
    setup!(pk_buf, sk_buf, ss_buf, valid_bytes, _genuine_ss, sk);

    let mut a = valid_bytes;
    a[0] ^= 0x01;
    let mut b = valid_bytes;
    b[1] ^= 0x80;

    let mut out_a = [0u8; CRYPTO_BYTES];
    let ss_a = *decapsulate(&Ciphertext::from(a), &sk, &mut out_a).as_array();
    let mut out_b = [0u8; CRYPTO_BYTES];
    let ss_b = *decapsulate(&Ciphertext::from(b), &sk, &mut out_b).as_array();

    assert_ne!(
        ss_a, ss_b,
        "two distinct rejected ciphertexts produced the same value, so the implicit-rejection \
         fallback is not binding the ciphertext into its output"
    );
}
