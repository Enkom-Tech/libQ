//! Constant-time test for Classical McEliece decapsulation's implicit-rejection path.
//!
//! `operations::crypto_kem_dec` implements the Fujisaki-Okamoto-style implicit
//! rejection: whether the ciphertext decodes to the claimed error weight or not, it
//! runs the exact same operations and only differs by a branchless bitmask (`m`)
//! that selects between the real decrypted error vector `e` and the secret-derived
//! pseudorandom fallback `s` before hashing:
//!
//! ```text
//! preimage[1 + i] = (!m as u8 & s[i]) | (m as u8 & e[i]);
//! ```
//!
//! That masking exists specifically so decapsulation time does not reveal whether a
//! ciphertext was valid -- the property a chosen-ciphertext attacker would otherwise
//! exploit. This test checks it from the outside, on the public API, by comparing
//! decapsulation timing for a genuine ciphertext against a bit-flipped (invalid)
//! one under the same keypair.
//!
//! Coarse wall-clock smoke test only -- see `lib-q-k12/tests/constant_time.rs` for
//! the caveat spelled out in full. A pass here is not a side-channel proof; it is a
//! check that the masking has not regressed into an actual branch (e.g. an early
//! return, or a length check on `e`/`s` that only fires one way).

use std::time::{
    Duration,
    Instant,
};

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

/// Keygen is the expensive part of Classical McEliece; decapsulation is cheap.
/// A handful of repetitions is enough for a coarse ratio check without making the
/// step slow (this crate's default features + `cbkem348864`, the smallest variant).
const ITERATIONS: usize = 40;
const REPS: usize = 5;

fn min_time(iterations: usize, mut op: impl FnMut()) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..REPS {
        let start = Instant::now();
        for _ in 0..iterations {
            op();
        }
        let elapsed = start.elapsed();
        if elapsed < best {
            best = elapsed;
        }
    }
    best
}

#[test]
fn test_decapsulate_constant_time_valid_vs_invalid_ciphertext() {
    let mut rng = LibQRng::new_deterministic(0xC0FF_EEC0_FFEE_C0DE);
    let mut pk_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut sk_buf = [0u8; CRYPTO_SECRETKEYBYTES];
    let (pk, sk) = keypair(&mut pk_buf, &mut sk_buf, &mut rng);

    let mut ss_buf = [0u8; CRYPTO_BYTES];
    let (valid_ct, _shared_secret) = encapsulate(&pk, &mut ss_buf, &mut rng);

    // Flip a single bit of the syndrome so decryption fails and the implicit-rejection
    // branch (the `s`-instead-of-`e` mask) is exercised. For any real Goppa code this makes
    // decoding fail with overwhelming probability -- it is not a targeted attack, just noise.
    let mut invalid_bytes: [u8; CRYPTO_CIPHERTEXTBYTES] = *valid_ct.as_array();
    invalid_bytes[0] ^= 0x01;
    let invalid_ct = Ciphertext::from(invalid_bytes);

    let mut out_buf = [0u8; CRYPTO_BYTES];

    // Warm up both paths.
    for _ in 0..5 {
        let _ = decapsulate(&valid_ct, &sk, &mut out_buf);
        let _ = decapsulate(&invalid_ct, &sk, &mut out_buf);
    }

    let valid_time = min_time(ITERATIONS, || {
        let shared_secret = decapsulate(&valid_ct, &sk, &mut out_buf);
        std::hint::black_box(shared_secret.as_array());
    });
    let invalid_time = min_time(ITERATIONS, || {
        let shared_secret = decapsulate(&invalid_ct, &sk, &mut out_buf);
        std::hint::black_box(shared_secret.as_array());
    });

    let avg = (valid_time + invalid_time) / 2;
    let diff = valid_time.abs_diff(invalid_time);
    // Both paths do identical work (mask, not branch); allow generous CI-runner noise.
    let tolerance = avg * 50 / 100;

    assert!(
        diff <= tolerance,
        "decapsulate() timing depends on ciphertext validity: valid={valid_time:?} invalid={invalid_time:?} diff={diff:?} tolerance={tolerance:?}"
    );
}
