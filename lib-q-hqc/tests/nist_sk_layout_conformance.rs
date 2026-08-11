//! NIST secret-key layout conformance: checks `HqcKemSecretKey::to_nist_bytes`/`from_nist_bytes`
//! against the official HQC v5.0.0 reference secret-key layout, built from first principles off
//! the reference C struct rather than a literal reference-generated KAT vector (none exists for
//! this exact new layout — see `lib-q-hqc/kats/regression-pins/PROVENANCE.md`, "CORRECTION
//! 2026-08-11").
//!
//! Reference layout, `reference/hqc/src/common/kem.c:63-67` (`crypto_kem_keypair`):
//! ```c
//! memcpy(dk_kem,                                                       ek_kem,   PUBLIC_KEY_BYTES);
//! memcpy(dk_kem + PUBLIC_KEY_BYTES,                                    dk_pke,   SEED_BYTES);          // 32
//! memcpy(dk_kem + PUBLIC_KEY_BYTES + SEED_BYTES,                       sigma,    PARAM_SECURITY_BYTES); // 16/24/32
//! memcpy(dk_kem + PUBLIC_KEY_BYTES + SEED_BYTES + PARAM_SECURITY_BYTES, seed_kem, SEED_BYTES);          // 32
//! ```
//! i.e. `dk_kem = ek_pke ‖ dk_pke(32) ‖ sigma(K) ‖ seed_kem(32)`, whose total length equals
//! upstream `CRYPTO_SECRETKEYBYTES` at every level (`src/common/hqc-{1,3,5}/api.h`):
//! `2241+32+16+32 = 2321`, `4514+32+24+32 = 4602`, `7237+32+32+32 = 7333`.
//!
//! Needs a `[[test]]` entry in `Cargo.toml` (it has one): a file gated by an inner `cfg` with no
//! corresponding entry silently compiles to nothing and reports `running 0 tests ... ok`. Always
//! read the COUNT when running this.

#![cfg(all(feature = "alloc", feature = "hqc", feature = "random"))]

use lib_q_hqc::hqc_kem::{
    HqcKem,
    HqcKemSecretKey,
};
use lib_q_hqc::params::{
    Hqc1Params,
    Hqc3Params,
    Hqc5Params,
    HqcParams,
};

/// Encodes a keypair and checks every field's offset and width against
/// the reference struct layout, independently of `nist_secret_key_len()` (which is the
/// implementation under test — this derives the expected split from `P`'s own published sizes so
/// a bug in both the encoder and the length helper at once would still be caught).
fn check_reference_layout<P: HqcParams>(seed_byte: u8) {
    let kem = HqcKem::<P>::new().expect("HqcKem::new");
    let seed = [seed_byte; 48];
    let (_pk, sk) = kem.keygen_with_seed(&seed).expect("keygen_with_seed");

    let (ek_pke, dk_pke, sigma, seed_kem) = sk.parse();
    let bytes = sk.to_nist_bytes();

    // Total length: ek_pke ‖ dk_pke(32) ‖ sigma(K) ‖ seed_kem(32).
    let expected_len = P::PUBLIC_KEY_BYTES + 32 + P::K + 32;
    assert_eq!(
        bytes.len(),
        expected_len,
        "reference-layout sk length must be ek_pke + 32 + K + 32"
    );
    assert_eq!(
        bytes.len(),
        HqcKemSecretKey::<P>::nist_secret_key_len(),
        "nist_secret_key_len() must agree with the actual encoded length"
    );

    // Field 1: ek_pke, at offset 0, PUBLIC_KEY_BYTES wide.
    assert_eq!(
        &bytes[..P::PUBLIC_KEY_BYTES],
        ek_pke.as_bytes(),
        "ek_pke must be the first field (upstream writes it first, this crate's legacy layout \
         wrote it last)"
    );

    // Field 2: dk_pke, immediately after ek_pke, 32 bytes wide.
    let dk_off = P::PUBLIC_KEY_BYTES;
    assert_eq!(
        &bytes[dk_off..dk_off + 32],
        &dk_pke.data[..],
        "dk_pke must follow ek_pke, 32 bytes wide"
    );

    // Field 3: sigma, immediately after dk_pke, K (PARAM_SECURITY_BYTES) bytes wide.
    let sigma_off = dk_off + 32;
    assert_eq!(
        &bytes[sigma_off..sigma_off + P::K],
        &sigma[..P::K],
        "sigma must follow dk_pke, PARAM_SECURITY_BYTES (K) bytes wide"
    );

    // Field 4: seed_kem, the trailing 32 bytes -- the field the legacy layout omitted entirely.
    let seed_off = sigma_off + P::K;
    assert_eq!(
        seed_off + 32,
        bytes.len(),
        "seed_kem must be the final field, 32 bytes wide"
    );
    assert_eq!(
        &bytes[seed_off..],
        &seed_kem[..32],
        "trailing 32 bytes must be the first 32 bytes of seed_kem"
    );

    // Round-trip: from_nist_bytes must reconstruct a key that decapsulates identically.
    let restored = HqcKemSecretKey::<P>::from_nist_bytes(&bytes).expect("from_nist_bytes");
    assert_eq!(
        bytes,
        restored.to_nist_bytes(),
        "reference-layout round-trip must be byte-exact"
    );

    let m = vec![0x11u8; P::K];
    let salt = [0x22u8; 16];
    let (ciphertext, shared_secret) = kem
        .encapsulate_with_m_salt(&_pk, &m, &salt)
        .expect("encapsulate_with_m_salt");
    let decapsulated = kem
        .decapsulate(&restored, &ciphertext)
        .expect("decapsulate");
    assert_eq!(
        shared_secret.as_bytes(),
        decapsulated.as_bytes(),
        "decapsulation with the v5-layout-round-tripped key must recover the shared secret"
    );
}

#[test]
fn hqc1_layout_matches_reference_struct() {
    check_reference_layout::<Hqc1Params>(0xA1);
    // Matches upstream CRYPTO_SECRETKEYBYTES for hqc-128 (`src/common/hqc-1/api.h`): 2321.
    assert_eq!(HqcKemSecretKey::<Hqc1Params>::nist_secret_key_len(), 2321);
}

#[test]
fn hqc3_layout_matches_reference_struct() {
    check_reference_layout::<Hqc3Params>(0xA3);
    // Matches upstream CRYPTO_SECRETKEYBYTES for hqc-192 (`src/common/hqc-3/api.h`): 4602.
    assert_eq!(HqcKemSecretKey::<Hqc3Params>::nist_secret_key_len(), 4602);
}

#[test]
fn hqc5_layout_matches_reference_struct() {
    check_reference_layout::<Hqc5Params>(0xA5);
    // Matches upstream CRYPTO_SECRETKEYBYTES for hqc-256 (`src/common/hqc-5/api.h`): 7333.
    assert_eq!(HqcKemSecretKey::<Hqc5Params>::nist_secret_key_len(), 7333);
}

/// `from_nist_bytes` must still reject the wrong length under the v5 layout (not just the legacy
/// one) -- a length check that only ever compiles under one cfg arm is easy to silently drop.
#[test]
fn hqc1_layout_rejects_wrong_length() {
    let too_short = vec![0u8; HqcKemSecretKey::<Hqc1Params>::nist_secret_key_len() - 1];
    assert!(HqcKemSecretKey::<Hqc1Params>::from_nist_bytes(&too_short).is_err());

    let too_long = vec![0u8; HqcKemSecretKey::<Hqc1Params>::nist_secret_key_len() + 1];
    assert!(HqcKemSecretKey::<Hqc1Params>::from_nist_bytes(&too_long).is_err());
}
