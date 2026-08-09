//! KAT Tests with AES-CTR-DRBG
//!
//! This module contains KAT (Known Answer Test) tests that use the AES-CTR-DRBG
//! implementation to achieve exact byte-for-byte compatibility with the reference implementation.

#[cfg(feature = "aes-drbg")]
use lib_q_hqc::{
    Hqc1Params,
    hqc_kem::HqcKem,
};

/// Helper function to convert hex string to bytes
#[allow(dead_code)]
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chars = hex.chars().peekable();

    while let (Some(c1), Some(c2)) = (chars.next(), chars.next()) {
        let byte = u8::from_str_radix(&format!("{}{}", c1, c2), 16).unwrap();
        bytes.push(byte);
    }

    bytes
}

// `test_kat_with_aes_drbg` was DELETED here (2026-08-09).
//
// It compared a generated public key against a hardcoded EXPECTED_PK_HEX and then -- whatever the
// result -- only `println!`d a tick or a cross and returned Ok. It could not fail. It closed with
// "This is expected to fail until AES-CTR-DRBG produces exact reference output", so the vacuity
// was deliberate and permanent.
//
// The expected constant could never have matched in any case: it decodes to 2225 bytes against
// this crate's 2241-byte HQC-128 public key. So the test was a non-assertion against garbage.
//
// CORRECTION (2026-08-09), superseding what this comment said when the deletion landed. Two claims
// here were wrong, and the fresh upstream oracle refutes both:
//   * "the constant came from an older revision of the HQC spec" -- no. The official HQC v5.0.0
//     hqc-1 public key IS 2241 bytes, same as this crate. 2225 = 2241 - 16, and the constant's
//     leading bytes `74b2d352cf74c934...` are byte 32 onward of the count=0 `seed` line. It was a
//     mis-sliced seed, not old-spec data.
//   * "byte-exact HQC conformance is blocked by an algorithmic divergence" -- no. HQC v5.0.0 has
//     no AES-CTR-DRBG at all; its PRNG is SHAKE256, and this crate's HQC-128 keygen, encaps and
//     decaps are byte-exact against the official upstream vectors. See
//     tests/reference_intermediates_kat.rs and kats/reference-intermediates/PROVENANCE.md.
// The only KEM-boundary gap is that upstream draws `seed_kem = SHAKE256(seed48 || 0x00)[0..32]`
// where `keygen_with_seed` uses `seed48[0..32]`.
//
// The deletion itself stands: this file's AES-CTR-DRBG path is chasing the pre-v5 NIST rng.c and
// is not what the current reference uses, so there was nothing valid for it to assert.

#[cfg(feature = "aes-drbg")]
#[test]
fn test_kat_encapsulation_with_aes_drbg() {
    println!("=== KAT Encapsulation Test with AES-CTR-DRBG (count=0) ===");

    // Official KAT seed (count=0)
    let seed = hex::decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1").unwrap();
    let seed_array: [u8; 48] = seed.try_into().unwrap();

    // Generate keypair using KEM
    let kem = HqcKem::<Hqc1Params>::new().unwrap();
    let (pk, sk) = kem.keygen_with_seed(&seed_array).unwrap();

    // Generate theta for encapsulation using the same PRNG approach
    let mut entropy_input = [0u8; 48];
    for (i, byte) in entropy_input.iter_mut().enumerate() {
        *byte = i as u8;
    }

    // Use AES-CTR-DRBG for encapsulation randomness
    use lib_q_hqc::aes_ctr_drbg::Aes256CtrDrbg;
    use rand_core::Rng;

    let mut rng_for_encaps = Aes256CtrDrbg::instantiate(&entropy_input);
    // Skip the seed generation bytes
    let mut _skip = [0u8; 32];
    rng_for_encaps.fill_bytes(&mut _skip);

    let (ct, ss) = kem.encapsulate(&pk, &mut rng_for_encaps).unwrap();

    println!("Ciphertext length: {} bytes", ct.as_bytes().len());
    println!("Ciphertext (first 32 bytes): {:02x?}", &ct.as_bytes()[..32]);
    println!("Shared secret length: {} bytes", ss.as_bytes().len());
    println!("Shared secret: {:02x?}", ss.as_bytes());

    // Test decapsulation
    let decapsulated_ss = kem.decapsulate(&sk, &ct).unwrap();

    // ASSERT, do not merely print. This previously branched on the comparison and printed a tick
    // or a cross either way, so a decapsulation returning the WRONG shared secret -- a total KEM
    // correctness failure -- reported success. Round-trip agreement is a genuine, checkable
    // property that needs no external vectors, so there is no excuse for not asserting it.
    assert_eq!(
        ss.as_bytes(),
        decapsulated_ss.as_bytes(),
        "HQC round-trip broken under AES-CTR-DRBG: decapsulated shared secret differs from the          encapsulated one"
    );
    assert_eq!(
        ss.as_bytes().len(),
        32,
        "HQC-128 shared secret must be 32 bytes"
    );
    assert!(!ct.as_bytes().is_empty(), "ciphertext must not be empty");
}

// `test_feature_disabled` was DELETED here (2026-08-09), on the second pass.
//
// It existed only to exist: gated on `#[cfg(not(feature = "aes-drbg"))]` and asserting that the
// feature is off. That is a tautology -- the cfg the compiler already evaluated to compile the
// test is the thing being asserted. My first repair of this file replaced its bare `println!`
// with `assert!(!cfg!(feature = "aes-drbg"))`, which turned it from a test that could not fail
// into one that could not compile: clippy's `assertions_on_constants` fires under `-D warnings`
// because both sides are compile-time constants, and CI rejected it.
//
// There is no runtime property here to test. The cfg attribute IS the guarantee.
