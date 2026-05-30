//! Comprehensive integration test for the full HQC implementation

#[cfg(feature = "alloc")]
extern crate alloc;

use lib_q_hqc::concatenated_code::ConcatenatedCode;
use lib_q_hqc::hqc_kem::HqcKem;
use lib_q_hqc::hqc_pke::HqcPke;
use lib_q_hqc::params_correct::{
    Hqc1Params,
    Hqc3Params,
    Hqc5Params,
    HqcParams,
};
use lib_q_hqc::reed_muller::ReedMuller;
use lib_q_hqc::reed_solomon::ReedSolomon;
use lib_q_hqc::shake256_prng::create_shake256_prng_rng;

/// NIST HQC KAT count=0 entropy (48 bytes); reused for deterministic KEM keygen at all levels.
const KEM_INTEGRATION_KEY_SEED_48: [u8; 48] = [
    0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A, 0x25,
    0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC, 0xFD, 0xE7,
    0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2, 0xE1, 0xFF, 0xA1,
];

/// 48-byte seed for `create_shake256_prng_rng` (encapsulation-only); `base` tags the test vector.
const fn kem_encaps_prng_seed(base: u8) -> [u8; 48] {
    let mut out = [0u8; 48];
    let mut i = 0usize;
    while i < 48 {
        out[i] = base.wrapping_add(i as u8);
        i += 1;
    }
    out
}

#[test]
fn test_full_hqc1_integration() {
    println!("Testing HQC-1 (128-bit security) full integration...");

    // Deterministic key + encapsulation PRNG so the shared-secret comparison is reproducible.
    let kem = HqcKem::<Hqc1Params>::new().expect("Failed to create HQC-1 KEM");
    let (public_key, secret_key) = kem
        .keygen_with_seed(&KEM_INTEGRATION_KEY_SEED_48)
        .expect("Failed to generate HQC-1 keypair");
    let mut enc_rng = create_shake256_prng_rng(kem_encaps_prng_seed(0xB1));

    // Encapsulate
    let (ciphertext, shared_secret1) = kem
        .encapsulate(&public_key, &mut enc_rng)
        .expect("Failed to encapsulate HQC-1");

    // Decapsulate
    let shared_secret2 = kem
        .decapsulate(&secret_key, &ciphertext)
        .expect("Failed to decapsulate HQC-1");

    // Verify sizes
    assert_eq!(public_key.as_bytes().len(), Hqc1Params::PUBLIC_KEY_BYTES);
    assert_eq!(ciphertext.as_bytes().len(), Hqc1Params::CIPHERTEXT_BYTES);
    assert_eq!(
        shared_secret1.as_bytes().len(),
        Hqc1Params::SHARED_SECRET_BYTES
    );
    assert_eq!(
        shared_secret2.as_bytes().len(),
        Hqc1Params::SHARED_SECRET_BYTES
    );
    assert_eq!(
        shared_secret1.as_bytes(),
        shared_secret2.as_bytes(),
        "HQC-1 shared secrets must match after roundtrip"
    );

    println!("✅ HQC-1 KEM integration test passed");
    println!("   Public key size: {} bytes", public_key.as_bytes().len());
    println!("   Ciphertext size: {} bytes", ciphertext.as_bytes().len());
    println!(
        "   Shared secret size: {} bytes",
        shared_secret1.as_bytes().len()
    );
}

#[test]
fn test_full_hqc3_integration() {
    println!("Testing HQC-3 (192-bit security) full integration...");

    let kem = HqcKem::<Hqc3Params>::new().expect("Failed to create HQC-3 KEM");
    let (public_key, secret_key) = kem
        .keygen_with_seed(&KEM_INTEGRATION_KEY_SEED_48)
        .expect("Failed to generate HQC-3 keypair");
    let mut enc_rng = create_shake256_prng_rng(kem_encaps_prng_seed(0xB3));

    // Encapsulate
    let (ciphertext, shared_secret1) = kem
        .encapsulate(&public_key, &mut enc_rng)
        .expect("Failed to encapsulate HQC-3");

    // Decapsulate
    let shared_secret2 = kem
        .decapsulate(&secret_key, &ciphertext)
        .expect("Failed to decapsulate HQC-3");

    // Verify sizes
    assert_eq!(public_key.as_bytes().len(), Hqc3Params::PUBLIC_KEY_BYTES);
    assert_eq!(ciphertext.as_bytes().len(), Hqc3Params::CIPHERTEXT_BYTES);
    assert_eq!(
        shared_secret1.as_bytes().len(),
        Hqc3Params::SHARED_SECRET_BYTES
    );
    assert_eq!(
        shared_secret2.as_bytes().len(),
        Hqc3Params::SHARED_SECRET_BYTES
    );
    assert_eq!(
        shared_secret1.as_bytes(),
        shared_secret2.as_bytes(),
        "HQC-3 shared secrets must match after roundtrip"
    );

    println!("✅ HQC-3 KEM integration test passed");
    println!("   Public key size: {} bytes", public_key.as_bytes().len());
    println!("   Ciphertext size: {} bytes", ciphertext.as_bytes().len());
    println!(
        "   Shared secret size: {} bytes",
        shared_secret1.as_bytes().len()
    );
}

#[test]
fn test_full_hqc5_integration() {
    println!("Testing HQC-5 (256-bit security) full integration...");

    let kem = HqcKem::<Hqc5Params>::new().expect("Failed to create HQC-5 KEM");
    let (public_key, secret_key) = kem
        .keygen_with_seed(&KEM_INTEGRATION_KEY_SEED_48)
        .expect("Failed to generate HQC-5 keypair");
    let mut enc_rng = create_shake256_prng_rng(kem_encaps_prng_seed(0xB5));

    // Encapsulate
    let (ciphertext, shared_secret1) = kem
        .encapsulate(&public_key, &mut enc_rng)
        .expect("Failed to encapsulate HQC-5");

    // Decapsulate
    let shared_secret2 = kem
        .decapsulate(&secret_key, &ciphertext)
        .expect("Failed to decapsulate HQC-5");

    // Verify sizes
    assert_eq!(public_key.as_bytes().len(), Hqc5Params::PUBLIC_KEY_BYTES);
    assert_eq!(ciphertext.as_bytes().len(), Hqc5Params::CIPHERTEXT_BYTES);
    assert_eq!(
        shared_secret1.as_bytes().len(),
        Hqc5Params::SHARED_SECRET_BYTES
    );
    assert_eq!(
        shared_secret2.as_bytes().len(),
        Hqc5Params::SHARED_SECRET_BYTES
    );
    assert_eq!(
        shared_secret1.as_bytes(),
        shared_secret2.as_bytes(),
        "HQC-5 shared secrets must match after roundtrip"
    );

    println!("✅ HQC-5 KEM integration test passed");
    println!("   Public key size: {} bytes", public_key.as_bytes().len());
    println!("   Ciphertext size: {} bytes", ciphertext.as_bytes().len());
    println!(
        "   Shared secret size: {} bytes",
        shared_secret1.as_bytes().len()
    );
}

#[test]
fn test_error_correcting_codes_integration() {
    println!("Testing error-correcting codes integration...");

    // Test Reed-Solomon
    let rs = ReedSolomon::<Hqc1Params>::new().expect("Failed to create Reed-Solomon code");
    let message = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let mut codeword = [0u8; 46];
    rs.encode(&message, &mut codeword)
        .expect("Failed to encode with Reed-Solomon");

    // Test Reed-Muller
    let rm = ReedMuller::<Hqc1Params>::new();
    let mut rm_codeword = [0u8; 384]; // N2 for HQC-1
    rm.encode(&message, &mut rm_codeword)
        .expect("Failed to encode with Reed-Muller");

    // Test Concatenated Code
    let cc = ConcatenatedCode::<Hqc1Params>::new().expect("Failed to create concatenated code");
    let mut cc_codeword = [0u8; 3680]; // VEC_N1N2_SIZE_BYTES for HQC-1
    cc.encode(&message, &mut cc_codeword)
        .expect("Failed to encode with concatenated code");

    println!("✅ Error-correcting codes integration test passed");
    println!(
        "   Reed-Solomon: {} -> {} bytes",
        message.len(),
        codeword.len()
    );
    println!(
        "   Reed-Muller: {} -> {} bytes",
        message.len(),
        rm_codeword.len()
    );
    println!(
        "   Concatenated: {} -> {} bytes",
        message.len(),
        cc_codeword.len()
    );
}

#[test]
fn test_pke_integration() {
    println!("Testing PKE integration...");

    let pke = HqcPke::<Hqc1Params>::new().expect("Failed to create PKE instance");

    // Exercise distinct keypairs with deterministic, varied seeds so the round-trip
    // assertion is reproducible in CI while still covering many independent keys.
    let trials = 16;
    let k_words = Hqc1Params::K.div_ceil(8);
    for i in 0..trials {
        let mut rng = create_shake256_prng_rng(kem_encaps_prng_seed(0x40u8.wrapping_add(i as u8)));
        let (public_key, secret_key) = pke
            .keygen(&mut rng)
            .expect("Failed to generate PKE keypair");

        // Message occupies the low K bytes; trailing words stay zero.
        let mut message = [0u64; 16];
        for (w, word) in message.iter_mut().take(k_words).enumerate() {
            *word = 0x0102_0304_0506_0708u64
                .wrapping_mul((i as u64) + 1)
                .wrapping_add(w as u64);
        }

        let mut theta = [0u8; 32];
        for (b, slot) in theta.iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(31).wrapping_add(b as u8);
        }

        let ciphertext = pke
            .encrypt(&public_key, &message[..k_words], &theta)
            .expect("Failed to encrypt with PKE");
        let decrypted = pke
            .decrypt(&secret_key, &ciphertext)
            .expect("Failed to decrypt with PKE");

        assert_eq!(
            &message[..k_words],
            &decrypted[..k_words],
            "PKE round-trip mismatch on trial {i}"
        );
    }

    println!("✅ PKE integration test passed ({trials} distinct keypairs)");
}

#[test]
fn test_multiple_kem_operations() {
    println!("Testing multiple KEM operations...");

    let kem = HqcKem::<Hqc1Params>::new().expect("Failed to create KEM");

    // Deterministic key material (NIST KAT seed) plus a SHAKE256 encapsulation PRNG keep the
    // shared-secret comparison reproducible across multiple encaps/decaps cycles on one keypair.
    // Coverage of many independent keys lives in `test_kem_roundtrip_varied_keys_all_params`.
    let (public_key, secret_key) = kem
        .keygen_with_seed(&KEM_INTEGRATION_KEY_SEED_48)
        .expect("Failed to generate keypair");

    let mut enc_rng = create_shake256_prng_rng([
        0xCE, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
        0x2D, 0x2E, 0x2F,
    ]);

    // Perform multiple encapsulate/decapsulate operations
    for i in 0..5 {
        let (ciphertext, shared_secret1) = kem
            .encapsulate(&public_key, &mut enc_rng)
            .expect("Failed to encapsulate");
        let shared_secret2 = kem
            .decapsulate(&secret_key, &ciphertext)
            .expect("Failed to decapsulate");

        assert_eq!(
            shared_secret1.as_bytes(),
            shared_secret2.as_bytes(),
            "HQC-1 shared secrets must match (iteration {})",
            i + 1
        );
        println!(
            "   Operation {}: Encapsulation and decapsulation completed",
            i + 1
        );
    }

    println!("✅ Multiple KEM operations test passed");
}

/// Exercises the full KEM round-trip across many independent keypairs for every
/// parameter set. Keys are derived from varied deterministic seeds (not a single
/// pinned seed) so the test covers a broad slice of the key space while remaining
/// reproducible in CI. A decapsulation mismatch here means PKE decryption failed to
/// recover the message — i.e. a decode-correctness regression, since HQC's spec
/// decryption-failure rate is cryptographically negligible.
#[test]
fn test_kem_roundtrip_varied_keys_all_params() {
    fn run<P: HqcParams>(label: &str, trials: usize) {
        let kem = HqcKem::<P>::new().expect("Failed to create KEM");
        for i in 0..trials {
            let key_seed = kem_encaps_prng_seed(0x10u8.wrapping_add(i as u8));
            let (public_key, secret_key) = kem
                .keygen_with_seed(&key_seed)
                .expect("Failed to generate keypair");

            let mut enc_rng =
                create_shake256_prng_rng(kem_encaps_prng_seed(0x90u8.wrapping_add(i as u8)));
            let (ciphertext, ss_send) = kem
                .encapsulate(&public_key, &mut enc_rng)
                .expect("Failed to encapsulate");
            let ss_recv = kem
                .decapsulate(&secret_key, &ciphertext)
                .expect("Failed to decapsulate");

            assert_eq!(
                ss_send.as_bytes(),
                ss_recv.as_bytes(),
                "{label}: shared-secret mismatch on trial {i} (decode-correctness regression)"
            );
        }
        println!("✅ {label}: {trials} varied-key KEM round-trips matched");
    }

    run::<Hqc1Params>("HQC-128", 24);
    run::<Hqc3Params>("HQC-192", 16);
    run::<Hqc5Params>("HQC-256", 12);
}
