// Diagnostic mode tests
#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
use lib_q_hqc::hqc_kem::HqcKem;
#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
use lib_q_hqc::hqc_pke::HqcPke;
#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
use lib_q_hqc::params_correct::Hqc1Params;

#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
#[test]
fn test_kem_full_cycle_consistency() {
    println!("=== KEM Full Cycle Consistency Test ===\n");

    let kem = HqcKem::<Hqc1Params>::new().unwrap();
    let seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    // Generate keypair
    let (pk, sk) = kem.keygen_with_seed(&seed).unwrap();

    // Create RNG for encapsulation - use a simple deterministic RNG for testing
    use rand_core::{
        CryptoRng,
        RngCore,
    };
    struct TestRng {
        counter: u64,
    }
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.counter = self.counter.wrapping_add(1);
            self.counter as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.counter = self.counter.wrapping_add(1);
            self.counter
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest.iter_mut() {
                *byte = (self.counter & 0xFF) as u8;
                self.counter = self.counter.wrapping_add(1);
            }
        }
    }
    impl CryptoRng for TestRng {}
    let mut rng = TestRng { counter: 0 };

    // Encapsulate
    let (ct, ss_enc) = kem.encapsulate(&pk, &mut rng).unwrap();

    // Decapsulate
    let ss_dec = kem.decapsulate(&sk, &ct).unwrap();

    // Verify shared secrets match
    assert_eq!(ss_enc, ss_dec, "Shared secrets must match");

    println!("✅ KEM encapsulation/decapsulation successful");
}

#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
#[test]
fn test_kem_multiple_encapsulations() {
    println!("=== KEM Multiple Encapsulations Test ===\n");

    let kem = HqcKem::<Hqc1Params>::new().unwrap();
    let seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    let (pk, sk) = kem.keygen_with_seed(&seed).unwrap();

    // Create RNG for encapsulation - use a simple deterministic RNG for testing
    use rand_core::{
        CryptoRng,
        RngCore,
    };
    struct TestRng {
        counter: u64,
    }
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.counter = self.counter.wrapping_add(1);
            self.counter as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.counter = self.counter.wrapping_add(1);
            self.counter
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest.iter_mut() {
                *byte = (self.counter & 0xFF) as u8;
                self.counter = self.counter.wrapping_add(1);
            }
        }
    }
    impl CryptoRng for TestRng {}
    let mut rng = TestRng { counter: 0 };

    // Multiple encapsulation/decapsulation cycles
    for i in 0..10 {
        let (ct, ss_enc) = kem.encapsulate(&pk, &mut rng).unwrap();
        let ss_dec = kem.decapsulate(&sk, &ct).unwrap();

        assert_eq!(ss_enc, ss_dec, "Cycle {} shared secrets must match", i);
    }

    println!("✅ Multiple KEM cycles successful");
}

#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
#[test]
fn test_pke_full_cycle_consistency() {
    println!("=== PKE Full Cycle Consistency Test ===\n");

    let pke = HqcPke::<Hqc1Params>::new().unwrap();
    let seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    let (pk, sk) = pke.keygen_with_seed(&seed).unwrap();

    // Test with various message sizes
    for size in &[1, 16, 32, 64, 128] {
        let message_bytes = vec![0xABu8; *size];
        let mut message = vec![0u64; message_bytes.len().div_ceil(8)];
        for (i, &byte) in message_bytes.iter().enumerate() {
            let word_idx = i / 8;
            let bit_idx = i % 8;
            message[word_idx] |= (byte as u64) << (bit_idx * 8);
        }

        let theta = [0u8; 16]; // PARAM_SECURITY_BYTES
        let ct = pke.encrypt(&pk, &message, &theta).unwrap();
        let pt = pke.decrypt(&sk, &ct).unwrap();

        // Convert back to bytes for comparison
        let mut pt_bytes = vec![0u8; message_bytes.len()];
        for (i, &word) in pt.iter().enumerate() {
            for bit_idx in 0..8 {
                let byte_idx = i * 8 + bit_idx;
                if byte_idx < pt_bytes.len() {
                    pt_bytes[byte_idx] = ((word >> (bit_idx * 8)) & 0xFF) as u8;
                }
            }
        }

        assert_eq!(
            &pt_bytes[..*size],
            &message_bytes[..],
            "Message size {} must round-trip",
            size
        );
    }

    println!("✅ PKE operations consistent across message sizes");
}

#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
#[test]
fn test_vector_operations_determinism() {
    println!("=== Vector Operations Determinism Test ===\n");

    let pke = HqcPke::<Hqc1Params>::new().unwrap();
    let seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    // Generate keys multiple times with same seed
    let mut public_keys = Vec::new();
    let mut secret_keys = Vec::new();

    for _ in 0..5 {
        let (pk, sk) = pke.keygen_with_seed(&seed).unwrap();
        public_keys.push(pk);
        secret_keys.push(sk);
    }

    // Verify all public keys are identical
    for i in 1..public_keys.len() {
        assert_eq!(
            public_keys[0].as_bytes(),
            public_keys[i].as_bytes(),
            "Public key {} must match first",
            i
        );
    }

    // Verify all secret keys are identical
    for i in 1..secret_keys.len() {
        assert_eq!(
            secret_keys[0].data, secret_keys[i].data,
            "Secret key {} must match first",
            i
        );
    }

    println!("✅ Vector operations are deterministic");
}

#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
#[test]
fn test_full_operations_with_diagnostic_logging() {
    println!("=== Full Operations with Diagnostic Logging ===");

    let kem = HqcKem::<Hqc1Params>::new().unwrap();
    let seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    // Generate keypair using diagnostic mode
    let (pk, sk) = kem.keygen_with_seed(&seed).unwrap();

    // Create RNG for encapsulation - use a simple deterministic RNG for testing
    use rand_core::{
        CryptoRng,
        RngCore,
    };
    struct TestRng {
        counter: u64,
    }
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.counter = self.counter.wrapping_add(1);
            self.counter as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.counter = self.counter.wrapping_add(1);
            self.counter
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest.iter_mut() {
                *byte = (self.counter & 0xFF) as u8;
                self.counter = self.counter.wrapping_add(1);
            }
        }
    }
    impl CryptoRng for TestRng {}
    let mut rng = TestRng { counter: 0 };

    // Encapsulate using diagnostic mode
    let (ciphertext, shared_secret) = kem.encapsulate(&pk, &mut rng).unwrap();

    // Decapsulate using diagnostic mode
    let decapsulated_secret = kem.decapsulate(&sk, &ciphertext).unwrap();

    assert_eq!(
        shared_secret, decapsulated_secret,
        "Shared secrets must match"
    );

    println!("Generated public key: {:02x?}", &pk.as_bytes()[..16]);
    println!("Generated secret key: {:02x?}", &sk.as_bytes()[..16]);
    println!("Ciphertext: {:02x?}", &ciphertext.as_bytes()[..16]);
    println!("Shared secret: {:02x?}", &shared_secret.as_bytes()[..16]);

    // Note: The actual diagnostic logs would be captured by the DualModeDrbg
    // inside the keygen_with_seed call, but we can't access them directly here
    // since they're internal to the DRBG wrapper.

    println!("✅ Full KEM operations completed with diagnostic mode");
    println!("   (Diagnostic logs are captured internally by DualModeDrbg)");
}
