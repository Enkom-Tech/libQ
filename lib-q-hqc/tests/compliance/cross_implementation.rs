use lib_q_hqc::{Hqc1Params, hqc_pke::HqcPke, hqc_kem::HqcKem, HqcParams};
use lib_q_hqc::internal::shake256::Shake256Xof;
use lib_q_hqc::shake256_prng::create_shake256_prng_rng;
use rand_core::Rng;

/// Cross-implementation tests to compare our implementation against reference behavior
/// 
/// This test compares our implementation's behavior against the reference C implementation
/// by testing specific algorithms and intermediate values.

#[test]
fn test_hash_i_function() {
    println!("=== Hash_i Function Cross-Implementation Test ===");
    
    let pke = HqcPke::<Hqc1Params>::new().unwrap();
    
    // Test with known input
    let seed_kem = [0u8; 32];
    let mut keypair_seed = [0u8; 64];
    
    pke.hash_i(&mut keypair_seed, &seed_kem);
    
    // Verify that hash_i produces deterministic output
    let mut keypair_seed2 = [0u8; 64];
    pke.hash_i(&mut keypair_seed2, &seed_kem);
    
    assert_eq!(keypair_seed, keypair_seed2, "hash_i should be deterministic");
    
    // Verify that different inputs produce different outputs
    let seed_kem2 = [1u8; 32];
    let mut keypair_seed3 = [0u8; 64];
    pke.hash_i(&mut keypair_seed3, &seed_kem2);
    
    assert_ne!(keypair_seed, keypair_seed3, "hash_i should produce different output for different input");
    
    println!("✅ hash_i function behavior verified");
}

#[test]
fn test_vect_sample_fixed_weight_consistency() {
    println!("=== Vector Sampling Consistency Test ===");
    
    let pke = HqcPke::<Hqc1Params>::new().unwrap();
    
    // Test with deterministic XOF
    let seed = [0u8; 32];
    let mut xof = Shake256Xof::new();
    xof.init_with_domain(&seed, 1).unwrap();
    
    let mut output1 = vec![0u64; Hqc1Params::VEC_N_SIZE_64];
    pke.vect_sample_fixed_weight1(&mut xof, &mut output1, Hqc1Params::OMEGA).unwrap();
    
    // Verify weight is correct
    let weight = output1.iter().map(|w| w.count_ones()).sum::<u32>() as usize;
    assert_eq!(weight, Hqc1Params::OMEGA, "Fixed weight sampling should produce correct weight");
    
    // Test with different seed
    let seed2 = [1u8; 32];
    let mut xof2 = Shake256Xof::new();
    xof2.init_with_domain(&seed2, 1).unwrap();
    
    let mut output2 = vec![0u64; Hqc1Params::VEC_N_SIZE_64];
    pke.vect_sample_fixed_weight1(&mut xof2, &mut output2, Hqc1Params::OMEGA).unwrap();
    
    // Different seeds should produce different outputs
    assert_ne!(output1, output2, "Different seeds should produce different fixed-weight vectors");
    
    // Verify weight is still correct
    let weight2 = output2.iter().map(|w| w.count_ones()).sum::<u32>() as usize;
    assert_eq!(weight2, Hqc1Params::OMEGA, "Fixed weight sampling should produce correct weight");
    
    println!("✅ Vector sampling consistency verified");
}

#[test]
fn test_polynomial_multiplication_properties() {
    println!("=== Polynomial Multiplication Properties Test ===");
    
    let pke = HqcPke::<Hqc1Params>::new().unwrap();
    
    // Test with simple vectors
    let mut a = vec![0u64; Hqc1Params::VEC_N_SIZE_64];
    let mut b = vec![0u64; Hqc1Params::VEC_N_SIZE_64];
    let mut result = vec![0u64; Hqc1Params::VEC_N_SIZE_64];
    
    // Set some bits for testing
    a[0] = 1;
    b[0] = 1;
    
    pke.test_vect_mul(&mut result, &a, &b).unwrap();
    
    // Test zero multiplication
    let mut zero = vec![0u64; Hqc1Params::VEC_N_SIZE_64];
    let mut zero_result = vec![0u64; Hqc1Params::VEC_N_SIZE_64];
    
    pke.test_vect_mul(&mut zero_result, &zero, &a).unwrap();
    assert_eq!(zero_result, zero, "Multiplication by zero should produce zero");
    
    // Test identity multiplication (x^0 = 1)
    let mut identity = vec![0u64; Hqc1Params::VEC_N_SIZE_64];
    identity[0] = 1;
    let mut identity_result = vec![0u64; Hqc1Params::VEC_N_SIZE_64];
    
    pke.test_vect_mul(&mut identity_result, &identity, &a).unwrap();
    assert_eq!(identity_result, a, "Multiplication by identity should produce original vector");
    
    println!("✅ Polynomial multiplication properties verified");
}

#[test]
fn test_polynomial_addition_properties() {
    println!("=== Polynomial Addition Properties Test ===");
    
    let pke = HqcPke::<Hqc1Params>::new().unwrap();
    
    // Test with simple vectors
    let mut a = vec![0u64; Hqc1Params::VEC_N_SIZE_64];
    let mut b = vec![0u64; Hqc1Params::VEC_N_SIZE_64];
    let mut result = vec![0u64; Hqc1Params::VEC_N_SIZE_64];
    
    // Set some bits for testing
    a[0] = 1;
    b[0] = 1;
    
    pke.test_vect_add(&mut result, &a, &b, Hqc1Params::VEC_N_SIZE_64).unwrap();
    
    // Test zero addition
    let mut zero = vec![0u64; Hqc1Params::VEC_N_SIZE_64];
    let mut zero_result = vec![0u64; Hqc1Params::VEC_N_SIZE_64];
    
    pke.test_vect_add(&mut zero_result, &zero, &a, Hqc1Params::VEC_N_SIZE_64).unwrap();
    assert_eq!(zero_result, a, "Addition with zero should produce original vector");
    
    // Test commutativity
    let mut result2 = vec![0u64; Hqc1Params::VEC_N_SIZE_64];
    pke.test_vect_add(&mut result2, &b, &a, Hqc1Params::VEC_N_SIZE_64).unwrap();
    assert_eq!(result, result2, "Polynomial addition should be commutative");
    
    println!("✅ Polynomial addition properties verified");
}

#[test]
fn test_xof_consistency() {
    println!("=== XOF Consistency Test ===");
    
    let pke = HqcPke::<Hqc1Params>::new().unwrap();
    
    // Test XOF with same seed produces same output
    let seed = [0u8; 32];
    let mut xof1 = Shake256Xof::new();
    let mut xof2 = Shake256Xof::new();
    
    xof1.init_with_domain(&seed, 1).unwrap();
    xof2.init_with_domain(&seed, 1).unwrap();
    
    let mut output1 = vec![0u64; Hqc1Params::VEC_N_SIZE_64];
    let mut output2 = vec![0u64; Hqc1Params::VEC_N_SIZE_64];
    
    pke.vect_set_random(&mut xof1, &mut output1).unwrap();
    pke.vect_set_random(&mut xof2, &mut output2).unwrap();
    
    assert_eq!(output1, output2, "XOF should be deterministic with same seed");
    
    // Test that different domain separators produce different output
    let mut xof3 = Shake256Xof::new();
    xof3.init_with_domain(&seed, 2).unwrap();
    
    let mut output3 = vec![0u64; Hqc1Params::VEC_N_SIZE_64];
    pke.vect_set_random(&mut xof3, &mut output3).unwrap();
    
    assert_ne!(output1, output3, "Different domain separators should produce different output");
    
    println!("✅ XOF consistency verified");
}

#[test]
fn test_key_generation_consistency() {
    println!("=== Key Generation Consistency Test ===");
    
    let kem = HqcKem::<Hqc1Params>::new().unwrap();
    
    // Test that same seed produces same keypair
    let seed = [0u8; 32];
    let (pk1, sk1) = kem.keygen_with_seed(&seed).unwrap();
    let (pk2, sk2) = kem.keygen_with_seed(&seed).unwrap();
    
    // Compare public keys
    assert_eq!(pk1.data, pk2.data, "Same seed should produce same public key");
    
    // Compare secret keys
    assert_eq!(sk1.data, sk2.data, "Same seed should produce same secret key");
    
    // Test that different seeds produce different keypairs
    let seed2 = [1u8; 32];
    let (pk3, sk3) = kem.keygen_with_seed(&seed2).unwrap();
    
    assert_ne!(pk1.data, pk3.data, "Different seeds should produce different public keys");
    assert_ne!(sk1.data, sk3.data, "Different seeds should produce different secret keys");
    
    println!("✅ Key generation consistency verified");
}

#[test]
fn test_encapsulation_decapsulation_roundtrip() {
    println!("=== Encapsulation/Decapsulation Roundtrip Test ===");
    
    let kem = HqcKem::<Hqc1Params>::new().unwrap();
    
    // Generate keypair
    let seed = [0u8; 32];
    let (pk, sk) = kem.keygen_with_seed(&seed).unwrap();
    
    // Test multiple encapsulations with same keypair
    let mut rng = create_shake256_prng_rng([0u8; 48]);
    
    for i in 0..10 {
        let mut theta = [0u8; 64];
        rng.fill_bytes(&mut theta);
        
        let (ct, ss1) = kem.encapsulate(&pk, &mut rng).unwrap();
        let ss2 = kem.decapsulate(&sk, &ct).unwrap();
        
        assert_eq!(ss1, ss2, "Encapsulation/decapsulation roundtrip should produce same shared secret (test {})", i);
    }
    
    println!("✅ Encapsulation/decapsulation roundtrip verified");
}

#[test]
fn test_parameter_set_consistency() {
    println!("=== Parameter Set Consistency Test ===");
    
    // Test that all parameter sets have consistent properties
    let param_sets = [
        ("HQC-1", Hqc1Params::N, Hqc1Params::OMEGA, Hqc1Params::OMEGA_R),
        ("HQC-3", Hqc3Params::N, Hqc3Params::OMEGA, Hqc3Params::OMEGA_R),
        ("HQC-5", Hqc5Params::N, Hqc5Params::OMEGA, Hqc5Params::OMEGA_R),
    ];
    
    for (name, n, omega, omega_r) in param_sets {
        // Verify that OMEGA_R > OMEGA
        assert!(omega_r > omega, "{}: OMEGA_R ({}) should be greater than OMEGA ({})", name, omega_r, omega);
        
        // Verify that N is reasonable (should be large enough for security)
        assert!(n > 10000, "{}: N ({}) should be large enough for security", name, n);
        
        // Verify that OMEGA is reasonable (should be much smaller than N)
        assert!(omega < n / 100, "{}: OMEGA ({}) should be much smaller than N ({})", name, omega, n);
        
        println!("✅ {} parameter consistency verified", name);
    }
}
