use lib_q_hqc::{Hqc1Params, Hqc3Params, Hqc5Params, HqcParams};

/// Parameter validation tests to ensure all constants match the HQC specification
/// 
/// This test verifies that our parameter sets match the official HQC specification
/// and reference implementation parameters.

#[test]
fn test_hqc1_parameters() {
    println!("=== HQC-1 Parameter Validation ===");
    
    // Verify HQC-1 parameters against specification
    assert_eq!(Hqc1Params::N, 17669, "HQC-1 N parameter");
    assert_eq!(Hqc1Params::N1, 46, "HQC-1 N1 parameter");
    assert_eq!(Hqc1Params::N2, 384, "HQC-1 N2 parameter");
    assert_eq!(Hqc1Params::OMEGA, 66, "HQC-1 OMEGA parameter");
    assert_eq!(Hqc1Params::OMEGA_R, 75, "HQC-1 OMEGA_R parameter");
    
    // Verify derived parameters
    assert_eq!(Hqc1Params::VEC_N_SIZE_64, 277, "HQC-1 VEC_N_SIZE_64 parameter");
    assert_eq!(Hqc1Params::VEC_N1N2_SIZE_64, 276, "HQC-1 VEC_N1N2_SIZE_64 parameter");
    
    // Verify key and ciphertext sizes
    assert_eq!(Hqc1Params::SECRET_KEY_BYTES, 2321, "HQC-1 SECRET_KEY_BYTES");
    assert_eq!(Hqc1Params::PUBLIC_KEY_BYTES, 2321, "HQC-1 PUBLIC_KEY_BYTES");
    assert_eq!(Hqc1Params::CIPHERTEXT_BYTES, 2321, "HQC-1 CIPHERTEXT_BYTES");
    assert_eq!(Hqc1Params::SHARED_SECRET_BYTES, 32, "HQC-1 SHARED_SECRET_BYTES");
    
    println!("✅ HQC-1 parameters validated");
}

#[test]
fn test_hqc3_parameters() {
    println!("=== HQC-3 Parameter Validation ===");
    
    // Verify HQC-3 parameters against specification
    assert_eq!(Hqc3Params::N, 35851, "HQC-3 N parameter");
    assert_eq!(Hqc3Params::N1, 46, "HQC-3 N1 parameter");
    assert_eq!(Hqc3Params::N2, 768, "HQC-3 N2 parameter");
    assert_eq!(Hqc3Params::OMEGA, 103, "HQC-3 OMEGA parameter");
    assert_eq!(Hqc3Params::OMEGA_R, 115, "HQC-3 OMEGA_R parameter");
    
    // Verify derived parameters
    assert_eq!(Hqc3Params::VEC_N_SIZE_64, 561, "HQC-3 VEC_N_SIZE_64 parameter");
    assert_eq!(Hqc3Params::VEC_N1N2_SIZE_64, 560, "HQC-3 VEC_N1N2_SIZE_64 parameter");
    
    // Verify key and ciphertext sizes
    assert_eq!(Hqc3Params::SECRET_KEY_BYTES, 4602, "HQC-3 SECRET_KEY_BYTES");
    assert_eq!(Hqc3Params::PUBLIC_KEY_BYTES, 4602, "HQC-3 PUBLIC_KEY_BYTES");
    assert_eq!(Hqc3Params::CIPHERTEXT_BYTES, 4602, "HQC-3 CIPHERTEXT_BYTES");
    assert_eq!(Hqc3Params::SHARED_SECRET_BYTES, 32, "HQC-3 SHARED_SECRET_BYTES");
    
    println!("✅ HQC-3 parameters validated");
}

#[test]
fn test_hqc5_parameters() {
    println!("=== HQC-5 Parameter Validation ===");
    
    // Verify HQC-5 parameters against specification
    assert_eq!(Hqc5Params::N, 57637, "HQC-5 N parameter");
    assert_eq!(Hqc5Params::N1, 46, "HQC-5 N1 parameter");
    assert_eq!(Hqc5Params::N2, 1152, "HQC-5 N2 parameter");
    assert_eq!(Hqc5Params::OMEGA, 134, "HQC-5 OMEGA parameter");
    assert_eq!(Hqc5Params::OMEGA_R, 149, "HQC-5 OMEGA_R parameter");
    
    // Verify derived parameters
    assert_eq!(Hqc5Params::VEC_N_SIZE_64, 901, "HQC-5 VEC_N_SIZE_64 parameter");
    assert_eq!(Hqc5Params::VEC_N1N2_SIZE_64, 900, "HQC-5 VEC_N1N2_SIZE_64 parameter");
    
    // Verify key and ciphertext sizes
    assert_eq!(Hqc5Params::SECRET_KEY_BYTES, 7333, "HQC-5 SECRET_KEY_BYTES");
    assert_eq!(Hqc5Params::PUBLIC_KEY_BYTES, 7333, "HQC-5 PUBLIC_KEY_BYTES");
    assert_eq!(Hqc5Params::CIPHERTEXT_BYTES, 7333, "HQC-5 CIPHERTEXT_BYTES");
    assert_eq!(Hqc5Params::SHARED_SECRET_BYTES, 32, "HQC-5 SHARED_SECRET_BYTES");
    
    println!("✅ HQC-5 parameters validated");
}

#[test]
fn test_parameter_consistency() {
    println!("=== Parameter Consistency Validation ===");
    
    // Verify that N1 is consistent across all parameter sets
    assert_eq!(Hqc1Params::N1, 46, "N1 should be 46 for all HQC parameter sets");
    assert_eq!(Hqc3Params::N1, 46, "N1 should be 46 for all HQC parameter sets");
    assert_eq!(Hqc5Params::N1, 46, "N1 should be 46 for all HQC parameter sets");
    
    // Verify that N2 increases with security level
    assert!(Hqc1Params::N2 < Hqc3Params::N2, "N2 should increase with security level");
    assert!(Hqc3Params::N2 < Hqc5Params::N2, "N2 should increase with security level");
    
    // Verify that OMEGA increases with security level
    assert!(Hqc1Params::OMEGA < Hqc3Params::OMEGA, "OMEGA should increase with security level");
    assert!(Hqc3Params::OMEGA < Hqc5Params::OMEGA, "OMEGA should increase with security level");
    
    // Verify that OMEGA_R > OMEGA for all parameter sets
    assert!(Hqc1Params::OMEGA_R > Hqc1Params::OMEGA, "OMEGA_R should be greater than OMEGA");
    assert!(Hqc3Params::OMEGA_R > Hqc3Params::OMEGA, "OMEGA_R should be greater than OMEGA");
    assert!(Hqc5Params::OMEGA_R > Hqc5Params::OMEGA, "OMEGA_R should be greater than OMEGA");
    
    // Verify that key sizes increase with security level
    assert!(Hqc1Params::SECRET_KEY_BYTES < Hqc3Params::SECRET_KEY_BYTES, "Key sizes should increase with security level");
    assert!(Hqc3Params::SECRET_KEY_BYTES < Hqc5Params::SECRET_KEY_BYTES, "Key sizes should increase with security level");
    
    println!("✅ Parameter consistency validated");
}

#[test]
fn test_vector_size_calculations() {
    println!("=== Vector Size Calculation Validation ===");
    
    // Verify VEC_N_SIZE_64 calculations
    assert_eq!(Hqc1Params::VEC_N_SIZE_64, (Hqc1Params::N + 63) / 64, "VEC_N_SIZE_64 calculation for HQC-1");
    assert_eq!(Hqc3Params::VEC_N_SIZE_64, (Hqc3Params::N + 63) / 64, "VEC_N_SIZE_64 calculation for HQC-3");
    assert_eq!(Hqc5Params::VEC_N_SIZE_64, (Hqc5Params::N + 63) / 64, "VEC_N_SIZE_64 calculation for HQC-5");
    
    // Verify VEC_N1N2_SIZE_64 calculations
    assert_eq!(Hqc1Params::VEC_N1N2_SIZE_64, (Hqc1Params::N1 * Hqc1Params::N2 + 63) / 64, "VEC_N1N2_SIZE_64 calculation for HQC-1");
    assert_eq!(Hqc3Params::VEC_N1N2_SIZE_64, (Hqc3Params::N1 * Hqc3Params::N2 + 63) / 64, "VEC_N1N2_SIZE_64 calculation for HQC-3");
    assert_eq!(Hqc5Params::VEC_N1N2_SIZE_64, (Hqc5Params::N1 * Hqc5Params::N2 + 63) / 64, "VEC_N1N2_SIZE_64 calculation for HQC-5");
    
    println!("✅ Vector size calculations validated");
}

#[test]
fn test_key_size_calculations() {
    println!("=== Key Size Calculation Validation ===");
    
    // Verify key size calculations
    // SECRET_KEY_BYTES = SEED_BYTES + PUBLIC_KEY_BYTES
    // PUBLIC_KEY_BYTES = SEED_BYTES + VEC_N_SIZE_64 * 8
    // CIPHERTEXT_BYTES = VEC_N_SIZE_64 * 8 + VEC_N1N2_SIZE_64 * 8
    
    let hqc1_expected_pk = 32 + Hqc1Params::VEC_N_SIZE_64 * 8;
    let hqc1_expected_sk = 32 + hqc1_expected_pk;
    let hqc1_expected_ct = Hqc1Params::VEC_N_SIZE_64 * 8 + Hqc1Params::VEC_N1N2_SIZE_64 * 8;
    
    assert_eq!(Hqc1Params::PUBLIC_KEY_BYTES, hqc1_expected_pk, "HQC-1 PUBLIC_KEY_BYTES calculation");
    assert_eq!(Hqc1Params::SECRET_KEY_BYTES, hqc1_expected_sk, "HQC-1 SECRET_KEY_BYTES calculation");
    assert_eq!(Hqc1Params::CIPHERTEXT_BYTES, hqc1_expected_ct, "HQC-1 CIPHERTEXT_BYTES calculation");
    
    let hqc3_expected_pk = 32 + Hqc3Params::VEC_N_SIZE_64 * 8;
    let hqc3_expected_sk = 32 + hqc3_expected_pk;
    let hqc3_expected_ct = Hqc3Params::VEC_N_SIZE_64 * 8 + Hqc3Params::VEC_N1N2_SIZE_64 * 8;
    
    assert_eq!(Hqc3Params::PUBLIC_KEY_BYTES, hqc3_expected_pk, "HQC-3 PUBLIC_KEY_BYTES calculation");
    assert_eq!(Hqc3Params::SECRET_KEY_BYTES, hqc3_expected_sk, "HQC-3 SECRET_KEY_BYTES calculation");
    assert_eq!(Hqc3Params::CIPHERTEXT_BYTES, hqc3_expected_ct, "HQC-3 CIPHERTEXT_BYTES calculation");
    
    let hqc5_expected_pk = 32 + Hqc5Params::VEC_N_SIZE_64 * 8;
    let hqc5_expected_sk = 32 + hqc5_expected_pk;
    let hqc5_expected_ct = Hqc5Params::VEC_N_SIZE_64 * 8 + Hqc5Params::VEC_N1N2_SIZE_64 * 8;
    
    assert_eq!(Hqc5Params::PUBLIC_KEY_BYTES, hqc5_expected_pk, "HQC-5 PUBLIC_KEY_BYTES calculation");
    assert_eq!(Hqc5Params::SECRET_KEY_BYTES, hqc5_expected_sk, "HQC-5 SECRET_KEY_BYTES calculation");
    assert_eq!(Hqc5Params::CIPHERTEXT_BYTES, hqc5_expected_ct, "HQC-5 CIPHERTEXT_BYTES calculation");
    
    println!("✅ Key size calculations validated");
}
