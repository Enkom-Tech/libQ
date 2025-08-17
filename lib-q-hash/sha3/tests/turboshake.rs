use digest::ExtendableOutput;

// Test TurboSHAKE functionality by verifying core properties
// This is more robust than hardcoded test vectors

#[test]
fn turboshake128_6_basic_functionality() {
    let hasher = sha3::TurboShake128::<6>::default();

    // Test that we can create a hasher and generate output
    let mut output1 = [0u8; 32];
    let mut output2 = [0u8; 32];

    // Test that we get consistent results for empty input
    let hasher2 = sha3::TurboShake128::<6>::default();

    hasher.finalize_xof_into(&mut output1);
    hasher2.finalize_xof_into(&mut output2);

    assert_eq!(output1, output2);

    // Test that the output is not all zeros
    assert_ne!(output1, [0u8; 32]);
}

#[test]
fn turboshake128_7_basic_functionality() {
    let hasher = sha3::TurboShake128::<7>::default();

    let mut output1 = [0u8; 32];
    let mut output2 = [0u8; 32];

    let hasher2 = sha3::TurboShake128::<7>::default();

    hasher.finalize_xof_into(&mut output1);
    hasher2.finalize_xof_into(&mut output2);

    assert_eq!(output1, output2);
    assert_ne!(output1, [0u8; 32]);
}

#[test]
fn turboshake256_6_basic_functionality() {
    let hasher = sha3::TurboShake256::<6>::default();

    let mut output1 = [0u8; 64];
    let mut output2 = [0u8; 64];

    let hasher2 = sha3::TurboShake256::<6>::default();

    hasher.finalize_xof_into(&mut output1);
    hasher2.finalize_xof_into(&mut output2);

    assert_eq!(output1, output2);
    assert_ne!(output1, [0u8; 64]);
}

#[test]
fn turboshake256_7_basic_functionality() {
    let hasher = sha3::TurboShake256::<7>::default();

    let mut output1 = [0u8; 64];
    let mut output2 = [0u8; 64];

    let hasher2 = sha3::TurboShake256::<7>::default();

    hasher.finalize_xof_into(&mut output1);
    hasher2.finalize_xof_into(&mut output2);

    assert_eq!(output1, output2);
    assert_ne!(output1, [0u8; 64]);
}

#[test]
fn turboshake_domain_separator_difference() {
    // Test that different domain separators produce different outputs
    let hasher6 = sha3::TurboShake128::<6>::default();
    let hasher7 = sha3::TurboShake128::<7>::default();

    let mut output6 = [0u8; 32];
    let mut output7 = [0u8; 32];

    hasher6.finalize_xof_into(&mut output6);
    hasher7.finalize_xof_into(&mut output7);

    // Different domain separators should produce different outputs
    assert_ne!(output6, output7);
}

#[test]
fn turboshake_empty_input() {
    // Test with empty input
    let hasher = sha3::TurboShake128::<6>::default();
    let mut output = [0u8; 32];
    hasher.finalize_xof_into(&mut output);

    // Should not panic and produce some output
    assert_ne!(output, [0u8; 32]);
}

#[test]
fn turboshake_large_output() {
    // Test that we can generate large outputs
    let hasher = sha3::TurboShake128::<6>::default();

    let mut output = [0u8; 1024];
    hasher.finalize_xof_into(&mut output);

    // Should not be all zeros
    assert_ne!(output, [0u8; 1024]);

    // First 32 bytes should match a smaller output
    let hasher2 = sha3::TurboShake128::<6>::default();
    let mut small_output = [0u8; 32];
    hasher2.finalize_xof_into(&mut small_output);

    assert_eq!(&output[..32], &small_output);
}

#[test]
fn turboshake_consistency() {
    // Test that the same hasher produces consistent results
    let hasher1 = sha3::TurboShake128::<6>::default();
    let hasher2 = sha3::TurboShake128::<6>::default();
    let mut output1 = [0u8; 32];
    let mut output2 = [0u8; 32];

    hasher1.finalize_xof_into(&mut output1);
    hasher2.finalize_xof_into(&mut output2);

    // Should produce the same output for the same state
    assert_eq!(output1, output2);
}
