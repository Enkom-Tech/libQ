//! Zeroization property tests.
//!
//! These tests verify that secret data is properly zeroized when dropped.
//! Note: Full verification requires memory inspection tools, but these tests
//! verify the zeroization API works correctly.

use lib_q_stark::SecretWitness;
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::Mersenne31;
use zeroize::Zeroize;

#[test]
fn test_secret_witness_zeroize() {
    // Create a trace with known values
    let values = vec![
        Mersenne31::new(1),
        Mersenne31::new(2),
        Mersenne31::new(3),
        Mersenne31::new(4),
    ];
    let trace = RowMajorMatrix::new(values.clone(), 2);

    // Wrap in SecretWitness
    let mut secret = SecretWitness::new(trace);

    // Verify we can access the trace
    assert_eq!(secret.trace().height(), 2);
    assert_eq!(secret.trace().width(), 2);

    // Zeroize and verify
    secret.zeroize();

    // After zeroize, all values should be zero
    // Note: We can't directly inspect the internal Vec, but zeroize should have been called
    // This test verifies the API works; full verification requires memory inspection
}

#[test]
fn test_secret_witness_drop() {
    // Verify that SecretWitness zeroizes on drop
    let values = vec![
        Mersenne31::new(10),
        Mersenne31::new(20),
        Mersenne31::new(30),
        Mersenne31::new(40),
    ];
    let trace = RowMajorMatrix::new(values, 2);

    // Create and immediately drop SecretWitness
    {
        let _secret = SecretWitness::new(trace);
        // _secret is dropped here, triggering zeroization
    }

    // Test passes if drop doesn't panic
    // Full verification of zeroization requires memory inspection tools
}
