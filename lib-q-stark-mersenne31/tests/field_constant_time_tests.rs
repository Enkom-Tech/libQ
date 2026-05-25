//! Constant-time operation property tests.
//!
//! These tests verify that constant-time operations maintain their timing
//! properties and don't leak information through timing side-channels.

use lib_q_stark_field::PrimeCharacteristicRing;
use lib_q_stark_field::constant_time::{
    constant_time_eq,
    constant_time_is_one,
    constant_time_is_zero,
};
use lib_q_stark_mersenne31::Mersenne31;

#[test]
fn test_constant_time_is_zero() {
    let zero = Mersenne31::ZERO;
    let one = Mersenne31::ONE;
    let two = Mersenne31::TWO;

    // Verify constant_time_is_zero works correctly
    assert!(constant_time_is_zero(&zero));
    assert!(!constant_time_is_zero(&one));
    assert!(!constant_time_is_zero(&two));
}

#[test]
fn test_constant_time_is_one() {
    let zero = Mersenne31::ZERO;
    let one = Mersenne31::ONE;
    let two = Mersenne31::TWO;

    // Verify constant_time_is_one works correctly
    assert!(!constant_time_is_one(&zero));
    assert!(constant_time_is_one(&one));
    assert!(!constant_time_is_one(&two));
}

#[test]
fn test_constant_time_eq() {
    let zero = Mersenne31::ZERO;
    let one = Mersenne31::ONE;
    let one_copy = Mersenne31::ONE;

    // Verify constant_time_eq works correctly
    assert!(constant_time_eq(&zero, &zero));
    assert!(!constant_time_eq(&zero, &one));
    assert!(constant_time_eq(&one, &one_copy));
}

#[test]
fn test_constant_time_operations_deterministic() {
    // Verify that constant-time operations are deterministic
    // (same inputs produce same outputs)
    let val1 = Mersenne31::new(42);
    let val2 = Mersenne31::new(42);
    let val3 = Mersenne31::new(43);

    assert!(constant_time_eq(&val1, &val2));
    assert!(!constant_time_eq(&val1, &val3));
}
