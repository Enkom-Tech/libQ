//! Randomness tests for lib-q-random
//!
//! This module provides tests to verify the randomness quality and properties
//! of the RNG implementations.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

// Conditional imports based on feature flags
#[cfg(feature = "alloc")]
use lib_q_random::new_secure_rng;
#[cfg(all(not(feature = "alloc"), feature = "getrandom"))]
use lib_q_random::new_secure_rng_no_std;
#[cfg(any(feature = "alloc", feature = "getrandom"))]
use rand_core::Rng;

#[test]
fn test_rng_randomness() {
    #[cfg(feature = "alloc")]
    {
        let mut rng1 = new_secure_rng().expect("Failed to create RNG");
        let mut rng2 = new_secure_rng().expect("Failed to create RNG");

        println!("RNG1 entropy source: {}", rng1.entropy_source_name());
        println!("RNG1 is secure: {}", rng1.is_secure());
        println!("RNG1 is deterministic: {}", rng1.is_deterministic());

        let mut bytes1 = [0u8; 16];
        let mut bytes2 = [0u8; 16];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        println!("RNG1 bytes: {:?}", bytes1);
        println!("RNG2 bytes: {:?}", bytes2);

        if bytes1 == bytes2 {
            panic!("RNGs generated identical bytes!");
        }

        // Test multiple calls to same RNG
        let mut bytes3 = [0u8; 16];
        rng1.fill_bytes(&mut bytes3);
        println!("RNG1 second call: {:?}", bytes3);

        if bytes1 == bytes3 {
            panic!("Same RNG generated identical bytes on second call!");
        }

        println!("RNG randomness test passed!");
    }

    #[cfg(all(not(feature = "alloc"), feature = "getrandom"))]
    {
        let mut rng1 = new_secure_rng_no_std().expect("Failed to create RNG");
        let mut rng2 = new_secure_rng_no_std().expect("Failed to create RNG");

        let mut bytes1 = [0u8; 16];
        let mut bytes2 = [0u8; 16];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        if bytes1 == bytes2 {
            panic!("RNGs generated identical bytes!");
        }

        // Test multiple calls to same RNG
        let mut bytes3 = [0u8; 16];
        rng1.fill_bytes(&mut bytes3);

        if bytes1 == bytes3 {
            panic!("Same RNG generated identical bytes on second call!");
        }
    }
}
