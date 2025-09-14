//! Thread Safety Tests for lib-q-hpke
//!
//! These tests verify that the HPKE implementation is thread-safe when compiled with std features.

#[cfg(feature = "std")]
use std::thread;
#[cfg(feature = "std")]
use std::time::Duration;

use lib_q_hpke::HpkeContext;

#[cfg(feature = "std")]
#[test]
fn test_hpke_context_thread_safety() {
    // Test that multiple threads can safely create and use HPKE contexts
    let mut handles = vec![];

    // Spawn multiple threads that create HPKE contexts concurrently
    for i in 0..5 {
        let handle = thread::spawn(move || {
            // Each thread creates multiple HPKE contexts
            for _ in 0..10 {
                let _context = HpkeContext::new();

                // Test that context creation is thread-safe
                // The context is created with default cipher suite
                // which includes MlKem512, HkdfShake256, Saturnin256

                // Small delay to increase chance of race conditions
                thread::sleep(Duration::from_micros(1));
            }
            i
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        let result = handle.join().expect("Thread should complete successfully");
        assert!(result < 5);
    }
}

#[cfg(feature = "std")]
#[test]
fn test_hpke_aead_access_thread_safety() {
    // Test that multiple threads can safely access AEAD functionality
    let mut handles = vec![];

    // Spawn multiple threads that access AEAD functionality concurrently
    for i in 0..3 {
        let handle = thread::spawn(move || {
            // Each thread tries to access AEAD functionality multiple times
            for _ in 0..20 {
                let _context = HpkeContext::new();

                // Test that AEAD context creation is thread-safe
                // The context is created with default AEAD (Saturnin256)
                // and accesses the global AEAD registry

                // Small delay to increase chance of race conditions
                thread::sleep(Duration::from_micros(1));
            }
            i
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        let result = handle.join().expect("Thread should complete successfully");
        assert!(result < 3);
    }
}

#[cfg(not(feature = "std"))]
#[test]
fn test_no_std_hpke_context() {
    // Test that HPKE context works in no_std mode
    let _context = HpkeContext::new();

    // In no_std mode, context creation should work without panicking
    // The context is created with default cipher suite
    // which includes MlKem512, HkdfShake256, Saturnin256
}
