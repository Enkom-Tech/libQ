//! Thread safety tests for lib-q-aead
//!
//! These tests verify that the AEAD registry and related functionality
//! is thread-safe when compiled with std features.

#[cfg(feature = "std")]
mod thread_safety_tests {
    use std::sync::Arc;
    use std::sync::atomic::{
        AtomicUsize,
        Ordering,
    };
    use std::thread;
    use std::time::Duration;

    use lib_q_aead::*;
    use lib_q_core::{
        AeadKey,
        Algorithm,
        Nonce,
    };

    /// Test that multiple threads can safely access the global registry
    #[test]
    fn test_registry_thread_safety() {
        const NUM_THREADS: usize = 10;
        const OPERATIONS_PER_THREAD: usize = 100;

        let success_count = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..NUM_THREADS {
            let success_count = Arc::clone(&success_count);

            let handle = thread::spawn(move || {
                for _ in 0..OPERATIONS_PER_THREAD {
                    // Test registry access
                    let algorithms = available_algorithms();
                    if !algorithms.is_empty() {
                        success_count.fetch_add(1, Ordering::Relaxed);
                    }

                    // Test algorithm availability checks
                    for algorithm in &algorithms {
                        if is_algorithm_available(*algorithm) {
                            success_count.fetch_add(1, Ordering::Relaxed);
                        }
                    }

                    // Test metadata retrieval
                    for algorithm in &algorithms {
                        if get_algorithm_metadata(*algorithm).is_some() {
                            success_count.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should not panic");
        }

        // Per iteration: 1 (non-empty registry) + 2 per registered algorithm
        // (availability check + metadata lookup).
        let n = available_algorithms().len();
        let ops_per_iteration = 1 + 2 * n;
        let total_operations = NUM_THREADS * OPERATIONS_PER_THREAD * ops_per_iteration;
        assert_eq!(success_count.load(Ordering::Relaxed), total_operations);
    }

    /// Test that multiple threads can safely create AEAD instances
    #[test]
    fn test_aead_creation_thread_safety() {
        const NUM_THREADS: usize = 5;
        const OPERATIONS_PER_THREAD: usize = 50;

        let success_count = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..NUM_THREADS {
            let success_count = Arc::clone(&success_count);

            let handle = thread::spawn(move || {
                for _ in 0..OPERATIONS_PER_THREAD {
                    let algorithms = available_algorithms();

                    for algorithm in algorithms {
                        match create_aead(algorithm) {
                            Ok(aead) => {
                                // Test basic operations
                                let key = AeadKey::new(vec![
                                    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC,
                                    0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44,
                                    0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
                                    0xFF, 0x00,
                                ]);
                                let nonce = Nonce::new(vec![
                                    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC,
                                    0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
                                ]);
                                let plaintext = b"test message";

                                match aead.encrypt(&key, &nonce, plaintext, None) {
                                    Ok(_) => {
                                        success_count.fetch_add(1, Ordering::Relaxed);
                                    }
                                    Err(_) => {
                                        // Some algorithms might not support encryption
                                        // This is not a thread safety issue
                                    }
                                }
                            }
                            Err(_) => {
                                // Some algorithms might not be available
                                // This is not a thread safety issue
                            }
                        }
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should not panic");
        }

        // Verify that at least some operations succeeded
        assert!(success_count.load(Ordering::Relaxed) > 0);
    }

    /// Test concurrent access to registry with mixed operations
    #[test]
    fn test_mixed_operations_thread_safety() {
        const NUM_THREADS: usize = 8;
        const OPERATIONS_PER_THREAD: usize = 25;

        let success_count = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for thread_id in 0..NUM_THREADS {
            let success_count = Arc::clone(&success_count);

            let handle = thread::spawn(move || {
                for _ in 0..OPERATIONS_PER_THREAD {
                    // Mix different operations
                    match thread_id % 4 {
                        0 => {
                            // Test algorithm listing
                            let algorithms = available_algorithms();
                            if !algorithms.is_empty() {
                                success_count.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        1 => {
                            // Test algorithm availability
                            let algorithms = available_algorithms();
                            for algorithm in algorithms {
                                if is_algorithm_available(algorithm) {
                                    success_count.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        2 => {
                            // Test metadata retrieval
                            let algorithms = available_algorithms();
                            for algorithm in algorithms {
                                if get_algorithm_metadata(algorithm).is_some() {
                                    success_count.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        3 => {
                            // Test AEAD creation
                            let algorithms = available_algorithms();
                            for algorithm in algorithms {
                                if create_aead(algorithm).is_ok() {
                                    success_count.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        _ => unreachable!(),
                    }

                    // Small delay to increase chance of race conditions
                    thread::sleep(Duration::from_millis(1));
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should not panic");
        }

        // Verify that operations succeeded
        assert!(success_count.load(Ordering::Relaxed) > 0);
    }

    /// Test that the registry is properly initialized in all threads
    #[test]
    fn test_registry_initialization_thread_safety() {
        const NUM_THREADS: usize = 20;

        let success_count = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..NUM_THREADS {
            let success_count = Arc::clone(&success_count);

            let handle = thread::spawn(move || {
                // Access the registry multiple times to ensure it's properly initialized
                for _ in 0..10 {
                    let algorithms = available_algorithms();
                    if !algorithms.is_empty() {
                        success_count.fetch_add(1, Ordering::Relaxed);
                    }

                    // Test that the same algorithms are always available
                    let algorithms2 = available_algorithms();
                    if algorithms == algorithms2 {
                        success_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should not panic");
        }

        // Verify that all operations succeeded
        let expected_operations = NUM_THREADS * 10 * 2; // 2 operations per iteration
        assert_eq!(success_count.load(Ordering::Relaxed), expected_operations);
    }

    /// Test specific algorithms for thread safety
    #[test]
    fn test_specific_algorithms_thread_safety() {
        const NUM_THREADS: usize = 5;
        const OPERATIONS_PER_THREAD: usize = 20;

        // Test with specific known algorithms (feature-gated registrations)
        let test_algorithms = {
            let mut v = vec![Algorithm::Shake256Aead];
            #[cfg(feature = "saturnin")]
            v.push(Algorithm::Saturnin);
            #[cfg(feature = "kem-aead")]
            v.push(Algorithm::KemAead);
            #[cfg(feature = "duplex-sponge-aead")]
            v.push(Algorithm::DuplexSpongeAead);
            #[cfg(feature = "tweak-aead")]
            v.push(Algorithm::TweakAead);
            #[cfg(feature = "romulus-n")]
            v.push(Algorithm::RomulusN);
            #[cfg(feature = "romulus-m")]
            v.push(Algorithm::RomulusM);
            v
        };

        let success_count = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..NUM_THREADS {
            let success_count = Arc::clone(&success_count);
            let algorithms = test_algorithms.clone();

            let handle = thread::spawn(move || {
                for _ in 0..OPERATIONS_PER_THREAD {
                    for algorithm in &algorithms {
                        // Test algorithm availability
                        if is_algorithm_available(*algorithm) {
                            success_count.fetch_add(1, Ordering::Relaxed);
                        }

                        // Test metadata retrieval
                        if get_algorithm_metadata(*algorithm).is_some() {
                            success_count.fetch_add(1, Ordering::Relaxed);
                        }

                        // Test AEAD creation
                        match create_aead(*algorithm) {
                            Ok(aead) => {
                                // Test basic operations
                                let key = AeadKey::new(vec![
                                    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC,
                                    0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44,
                                    0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
                                    0xFF, 0x00,
                                ]);
                                let nonce = Nonce::new(vec![
                                    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC,
                                    0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
                                ]);
                                let plaintext = b"thread safety test";

                                match aead.encrypt(&key, &nonce, plaintext, None) {
                                    Ok(ciphertext) => {
                                        // Test decryption
                                        match aead.decrypt(&key, &nonce, &ciphertext, None) {
                                            Ok(decrypted) => {
                                                if decrypted == plaintext {
                                                    success_count.fetch_add(1, Ordering::Relaxed);
                                                }
                                            }
                                            Err(_) => {
                                                // Decryption failure is not a thread safety issue
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        // Encryption failure is not a thread safety issue
                                    }
                                }
                            }
                            Err(_) => {
                                // AEAD creation failure is not a thread safety issue
                            }
                        }
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should not panic");
        }

        // Verify that at least some operations succeeded
        assert!(success_count.load(Ordering::Relaxed) > 0);
    }

    /// Test stress scenario with many concurrent operations
    #[test]
    fn test_stress_thread_safety() {
        const NUM_THREADS: usize = 50;
        const OPERATIONS_PER_THREAD: usize = 10;

        let success_count = Arc::new(AtomicUsize::new(0));
        let error_count = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..NUM_THREADS {
            let success_count = Arc::clone(&success_count);
            let error_count = Arc::clone(&error_count);

            let handle = thread::spawn(move || {
                for _ in 0..OPERATIONS_PER_THREAD {
                    // Perform various operations that could expose thread safety issues
                    let algorithms = available_algorithms();

                    for algorithm in algorithms {
                        // Test availability
                        if !is_algorithm_available(algorithm) {
                            error_count.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }

                        // Test metadata retrieval
                        if get_algorithm_metadata(algorithm).is_none() {
                            error_count.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }

                        // Test AEAD creation
                        match create_aead(algorithm) {
                            Ok(_) => {
                                success_count.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(_) => {
                                error_count.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should not panic");
        }

        // Verify that most operations succeeded
        let total_operations =
            success_count.load(Ordering::Relaxed) + error_count.load(Ordering::Relaxed);
        let success_rate = success_count.load(Ordering::Relaxed) as f64 / total_operations as f64;

        // Allow for some errors due to algorithm unavailability, but most should succeed
        assert!(
            success_rate > 0.8,
            "Success rate was {:.2}%, expected > 80%",
            success_rate * 100.0
        );
    }
}

#[cfg(not(feature = "std"))]
mod thread_safety_tests {
    // Thread safety tests are not applicable in no_std environments
    #[test]
    fn test_no_std_thread_safety_placeholder() {
        // This test always passes in no_std environments
        // since threading is not available
        assert!(true);
    }
}
