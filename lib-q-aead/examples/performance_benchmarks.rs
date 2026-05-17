//! Performance Benchmarks Example for lib-q-aead
//!
//! This example demonstrates how to measure and analyze the performance
//! of lib-q-aead implementations.

use std::time::Instant;

use lib_q_aead::security::timing::protect_timing;
use lib_q_aead::{
    AeadKey,
    Algorithm,
    Nonce,
    create_aead,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("lib-q-aead Performance Benchmarks");
    println!("=================================");

    // Generate test data
    let key_data = vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x00,
    ];

    let nonce_data = vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];

    let key = AeadKey::new(key_data);
    let nonce = Nonce::new(nonce_data);

    // Test different message sizes
    let message_sizes = [64, 256, 1024, 4096, 16384];
    let iterations = 1000;

    println!("Benchmarking with {} iterations per test", iterations);
    println!();

    // Benchmark SHAKE256 AEAD
    if let Ok(aead) = create_aead(Algorithm::Shake256Aead) {
        println!("SHAKE256 AEAD Performance");
        println!("------------------------");

        for &size in &message_sizes {
            let plaintext = vec![0x42u8; size];
            let associated_data = b"benchmark metadata";

            // Warm up
            for _ in 0..10 {
                let _ = aead.encrypt(&key, &nonce, &plaintext, Some(associated_data))?;
            }

            // Benchmark encryption
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = aead.encrypt(&key, &nonce, &plaintext, Some(associated_data))?;
            }
            let encrypt_time = start.elapsed();

            // Benchmark decryption
            let ciphertext = aead.encrypt(&key, &nonce, &plaintext, Some(associated_data))?;

            let start = Instant::now();
            for _ in 0..iterations {
                let _ = aead.decrypt(&key, &nonce, &ciphertext, Some(associated_data))?;
            }
            let decrypt_time = start.elapsed();

            // Calculate metrics
            let avg_encrypt = encrypt_time / iterations as u32;
            let avg_decrypt = decrypt_time / iterations as u32;
            let encrypt_ops_per_sec = 1_000_000_000.0 / avg_encrypt.as_nanos() as f64;
            let decrypt_ops_per_sec = 1_000_000_000.0 / avg_decrypt.as_nanos() as f64;
            let throughput_mbps = (size as f64 * encrypt_ops_per_sec) / 1_000_000.0;

            println!("Message size: {} bytes", size);
            println!(
                "  Encryption: {:?} avg, {:.0} ops/sec, {:.2} MB/s",
                avg_encrypt, encrypt_ops_per_sec, throughput_mbps
            );
            println!(
                "  Decryption: {:?} avg, {:.0} ops/sec",
                avg_decrypt, decrypt_ops_per_sec
            );
            println!();
        }
    }

    // Benchmark constant-time wrapper overhead
    println!("Constant-Time Wrapper Overhead");
    println!("------------------------------");

    if let Ok(aead) = create_aead(Algorithm::Shake256Aead) {
        let plaintext = vec![0x42u8; 1024];
        let associated_data = b"benchmark metadata";

        // Without constant-time wrapper
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = aead.encrypt(&key, &nonce, &plaintext, Some(associated_data))?;
        }
        let unprotected_time = start.elapsed();

        // With constant-time wrapper
        let start = Instant::now();
        for _ in 0..iterations {
            let _ =
                protect_timing(|| aead.encrypt(&key, &nonce, &plaintext, Some(associated_data)))?;
        }
        let protected_time = start.elapsed();

        let unprotected_avg = unprotected_time / iterations as u32;
        let protected_avg = protected_time / iterations as u32;
        let overhead =
            (protected_avg.as_nanos() as f64 / unprotected_avg.as_nanos() as f64 - 1.0) * 100.0;

        println!("Without constant-time wrapper: {:?}", unprotected_avg);
        println!("With constant-time wrapper: {:?}", protected_avg);
        println!("Overhead: {:.1}%", overhead);
        println!();
    }

    // Memory usage analysis
    println!("Memory Usage Analysis");
    println!("--------------------");

    if let Ok(aead) = create_aead(Algorithm::Shake256Aead) {
        let plaintext = vec![0x42u8; 1024];
        let associated_data = b"benchmark metadata";

        // Measure memory allocation
        let start = Instant::now();
        let ciphertext = aead.encrypt(&key, &nonce, &plaintext, Some(associated_data))?;
        let allocation_time = start.elapsed();

        println!("Ciphertext size: {} bytes", ciphertext.len());
        println!("Allocation time: {:?}", allocation_time);
        println!(
            "Memory efficiency: {:.2} bytes/ns",
            ciphertext.len() as f64 / allocation_time.as_nanos() as f64
        );
        println!();
    }

    // Performance comparison
    println!("Performance Comparison");
    println!("---------------------");

    let plaintext = vec![0x42u8; 1024];
    let associated_data = b"benchmark metadata";

    if let Ok(shake256_aead) = create_aead(Algorithm::Shake256Aead) {
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = shake256_aead.encrypt(&key, &nonce, &plaintext, Some(associated_data))?;
        }
        let shake256_time = start.elapsed();

        println!("SHAKE256 AEAD: {:?} avg", shake256_time / iterations as u32);
    }

    println!();
    println!("🎉 Performance benchmarks completed!");
    println!("lib-q-aead provides high-performance quantum-resistant cryptography.");

    Ok(())
}
