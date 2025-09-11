//! Saturnin Performance Benchmarks
//!
//! This module provides comprehensive benchmarks for all Saturnin algorithm modes,
//! measuring performance across different data sizes and operations.

#![feature(test)]
#![allow(unused_imports, dead_code)]

extern crate alloc;
extern crate test;

use alloc::vec::Vec;

use lib_q_core::{
    AeadKey,
    Nonce,
};
use test::Bencher;

// Test data sizes
const SMALL_DATA: usize = 64; // 64 bytes
const MEDIUM_DATA: usize = 1024; // 1 KB
const LARGE_DATA: usize = 10240; // 10 KB
const XLARGE_DATA: usize = 102400; // 100 KB

// Helper function to generate test data
fn generate_test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

// Helper function to generate test key
fn generate_test_key() -> AeadKey {
    AeadKey {
        data: (0..32).map(|i| (i % 256) as u8).collect(),
    }
}

// Helper function to generate test nonce
fn generate_test_nonce() -> Nonce {
    Nonce {
        data: (0..16).map(|i| (i % 256) as u8).collect(),
    }
}

// ============================================================================
// AEAD Benchmarks
// ============================================================================

#[cfg(feature = "aead")]
mod aead_benches {
    use lib_q_saturnin::SaturninAead;

    use super::*;

    #[bench]
    fn aead_encrypt_small(b: &mut Bencher) {
        let aead = SaturninAead::new();
        let key = generate_test_key();
        let nonce = generate_test_nonce();
        let plaintext = generate_test_data(SMALL_DATA);

        b.iter(|| {
            let _ = aead.encrypt(&key, &nonce, &plaintext, None);
        });
    }

    #[bench]
    fn aead_encrypt_medium(b: &mut Bencher) {
        let aead = SaturninAead::new();
        let key = generate_test_key();
        let nonce = generate_test_nonce();
        let plaintext = generate_test_data(MEDIUM_DATA);

        b.iter(|| {
            let _ = aead.encrypt(&key, &nonce, &plaintext, None);
        });
    }

    #[bench]
    fn aead_encrypt_large(b: &mut Bencher) {
        let aead = SaturninAead::new();
        let key = generate_test_key();
        let nonce = generate_test_nonce();
        let plaintext = generate_test_data(LARGE_DATA);

        b.iter(|| {
            let _ = aead.encrypt(&key, &nonce, &plaintext, None);
        });
    }

    #[bench]
    fn aead_encrypt_xlarge(b: &mut Bencher) {
        let aead = SaturninAead::new();
        let key = generate_test_key();
        let nonce = generate_test_nonce();
        let plaintext = generate_test_data(XLARGE_DATA);

        b.iter(|| {
            let _ = aead.encrypt(&key, &nonce, &plaintext, None);
        });
    }

    #[bench]
    fn aead_encrypt_with_ad(b: &mut Bencher) {
        let aead = SaturninAead::new();
        let key = generate_test_key();
        let nonce = generate_test_nonce();
        let plaintext = generate_test_data(MEDIUM_DATA);
        let ad = generate_test_data(256);

        b.iter(|| {
            let _ = aead.encrypt(&key, &nonce, &plaintext, Some(&ad));
        });
    }

    #[bench]
    fn aead_decrypt_small(b: &mut Bencher) {
        let aead = SaturninAead::new();
        let key = generate_test_key();
        let nonce = generate_test_nonce();
        let plaintext = generate_test_data(SMALL_DATA);
        let ciphertext = aead.encrypt(&key, &nonce, &plaintext, None).unwrap();

        b.iter(|| {
            let _ = aead.decrypt(&key, &nonce, &ciphertext, None);
        });
    }

    #[bench]
    fn aead_decrypt_medium(b: &mut Bencher) {
        let aead = SaturninAead::new();
        let key = generate_test_key();
        let nonce = generate_test_nonce();
        let plaintext = generate_test_data(MEDIUM_DATA);
        let ciphertext = aead.encrypt(&key, &nonce, &plaintext, None).unwrap();

        b.iter(|| {
            let _ = aead.decrypt(&key, &nonce, &ciphertext, None);
        });
    }

    #[bench]
    fn aead_round_trip_small(b: &mut Bencher) {
        let aead = SaturninAead::new();
        let key = generate_test_key();
        let nonce = generate_test_nonce();
        let plaintext = generate_test_data(SMALL_DATA);

        b.iter(|| {
            let ciphertext = aead.encrypt(&key, &nonce, &plaintext, None).unwrap();
            let _ = aead.decrypt(&key, &nonce, &ciphertext, None).unwrap();
        });
    }

    #[bench]
    fn aead_round_trip_medium(b: &mut Bencher) {
        let aead = SaturninAead::new();
        let key = generate_test_key();
        let nonce = generate_test_nonce();
        let plaintext = generate_test_data(MEDIUM_DATA);

        b.iter(|| {
            let ciphertext = aead.encrypt(&key, &nonce, &plaintext, None).unwrap();
            let _ = aead.decrypt(&key, &nonce, &ciphertext, None).unwrap();
        });
    }
}

// ============================================================================
// AEAD-Short Benchmarks
// ============================================================================

#[cfg(feature = "aead-short")]
mod aead_short_benches {
    use lib_q_saturnin::SaturninShortAead;

    use super::*;

    #[bench]
    fn aead_short_encrypt_small(b: &mut Bencher) {
        let aead = SaturninShortAead::new();
        let key = generate_test_key();
        let nonce = generate_test_nonce();
        let plaintext = generate_test_data(SMALL_DATA);

        b.iter(|| {
            let _ = aead.encrypt(&key, &nonce, &plaintext, None);
        });
    }

    #[bench]
    fn aead_short_encrypt_medium(b: &mut Bencher) {
        let aead = SaturninShortAead::new();
        let key = generate_test_key();
        let nonce = generate_test_nonce();
        let plaintext = generate_test_data(MEDIUM_DATA);

        b.iter(|| {
            let _ = aead.encrypt(&key, &nonce, &plaintext, None);
        });
    }

    #[bench]
    fn aead_short_encrypt_large(b: &mut Bencher) {
        let aead = SaturninShortAead::new();
        let key = generate_test_key();
        let nonce = generate_test_nonce();
        let plaintext = generate_test_data(LARGE_DATA);

        b.iter(|| {
            let _ = aead.encrypt(&key, &nonce, &plaintext, None);
        });
    }

    #[bench]
    fn aead_short_round_trip_medium(b: &mut Bencher) {
        let aead = SaturninShortAead::new();
        let key = generate_test_key();
        let nonce = generate_test_nonce();
        let plaintext = generate_test_data(MEDIUM_DATA);

        b.iter(|| {
            let ciphertext = aead.encrypt(&key, &nonce, &plaintext, None).unwrap();
            let _ = aead.decrypt(&key, &nonce, &ciphertext, None).unwrap();
        });
    }
}

// ============================================================================
// Block Cipher Benchmarks
// ============================================================================

#[cfg(feature = "block-cipher")]
mod block_cipher_benches {
    use lib_q_saturnin::SaturninBlockCipher;

    use super::*;

    #[bench]
    fn block_cipher_encrypt_single(b: &mut Bencher) {
        let cipher = SaturninBlockCipher::new();
        let key = generate_test_data(32);
        let block = generate_test_data(32);

        b.iter(|| {
            let _ = cipher.encrypt_block(&key, &block);
        });
    }

    #[bench]
    fn block_cipher_decrypt_single(b: &mut Bencher) {
        let cipher = SaturninBlockCipher::new();
        let key = generate_test_data(32);
        let block = generate_test_data(32);
        let encrypted = cipher.encrypt_block(&key, &block).unwrap();

        b.iter(|| {
            let _ = cipher.decrypt_block(&key, &encrypted);
        });
    }

    #[bench]
    fn block_cipher_encrypt_multiple(b: &mut Bencher) {
        let cipher = SaturninBlockCipher::new();
        let key = generate_test_data(32);
        let blocks = (0..10).map(|_| generate_test_data(32)).collect::<Vec<_>>();

        b.iter(|| {
            for block in &blocks {
                let _ = cipher.encrypt_block(&key, block);
            }
        });
    }

    #[bench]
    fn block_cipher_round_trip(b: &mut Bencher) {
        let cipher = SaturninBlockCipher::new();
        let key = generate_test_data(32);
        let block = generate_test_data(32);

        b.iter(|| {
            let encrypted = cipher.encrypt_block(&key, &block).unwrap();
            let _ = cipher.decrypt_block(&key, &encrypted).unwrap();
        });
    }
}

// ============================================================================
// Hash Benchmarks
// ============================================================================

#[cfg(feature = "hash")]
mod hash_benches {
    use lib_q_saturnin::SaturninHash;

    use super::*;

    #[bench]
    fn hash_small(b: &mut Bencher) {
        let hash = SaturninHash::new();
        let data = generate_test_data(SMALL_DATA);

        b.iter(|| {
            let _ = hash.hash(&data);
        });
    }

    #[bench]
    fn hash_medium(b: &mut Bencher) {
        let hash = SaturninHash::new();
        let data = generate_test_data(MEDIUM_DATA);

        b.iter(|| {
            let _ = hash.hash(&data);
        });
    }

    #[bench]
    fn hash_large(b: &mut Bencher) {
        let hash = SaturninHash::new();
        let data = generate_test_data(LARGE_DATA);

        b.iter(|| {
            let _ = hash.hash(&data);
        });
    }

    #[bench]
    fn hash_xlarge(b: &mut Bencher) {
        let hash = SaturninHash::new();
        let data = generate_test_data(XLARGE_DATA);

        b.iter(|| {
            let _ = hash.hash(&data);
        });
    }

    #[bench]
    fn hash_empty(b: &mut Bencher) {
        let hash = SaturninHash::new();
        let data = Vec::new();

        b.iter(|| {
            let _ = hash.hash(&data);
        });
    }

    #[bench]
    fn hash_single_byte(b: &mut Bencher) {
        let hash = SaturninHash::new();
        let data = vec![0x42];

        b.iter(|| {
            let _ = hash.hash(&data);
        });
    }

    #[bench]
    fn hash_multiple_chunks(b: &mut Bencher) {
        let hash = SaturninHash::new();
        let chunks = (0..10)
            .map(|i| generate_test_data(1024 + i * 100))
            .collect::<Vec<_>>();

        b.iter(|| {
            for chunk in &chunks {
                let _ = hash.hash(chunk);
            }
        });
    }
}

// ============================================================================
// Stream Cipher Benchmarks
// ============================================================================

#[cfg(feature = "stream")]
mod stream_benches {
    use lib_q_saturnin::SaturninStream;

    use super::*;

    #[bench]
    fn stream_encrypt_small(b: &mut Bencher) {
        let stream = SaturninStream::new();
        let key = generate_test_data(32);
        let nonce = generate_test_data(16);
        let plaintext = generate_test_data(SMALL_DATA);

        b.iter(|| {
            let _ = stream.encrypt(&key, &nonce, &plaintext);
        });
    }

    #[bench]
    fn stream_encrypt_medium(b: &mut Bencher) {
        let stream = SaturninStream::new();
        let key = generate_test_data(32);
        let nonce = generate_test_data(16);
        let plaintext = generate_test_data(MEDIUM_DATA);

        b.iter(|| {
            let _ = stream.encrypt(&key, &nonce, &plaintext);
        });
    }

    #[bench]
    fn stream_encrypt_large(b: &mut Bencher) {
        let stream = SaturninStream::new();
        let key = generate_test_data(32);
        let nonce = generate_test_data(16);
        let plaintext = generate_test_data(LARGE_DATA);

        b.iter(|| {
            let _ = stream.encrypt(&key, &nonce, &plaintext);
        });
    }

    #[bench]
    fn stream_encrypt_xlarge(b: &mut Bencher) {
        let stream = SaturninStream::new();
        let key = generate_test_data(32);
        let nonce = generate_test_data(16);
        let plaintext = generate_test_data(XLARGE_DATA);

        b.iter(|| {
            let _ = stream.encrypt(&key, &nonce, &plaintext);
        });
    }

    #[bench]
    fn stream_decrypt_medium(b: &mut Bencher) {
        let stream = SaturninStream::new();
        let key = generate_test_data(32);
        let nonce = generate_test_data(16);
        let plaintext = generate_test_data(MEDIUM_DATA);
        let ciphertext = stream.encrypt(&key, &nonce, &plaintext).unwrap();

        b.iter(|| {
            let _ = stream.decrypt(&key, &nonce, &ciphertext);
        });
    }

    #[bench]
    fn stream_round_trip_medium(b: &mut Bencher) {
        let stream = SaturninStream::new();
        let key = generate_test_data(32);
        let nonce = generate_test_data(16);
        let plaintext = generate_test_data(MEDIUM_DATA);

        b.iter(|| {
            let ciphertext = stream.encrypt(&key, &nonce, &plaintext).unwrap();
            let _ = stream.decrypt(&key, &nonce, &ciphertext).unwrap();
        });
    }

    #[bench]
    fn stream_keystream_generation(b: &mut Bencher) {
        let stream = SaturninStream::new();
        let key = generate_test_data(32);
        let nonce = generate_test_data(16);

        b.iter(|| {
            let _ = stream.generate_keystream(&key, &nonce, MEDIUM_DATA);
        });
    }
}

// ============================================================================
// Comparative Benchmarks
// ============================================================================

#[cfg(all(feature = "aead", feature = "aead-short"))]
mod comparative_benches {
    use lib_q_saturnin::{
        SaturninAead,
        SaturninShortAead,
    };

    use super::*;

    #[bench]
    fn aead_vs_aead_short_encrypt(b: &mut Bencher) {
        let aead = SaturninAead::new();
        let aead_short = SaturninShortAead::new();
        let key = generate_test_key();
        let nonce = generate_test_nonce();
        let plaintext = generate_test_data(MEDIUM_DATA);

        b.iter(|| {
            let _ = aead.encrypt(&key, &nonce, &plaintext, None);
            let _ = aead_short.encrypt(&key, &nonce, &plaintext, None);
        });
    }

    #[bench]
    fn aead_vs_aead_short_round_trip(b: &mut Bencher) {
        let aead = SaturninAead::new();
        let aead_short = SaturninShortAead::new();
        let key = generate_test_key();
        let nonce = generate_test_nonce();
        let plaintext = generate_test_data(MEDIUM_DATA);

        b.iter(|| {
            // AEAD round trip
            let ciphertext = aead.encrypt(&key, &nonce, &plaintext, None).unwrap();
            let _ = aead.decrypt(&key, &nonce, &ciphertext, None).unwrap();

            // AEAD-Short round trip
            let ciphertext = aead_short.encrypt(&key, &nonce, &plaintext, None).unwrap();
            let _ = aead_short.decrypt(&key, &nonce, &ciphertext, None).unwrap();
        });
    }
}

// ============================================================================
// Throughput Benchmarks
// ============================================================================

#[cfg(feature = "aead")]
mod throughput_benches {
    use lib_q_saturnin::SaturninAead;

    use super::*;

    #[bench]
    fn aead_throughput_1mb(b: &mut Bencher) {
        let aead = SaturninAead::new();
        let key = generate_test_key();
        let nonce = generate_test_nonce();
        let plaintext = generate_test_data(1024 * 1024); // 1 MB

        b.iter(|| {
            let _ = aead.encrypt(&key, &nonce, &plaintext, None);
        });
    }

    #[bench]
    fn aead_throughput_10mb(b: &mut Bencher) {
        let aead = SaturninAead::new();
        let key = generate_test_key();
        let nonce = generate_test_nonce();
        let plaintext = generate_test_data(10 * 1024 * 1024); // 10 MB

        b.iter(|| {
            let _ = aead.encrypt(&key, &nonce, &plaintext, None);
        });
    }
}

#[cfg(feature = "hash")]
mod hash_throughput_benches {
    use lib_q_saturnin::SaturninHash;

    use super::*;

    #[bench]
    fn hash_throughput_1mb(b: &mut Bencher) {
        let hash = SaturninHash::new();
        let data = generate_test_data(1024 * 1024); // 1 MB

        b.iter(|| {
            let _ = hash.hash(&data);
        });
    }

    #[bench]
    fn hash_throughput_10mb(b: &mut Bencher) {
        let hash = SaturninHash::new();
        let data = generate_test_data(10 * 1024 * 1024); // 10 MB

        b.iter(|| {
            let _ = hash.hash(&data);
        });
    }
}

// Main function for benchmark harness
fn main() {
    // This is required for the benchmark harness
    // The actual benchmarks are run by the test framework
}
