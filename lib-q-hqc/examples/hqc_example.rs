//! HQC Example - Demonstrates HQC KEM usage
//!
//! This example shows how to use the HQC (Hamming Quasi-Cyclic) KEM
//! implementation with the libQ architecture.

use lib_q_hqc::hqc_kem::*;
use lib_q_hqc::params_correct::*;
use lib_q_random::LibQRng;

fn main() {
    println!("HQC (Hamming Quasi-Cyclic) KEM Example");
    println!("=====================================");

    // Create a deterministic RNG for reproducible results
    let seed = [42u8; 32];
    let mut rng = LibQRng::new_deterministic(seed);

    // Demonstrate HQC-1 (128-bit security)
    println!("\n1. HQC-1 KEM Demo");
    println!("------------------");
    demonstrate_hqc1(&mut rng);

    // Demonstrate HQC-3 (192-bit security)
    println!("\n2. HQC-3 KEM Demo");
    println!("------------------");
    demonstrate_hqc3(&mut rng);

    // Demonstrate HQC-5 (256-bit security)
    println!("\n3. HQC-5 KEM Demo");
    println!("------------------");
    demonstrate_hqc5(&mut rng);

    // Demonstrate parameter information
    println!("\n4. HQC Parameter Information");
    println!("---------------------------");
    demonstrate_parameters();
}

fn demonstrate_hqc1(rng: &mut LibQRng) {
    println!("Creating HQC-1 KEM instance...");
    let kem = HqcKem::<Hqc1Params>::new().expect("Failed to create HQC-1 KEM");

    println!("Generating HQC-1 keypair...");
    let (public_key, secret_key) = kem.keygen(rng).expect("Key generation should succeed");

    println!("Public key size: {} bytes", public_key.as_bytes().len());
    println!("Secret key size: {} bytes", secret_key.as_bytes().len());

    println!("Encapsulating shared secret...");
    let (ciphertext, shared_secret1) = kem
        .encapsulate(&public_key, rng)
        .expect("Encapsulation should succeed");

    println!("Ciphertext size: {} bytes", ciphertext.as_bytes().len());
    println!(
        "Shared secret size: {} bytes",
        shared_secret1.as_bytes().len()
    );

    println!("Decapsulating shared secret...");
    let shared_secret2 = kem
        .decapsulate(&secret_key, &ciphertext)
        .expect("Decapsulation should succeed");

    println!(
        "Shared secrets match: {}",
        shared_secret1.as_bytes() == shared_secret2.as_bytes()
    );
}

fn demonstrate_hqc3(rng: &mut LibQRng) {
    println!("Creating HQC-3 KEM instance...");
    let kem = HqcKem::<Hqc3Params>::new().expect("Failed to create HQC-3 KEM");

    println!("Generating HQC-3 keypair...");
    let (public_key, secret_key) = kem.keygen(rng).expect("Key generation should succeed");

    println!("Public key size: {} bytes", public_key.as_bytes().len());
    println!("Secret key size: {} bytes", secret_key.as_bytes().len());

    println!("Encapsulating shared secret...");
    let (ciphertext, shared_secret1) = kem
        .encapsulate(&public_key, rng)
        .expect("Encapsulation should succeed");

    println!("Ciphertext size: {} bytes", ciphertext.as_bytes().len());
    println!(
        "Shared secret size: {} bytes",
        shared_secret1.as_bytes().len()
    );

    println!("Decapsulating shared secret...");
    let shared_secret2 = kem
        .decapsulate(&secret_key, &ciphertext)
        .expect("Decapsulation should succeed");

    println!(
        "Shared secrets match: {}",
        shared_secret1.as_bytes() == shared_secret2.as_bytes()
    );
}

fn demonstrate_hqc5(rng: &mut LibQRng) {
    println!("Creating HQC-5 KEM instance...");
    let kem = HqcKem::<Hqc5Params>::new().expect("Failed to create HQC-5 KEM");

    println!("Generating HQC-5 keypair...");
    let (public_key, secret_key) = kem.keygen(rng).expect("Key generation should succeed");

    println!("Public key size: {} bytes", public_key.as_bytes().len());
    println!("Secret key size: {} bytes", secret_key.as_bytes().len());

    println!("Encapsulating shared secret...");
    let (ciphertext, shared_secret1) = kem
        .encapsulate(&public_key, rng)
        .expect("Encapsulation should succeed");

    println!("Ciphertext size: {} bytes", ciphertext.as_bytes().len());
    println!(
        "Shared secret size: {} bytes",
        shared_secret1.as_bytes().len()
    );

    println!("Decapsulating shared secret...");
    let shared_secret2 = kem
        .decapsulate(&secret_key, &ciphertext)
        .expect("Decapsulation should succeed");

    println!(
        "Shared secrets match: {}",
        shared_secret1.as_bytes() == shared_secret2.as_bytes()
    );
}

fn demonstrate_parameters() {
    println!("HQC-1 Parameters:");
    println!("  N (code length): {}", Hqc1Params::N);
    println!("  N1 (first dimension): {}", Hqc1Params::N1);
    println!("  N2 (second dimension): {}", Hqc1Params::N2);
    println!("  Omega (error weight): {}", Hqc1Params::OMEGA);
    println!("  Delta (decoding threshold): {}", Hqc1Params::DELTA);
    println!("  Security level: 128 bits");

    println!("\nHQC-3 Parameters:");
    println!("  N (code length): {}", Hqc3Params::N);
    println!("  N1 (first dimension): {}", Hqc3Params::N1);
    println!("  N2 (second dimension): {}", Hqc3Params::N2);
    println!("  Omega (error weight): {}", Hqc3Params::OMEGA);
    println!("  Delta (decoding threshold): {}", Hqc3Params::DELTA);
    println!("  Security level: 192 bits");

    println!("\nHQC-5 Parameters:");
    println!("  N (code length): {}", Hqc5Params::N);
    println!("  N1 (first dimension): {}", Hqc5Params::N1);
    println!("  N2 (second dimension): {}", Hqc5Params::N2);
    println!("  Omega (error weight): {}", Hqc5Params::OMEGA);
    println!("  Delta (decoding threshold): {}", Hqc5Params::DELTA);
    println!("  Security level: 256 bits");

    println!("\nKey and Ciphertext Sizes:");
    println!(
        "HQC-1: PK={} bytes, SK={} bytes, CT={} bytes, SS={} bytes",
        Hqc1Params::PUBLIC_KEY_BYTES,
        Hqc1Params::SECRET_KEY_BYTES,
        Hqc1Params::CIPHERTEXT_BYTES,
        Hqc1Params::SHARED_SECRET_BYTES
    );

    println!(
        "HQC-3: PK={} bytes, SK={} bytes, CT={} bytes, SS={} bytes",
        Hqc3Params::PUBLIC_KEY_BYTES,
        Hqc3Params::SECRET_KEY_BYTES,
        Hqc3Params::CIPHERTEXT_BYTES,
        Hqc3Params::SHARED_SECRET_BYTES
    );

    println!(
        "HQC-5: PK={} bytes, SK={} bytes, CT={} bytes, SS={} bytes",
        Hqc5Params::PUBLIC_KEY_BYTES,
        Hqc5Params::SECRET_KEY_BYTES,
        Hqc5Params::CIPHERTEXT_BYTES,
        Hqc5Params::SHARED_SECRET_BYTES
    );
}
