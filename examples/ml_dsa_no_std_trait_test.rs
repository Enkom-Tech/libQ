//! ML-DSA via the `Signature` trait (`lib-q-sig`) and the external-randomness API.
//!
//! This package links `lib-q-sig` with **`std`** (see `examples/Cargo.toml`), so
//! [`Signature::generate_keypair`] and [`Signature::sign`] use the built-in RNG.
//!
//! For **no_std** targets, disable default features on `lib-q-sig` and enable `alloc` + `ml-dsa`:
//! `generate_keypair` / `sign` on the trait then return errors; use
//! [`MlDsa::generate_keypair_with_randomness`] and [`MlDsa::sign_with_randomness`] instead.
//!
//! Run: `cargo run -p lib-q-examples --example ml_dsa_no_std_trait_test`

use lib_q_core::Signature;
use lib_q_ml_dsa::constants::{
    KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE,
};
use lib_q_sig::ml_dsa::MlDsa;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ML-DSA: Signature trait (std build) + external randomness API");
    println!("============================================================\n");

    println!("1. Signature trait with automatic RNG (requires `std` on lib-q-sig)...");
    test_signature_trait_with_std_rng()?;

    println!(
        "\n2. Explicit randomness (`generate_keypair_with_randomness` / `sign_with_randomness`)..."
    );
    test_external_randomness_path()?;

    println!("\nDone.");
    Ok(())
}

fn test_signature_trait_with_std_rng() -> Result<(), Box<dyn std::error::Error>> {
    let ml_dsa = MlDsa::ml_dsa_65();

    let keypair = ml_dsa.generate_keypair()?;
    println!("   Keypair generated.");

    let message = b"trait path with std RNG";
    let signature = ml_dsa.sign(keypair.secret_key(), message)?;
    println!("   Signed ({} bytes).", signature.len());

    assert!(ml_dsa.verify(keypair.public_key(), message, &signature)?);
    println!("   Verify OK.");
    Ok(())
}

fn test_external_randomness_path() -> Result<(), Box<dyn std::error::Error>> {
    let ml_dsa = MlDsa::ml_dsa_65();

    let keypair_randomness = [7u8; KEY_GENERATION_RANDOMNESS_SIZE];
    let signing_randomness = [11u8; SIGNING_RANDOMNESS_SIZE];

    let keypair = ml_dsa.generate_keypair_with_randomness(keypair_randomness)?;
    let message = b"embedded-style path";
    let signature =
        ml_dsa.sign_with_randomness(keypair.secret_key(), message, signing_randomness)?;

    assert!(ml_dsa.verify(keypair.public_key(), message, &signature)?);
    println!("   Keygen + sign with supplied randomness; verify OK.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn std_rng_round_trip() {
        test_signature_trait_with_std_rng().unwrap();
    }

    #[test]
    fn external_randomness_round_trip() {
        test_external_randomness_path().unwrap();
    }
}
