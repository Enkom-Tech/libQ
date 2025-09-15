//! No_std test example for lib-q-keccak
//!
//! This example demonstrates that the keccak library works correctly in no_std mode
//! by running the same test vectors that are used in the unit tests.
//!
//! Run with: cargo run --example keccak_no_std_test --no-default-features

// NOTE: This example is currently disabled because the low-level keccak functions
// (f200, f400, f800, f1600) are not part of the public API in the current architecture.
// These functions may be available in the lib-q-hash crate but are not re-exported
// through the main lib-q crate.

fn main() {
    println!("This example is currently disabled due to API changes.");
    println!(
        "The low-level keccak functions (f200, f400, f800, f1600) are not part of the public API."
    );
    println!("These functions may be available in the lib-q-hash crate but are not re-exported");
    println!("through the main lib-q crate.");
    println!();
    println!("To use keccak functions, use the hash context API instead:");
    println!("  use libq::{{create_hash_context, Algorithm}};");
    println!("  let mut hash_ctx = create_hash_context();");
    println!("  let result = hash_ctx.hash(Algorithm::Keccak256, data);");
}
