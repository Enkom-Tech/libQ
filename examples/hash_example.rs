//! Hash Example for lib-Q
//!
//! This example demonstrates the usage of SHA-3 hash functions.

use lib_q_core::{Algorithm, Hash, HashContext};
use lib_q_hash::{CShake128Hash, CShake256Hash};

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    println!("=== lib-Q Hash Example ===\n");

    // Basic cSHAKE256 Example
    println!("1. Basic cSHAKE256 Example:");
    let hasher = CShake256Hash::new();
    let data = b"Hello, World!";
    let hash = hasher.hash(data).unwrap();
    println!("   Input: {}", String::from_utf8_lossy(data));
    println!("   Hash:  {}", bytes_to_hex(&hash));
    println!();

    // cSHAKE128 Example
    println!("2. cSHAKE128 Example:");
    let hasher_128 = CShake128Hash::new();
    let hash_128 = hasher_128.hash(data).unwrap();
    println!("   Input: {}", String::from_utf8_lossy(data));
    println!("   Hash:  {}", bytes_to_hex(&hash_128));
    println!();

    // Customization Example
    println!("3. cSHAKE256 with Customization:");
    let custom_hasher = CShake256Hash::new_customized(b"MyApp");
    let custom_hash = custom_hasher.hash(data).unwrap();
    println!("   Input: {}", String::from_utf8_lossy(data));
    println!("   Customization: MyApp");
    println!("   Hash:  {}", bytes_to_hex(&custom_hash));
    println!();

    // Function Name Example
    println!("4. cSHAKE256 with Function Name:");
    let fn_hasher = CShake256Hash::new_with_function_name(b"MyFunction", b"MyApp");
    let fn_hash = fn_hasher.hash(data).unwrap();
    println!("   Input: {}", String::from_utf8_lossy(data));
    println!("   Function Name: MyFunction");
    println!("   Customization: MyApp");
    println!("   Hash:  {}", bytes_to_hex(&fn_hash));
    println!();

    // Variable Output Length Example (using cSHAKE256 with slicing)
    println!("5. Variable Output Length Example:");
    let var_hasher = CShake256Hash::new();
    let hash_16 = var_hasher.hash(data).unwrap();
    println!("   Input: {}", String::from_utf8_lossy(data));
    println!("   16 bytes: {}", bytes_to_hex(&hash_16[..16]));
    println!("   32 bytes: {}", bytes_to_hex(&hash_16));
    println!();

    // Customization Comparison
    println!("6. Customization Comparison:");
    let app1_hasher = CShake256Hash::new_customized(b"App1");
    let app2_hasher = CShake256Hash::new_customized(b"App2");

    let hash1 = app1_hasher.hash(data).unwrap();
    let hash2 = app2_hasher.hash(data).unwrap();

    println!("   Input: {}", String::from_utf8_lossy(data));
    println!("   App1 hash: {}", bytes_to_hex(&hash1));
    println!("   App2 hash: {}", bytes_to_hex(&hash2));
    println!("   Different: {}", hash1 != hash2);
    println!();

    // Hash Context Example
    println!("7. Hash Context Example:");
    let mut ctx = HashContext::new();
    match ctx.hash(Algorithm::Shake256, data) {
        Ok(result) => println!("   Context hash: {}", bytes_to_hex(&result)),
        Err(e) => println!("   Context error: {e:?}"),
    }
    println!();

    println!("=== Example Complete ===");
}
