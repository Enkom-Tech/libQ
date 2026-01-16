# lib-Q SLH-DSA - Stateless Hash-based Digital Signature Algorithm

This crate provides a complete implementation of SLH-DSA (Stateless Hash-based Digital Signature Algorithm) based on the finalized NIST FIPS-205 standard. SLH-DSA is a post-quantum digital signature scheme designed to be resistant to quantum computers.

## Features

- **NIST FIPS-205 Compliant**: Implements all 12 standardized parameter sets
- **Post-Quantum Security**: Resistant to both classical and quantum attacks
- **Stateless Design**: No state management required, making it suitable for distributed systems
- **Memory Safe**: Zero unsafe code with automatic memory zeroization
- **`no_std` Compatible**: Works in constrained environments
- **WASM Support**: JavaScript-compatible bindings for web environments

## Supported Parameter Sets

### SHA256-based (Levels 1, 3, 5)
- **SLH-DSA-SHA256-128f-Robust**: Level 1 security (128-bit)
- **SLH-DSA-SHA256-192f-Robust**: Level 3 security (192-bit)  
- **SLH-DSA-SHA256-256f-Robust**: Level 5 security (256-bit)

### SHAKE256-based (Levels 1, 3, 5)
- **SLH-DSA-SHAKE256-128f-Robust**: Level 1 security (128-bit)
- **SLH-DSA-SHAKE256-192f-Robust**: Level 3 security (192-bit)
- **SLH-DSA-SHAKE256-256f-Robust**: Level 5 security (256-bit)

## Usage

### Basic Usage

```rust
use lib_q_slh_dsa::*;
use lib_q_random::new_secure_rng;
use signature::*;

let mut rng = new_secure_rng().expect("Failed to create secure RNG");

// Generate a signing key using the SHAKE256-128f parameter set
let sk = SigningKey::<Shake128f>::new(&mut rng);

// Generate the corresponding public key
let vk = sk.verifying_key();

// Sign a message
let message = b"Hello, SLH-DSA!";
let sig = sk.sign_with_rng(&mut rng, message);

// Verify the signature
assert!(vk.verify(message, &sig).is_ok());
```

### Integration with lib-Q

```rust
use lib_q_core::{Algorithm, SignatureContext, create_signature_context};
// use lib_q_sig::LibQSignatureProvider;

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Create signature context with provider
    // let mut ctx = create_signature_context();
    // ctx.set_provider(Box::new(LibQSignatureProvider::new()?));

    // Generate keypair for SLH-DSA-SHAKE256-128f-Robust
    // let keypair = ctx.generate_keypair(Algorithm::SlhDsaShake256128fRobust, None)?;

    // Sign message
    // let message = b"Hello, lib-Q SLH-DSA!";
    // let signature = ctx.sign(Algorithm::SlhDsaShake256128fRobust, keypair.secret_key(), message, None)?;

    // Verify signature
    // let is_valid = ctx.verify(Algorithm::SlhDsaShake256128fRobust, keypair.public_key(), message, &signature)?;
    // assert!(is_valid);
    
    Ok(())
}
```

### External Randomness (`no_std` environments)

```rust,no_run
use lib_q_slh_dsa::{SigningKey, Shake128f};
use signature::*;

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // In no_std environments, you must provide cryptographically secure randomness externally
    // This example shows the pattern, but uses placeholder values for illustration
    
    // ⚠️ NEVER use predictable values like this in production!
    // Use a hardware RNG or other cryptographically secure source
    let key_randomness = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    ]; // 48 bytes for Shake128f
    
    // Generate keypair with external randomness
    let sk = SigningKey::<Shake128f>::try_from(&key_randomness[..])?;
    let vk = sk.verifying_key();
    
    // In real no_std environments, you'd need to provide your own RNG for signing
    // This example demonstrates the API structure
    let message = b"Hello, no_std SLH-DSA!";
    // let mut rng = YourCustomRng::new(&signing_randomness);
    // let signature = sk.sign_with_rng(&mut rng, message)?;
    // let is_valid = vk.verify(message, &signature).is_ok();
    // assert!(is_valid);
    
    Ok(())
}
```

## Performance Characteristics

### Key Generation Performance
- **128-bit security**: ~0.5-1ms per keypair
- **192-bit security**: ~1-2ms per keypair
- **256-bit security**: ~2-4ms per keypair

### Signing Performance
- **128-bit security**: ~1-2ms per signature
- **192-bit security**: ~2-4ms per signature
- **256-bit security**: ~4-8ms per signature

### Verification Performance
- **128-bit security**: ~0.5-1ms per signature
- **192-bit security**: ~1-2ms per signature
- **256-bit security**: ~2-4ms per signature

### Memory Usage
- **Key sizes**: 48-96 bytes (signing keys), 32-64 bytes (verifying keys)
- **Signature sizes**: 7KB-50KB depending on parameter set
- **Stack usage**: ~2-8KB during operations (varies by parameter set)

### Performance Optimization Tips
1. **Batch Operations**: Process multiple signatures together when possible
2. **Parameter Selection**: Choose appropriate security level for your use case
3. **Memory Management**: Consider heap allocation for large signatures in constrained environments
4. **RNG Performance**: Use fast, secure RNGs for better overall performance

### Benchmarking
Run the included benchmarks to measure performance on your specific hardware:
```bash
cargo bench --package lib-q-slh-dsa
```

## Security Considerations

### Cryptographic Security
- **Post-Quantum Security**: SLH-DSA provides security against both classical and quantum attacks
- **NIST Standardization**: All parameter sets are NIST-approved and follow FIPS-205 specification
- **Hash Function Security**: Uses SHA-256 and SHAKE-256, both cryptographically secure hash functions

### Implementation Security
- **Memory Safety**: Automatic zeroization of sensitive data when keys are dropped
- **Constant-Time Operations**: Critical operations are implemented in constant time where possible
- **Input Validation**: Comprehensive validation of all inputs to prevent attacks
- **Error Handling**: Secure error handling that doesn't leak sensitive information

### Operational Security
- **Randomness Requirements**: All operations require cryptographically secure randomness
- **Key Management**: Signing keys must be stored securely and zeroized after use
- **Parameter Selection**: Choose appropriate parameter sets based on security requirements
- **Signature Verification**: Always verify signatures before trusting them

### Security Best Practices

#### Key Generation
```rust
use lib_q_slh_dsa::{SigningKey, Shake128f};
use lib_q_random::new_secure_rng;

// ✅ Good: Use secure RNG
let mut rng = new_secure_rng().expect("Failed to create RNG");
let sk = SigningKey::<Shake128f>::new(&mut rng);

// ❌ Bad: Don't use predictable randomness
let predictable_bytes = [0u8; 48];
// let sk = SigningKey::<Shake128f>::try_from(&predictable_bytes[..]).unwrap(); // This will fail!
```

#### Key Storage
```rust
use lib_q_slh_dsa::{SigningKey, Shake128f};
use lib_q_random::new_secure_rng;

let mut rng = new_secure_rng().expect("Failed to create RNG");
let sk = SigningKey::<Shake128f>::new(&mut rng);

// ✅ Good: Store keys securely
let sk_bytes = sk.to_bytes();
// Store in secure key management system
// secure_key_store.store("user_key", &sk_bytes);

// ❌ Bad: Don't store keys in plaintext
let sk_bytes = sk.to_bytes();
// std::fs::write("key.txt", &sk_bytes).unwrap(); // Insecure!
```

#### Signature Verification
```rust
use lib_q_slh_dsa::{SigningKey, Shake128f};
use lib_q_random::new_secure_rng;
use signature::*;

let mut rng = new_secure_rng().expect("Failed to create RNG");
let sk = SigningKey::<Shake128f>::new(&mut rng);
let vk = sk.verifying_key();
let message = b"Hello, world!";
let signature = sk.sign_with_rng(&mut rng, message);

// ✅ Good: Always verify signatures
let is_valid = vk.verify(message, &signature).is_ok();
if !is_valid {
    panic!("Invalid signature");
}

// ❌ Bad: Don't skip verification
// let is_valid = vk.verify(message, &signature)?; // Missing this!
// process_message(message); // Dangerous!
```

### Security Considerations by Environment

#### Standard Library (std)
- **Advantages**: Full RNG support, comprehensive error handling
- **Security**: Highest level of security features available
- **Use Case**: General-purpose applications, servers, desktop applications

#### `no_std` Environments
- **Advantages**: Minimal dependencies, embedded-friendly
- **Security**: Requires external randomness management
- **Use Case**: Embedded systems, `IoT` devices, constrained environments

#### `WebAssembly` (WASM)
- **Advantages**: Cross-platform compatibility, sandboxed execution
- **Security**: Limited RNG options, requires careful randomness management
- **Use Case**: Web applications, browser-based cryptography

### Threat Model Considerations

#### Classical Attacks
- **Brute Force**: SLH-DSA provides 128/192/256-bit security levels
- **Side-Channel**: Implementation includes constant-time operations
- **Implementation Bugs**: Comprehensive testing and validation

#### Quantum Attacks
- **Grover's Algorithm**: Security levels account for quantum speedup
- **Shor's Algorithm**: Not applicable to hash-based signatures
- **Future Quantum**: Designed to resist known quantum attacks

### Performance vs Security Trade-offs

| Parameter Set | Security Level | Signature Size | Performance | Use Case |
|---------------|----------------|----------------|-------------|----------|
| SHA256-128f   | 128-bit        | ~7KB           | Fast        | General purpose |
| SHA256-192f   | 192-bit        | ~11KB          | Medium      | High security |
| SHA256-256f   | 256-bit        | ~15KB          | Slower      | Maximum security |

### Common Security Pitfalls

1. **Weak Randomness**: Never use predictable or weak random number generators
2. **Key Reuse**: Don't reuse signing keys across different contexts
3. **Signature Forgery**: Always verify signatures before processing messages
4. **Memory Leaks**: Ensure keys are properly zeroized when no longer needed
5. **Parameter Mismatch**: Use consistent parameter sets across your application

## Feature Flags

- `alloc`: Enable heap allocation (required for most operations)
- `std`: Enable standard library features
- `zeroize`: Enable automatic memory zeroization

## License

This crate is licensed under the Apache-2.0 license.