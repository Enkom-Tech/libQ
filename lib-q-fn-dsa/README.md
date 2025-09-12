# lib-Q FN-DSA

A production-ready implementation of FN-DSA (FIPS 206) post-quantum digital signatures, fully integrated into the libQ cryptography library.

## Overview

FN-DSA (Falcon-based Digital Signature Algorithm) is a NIST-approved post-quantum digital signature scheme that provides compact signatures with strong security guarantees. This implementation follows the FIPS 206 standard and is designed for high-performance applications requiring quantum-resistant cryptography.

## Key Features

- **NIST-Approved**: Implements the FIPS 206 standard for FN-DSA
- **High Performance**: Optimized implementations for x86_64 and ARM64 architectures
- **Compact Signatures**: Significantly smaller signature sizes compared to other post-quantum schemes
- **Multiple Security Levels**: Supports Level 1 (128-bit) and Level 5 (256-bit) security
- **Memory Safe**: Zero unsafe code with automatic secure memory management
- **Constant-Time Operations**: All cryptographic operations are constant-time to prevent timing attacks
- **WASM Compatible**: Full WebAssembly support for web applications
- **Comprehensive Testing**: Extensive test suite including security, performance, and interoperability tests

## Security Levels

| Security Level | Parameter Set | Security (bits) | Use Case |
|----------------|---------------|-----------------|----------|
| Level 1 | FN-DSA-512 | 128 | General applications, IoT devices |
| Level 5 | FN-DSA-1024 | 256 | High-security applications, government use |

## Installation

### Rust

Add to your `Cargo.toml`:

```toml
[dependencies]
lib-q-fn-dsa = "0.0.1"
```

### Node.js

```bash
npm install @lib-q/fn-dsa
```

## Usage

### Basic Usage

```rust
use lib_q_fn_dsa::{FnDsa512, FnDsa1024};

// Create an FN-DSA instance
let fn_dsa = FnDsa512::new();

// Generate a keypair
let keypair = fn_dsa.generate_keypair()?;

// Sign a message
let message = b"Hello, FN-DSA!";
let signature = fn_dsa.sign(&keypair.secret_key, message)?;

// Verify the signature
let is_valid = fn_dsa.verify(&keypair.public_key, message, &signature)?;
assert!(is_valid);
```

### Advanced Usage

```rust
use lib_q_fn_dsa::{FnDsa1024, KeyPair, Signature};

// High-security application
let fn_dsa = FnDsa1024::new();

// Generate keypair with custom entropy
let mut rng = rand::thread_rng();
let keypair = fn_dsa.generate_keypair_with_rng(&mut rng)?;

// Sign with additional context
let context = b"application_context";
let signature = fn_dsa.sign_with_context(
    &keypair.secret_key, 
    message, 
    context
)?;

// Verify with context
let is_valid = fn_dsa.verify_with_context(
    &keypair.public_key, 
    message, 
    &signature, 
    context
)?;
```

### WebAssembly Usage

```javascript
import { FnDsa512 } from '@lib-q/fn-dsa';

// Initialize FN-DSA
const fnDsa = new FnDsa512();

// Generate keypair
const keypair = fnDsa.generateKeypair();

// Sign message
const message = new TextEncoder().encode("Hello, FN-DSA!");
const signature = fnDsa.sign(keypair.secretKey, message);

// Verify signature
const isValid = fnDsa.verify(keypair.publicKey, message, signature);
console.log('Signature valid:', isValid);
```

## API Reference

### Core Types

- **`FnDsa512`**: FN-DSA implementation with 512-bit parameters (Level 1 security)
- **`FnDsa1024`**: FN-DSA implementation with 1024-bit parameters (Level 5 security)
- **`KeyPair`**: Container for public and secret keys
- **`PublicKey`**: Public key for signature verification
- **`SecretKey`**: Secret key for signature generation
- **`Signature`**: Digital signature

### Key Methods

- **`generate_keypair()`**: Generate a new keypair using system entropy
- **`generate_keypair_with_rng(rng)`**: Generate keypair with custom random number generator
- **`sign(secret_key, message)`**: Sign a message
- **`sign_with_context(secret_key, message, context)`**: Sign with additional context
- **`verify(public_key, message, signature)`**: Verify a signature
- **`verify_with_context(public_key, message, signature, context)`**: Verify with context

## Testing

### Run All Tests

```bash
cargo test
```

### Run Security Tests

```bash
cargo test --test security_tests
```

### Run Performance Benchmarks

```bash
cargo bench
```

### Run Constant-Time Tests

```bash
cargo test --test constant_time
```

## Integration

This crate is fully integrated into the libQ ecosystem:

- **Algorithm Registry**: Registered in `lib-q-core` for automatic discovery
- **CI/CD Pipeline**: Complete testing, security validation, and publishing workflows
- **WASM Support**: Automatic WebAssembly compilation and publishing
- **Documentation**: Integrated into main libQ documentation

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](../LICENSE) file for details.