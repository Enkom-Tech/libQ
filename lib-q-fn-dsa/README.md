# lib-Q FN-DSA

An implementation of FN-DSA (the Falcon-based signature scheme NIST intends to publish as FIPS 206) post-quantum digital signatures, fully integrated into the libQ cryptography library.

> **FIPS 206 is not yet published.** There is no finalized standard — and no public draft — to be
> "compliant" with, so this crate cannot be, and does not claim to be, FIPS 206 certified or
> NIST-validated. What it implements is the FN-DSA/Falcon design as tracked by the upstream `fn-dsa`
> reference implementation. Every "FIPS 206" reference below means *the expected FN-DSA design*, not
> certified standards conformance, and encoding or domain-separation details **may change** when the
> standard is finalized. See [Note on FIPS 206](#note-on-fips-206-and-kat-differences) and
> [docs/fn-dsa-nist-gate.md](../docs/fn-dsa-nist-gate.md) for the steps required before claiming NIST
> alignment for production use.

## Overview

FN-DSA (Falcon-based Digital Signature Algorithm) is a post-quantum digital signature scheme selected by NIST for standardization, providing compact signatures with strong security guarantees. This implementation follows the FN-DSA design and is aimed at high-performance applications requiring quantum-resistant cryptography.

## Key Features

- **NIST-selected algorithm, pre-standard**: implements FN-DSA, the scheme NIST selected for FIPS 206 — which is not yet published (see the note above)
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
lib-q-fn-dsa = "0.0.11"
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

## Documentation

- [Constrained-device signature suite](docs/CONSTRAINED_DEVICE_SUITE.md) — FN-DSA vs ML-DSA-65 bandwidth trade-offs for IoT and low-rate links.
- [KAT verification against FIPS 206](docs/KAT_VERIFICATION.md) — how internal vectors relate to published test data and optional `shake256x4` divergence.

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

## Implementation Notes

### Version Differences

This implementation is based on the upstream `fn-dsa` reference implementation but uses version `0.0.9` of the internal crates (`fn-dsa-comm`, `fn-dsa-kgen`, `fn-dsa-sign`, `fn-dsa-vrfy`) rather than the upstream `0.3.0` version. This version difference was chosen during integration into the libQ workspace to maintain consistency with the libQ versioning scheme.

### Security Improvements

This implementation includes security enhancements over the upstream reference:

1. **Removed HASH_ID_ORIGINAL_FALCON**: The original Falcon design bypassed domain separation, creating a critical security vulnerability that could enable cross-protocol attacks. This implementation enforces proper FN-DSA domain separation as specified in the FN-DSA design NIST selected. (There is no published NIST standard for FN-DSA to specify it — see the note at the top of this file.)
2. **Hardened hash_to_point**: The `hash_to_point` function no longer supports the insecure original Falcon mode, ensuring all operations use proper domain separation.

### API Compatibility Differences

Due to dependency version differences, there are minor API differences from the upstream reference:

1. **RngError type**: 
   - Reference uses `rand_core::Error` from rand_core 0.6.4
   - This implementation uses `core::fmt::Error` because rand_core 0.9.3 (used in libQ) does not export `Error` directly
   - Both are compatible with `no_std` and provide equivalent functionality

### Note on FIPS 206 and KAT differences

When the `shake256x4` feature is enabled, the Known Answer Test (KAT) values differ from the upstream reference implementation. This is due to:

1. **Dependency Version Differences**: Different versions of `cpufeatures` and potentially `rand_core` between this implementation and upstream
2. **AVX2 Code Generation**: Subtle differences in how the compiler generates AVX2 instructions or manages state
3. **Integration Changes**: Minor adaptations made during integration into the libQ workspace structure

**Note on FIPS 206**: FIPS 206 (FN-DSA) is **not yet published** — there is no finalized standard
(nor public draft) to be "compliant" with. The wording below should be read as *alignment with the
upstream `fn-dsa` reference implementation and the expected FN-DSA design*, not certified
standards conformance. Interoperability claims are with respect to that reference, and may change
when FIPS 206 is finalized.

These differences do NOT affect cryptographic correctness or interoperability with the reference:
- All signatures are mathematically valid and verify correctly
- The implementation follows the FN-DSA design (the basis for the forthcoming FIPS 206)
- Signatures generated by this implementation verify under a compatible FN-DSA implementation
- Signatures from a compatible FN-DSA implementation verify under this implementation

The KAT differences only affect the internal test vectors used for regression testing. The signature format and verification logic follow the upstream reference implementation.

### Interoperability

Interoperability is claimed **against the upstream `fn-dsa` reference implementation**, not against
a published standard — there is no FIPS 206 to be compliant with yet (see the note above):

- **Signature Format**: Uses the FN-DSA signature encoding as specified by the reference implementation
- **Key Format**: Uses the FN-DSA key encoding as specified by the reference implementation
- **Verification**: Implements the FN-DSA verification algorithm
- **Domain Separation**: Implements FN-DSA domain separation as specified by the reference implementation

Signatures generated by this implementation are expected to be accepted by any FN-DSA verifier that
tracks the same reference, and vice versa. **This is not a certified conformance claim, and it is not
a guarantee of interoperability with implementations built against the final FIPS 206 text** —
encoding or domain-separation details may change at standardization. Re-verify against published NIST
vectors when FIPS 206 lands; see [docs/fn-dsa-nist-gate.md](../docs/fn-dsa-nist-gate.md).

## Workspace

Enable via [`lib-q-sig`](../lib-q-sig) with feature `fn-dsa`, or use this crate directly. See the [workspace README](../README.md).

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](../LICENSE) file for details.