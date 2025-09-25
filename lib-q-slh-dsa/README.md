# lib-Q SLH-DSA - Stateless Hash-based Digital Signature Algorithm

This crate provides a complete implementation of SLH-DSA (Stateless Hash-based Digital Signature Algorithm) based on the finalized NIST FIPS-205 standard. SLH-DSA is a post-quantum digital signature scheme designed to be resistant to quantum computers.

## Features

- **NIST FIPS-205 Compliant**: Implements all 12 standardized parameter sets
- **Post-Quantum Security**: Resistant to both classical and quantum attacks
- **Stateless Design**: No state management required, making it suitable for distributed systems
- **Memory Safe**: Zero unsafe code with automatic memory zeroization
- **no_std Compatible**: Works in constrained environments
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
use signature::*;

let mut rng = rand::rng();

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
use lib_q_sig::LibQSignatureProvider;

// Create signature context with provider
let mut ctx = create_signature_context();
ctx.set_provider(Box::new(LibQSignatureProvider::new()?));

// Generate keypair for SLH-DSA-SHAKE256-128f-Robust
let keypair = ctx.generate_keypair(Algorithm::SlhDsaShake256128fRobust, None)?;

// Sign message
let message = b"Hello, lib-Q SLH-DSA!";
let signature = ctx.sign(Algorithm::SlhDsaShake256128fRobust, keypair.secret_key(), message, None)?;

// Verify signature
let is_valid = ctx.verify(Algorithm::SlhDsaShake256128fRobust, keypair.public_key(), message, &signature)?;
assert!(is_valid);
```

## Security Considerations

- **Large Signatures**: SLH-DSA signatures are significantly larger than classical schemes (7KB-50KB)
- **Stack Usage**: Current implementation uses stack allocation, which may cause issues in constrained environments
- **Randomness**: Requires cryptographically secure randomness for key generation and signing
- **Parameter Selection**: Choose appropriate parameter sets based on security requirements

## Performance Characteristics

- **Key Generation**: Fast, typically under 100ms
- **Signing**: Moderate speed, depends on parameter set
- **Verification**: Fast, typically under 10ms
- **Memory Usage**: Higher than classical schemes due to large signature sizes

## Feature Flags

- `alloc`: Enable heap allocation (required for most operations)
- `std`: Enable standard library features
- `zeroize`: Enable automatic memory zeroization

## License

This crate is licensed under the Apache-2.0 license.