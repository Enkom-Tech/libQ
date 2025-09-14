# lib-q-dawn

NTRU-based Key Encapsulation Mechanism with double encoding for smaller ciphertext sizes.

DAWN provides post-quantum security through NTRU lattice cryptography with optimized parameter sets for bandwidth-constrained applications. It offers smaller ciphertext sizes compared to ML-KEM while maintaining equivalent security levels.

## Features

- NTRU lattice-based post-quantum security
- Four parameter sets with NIST-I and NIST-V security levels
- Smaller ciphertext sizes than ML-KEM
- WASM compilation support
- Constant-time operations and side-channel resistance

## Usage

```rust
use lib_q_dawn::{DawnKem, DawnParameterSet};

let kem = DawnKem::new(DawnParameterSet::Alpha512);
let keypair = kem.generate_keypair()?;
let (ciphertext, shared_secret) = kem.encapsulate(&keypair.public_key)?;
let decrypted_secret = kem.decapsulate(&keypair.secret_key, &ciphertext)?;
```

### Available Parameter Sets

- `DawnParameterSet::Alpha512` - NIST-I security, minimal ciphertext size
- `DawnParameterSet::Alpha1024` - NIST-V security, minimal ciphertext size  
- `DawnParameterSet::Beta512` - NIST-I security, minimal combined size
- `DawnParameterSet::Beta1024` - NIST-V security, minimal combined size

## Parameter Sets

| Parameter Set | Security | Public Key | Secret Key | Ciphertext |
|---------------|----------|------------|------------|------------|
| DAWN-α-512    | NIST-I   | 615 bytes  | 1319 bytes | 436 bytes  |
| DAWN-α-1024   | NIST-V   | 1229 bytes | 2605 bytes | 973 bytes  |
| DAWN-β-512    | NIST-I   | 514 bytes  | 1154 bytes | 450 bytes  |
| DAWN-β-1024   | NIST-V   | 1027 bytes | 2275 bytes | 1027 bytes |

- **α variants**: Minimal ciphertext size
- **β variants**: Minimal combined public key + ciphertext size

## Security

- NTRU lattice-based cryptography with double encoding
- Constant-time operations and side-channel resistance
- Secure memory management with automatic zeroization
- NIST-approved post-quantum security levels
- Resistance to quantum attacks under NTRU and Ring-LWE assumptions

## Implementation

The implementation includes:
- Power-of-2 cyclotomic rings R[x^n+1] with NTT optimization
- Zero divisor encoding with t = x^(n/2) + 1, w = x^(n/4) + 1
- Comprehensive test suite with 82 tests
- WASM bindings for web deployment

## Testing

```bash
cargo test
```

## License

See the main [lib-q license](../LICENSE).
