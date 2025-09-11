# lib-q-dawn

DAWN NTRU-based Key Encapsulation Mechanism for lib-q.

DAWN is a post-quantum KEM based on NTRU with double encoding that provides smaller and faster ciphertext sizes compared to Kyber/ML-KEM, making it suitable for bandwidth-constrained applications.

## Features

- NTRU-based post-quantum security
- Smaller ciphertext sizes than ML-KEM
- Faster encapsulation/decapsulation
- Optimized for constrained environments

## Status

**Development Phase**: Core structure implemented with placeholder cryptographic operations.

### Completed
- DAWN KEM type definitions
- Core KEM trait implementation
- Error handling and validation
- Test framework

### Development Tasks
- NTRU polynomial operations
- Double encoding implementation
- Key generation algorithms
- Encapsulation/decapsulation logic
- Performance optimization

## Usage

```rust
use lib_q_dawn::DawnKem;

let kem = DawnKem::new();
let keypair = kem.generate_keypair()?;
let (ciphertext, shared_secret) = kem.encapsulate(&keypair.public_key)?;
let decrypted_secret = kem.decapsulate(&keypair.secret_key, &ciphertext)?;
```

## Security Model

DAWN provides post-quantum security through:
- NTRU lattice-based cryptography
- Double encoding for enhanced security
- Resistance to quantum attacks
- Smaller attack surface than classical KEMs

## Development Status

**Pre-production**: Active development phase.

### Remaining Tasks
1. Complete NTRU polynomial arithmetic
2. Implement double encoding scheme
3. Comprehensive test suite
4. Security audit and validation
5. Performance benchmarking

## Contributing

See the main [lib-q contributing guide](../CONTRIBUTING.md).

## License

See the main [lib-q license](../LICENSE).
