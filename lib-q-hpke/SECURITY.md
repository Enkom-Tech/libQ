# Security Policy

## Security Model

lib-q-hpke implements RFC 9180 using exclusively post-quantum algorithms:

- **KEM**: ML-KEM (NIST PQC Standard) - IND-CCA2 security
- **AEAD**: Saturnin-256 - post-quantum authenticated encryption
- **KDF**: HKDF with SHAKE256/SHA3 - secure key derivation

## Security Guarantees

- **Confidentiality**: IND-CCA2 security against chosen ciphertext attacks
- **Authenticity**: Message integrity and authentication via Saturnin-256
- **Forward Secrecy**: Compromising long-term keys doesn't affect past communications
- **Post-Quantum Security**: Resistance against quantum computer attacks

## Implementation Security

- **Constant-Time Operations**: Key comparisons and cryptographic operations use constant-time algorithms where possible
- **Memory Safety**: Sensitive data is zeroed after use; bounded allocations prevent DoS
- **Error Handling**: Error messages don't leak sensitive information; consistent timing characteristics

## Best Practices

### Key Management
- Use cryptographically secure random number generation
- Store private keys securely (HSM, secure enclave)
- Regularly rotate long-term keys
- Validate all keys before use

### Usage
- Use unique info strings for different contexts
- Bind additional context using AAD
- Don't reuse sequence numbers in the same context
- Use exported keys only for their intended purpose

### Algorithm Selection
- ML-KEM-512: Level 1 security (AES-128 equivalent)
- ML-KEM-768: Level 3 security (AES-192 equivalent)  
- ML-KEM-1024: Level 5 security (AES-256 equivalent)

## Known Limitations

- Pre-shared key mode not implemented
- Authenticated sender mode not implemented
- Software-only implementations (no hardware acceleration)
- Limited side-channel protection

## Reporting Vulnerabilities

**Do not** create public issues for security vulnerabilities. Contact maintainers privately with detailed information. Allow time for fixes before disclosure.

## Compliance

- RFC 9180: Hybrid Public Key Encryption
- NIST PQC Standards: ML-KEM specifications
- FIPS 140-2: Cryptographic module requirements (when applicable)
