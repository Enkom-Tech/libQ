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
- **Error Handling**: Error messages avoid secret-bearing payloads; AEAD `open` surfaces authentication through `Result` and inherits the underlying AEAD’s verification discipline (see `lib-q-core` `Aead` trait documentation and `lib-q-saturnin` security notes where applicable). **Layer B:** `SaturninAeadImpl::decrypt_semantic` and `Shake256AeadImpl::decrypt_semantic` expose semantic outcomes; HPKE `PostQuantumProvider` / `AeadProvider` `open` stays **Layer A** (`Result`-first) over `Box<dyn Aead>`. For duplex-sponge HPKE (`HpkeAead::DuplexSpongeAead`), use concrete `lib_q_aead::DuplexSpongeAead` or `lib_q_duplex_aead::DuplexSpongeAead` for `decrypt_semantic`—the provider does not surface that trait on the boxed handle.
- **Saturnin-256 tag size**: The HPKE identifier `Saturnin256` uses `lib-q-saturnin` full AEAD with a **32-byte** tag; `HpkeAead::Saturnin256.tag_len()` matches `SaturninAead::tag_size()` for correct minimum ciphertext sizing

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

## RFC 9180 conformance

The HPKE **state machine** (modes, `SetupBaseS`/`SetupBaseR`-style key schedule, labeled extract/expand, sequence handling) follows RFC 9180. **Cipher suites** use lib-q–assigned KEM/KDF/AEAD code points for post-quantum algorithms (not the RFC’s classical DHKEM + AES-GCM/ChaCha20 suites).

For **PSK** and **AuthPSK**, the default `HpkePskWireFormat` is **RFC 9180** on the wire (no extra suffix). `HpkePskWireFormat::LibQCommitmentSuffix` is an optional extension: both peers must enable it explicitly.

## Known limitations

- **Interop:** Peers must agree on the same cipher suite identifiers and, for PSK modes, the same `HpkePskWireFormat`.
- **Software-only:** No mandatory hardware acceleration in this crate.
- **Side channels:** Best-effort constant-time comparisons; full side-channel resistance depends on lower-level primitives and deployment.

## Reporting Vulnerabilities

**Do not** create public issues for security vulnerabilities. Contact maintainers privately with detailed information. Allow time for fixes before disclosure.

## Compliance

- RFC 9180: Hybrid Public Key Encryption
- NIST PQC Standards: ML-KEM specifications
- FIPS 140-2: Cryptographic module requirements (when applicable)
