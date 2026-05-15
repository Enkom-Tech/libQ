# Security Model

lib-Q targets **post-quantum asymmetric** cryptography and **SHA-3–family** hashing for its stated APIs, with **Saturnin** and **SHAKE-based** symmetric options as the design center (see [SECURITY.md](../SECURITY.md)). Our threat model assumes:

1. **Quantum-capable adversaries** can break classical **public-key** schemes (RSA, ECC, and similar)
2. **Adversaries are computationally strong** (classical and quantum where relevant)
3. **Side-channel attacks are real** and must be mitigated in implementation
4. **Memory safety is critical** for cryptographic implementations

## Threat Model

### Adversary Capabilities
- **Quantum computers**: Can break RSA, ECC, and other classical algorithms
- **Classical computers**: Unlimited computational power
- **Side-channel attacks**: Timing, power analysis, cache attacks
- **Memory attacks**: Buffer overflows, use-after-free, memory leaks
- **Implementation attacks**: Protocol-level vulnerabilities

### Security Goals
- **Confidentiality**: Messages remain secret even against quantum adversaries
- **Integrity**: Messages cannot be tampered with undetected
- **Authenticity**: Message origin can be verified
- **Forward secrecy**: Compromised keys don't affect past communications
- **Post-quantum security**: All security properties hold against quantum attacks

## Algorithm Selection

### Security Tiers
lib-Q provides three security tiers to balance quantum resistance with performance:

#### Tier 1: Ultra-Secure (Pure Post-Quantum)
- **KEMs**: ML-KEM, CB-KEM, HQC
- **Signatures**: ML-DSA, FN-DSA, SLH-DSA
- **Symmetric**: SHAKE256-based constructions, Saturnin
- **HPKE**: Pure post-quantum HPKE with Saturnin AEAD
- **Hash**: SHAKE256, SHAKE128, cSHAKE256
- **Use Case**: Maximum security, performance secondary

#### Tier 2: Balanced (Hybrid Post-Quantum)
- **KEMs**: ML-KEM, CB-KEM, HQC
- **Signatures**: ML-DSA, FN-DSA, SLH-DSA
- **Symmetric**: Post-quantum KEM + Saturnin AEAD
- **HPKE**: Hybrid HPKE (PQ KEM + Saturnin)
- **Hash**: SHAKE256, SHAKE128, cSHAKE256
- **Use Case**: Strong security with good performance

#### Tier 3: Performance (Post-Quantum + Optimized)
- **KEMs**: ML-KEM, CB-KEM, HQC
- **Signatures**: ML-DSA, FN-DSA
- **Symmetric**: Post-quantum KEM + Saturnin AEAD (optimized modes)
- **HPKE**: Performance HPKE (PQ KEM + Saturnin)
- **Hash**: SHAKE256, SHAKE128, cSHAKE256
- **Use Case**: Maximum performance, strong security

### Zero-Knowledge Proofs (ZKPs)
All tiers support post-quantum zero-knowledge proofs:

#### zk-STARKs (Primary)
- **Scalable**: Proof size grows logarithmically with computation
- **Transparent**: No trusted setup required
- **Post-quantum secure**: Based on collision-resistant hash functions
- **WASM compatible**: Full browser and Node.js support
- **Use Cases**: Blockchain privacy, scalable computation, verifiable computation

lib-Q implements zk-STARKs via its own NIST-adapted stack (lib-q-stark) and a full Plonky3-derived stack (lib-q-plonky); see [ZKP Implementation](zkp-implementation.md) (section "Library layout and implementation status") for the library layout.

#### Other ZKP work in-tree
- **`lib-q-lattice-zkp`**: Research crate for **module-lattice** commitments and sigma-style proofs on `lib-q-ring`; not an AIR/STARK pipeline. See [zkp-implementation.md](zkp-implementation.md).

#### Privacy-oriented protocols (registry metadata only)
These components use **NIST PQC** primitives (ML-KEM, ML-DSA-field-compatible rings, Saturnin, SHAKE256) but are **not** drop-in replacements for the `lib-q-core` KEM/signature providers. They are labeled under `AlgorithmCategory::PrivacyProtocol` in `lib-q-types` for policy and documentation.

| Component | Crate / module | Security notes |
|-----------|----------------|----------------|
| Blind issuance + anonymous tokens | `lib-q-lattice-zkp` (`blind`, `token`) | CRS Ajtai model; see [`BLIND_ISSUANCE.md`](../lib-q-lattice-zkp/BLIND_ISSUANCE.md). Issuer attestation binds blinded commitments; not Chaum blind RSA. `SpendingProof` carries the token serial; double-spends are rejected at the application layer by serial-set membership (verifier-tracked registry, not in-protocol). |
| Nullifier + batch amortisation | `lib-q-lattice-zkp` (`sigma/uniqueness`, `sigma/amortise`) | Deterministic nullifiers for registries; opening proofs bind nullifiers into Fiat–Shamir contexts. Uniqueness amortisation labels enable single-batch verification across multiple commitments under one realm. |
| Hierarchical Merkle + opening | `lib-q-lattice-zkp` (`sigma/hierarchical`) — `prove_level_membership` / `verify_level_membership` | Leaf payload is **revealed** (clearance level, role tag, parent digest). The verifier learns the path position. Full position-and-attribute-hiding PVTN ZK is **future work**; this construction is a Merkle path certificate composed with an Ajtai opening tied to the leaf. |
| Federation ring openings | `lib-q-ring-sig` | Opening proofs over a shared CRS; linear-scan verification is not issuer-hiding toward the verifier (see [crate DESIGN](../lib-q-ring-sig/DESIGN.md)). Default DualRing-LB path uses an aggregated CCS 2021–style verify (`verify_dual_ring_opening`). |
| Credential presentation | `lib-q-ring-sig` (`credential`) | Default path verifies with **`verify_dualring_lb`** (full-ring aggregate). A **legacy** API remains that uses **`verify_federation_opening_scan`** (linear cost; see module docs). The verifier does not receive the signer index on the default path. |

##### Constant-time scope (Phase 7 paths)

The following paths are wired for statistical timing / TVLA-style harnesses via
[`lib-q-sca-test` `privacy_workloads`](../lib-q-sca-test/src/privacy_workloads.rs)
(scaffold only; not a certification claim):

- `BlindIssuance::verify` — blind issuance bundle verification.
- `verify_federation_opening` — federation opening at a **known** signer index.
- `verify_dualring_lb` — DualRing-LB (aggregated `verify_dual_ring_opening`; uniform cost across ring slots).
- `BlindSignature::verify_blind_signature` — pilot blind-signature bundle verify.
- `verify_private_membership` — private-membership pilot verifier.
- `registry_nullifier`, `witness_nullifier`, `federation_digest` — public transcript / registry digests (SHAKE256).

Prover-side rejection-sampling paths (`BlindIssuance::request`/`issuer_sign`,
`sign_federation_message`, `prove_opening`, `prove_dual_ring_opening`, `sign_dualring_lb`, `amortise`) are **intentionally excluded**:
their timing is data-dependent by construction (loop count of the abort), and they
must be invoked only on attacker-independent secrets.

##### Replay model

| Asset | Replay defence | Where enforced |
|-------|----------------|----------------|
| Anonymous token (`AnonymousToken::spend`) | Application-layer registry of spent serials | Verifier maintains a per-realm `serial → seen` set; `SpendingProof::verify` rejects mismatched serials. |

#### ZKP Features
- **Proof Generation**: Create zero-knowledge proofs of computation
- **Proof Verification**: Verify proofs without revealing inputs
- **Privacy-Preserving**: Hide sensitive data while proving statements
- **Scalable Verification**: Efficient verification of complex computations

### Post-Quantum Hash Functions
We use only SHA-3 family hash functions, which are quantum-resistant:

1. **SHAKE256** (Primary)
   - Variable output length
   - Used for hash-based signatures (SLH-DSA)
   - 256-bit security level
   - NIST standardized

2. **SHAKE128** (General Purpose)
   - Variable output length
   - Used for general hashing needs
   - 128-bit security level
   - NIST standardized

3. **cSHAKE256** (Customizable)
   - Customizable hash function
   - Domain separation capabilities
   - Used for specific applications requiring customization
   - NIST standardized

### NIST PQC Standardization
We only use algorithms that have been standardized or are in the final round of NIST's Post-Quantum Cryptography standardization process:

#### Standardized Algorithms
- **ML-KEM**: NIST PQC Standard (FIPS 203)
- **ML-DSA**: NIST PQC Standard (FIPS 204)
- **FN-DSA**: NIST PQC Standard (FIPS 206)
- **SLH-DSA**: NIST PQC Standard (FIPS 205)

#### NIST FIPS Standards
- **FIPS 206 / FN-DSA**: Fast Fourier Transform over NTRU-Lattice-Based Digital Signature Algorithm
  - Official NIST designation for FALCON algorithm
  - Compact signature sizes for bandwidth-constrained applications
  - Suitable for root and intermediate certificates in PKI systems

#### Code-based KEMs (workspace implementations)
- **CB-KEM** (Classic McEliece–family parameter sets) and **HQC** are implemented as **post-quantum KEMs** in this repository; track each crate’s README and NIST publications for the exact standardization status of the parameter sets you enable.

#### Emerging Post-Quantum Algorithms
- **Saturnin**: Lightweight symmetric algorithm suite with 256-bit block cipher
  - Designed for IoT and constrained devices
  - Provides authenticated encryption and hashing modes
  - Superior post-quantum security compared to classical alternatives
### Forbidden Classical Algorithms
The following classical algorithms are explicitly forbidden in lib-Q:

#### Forbidden KEMs
- **RSA**: Broken by Shor's algorithm
- **ECC**: Broken by Shor's algorithm
- **DH**: Broken by Shor's algorithm
- **ECDH**: Broken by Shor's algorithm

#### Forbidden Signatures
- **RSA-PSS**: Broken by Shor's algorithm
- **ECDSA**: Broken by Shor's algorithm
- **Ed25519**: Broken by Shor's algorithm
- **Ed448**: Broken by Shor's algorithm

#### Forbidden Hash Functions
- **MD5**: Completely broken (collision and preimage attacks)
- **SHA-1**: Practically broken (collision attacks)
- **SHA-256 / SHA-512** (SHA-2 family): Grover's algorithm halves the effective security level — SHA-256 is reduced to 128-bit security against quantum adversaries, which falls below the required margin for new designs. lib-Q uses the SHA-3 / Keccak family exclusively for hash-based constructions.

  Note: SHA-2 may still appear inside third-party crates as part of TLS record MAC or HKDF where no lib-Q-controlled path is involved. Those usages are not sanctioned for security-critical lib-Q operations.

#### Forbidden Symmetric Ciphers
- **AES-128**: Grover's algorithm reduces security to approximately 64 bits — not acceptable for post-quantum use.
- **ChaCha20 / Poly1305** (standalone): 256-bit key variants survive Grover with ~128-bit quantum security, but these primitives are not part of the lib-Q algorithm set, which centers on Saturnin and SHA-3 family constructions. Do not substitute them for lib-Q primitives.

  Note: **AES-256** may appear **inside reviewed implementations** where a standard or interoperability layer requires it (for example certain RNG or KEM-adjacent paths). That is not an invitation to add AES-GCM or ChaCha20-Poly1305 as general-purpose user-facing substitutes for the Saturnin / SHAKE-centered AEAD story without maintainer review.

## Implementation Security Guidelines

### Constant-Time Operations
All cryptographic operations must be constant-time to prevent timing attacks:

#### Constant-Time Requirements
- **No branching on secret data**: All branches must be independent of secret values
- **Constant-time comparison**: Use dedicated comparison functions
- **Constant-time selection**: Use bitwise operations for conditional selection
- **Cache-timing resistance**: Avoid memory access patterns that depend on secrets

#### Implementation Examples
```rust
// Constant-time comparison
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

// Constant-time selection
pub fn constant_time_select(condition: bool, a: u32, b: u32) -> u32 {
    let mask = if condition { 0xffffffff } else { 0 };
    (a & mask) | (b & !mask)
}
```

### WebAssembly and constant-time discipline

The same source-level rules (no secret-dependent branches, subtle-based selection where applicable, table-lookup discipline) apply when compiling for `wasm32-unknown-unknown`. LLVM may choose different instruction sequences and memory layouts than for x86_64 or AArch64; **constant-time intent in Rust is not a formal proof on any target**, and WASM adds a distinct JIT and sandbox model. Treat WASM deployments like any other high-risk environment: pin toolchains, run regression tests on the actual target, and plan dedicated side-channel review if your threat model assumes browser-grade adversaries.

### Memory Safety
Rust's ownership model provides memory safety, but additional measures are required:

#### Secure Memory Management
- **Automatic zeroing**: Use `zeroize` crate for sensitive data
- **No heap allocation**: Stack-only operations for constrained environments
- **Memory barriers**: Prevent compiler optimizations that could leak secrets
- **Secure deallocation**: Ensure sensitive data is properly cleared

#### Implementation Examples
```rust
use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretKey {
    key: [u8; 32],
}

impl SecretKey {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).expect("Failed to generate random key");
        Self { key }
    }
}
```

### Input Validation
Comprehensive input validation prevents many security vulnerabilities:

#### Validation Requirements
- **Key sizes**: Verify all key sizes match expected values
- **Algorithm parameters**: Validate security levels and algorithm choices
- **Buffer bounds**: Check all buffer accesses are within bounds
- **Format validation**: Verify input data formats are correct

#### Implementation Examples
```rust
pub fn validate_key_size(key: &[u8], expected_size: usize) -> Result<(), Error> {
    if key.len() != expected_size {
        return Err(Error::InvalidKeySize {
            expected: expected_size,
            actual: key.len(),
        });
    }
    Ok(())
}

pub fn validate_security_level(level: u32) -> Result<(), Error> {
    if !is_supported_security_level(level) {
        return Err(Error::InvalidSecurityLevel {
            level,
            supported: SECURITY_LEVELS,
        });
    }
    Ok(())
}
```

### Random Number Generation
Cryptographically secure random number generation is essential:

#### RNG Requirements
- **Cryptographic quality**: Use cryptographically secure RNG
- **Entropy sources**: Multiple entropy sources for robustness
- **Platform integration**: Use platform-specific secure RNG when available
- **WASM compatibility**: Support for browser and Node.js environments

#### Implementation Examples
```rust
// Platform-specific RNG
#[cfg(target_arch = "wasm32")]
pub fn secure_random_bytes(buffer: &mut [u8]) -> Result<(), Error> {
    use wasm_bindgen::JsCast;
    use web_sys::window;
    
    let window = window().ok_or(Error::NoWindow)?;
    let crypto = window.crypto().ok_or(Error::NoCrypto)?;
    
    let array = js_sys::Uint8Array::new_with_length(buffer.len() as u32);
    crypto.get_random_values_with_u8_array(&array);
    
    array.copy_to(buffer);
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn secure_random_bytes(buffer: &mut [u8]) -> Result<(), Error> {
    getrandom::getrandom(buffer).map_err(|_| Error::RandomGenerationFailed)
}
```

## Security Testing

### Static Analysis
- **Rust Analyzer**: Type safety and memory safety checks
- **Clippy**: Additional linting and security checks
- **Cargo Audit**: Dependency vulnerability scanning
- **CodeQL**: Advanced static analysis for security vulnerabilities

### Dynamic Analysis
- **Fuzzing**: Automated input testing for edge cases
- **Memory testing**: AddressSanitizer and MemorySanitizer
- **Timing analysis**: Constant-time verification
- **Side-channel testing**: Power and timing analysis

### Formal Verification
- **Cryptographic proofs**: Formal verification of algorithm correctness
- **Implementation proofs**: Formal verification of constant-time properties
- **Protocol proofs**: Formal verification of security protocols
- **Memory safety proofs**: Formal verification of memory safety

## Security Audits

### Internal Audits
- **Code review**: Security-focused code review process
- **Architecture review**: Security architecture validation
- **Implementation review**: Implementation security validation
- **Integration review**: Integration security validation

### External Audits
- **Third-party audits**: Independent security audits
- **Academic review**: Academic community review
- **Industry review**: Industry expert review
- **Community review**: Open source community review

### Audit Requirements
- **Zero classical crypto**: Verify no classical algorithms are used
- **Constant-time verification**: Verify all operations are constant-time
- **Memory safety**: Verify memory safety properties
- **Input validation**: Verify comprehensive input validation
- **Random number generation**: Verify secure RNG usage

## Incident Response

### Security Incident Process
1. **Detection**: Automated and manual detection of security issues
2. **Assessment**: Rapid assessment of impact and severity
3. **Containment**: Immediate containment of security issues
4. **Investigation**: Thorough investigation of root causes
5. **Remediation**: Comprehensive remediation of security issues
6. **Communication**: Transparent communication with users
7. **Prevention**: Implementation of preventive measures

### Disclosure Policy
- **Responsible disclosure**: Coordinated disclosure with researchers
- **Transparent communication**: Open communication about security issues
- **Timely updates**: Prompt updates for security issues
- **User notification**: Clear notification of affected users

### Security Contact
- **Security email**: github@enkom.dev
- **PGP key**: Published for secure communication (when available)
- **Responsible disclosure**: Recognition for responsible disclosure