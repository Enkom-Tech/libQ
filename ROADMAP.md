# lib-Q development roadmap

This document sequences engineering and assurance work for lib-Q: a Rust workspace for post-quantum key establishment, signatures, symmetric constructions, HPKE, and a STARK-based ZKP stack. Priorities follow cryptographic risk, standards evolution, and what integrators need to ship safely.

**Status:** Core algorithms and protocols are largely implemented; remaining effort skews toward performance, verification, third-party audit, and operational polish (see [README.md](README.md) and [SECURITY.md](SECURITY.md)).

## Phase 0: Foundation (mature; continuous maintenance)

### Core infrastructure
- [x] Project structure and configuration
- [x] Error handling system
- [x] Security documentation and guidelines
- [x] Development workflow setup
- [x] Basic utility functions
- [x] Random number generation
- [x] Memory management utilities (zeroization, secure key traits)
- [x] Constant-time operations

### Development tools
- [x] CI/CD pipeline setup
- [x] Security scanning integration (`cargo audit`, NIST validation utilities, dedicated security workflow)
- [x] Code coverage requirements
- [x] Performance benchmarking framework
- [x] WASM compilation pipeline
- [x] Documentation generation

### Security foundation
- [x] Security audit framework (`cargo audit`, NIST compliance validation, scheduled security workflow)
- [ ] Constant-time verification tooling (targeted work in HQC; broader coverage TBD)
- [x] Side-channel analysis tooling and methodology (`lib-q-sca-test` TVLA/dudect-style harnesses)
- [x] Fuzzing infrastructure (e.g. HPKE harness, property-based tests; expand coverage over time)
- [ ] Formal verification setup where cost-effective

## Phase 1: Core algorithms

### Hash functions
- [x] SHAKE256 implementation
- [x] SHAKE128 implementation
- [x] cSHAKE256 implementation
- [x] Hash-based signature support
- [ ] Performance optimizations
- [ ] Constant-time verification

### Key encapsulation mechanisms (KEMs)
- [x] ML-KEM (FIPS 203, Level 1, 3, 5)
  - [x] Core implementation
  - [x] Key generation
  - [x] Encapsulation/Decapsulation
  - [x] All parameter sets (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
  - [x] Complete test coverage
  - [ ] Performance optimization
  - [ ] Security audit
- [x] CB-KEM (Classical McEliece, all five parameter sets)
  - [x] Core implementation
  - [x] Key generation
  - [x] Encapsulation/Decapsulation
  - [ ] Performance optimization
- [x] HQC (Level 1, 3, 5 — HQC-128, HQC-192, HQC-256)
  - [x] Core implementation
  - [x] Key generation
  - [x] Encapsulation/Decapsulation
  - [ ] Performance optimization

### Digital signatures
- [x] ML-DSA (FIPS 204, Level 1, 3, 5)
  - [x] Core implementation
  - [x] Key generation
  - [x] Signing/Verification
  - [x] Shared ring / NTT layer (`lib-q-ring`) for portable `R_q` arithmetic
  - [ ] Performance optimization
- [x] FN-DSA (FIPS 206, Level 1, 5)
  - [x] Core implementation
  - [x] Key generation
  - [x] Signing/Verification
  - [x] All parameter sets
  - [ ] CAVP `.rsp` parser harness (blocked until NIST publishes redistributable FN-DSA vectors; see `lib-q-fn-dsa/docs/KAT_VERIFICATION.md`)
  - [ ] Performance optimization
- [x] SLH-DSA (FIPS 205, Level 1, 3, 5)
  - [x] Core implementation
  - [x] Key generation
  - [x] Signing/Verification
  - [x] All 12 parameter sets (SHA2-128f/s, SHA2-192f/s, SHA2-256f/s, SHAKE-128f/s, SHAKE-192f/s, SHAKE-256f/s)
  - [x] Complete test coverage
  - [ ] Performance optimization

## Phase 2: High-level APIs

### Authenticated encryption
- [x] Saturnin AEAD implementation
  - [x] Core AEAD mode
  - [x] Block cipher mode
  - [x] Hash function mode
  - [x] Stream cipher mode
  - [x] Complete test coverage
  - [x] Performance optimization (runtime SIMD dispatch + Criterion benchmarks + SIMD/scalar equivalence tests)
- [x] Post-quantum AEAD construction
  - [x] Saturnin AEAD implementation
  - [x] SHAKE256 AEAD implementation
  - [x] KEM-based AEAD construction
  - [x] HPKE AEAD integration
- [x] KEM-based encryption
  - [x] HPKE (RFC 9180) implementation
  - [x] KEM-AEAD direct encryption
  - [x] Provider pattern integration
- [x] Streaming encryption support
  - [x] Saturnin stream cipher
  - [x] SHAKE256 stream mode
  - [x] CTR mode streaming
- [x] Nonce management
  - [x] Secure nonce generation
  - [x] Uniqueness checking and collision detection
  - [x] Global nonce manager with thread safety
  - [x] Counter-based and random nonce support

### Hybrid public-key encryption (HPKE)
- [x] RFC 9180 compliant HPKE implementation
  - [x] ML-KEM integration (512, 768, 1024)
  - [x] SHAKE256 and SHA3 KDF support
  - [x] Saturnin and SHAKE256 AEAD support
  - [x] Complete test suite (95+ tests)
  - [x] Provider pattern integration
- [x] Tier 1: Ultra-Secure HPKE (Pure post-quantum with SHAKE256-based AEAD)
- [x] Tier 2: Balanced HPKE (Post-quantum KEM + Saturnin AEAD)
- [x] Tier 3: Performance HPKE (Post-quantum KEM + optimized Saturnin)
- [ ] HPKE performance benchmarking
- [ ] HPKE constant-time verification

### Key exchange and sessions
- [ ] Higher-level session protocols on top of existing KEMs (where distinct from HPKE)
- [ ] Documented forward-secrecy patterns for integrators
- [ ] Session key derivation guidance and reference patterns

## Phase 3: Platform support

### WASM support
- [x] Basic WASM compilation
- [x] WASM feature support across core crates (core, hash, KEM, sig, AEAD, HPKE, random, etc.)
- [x] CI WASM validation (wasm32-unknown-unknown check for algorithm crates)
- [x] Browser compatibility (wasm-pack `--target web` in CI/CD)
- [x] Node.js compatibility (wasm-pack `--target nodejs` in CI/CD)
- [ ] Performance optimization
- [ ] Memory management

### Cross-platform
- [ ] ARM optimization (NEON)
- [ ] x86 optimization (AVX2, AVX512)
- [ ] RISC-V support
- [ ] Mobile platforms
- [ ] Embedded systems

### Language bindings
- [x] JavaScript / TypeScript (WASM and published `@lib-q/*` packages where released)
- [ ] Python
- [ ] C / C++

## Phase 4: Advanced features

### Advanced cryptography
- [x] Zero-knowledge proofs (zk-STARKs)
  - [x] Core STARK implementation
  - [x] Proof generation and verification
  - [x] WASM compatibility (lib-q-zkp wasm feature)
  - [x] Integration with post-quantum crypto (SHAKE256, Mersenne31)
- [x] Module-lattice / sigma ZKP research path (`lib-q-lattice-zkp` on `lib-q-ring`; algebraic lattice relations, not the STARK AIR stack)
  - [ ] Protocol-level hardening, parameter audit, and API stability (research-grade today)

### Performance optimization
- [x] SIMD optimizations (Saturnin AVX2/NEON dispatch and kernels)
- [ ] Parallel processing
- [ ] Hardware acceleration
- [ ] Memory pooling

### Security enhancements
- [ ] Formal verification
- [x] Side-channel resistance baseline (hardened ML-KEM/ML-DSA paths with masking and shuffled processing)
- [ ] Quantum-resistant randomness

## Phase 5: Ecosystem

### Documentation and education
- [ ] Comprehensive API documentation
- [ ] Migration guides
- [ ] Security best practices
- [ ] Performance guides

### Tools and utilities
- [ ] Command-line tools
- [ ] Key management utilities
- [ ] Performance benchmarking tools
- [ ] Security analysis tools

### Integration
- [ ] TLS/SSL integration
- [ ] SSH integration
- [ ] IoT protocols

## Phase 6: Production readiness

### Security certification
- [ ] Third-party security audit
- [ ] Formal verification completion
- [ ] Side-channel analysis
- [ ] Penetration testing

### Performance validation
- [ ] Performance benchmarking
- [ ] Memory usage analysis
- [ ] Scalability testing
- [ ] Stress testing

### Production deployment
- [ ] Production-ready releases
- [ ] Long-term support (LTS)
- [ ] Security update process
- [ ] Vulnerability disclosure

## Phase 7: Privacy protocols (anonymous credentials)

Engineering trackers for Phase 7 “deferred” items. Implementations are **not** wired as `lib-q-core` KEM/signature providers; identifiers live in `AlgorithmCategory::PrivacyProtocol` ([`lib-q-types`](lib-q-types/README.md)).

- [x] **Lattice ZKP** ([`lib-q-lattice-zkp`](../lib-q-lattice-zkp/))
  - [x] `BlindIssuance` / blind bundle verification; pilot `BlindIssuerKeypair` + `BlindSignature` path (`BLIND_ISSUANCE.md`).
  - [x] `AnonymousToken` + spending proofs.
  - [x] Commitment nullifier openings (`NullifierOpeningProof`) + witness nullifier openings (`WitnessNullifierOpeningProof`); `Algorithm::LatticeWitnessNullifier` in `lib-q-types`.
  - [x] Uniqueness batch labels for `amortise`.
  - [x] Hierarchical `HierarchicalAuthProof` (Merkle + opening) + pilot `prove_private_membership` / `verify_private_membership`.
- [x] **PRF building blocks** ([`lib-q-prf`](../lib-q-prf/)) — Legendre / Gold PRFs over safe-prime fields for optional `dualring-prf` transcripts in [`lib-q-ring-sig`](../lib-q-ring-sig/).
- [x] **Federation / ring-sig** ([`lib-q-ring-sig`](../lib-q-ring-sig/))
  - [x] Fiat–Shamir opening proofs with ring digest; legacy scan verifier behind `federation-opening`.
  - [x] DualRing-LB–oriented pilot (`dualring_lb`, constant-time full-ring verify); `Algorithm::LatticeDualRingLb`.
  - [x] `CredentialPresentation` default path uses `verify_dualring_lb`.
- [x] **Fuzzing** — `lib-q-lattice-zkp/fuzz` (opening, nullifier, blind bundle, blind signature, witness nullifier, private membership), `lib-q-ring-sig/fuzz` (federation, dualring PRF, dualring LB).
- [x] **Integration smoke** — [`lib-q/tests/privacy_protocol_integration_tests.rs`](../lib-q/tests/privacy_protocol_integration_tests.rs) (blind signature, witness nullifier, DualRing-LB, private membership, credentials).
- [x] **SCA hooks** — [`lib-q-sca-test`](../lib-q-sca-test/) `privacy` feature: `touch_dualring_lb_verify`, `touch_witness_nullifier`, `touch_blind_signature_verify`, `touch_private_membership`.

## Ongoing development

### Continuous improvement
- [ ] Algorithm updates based on NIST progress
- [ ] Performance optimizations
- [ ] Security enhancements
- [ ] Platform support expansion
- [ ] Documentation updates

### Research and development
- [ ] New post-quantum algorithms
- [ ] Advanced cryptographic protocols
- [ ] Quantum-resistant protocols

## Success metrics

### Security
- [x] No classical cryptographic primitives in the project’s stated PQC / SHA-3 / Saturnin threat model
- [ ] Demonstrated constant-time behavior on supported targets (measured, not asserted)
- [x] Memory safety via Rust’s model; `unsafe` only where justified and reviewed
- [ ] Independent security audit with published results
- [ ] Formal verification only where ROI is clear

### Performance
- [ ] Competitive operational cost versus comparable PQC stacks (not versus pre-quantum RSA/ECC, which are out of scope)
- [ ] WASM performance characterized for supported call paths
- [ ] Documented memory footprint for primary parameter sets
- [ ] Key generation and encapsulation/signing latencies acceptable for stated use cases
- [ ] Efficient encryption, decryption, and verification on hot paths

