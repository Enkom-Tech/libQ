# Zero-Knowledge Proofs Implementation

## Overview

Integration strategy for zero-knowledge proofs (ZKPs) into lib-Q, focusing on zk-STARKs for post-quantum security and scalability.

## Library layout and implementation status

This section is the single source of truth for where ZKP/STARK/Plonky functionality lives and when to use which stack.

- **lib-q-stark** (and lib-q-stark-*): Core NIST-adapted STARK stack (SHAKE256, Complex&lt;Mersenne31&gt;, FRI, Merkle). Provides the minimal univariate STARK used by the default high-level API.

- **lib-q-zkp**: Public ZKP API. Uses lib-q-stark for proving and verifying. Exposes `ZkpProver`, `ZkpVerifier`, `StarkProver`, `StarkVerifier`, `default_config`, aggregation, and type-specific verification. The default dependency for ZKP is lib-q-stark.

- **lib-q-plonky**: Full Plonky3-derived STARK ecosystem. It is the complete port of the Plonky3 feature set: univariate STARK (lib-q-plonky-uni-stark), batch STARK (lib-q-plonky-batch-stark), Keccak AIR (lib-q-plonky-keccak-air), lookup arguments (lib-q-plonky-lookup), multilinear utilities (lib-q-plonky-multilinear-util). All of these are fully implemented; they are optional only in the sense of feature flags (e.g. `lib-q-plonky` with feature `full`). Use lib-q-plonky when you need batch proving, Keccak AIR, or lookup; use lib-q-zkp with lib-q-stark for the default high-level API.

- **lib-q-lattice-zkp**: **Research** crate for module-lattice relations (Ajtai-style commitments, sigma-style openings, ML-DSA–compatible challenges) built on **`lib-q-ring`**. It does **not** prove arbitrary circuits via AIR; it targets algebraic lattice statements that are impractical to encode in the bitwise STARK pipeline. Recent additions include witness-derived nullifiers, a pilot private-membership bundle over SHAKE256 Merkle trees (see `DESIGN.md` §4.1), and a pilot blind-signature-shaped issuer transcript (`blind.rs`). See `lib-q-lattice-zkp/README.md` and `DESIGN.md` for scope and status.

- **Security**: The STARK / Plonky paths use NIST-approved primitives (SHAKE256) in the default pipeline. Any exception (e.g. Poseidon in a specific AIR) is documented where it occurs (e.g. lib-q-zkp for `prove_secret_value`). The lattice ZKP crate documents its own assumptions and is not interchangeable with the STARK verifier API.

## Strategic Alignment

- **Post-quantum security**: zk-STARKs use collision-resistant hash functions
- **Privacy enhancement**: Enables privacy-preserving applications
- **Scalability**: Proof size grows logarithmically with computation complexity
- **Transparency**: No trusted setup required

## Use Cases

1. **Privacy-preserving authentication**: Prove identity without revealing credentials
2. **Confidential transactions**: Prove transaction validity without revealing amounts
3. **Verifiable computation**: Prove computation correctness without revealing inputs
4. **Blockchain privacy**: Enable private smart contracts and transactions
5. **Supply chain privacy**: Prove compliance without revealing sensitive data

## Architecture

The public ZKP surface is **`lib-q-zkp`** (`lib-q-zkp/src/`: `lib.rs`, `api.rs`, `air/`, and supporting modules). It builds on the in-repo STARK crates (`lib-q-stark*`, and optionally `lib-q-plonky*`) described in [Library layout and implementation status](#library-layout-and-implementation-status). There is **no** repository-root `src/zkp/` tree.

```
lib-Q workspace (ZKP-related)
├── lib-q-zkp/src/     # ZkpProver, ZkpVerifier, AIRs, aggregation hooks
├── lib-q-stark*/      # Core STARK / FRI / Merkle / field stack
└── lib-q-plonky*/     # Plonky3-derived STARK ecosystem (feature-gated)
```

**External prover libraries** (Winterfell, `zkp-stark`, and similar) are **not** used as dependencies. Stack choice is expressed with Cargo features on workspace crates, not optional third-party ZKP engines.

## Historical implementation plan (obsolete)

An older phased checklist lived in this file and implied most work was unfinished. **That checklist was removed:** STARK prove/verify, FRI/Merkle infrastructure, ML-KEM-facing integration tests, WASM `cargo check`, benchmarks, and scheduled fuzzing are already present (see [Testing Strategy](#testing-strategy) and [ROADMAP.md](../ROADMAP.md)). Use those sections—not removed `[ ]` items—for status.

## Performance targets

The numbers below are **aspirational engineering goals**, not CI-enforced SLOs. Profile on your target CPU, trace size, and feature set.

### Proof Generation
- **Small proofs** (< 1KB): < 100ms
- **Medium proofs** (1-10KB): < 1s
- **Large proofs** (10-100KB): < 10s
- **Very large proofs** (> 100KB): < 60s

### Proof Verification
- **Small proofs**: < 10ms
- **Medium proofs**: < 100ms
- **Large proofs**: < 1s
- **Very large proofs**: < 10s

### Memory Usage
- **Proof generation**: < 1GB for typical use cases
- **Proof verification**: < 100MB for typical use cases
- **WASM compatibility**: < 50MB total memory usage

## Security Considerations

### Post-Quantum Security
- **Hash functions**: Multiple NIST-approved hash options available (all FIPS 202 compliant):
  - **SHAKE128**: 128-bit security level, lighter option for performance-sensitive applications
  - **SHAKE256**: 256-bit security level, recommended default for production use
  - **SHA3-256**: 256-bit security level, fixed-length output (non-XOF)
- **Modular architecture**: The challenger and Merkle tree implementations are generic over hash functions via the `CryptographicHasher` trait, allowing any NIST-approved hash to be used
- **Default recommendation**: SHAKE256 is the recommended default for all STARK operations
- **Field arithmetic**: Use large prime fields (≥ 256 bits)
- **Proof parameters**: Ensure quantum-resistant security levels

### Implementation Security
- **Constant-time operations**: All ZKP operations must be constant-time
- **Memory safety**: Secure memory management for sensitive data
- **Input validation**: Comprehensive validation of all inputs
- **Side-channel resistance**: Prevent timing and power analysis attacks

## Public API surface

The shipped entry points are **`ZkpProver`** and **`ZkpVerifier`** in [`lib-q-zkp`](../lib-q-zkp/) (concrete types with methods such as prove/verify paths for secret-value and arithmetic AIRs—see `lib-q-zkp/src/lib.rs` and `lib-q-zkp/src/api.rs`). Circuit construction uses in-crate `CircuitBuilder` / AIR types exercised by [`lib-q-zkp/tests/air_integration.rs`](../lib-q-zkp/tests/air_integration.rs). For authoritative signatures, use `cargo doc -p lib-q-zkp --open` or [docs.rs/lib-q-zkp](https://docs.rs/lib-q-zkp) once published.

## Testing Strategy

This section tracks **what is automated in the repo and CI** versus **partial coverage** or **deferred** work. Primary test locations: `lib-q-zkp/tests/`, `lib-q-stark/tests/`, and (for fuzzing) `lib-q-zkp/fuzz/`.

### Unit Testing

| Item | Status | Where |
|------|--------|--------|
| Individual component testing | **Implemented** | STARK stack: [lib-q-stark/tests/](../lib-q-stark/tests/) (see [lib-q-stark/tests/README.md](../lib-q-stark/tests/README.md)). ZKP crate: [lib-q-zkp/tests/](../lib-q-zkp/tests/) (`merkle_*`, `security_parameter_tests`, `stub_tests`, `ip_soundness_tests`, etc.). |
| Circuit correctness testing | **Implemented** | [lib-q-zkp/tests/air_integration.rs](../lib-q-zkp/tests/air_integration.rs) (`CircuitBuilder`, `ArithmeticCircuit`, wrong-public rejection). |
| Proof generation / verification testing | **Implemented** | [lib-q-zkp/tests/air_integration.rs](../lib-q-zkp/tests/air_integration.rs), [zero_knowledge_tests.rs](../lib-q-zkp/tests/zero_knowledge_tests.rs), [aggregation_tests.rs](../lib-q-zkp/tests/aggregation_tests.rs); unit tests in [lib-q-zkp/src/lib.rs](../lib-q-zkp/src/lib.rs). |
| Error handling testing | **Partial** | Validation and `AirError` paths covered in integration tests; not every public error variant has a dedicated test. |
| Memory management / DoS limits | **Implemented** | [lib-q-zkp/tests/dos_limits_tests.rs](../lib-q-zkp/tests/dos_limits_tests.rs) exercises `MAX_OPERATIONS`, `MAX_TRACE_WIDTH`, `MAX_TRACE_HEIGHT`, and related `AirError::ExceedsMaxSize` paths; STARK-layer DoS: [lib-q-stark/tests/dos_protection_tests.rs](../lib-q-stark/tests/dos_protection_tests.rs). |

### Integration Testing

| Item | Status | Where |
|------|--------|--------|
| End-to-end proof workflows | **Implemented** | Prove/verify across AIRs in `lib-q-zkp` tests; CI job **ZKP Recursive Aggregation** (`.github/workflows/ci.yml`, `zkp-recursive`): release prove → aggregate → verify. |
| Integration with post-quantum crypto | **Implemented** | [lib-q-zkp/tests/ml_kem_session_key_integration.rs](../lib-q-zkp/tests/ml_kem_session_key_integration.rs): ML-KEM encaps/decaps consistency, then STARK prove/verify on `ArithmeticAir` with witness derived from the shared secret bytes (`cargo test -p lib-q-zkp --features zkp,std`). `SessionKeyDerivationAir` trace generation is unit-tested in [session_key.rs](../lib-q-zkp/src/air/session_key.rs); a full STARK prove path for that AIR is not yet enabled. |
| WASM compatibility testing | **Implemented** | CI **WASM Validation** matrix: `lib-q-zkp` with `wasm,zkp` (`check-only`). |
| Cross-platform testing | **Partial** | Linux CI matrix includes `zkp` (`lib-q`, `lib-q-zkp`). **Cross-Platform Builds** job compiles `lib-q` with `all-algorithms` (includes `zkp`) on multiple OSes; ZKP tests are not executed on every platform in CI. |
| Performance regression testing | **Implemented** | Criterion bench [lib-q-zkp/benches/stark_arithmetic_bench.rs](../lib-q-zkp/benches/stark_arithmetic_bench.rs); CI **Performance & Benchmarks** runs `cargo bench -p lib-q-zkp --features zkp --bench stark_arithmetic_bench` (non-PR workflow). |

### Security Testing

| Item | Status | Notes |
|------|--------|--------|
| Constant-time verification | **Partial (workspace)** | ZKP verifier paths are written with constant-time intent (see module docs in `lib-q-zkp/src/air/*`). CI **Constant-Time Verification** job targets `lib-q-sha3` / `lib-q-k12`, not ZKP-specific statistical timing gates. |
| Side-channel analysis | **Deferred** | No automated lab harness; design/review only. |
| Fuzzing of proof generation | **Implemented** | `cargo fuzz run zkp_prove_arithmetic` in [lib-q-zkp/fuzz/](../lib-q-zkp/fuzz/) (bounded `ArithmeticAir` inputs). |
| Fuzzing of proof verification | **Implemented** | `cargo fuzz run zkp_verify_bytes` in [lib-q-zkp/fuzz/](../lib-q-zkp/fuzz/) (deserialization + verify). |
| Formal verification of critical components | **Deferred** | Not wired for the ZKP pipeline in this repository. |

Scheduled fuzzing: [.github/workflows/zkp-fuzz-scheduled.yml](../.github/workflows/zkp-fuzz-scheduled.yml) (weekly `workflow_dispatch` / cron).

## Future Enhancements

### Advanced ZKP Types

The current ZKP stack is zk-STARK based (SHAKE256 / SHA-3 family), which is inherently post-quantum secure. Classical ZKP systems that rely on elliptic-curve pairings or discrete-logarithm hardness (e.g. zk-SNARKs, Bulletproofs, Plonk, Halo2) are **not in scope** for this library — they depend on classical asymmetric assumptions and are broken by quantum adversaries.

Planned post-quantum-safe enhancements:
- [ ] Broader recursive STARK composition (beyond current aggregation / recursive CI paths—see `lib-q-zkp` aggregation tests and the **ZKP Recursive Aggregation** job in `ci.yml`)
- [ ] Heavier batch proof accumulation APIs (FRI-based batching where not yet exposed)
- [ ] Post-quantum range proofs built on STARK arithmetic circuits
- [ ] Lattice-based commitments as an optional Merkle-tree alternative

### Performance Optimizations
- [ ] GPU acceleration for proof generation
- [ ] Parallel verification algorithms
- [ ] Proof compression techniques
- [ ] Memory-efficient algorithms

### Application-Specific Circuits
- [ ] Blockchain transaction circuits
- [ ] Machine learning inference circuits
- [ ] Database query circuits
- [ ] Financial calculation circuits

## Success Metrics

### Technical Metrics
- [ ] Proof generation time < target benchmarks
- [ ] Proof verification time < target benchmarks
- [ ] Memory usage < target limits
- [ ] WASM compatibility verified
- [ ] Zero security vulnerabilities
