# lib-Q - Post-Quantum Cryptography Library

A Rust cryptography workspace focused on **NIST-standardized post-quantum** key exchange and signatures, **SHA-3-family** hashes and XOFs, and a **transparent STARK**–based zero-knowledge stack. WASM builds are supported for selected crates and features.

## Mission

lib-Q provides a coherent Rust API surface over NIST-track post-quantum primitives, SHA-3–family hashing, Saturnin AEAD, HPKE, and optional STARK-based proofs, with the goal of keeping advanced cryptography approachable without hiding residual implementation risk.

## Key features

- **Post-quantum first**: Post-quantum KEMs and signatures with tiered symmetric options
- **Standards-aligned**: PQC KEMs and signatures track NIST-standardized modules (e.g. FIPS 203/204/205/206, HQC, Classic McEliece–family CB-KEM); hashes and XOFs use the SHA-3 family; symmetric design centers on Saturnin; ZKPs use a transparent STARK stack (complementary to the NIST PQC algorithm set)
- **Memory safe**: Built in Rust with zero-cost abstractions
- **Cross-platform**: Native Rust + WASM compilation
- **Intuitive API**: Clean, consistent interface designed for modern development
- **Self-contained algorithms**: No external non-Rust tooling required for core use
- **Three security tiers**: Ultra-secure, balanced, and performance-optimized options
- **Modular design**: Use only what you need with individual crates and npm packages

## no_std, embedded, and WebAssembly

- **Umbrella `lib-q` crate**: Disabling default features applies `#![no_std]` to this crate's own code, but some path dependencies are still declared with `std` enabled (for example unified signature support via `lib-q-sig`). The final artifact may still link the standard library. For a **true** `no_std` + `alloc` dependency tree, use the **workspace crates you need** (`lib-q-core`, `lib-q-kem`, `lib-q-ml-dsa`, etc.) with `--no-default-features` and each crate's `alloc` / algorithm features. Per-crate READMEs describe WASM and `no_std` where relevant (for example [lib-q-saturnin/README.md](lib-q-saturnin/README.md)).

- **WASM and `getrandom`**: Match CI when compiling for `wasm32-unknown-unknown`: set `CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS` to `--cfg getrandom_backend="wasm_js" -C panic=abort` (see [.github/actions/wasm-build/action.yml](.github/actions/wasm-build/action.yml), [scripts/build-wasm.ps1](scripts/build-wasm.ps1), [scripts/security-check.ps1](scripts/security-check.ps1)).

- **`lib-q-zkp`**: Built as a normal Rust library (not a `cdylib` npm bundle). CI runs `cargo check --target wasm32-unknown-unknown` with `wasm,zkp` to guard the ZKP stack on WASM without `wasm-pack`.

## Package structure

lib-Q is organized as a Rust workspace with individual crates and npm packages:

### Rust crates (crates.io)

- **`lib-q`** - Complete library (re-exports everything)
- **`lib-q-core`** - Core types and traits
- **`lib-q-kem`** - Key Encapsulation Mechanisms (ML-KEM, CB-KEM, HQC, DAWN)
- **`lib-q-sig`** - Digital Signatures (ML-DSA, SLH-DSA)
- **`lib-q-fn-dsa`** - FN-DSA Digital Signatures (FIPS 206)
- **`lib-q-hash`** - Hash Functions (SHAKE256, SHAKE128, cSHAKE256)
- **`lib-q-aead`** - Authenticated Encryption (Saturnin)
- **`lib-q-utils`** - Utility functions
- **`lib-q-zkp`** - Zero-Knowledge Proofs

### npm packages (npmjs.com)

- **`@lib-q/core`** - Complete library for Node.js
- **`@lib-q/kem`** - KEM-only package
- **`@lib-q/sig`** - Signature-only package
- **`@lib-q/fn-dsa`** - FN-DSA signature-only package
- **`@lib-q/hash`** - Hash-only package
- **`@lib-q/utils`** - Utilities-only package

## Installation

### Rust (Complete Library)
```bash
cargo add lib-q
```

### Rust (Individual Crates)
```bash
# For KEM operations only
cargo add lib-q-kem

# For signatures only
cargo add lib-q-sig

# For FN-DSA signatures only
cargo add lib-q-fn-dsa

# For hash functions only
cargo add lib-q-hash

# For utilities only
cargo add lib-q-utils
```

### Node.js (Complete Library)
```bash
npm install @lib-q/core
```

### Node.js (Individual Packages)
```bash
# For KEM operations only
npm install @lib-q/kem

# For signatures only
npm install @lib-q/sig

# For FN-DSA signatures only
npm install @lib-q/fn-dsa

# For hash functions only
npm install @lib-q/hash

# For utilities only
npm install @lib-q/utils
```

## Supported algorithms

### Key encapsulation mechanisms (KEMs)
- **ML-KEM** (FIPS 203; security levels 1, 3, and 5)
- **CB-KEM** (code-based KEM in the Classic McEliece family; five NIST parameter sets, selectable via crate features)
- **HQC** (NIST-standardized code-based KEM; parameter sets HQC-128, HQC-192, and HQC-256, corresponding to levels 1, 3, and 5)
- **DAWN** (NTRU-based KEM; multiple parameter sets)

### Digital signatures
- **ML-DSA** (FIPS 204; levels 1, 3, and 5)
- **FN-DSA** (FIPS 206; levels 1 and 5)
- **SLH-DSA** (FIPS 205; levels 1, 3, and 5)

### Hash functions
- **SHAKE256**, **SHAKE128**, **cSHAKE256** (SHA-3 family; used across signatures, KDFs, and protocols)
- Additional SHA-3–family APIs where exposed by `lib-q-hash` and related workspace crates (see crate documentation)

### Authenticated encryption
- **Saturnin** (post-quantum symmetric suite: AEAD, block cipher, hash, and stream modes)

### Hybrid public-key encryption (HPKE)
- **Tier 1: Ultra-Secure** (Pure post-quantum with SHAKE256-based AEAD)
- **Tier 2: Balanced** (Post-quantum KEM + Saturnin AEAD)
- **Tier 3: Performance** (Post-quantum KEM + optimized Saturnin)

### Zero-knowledge proofs (ZKPs)
- **zk-STARKs** (transparent, post-quantum-friendly proof system used in this stack)
- **Proof generation and verification** via `lib-q-zkp` (built on the workspace STARK crates)
- **WASM**: `lib-q-zkp` is checked for `wasm32-unknown-unknown` in CI when the relevant features are enabled
- **Deeper stack**: `lib-q-plonky` and related crates host the Plonky3-derived STARK pipeline (including univariate and batch STARK, Keccak AIR, and lookup support), gated by features for selective compilation

## Architecture

The workspace is centered on the umbrella **`lib-q`** crate and splits algorithms and infrastructure across focused crates. Conceptually:

```
lib-Q/   (repository root)
├── lib-q/              # Umbrella library (feature-gated re-exports)
├── lib-q-core/         # Types, traits, provider surface, validation
├── lib-q-kem/          # KEM façade and integrations
├── lib-q-ml-kem/, lib-q-cb-kem/, lib-q-dawn/, lib-q-hqc/  # Concrete KEM implementations
├── lib-q-sig/, lib-q-ml-dsa/, lib-q-slh-dsa/, lib-q-fn-dsa/
├── lib-q-hash/, lib-q-sha3/, lib-q-keccak/, lib-q-k12/
├── lib-q-aead/, lib-q-saturnin/
├── lib-q-hpke/
├── lib-q-zkp/, lib-q-stark*/, lib-q-plonky*/
├── lib-q-utils/, lib-q-random/, lib-q-platform/, …
└── examples/
```

For a full member list, see the `[workspace].members` table in [Cargo.toml](Cargo.toml).

## Security model

- **Post-quantum only**: No reliance on classical public-key or symmetric primitives outside the stated SHA-3 family and PQC standards.
- **Constant-time intent**: Critical paths are written for constant-time behavior; full guarantees require platform-specific review and tooling (see [ROADMAP.md](ROADMAP.md)).
- **Secure memory**: Sensitive buffers use explicit zeroization where the type system allows.
- **Side-channel awareness**: Design and review target timing and cache behavior; formal side-channel certification is not yet claimed.

## Development status

**Active development.** Major algorithms are implemented and covered by automated tests; the library remains **pre-production** until independent audit and release hardening (see [SECURITY.md](SECURITY.md)).

### Implemented capabilities
- **ML-DSA** (FIPS 204; parameter sets ML-DSA-44, ML-DSA-65, ML-DSA-87) with provider-style integration
- **FN-DSA** (FIPS 206) with CI coverage
- **SLH-DSA** (FIPS 205) including all twelve SLH-DSA parameter sets
- **ML-KEM** (FIPS 203; levels 1, 3, and 5)
- **CB-KEM** (Classic McEliece–family; five parameter sets, feature-selected)
- **DAWN** NTRU-based KEM (α-512, α-1024, β-512, β-1024)
- **HQC** (HQC-128, HQC-192, HQC-256)
- **Saturnin** (AEAD, block, hash, stream modes)
- **HPKE** (RFC 9180) with post-quantum KEM and AEAD options
- **Hash and XOF suite** (SHA-3 family, including SHAKE and cSHAKE, as exposed by workspace crates)
- **ZKP / STARK stack** (`lib-q-zkp` and supporting `lib-q-stark*` / `lib-q-plonky*` crates)
- **WASM** build paths for core scenarios (see CI and scripts referenced in the [no_std and WASM](#no_std-embedded-and-webassembly) section)
- **Engineering**: consistent error types, security validation utilities, and GitHub Actions for build, test, coverage, and security checks

### Near-term focus
- **Performance and ergonomics** for CB-KEM and other large-key KEMs
- **Assurance**: expanded fuzzing, constant-time verification where feasible, and third-party security review
- **ZKP**: documentation, API stability, and production-oriented hardening of the STARK pipeline

## Documentation

- [ROADMAP](ROADMAP.md)
- [Security policy](SECURITY.md)
- [Security model (technical)](docs/security.md)
- [ZKP Implementation and Library Layout](docs/zkp-implementation.md)
- [API Design](docs/api-design.md)
- [HPKE Architecture](docs/hpke-architecture.md)
- [Memory Architecture](docs/memory-architecture.md)
- [Interoperability](docs/interoperability.md)
- [Architecture Summary](docs/architecture-summary.md)
- [AI-Generated Wiki](https://deepwiki.com/Enkom-Tech/libQ)

## License

Apache 2.0 License - see [LICENSE](LICENSE) for details.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security notice

This project ships real cryptographic code but is **not positioned as production-ready**. Treat it as suitable for research, education, interoperability experiments, and internal prototypes until:

- An independent security audit of the code you enable has been completed, and  
- Your own integration testing, threat modeling, and operational controls are in place.

Absence of a published vulnerability report does not constitute a warranty. Track [SECURITY.md](SECURITY.md) for supported branches, reporting, and update policy.
