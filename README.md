# lib-Q - Post-Quantum Cryptography Library

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Enkom-Tech/libQ)

A Rust cryptography workspace focused on **NIST-standardized post-quantum** key exchange and signatures, **SHA-3-family** hashes and XOFs, and a **transparent STARK**–based zero-knowledge stack. CI enforces `cargo check --workspace --exclude lib-q-examples --exclude lib-q-sca-test --target wasm32-unknown-unknown` (with the `getrandom` wasm_js cfg) so the **publishable library workspace** compiles for the WebAssembly target; npm bundles are produced for the `@lib-q/*` packages listed below (see [docs/npm-packages.md](docs/npm-packages.md)). For build modes, feature flags, and browser baselines, see [docs/wasm-compilation.md](docs/wasm-compilation.md).

## Mission

lib-Q provides a coherent Rust API surface over NIST-track post-quantum primitives, SHA-3–family hashing, Saturnin and Rocca-S AEAD, HPKE, and optional STARK-based proofs, with the goal of keeping advanced cryptography approachable without hiding residual implementation risk.

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

- **`lib-q-zkp`**: Ships a `cdylib` + `wasm` feature for `wasm-pack` / `@lib-q/zkp`; CI also `cargo check`s the ZKP stack on `wasm32-unknown-unknown`.

### Browser example

The minimal browser demo in [`examples/wasm-browser-demo`](examples/wasm-browser-demo) exposes an ML-DSA-44 smoke API:

```javascript
import init, { wasm_smoke_ml_dsa_sign_verify } from "./pkg/wasm_browser_demo.js";

await init();
const ok = await wasm_smoke_ml_dsa_sign_verify();
console.log("ML-DSA wasm smoke:", ok);
```

## Package structure

lib-Q is organized as a Rust workspace with individual crates and npm packages:

### Rust workspace crates

Publishing to [crates.io](https://crates.io/) is driven by [`.github/workflows/cd.yml`](.github/workflows/cd.yml) in dependency order. The `examples` umbrella and `examples/wasm-browser-demo` are integration harnesses (`publish = false` where set); other members follow `[workspace].members` in [Cargo.toml](Cargo.toml). The workspace-wide WASM compile gate excludes those example crates and `lib-q-sca-test`.

| Crate | Role |
|-------|------|
| **`lib-q`** | Umbrella library (feature-gated re-exports) |
| **`lib-q-types`** | Shared type definitions |
| **`lib-q-core`** | Core types, traits, provider surface, validation |
| **`lib-q-keccak`** | Keccak-f / sponge building blocks |
| **`lib-q-k12`** | KangarooTwelve (K12) |
| **`lib-q-sha3`** | SHA-3 / SHAKE / cSHAKE core |
| **`lib-q-keccak-digest`** | Digest adapter over Keccak |
| **`lib-q-kem`** | KEM façade (ML-KEM, CB-KEM, HQC integration) |
| **`lib-q-ml-kem`** | ML-KEM (FIPS 203) |
| **`lib-q-ml-dsa`** | ML-DSA (FIPS 204) |
| **`lib-q-ring`** | Negacyclic ring / NTT layer for ML-DSA |
| **`lib-q-sca-test`** | Statistical side-channel harness (TVLA-style) |
| **`lib-q-lattice-zkp`** | Module-lattice commitments / sigma research |
| **`lib-q-ring-sig`** | Ring-style openings / DualRing pilots |
| **`lib-q-prf`** | Legendre / Gold PRF building blocks |
| **`lib-q-platform`** | Platform helpers |
| **`lib-q-intrinsics`** | SIMD / intrinsics helpers |
| **`lib-q-sig`** | Signature façade (ML-DSA, SLH-DSA) |
| **`lib-q-hash`** | Hash façade (SHAKE, KMAC, TupleHash, etc.) |
| **`lib-q-aead`** | AEAD façade (Saturnin, Rocca-S, Romulus, duplex, tweak) |
| **`lib-q-saturnin`** | Saturnin suite |
| **`lib-q-rocca-s`** | Rocca-S AEAD (AES-accelerated; IETF draft-nakano-rocca-s) |
| **`lib-q-duplex-aead`** | Duplex-sponge AEAD |
| **`lib-q-tweak-aead`** | Tweakable CTR AEAD over Keccak |
| **`lib-q-romulus`** | Romulus AEAD (Skinny-based) |
| **`lib-q-hpke`** | HPKE (RFC 9180) |
| **`lib-q-utils`** | Shared utilities |
| **`lib-q-zkp`** | ZKP public API (STARK-backed); includes the experimental unlinkable set-membership proof (**RED**) |
| **`lib-q-mve`** | Multi-recipient verifiable encryption / verifiable rekey — single proof that every recipient is wrapped the same group key, relay-checkable without learning it (**RED / research, pending cryptographer sign-off**) |
| **`lib-q-transcript`** | Shared Fiat–Shamir / CFRG-sigma duplex-transcript discipline for lib-Q ZK proofs (K12 out-of-circuit, Poseidon-256 in-circuit; no_std + alloc) (**RED / research, pending sign-off**) |
| **`lib-q-fn-dsa`** | FN-DSA (FIPS 206) |
| **`lib-q-slh-dsa`** | SLH-DSA (FIPS 205) |
| **`lib-q-cb-kem`** | Classic McEliece–family CB-KEM |
| **`lib-q-random`** | Randomness / entropy helpers |
| **`lib-q-hqc`** | HQC KEM |
| **`lib-q-hqc-traits`** | HQC shared traits (`lib-q-hqc/traits`) |
| **`lib-q-stark`** | STARK prover stack (top-level) |
| **`lib-q-stark-air`** | AIR definitions |
| **`lib-q-stark-challenger`** | Fiat–Shamir challenger |
| **`lib-q-stark-commit`** | Commitment layer |
| **`lib-q-stark-dft`** | DFT / NTT for STARKs |
| **`lib-q-stark-field`** | Field arithmetic |
| **`lib-q-stark-field-testing`** | Field test helpers |
| **`lib-q-stark-fri`** | FRI |
| **`lib-q-stark-interpolation`** | Interpolation |
| **`lib-q-stark-matrix`** | Matrix ops |
| **`lib-q-stark-mds`** | MDS layer |
| **`lib-q-stark-merkle`** | Merkle trees |
| **`lib-q-stark-mersenne31`** | Mersenne-31 field |
| **`lib-q-stark-monty31`** | Monty-31 field |
| **`lib-q-stark-baby-bear`** | BabyBear prime field (p = 2³¹ − 2²⁷ + 1) as a Monty-31 instance |
| **`lib-q-stark-rayon`** | Optional Rayon parallelism |
| **`lib-q-stark-symmetric`** | Symmetric primitives for STARKs |
| **`lib-q-stark-util`** | STARK utilities |
| **`lib-q-stark-shake256`** | SHAKE256 bindings |
| **`lib-q-stark-shake128`** | SHAKE128 bindings |
| **`lib-q-stark-sha3-256`** | SHA3-256 bindings |
| **`lib-q-poseidon`** | Poseidon permutation |
| **`lib-q-plonky-multilinear-util`** | Plonky3 multilinear utilities |
| **`lib-q-plonky-keccak-air`** | Keccak AIR |
| **`lib-q-plonky-lookup`** | Lookup argument support |
| **`lib-q-plonky-uni-stark`** | Univariate STARK |
| **`lib-q-plonky-batch-stark`** | Batch STARK |
| **`lib-q-plonky`** | Plonky3-derived integration |

### npm packages (npmjs.com)

**30** `@lib-q/*` packages are published in CD: **29** WASM bundles built with `wasm-pack` (the `publish-wasm-packages` matrix in [`cd.yml`](.github/workflows/cd.yml)) plus the TypeScript-only **`@lib-q/types`** package. See [docs/npm-coverage.md](docs/npm-coverage.md) for how npm maps to the Rust workspace (STARK/Plonky subcrates stay Rust-only; umbrella npm packages cover the JS surface). The newest crates — `lib-q-mve`, `lib-q-transcript`, and `lib-q-stark-baby-bear` — are **crates.io-only** (no npm/WASM packages).

- **`@lib-q/core`** — Umbrella WASM bundle (all algorithms path used in CD)
- **`@lib-q/ml-kem`** — ML-KEM (FIPS 203) only
- **`@lib-q/kem`** — Post-quantum KEM façade
- **`@lib-q/sig`** — Post-quantum signatures (ML-DSA path in CD)
- **`@lib-q/fn-dsa`** — FN-DSA (FIPS 206)
- **`@lib-q/hash`** — SHA-3–family hash façade
- **`@lib-q/utils`** — Utilities
- **`@lib-q/aead`** — Post-quantum AEAD (Saturnin, Rocca-S, Romulus, duplex-sponge)
- **`@lib-q/hpke`** — Post-quantum HPKE (RFC 9180)
- **`@lib-q/zkp`** — ZKP / STARK proofs (high-level JSON API)
- **`@lib-q/random`** — Secure random bytes (`getrandom` / wasm_js)
- **`@lib-q/hqc`** — HQC KEM
- **`@lib-q/slh-dsa`** — SLH-DSA (FIPS 205)
- **`@lib-q/cb-kem`** — Classic McEliece CB-KEM (single compile-time parameter set per build)
- **`@lib-q/ring-sig`** — Federation / DualRing-LB pilot bindings
- **`@lib-q/prf`** — Legendre / Gold PRF pilots
- **`@lib-q/stark`** — STARK framework (metadata; use **`@lib-q/zkp`** for preimage prove/verify in JS)
- **`@lib-q/plonky`** — Plonky3-derived STARK components
- **`@lib-q/poseidon`** — Poseidon-128 for STARK fields
- **`@lib-q/lattice-zkp`** — Module-lattice / sigma research APIs
- **`@lib-q/ring`** — ML-DSA ring arithmetic \(R_q\)

API reference: [docs/npm-wasm-api.md](docs/npm-wasm-api.md).

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
# For ML-KEM only
npm install @lib-q/ml-kem

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

# AEAD, HPKE, ZKP, RNG, HQC, SLH-DSA, CB-KEM, ring-sig, PRF
npm install @lib-q/aead @lib-q/hpke @lib-q/zkp @lib-q/random @lib-q/hqc @lib-q/slh-dsa @lib-q/cb-kem @lib-q/ring-sig @lib-q/prf
```

## Supported algorithms

### Key encapsulation mechanisms (KEMs)
- **ML-KEM** (FIPS 203; security levels 1, 3, and 5)
- **CB-KEM** (code-based KEM in the Classic McEliece family; five NIST parameter sets, selectable via crate features)
- **HQC** (NIST-standardized code-based KEM; parameter sets HQC-128, HQC-192, and HQC-256, corresponding to levels 1, 3, and 5)

### Digital signatures
- **ML-DSA** (FIPS 204; levels 1, 3, and 5)
- **FN-DSA** (FIPS 206; levels 1 and 5)
- **SLH-DSA** (FIPS 205; levels 1, 3, and 5)

### Hash functions
- **SHAKE256**, **SHAKE128**, **cSHAKE256** (SHA-3 family; used across signatures, KDFs, and protocols)
- Additional SHA-3–family APIs where exposed by `lib-q-hash` and related workspace crates (see crate documentation)

### Authenticated encryption
- **Saturnin** (post-quantum symmetric suite: AEAD, block cipher, hash, and stream modes)
- **Rocca-S** (AES-accelerated 256-bit AEAD; IETF draft-nakano-rocca-s; 128-bit nonce, 256-bit tag)
- **Romulus** (NIST-submitted Skinny-based AEAD)
- **Duplex-sponge AEAD** (Keccak-duplex construction)
- **Tweak-AEAD** (tweakable CTR AEAD over Keccak)

### Hybrid public-key encryption (HPKE)
- **Tier 1: Ultra-Secure** (Pure post-quantum with SHAKE256-based AEAD)
- **Tier 2: Balanced** (Post-quantum KEM + Saturnin AEAD)
- **Tier 3: Performance** (Post-quantum KEM + optimized Saturnin)

### Zero-knowledge proofs (ZKPs)
- **zk-STARKs** (transparent, post-quantum-friendly proof system used in this stack)
- **Proof generation and verification** via `lib-q-zkp` (built on the workspace STARK crates)
- **WASM**: `lib-q-zkp` is checked for `wasm32-unknown-unknown` in CI when the relevant features are enabled
- **Deeper stack**: `lib-q-plonky` and related crates host the Plonky3-derived STARK pipeline (including univariate and batch STARK, Keccak AIR, and lookup support), gated by features for selective compilation
- **Experimental / RED — not proven, not audited, pending human cryptographer sign-off (IACR review):**
  - **Unlinkable set-membership proof** in `lib-q-zkp` (Fiat–Shamir domain `libq.zkfri.membership.v0`), in two arms. **Arm A** uses value field `Complex<Mersenne31>` = GF(p²) with a degree-3 FRI challenge extension (~186 bits) and reaches 128-bit post-quantum security **only at the PCS/commitment layer** (binding on the SHAKE256 Merkle commitment); its Poseidon-over-GF(p²) round-count soundness is still unverified. **Arm B** uses the BabyBear base field with Poseidon2 and is ~116-bit conjectured / ~99-bit provable (**not** 128-bit). Both arms are RED and gated behind ADR-113 freeze review.
  - **Verifiable rekey** (`lib-q-mve`): multi-recipient verifiable encryption — a producer distributes one fresh group key to many recipients (each wrapped under that recipient's ML-KEM update key) with a single proof that everyone receives the same key, checkable by an untrusted relay without it learning the key (insider-robustness / anti-split).
  - **Fiat–Shamir transcript discipline** (`lib-q-transcript`): a shared duplex transcript for new lib-Q ZK proofs, with K12 (out-of-circuit) and Poseidon-256 (in-circuit) instantiations.

## Architecture

The workspace is centered on the umbrella **`lib-q`** crate and splits algorithms and infrastructure across focused crates. Conceptually:

```
lib-Q/   (repository root)
├── lib-q/              # Umbrella library (feature-gated re-exports)
├── lib-q-core/         # Types, traits, provider surface, validation
├── lib-q-kem/          # KEM façade and integrations
├── lib-q-ml-kem/, lib-q-cb-kem/, lib-q-hqc/  # Concrete KEM implementations
├── lib-q-ring/         # ML-DSA field / NTT shared layer
├── lib-q-prf/, lib-q-ring-sig/  # PRF pilots + lattice-backed ring-style openings (research)
├── lib-q-sig/, lib-q-ml-dsa/, lib-q-slh-dsa/, lib-q-fn-dsa/
├── lib-q-lattice-zkp/  # Module-lattice ZKP research (sigma, commitments)
├── lib-q-sca-test/     # SCA screening tooling
├── lib-q-hash/, lib-q-sha3/, lib-q-keccak/, lib-q-k12/
├── lib-q-aead/, lib-q-saturnin/, lib-q-rocca-s/
├── lib-q-hpke/
├── lib-q-zkp/, lib-q-stark*/, lib-q-plonky*/
├── lib-q-utils/, lib-q-random/, lib-q-platform/, …
└── examples/
```

The table above is the authoritative crate list; the `[workspace].members` table in [Cargo.toml](Cargo.toml) is the same set plus the non-published `examples` member.

## Security model

- **Post-quantum asymmetric**: No classical public-key schemes (RSA, ECC, etc.) for those roles; asymmetric modules track NIST PQC (see [SECURITY.md](SECURITY.md)).
- **Hashes / XOFs**: Cryptographic design targets the SHA-3 family; symmetric constructions center on Saturnin and SHAKE-based options as documented per crate.
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
- **HQC** (HQC-128, HQC-192, HQC-256)
- **Saturnin** (AEAD, block, hash, stream modes) and **Rocca-S** (AES-accelerated 256-bit AEAD)
- **HPKE** (RFC 9180) with post-quantum KEM and AEAD options
- **Hash and XOF suite** (SHA-3 family, including SHAKE and cSHAKE, as exposed by workspace crates)
- **ZKP / STARK stack** (`lib-q-zkp` and supporting `lib-q-stark*` / `lib-q-plonky*` crates)
- **Lattice infrastructure** (`lib-q-ring` for ML-DSA field arithmetic; `lib-q-lattice-zkp` for research-grade module-lattice proofs, separate from STARKs)
- **PRF and ring-style opening pilots** (`lib-q-prf`, `lib-q-ring-sig`; research crates layered on lattice commitments—see per-crate READMEs)
- **Side-channel tooling** (`lib-q-sca-test` for statistical leakage screening, not a certification claim)
- **WASM** build paths for core scenarios (see CI and scripts referenced in the [no_std and WASM](#no_std-embedded-and-webassembly) section)
- **Engineering**: consistent error types, security validation utilities, and GitHub Actions for build, test, coverage, and security checks

### Near-term focus
- **Performance and ergonomics** for CB-KEM and other large-key KEMs
- **Assurance**: expanded fuzzing, constant-time verification where feasible, and third-party security review
- **ZKP**: documentation, API stability, and production-oriented hardening of the STARK pipeline

## Testing

### `lib-q-sig` and SLH-DSA features

`lib-q-sig` separates **algorithm enablement** from **who supplies randomness**:

- **`slh-dsa`**: SLH-DSA with caller-supplied randomness (suitable for `no_std` and tests that pass explicit buffers).
- **`slh-dsa-std`**: The above plus OS-backed entropy when APIs use `None` for randomness on std targets.

Run crate integration tests accordingly:

```bash
cargo test -p lib-q-sig --features slh-dsa
cargo test -p lib-q-sig --features slh-dsa-std
```

The second command includes end-to-end tests that rely on implicit RNG wiring (`lib-q-random`); the first is appropriate when you only need explicit-randomness coverage.

## Documentation

- [ROADMAP](ROADMAP.md)
- [Security policy](SECURITY.md)
- [Security model (technical)](docs/security.md)
- [ZKP Implementation and Library Layout](docs/zkp-implementation.md) (includes STARK stack and `lib-q-lattice-zkp`)
- [API Design](docs/api-design.md)
- [HPKE Architecture](docs/hpke-architecture.md)
- [Memory Architecture](docs/memory-architecture.md)
- [Interoperability](docs/interoperability.md)
- [Entropy Validation](docs/entropy-validation.md)
- [Test Coverage](docs/test-coverage.md)
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
