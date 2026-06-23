# npm vs Rust workspace coverage

lib-Q ships **two release surfaces**:

1. **crates.io** — full workspace (50+ crates), including `lib-q-stark-*`, `lib-q-plonky-*`, research crates, and infrastructure.
2. **npm (`@lib-q/*`)** — **30** scoped packages: **29** built with [`wasm-pack`](https://rustwasm.github.io/wasm-pack/) for Node.js and browsers, plus the TypeScript-only `@lib-q/types`.

npm is the **JavaScript product boundary**, not a 1:1 mirror of every Rust crate name.

## Package map (30 npm packages)

### Core cryptography (17, published in 0.0.2)

| npm | Rust crate | Role |
|-----|------------|------|
| `@lib-q/core` | `lib-q` | Umbrella WASM (`wasm`, `all-algorithms`, `ml-kem`) |
| `@lib-q/ml-kem` | `lib-q-ml-kem` | ML-KEM (FIPS 203) |
| `@lib-q/kem` | `lib-q-kem` | KEM façade |
| `@lib-q/sig` | `lib-q-sig` | ML-DSA / SLH-DSA paths |
| `@lib-q/fn-dsa` | `lib-q-fn-dsa` | FN-DSA (FIPS 206) |
| `@lib-q/hash` | `lib-q-hash` | SHA-3 family façade |
| `@lib-q/utils` | `lib-q-utils` | Shared helpers |
| `@lib-q/aead` | `lib-q-aead` | AEAD (Saturnin, Rocca-S, Romulus, duplex-sponge) |
| `@lib-q/hpke` | `lib-q-hpke` | HPKE (ML-KEM + symmetric) |
| `@lib-q/zkp` | `lib-q-zkp` | High-level preimage STARK proofs (JSON API) |
| `@lib-q/random` | `lib-q-random` | `secureRandomBytes` |
| `@lib-q/hqc` | `lib-q-hqc` | HQC KEM |
| `@lib-q/slh-dsa` | `lib-q-slh-dsa` | SLH-DSA (FIPS 205) |
| `@lib-q/cb-kem` | `lib-q-cb-kem` | CB-KEM (single compile-time parameter set) |
| `@lib-q/ring-sig` | `lib-q-ring-sig` | DualRing-LB pilot (uses `lib-q-lattice-zkp`) |
| `@lib-q/prf` | `lib-q-prf` | Legendre / Gold PRF pilots |
| `@lib-q/types` | `npm/lib-q-types` | TypeScript-only shared shapes |

### STARK / lattice stack (5, wired in repo; publish on next npm release)

| npm | Rust crate | Role |
|-----|------------|------|
| `@lib-q/stark` | `lib-q-stark` | STARK framework metadata; full prove/verify flows use `@lib-q/zkp` or Rust |
| `@lib-q/plonky` | `lib-q-plonky` | Plonky3-derived STARK components (feature-gated re-exports) |
| `@lib-q/poseidon` | `lib-q-poseidon` | Poseidon-128 over `Complex<Mersenne31>` |
| `@lib-q/lattice-zkp` | `lib-q-lattice-zkp` | Module-lattice commitments / sigma (research) |
| `@lib-q/ring` | `lib-q-ring` | Shared ring \(R_q\) for ML-DSA / lattice-zkp |

Publish order and scripts: [npm-publish.md](npm-publish.md) (`scripts/publish-npm-ordered.sh`).

### Advanced primitives (8, tier-4b npm parity)

| npm | Rust crate | Role |
|-----|------------|------|
| `@lib-q/mac` | `lib-q-mac` | qCW-MAC symmetric authentication |
| `@lib-q/blind-pcs` | `lib-q-blind-pcs` | Experimental blind commitment demo |
| `@lib-q/double-kem` | `lib-q-double-kem` | PROVISIONAL MAUL v1 double ML-KEM-768 |
| `@lib-q/fhe` | `lib-q-fhe` | Experimental toy lattice FHE |
| `@lib-q/threshold-kem` | `lib-q-threshold-kem` | PROVISIONAL threshold KEM |
| `@lib-q/threshold-sig` | `lib-q-threshold-sig` | PROVISIONAL threshold signatures |
| `@lib-q/dkg` | `lib-q-dkg` | PROVISIONAL lattice dealerless DKG |
| `@lib-q/threshold-raccoon` | `lib-q-threshold-raccoon` | PROVISIONAL PQ lattice threshold signature |

(`lib-q-blind-token` is tier-4b on crates.io but **crates.io-only** — `crate-type = ["rlib"]`, no wasm-pack bindings — so it has no `@lib-q/*` package; it is exempt from the tier-4b npm-parity guard.)

## What stays Rust-only on npm

These **compile for `wasm32`** in CI (`cargo check` / `check-only` wasm gate) but **do not** get separate `@lib-q/*` tarballs:

| Family | Examples | Use from JS via |
|--------|----------|-----------------|
| STARK internals | `lib-q-stark-air`, `lib-q-stark-fri`, `lib-q-stark-field`, `lib-q-stark-matrix`, … | `@lib-q/stark` (metadata), `@lib-q/zkp` (preimage API), or Rust |
| Plonky internals | `lib-q-plonky-uni-stark`, `lib-q-plonky-batch-stark`, `lib-q-plonky-keccak-air`, … | `@lib-q/plonky` or Rust `lib-q-plonky` features |
| Hash primitives | `lib-q-keccak`, `lib-q-sha3`, `lib-q-k12` | `@lib-q/hash` / `@lib-q/core` |
| ML-DSA crate | `lib-q-ml-dsa` | `@lib-q/sig` / `@lib-q/core` |
| Platform | `lib-q-platform`, `lib-q-intrinsics`, `lib-q-core` (as Rust lib) | Rust only |
| Research | `lib-q-lattice-zkp` (full sigma API), `lib-q-ring` (full arithmetic) | `@lib-q/lattice-zkp`, `@lib-q/ring` (initial WASM exports), Rust for production |

Deliberately **not** publishing one npm package per `lib-q-stark-*` crate keeps install size and versioning manageable. Consumers who need low-level STARK building blocks should use **Rust** or extend WASM bindings in the umbrella crates above.

### crates.io-only crates (no npm / wasm-pack package)

Some crates ship to **crates.io only** — they are Rust libraries with no corresponding `@lib-q/*` tarball, and several are explicitly exempt from (or simply outside) the **tier-4b npm-parity CI guard** (`scripts/ci-guard-new-crates-and-npm.sh`).

| Rust crate | Status | Why crates.io-only |
|------------|--------|--------------------|
| `lib-q-blind-token` | PROVISIONAL (pre-standard) | `crate-type = ["rlib"]` with no `wasm-pack` bindings; secure-params keygen is impractical in wasm (debug keygen is on the order of minutes). **Exempt** from the tier-4b npm-parity guard. |
| `lib-q-transcript` | **RED** — experimental / research, NOT proven sound, NOT audited; pending human cryptographer sign-off (IACR review) | Rust-only Fiat-Shamir duplex-transcript discipline (K12 out-of-circuit, Poseidon-256 in-circuit); no npm consumer surface, like the other STARK subcrates. |
| `lib-q-mve` | **RED** — experimental / research, NOT proven sound, NOT audited; pending human cryptographer sign-off (IACR review) | Rust-only multi-recipient verifiable encryption (verifiable rekey); no npm package, like the other STARK subcrates. |
| `lib-q-stark-baby-bear` | New in 0.0.8 | BabyBear prime field (a `lib-q-stark-monty31` instance); a low-level STARK subcrate — used from JS via `@lib-q/stark` / `@lib-q/zkp` or Rust, never its own tarball. |

These are **new in 0.0.8** (except `lib-q-blind-token`, which was already crates.io-only) and intentionally have **no npm / wasm packages**, matching the policy above for low-level STARK subcrates.

## Choosing a package

```text
Need everything in one bundle?     → @lib-q/core
Need only ML-KEM?                    → @lib-q/ml-kem
Need STARK preimage prove/verify?    → @lib-q/zkp
Need Poseidon / STARK field hash?    → @lib-q/poseidon (+ @lib-q/stark for version checks)
Need lattice pilot + ring constants? → @lib-q/lattice-zkp + @lib-q/ring
Need Plonky3 stack in Rust from JS?  → @lib-q/plonky (metadata today; extend bindings as needed)
```

## TypeScript

Install `@lib-q/types` alongside any WASM package for shared result types (`LibQWasmError`, HPKE handles, etc.). Generated `*.d.ts` from wasm-bindgen live in each package’s `web/` and `nodejs/` trees.

## See also

- [npm-packages.md](npm-packages.md) — install, dual-target layout, security notes
- [npm-wasm-api.md](npm-wasm-api.md) — exported JavaScript function names
- [wasm-compilation.md](wasm-compilation.md) — CI wasm gate and size budgets
- [crates-io-publish.md](crates-io-publish.md) — Rust crate publish order
