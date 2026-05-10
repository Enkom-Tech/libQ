# @lib-q npm packages

Published packages are built in release with [`wasm-pack`](https://rustwasm.github.io/wasm-pack/) from the matching workspace crate (see `.github/workflows/cd.yml`, job `publish-wasm-packages`). Each package ships the `wasm-pack` output (`*.js`, `*.d.ts`, `*.wasm`) scoped as `@lib-q/<name>`.

## Packages

| Package | Crate | Role |
|---------|-------|------|
| `@lib-q/core` | `lib-q` | Umbrella entry point; broad feature set in CD |
| `@lib-q/ml-kem` | `lib-q-ml-kem` | ML-KEM (FIPS 203); `wasm-pack` with `--features wasm` |
| `@lib-q/kem` | `lib-q-kem` | KEM façade + ML-KEM |
| `@lib-q/sig` | `lib-q-sig` | Signatures (ML-DSA path in CD) |
| `@lib-q/fn-dsa` | `lib-q-fn-dsa` | FN-DSA (FIPS 206) |
| `@lib-q/hash` | `lib-q-hash` | SHA-3 family façade |
| `@lib-q/utils` | `lib-q-utils` | Shared utilities |
| `@lib-q/aead` | `lib-q-aead` | AEAD (`wasm` + Saturnin / Romulus / duplex-sponge as configured in CD) |
| `@lib-q/hpke` | `lib-q-hpke` | HPKE (`hpkeSeal` / `hpkeOpen`, multi-shot sender/receiver objects, opaque `u32` handles for secret-bearing contexts) |
| `@lib-q/zkp` | `lib-q-zkp` | Preimage proofs (`provePreimage` / `verifyPreimage`) |
| `@lib-q/types` | `npm/lib-q-types` | Shared TypeScript interfaces for WASM return shapes (`LibQWasmError`, `HpkeSealResult`, …) |
| `@lib-q/random` | `lib-q-random` | `secureRandomBytes` |
| `@lib-q/hqc` | `lib-q-hqc` | HQC KEM JSON/hex helpers |
| `@lib-q/slh-dsa` | `lib-q-slh-dsa` | SLH-DSA keygen/sign/verify by parameter-set id |
| `@lib-q/cb-kem` | `lib-q-cb-kem` | CB-KEM for the **single** parameter set compiled into that build |
| `@lib-q/ring-sig` | `lib-q-ring-sig` | Pilot singleton DualRing-LB sign/verify |
| `@lib-q/prf` | `lib-q-prf` | Legendre / Gold PRF evaluation (pilot moduli) |

## Installation

```bash
npm install @lib-q/core
```

Pin by version in production (`@lib-q/core@<version>`).

## Dual-target layout (`web/` + `nodejs/`)

CD runs `wasm-pack` twice into **`pkg/web`** (bundler / browser glue) and **`pkg/nodejs`** (Node glue) so artifacts are not overwritten. Published `package.json` sets conditional `exports`: **Node** resolves the `node` condition; browser bundlers use `browser` / `module` (see `scripts/npm-publish-annotate.mjs`).

## WASM size and CI

`scripts/wasm-size-check.sh` enforces per-crate `.wasm` size budgets on the workspace wasm gate (see `docs/wasm-compilation.md`). Budgets are intentionally loose for STARK-heavy crates; tighten after profiling your release profile.

## Security

All `@lib-q/*` packages follow the same policy as the Rust workspace: **NIST-approved post-quantum** algorithms for asymmetric cryptography; no classical RSA/ECC/X25519 as a primary security mechanism.
