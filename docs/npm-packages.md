# @lib-q npm packages

**26** scoped packages (`@lib-q/*`) are built in release with [`wasm-pack`](https://rustwasm.github.io/wasm-pack/) from the matching workspace crate (see `.github/workflows/cd.yml`, job `publish-wasm-packages`). Each WASM package ships `*.js`, `*.d.ts`, and `*.wasm` under `pkg/web` and `pkg/nodejs` (or crate-specific `out-dir`).

`@lib-q/threshold-sig`, `@lib-q/fhe`, and `@lib-q/threshold-kem` are not among them: all three
crates were withdrawn and have since been removed from the workspace —
`lib-q-threshold-sig` as **cryptographically unsound**, `lib-q-fhe` because `decrypt` never read
the key, and `lib-q-threshold-kem` because its partial-decapsulation shares disclosed the full
ML-KEM-768 decapsulation key (board cards t_2a349708 / t_8ca3fd06). See
[Removed crates](npm-coverage.md#removed-crates).

Coverage vs the full Rust workspace: [npm-coverage.md](npm-coverage.md). JavaScript export names: [npm-wasm-api.md](npm-wasm-api.md).

Manual ordered publish: [npm-publish.md](npm-publish.md) — `scripts/publish-npm-ordered.sh` or `scripts/publish-npm-ordered.ps1`.

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
| `@lib-q/aead` | `lib-q-aead` | AEAD (`wasm` + Saturnin / Rocca-S / Romulus / duplex-sponge as configured in CD) |
| `@lib-q/hpke` | `lib-q-hpke` | HPKE (`hpkeSeal` / `hpkeOpen`, multi-shot sender/receiver objects, opaque `u32` handles for secret-bearing contexts) |
| `@lib-q/zkp` | `lib-q-zkp` | Preimage proofs (`provePreimage` / `verifyPreimage`) |
| `@lib-q/types` | `npm/lib-q-types` | Shared TypeScript interfaces for WASM return shapes (`LibQWasmError`, `HpkeSealResult`, …) |
| `@lib-q/random` | `lib-q-random` | `secureRandomBytes` |
| `@lib-q/hqc` | `lib-q-hqc` | HQC KEM JSON/hex helpers |
| `@lib-q/slh-dsa` | `lib-q-slh-dsa` | SLH-DSA keygen/sign/verify by parameter-set id |
| `@lib-q/cb-kem` | `lib-q-cb-kem` | CB-KEM for the **single** parameter set compiled into that build |
| `@lib-q/ring-sig` | `lib-q-ring-sig` | Pilot singleton DualRing-LB sign/verify |
| `@lib-q/prf` | `lib-q-prf` | Legendre / Gold PRF evaluation (pilot moduli) |
| `@lib-q/stark` | `lib-q-stark` | STARK framework; JS metadata + Rust/zkp for prove/verify |
| `@lib-q/plonky` | `lib-q-plonky` | Plonky3-derived STARK components |
| `@lib-q/poseidon` | `lib-q-poseidon` | Poseidon-128 over `Complex<Mersenne31>` |
| `@lib-q/lattice-zkp` | `lib-q-lattice-zkp` | Module-lattice commitments / sigma (research) |
| `@lib-q/ring` | `lib-q-ring` | ML-DSA ring \(R_q\) constants and shared arithmetic (Rust-heavy) |
| `@lib-q/mac` | `lib-q-mac` | qCW-MAC sign/verify (`qcwMacGenerateKey`, `qcwMacSign`, `qcwMacVerify`) |
| `@lib-q/blind-pcs` | `lib-q-blind-pcs` | Experimental blind commitment demo (**EXPERIMENTAL_NON_NIST**) |

`lib-q-stark-*` and `lib-q-plonky-*` subcrates remain **crates.io-only**; npm uses the umbrella rows above.

## Installation

```bash
npm install @lib-q/core
```

Pin by version in production (`@lib-q/core@<version>`).

## Dual-target layout (`web/` + `nodejs/`)

CD runs `wasm-pack` twice into **`pkg/web`** (bundler / browser glue) and **`pkg/nodejs`** (Node glue) so artifacts are not overwritten. Published `package.json` sets conditional `exports`: **Node** resolves the `node` condition; browser bundlers use `browser` / `module` (see `scripts/npm-publish-annotate.mjs`).

`exports` is not root-only: it also lists an explicit key for every `.wasm` file the package ships (e.g. `./web/lib_q_aead_bg.wasm`, `./nodejs/lib_q_aead_bg.wasm`), plus `./integrity-manifest.json` and `./package.json`. Those subpaths exist for consumers who must name the `.wasm` binary directly — self-hosting/CDN copies, a bundler `?url` import, or a Worker/Deno build — since a bundler or Node resolving strictly through `exports` cannot otherwise reach a file that is only present in the tarball. The default `import '@lib-q/x'` entry point never needed this: wasm-pack's own glue loads its `.wasm` by a path relative to itself (`new URL(..., import.meta.url)`), which bypasses `exports` entirely. `scripts/ci-guard-npm-exports.mjs` enforces (structurally and by a real `npm pack`+install+resolve probe) that every packaged `.wasm` and `./package.json` stays reachable this way.

## WASM size and CI

`scripts/wasm-size-check.sh` enforces per-crate `.wasm` size budgets on the workspace wasm gate (see `docs/wasm-compilation.md`). Budgets are intentionally loose for STARK-heavy crates; tighten after profiling your release profile.

## Security

All `@lib-q/*` packages follow the same policy as the Rust workspace: **NIST-approved post-quantum** algorithms for asymmetric cryptography; no classical RSA/ECC/X25519 as a primary security mechanism.

### `@lib-q/ml-kem` WASM API (secret return types)

`MlKemKeypair.secret_key`, `MlKemEncapsulationResult.shared_secret`, and the return value of `ml_kem_decapsulate` are exported as `Uint8Array` in generated TypeScript (Rust `js_sys::Uint8Array`), replacing the older wasm-bindgen path that returned owned `Vec<u8>` for those values. Update any downstream typings or wrappers that assumed `Vec<u8>`-shaped glue. Sensitive bytes must still be cleared on the JavaScript side after use (for example `fill(0)` on a mutable view).

### `@lib-q/random` WASM API

`secureRandomBytes` returns `Uint8Array` (same Rust projection as above); the Rust side uses `Zeroizing` for the intermediate fill buffer. Clear outputs in JS when they are no longer needed.

### `@lib-q/core` WASM key material

`KemKeypair::secret_key_bytes` and `KemSecretKey::bytes` return `Uint8Array` for WASM bindings (not owned `Vec<u8>`). Treat like other secret exports: clear on the JS side after use.
