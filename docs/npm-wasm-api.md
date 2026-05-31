# @lib-q WASM JavaScript API reference

Functions below are exported by **wasm-bindgen** (names in **camelCase** in TypeScript). Unless noted, failures throw or return `LibQWasmError`-shaped values; see `@lib-q/types`.

Packages ship **dual targets**: `web/` (bundlers) and `nodejs/` (Node). Import the package root; `package.json` `exports` selects the right glue.

## `@lib-q/core`

Umbrella crate (`lib-q`). Feature set in CD: `wasm`, `all-algorithms`, `ml-kem`. Exposes KEM, signature, hash, AEAD, and optional algorithm paths compiled into the build.

Typical imports: generated `libq` module plus algorithm-specific helpers from the same bundle. Secret key material is returned as **`Uint8Array`** (not `Vec<u8>`).

## `@lib-q/ml-kem`

| JS name | Description |
|---------|-------------|
| `mlKemKeygen` | Keypair generation (parameter set from build) |
| `mlKemEncapsulate` | Encapsulation; `shared_secret` as `Uint8Array` |
| `mlKemDecapsulate` | Decapsulation; shared secret as `Uint8Array` |

## `@lib-q/kem`

KEM façade over ML-KEM (and optional features in custom builds). See generated `lib_q_kem.d.ts` for the exact surface enabled in CD (`wasm`, `ml-kem`).

## `@lib-q/sig`

ML-DSA / SLH-DSA WASM paths enabled in CD (`wasm`, `ml-dsa`). See `lib_q_sig.d.ts` under `pkg-sig/web` or `pkg-sig/nodejs`.

## `@lib-q/fn-dsa`

FN-DSA keygen, sign, verify (build features: `wasm`, `std`, `rand`). See `lib_q_fn_dsa.d.ts`.

## `@lib-q/hash`

SHA-3 family operations (`alloc`, `oid` in CD). See `lib_q_hash.d.ts`.

## `@lib-q/utils`

Shared utility helpers. See `lib_q_utils.d.ts`.

## `@lib-q/aead`

AEAD encrypt/decrypt (Saturnin, Romulus, duplex-sponge per CD features). See `lib_q_aead.d.ts`.

## `@lib-q/hpke`

| Area | Notes |
|------|--------|
| `hpkeSeal` / `hpkeOpen` | Single-shot seal/open |
| Sender/receiver objects | Multi-shot HPKE; opaque `u32` handles for secret contexts |

See `lib_q_hpke.d.ts` and `@lib-q/types` (`HpkeSealResult`, etc.).

## `@lib-q/zkp`

High-level **preimage** STARK proofs (JSON-serialized proof objects):

| JS name | Description |
|---------|-------------|
| `zkpProvePreimageJson` | Prove knowledge of secret preimage (Poseidon-128 commitment) |
| `zkpVerifyPreimageJson` | Verify proof; `expected_hash_hex` is 32-byte hash as hex |
| `zkpProvePreimageNistJson` | NIST cSHAKE256 variant |
| `zkpVerifyPreimageNistJson` | Verify NIST variant |

Full STARK prover/verifier AIR APIs remain in **Rust** (`lib-q-stark`, `lib-q-zkp::stark`). Use `@lib-q/stark` / `@lib-q/plonky` for integration metadata or extend bindings as needed.

## `@lib-q/random`

| JS name | Description |
|---------|-------------|
| `secureRandomBytes` | Returns `Uint8Array`; clear in JS after use |

## `@lib-q/hqc`, `@lib-q/slh-dsa`, `@lib-q/cb-kem`

JSON/hex-oriented helpers for each algorithm family. See respective `lib_q_*.d.ts` files. CB-KEM is built for **one** parameter set per release artifact.

## `@lib-q/ring-sig`

Pilot DualRing-LB sign/verify (fixed CRS). Depends on lattice-zkp wire formats. See `lib_q_ring_sig.d.ts`.

## `@lib-q/prf`

| JS name | Description |
|---------|-------------|
| `legendrePrfU256BeHex` | Legendre PRF; key and x as 64-char big-endian hex |
| `goldPrfU256BeHex` | Gold PRF; returns hex-encoded 32-byte output |

## `@lib-q/stark` (new)

| JS name | Description |
|---------|-------------|
| `starkPackageVersion` | Crate version string (`0.0.2`, …) |

Use **`@lib-q/zkp`** for preimage prove/verify from JavaScript. Use **Rust** `lib-q-stark` for `prove`, `verify`, AIR builders, and FRI APIs.

## `@lib-q/plonky` (new)

| JS name | Description |
|---------|-------------|
| `plonkyPackageVersion` | Crate version string |

Rust consumers enable `full`, `uni-stark`, `batch-stark`, etc. on `lib-q-plonky`. npm package confirms the WASM artifact links; extend with JSON APIs when needed.

## `@lib-q/poseidon` (new)

| JS name | Description |
|---------|-------------|
| `poseidon128Hash12Hex` | Poseidon-128 sponge hash of field elements `[1, 2]`; returns 16-byte hex (real‖imag canonical u32) for smoke/KAT alignment |

Field: `Complex<Mersenne31>`. For custom inputs, use Rust `lib-q-poseidon` or add bindings.

## `@lib-q/lattice-zkp` (new)

| JS name | Description |
|---------|-------------|
| `latticeZkpPilotCommitHex` | Hex-encoded Ajtai commitment for a fixed pilot CRS and zero opening (integration smoke) |

Full sigma protocols, amortisation, and BLNS hooks are **Rust-only** (`lib-q-lattice-zkp` modules). `@lib-q/ring-sig` builds on the same serialization.

## `@lib-q/ring` (new)

| JS name | Description |
|---------|-------------|
| `ringCoefficientCount` | Returns `256` (ML-DSA ring dimension) |
| `ringModulusQ` | Returns modulus `q` = `8380417` |

Polynomial arithmetic, NTT, and module matrices are **Rust-only** (`lib_q_ring`).

## `@lib-q/types`

TypeScript-only (`index.d.ts`, `index.js`). No WASM. Shared interfaces for cross-package typings.

## Versioning

All packages share the workspace version (e.g. `0.0.5`) on release. Pin in production:

```bash
npm install @lib-q/core@0.0.5 @lib-q/zkp@0.0.5
```

## Security

- NIST-oriented post-quantum asymmetric crypto only in published builds.
- Clear secret `Uint8Array` values in JS when done (`fill(0)`).
- Browser deployments: CSP compatible with WASM loading (see [wasm-security-model.md](wasm-security-model.md)).
- Subresource integrity: `integrity-manifest.json` in each WASM package (SHA-384).
