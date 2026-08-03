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

AEAD encrypt/decrypt (Saturnin, Rocca-S, Romulus, duplex-sponge per CD features). See `lib_q_aead.d.ts`.

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

## `@lib-q/mac` (since 0.0.7, EXPERIMENTAL_NON_NIST)

| JS name | Description |
|---------|-------------|
| `qcwMacKeyBytes` | Returns key size (32) |
| `qcwMacTagBytes` | Returns tag size (32) |
| `qcwMacGenerateKey` | Fresh key as `Uint8Array` |
| `qcwMacSign` | Sign `(key, msg, ad)` → tag `Uint8Array` |
| `qcwMacVerify` | Constant-time verify |

## `@lib-q/blind-pcs` (since 0.0.7, EXPERIMENTAL_NON_NIST)

| JS name | Description |
|---------|-------------|
| `blindCommit` | Commitment `Uint8Array` (32 bytes) |
| `blindOpen` | JSON `{ messageHex, blindHex }` |
| `blindVerify` | Verify with hex opening fields |
| `blindVerifyBytes` | Verify with raw byte slices |

## `@lib-q/double-kem` — REMOVED

**Removed from the workspace and from all publish matrices.** The crate misimplemented its cited
construction (Maul, ePrint 2025/1755): its second KEM leg derived the shared secret from
transmitted wire bytes and the public `ek_b` alone, so the second decapsulation key was never
required by either party. It therefore delivered plain ML-KEM-768 security — no dual-key property —
at 1260 wire bytes where a single ML-KEM-768 ciphertext (`@lib-q/ml-kem`) delivers the same security
in 1088. Its only known consumer retracted the mode and permanently rejects its wire id. The paper's
construction itself is sound; this implementation of it was not, and it is deleted rather than
repaired. Do not use previously published `@lib-q/double-kem` / `lib-q-double-kem` artifacts (latest
0.0.7): treat anything derived through them as single-ML-KEM-768 security, never as two-key custody.
Use `@lib-q/ml-kem` instead; a faithful implementation of the paper may appear later as a new crate.

## `@lib-q/fhe` (since 0.0.7, EXPERIMENTAL_NON_NIST)

| JS name | Description |
|---------|-------------|
| `fheKeygen` | Deterministic key params JSON |
| `fheEncrypt` | Encrypt `Int32Array` plaintext |
| `fheEval` | Homomorphic op via tagged JSON (`addConstant`, `mulConstant`, `addCiphertext`) |
| `fheDecrypt` | Decrypt to `Int32Array` |
| `fheCiphertextToBytes` | Canonical ciphertext bytes |

## `@lib-q/threshold-kem` (since 0.0.7, PROVISIONAL)

Hybrid API: JSON for public artifacts, `Uint8Array` for secrets and wire blobs.

| JS name | Description |
|---------|-------------|
| `thresholdKemSetup` | Profile metadata JSON |
| `thresholdKemKeygenShares` | `{ publicKey, secretShares[] }` with `shareBytes` as `Uint8Array` |
| `thresholdKemEncap` | `{ sharedSecret, ciphertextHex, wire }` |
| `thresholdKemPartialDecap` | Partial share JSON |
| `thresholdKemCombineDecap` | Combined shared secret `Uint8Array` |
| `thresholdKemVerifyShare` | Share proof check |
| `thresholdKemEncodeWireV1` / `thresholdKemDecodeWireV1` | Canonical wire codec |

## `@lib-q/threshold-sig` — WITHDRAWN and REMOVED

**Not a signature scheme; provided no security.** `lib-q-threshold-sig`'s published verifying keys
were the private Shamir shares and its group key was the master secret recoverable from public
data, so its verifier authenticated nothing. The defect was structural, so the crate was withdrawn
in 0.0.10 (every entry point failing closed) and has since been deleted from the workspace.

There is no `@lib-q/threshold-sig` package on npm and no `lib-q-threshold-sig` crate on crates.io;
no version that ever existed was sound, so do not install one from history. The former exports
(`thresholdSigSetup`, `thresholdSigKeygenShares`, `thresholdSigSignRound1/2`,
`thresholdSigAggregate`, `thresholdSigVerify`, `thresholdSigIdentifyAbort`,
`thresholdSigEncodeWireV1` / `thresholdSigDecodeWireV1`) are listed here only so old call sites can
be identified and removed; the corresponding `ThresholdSig*` TypeScript shapes are gone from
`@lib-q/types`.

**Migrating:** the threshold-signature capability is provided by `@lib-q/threshold-raccoon`
(Rust: `lib-q-threshold-raccoon`), a lattice threshold signature with a stated hardness
assumption that consumes `lib-q-dkg` shares. It is not
wire-compatible — keys and signatures must be regenerated, and anything the old scheme "signed"
should be re-evaluated as unauthenticated.

## `@lib-q/types`

TypeScript-only (`index.d.ts`, `index.js`). No WASM. Shared interfaces for cross-package typings.

## Versioning

All packages share the workspace version on release — currently **0.0.10** (the single source of
truth is `version` under `[workspace.package]` in the root `Cargo.toml`). Pin in production:

```bash
npm install @lib-q/core@0.0.10 @lib-q/zkp@0.0.10
```

## Security

- NIST-oriented post-quantum asymmetric crypto only in published builds.
- Clear secret `Uint8Array` values in JS when done (`fill(0)`).
- Browser deployments: CSP compatible with WASM loading (see [wasm-security-model.md](wasm-security-model.md)).
- Subresource integrity: `integrity-manifest.json` in each WASM package (SHA-384).
