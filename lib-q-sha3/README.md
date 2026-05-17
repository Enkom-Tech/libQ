# lib-q-sha3

NIST-aligned **SHA-3** (FIPS 202), **SHAKE**, **cSHAKE** (SP 800-185), and **TurboSHAKE** (12-round Keccak as in [RFC 9861](https://www.rfc-editor.org/rfc/rfc9861.html) KangarooTwelve) for **lib-Q**. Pre–FIPS **raw Keccak** fixed digests (`Keccak224` … `Keccak512`, `Keccak256Full`) are in the separate crate [`lib-q-keccak-digest`](https://github.com/Enkom-Tech/libQ/tree/main/lib-q-keccak-digest) (see [ADR 001](https://github.com/Enkom-Tech/libQ/blob/main/lib-q-sha3/docs/adr/001-keccak-nonfips-surface.md)).

- **Repository:** <https://github.com/Enkom-Tech/libQ>
- **API reference:** <https://docs.rs/lib-q-sha3>
- **Related crates:** [`lib-q-keccak`](https://github.com/Enkom-Tech/libQ/tree/main/lib-q-keccak) (Keccak-`p` permutation), [`lib-q-k12`](https://github.com/Enkom-Tech/libQ/tree/main/lib-q-k12) (KangarooTwelve), [`lib-q-keccak-digest`](https://github.com/Enkom-Tech/libQ/tree/main/lib-q-keccak-digest) (raw Keccak / non–FIPS-202 digests)

## Algorithms

| Family | Types (crate root) | Normative reference |
|--------|-------------------|----------------------|
| SHA-3 (224–512) | `Sha3_224` … `Sha3_512` | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) |
| SHAKE XOF | `Shake128`, `Shake256` + readers | FIPS 202 |
| cSHAKE XOF | `CShake128`, `CShake256` + readers | [SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final) |
| TurboSHAKE XOF | `TurboShake128<DS>`, `TurboShake256<DS>` (domain byte `DS`) | IRTF / RFC 9861 (K12); collision strength in type impls |
| Raw Keccak (not this crate) | `Keccak224` … / `Keccak256Full` | See [`lib-q-keccak-digest`](https://github.com/Enkom-Tech/libQ/tree/main/lib-q-keccak-digest) (pre-FIPS padding; not interoperable with SHA-3) |

## Which traits to use

- **Fixed-length digest** (`SHA3-*`): implement [`Digest`](https://docs.rs/digest/latest/digest/trait.Digest.html) — `update`, `finalize` into a fixed `Output`.
- **XOFs** (`SHAKE`, `cSHAKE`, `TurboSHAKE`): do **not** use `Digest`. Use [`Update`](https://docs.rs/digest/latest/digest/trait.Update.html), [`ExtendableOutput`](https://docs.rs/digest/latest/digest/trait.ExtendableOutput.html) (or `ExtendableOutputReset` where implemented), and [`XofReader`](https://docs.rs/digest/latest/digest/trait.XofReader.html). These traits are re-exported at the crate root (`use lib_q_sha3::{Update, ExtendableOutput, XofReader}`). If you also import [`Digest`](https://docs.rs/digest/latest/digest/trait.Digest.html) in the same module, qualify [`Digest::update`](https://docs.rs/digest/latest/digest/trait.Digest.html#tymethod.update) or [`Update::update`](https://docs.rs/digest/latest/digest/trait.Update.html#tymethod.update) to avoid method-name ambiguity.
- **cSHAKE customization only** (NIST “S” string, empty function name): [`CustomizedInit::new_customized`](https://docs.rs/digest/latest/digest/trait.CustomizedInit.html) or the `CShake*` constructors.

`Digest` is not implemented for XOFs by design (the `digest` crate splits fixed vs extendable output APIs).

## Prelude

This crate **does not** provide a `prelude` module. Imports are kept explicit so security reviews can see exactly which algorithms and traits are in scope. Use the re-exports documented below or `use lib_q_sha3::digest::{...}` for additional `digest` traits.

## Feature flags

| Feature | Effect |
|---------|--------|
| `alloc` (default) | Enables `digest/alloc` (e.g. `finalize_boxed` on XOFs where applicable). |
| `oid` (default) | OID support for fixed-output types where defined. |
| `zeroize` | Zeroizes dropped sponge state for supported types (see `digest` + this crate’s `ZeroizeOnDrop` impls). |
| `asm` | ARMv8 Keccak acceleration via `lib-q-keccak` (not all targets). |

`no_std`: supported with `default-features = false`; you may need to disable `alloc` for the leanest build.

## Security

- **Output length (XOF):** security depends on how many bytes you read; use enough bytes for your collision and preimage profile (see FIPS 202 / SP 800-185 and `CollisionResistance` on each type in rustdoc).
- **cSHAKE:** use distinct function-name and/or customization strings for distinct protocols: both empty degrades to SHAKE (SP 800-185).
- **TurboSHAKE:** the const generic `DS` (domain separator, `0x01`–`0x7F`) must differ across independent uses to avoid cross-protocol output collisions (see RFC 9861 / Turbot documentation).
- **SHA3-256 vs SHA-256:** `Sha3_256` and [`sha3_256`](https://docs.rs/lib-q-sha3/latest/lib_q_sha3/fn.sha3_256.html) are **FIPS 202 SHA3-256** (Keccak sponge with SHA-3 padding). They are not FIPS 180-4 SHA-256 (Merkle–Damgård); outputs and wire formats differ.
- **Keccak vs SHA-3:** use [`lib-q-keccak-digest`](https://github.com/Enkom-Tech/libQ/tree/main/lib-q-keccak-digest) for pre-FIPS `Keccak256` types; they are **different** from `Sha3_256` (different padding).
- **Implementation status:** the code targets **correct** sponge semantics per the referenced standards. Constant-time or side-channel **guarantees** are not claimed here unless supported by your platform and analysis.
- **Architecture:** whether to split non–FIPS-202 Keccak surfaces is recorded in [docs/adr/001-keccak-nonfips-surface.md](https://github.com/Enkom-Tech/libQ/blob/main/lib-q-sha3/docs/adr/001-keccak-nonfips-surface.md).

## Examples

### SHA3-256 (`Digest`)

```rust
use hex_literal::hex;
use lib_q_sha3::{Digest, Sha3_256};

let mut hasher = Sha3_256::new();
hasher.update(b"abc");
let hash = hasher.finalize();
assert_eq!(hash, hex!("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));
```

### One-shot SHA3-256

For a single input slice, [`sha3_256`](https://docs.rs/lib-q-sha3/latest/lib_q_sha3/fn.sha3_256.html) hashes in one call. This is **SHA3-256** (FIPS 202); it is **not** SHA-256 (FIPS 180). Prefer [`Sha3_256`](https://docs.rs/lib-q-sha3/latest/lib_q_sha3/struct.Sha3_256.html) with [`Digest`](https://docs.rs/digest/latest/digest/trait.Digest.html) when you need incremental updates or state serialization.

```rust
use hex_literal::hex;
use lib_q_sha3::sha3_256;

let digest = sha3_256(b"abc");
assert_eq!(digest, hex!("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));
```

### SHAKE128 (XOF)

```rust
use hex_literal::hex;
use lib_q_sha3::{ExtendableOutput, Shake128, Update, XofReader};

let mut hasher = Shake128::default();
hasher.update(b"abc");
let mut reader = hasher.finalize_xof();
let mut buf = [0u8; 10];
reader.read(&mut buf);
assert_eq!(buf, hex!("5881092dd818bf5cf8a3"));
```

### cSHAKE256 with customization

```rust
use lib_q_sha3::{CShake256, CustomizedInit, ExtendableOutput, Update, XofReader};

let mut h = CShake256::new_customized(b"my application");
h.update(b"message");
let mut out = [0u8; 64];
h.finalize_xof().read(&mut out);
```

### TurboSHAKE128 with domain byte (RFC 9861 style)

```rust
use lib_q_sha3::{ExtendableOutput, TurboShake128, Update, XofReader};

const D: u8 = 0x07; // distinct per protocol; see RFC 9861
let mut h = TurboShake128::<D>::default();
h.update(b"data");
let mut out = [0u8; 32];
h.finalize_xof().read(&mut out);
```

## License

Licensed under **Apache License, Version 2.0**; see the [workspace `LICENSE` file](https://github.com/Enkom-Tech/libQ/blob/main/LICENSE).

[SHA-3]: https://en.wikipedia.org/wiki/SHA-3
[SHA-3 Derived Functions]: https://csrc.nist.gov/pubs/sp/800/185/final
