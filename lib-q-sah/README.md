# lib-q-sah

Stream-AEAD-H (S-A-H) — the high-throughput, **nonce-sensitive** AEAD for
capable GIP nodes. Canonical, deployable implementation of the primitive defined
in `GIP-SPEC/spec/crypto/sah/sah.md`.

This crate implements **S-A-H-256** (256-bit key, 128-bit nonce, 128-bit tag).
S-A-H-512 is future work.

## Status

> **DRAFT — do not deploy.** Spec version `0.2.0`: round constants, rotations,
> and the S-box are provisional placeholders carrying no security claim. The
> primitive must pass the research-track freeze gates (cryptanalysis,
> constant-time S-box, external review) before a `frozen` v1.0.0 profile.

## Role in the libQ AEAD landscape

| AEAD | Role |
|---|---|
| Saturnin | conservative mandatory baseline |
| duplex-sponge | Keccak-family option |
| Romulus-M1 | constrained-friendly, misuse-resistant |
| **S-A-H** | **high-throughput, nonce-sensitive** |

## API

```rust
use lib_q_sah::{Sah256, Sah256Key, Sah256Nonce};

let key = Sah256Key::new([0u8; 32]);     // from the active suite KDF
let nonce = Sah256Nonce::new([0u8; 16]); // unique per (key, direction)

let sealed = Sah256::seal(&key, &nonce, b"header", b"payload")?;  // ct || tag
let opened = Sah256::open(&key, &nonce, b"header", &sealed)?;
assert_eq!(opened, b"payload");

// Detached, no_std / no-alloc:
let mut ct = [0u8; 7];
let tag = Sah256::seal_detached(&key, &nonce, b"header", b"payload", &mut ct)?;
let mut pt = [0u8; 7];
Sah256::open_detached(&key, &nonce, b"header", &ct, &tag, &mut pt)?;
# Ok::<(), lib_q_sah::SahError>(())
```

`#![no_std]`, `#![forbid(unsafe_code)]`. The combined `seal`/`open` require the
`alloc` feature; the detached API does not allocate.

## Nonce model — read before use

S-A-H is **not** misuse-resistant. Nonce uniqueness per `(key, direction)` MUST
be enforced at the integration boundary (a monotone record counter, rekey before
exhaustion). Nonce reuse leaks the XOR of plaintexts and degrades integrity. For
uniqueness-uncertain contexts use Romulus-M1. See `SECURITY.md`.

## Cross-validation

KATs (`tests/kat_tests.rs`) are the canonical vectors emitted by the Zig research
harness (`sah-research/`). Rust and Zig are independent implementations of the
same spec; passing these proves they agree. `tests/spec_pin.rs` asserts the
compiled-in constants equal the vendored profile JSON.

```sh
cargo test -p lib-q-sah
```

## Integration

The GIP SDK does **not** depend on this crate directly. S-A-H is exposed through
`lib-q-aead`'s suite registry (`lib-q-aead/src/sah.rs`, implementing
`lib_q_core::Aead` + `AeadWithMetadata` + `AeadPlugin`) and consumed via normal
cryptosuite plumbing. See `PLAN.md` Part 5.
