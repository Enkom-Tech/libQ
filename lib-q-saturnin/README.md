# lib-q-saturnin

Rust implementation of the Saturnin post-quantum symmetric algorithm suite.

Saturnin is the primary symmetric suite for HPKE/AEAD tiers in this workspace (see [`lib-q-hpke`](../lib-q-hpke), [`lib-q-aead`](../lib-q-aead)).

## Overview

Saturnin is a lightweight block cipher designed for post-quantum security. This implementation provides AEAD, block cipher, hash, and stream cipher modes.

## Usage

Add to `Cargo.toml`:

```toml
[dependencies]
lib-q-saturnin = "0.0.10"
```

### AEAD

```rust
use lib_q_saturnin::{
    Aead,
    AeadKey,
    Nonce,
    Result,
    SaturninAead,
};

fn main() -> Result<()> {
    let aead = SaturninAead::new();
    let key = AeadKey::new(vec![0u8; 32]);
    let nonce = Nonce::new(vec![0u8; 16]);

    let ciphertext = aead.encrypt(&key, &nonce, b"data", Some(b"ad"))?;
    let plaintext = aead.decrypt(&key, &nonce, &ciphertext, Some(b"ad"))?;
    assert_eq!(plaintext, b"data");
    Ok(())
}
```

### Saturnin-QCB (one-pass AEAD)

`SaturninQcb` is the one-pass, parallelizable AEAD from "An Update on Saturnin", built on the
Saturnin tweakable block cipher (`SaturninTbc` = `Saturnin16^d_{K⊕T}`). Message blocks use domain
9, the tag uses domain 10; each block is encrypted with a tweak binding the nonce and block index,
so encryption is rate-one and embarrassingly parallel.

```rust
use lib_q_saturnin::{
    Aead,
    AeadKey,
    Nonce,
    Result,
    SaturninQcb,
};

fn main() -> Result<()> {
    let aead = SaturninQcb::new();
    let key = AeadKey::new(vec![0u8; 32]);
    let nonce = Nonce::new(vec![0u8; 16]);

    let ciphertext = aead.encrypt(&key, &nonce, b"data", Some(b"ad"))?;
    let plaintext = aead.decrypt(&key, &nonce, &ciphertext, Some(b"ad"))?;
    assert_eq!(plaintext, b"data");
    Ok(())
}
```

> ⚠️ **Spec-faithful interpretation, not a byte-compatible reference.** The update note only gives
> a high-level description of Saturnin-QCB; the full mode lives in the separate QCB paper
> (`[BBC+20]`), and no official QCB known-answer tests are published. This implementation follows
> everything the note specifies and documents every gap-filling choice (padding, tweak encoding,
> AD folding) in the [`qcb` module docs](src/qcb.rs). It is verified by round-trip, tamper, and
> pinned self-consistency vectors — not by designer KATs. See [SECURITY.md](SECURITY.md).

### Hash

```rust
use lib_q_saturnin::{Result, SaturninHash};

fn main() -> Result<()> {
    let hash = SaturninHash::new();
    let output = hash.hash(b"data")?;
    assert_eq!(output.len(), 32);
    Ok(())
}
```

### Block Cipher

```rust
use lib_q_saturnin::{Result, SaturninBlockCipher};

fn main() -> Result<()> {
    let cipher = SaturninBlockCipher::new();
    let key = vec![0u8; 32];
    let block = vec![0u8; 32];
    let encrypted = cipher.encrypt_block(&key, &block)?;
    let decrypted = cipher.decrypt_block(&key, &encrypted)?;
    assert_eq!(decrypted, block);
    Ok(())
}
```

### Stream Cipher

```rust
use lib_q_saturnin::{Result, SaturninStream};

fn main() -> Result<()> {
    let stream = SaturninStream::new();
    let key = vec![0u8; 32];
    let nonce = vec![0u8; 16];
    let plaintext = b"Hello, World!";
    let ciphertext = stream.encrypt(&key, &nonce, plaintext)?;
    let decrypted = stream.decrypt(&key, &nonce, &ciphertext)?;
    assert_eq!(decrypted, plaintext);
    Ok(())
}
```

## Features

- `aead` - Authenticated encryption (default)
- `aead-short` — **Saturnin-Short** (spec section 2.3): single `Saturnin^6` block over `pad(nonce ‖ plaintext)`; fixed 32-byte ciphertext, no associated data, plaintext strictly under 128 bits. This is not CTR-Cascade (`aead`). Supports the update note's **shorter-nonce tweak** via `SaturninShortAead::with_nonce_len` (a shorter nonce frees room for longer plaintext: max plaintext = `31 - nonce_len` bytes).
- `qcb` — **Saturnin-QCB** (default): one-pass, parallelizable TBC-based AEAD from the update note. Exposes `SaturninQcb` and the reusable tweakable block cipher `SaturninTbc`. See the caveat above.
- `block-cipher` - Block cipher operations
- `hash` - Hash function
- `stream` - Stream cipher
- `zeroize` - Secure memory zeroization

### Performance features

- `simd` enables runtime SIMD dispatch.
- `simd-avx2` enables AVX2 backend support on `x86_64` (runtime detected).
- `simd-neon` enables NEON backend support on `aarch64` (runtime detected).
- `parallel` enables multi-block parallel helpers on non-WASM targets.

Scalar `core` and `bs32_core` remain the audited reference implementations. SIMD paths are optimized implementations that must remain byte-for-byte equivalent to scalar outputs.

### WebAssembly

The crate builds for `wasm32-unknown-unknown`. Enable the `wasm` feature so that the `getrandom` dependency (via lib-q-core) compiles with `wasm_js`; otherwise the build will fail on that target. The `parallel` feature is not available on `wasm32` (the module is omitted on that target).

Example: `cargo build --target wasm32-unknown-unknown --features wasm`

## Security

- 256-bit post-quantum security
- Constant-time operations; AEAD tag verification uses constant-time comparison (see [SECURITY.md](SECURITY.md)).
- **No masked or threshold implementation.** Saturnin has no published DPA- or fault-resistant
  implementation and this crate does not provide one. Do not read "constant-time" as covering
  power or EM side channels — it does not.
- Validated against the designers' NIST LWC submission: the scalar core reproduces their generated
  hash, CTR-Cascade and Short KAT vectors. The AVX2 and NEON backends have **not** been compared
  against that reference — see [docs/HARDWARE.md](docs/HARDWARE.md) §6.

## Implementing Saturnin in hardware

[docs/HARDWARE.md](docs/HARDWARE.md) collects what building this twice taught us: the one-core /
one-datapath property and its evidence, why the round constants must be generated rather than
ROMed, the RC packing convention written as normative prose, the fact that the S-box and MDS are
**not** involutions (so an inverse datapath is real area), and a catalogue of the four defects that
survived a green test suite here.

## Performance

Typical throughput on modern hardware:
- AEAD: ~200-400 MB/s
- Hash: ~400-600 MB/s
- Block cipher: ~150-300 MB/s
- Stream cipher: ~250-450 MB/s

## Testing

```bash
cargo test --all-features
cargo bench
```

### SIMD validation matrix

```bash
# Scalar reference path
cargo test -p lib-q-saturnin --features "alloc,aead,aead-short,block-cipher,hash,stream"

# AVX2-enabled path (x86_64)
cargo test -p lib-q-saturnin --features "alloc,aead,aead-short,block-cipher,hash,stream,simd-avx2"

# NEON-enabled path (aarch64)
cargo test -p lib-q-saturnin --features "alloc,aead,aead-short,block-cipher,hash,stream,simd-neon"
```

### Benchmark protocol

- Run on an otherwise idle machine with fixed CPU frequency governor when possible.
- Collect scalar baseline first, then collect SIMD-enabled results on the same machine.
- Use identical workload sizes and warmup/sample settings for all runs.
- Report bytes/second and relative speedup (`simd / scalar`) for each workload.

Recommended commands:

```bash
# Scalar baseline
cargo bench -p lib-q-saturnin --features "alloc,aead,block-cipher,hash,stream"

# AVX2 benchmark run
cargo bench -p lib-q-saturnin --features "alloc,aead,block-cipher,hash,stream,simd-avx2"
```

### Performance acceptance gates

When evaluating SIMD changes, use these minimum expected speedups against scalar baseline on the same host:

- Hash throughput: `>= 1.30x`
- Stream throughput: `>= 1.25x`
- Block single-block encryption: `>= 1.05x`

If a change does not meet these thresholds, keep it behind feature gates until further optimization or analysis is completed.

## License

See the main [lib-q license](../LICENSE).

## Contributing

See the main [lib-q contributing guide](../CONTRIBUTING.md).

## Key commitment (CMT-1)

**No libQ AEAD is key-committing, and none of them claims to be.** CMT-1 asks whether one
ciphertext can be made to decrypt successfully under two *distinct* keys, with the nonce and
associated data free on each side. That property is not part of the AEAD security goal these modes
were designed for, and libQ does not provide it.

**Do not use any libQ AEAD for multi-recipient encryption, key wrapping / envelope encryption, or
password-based decryption as an identification or authorization signal without binding the key
externally** — e.g. put `H(key ‖ context)` in the associated data, or carry an explicit key
commitment beside the ciphertext (`lib-q-mve` does the latter: see `MVE_COMMIT_LABEL`).

Two modes have a **demonstrated** break: a test produces one ciphertext that decrypts successfully
under two distinct keys. For the other seven a bounded search found nothing, which is **not**
evidence that they commit — read the box under the table before quoting any row of it.

| Mode | Key / tag | CMT-1 status |
|---|---|---|
| `SaturninQcb` | 256 / 256-bit | **BROKEN.** Cheap search then closed-form algebra. Measured over 200 independent key pairs, all of which broke: mean **249** padding-search tries ≈ **~500 Saturnin block calls** (median 201, min 1, max 1316), and **0** searches of the 256-bit tag. Cause: associated data enters the tag by plain XOR through a public keyed permutation, so side 2's associated data is *solved*, not searched. |
| `SaturninShortAead` | 256-bit / no tag | **BROKEN.** ~2^8 random keys at any nonce length, including the 16-byte default — the nonce *is* the redundancy and CMT-1 lets the adversary choose it. Measured acceptance **78 / 20 000** random keys (0.0039, predicted 2^-8). |
| `SaturninAead` (CTR-Cascade) | 256 / 256-bit | no cheap break found — **not shown to commit** |
| `Shake256Aead` | 256 / 256-bit | no cheap break found — **not shown to commit** |
| `DuplexSpongeAead` | 256 / 256-bit | no cheap break found — **not shown to commit** |
| `TweakAead` | 256 / 256-bit | no cheap break found — **not shown to commit**. Its tag is a sponge hash of `key ‖ nonce ‖ ad ‖ ct`, which is the *shape* a committing mode has; that is an argument for looking here first, not a result. |
| `RoccaSAead` | 256 / 256-bit | no cheap break found — **not shown to commit** |
| `RomulusN` / `RomulusM` | 128 / **128-bit** | no cheap break found — **not shown to commit**. With a 128-bit tag the *generic* CMT-1 cost is only ~2^64, the weakest margin in the set. |

> **The "no cheap break found" rows are not evidence of key commitment and must never be quoted as
> if they were.** Each comes from 20 000 random `(key, nonce, associated-data)` trials against a
> fixed ciphertext. Against a 256-bit tag the expected yield of that search is ~2^-242 hits, so it
> returns zero *whether or not* the mode commits — and it would return zero just the same against
> a mode with a 2^40 structural break the search does not model. All those rows rule out is the
> class of break the two Saturnin modes fell into: one cheap enough for ~2^14 trials to stumble
> onto.
>
> Demonstrating the positive — that a mode *is* committing — is not achievable by search at these
> tag sizes at all, however many trials are run. It needs a proof, or a committing transform (bind
> `H(key ‖ nonce ‖ associated data)` into the tag) that changes the construction. libQ has neither,
> which is why no row above reads "committing".

Reproduce (each prints its own measurements with `--nocapture`):

```sh
# the two breaks, and the measured QCB attack cost
cargo test -p lib-q-saturnin --test key_commitment -- --nocapture
cargo test -p lib-q-saturnin --features aead-short --lib key_commitment_tests -- --nocapture
# the bounded searches for the registry modes
cargo test -p lib-q-aead \
  --features "saturnin,duplex-sponge-aead,tweak-aead,romulus-n,romulus-m,rocca-s" \
  --test key_commitment -- --nocapture
```

Sources: `lib-q-saturnin/tests/key_commitment.rs`, `lib-q-saturnin/src/aead_short.rs`
(`key_commitment_tests`), `lib-q-aead/tests/key_commitment.rs`. Card `t_16ddf21c`.

### Nonce extension (XChaCha-style) — evaluated and deliberately not pursued

Every libQ AEAD uses a **128-bit nonce**. XChaCha20-Poly1305 exists to stretch a 96-bit nonce to
192 bits so that *random* nonces stop colliding around 2^32 messages per key; at 128 bits the
birthday bound is already 2^64, beyond any realistic message volume. Nonce extension therefore buys
nothing here and is not planned — please do not re-raise it. The adjacent gap that *is* real is key
and context commitment, above.

### Saturnin specifics — who actually gets the broken modes

`SaturninQcb` and `SaturninShortAead` are the two modes with a **demonstrated** break, both proven
by tests in this crate. Their exposure is **not** symmetric:

- **`aead-short` is opt-in.** `SaturninShortAead` is compiled only if you ask for it
  (`Cargo.toml:27`; not in `default`).
- **`qcb` is a DEFAULT feature** (`Cargo.toml:21`: `default = ["std", "aead", "block-cipher",
  "hash", "stream", "qcb", "alloc"]`). Any crate that depends on `lib-q-saturnin` without
  `default-features = false` compiles `SaturninQcb` and can call it — no opt-in required. Inside
  this workspace that is `lib-q-aead` (`Cargo.toml:24`) and `lib-q-hpke` (`Cargo.toml:45`), both of
  which omit `default-features = false`; `cargo tree -p lib-q-aead --features saturnin -e features`
  lists `lib-q-saturnin feature "qcb"`. (Neither crate re-exports the type, so the mode is compiled
  but not reachable through their APIs.) `lib-q-random` (`Cargo.toml:28`) and GIP's
  `sdk/Cargo.toml:197` do pass `default-features = false` and are unaffected.

**A decision on whether `qcb` should remain a default feature is open with the maintainers and has
not been made** — the options on the table are deprecating the mode, moving it behind a non-default
feature (a semver-visible change for anyone relying on the default set), or leaving the default and
documenting the break, which is what this README currently does.
