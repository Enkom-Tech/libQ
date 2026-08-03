# lib-q-aead

A high-performance, quantum-resistant Authenticated Encryption with Associated Data (AEAD) library for Rust, designed for the libQ cryptographic ecosystem.

## Overview

lib-q-aead provides AEAD implementations chosen for large-state, quantum-resistant security margins. The library emphasizes security-first design with constant-time primitives where implemented and robust input validation.

> **None of these AEAD modes is NIST-approved.** NIST's approved AEADs are AES-GCM and AES-CCM
> (SP 800-38D / SP 800-38C) and Ascon (SP 800-232); this crate ships none of them. Of the seven
> modes registered here, **Saturnin** and **Romulus** were NIST Lightweight Cryptography candidates
> that were **not selected** (Ascon won), **Rocca-S** is an IETF draft (`draft-nakano-rocca-s`), and
> the **SHAKE256**, **duplex-sponge**, and **tweakable-CTR** modes are libQ constructions over the
> FIPS 202 Keccak-f[1600] permutation. The *permutation* is NIST-standardized in those three cases;
> the *AEAD mode built on it* is not. Treat every algorithm here as pre-standard for compliance
> purposes.

## Features

- **Large-state symmetric security**: 256-bit keys and 256-bit tags, chosen for margin against Grover-style key search — **except Romulus-N/M, which are 128-bit in both** (measured: `cargo test -p lib-q-aead --features romulus-n,romulus-m --test nonce_misuse all_registry_aeads_take_a_128_bit_nonce -- --nocapture` prints `RomulusNAead: key 16 B, nonce 16 B, tag 16 B`)
- **Security-First**: Constant-time primitives and robust input validation
- **High Performance**: Optimized implementations with minimal overhead
- **Modular Design**: Pluggable architecture supporting multiple algorithms
- **No-Std Support**: Works in embedded and no-std environments

Read [Key commitment (CMT-1)](#key-commitment-cmt-1) below before using any mode for key wrapping,
envelope encryption, or multi-recipient encryption — these AEADs are **not** key-committing.

## Supported Algorithms

### SHAKE256 AEAD
- **Algorithm**: SHAKE256-based AEAD construction
- **Security Level**: 128-bit post-quantum security
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 128 bits (16 bytes)
- **Tag Size**: 256 bits (32 bytes)

### Saturnin AEAD
- **Algorithm**: Saturnin block cipher in AEAD mode
- **Security Level**: 128-bit post-quantum security
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 128 bits (16 bytes)
- **Tag Size**: 256 bits (32 bytes) (full Saturnin AEAD; matches `lib-q-saturnin::SaturninAead`)

### Semantic decrypt (Layer B)

Factory-returned handles use the **Layer A** `decrypt` → `Result` path via `lib-q-core` traits and contexts. The concrete registry types in this crate (`SaturninAead`, `Shake256Aead`, `DuplexSpongeAead`, `TweakAead`, `RomulusNAead`, `RomulusMAead`) implement `lib_q_core::AeadDecryptSemantic` where the underlying algorithm does—call `decrypt_semantic` on those **concrete** types (not on `Box<dyn AeadWithMetadata>`). **Discoverability:** `AeadMetadata::supports_semantic_decrypt` and `AeadWithMetadata::supports_semantic_decrypt` report whether Layer B is available for the canonical algorithm row; registry test stubs override the trait method to `false` (see `docs/adr/003-aead-decrypt-layers.md`). **Test-only** `MockAead` in `plugin.rs` tests is Layer A + metadata only.

## Quick Start

### Basic Usage

```rust
use lib_q_aead::{create_aead, Algorithm, AeadKey, Nonce};

// Create an AEAD instance
let aead = create_aead(Algorithm::Shake256Aead)?;

// Generate or load your key and nonce
let key = AeadKey::new(vec![0x01; 32]); // In practice, use secure random generation
let nonce = Nonce::new(vec![0x02; 16]); // In practice, use secure random generation

// Your data to encrypt
let plaintext = b"Hello, World!";
let associated_data = b"metadata";

// Encrypt
let ciphertext = aead.encrypt(&key, &nonce, plaintext, Some(associated_data))?;

// Decrypt
let decrypted = aead.decrypt(&key, &nonce, &ciphertext, Some(associated_data))?;

assert_eq!(decrypted, plaintext);
```

### Advanced Usage with Security Configuration

```rust
use lib_q_aead::{
    create_aead, Algorithm, AeadKey, Nonce,
    security::{SecurityConfig, SecurityContext}
};

// Create AEAD with custom security configuration
let aead = create_aead(Algorithm::Shake256Aead)?;

// Configure security settings
let security_config = SecurityConfig::strict();
let security_ctx = SecurityContext::with_config(security_config);

// Security context can be used to track operation metadata
let key = AeadKey::new(secure_random_bytes(32));
let nonce = Nonce::new(secure_random_bytes(16));

let ciphertext = aead.encrypt(&key, &nonce, plaintext, Some(associated_data))?;
```

## Security Features

### Constant-Time Operation Wrapper

The `timing` module enforces a fixed wall-clock duration for wrapped operations, preventing timing side-channels from leaking information about internal control flow. The wrapper uses `compiler_fence(SeqCst)` and `core::hint::black_box` to prevent the compiler from eliding the busy-wait or reordering results past the timing barrier.

```rust
use lib_q_aead::security::timing::{TimingProtection, protect_timing};

// Wrap an operation so it always takes at least target_duration_ns
let result = protect_timing(|| {
    perform_sensitive_operation()
})?;

// Custom target duration (5 µs)
let timing_protection = TimingProtection::strict();
let result = timing_protection.protect(|| {
    perform_sensitive_operation()
})?;
```

### Constant-Time Operations

All critical operations are implemented in constant time:

```rust
use lib_q_aead::security::constant_time::constant_time_eq;

// Secure comparison
let is_equal = constant_time_eq(&tag1, &tag2);

// Secure selection
let result = constant_time_select(condition, &value1, &value2);
```

### Input Validation

Comprehensive input validation prevents common security issues:

```rust
use lib_q_aead::security::validation::{validate_key, validate_nonce};

// Validate key material
validate_key(key_bytes)?;

// Validate nonce
validate_nonce(nonce_bytes)?;
```

## Performance

The library is optimized for high performance while maintaining security:

- **SHAKE256 AEAD**: ~2-5μs per operation (typical)
- **Saturnin AEAD**: ~1-3μs per operation (typical)
- **Memory Usage**: Minimal stack allocation with secure cleanup
- **Constant-Time Wrapper**: Fixed wall-clock overhead per protected call

## Feature Flags

- `shake256`: Enable SHAKE256 AEAD implementation (default)
- `saturnin`: Enable Saturnin AEAD implementation
- `std`: Enable standard library features (default)
- `no-std`: Disable standard library for embedded environments

## Security Considerations

### Key Management
- Always use cryptographically secure random number generation for keys
- Never reuse keys across different contexts
- Implement proper key rotation policies

### Nonce Management
- Never reuse nonces with the same key
- Use cryptographically secure random number generation for nonces
- Consider using counter-based nonces for high-throughput scenarios

### Timing Attacks
- The `TimingProtection` wrapper enforces a fixed wall-clock duration per call, preventing timing side-channels at the API boundary
- Set `target_duration_ns` above the worst-case execution time of the wrapped operation
- Constant-time algorithmic behavior (e.g. constant-time comparisons via `subtle`) is still required at the primitive level

## Examples

See the `examples/` directory for comprehensive usage examples:

- `basic_usage.rs`: Basic encryption/decryption
- `security_features.rs`: Advanced security features
- `performance_benchmarks.rs`: Performance testing
- `no_std_example.rs`: Embedded usage

## Testing

The library includes comprehensive tests:

```bash
# Run all tests
cargo test

# Run security tests
cargo test --test comprehensive_security_tests

# Run performance benchmarks
cargo bench
```

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Security

For security issues, please see the main libQ repository's security policy.

## Workspace

Exposes Saturnin and SHAKE-based AEAD integrations for [`lib-q-hpke`](../lib-q-hpke) and the umbrella stack. See the [workspace README](../README.md) for the full crate graph.

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

**Neither broken mode is reachable through this crate.** `lib-q-aead`'s registry exposes
`Shake256Aead`, `SaturninAead`, `DuplexSpongeAead`, `TweakAead`, `RomulusNAead`, `RomulusMAead` and
`RoccaSAead` — it never re-exports `SaturninQcb` or `SaturninShortAead` (verified: `rg -n "Qcb|qcb"
lib-q-aead/src` returns nothing, while `rg -c "Saturnin" lib-q-aead/src` matches six files). Reaching
either break requires depending on `lib-q-saturnin` directly; the table covers them because they are
part of the same suite and the two rows are the only *demonstrated* results in it.

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
