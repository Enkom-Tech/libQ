# lib-q-hqc

Post-quantum HQC (Hamming Quasi-Cyclic) KEM implementation for libQ.

Enable from the KEM façade with **`hqc`** on [`lib-q-kem`](../lib-q-kem).

## Overview

Pure-Rust HQC KEM for parameter sets HQC-128, HQC-192, and HQC-256 (internal names
HQC-1, HQC-3, HQC-5). The crate follows libQ provider patterns, supports `no_std` and
WASM, and offers optional AVX2 acceleration with portable fallback.

## Implementation status

**Not production-ready.** Core modules (Reed–Solomon, Reed–Muller, concatenated code,
PKE, KEM, SHAKE256 PRNG) are implemented and covered by tests. Randomized
encrypt/decrypt and encapsulate/decapsulate round-trips are verified across all
parameter sets (portable and AVX2 paths). Remaining blockers are full NIST KEM KAT
conformance and independent side-channel evaluation — see
[docs/audit-package/README.md](docs/audit-package/README.md) for verified facts and open
findings. Do not deploy for confidentiality guarantees until those findings are closed.

## Security levels

Object sizes match [`lib-q-types::hqc`](../lib-q-types/src/hqc.rs) (workspace source of
truth for wire lengths):

| Algorithm | Security | Public key | Secret key | Ciphertext | Shared secret |
|-----------|----------|------------|------------|------------|---------------|
| HQC-128   | 128 bits | 2,241 B    | 2,337 B    | 4,433 B    | 32 B          |
| HQC-192   | 192 bits | 4,522 B    | 4,618 B    | 8,978 B    | 32 B          |
| HQC-256   | 256 bits | 7,245 B    | 7,341 B    | 14,421 B   | 32 B          |

Secret key layout: `ek_pke` ‖ `dk_pke` (32) ‖ `sigma` (16) ‖ `seed_kem` (48).

## Features

- Three parameter sets: `hqc128`, `hqc192`, `hqc256` (or `hqc` for all)
- libQ provider integration and typed key/ciphertext wrappers
- `zeroize` for sensitive buffers; `no_std` and `wasm` targets
- Pure Rust (no C/FFI); BearSSL-compatible and standard AES DRBG backends
- Optional `simd-avx2` (runtime detection, bit-exact portable fallback)

## Architecture

| Module | Role |
|--------|------|
| `hqc_kem` | KEM encapsulation / decapsulation |
| `hqc_pke` | Public-key encryption layer |
| `params_correct` | Parameter sets HQC-1 / HQC-3 / HQC-5 |
| `concatenated_code` | Reed–Solomon + Reed–Muller concatenated code |
| `reed_solomon`, `reed_muller` | Constituent codes |
| `internal` | Polynomial / vector primitives, SHAKE256 |
| `provider` | libQ KEM provider |

Optional KAT DRBG backends (not enabled by default): `kat-drbg` / `bearssl-aes` (reference-compatible) and `aes-drbg` (pure Rust NIST CTR_DRBG). Production RNG uses `lib-q-random` via the `random` feature.

See [SIMD architecture](docs/simd-architecture.md) and [vector operations](docs/vector-operations.md).

## Usage

```rust
use lib_q_random::LibQRng;
use lib_q_hqc::hqc_core_impl::*;

let mut rng = LibQRng::new_deterministic([42u8; 32]);
let keypair = Hqc128CoreImpl::generate_keypair(&mut rng);

let (ciphertext, shared_secret1) = Hqc128CoreImpl::encapsulate(&keypair.public_key, &mut rng)
    .expect("encapsulation");
let shared_secret2 = Hqc128CoreImpl::decapsulate(&keypair.secret_key, &ciphertext)
    .expect("decapsulation");

assert_eq!(shared_secret1.as_slice(), shared_secret2.as_slice());
```

Integration tests exercise KEM round-trips with both pinned seeds (for reproducible
shared-secret comparison) and many varied keypairs across all parameter sets
(`test_kem_roundtrip_varied_keys_all_params`).

## Testing

```bash
cargo test -p lib-q-hqc --features alloc,hqc
cargo test -p lib-q-hqc --test integration_test --features alloc,hqc128
cargo test -p lib-q-hqc --features "simd-avx2,alloc,hqc128" --test simd_correctness
```

See [tests/README.md](tests/README.md) for the test layout. Diagnostic and historical
debug tests live under `tests/archive/`.

## SIMD (AVX2)

```bash
cargo build --release -p lib-q-hqc --features simd-avx2
cargo bench -p lib-q-hqc --features "simd-avx2,alloc,hqc128" --bench simd_benchmarks
```

Requires x86_64 with AVX2; falls back to portable code when unavailable.

## Known limitations

Documented in [SECURITY.md](SECURITY.md) and [docs/audit-package/README.md](docs/audit-package/README.md):

- No independent side-channel evaluation; constant-time discipline in source only.
- Full NIST KEM KAT conformance is not yet established by a non-ignored test suite.

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities via the workspace
[SECURITY.md](../SECURITY.md) policy.

## License

Same terms as the main libQ workspace.
