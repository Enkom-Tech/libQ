# lib-q-mac (EXPERIMENTAL_NON_NIST)

> **EXPERIMENTAL_NON_NIST — pre-standard.** qCW-MAC is **not** a NIST-standardized MAC. NIST's
> approved message authentication codes are HMAC (FIPS 198-1), KMAC (SP 800-185), CMAC and GMAC
> (SP 800-38B / 38D); this crate implements none of them. The construction follows a recent research
> paper (Boneh–Zhandry, ePrint 2026/271) and has **not** been audited or reviewed by a human
> cryptographer. Use `lib-q-hash`'s KMAC/HMAC paths where a standardized MAC is required.

Quantum Carter-Wegman MAC (qCW-MAC) targeting **splitting unforgeability (SU)** against quantum adversaries (Boneh-Zhandry, ePrint 2026/271).

## Security target

The SU rows below record **what is tested**, not what is proven. Property tests over bounded query
counts are evidence against regressions; they are not a security proof, and no proof of SU for this
implementation has been reviewed.

| Property | Status |
|----------|--------|
| SU stability (bounded queries) | Property tests in `tests/su_properties.rs` — tested, not proven |
| SU exclusiveness (bounded queries) | Property tests in `tests/su_properties.rs` — tested, not proven |
| Wire budget | N/A (definitional primitive) |

## API

- `QcwMacKey::generate`
- `QcwMac::sign`
- `QcwMac::verify`

## KAT export

Schema: `qcw-mac-kat-v1`

```bash
cargo test -p lib-q-mac kat_regenerate_vectors -- --ignored
```

Output: `tests/vectors/qcw-mac-v1.json`

## Features

| Feature | Default | Purpose |
|---------|:-------:|---------|
| `alloc` | yes | Heap-backed tag buffers |
| `std` | no | Standard library RNG |
| `random` | no | Secure key generation |
