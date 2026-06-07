# lib-q-mac

Quantum Carter-Wegman MAC (qCW-MAC) targeting **splitting unforgeability (SU)** against quantum adversaries (Boneh-Zhandry, ePrint 2026/271).

## Security target

| Property | Status |
|----------|--------|
| SU stability (bounded queries) | Property tests in `tests/su_properties.rs` |
| SU exclusiveness (bounded queries) | Property tests in `tests/su_properties.rs` |
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
