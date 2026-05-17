# lib-q-ml-dsa

Rust implementation of **ML-DSA** (Module-Lattice Digital Signature Algorithm), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), for all three parameter sets: ML-DSA-44, ML-DSA-65, and ML-DSA-87.

Ring arithmetic and NTT live in the shared workspace crate [**lib-q-ring**](../lib-q-ring) (`R_q = Z_q[X]/(X^{256}+1)` at `q = 8_380_417`). This crate wires FIPS 204 logic, SIMD paths, serialization, and optional hardening.

## Verification

Parts of the portable and AVX2 field/NTT and related paths are amenable to formal verification with [hax](https://cryspen.com/hax) and [F\*](https://fstar-lang.org); see crate metadata and CI for the current `hax` configuration.

## Features

| Feature | Purpose |
|--------|---------|
| `mldsa44`, `mldsa65`, `mldsa87` | Enable parameter sets (default enables all three). |
| `std` | Standard library (default). |
| `random` | OS-backed / integration RNG via `lib-q-random` (default). |
| `nist-drbg` | NIST SP 800-90A DRBG wiring for KAT-style runs. |
| `simd128` / `simd256` | NEON / AVX2 acceleration (`lib-q-intrinsics`). |
| `hardened` | **Atomic** gate: masking / shuffled processing and constant-time-oriented signing paths; requires `random`, `zeroize`, `subtle`, `getrandom`. Do not enable piecemeal. |
| `zeroize` | Zeroization of sensitive buffers where supported. |
| `fips-mode` | Stricter FIPS-oriented behavior flag (see source/docs). |

## Related workspace crates

- [**lib-q-ring**](../lib-q-ring) — negacyclic NTT / polynomial layer.
- [**lib-q-lattice-zkp**](../lib-q-lattice-zkp) — research module-lattice proofs that reuse the same ring (not a replacement for this signature API).
- [**lib-q-sca-test**](../lib-q-sca-test) — optional TVLA/timing harness for `hardened` paths (screening, not certification).

## Documentation in this crate

- [docs/MODES.md](docs/MODES.md) — operational modes (including hardened).
- [docs/INTEROPERABILITY.md](docs/INTEROPERABILITY.md) — wire formats and integration notes.
- [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md) — audit-oriented notes.

## Usage sketch

Enable the parameter sets you need and depend on `lib-q-ml-dsa` from the workspace or crates.io (version aligned with the workspace `version` in the root `Cargo.toml`).

```rust
use lib_q_ml_dsa::ml_dsa_65::{generate_key_pair, sign, verify};

// Supply cryptographically strong randomness (see FIPS 204 and project RNG guidance).
let seed = [0u8; lib_q_ml_dsa::KEY_GENERATION_RANDOMNESS_SIZE];
let key_pair = generate_key_pair(seed);

let msg = b"message";
let context = b"";
let sig_seed = [0u8; lib_q_ml_dsa::SIGNING_RANDOMNESS_SIZE];
let sig = sign(&key_pair.signing_key, msg, context, sig_seed).expect("sign");

assert!(verify(&key_pair.verification_key, msg, context, &sig).is_ok());
```

For provider-style use through the umbrella stack, see [**lib-q-sig**](../lib-q-sig) and [**lib-q**](../lib-q).

## License

Apache-2.0 — see [LICENSE](../LICENSE).
