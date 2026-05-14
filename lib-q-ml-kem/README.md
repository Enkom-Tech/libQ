# lib-Q ML-KEM - Module-Lattice-Based Key-Encapsulation Mechanism

Pure Rust implementation of the Module-Lattice-Based Key-Encapsulation Mechanism Standard (formerly known as Kyber) as described in [FIPS 203] (final).

## About

ML-KEM is an algorithm which uses public-key cryptography to securely transfer a symmetric key between two parties who want to establish encrypted communications with each other. It uses algorithms which resist potential attacks by hypothetical future quantum computers which, when such computers are sufficiently mature, pose a problem for the algorithms we typically use for secure key establishment using public-key cryptography such as (EC)DH and RSA key encipherment.

Originally developed as [CRYSTALS-Kyber] (a.k.a. "Kyber"), ML-KEM is a refinement of the original Kyber algorithm after it was selected for standardization by [NIST]'s [Post-Quantum Cryptography] (PQC) competition. The Kyber algorithm received considerable feedback as part of the standardization process and as such, ML-KEM includes many changes from the original Kyber. It can be thought of as the official successor of Kyber.

In summary, ML-KEM stands at the forefront of post-quantum cryptography, offering enhanced security and efficiency in key encapsulation mechanisms to safeguard sensitive communications in an era where quantum computers potentially pose a looming threat.

## Security implementation

- **Infallible operations** on public paths where the design allows it, plus strict size checks on wire objects.
- **Constant-time intent** on sensitive comparisons and decapsulation logic; full guarantees require target-specific review.
- **Optional hardening** — feature `hardened` (see `Cargo.toml`): atomic gate enabling masking, NTT randomisation, and `subtle` comparisons; pairs with `random`, `zeroize`, and `getrandom`. Do not split the feature set.
- **Screening** — workspace crate [**lib-q-sca-test**](../lib-q-sca-test) can run TVLA/timing-style checks against `hardened` code paths (lab / CI smoke, not a certification).

This crate has **not** been independently audited; see the warning below.

## Usage

This crate is primarily used as a dependency for `lib-q-kem`. For direct usage:

```rust,ignore
// Doctest temporarily disabled due to complex trait import resolution
// The functionality works correctly as demonstrated by unit tests
//
// To use ML-KEM:
// 1. Add lib_q_ml_kem to your Cargo.toml
// 2. Use the appropriate ML-KEM variant (MlKem512, MlKem768, MlKem1024)
// 3. Generate keypairs and perform encapsulation/decapsulation
```

## Supported Algorithms

| Algorithm | Security Level | Public Key Size | Secret Key Size | Ciphertext Size |
|-----------|----------------|-----------------|-----------------|-----------------|
| ML-KEM 512 | Level 1 (128-bit) | 800 bytes | 1,632 bytes | 768 bytes |
| ML-KEM 768 | Level 3 (192-bit) | 1,184 bytes | 2,400 bytes | 1,088 bytes |
| ML-KEM 1024 | Level 5 (256-bit) | 1,568 bytes | 3,168 bytes | 1,568 bytes |

All algorithms produce a 32-byte shared secret.

## Features

- `deterministic` — deterministic encapsulation for testing.
- `zeroize` — zeroization helpers for sensitive buffers.
- `random` — wiring to `lib-q-random` for implementations that need it.
- `std` — compatibility flag (the crate is already usable with `std` without it).
- `wasm` — `wasm-bindgen` exports where enabled (also enables `zeroize` so WASM-held decapsulation keys and shared secrets are cleared on drop on the Rust side).
- `hardened` — side-channel-oriented hardening (see above); enable only as a complete feature set.

Default feature set is empty; enable what your integration needs (CI often uses `std` and/or `random`).

### WASM / `JavaScript` (`wasm` feature)

`ml_kem_generate_keypair`, `ml_kem_encapsulate`, and `ml_kem_decapsulate` expose decapsulation keys and shared secrets to JS as `Uint8Array` (not owned `Vec<u8>` through the bindgen boundary). Rust stores those fields in `Zeroizing` buffers. Callers must still overwrite or discard sensitive `Uint8Array` values in `JavaScript` after use (for example `fill(0)`); Rust cannot erase the JS heap once bytes have crossed the boundary.

## Testing

```bash
# Run all tests
cargo test

# Run with specific features
cargo test --features deterministic

# Run benchmarks
cargo bench
```

## Security Warning

The implementation contained in this crate has never been independently audited!

USE AT YOUR OWN RISK!

However, this implementation follows the practices outlined above.

## Related crates

- [**lib-q-kem**](../lib-q-kem) — façade over ML-KEM, CB-KEM, and HQC.
- [**lib-q-sca-test**](../lib-q-sca-test) — optional statistical leakage harness.

## License

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[//]: # (links)

[RustCrypto]: https://github.com/rustcrypto
[FIPS 203]: https://csrc.nist.gov/pubs/fips/203/final
[CRYSTALS-Kyber]: https://pq-crystals.org/ml_kem/
[NIST]: https://www.nist.gov/cryptography
[Post-Quantum Cryptography]: https://csrc.nist.gov/projects/post-quantum-cryptography
