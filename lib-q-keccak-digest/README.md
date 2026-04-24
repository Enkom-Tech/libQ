# lib-q-keccak-digest

**Pre–FIPS Keccak** fixed-length digests for **lib-Q**: `Keccak224` … `Keccak512` and the non-standard **`Keccak256Full`** (200-byte output, CryptoNight-style width). This is **not** [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) **SHA-3**—different padding from [`lib-q-sha3`](https://github.com/Enkom-Tech/libQ/tree/main/lib-q-sha3) (`Sha3_256`, SHAKE, cSHAKE, TurboSHAKE).

- **Repository:** <https://github.com/Enkom-Tech/libQ>
- **SHA-3 / SHAKE / cSHAKE / TurboSHAKE:** [`lib-q-sha3`](https://github.com/Enkom-Tech/libQ/tree/main/lib-q-sha3)
- **Keccak-`p` permutation:** [`lib-q-keccak`](https://github.com/Enkom-Tech/libQ/tree/main/lib-q-keccak)

## Security

- **`Keccak256` and `Sha3_256` are different functions** (different padding). Do not swap them in a protocol.
- **`Keccak256Full`** is a 200-byte digest width, not a 32-byte “Keccak-256” hash. Do not treat it like `Sha3_256` or `Keccak256`.
- This crate is for **interoperability** with legacy or non-NIST uses of the Keccak sponge with original padding; for new NIST-aligned designs, use SHA-3 and related types from `lib-q-sha3`.

## `no_std`, `alloc`, and WebAssembly

The crate is `#![no_std]`. Default features include `alloc` (via the `digest` feature) for the usual `buffer_fixed!` hasher API. The dependency on [`lib-q-sha3`](../lib-q-sha3) uses `default-features = false` so the Keccak permutation does not pull `std` (for example for `thumb*` or `wasm32-unknown-unknown`).

CI cross-checks `wasm32-unknown-unknown` and `thumbv7em-none-eabi` for this package. For `wasm32-unknown-unknown`, match the workspace pattern for `getrandom` if your binary links crates that use it: set `CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS` to include `--cfg getrandom_backend="wasm_js"` (see the `k12-no-std-wasm` job in `.github/workflows/ci.yml`).

## License

Apache-2.0; see the [workspace `LICENSE` file](https://github.com/Enkom-Tech/libQ/blob/main/LICENSE).

## Architecture

Non–FIPS-202 digests are isolated here; rationale is [ADR 001 in lib-q-sha3](https://github.com/Enkom-Tech/libQ/blob/main/lib-q-sha3/docs/adr/001-keccak-nonfips-surface.md). A future slimmer dependency graph (without a full `lib-q-sha3` line for every use case) is [ADR 002](https://github.com/Enkom-Tech/libQ/blob/main/lib-q-keccak-digest/docs/adr/002-keccak-digest-dependency-extraction.md).
