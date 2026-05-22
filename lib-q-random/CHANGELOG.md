# Changelog

## 0.0.4

### Changed (breaking)

- Deterministic RNG (`new_deterministic`, `new_deterministic_from_u64`, `DeterministicEntropySource`, `NoStdRng` deterministic mode) now expands bytes with **KT128** (KangarooTwelve) and domain `libQ-DET-RNG-v1` instead of ChaCha20.
- `new_deterministic_from_u64` uses SplitMix64 to derive a 32-byte seed before KT128 (not `ChaCha20Rng::seed_from_u64`).
- All deterministic output byte sequences change; re-record KATs that depended on ChaCha20 streams.

### Added

- `kt128_expander` module and `Kt128Expander` type; golden constants `KT128_DET_GOLDEN_*`.
- Optional feature `deterministic-saturnin`: `LibQRng::new_deterministic_saturnin` (Saturnin CTR keystream).
- `Kt128Rng` delegates to shared expander (`HPKE-RNG` domain unchanged).

### Removed

- `rand_chacha` dependency from this crate.
