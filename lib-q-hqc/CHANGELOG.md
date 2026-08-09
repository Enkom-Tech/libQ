# Changelog — lib-q-hqc

All notable changes to this crate are documented here.

## Unreleased

### BREAKING — HQC-192/HQC-256 Hamming-weight parameters corrected to HQC v5.0.0

`Hqc3Params` (HQC-192) and `Hqc5Params` (HQC-256) secret-support Hamming-weight parameters were
wrong relative to the current HQC specification:

| parameter | old (wrong) | corrected (HQC v5.0.0) |
|---|---|---|
| `Hqc3Params::OMEGA` (HQC-192) | 103 | **100** |
| `Hqc3Params::OMEGA_R` (HQC-192) | 115 | **114** |
| `Hqc5Params::OMEGA` (HQC-256) | 134 | **131** |

(`Hqc5Params::OMEGA_R` was already correct at 149; `Hqc1Params`/HQC-128 was already correct and is
unchanged.)

**Impact:** `OMEGA`/`OMEGA_R` govern the Hamming weight of the secret support `(x, y)` and of
`(r1, r2)` sampled during keygen/encapsulation. Any HQC-192 or HQC-256 keypair, ciphertext, or
shared secret produced by a pre-fix build of this crate is **incompatible** with the corrected
code and vice versa — this is a wire-breaking change for those two security levels.
HQC-128 (`Hqc1Params`) is unaffected. `PUBLIC_KEY_BYTES`, `CIPHERTEXT_BYTES`, and
`SHARED_SECRET_BYTES` are unchanged at all three levels (verified against upstream
`src/{ref/hqc-N/parameters.h, common/hqc-N/api.h}`, tag `v5.0.0`, commit `f46e542` — `OMEGA` does
not feed the encoded-size formulas).

Corrected against upstream `gitlab.com/pqc-hqc/hqc` tag `v5.0.0`, commit `f46e542` (2025-08-22),
matching `hqc_specifications_2025_08_22.pdf` — see `kats/reference-intermediates/PROVENANCE.md` and
`kats/reference-intermediates/hqc-{3,5}/intermediates_values` for the byte-exact external oracle
this was verified against (`tests/reference_intermediates_kat.rs`).

Self-generated regression-pin fixtures `kats/regression-pins/hqc-{3,5}/PQCkemKAT_*_regression_pin.rsp`
were regenerated under the corrected parameters (they were previously self-consistent only with the
wrong parameters); the corresponding entries in the repo-root `kats-manifest.toml` were updated to
the new file hashes. `kats/regression-pins/hqc-1/*` is bit-identical (HQC-128 was already correct).

A pre-existing, unrelated non-conformance was found and left untouched during this audit (tracked
separately, not caused by and not fixed as part of this change): `HqcKemSecretKey::as_bytes()`
computes a different length than upstream `CRYPTO_SECRETKEYBYTES` at all three security levels
(the internal encoding stores a 48-byte seed and a hardwired 16-byte `sigma`/`m` instead of
upstream's `PARAM_SECURITY_BYTES`-sized `seed_kem`/`sigma`/`m`). See
`kats/reference-intermediates/PROVENANCE.md`, "Scope and known gaps".
