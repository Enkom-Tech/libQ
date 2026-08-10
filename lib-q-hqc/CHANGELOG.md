# Changelog — lib-q-hqc

All notable changes to this crate are documented here.

## Unreleased

### BREAKING — `m` and `sigma` are now `PARAM_SECURITY_BYTES` (16/24/32), not a hardwired 16

`PARAM_SECURITY_BYTES` is per-level in HQC — 16/24/32 for HQC-128/192/256, equal to `P::K` — and
this crate hardwired both the KEM message `m` and the implicit-rejection secret `sigma` to 16 bytes
at every level. Two consequences, one of them a security defect:

* **Entropy.** The shared secret is `K = G(H(ek_pke) ‖ m ‖ salt)`. `H(ek_pke)` is a hash of the
  public key and `salt` is transmitted in the clear inside the ciphertext, so `m` is the only
  secret input and the shared secret carries at most `|m|` bits. With `m` fixed at 16 bytes, an
  HQC-192 or HQC-256 shared secret had **128 bits** of entropy, not the 192/256 the parameter set
  is chosen for. HQC-128 was unaffected.
* **Conformance.** Upstream's HQC-192/256 encaps vectors use a 24/32-byte `m` and could not even be
  supplied to the old `encapsulate_with_m_salt(m: &[u8; 16])` signature, so encaps/decaps
  conformance was only ever checked at HQC-128.

What changed:

* `HqcKem::encapsulate_with_m_salt` now takes `m: &[u8]` and requires `m.len() == P::K`, returning
  `HqcKemError::InvalidInput` otherwise. `HqcKem::encapsulate` samples `P::K` random bytes.
* `HqcKemSecretKey`'s `sigma` is a `[u8; MAX_SECURITY_BYTES]` buffer whose live prefix is `P::K`;
  `as_bytes`/`to_nist_bytes` emit exactly `P::K` bytes and `from_nist_bytes` reads that many.
* `lib_q_types::hqc::{kem_secret_key_serialized_len, kem_nist_secret_key_bytes}` take a `sigma_len`
  argument; `KEM_SIGMA_BYTES_192`/`KEM_SIGMA_BYTES_256` are new. `HQC192_SECRET_KEY_BYTES`
  4610→4618, `HQC256_SECRET_KEY_BYTES` 7333→7349, `HQC192_NIST_SECRET_KEY_BYTES` 4562→4570,
  `HQC256_NIST_SECRET_KEY_BYTES` 7285→7301.

**Wire-breaking for HQC-192 and HQC-256**: secret keys, ciphertexts and shared secrets all change.
Peers on earlier versions will not interoperate at those levels, and stored HQC-192/256 keys do not
convert. **HQC-128 is bit-for-bit unchanged** — its regression-pin `.rsp` hashes are identical
across this change, which is the evidence for that claim.

Verification: `tests/reference_intermediates_kat.rs` now compares the **full** keygen → encaps →
decaps chain against the vendored upstream HQC v5.0.0 `intermediates_values` at all three levels
(8 tests, none ignored) — HQC-192/256 `sigma`, `c_kem` and `K` are byte-exact with upstream where
previously they were unreachable. `kats/regression-pins/hqc-{3,5}` regenerated; `kats-manifest.toml`
digests updated.

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

> Update: the `sigma`/`m` half of that gap is fixed — see the entry at the top of this file. The
> `dk_pke` seed-vs-expanded half remains open, so the length still differs from upstream.
