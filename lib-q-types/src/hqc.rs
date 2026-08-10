//! HQC KEM object sizes (bytes) shared across the workspace.
//!
//! This module is the **single source of truth** for wire-format lengths used by
//! `lib-q-hqc` (`HqcParams` key/ciphertext sizes) and `lib-q-core` (`SecurityConstants`).
//!
//! # Serialized KEM secret key
//!
//! Matches `lib-q-hqc` `HqcKemSecretKey::as_bytes`:
//! `ek_pke` ‖ `dk_pke` ‖ `sigma` ‖ `seed_kem`.
//!
//! NIST reference `CRYPTO_SECRETKEYBYTES` in some packages used a shorter packing; this workspace
//! uses the layout above consistently, so `HQC*_SECRET_KEY_BYTES` here
//! is the length of that serialization, not necessarily the historical API constant.

/// PKE decryption key seed (`dk_pke`) length in bytes (`u8; 32` in `HqcPkeSecretKey`).
pub const PKE_DK_SEED_BYTES: usize = 32;
/// PKE encryption key seed (`seed_ek`) length in bytes — the fixed-size prefix of the public key.
pub const PKE_EK_SEED_BYTES: usize = 32;
/// `sigma` length (`PARAM_SECURITY_BYTES`) for HQC-128.
///
/// `PARAM_SECURITY_BYTES` is **per level** in the HQC v5.0.0 reference — 16/24/32 for
/// HQC-128/192/256 — and the vendored upstream `intermediates_values` dumps confirm it (`sigma`
/// and `m` are 16/24/32 hex-decoded bytes there; `salt` stays 16 at every level). Use
/// [`KEM_SIGMA_BYTES_192`] / [`KEM_SIGMA_BYTES_256`] for the higher levels rather than assuming
/// this one is universal.
pub const KEM_SIGMA_BYTES: usize = 16;
/// `sigma` length (`PARAM_SECURITY_BYTES`) for HQC-192.
pub const KEM_SIGMA_BYTES_192: usize = 24;
/// `sigma` length (`PARAM_SECURITY_BYTES`) for HQC-256.
pub const KEM_SIGMA_BYTES_256: usize = 32;
/// KEM seed length (`seed_kem` in `HqcKemSecretKey`).
pub const KEM_SEED_KEM_BYTES: usize = 48;

/// Byte length of a serialized KEM public key (`seed_ek` ‖ `s`) for parameter `N` (in bits), per
/// the HQC v5.0.0 (2025-08-22) specification. `PUBLIC_KEY_BYTES` must always equal this — see the
/// `params.rs` conformance test that checks it against `VEC_N_SIZE_BYTES` directly.
#[must_use]
pub const fn kem_public_key_bytes(n_bits: usize) -> usize {
    PKE_EK_SEED_BYTES + n_bits.div_ceil(8)
}

/// Byte length of a serialized KEM secret key for a given `ek_pke` / public key prefix size and
/// `sigma` length (`PARAM_SECURITY_BYTES`, which is per-level: 16/24/32).
#[must_use]
pub const fn kem_secret_key_serialized_len(ek_pke_len: usize, sigma_len: usize) -> usize {
    ek_pke_len + PKE_DK_SEED_BYTES + sigma_len + KEM_SEED_KEM_BYTES
}

/// libQ's own `dk_pke` ‖ `sigma` ‖ `ek_pke` secret-key layout, named after (but **not
/// byte-identical to**) the upstream HQC reference's `CRYPTO_SECRETKEYBYTES` wire format.
///
/// The field order matches upstream's, and `sigma` is now sized per-level as upstream sizes it
/// (`PARAM_SECURITY_BYTES` = 16/24/32), but `dk_pke` is still this workspace's 32-byte seed rather
/// than upstream's expanded form. A same-seed comparison against the official HQC
/// v5.0.0 reference implementation (commit `f46e542`) measured the resulting constants as
/// numerically smaller than upstream's `CRYPTO_SECRETKEYBYTES` at all three levels — HQC-128:
/// 2289 vs 2321, HQC-192: 4562 vs 4602, HQC-256: 7285 vs 7333 (deltas -32/-40/-48) — see
/// `lib-q-hqc/kats/regression-pins/PROVENANCE.md` ("Known divergence...") for the measurement.
/// This is a tracked, open, low-severity naming/documentation gap, not a length-check defect:
/// nothing in this workspace parses real upstream-produced NIST-format secret-key bytes through
/// this constant (`HqcKemSecretKey::from_nist_bytes` round-trips only against
/// `HqcKemSecretKey::to_nist_bytes`, both using this crate's own sizing, with an exact `!=`
/// length check). Do not treat a value returned here as compatible with genuine upstream HQC
/// `CRYPTO_SECRETKEYBYTES`-sized keys.
#[must_use]
pub const fn kem_nist_secret_key_bytes(public_key_len: usize, sigma_len: usize) -> usize {
    PKE_DK_SEED_BYTES + sigma_len + public_key_len
}

// --- HQC-128 (parameter set 1) ---

/// KEM public key length (`CRYPTO_PUBLICKEYBYTES` / `seed_ek` ‖ `s`).
pub const HQC128_PUBLIC_KEY_BYTES: usize = kem_public_key_bytes(17669); // 2241
/// KEM ciphertext length (`CRYPTO_CIPHERTEXTBYTES`).
pub const HQC128_CIPHERTEXT_BYTES: usize = 4433;
/// Serialized KEM secret key length (see [`kem_secret_key_serialized_len`]).
pub const HQC128_SECRET_KEY_BYTES: usize =
    kem_secret_key_serialized_len(HQC128_PUBLIC_KEY_BYTES, KEM_SIGMA_BYTES);
/// NIST KEM secret key wire length (`dk_pke` ‖ `sigma` ‖ `ek_pke`).
pub const HQC128_NIST_SECRET_KEY_BYTES: usize =
    kem_nist_secret_key_bytes(HQC128_PUBLIC_KEY_BYTES, KEM_SIGMA_BYTES);

// --- HQC-192 (parameter set 3) ---

// NOTE (fix for card t_1558e72f): this was previously the literal `4522`, which is the HQC
// round-3 (2020 submission) size — that submission used a 40-byte `seed_ek` (40 + 4482 = 4522).
// HQC-192 was never migrated to the v5.0.0 (2025-08-22) 32-byte-seed format (HQC-128 was);
// deriving it from `kem_public_key_bytes` makes that drift structurally impossible to repeat.
// BREAKING CHANGE: this constant changes from 4522 to 4514. It is absorbed into `hash_h` during
// KEM encapsulation (`lib-q-hqc/src/hqc_kem.rs`), so the ciphertext and shared secret also change
// for HQC-192 — peers on lib-q-types <=0.0.10 will not interoperate. At-rest keys convert
// losslessly by truncation: the dropped 8 bytes are provably all-zero padding, so
// `pk_new = pk_old[..4514]` recovers the correct value from any previously stored key.
pub const HQC192_PUBLIC_KEY_BYTES: usize = kem_public_key_bytes(35851); // 4514
pub const HQC192_CIPHERTEXT_BYTES: usize = 8978;
pub const HQC192_SECRET_KEY_BYTES: usize =
    kem_secret_key_serialized_len(HQC192_PUBLIC_KEY_BYTES, KEM_SIGMA_BYTES_192);
pub const HQC192_NIST_SECRET_KEY_BYTES: usize =
    kem_nist_secret_key_bytes(HQC192_PUBLIC_KEY_BYTES, KEM_SIGMA_BYTES_192);

// --- HQC-256 (parameter set 5) ---

// NOTE (fix for card t_1558e72f): same round-3-vs-v5.0.0 seed-size drift as HQC-192, see above.
// BREAKING CHANGE: 7245 -> 7237, with the same ciphertext/shared-secret and truncation-migration
// consequences as HQC-192 (`pk_new = pk_old[..7237]`).
pub const HQC256_PUBLIC_KEY_BYTES: usize = kem_public_key_bytes(57637); // 7237
pub const HQC256_CIPHERTEXT_BYTES: usize = 14421;
pub const HQC256_SECRET_KEY_BYTES: usize =
    kem_secret_key_serialized_len(HQC256_PUBLIC_KEY_BYTES, KEM_SIGMA_BYTES_256);
pub const HQC256_NIST_SECRET_KEY_BYTES: usize =
    kem_nist_secret_key_bytes(HQC256_PUBLIC_KEY_BYTES, KEM_SIGMA_BYTES_256);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_secret_lengths_match_explicit_sums() {
        assert_eq!(HQC128_SECRET_KEY_BYTES, 2241 + 32 + 16 + 48);
        assert_eq!(HQC192_SECRET_KEY_BYTES, 4514 + 32 + 24 + 48);
        assert_eq!(HQC256_SECRET_KEY_BYTES, 7237 + 32 + 32 + 48);
        assert_eq!(HQC128_NIST_SECRET_KEY_BYTES, 32 + 16 + 2241);
        assert_eq!(HQC192_NIST_SECRET_KEY_BYTES, 32 + 24 + 4514);
        assert_eq!(HQC256_NIST_SECRET_KEY_BYTES, 32 + 32 + 7237);
    }

    /// `PARAM_SECURITY_BYTES` is per-level, not a single constant. Pinned against the vendored
    /// upstream v5.0.0 `intermediates_values` dumps, whose `sigma`/`m` fields decode to exactly
    /// these widths (`lib-q-hqc/kats/reference-intermediates/`).
    #[test]
    fn sigma_is_sized_per_security_level() {
        assert_eq!(KEM_SIGMA_BYTES, 16);
        assert_eq!(KEM_SIGMA_BYTES_192, 24);
        assert_eq!(KEM_SIGMA_BYTES_256, 32);
    }

    #[test]
    fn public_key_bytes_match_spec_literals() {
        // Card t_1558e72f: pin the literal HQC v5.0.0 (2025-08-22) values independently of
        // `kem_public_key_bytes`'s own formula (comparing a value to its own definition is a
        // gate that cannot fail — see `lib-q-hqc::params` for the independent check
        // against `VEC_N_SIZE_BYTES`, which is not derived from this constant either).
        assert_eq!(HQC128_PUBLIC_KEY_BYTES, 2241);
        assert_eq!(HQC192_PUBLIC_KEY_BYTES, 4514);
        assert_eq!(HQC256_PUBLIC_KEY_BYTES, 7237);
    }
}
