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
/// `sigma` length (`PARAM_SECURITY_BYTES`).
pub const KEM_SIGMA_BYTES: usize = 16;
/// KEM seed length (`seed_kem` in `HqcKemSecretKey`).
pub const KEM_SEED_KEM_BYTES: usize = 48;

/// Byte length of a serialized KEM secret key for a given `ek_pke` / public key prefix size.
#[must_use]
pub const fn kem_secret_key_serialized_len(ek_pke_len: usize) -> usize {
    ek_pke_len + PKE_DK_SEED_BYTES + KEM_SIGMA_BYTES + KEM_SEED_KEM_BYTES
}

// --- HQC-128 (parameter set 1) ---

/// KEM public key length (`CRYPTO_PUBLICKEYBYTES` / `seed_ek` ‖ `s`).
pub const HQC128_PUBLIC_KEY_BYTES: usize = 2241;
/// KEM ciphertext length (`CRYPTO_CIPHERTEXTBYTES`).
pub const HQC128_CIPHERTEXT_BYTES: usize = 4433;
/// Serialized KEM secret key length (see [`kem_secret_key_serialized_len`]).
pub const HQC128_SECRET_KEY_BYTES: usize = kem_secret_key_serialized_len(HQC128_PUBLIC_KEY_BYTES);

// --- HQC-192 (parameter set 3) ---

pub const HQC192_PUBLIC_KEY_BYTES: usize = 4522;
pub const HQC192_CIPHERTEXT_BYTES: usize = 8978;
pub const HQC192_SECRET_KEY_BYTES: usize = kem_secret_key_serialized_len(HQC192_PUBLIC_KEY_BYTES);

// --- HQC-256 (parameter set 5) ---

pub const HQC256_PUBLIC_KEY_BYTES: usize = 7245;
pub const HQC256_CIPHERTEXT_BYTES: usize = 14421;
pub const HQC256_SECRET_KEY_BYTES: usize = kem_secret_key_serialized_len(HQC256_PUBLIC_KEY_BYTES);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_secret_lengths_match_explicit_sums() {
        assert_eq!(HQC128_SECRET_KEY_BYTES, 2241 + 32 + 16 + 48);
        assert_eq!(HQC192_SECRET_KEY_BYTES, 4522 + 32 + 16 + 48);
        assert_eq!(HQC256_SECRET_KEY_BYTES, 7245 + 32 + 16 + 48);
    }
}
