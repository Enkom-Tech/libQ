//! Global constants that are part of the API (i.e. array sizes)

#[cfg(any(feature = "cbkem348864", feature = "cbkem348864f"))]
/// The number of bytes required to store the public key
pub const CRYPTO_PUBLICKEYBYTES: usize = 261120;
#[cfg(any(feature = "cbkem348864", feature = "cbkem348864f"))]
/// The number of bytes required to store the secret key
pub const CRYPTO_SECRETKEYBYTES: usize = 6492;
#[cfg(any(feature = "cbkem348864", feature = "cbkem348864f"))]
/// The number of bytes required to store the ciphertext resulting from the encryption
pub const CRYPTO_CIPHERTEXTBYTES: usize = 96;

#[cfg(feature = "cbkem348864")]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "cbkem348864";
#[cfg(all(not(feature = "cbkem348864"), feature = "cbkem348864f"))]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "cbkem348864f";

#[cfg(all(
    not(any(feature = "cbkem348864", feature = "cbkem348864f")),
    any(feature = "cbkem460896", feature = "cbkem460896f")
))]
/// The number of bytes required to store the public key
pub const CRYPTO_PUBLICKEYBYTES: usize = 524160;
#[cfg(all(
    not(any(feature = "cbkem348864", feature = "cbkem348864f")),
    any(feature = "cbkem460896", feature = "cbkem460896f")
))]
/// The number of bytes required to store the secret key
pub const CRYPTO_SECRETKEYBYTES: usize = 13608;
#[cfg(all(
    not(any(feature = "cbkem348864", feature = "cbkem348864f")),
    any(feature = "cbkem460896", feature = "cbkem460896f")
))]
/// The number of bytes required to store the ciphertext resulting from the encryption
pub const CRYPTO_CIPHERTEXTBYTES: usize = 156;

#[cfg(all(
    not(any(feature = "cbkem348864", feature = "cbkem348864f")),
    feature = "cbkem460896"
))]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "cbkem460896";
#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896"
    )),
    feature = "cbkem460896f"
))]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "cbkem460896f";

#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f"
    )),
    any(feature = "cbkem6688128", feature = "cbkem6688128f")
))]
/// The number of bytes required to store the public key
pub const CRYPTO_PUBLICKEYBYTES: usize = 1044992;
#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f"
    )),
    any(feature = "cbkem6688128", feature = "cbkem6688128f")
))]
/// The number of bytes required to store the secret key
pub const CRYPTO_SECRETKEYBYTES: usize = 13932;
#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f"
    )),
    any(feature = "cbkem6688128", feature = "cbkem6688128f")
))]
/// The number of bytes required to store the ciphertext resulting from the encryption
pub const CRYPTO_CIPHERTEXTBYTES: usize = 208;

#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f"
    )),
    feature = "cbkem6688128"
))]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "cbkem6688128";
#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f",
        feature = "cbkem6688128"
    )),
    feature = "cbkem6688128f"
))]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "cbkem6688128f";

#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f",
        feature = "cbkem6688128",
        feature = "cbkem6688128f"
    )),
    any(feature = "cbkem6960119", feature = "cbkem6960119f")
))]
/// The number of bytes required to store the public key
pub const CRYPTO_PUBLICKEYBYTES: usize = 1047319;
#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f",
        feature = "cbkem6688128",
        feature = "cbkem6688128f"
    )),
    any(feature = "cbkem6960119", feature = "cbkem6960119f")
))]
/// The number of bytes required to store the secret key
pub const CRYPTO_SECRETKEYBYTES: usize = 13948;
#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f",
        feature = "cbkem6688128",
        feature = "cbkem6688128f"
    )),
    any(feature = "cbkem6960119", feature = "cbkem6960119f")
))]
/// The number of bytes required to store the ciphertext resulting from the encryption
pub const CRYPTO_CIPHERTEXTBYTES: usize = 194;

#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f",
        feature = "cbkem6688128",
        feature = "cbkem6688128f"
    )),
    feature = "cbkem6960119"
))]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "cbkem6960119";
#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f",
        feature = "cbkem6688128",
        feature = "cbkem6688128f",
        feature = "cbkem6960119"
    )),
    feature = "cbkem6960119f"
))]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "cbkem6960119f";

#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f",
        feature = "cbkem6688128",
        feature = "cbkem6688128f",
        feature = "cbkem6960119",
        feature = "cbkem6960119f"
    )),
    any(feature = "cbkem8192128", feature = "cbkem8192128f")
))]
/// The number of bytes required to store the public key
pub const CRYPTO_PUBLICKEYBYTES: usize = 1357824;
#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f",
        feature = "cbkem6688128",
        feature = "cbkem6688128f",
        feature = "cbkem6960119",
        feature = "cbkem6960119f"
    )),
    any(feature = "cbkem8192128", feature = "cbkem8192128f")
))]
/// The number of bytes required to store the secret key
pub const CRYPTO_SECRETKEYBYTES: usize = 14120;
#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f",
        feature = "cbkem6688128",
        feature = "cbkem6688128f",
        feature = "cbkem6960119",
        feature = "cbkem6960119f"
    )),
    any(feature = "cbkem8192128", feature = "cbkem8192128f")
))]
/// The number of bytes required to store the ciphertext resulting from the encryption
pub const CRYPTO_CIPHERTEXTBYTES: usize = 208;

#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f",
        feature = "cbkem6688128",
        feature = "cbkem6688128f",
        feature = "cbkem6960119",
        feature = "cbkem6960119f"
    )),
    feature = "cbkem8192128"
))]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "cbkem8192128";
#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f",
        feature = "cbkem6688128",
        feature = "cbkem6688128f",
        feature = "cbkem6960119",
        feature = "cbkem6960119f",
        feature = "cbkem8192128"
    )),
    feature = "cbkem8192128f"
))]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "cbkem8192128f";

/// The number of bytes required to store the shared secret negotiated between both parties
// this value is uniform
pub const CRYPTO_BYTES: usize = 32;

// Conformance guard: `lib-q-core::SecurityConstants` reads the CB-KEM sizes from
// `lib_q_types::cbkem` (lib-q-core cannot depend on this crate without a cycle). Only one
// parameter set's `CRYPTO_*BYTES` is compiled in per build (feature-selected above), so this
// test asserts whichever one is active still matches its mirror in lib-q-types.
#[cfg(test)]
mod size_conformance {
    use super::*;

    #[test]
    #[cfg(any(feature = "cbkem348864", feature = "cbkem348864f"))]
    fn matches_lib_q_types() {
        assert_eq!(
            CRYPTO_PUBLICKEYBYTES,
            lib_q_types::cbkem::CBKEM348864_PUBLIC_KEY_BYTES
        );
        assert_eq!(
            CRYPTO_SECRETKEYBYTES,
            lib_q_types::cbkem::CBKEM348864_SECRET_KEY_BYTES
        );
        assert_eq!(
            CRYPTO_CIPHERTEXTBYTES,
            lib_q_types::cbkem::CBKEM348864_CIPHERTEXT_BYTES
        );
    }

    #[test]
    #[cfg(all(
        not(any(feature = "cbkem348864", feature = "cbkem348864f")),
        any(feature = "cbkem460896", feature = "cbkem460896f")
    ))]
    fn matches_lib_q_types() {
        assert_eq!(
            CRYPTO_PUBLICKEYBYTES,
            lib_q_types::cbkem::CBKEM460896_PUBLIC_KEY_BYTES
        );
        assert_eq!(
            CRYPTO_SECRETKEYBYTES,
            lib_q_types::cbkem::CBKEM460896_SECRET_KEY_BYTES
        );
        assert_eq!(
            CRYPTO_CIPHERTEXTBYTES,
            lib_q_types::cbkem::CBKEM460896_CIPHERTEXT_BYTES
        );
    }

    #[test]
    #[cfg(all(
        not(any(
            feature = "cbkem348864",
            feature = "cbkem348864f",
            feature = "cbkem460896",
            feature = "cbkem460896f"
        )),
        any(feature = "cbkem6688128", feature = "cbkem6688128f")
    ))]
    fn matches_lib_q_types() {
        assert_eq!(
            CRYPTO_PUBLICKEYBYTES,
            lib_q_types::cbkem::CBKEM6688128_PUBLIC_KEY_BYTES
        );
        assert_eq!(
            CRYPTO_SECRETKEYBYTES,
            lib_q_types::cbkem::CBKEM6688128_SECRET_KEY_BYTES
        );
        assert_eq!(
            CRYPTO_CIPHERTEXTBYTES,
            lib_q_types::cbkem::CBKEM6688128_CIPHERTEXT_BYTES
        );
    }

    #[test]
    #[cfg(all(
        not(any(
            feature = "cbkem348864",
            feature = "cbkem348864f",
            feature = "cbkem460896",
            feature = "cbkem460896f",
            feature = "cbkem6688128",
            feature = "cbkem6688128f"
        )),
        any(feature = "cbkem6960119", feature = "cbkem6960119f")
    ))]
    fn matches_lib_q_types() {
        assert_eq!(
            CRYPTO_PUBLICKEYBYTES,
            lib_q_types::cbkem::CBKEM6960119_PUBLIC_KEY_BYTES
        );
        assert_eq!(
            CRYPTO_SECRETKEYBYTES,
            lib_q_types::cbkem::CBKEM6960119_SECRET_KEY_BYTES
        );
        assert_eq!(
            CRYPTO_CIPHERTEXTBYTES,
            lib_q_types::cbkem::CBKEM6960119_CIPHERTEXT_BYTES
        );
    }

    #[test]
    #[cfg(all(
        not(any(
            feature = "cbkem348864",
            feature = "cbkem348864f",
            feature = "cbkem460896",
            feature = "cbkem460896f",
            feature = "cbkem6688128",
            feature = "cbkem6688128f",
            feature = "cbkem6960119",
            feature = "cbkem6960119f"
        )),
        any(feature = "cbkem8192128", feature = "cbkem8192128f")
    ))]
    fn matches_lib_q_types() {
        assert_eq!(
            CRYPTO_PUBLICKEYBYTES,
            lib_q_types::cbkem::CBKEM8192128_PUBLIC_KEY_BYTES
        );
        assert_eq!(
            CRYPTO_SECRETKEYBYTES,
            lib_q_types::cbkem::CBKEM8192128_SECRET_KEY_BYTES
        );
        assert_eq!(
            CRYPTO_CIPHERTEXTBYTES,
            lib_q_types::cbkem::CBKEM8192128_CIPHERTEXT_BYTES
        );
    }
}
