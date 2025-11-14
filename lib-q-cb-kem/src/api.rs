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
    not(any(feature = "cbkem348864", feature = "cbkem348864f", feature = "cbkem460896")),
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
