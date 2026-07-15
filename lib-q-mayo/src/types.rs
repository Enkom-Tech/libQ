//! Key and signature newtypes. Secret material zeroizes on drop and never
//! prints via `Debug`.

use crate::params::{
    CPK_BYTES,
    CSK_BYTES,
    SIG_BYTES,
};

/// A MAYO_2 signing key (the 24-byte compact seed).
#[derive(Clone)]
pub struct Mayo2SigningKey {
    pub(crate) value: [u8; CSK_BYTES],
}

/// A MAYO_2 verification key (compact public key, 4912 bytes).
#[derive(Clone)]
pub struct Mayo2VerificationKey {
    pub(crate) value: [u8; CPK_BYTES],
}

/// A MAYO_2 signature (186 bytes, fixed length).
#[derive(Clone)]
pub struct Mayo2Signature {
    pub(crate) value: [u8; SIG_BYTES],
}

/// A MAYO_2 key pair.
pub struct Mayo2KeyPair {
    /// The signing (secret) key.
    pub signing_key: Mayo2SigningKey,
    /// The verification (public) key.
    pub verification_key: Mayo2VerificationKey,
}

/// Error returned when decoding a key or signature from bytes of the wrong
/// length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError {
    /// Expected byte length.
    pub expected: usize,
    /// Provided byte length.
    pub actual: usize,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "invalid length: expected {} bytes, got {}",
            self.expected, self.actual
        )
    }
}

macro_rules! impl_common {
    ($name:ident, $size:expr) => {
        impl $name {
            /// Init with zero.
            pub fn zero() -> Self {
                Self {
                    value: [0u8; $size],
                }
            }

            /// Build from a byte array.
            pub fn new(value: [u8; $size]) -> Self {
                Self { value }
            }

            /// A reference to the raw byte slice.
            pub fn as_slice(&self) -> &[u8] {
                &self.value
            }

            /// A reference to the raw byte array.
            #[allow(clippy::should_implement_trait)]
            pub fn as_ref(&self) -> &[u8; $size] {
                &self.value
            }

            /// A mutable reference to the raw byte array.
            pub fn as_ref_mut(&mut self) -> &mut [u8; $size] {
                &mut self.value
            }

            /// The number of bytes.
            pub const fn len() -> usize {
                $size
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = DecodeError;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                let value: [u8; $size] = bytes.try_into().map_err(|_| DecodeError {
                    expected: $size,
                    actual: bytes.len(),
                })?;
                Ok(Self { value })
            }
        }
    };
}

impl_common!(Mayo2SigningKey, CSK_BYTES);
impl_common!(Mayo2VerificationKey, CPK_BYTES);
impl_common!(Mayo2Signature, SIG_BYTES);

impl core::fmt::Debug for Mayo2SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Mayo2SigningKey([REDACTED])")
    }
}

impl core::fmt::Debug for Mayo2VerificationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mayo2VerificationKey")
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for Mayo2Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mayo2Signature").finish_non_exhaustive()
    }
}

impl Drop for Mayo2SigningKey {
    fn drop(&mut self) {
        crate::mayo_core::wipe_bytes(&mut self.value);
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for Mayo2SigningKey {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}
