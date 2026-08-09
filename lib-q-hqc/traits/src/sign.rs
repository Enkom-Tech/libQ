/// Traits for signature schemes
use crate::Result;

/// A public key for a signature scheme
pub trait PublicKey {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

/// A secret key for a signature scheme
pub trait SecretKey {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

/// A signed message.
///
/// This object contains both the message and the signature. Callers should treat
/// the authenticated payload as available only after verification: APIs that
/// verify and return the message (often named `open` or similar) should not
/// expose plaintext when the signature is invalid.
pub trait SignedMessage {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

/// A detached signature
///
/// This signature does not include the message it certifies; this means that to verify it you also
/// need the message.
///
/// If you can get away with it, use the [`SignedMessage`] API, which ensures you won't use the message
/// before having authenticated it.
pub trait DetachedSignature {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

/// Errors that may arise when verifying a signature
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum VerificationError {
    InvalidSignature,
    UnknownVerificationError,
}

impl core::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        match self {
            VerificationError::InvalidSignature => write!(f, "error: verification failed"),
            VerificationError::UnknownVerificationError => write!(f, "unknown error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerificationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    extern crate alloc;
    use alloc::format;

    #[test]
    fn invalid_signature_display() {
        assert_eq!(
            format!("{}", VerificationError::InvalidSignature),
            "error: verification failed"
        );
    }

    #[test]
    fn unknown_verification_error_display() {
        assert_eq!(
            format!("{}", VerificationError::UnknownVerificationError),
            "unknown error"
        );
    }

    #[test]
    fn verification_error_debug_is_derived() {
        let debug = format!("{:?}", VerificationError::InvalidSignature);
        assert!(debug.contains("InvalidSignature"));
    }

    // A dummy detached-signature type documenting the intended `from_bytes`
    // contract: a wrong-length input should surface `Error::BadLength` with
    // the offending name and the actual/expected lengths.
    #[derive(Debug)]
    struct DummySignature([u8; 4]);

    impl DetachedSignature for DummySignature {
        fn as_bytes(&self) -> &[u8] {
            &self.0
        }

        fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
            if bytes.len() != 4 {
                return Err(Error::BadLength {
                    name: "DummySignature",
                    actual: bytes.len(),
                    expected: 4,
                });
            }
            let mut buf = [0u8; 4];
            buf.copy_from_slice(bytes);
            Ok(DummySignature(buf))
        }
    }

    #[test]
    fn dummy_signature_from_bytes_round_trip() {
        let sig = DummySignature::from_bytes(&[1, 2, 3, 4]).expect("correct length parses");
        assert_eq!(sig.as_bytes(), &[1, 2, 3, 4]);

        let err = DummySignature::from_bytes(&[1, 2, 3]).unwrap_err();
        match err {
            Error::BadLength {
                name,
                actual,
                expected,
            } => {
                assert_eq!(name, "DummySignature");
                assert_eq!(actual, 3);
                assert_eq!(expected, 4);
            }
        }
    }
}
