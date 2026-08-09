//! Shared traits for post-quantum KEM and signature types used by lib-Q HQC tooling.

#![no_std]

#[cfg(feature = "std")]
extern crate std;

/// Convenience wrapper for Result
pub type Result<T> = core::result::Result<T, Error>;

/// Errors that may arise when constructing keys or signatures.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Error {
    BadLength {
        name: &'static str,
        actual: usize,
        expected: usize,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::BadLength {
                name,
                actual,
                expected,
            } => write!(
                f,
                "error: {} expected {} bytes, got {}",
                name, expected, actual
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

pub mod kem;
pub mod sign;

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::format;

    #[test]
    fn bad_length_display_reads_expected_then_actual() {
        let err = Error::BadLength {
            name: "public key",
            actual: 3,
            expected: 32,
        };
        assert_eq!(
            format!("{}", err),
            "error: public key expected 32 bytes, got 3"
        );
    }

    #[test]
    fn error_debug_is_derived() {
        let err = Error::BadLength {
            name: "secret key",
            actual: 1,
            expected: 2,
        };
        let debug = format!("{:?}", err);
        assert!(debug.contains("BadLength"));
        assert!(debug.contains("secret key"));
    }
}
