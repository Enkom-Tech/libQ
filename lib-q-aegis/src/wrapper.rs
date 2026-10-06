//! Public AEAD types: allocation-free detached API plus the lib-Q `Aead` traits.
//!
//! ## Verification
//!
//! Decryption always runs the full bulk decryption and recomputes the tag, then
//! compares it with the received tag in constant time
//! ([`lib_q_core::Utils::constant_time_compare`]). On mismatch the recovered
//! plaintext is overwritten with zeros before returning, as RFC 10032 Section 4.2
//! and the HiAE draft Section 3.3 require. Unverified plaintext is never returned.

use lib_q_core::Error;

/// Error for a failed tag check.
#[cold]
pub(crate) fn auth_failed() -> Error {
    Error::VerificationFailed {
        #[cfg(feature = "alloc")]
        operation: alloc::string::String::from("AEAD tag verification"),
        #[cfg(not(feature = "alloc"))]
        operation: "AEAD tag verification",
    }
}

/// Reject inputs longer than `P_MAX` / `A_MAX` (2^61 - 1 bytes).
#[inline]
pub(crate) fn check_len(len: usize) -> lib_q_core::Result<()> {
    if (len as u64) > crate::MAX_INPUT_LEN {
        return Err(Error::InvalidMessageSize {
            max: crate::MAX_INPUT_LEN as usize,
            actual: len,
        });
    }
    Ok(())
}

/// Defines a zero-sized AEAD type over a `seal`/`open` pair.
///
/// `seal(key, nonce, ad, buf) -> tag` encrypts `buf` in place;
/// `open(key, nonce, ad, buf) -> expected_tag` decrypts `buf` in place.
macro_rules! define_aead {
    (
        $(#[$doc:meta])*
        $ty:ident,
        name: $name:literal,
        key: $key:expr,
        nonce: $nonce:expr,
        tag: $tag:expr,
        seal: $seal:path,
        open: $open:path $(,)?
    ) => {
        $(#[$doc])*
        ///
        /// Stateless and free to construct. Nonces MUST be unique per key.
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $ty;

        impl $ty {
            /// Algorithm name.
            pub const NAME: &'static str = $name;
            /// Key size in bytes.
            pub const KEY_SIZE: usize = $key;
            /// Nonce size in bytes.
            pub const NONCE_SIZE: usize = $nonce;
            /// Tag size in bytes.
            pub const TAG_SIZE: usize = $tag;

            /// Create an instance.
            pub const fn new() -> Self {
                Self
            }

            /// Encrypt `buf` in place and return the detached tag.
            ///
            /// Fails only if `buf` or `ad` exceeds [`crate::MAX_INPUT_LEN`].
            pub fn encrypt_in_place_detached(
                key: &[u8; $key],
                nonce: &[u8; $nonce],
                ad: &[u8],
                buf: &mut [u8],
            ) -> $crate::Result<[u8; $tag]> {
                $crate::wrapper::check_len(ad.len())?;
                $crate::wrapper::check_len(buf.len())?;
                Ok($seal(key, nonce, ad, buf))
            }

            /// Decrypt `buf` in place and verify `tag` in constant time.
            ///
            /// On failure `buf` is zeroed and [`crate::Error::VerificationFailed`]
            /// is returned.
            pub fn decrypt_in_place_detached(
                key: &[u8; $key],
                nonce: &[u8; $nonce],
                ad: &[u8],
                buf: &mut [u8],
                tag: &[u8; $tag],
            ) -> $crate::Result<()> {
                use zeroize::Zeroize as _;
                $crate::wrapper::check_len(ad.len())?;
                $crate::wrapper::check_len(buf.len())?;
                let mut expected = $open(key, nonce, ad, buf);
                let ok = lib_q_core::Utils::constant_time_compare(&expected, tag);
                expected.zeroize();
                if ok {
                    Ok(())
                } else {
                    buf.zeroize();
                    Err($crate::wrapper::auth_failed())
                }
            }

            #[cfg(feature = "alloc")]
            fn stage(
                key: &$crate::AeadKey,
                nonce: &$crate::Nonce,
            ) -> $crate::Result<(zeroize::Zeroizing<[u8; $key]>, [u8; $nonce])> {
                let k = key.as_bytes();
                let n = nonce.as_bytes();
                if k.len() != $key {
                    return Err($crate::Error::InvalidKeySize {
                        expected: $key,
                        actual: k.len(),
                    });
                }
                if n.len() != $nonce {
                    return Err($crate::Error::InvalidNonceSize {
                        expected: $nonce,
                        actual: n.len(),
                    });
                }
                let mut kk = zeroize::Zeroizing::new([0u8; $key]);
                kk.copy_from_slice(k);
                let mut nn = [0u8; $nonce];
                nn.copy_from_slice(n);
                Ok((kk, nn))
            }

            #[cfg(feature = "alloc")]
            fn decrypt_core(
                key: &$crate::AeadKey,
                nonce: &$crate::Nonce,
                ciphertext: &[u8],
                associated_data: Option<&[u8]>,
            ) -> $crate::Result<$crate::DecryptSemanticOutcome> {
                let (k, n) = Self::stage(key, nonce)?;
                if ciphertext.len() < $tag {
                    return Err($crate::Error::aead_ciphertext_shorter_than_tag(
                        $tag,
                        ciphertext.len(),
                    ));
                }
                let ad = associated_data.unwrap_or(&[]);
                let (body, tag) = ciphertext.split_at(ciphertext.len() - $tag);
                let mut tag_arr = [0u8; $tag];
                tag_arr.copy_from_slice(tag);
                let mut pt = zeroize::Zeroizing::new(body.to_vec());
                match Self::decrypt_in_place_detached(&k, &n, ad, &mut pt, &tag_arr) {
                    Ok(()) => Ok($crate::DecryptSemanticOutcome::Success(pt)),
                    Err($crate::Error::VerificationFailed { .. }) => {
                        Ok($crate::DecryptSemanticOutcome::AuthenticationFailed)
                    },
                    Err(e) => Err(e),
                }
            }
        }

        #[cfg(feature = "alloc")]
        impl $crate::Aead for $ty {
            fn encrypt(
                &self,
                key: &$crate::AeadKey,
                nonce: &$crate::Nonce,
                plaintext: &[u8],
                associated_data: Option<&[u8]>,
            ) -> $crate::Result<alloc::vec::Vec<u8>> {
                let (k, n) = Self::stage(key, nonce)?;
                let ad = associated_data.unwrap_or(&[]);
                let mut out = alloc::vec::Vec::with_capacity(plaintext.len() + $tag);
                out.extend_from_slice(plaintext);
                let tag = Self::encrypt_in_place_detached(&k, &n, ad, &mut out)?;
                out.extend_from_slice(&tag);
                Ok(out)
            }

            fn decrypt(
                &self,
                key: &$crate::AeadKey,
                nonce: &$crate::Nonce,
                ciphertext: &[u8],
                associated_data: Option<&[u8]>,
            ) -> $crate::Result<alloc::vec::Vec<u8>> {
                match Self::decrypt_core(key, nonce, ciphertext, associated_data)? {
                    $crate::DecryptSemanticOutcome::Success(p) => Ok(p.to_vec()),
                    $crate::DecryptSemanticOutcome::AuthenticationFailed => {
                        Err($crate::wrapper::auth_failed())
                    },
                }
            }
        }

        #[cfg(feature = "alloc")]
        impl $crate::AeadDecryptSemantic for $ty {
            fn decrypt_semantic(
                &self,
                key: &$crate::AeadKey,
                nonce: &$crate::Nonce,
                ciphertext: &[u8],
                associated_data: Option<&[u8]>,
            ) -> $crate::Result<$crate::DecryptSemanticOutcome> {
                Self::decrypt_core(key, nonce, ciphertext, associated_data)
            }
        }
    };
}
pub(crate) use define_aead;
