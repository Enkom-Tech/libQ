//! Fixed-size secrets copied to the stack behind [`Zeroizing`].

use zeroize::Zeroizing;

/// Block size for Romulus key, nonce, and tag (bytes).
pub(crate) const LEN: usize = 16;

/// Copy `bytes` (must be exactly [`LEN`] bytes) into stack memory cleared on drop.
pub(crate) fn zeroizing_copy_16(bytes: &[u8]) -> Zeroizing<[u8; LEN]> {
    let mut out = Zeroizing::new([0u8; LEN]);
    out.copy_from_slice(bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_exactly_16_bytes_in_order() {
        let src: [u8; 16] = core::array::from_fn(|i| i as u8);
        let out = zeroizing_copy_16(&src);
        assert_eq!(*out, src);
    }

    /// Internal error path: `copy_from_slice` panics on a length mismatch. All call sites
    /// in this crate are expected to pass exactly `LEN` bytes (validated by the caller
    /// before reaching here); this documents and pins down that contract so a future
    /// refactor that relaxes an upstream length check surfaces as a panic here, not silent
    /// truncation or out-of-bounds reads.
    #[test]
    #[should_panic]
    fn panics_on_short_input() {
        let _ = zeroizing_copy_16(&[0u8; 15]);
    }

    #[test]
    #[should_panic]
    fn panics_on_long_input() {
        let _ = zeroizing_copy_16(&[0u8; 17]);
    }
}
