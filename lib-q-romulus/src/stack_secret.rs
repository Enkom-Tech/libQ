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
