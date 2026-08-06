//! Shared bounded reader for length-prefixed lists on the `lattice_zkp_wire_v0` wire.
//!
//! Every decoder in this module family reads an element *count* from untrusted bytes before it
//! has any element data to back that count. The historical bug shape was to size a `Vec`
//! (`Vec::with_capacity(n)`) directly from that untrusted count, so a single small, otherwise
//! malformed input could force a multi-megabyte allocation before the decoder ever noticed the
//! input was too short to contain what it claimed.
//!
//! The fix here is structural rather than a length check bolted on at each call site: carve the
//! exact byte span the claimed count implies out of the bytes *actually present* first (which
//! fails outright if the input is shorter than that), and only decode — and therefore only size
//! any `Vec` — from that already-in-bounds slice. The `Vec` is then grown by `collect()` over
//! `chunks_exact` of that slice, so its final length is a function of bytes actually received and
//! not of the claimed count, even if every other check in this file were deleted. That is what
//! makes the bug inexpressible through this helper rather than merely absent from today's call
//! sites.
//!
//! Note on the constant factor: `collect::<Result<Vec<_>, _>>()` goes through a fallible shunt
//! whose `size_hint` lower bound is 0, so the `Vec` grows by doubling rather than being sized
//! once. Peak allocation is therefore up to ~2x the decoded elements' in-memory size, which for a
//! `Poly` (1024 B in memory vs 704-736 B packed) is a small constant multiple of the input length
//! — bounded, but not equal to it. `tests/wire_v0_alloc_bound.rs` pins the measured worst case for
//! the largest wire an envelope can carry.

use alloc::vec::Vec;

use crate::error::VerifyError;

/// Decode `count` fixed-width elements of `elem_len` bytes each from `data`.
///
/// Validates the implied byte span (`count * elem_len`) against the bytes actually present in
/// `data` *before* decoding a single element or sizing any `Vec` from `count`. Returns the
/// decoded elements plus the number of bytes consumed (`count * elem_len`, exactly).
///
/// # Errors
///
/// Returns [`VerifyError::InvalidFormat`] if `elem_len` is zero (a zero-width element is never
/// valid on this wire, and would panic inside `chunks_exact`), if `count * elem_len` overflows
/// `usize`, if `data` is shorter than that product, or if `decode` rejects any element.
pub(crate) fn read_fixed_width<T>(
    data: &[u8],
    count: usize,
    elem_len: usize,
    mut decode: impl FnMut(&[u8]) -> Result<T, VerifyError>,
) -> Result<(Vec<T>, usize), VerifyError> {
    if elem_len == 0 {
        return Err(VerifyError::InvalidFormat);
    }
    let need = count
        .checked_mul(elem_len)
        .ok_or(VerifyError::InvalidFormat)?;
    let body = data.get(..need).ok_or(VerifyError::InvalidFormat)?;
    let items = body
        .chunks_exact(elem_len)
        .map(&mut decode)
        .collect::<Result<Vec<T>, VerifyError>>()?;
    Ok((items, need))
}

/// Read a `u16`-LE element-count prefix, reject it if it exceeds `max_count`, then decode that
/// many fixed-width elements via [`read_fixed_width`].
///
/// `max_count` is intentionally the call site's own pre-existing ceiling (e.g. `u16::MAX` where
/// the wire format's own prefix width was already the only limit) — this helper's job is to make
/// the *allocation* safe, not to silently tighten what a given call site already accepted.
///
/// Returns `(items, consumed)` where `consumed` includes the 2-byte prefix.
pub(crate) fn read_u16_counted<T>(
    data: &[u8],
    elem_len: usize,
    max_count: usize,
    decode: impl FnMut(&[u8]) -> Result<T, VerifyError>,
) -> Result<(Vec<T>, usize), VerifyError> {
    let prefix = data.get(..2).ok_or(VerifyError::InvalidFormat)?;
    let n = u16::from_le_bytes([prefix[0], prefix[1]]) as usize;
    if n > max_count {
        return Err(VerifyError::InvalidFormat);
    }
    let (items, need) = read_fixed_width(&data[2..], n, elem_len, decode)?;
    let consumed = 2usize.checked_add(need).ok_or(VerifyError::InvalidFormat)?;
    Ok((items, consumed))
}

/// Read a `u8` element-count prefix (used by dual-ring challenges), reject it if it exceeds
/// `max_count`, then decode that many fixed-width elements via [`read_fixed_width`].
///
/// Returns `(items, consumed)` where `consumed` includes the 1-byte prefix.
pub(crate) fn read_u8_counted<T>(
    data: &[u8],
    elem_len: usize,
    max_count: usize,
    decode: impl FnMut(&[u8]) -> Result<T, VerifyError>,
) -> Result<(Vec<T>, usize), VerifyError> {
    let n = usize::from(*data.first().ok_or(VerifyError::InvalidFormat)?);
    if n > max_count {
        return Err(VerifyError::InvalidFormat);
    }
    let (items, need) = read_fixed_width(&data[1..], n, elem_len, decode)?;
    let consumed = 1usize.checked_add(need).ok_or(VerifyError::InvalidFormat)?;
    Ok((items, consumed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_u8(chunk: &[u8]) -> Result<u8, VerifyError> {
        Ok(chunk[0])
    }

    #[test]
    fn read_fixed_width_rejects_short_input_before_allocating() {
        // count claims 0xFFFF elements of 4 bytes each (~256 KiB) but only 2 bytes are present.
        let data = [0u8, 0u8];
        let result = read_fixed_width(&data, 0xFFFF, 4, |c| Ok(c[0]));
        assert!(result.is_err());
    }

    #[test]
    fn read_fixed_width_zero_elem_len_is_rejected_not_a_panic() {
        let data = [1u8, 2, 3];
        let result = read_fixed_width(&data, 3, 0, decode_u8);
        assert_eq!(result, Err(VerifyError::InvalidFormat));
    }

    #[test]
    fn read_fixed_width_accepts_exact_fit() {
        let data = [1u8, 2, 3, 4];
        let (items, consumed) = read_fixed_width(&data, 4, 1, decode_u8).expect("fits exactly");
        assert_eq!(items, alloc::vec![1, 2, 3, 4]);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn read_u16_counted_rejects_count_over_max() {
        let mut data = alloc::vec![5u8, 0]; // n = 5
        data.extend_from_slice(&[0u8; 4]); // only 4 bytes of element data
        let result = read_u16_counted(&data, 1, 3, decode_u8);
        assert_eq!(result, Err(VerifyError::InvalidFormat));
    }

    #[test]
    fn read_u8_counted_rejects_huge_count_from_tiny_input() {
        let data = [0xFFu8]; // n = 255, elem_len = 736, nothing follows
        let result = read_u8_counted(&data, 736, u8::MAX as usize, decode_u8);
        assert_eq!(result, Err(VerifyError::InvalidFormat));
    }
}
