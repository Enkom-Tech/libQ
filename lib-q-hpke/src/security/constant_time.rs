//! Constant-time operations for cryptographic security

/// Constant-time equality comparison
///
/// This function performs a constant-time comparison of two byte slices
/// to prevent timing attacks. It returns true if the slices are equal,
/// false otherwise.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Constant-time selection
///
/// Returns a if choice is 1, b if choice is 0.
/// Choice must be 0 or 1, otherwise behavior is undefined.
pub fn constant_time_select(choice: u8, a: u8, b: u8) -> u8 {
    let mask = 0u8.wrapping_sub(choice);
    (a & mask) | (b & !mask)
}

/// Constant-time conditional copy
///
/// If choice is 1, copies src to dst. If choice is 0, leaves dst unchanged.
/// Choice must be 0 or 1, otherwise behavior is undefined.
pub fn constant_time_copy(choice: u8, dst: &mut [u8], src: &[u8]) {
    if dst.len() != src.len() {
        return;
    }

    let mask = 0u8.wrapping_sub(choice);
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = (*d & !mask) | (*s & mask);
    }
}

/// Constant-time conditional swap
///
/// If choice is 1, swaps a and b. If choice is 0, leaves them unchanged.
/// Choice must be 0 or 1, otherwise behavior is undefined.
pub fn constant_time_swap(choice: u8, a: &mut [u8], b: &mut [u8]) {
    if a.len() != b.len() {
        return;
    }

    let mask = 0u8.wrapping_sub(choice);
    for (a_elem, b_elem) in a.iter_mut().zip(b.iter_mut()) {
        let temp = *a_elem;
        *a_elem = (*a_elem & !mask) | (*b_elem & mask);
        *b_elem = (*b_elem & !mask) | (temp & mask);
    }
}

/// Constant-time conditional zero
///
/// If choice is 1, zeros out the slice. If choice is 0, leaves it unchanged.
/// Choice must be 0 or 1, otherwise behavior is undefined.
pub fn constant_time_zero(choice: u8, data: &mut [u8]) {
    let mask = 0u8.wrapping_sub(choice);
    for byte in data.iter_mut() {
        *byte &= !mask;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";
        let d = b"hell";

        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
        assert!(!constant_time_eq(a, d));
        assert!(!constant_time_eq(b"", b"a"));
    }

    #[test]
    fn test_constant_time_select() {
        assert_eq!(constant_time_select(1, 0xFF, 0x00), 0xFF);
        assert_eq!(constant_time_select(0, 0xFF, 0x00), 0x00);
    }

    #[test]
    fn test_constant_time_copy() {
        let mut dst = [0u8; 4];
        let src = [1u8, 2u8, 3u8, 4u8];

        constant_time_copy(1, &mut dst, &src);
        assert_eq!(dst, src);

        constant_time_copy(0, &mut dst, &[5u8, 6u8, 7u8, 8u8]);
        assert_eq!(dst, src); // Should be unchanged
    }

    #[test]
    fn test_constant_time_swap() {
        let mut a = [1u8, 2u8, 3u8, 4u8];
        let mut b = [5u8, 6u8, 7u8, 8u8];
        let a_orig = a;
        let b_orig = b;

        constant_time_swap(1, &mut a, &mut b);
        assert_eq!(a, b_orig);
        assert_eq!(b, a_orig);

        constant_time_swap(0, &mut a, &mut b);
        assert_eq!(a, b_orig); // Should be unchanged
        assert_eq!(b, a_orig); // Should be unchanged
    }

    #[test]
    fn test_constant_time_zero() {
        let mut data = [1u8, 2u8, 3u8, 4u8];

        constant_time_zero(1, &mut data);
        assert_eq!(data, [0u8, 0u8, 0u8, 0u8]);

        data = [1u8, 2u8, 3u8, 4u8];
        constant_time_zero(0, &mut data);
        assert_eq!(data, [1u8, 2u8, 3u8, 4u8]); // Should be unchanged
    }
}
