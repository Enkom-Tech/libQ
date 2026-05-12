//! Utility functions for SP800-185 derived functions
//!
//! This module provides [`left_encode`] and [`right_encode`], used by KMAC, TupleHash, and
//! ParallelHash. KMAC must not build `bytepad(encode_string(K), rate)` in a growable heap buffer:
//! that pattern copies the key into `Vec` storage that can remain readable after reuse or
//! reallocation. Production KMAC streams that construction into the sponge instead.

/// Left encode function
///
/// Encodes a non-negative integer x as a bit string of minimal length
/// followed by a bit string of length equal to the length of the minimal-length bit string.
///
/// # Arguments
/// * `val` - The value to encode
/// * `buf` - Buffer to store the encoded result (must be at least 9 bytes)
///
/// # Returns
/// Slice containing the encoded bytes
pub fn left_encode(val: u64, buf: &mut [u8; 9]) -> &[u8] {
    buf.fill(0);
    let n = if val == 0 {
        1usize
    } else {
        (64usize - val.leading_zeros() as usize).div_ceil(8)
    };

    buf[0] = n as u8;
    for i in 0..n {
        let shift = (n - 1 - i) * 8;
        buf[1 + i] = ((val >> shift) & 0xFF) as u8;
    }

    &buf[..(n + 1)]
}

/// Right encode function
///
/// Encodes a non-negative integer x as a bit string of minimal length
/// preceded by a bit string of length equal to the length of the minimal-length bit string.
///
/// # Arguments
/// * `val` - The value to encode
/// * `buf` - Buffer to store the encoded result (must be at least 9 bytes)
///
/// # Returns
/// Slice containing the encoded bytes
pub fn right_encode(val: u64, buf: &mut [u8; 9]) -> &[u8] {
    buf.fill(0);
    let n = if val == 0 {
        1usize
    } else {
        (64usize - val.leading_zeros() as usize).div_ceil(8)
    };

    for (i, out) in buf.iter_mut().take(n).enumerate() {
        let shift = (n - 1 - i) * 8;
        *out = ((val >> shift) & 0xFF) as u8;
    }
    buf[n] = n as u8;

    &buf[..(n + 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_left_encode() {
        let mut buf = [0u8; 9];

        // Test encoding 0
        let result = left_encode(0, &mut buf);
        assert_eq!(result, &[1, 0]);

        // Test encoding 1
        let result = left_encode(1, &mut buf);
        assert_eq!(result, &[1, 1]);

        // Test encoding 255
        let result = left_encode(255, &mut buf);
        assert_eq!(result, &[1, 255]);

        // Test encoding 256
        let result = left_encode(256, &mut buf);
        assert_eq!(result, &[2, 1, 0]);
    }

    #[test]
    fn test_right_encode() {
        let mut buf = [0u8; 9];

        // Test encoding 0
        let result = right_encode(0, &mut buf);
        assert_eq!(result, &[0, 1]);

        // Test encoding 1
        let result = right_encode(1, &mut buf);
        assert_eq!(result, &[1, 1]);

        // Test encoding 255
        let result = right_encode(255, &mut buf);
        assert_eq!(result, &[255, 1]);

        // Test encoding 256
        let result = right_encode(256, &mut buf);
        assert_eq!(result, &[1, 0, 2]);
    }
}
