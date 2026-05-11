//! Utility functions for SP800-185 derived functions
//!
//! This module provides encoding and padding functions required by KMAC, TupleHash, and ParallelHash.

#[cfg(test)]
use alloc::vec;
#[cfg(test)]
use alloc::vec::Vec;

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

/// Pads a byte string with zeros to make its length a multiple of the rate.
///
/// # Arguments
/// * `input` - The input byte string
/// * `rate` - The rate in bytes
///
/// # Returns
/// Padded byte string
#[cfg(test)]
pub fn bytepad(input: &[u8], rate: usize) -> Vec<u8> {
    let mut result = Vec::new();

    // Add the length encoding
    let mut enc_buf = [0u8; 9];
    let encoded_len = left_encode(rate as u64, &mut enc_buf);
    result.extend_from_slice(encoded_len);

    // Add the input
    result.extend_from_slice(input);

    // Pad with zeros to make length a multiple of rate
    let padding_needed = (rate - (result.len() % rate)) % rate;
    result.extend_from_slice(&vec![0u8; padding_needed]);

    result
}

/// Encodes a string by prepending its bit length.
///
/// # Arguments
/// * `input` - The input string
/// * `buf` - Buffer for encoding (must be at least 9 bytes)
///
/// # Returns
/// Encoded string as bytes
#[cfg(test)]
pub fn encode_string(input: &[u8], buf: &mut [u8; 9]) -> Vec<u8> {
    let mut result = Vec::new();

    // Encode the bit length
    let encoded_len = left_encode((input.len() * 8) as u64, buf);
    result.extend_from_slice(encoded_len);

    // Add the input
    result.extend_from_slice(input);

    result
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

    #[test]
    fn test_bytepad() {
        // Test with rate 168 (KMAC128)
        let input = b"test";
        let padded = bytepad(input, 168);

        // Should be padded to multiple of 168
        assert_eq!(padded.len() % 168, 0);

        // Should start with length encoding
        assert_eq!(padded[0], 1); // length of rate encoding
        assert_eq!(padded[1], 168); // rate in one byte

        // Should contain input
        assert_eq!(&padded[2..6], b"test");
    }

    #[test]
    fn test_encode_string() {
        let mut buf = [0u8; 9];

        // Test encoding empty string
        let result = encode_string(b"", &mut buf);
        assert_eq!(result, &[1, 0]);

        // Test encoding "test" (32 bits)
        let result = encode_string(b"test", &mut buf);
        assert_eq!(result, &[1, 32, 116, 101, 115, 116]); // length + "test"
    }
}
