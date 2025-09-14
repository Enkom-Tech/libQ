//! Constant-time operations for side-channel resistance
//!
//! This module provides constant-time implementations of common cryptographic
//! operations to prevent timing attacks and other side-channel vulnerabilities.

/// Constant-time equality comparison
///
/// Returns true if the two slices are equal, false otherwise.
/// The comparison is performed in constant time to prevent timing attacks.
///
/// # Arguments
/// * `a` - First byte slice
/// * `b` - Second byte slice
///
/// # Returns
/// * `true` if the slices are equal, `false` otherwise
///
/// # Security
/// This function performs the comparison in constant time regardless of
/// where the first difference occurs, preventing timing attacks.
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
/// Returns `a` if `condition` is true, `b` otherwise.
/// The selection is performed in constant time to prevent timing attacks.
///
/// # Arguments
/// * `condition` - Boolean condition
/// * `a` - Value to return if condition is true
/// * `b` - Value to return if condition is false
///
/// # Returns
/// * `a` if condition is true, `b` otherwise
///
/// # Security
/// This function performs the selection in constant time regardless of
/// the condition value, preventing timing attacks.
pub fn constant_time_select<T: Copy + ConstantTimeBytes>(condition: bool, a: T, b: T) -> T {
    let mask = if condition { !0u8 } else { 0u8 };

    // Convert to bytes for bitwise operations
    let a_bytes = to_bytes(a);
    let b_bytes = to_bytes(b);
    let mut result_bytes = [0u8; 8];

    for i in 0..8 {
        result_bytes[i] = (a_bytes[i] & mask) | (b_bytes[i] & !mask);
    }

    from_bytes(result_bytes)
}

/// Constant-time conditional copy
///
/// Copies `src` to `dst` if `condition` is true, otherwise leaves `dst` unchanged.
/// The operation is performed in constant time to prevent timing attacks.
///
/// # Arguments
/// * `condition` - Boolean condition
/// * `src` - Source slice
/// * `dst` - Destination slice (must be same length as src)
///
/// # Security
/// This function performs the copy in constant time regardless of
/// the condition value, preventing timing attacks.
pub fn constant_time_copy(condition: bool, src: &[u8], dst: &mut [u8]) {
    assert_eq!(src.len(), dst.len());

    let mask = if condition { !0u8 } else { 0u8 };

    for (s, d) in src.iter().zip(dst.iter_mut()) {
        *d = (*d & !mask) | (*s & mask);
    }
}

/// Constant-time conditional zero
///
/// Zeros `data` if `condition` is true, otherwise leaves it unchanged.
/// The operation is performed in constant time to prevent timing attacks.
///
/// # Arguments
/// * `condition` - Boolean condition
/// * `data` - Data to conditionally zero
///
/// # Security
/// This function performs the zeroing in constant time regardless of
/// the condition value, preventing timing attacks.
pub fn constant_time_zero(condition: bool, data: &mut [u8]) {
    let mask = if condition { !0u8 } else { 0u8 };

    for byte in data.iter_mut() {
        *byte &= !mask;
    }
}

/// Constant-time conditional swap
///
/// Swaps `a` and `b` if `condition` is true, otherwise leaves them unchanged.
/// The operation is performed in constant time to prevent timing attacks.
///
/// # Arguments
/// * `condition` - Boolean condition
/// * `a` - First value
/// * `b` - Second value
///
/// # Security
/// This function performs the swap in constant time regardless of
/// the condition value, preventing timing attacks.
pub fn constant_time_swap<T: Copy + ConstantTimeBytes>(condition: bool, a: &mut T, b: &mut T) {
    let mask = if condition { !0u8 } else { 0u8 };

    // Convert to bytes for bitwise operations
    let a_bytes = to_bytes(*a);
    let b_bytes = to_bytes(*b);
    let mut new_a_bytes = [0u8; 8];
    let mut new_b_bytes = [0u8; 8];

    for i in 0..8 {
        new_a_bytes[i] = (a_bytes[i] & !mask) | (b_bytes[i] & mask);
        new_b_bytes[i] = (b_bytes[i] & !mask) | (a_bytes[i] & mask);
    }

    *a = from_bytes(new_a_bytes);
    *b = from_bytes(new_b_bytes);
}

/// Constant-time conditional increment
///
/// Increments `value` if `condition` is true, otherwise leaves it unchanged.
/// The operation is performed in constant time to prevent timing attacks.
///
/// # Arguments
/// * `condition` - Boolean condition
/// * `value` - Value to conditionally increment
///
/// # Security
/// This function performs the increment in constant time regardless of
/// the condition value, preventing timing attacks.
pub fn constant_time_increment(condition: bool, value: &mut u8) {
    let mask = if condition { 1u8 } else { 0u8 };
    *value = value.wrapping_add(mask);
}

/// Constant-time conditional decrement
///
/// Decrements `value` if `condition` is true, otherwise leaves it unchanged.
/// The operation is performed in constant time to prevent timing attacks.
///
/// # Arguments
/// * `condition` - Boolean condition
/// * `value` - Value to conditionally decrement
///
/// # Security
/// This function performs the decrement in constant time regardless of
/// the condition value, preventing timing attacks.
pub fn constant_time_decrement(condition: bool, value: &mut u8) {
    let mask = if condition { 1u8 } else { 0u8 };
    *value = value.wrapping_sub(mask);
}

/// Constant-time conditional add
///
/// Adds `addend` to `value` if `condition` is true, otherwise leaves it unchanged.
/// The operation is performed in constant time to prevent timing attacks.
///
/// # Arguments
/// * `condition` - Boolean condition
/// * `value` - Value to conditionally add to
/// * `addend` - Value to add
///
/// # Security
/// This function performs the addition in constant time regardless of
/// the condition value, preventing timing attacks.
pub fn constant_time_add(condition: bool, value: &mut u8, addend: u8) {
    let mask = if condition { !0u8 } else { 0u8 };
    *value = value.wrapping_add(addend & mask);
}

/// Constant-time conditional subtract
///
/// Subtracts `subtrahend` from `value` if `condition` is true, otherwise leaves it unchanged.
/// The operation is performed in constant time to prevent timing attacks.
///
/// # Arguments
/// * `condition` - Boolean condition
/// * `value` - Value to conditionally subtract from
/// * `subtrahend` - Value to subtract
///
/// # Security
/// This function performs the subtraction in constant time regardless of
/// the condition value, preventing timing attacks.
pub fn constant_time_subtract(condition: bool, value: &mut u8, subtrahend: u8) {
    let mask = if condition { !0u8 } else { 0u8 };
    *value = value.wrapping_sub(subtrahend & mask);
}

/// Constant-time conditional XOR
///
/// XORs `value` with `mask` if `condition` is true, otherwise leaves it unchanged.
/// The operation is performed in constant time to prevent timing attacks.
///
/// # Arguments
/// * `condition` - Boolean condition
/// * `value` - Value to conditionally XOR
/// * `mask` - Value to XOR with
///
/// # Security
/// This function performs the XOR in constant time regardless of
/// the condition value, preventing timing attacks.
pub fn constant_time_xor(condition: bool, value: &mut u8, mask: u8) {
    let condition_mask = if condition { !0u8 } else { 0u8 };
    *value ^= mask & condition_mask;
}

/// Constant-time conditional AND
///
/// ANDs `value` with `mask` if `condition` is true, otherwise leaves it unchanged.
/// The operation is performed in constant time to prevent timing attacks.
///
/// # Arguments
/// * `condition` - Boolean condition
/// * `value` - Value to conditionally AND
/// * `mask` - Value to AND with
///
/// # Security
/// This function performs the AND in constant time regardless of
/// the condition value, preventing timing attacks.
pub fn constant_time_and(condition: bool, value: &mut u8, mask: u8) {
    let condition_mask = if condition { !0u8 } else { 0u8 };
    *value &= (mask & condition_mask) | (!condition_mask);
}

/// Constant-time conditional OR
///
/// ORs `value` with `mask` if `condition` is true, otherwise leaves it unchanged.
/// The operation is performed in constant time to prevent timing attacks.
///
/// # Arguments
/// * `condition` - Boolean condition
/// * `value` - Value to conditionally OR
/// * `mask` - Value to OR with
///
/// # Security
/// This function performs the OR in constant time regardless of
/// the condition value, preventing timing attacks.
pub fn constant_time_or(condition: bool, value: &mut u8, mask: u8) {
    let condition_mask = if condition { !0u8 } else { 0u8 };
    *value |= mask & condition_mask;
}

/// Constant-time conditional NOT
///
/// NOTs `value` if `condition` is true, otherwise leaves it unchanged.
/// The operation is performed in constant time to prevent timing attacks.
///
/// # Arguments
/// * `condition` - Boolean condition
/// * `value` - Value to conditionally NOT
///
/// # Security
/// This function performs the NOT in constant time regardless of
/// the condition value, preventing timing attacks.
pub fn constant_time_not(condition: bool, value: &mut u8) {
    let mask = if condition { !0u8 } else { 0u8 };
    *value = (*value & !mask) | (!*value & mask);
}

/// Constant-time conditional shift left
///
/// Shifts `value` left by `amount` if `condition` is true, otherwise leaves it unchanged.
/// The operation is performed in constant time to prevent timing attacks.
///
/// # Arguments
/// * `condition` - Boolean condition
/// * `value` - Value to conditionally shift
/// * `amount` - Amount to shift by
///
/// # Security
/// This function performs the shift in constant time regardless of
/// the condition value, preventing timing attacks.
pub fn constant_time_shift_left(condition: bool, value: &mut u8, amount: u8) {
    let mask = if condition { !0u8 } else { 0u8 };
    *value = (*value & !mask) | ((*value << amount) & mask);
}

/// Constant-time conditional shift right
///
/// Shifts `value` right by `amount` if `condition` is true, otherwise leaves it unchanged.
/// The operation is performed in constant time to prevent timing attacks.
///
/// # Arguments
/// * `condition` - Boolean condition
/// * `value` - Value to conditionally shift
/// * `amount` - Amount to shift by
///
/// # Security
/// This function performs the shift in constant time regardless of
/// the condition value, preventing timing attacks.
pub fn constant_time_shift_right(condition: bool, value: &mut u8, amount: u8) {
    let mask = if condition { !0u8 } else { 0u8 };
    *value = (*value & !mask) | ((*value >> amount) & mask);
}

/// Type-safe constant-time byte conversion trait
pub trait ConstantTimeBytes: Copy + Sized {
    /// Convert to bytes in constant time
    fn to_bytes(self) -> [u8; 8];
    /// Convert from bytes in constant time
    fn from_bytes(bytes: [u8; 8]) -> Self;
}

/// Helper function to convert a value to bytes with type safety
fn to_bytes<T: ConstantTimeBytes>(value: T) -> [u8; 8] {
    value.to_bytes()
}

/// Helper function to convert bytes to a value with type safety
fn from_bytes<T: ConstantTimeBytes>(bytes: [u8; 8]) -> T {
    T::from_bytes(bytes)
}

// Implement ConstantTimeBytes for common integer types
impl ConstantTimeBytes for u8 {
    fn to_bytes(self) -> [u8; 8] {
        [self, 0, 0, 0, 0, 0, 0, 0]
    }

    fn from_bytes(bytes: [u8; 8]) -> Self {
        bytes[0]
    }
}

impl ConstantTimeBytes for u16 {
    fn to_bytes(self) -> [u8; 8] {
        let bytes = self.to_le_bytes();
        [bytes[0], bytes[1], 0, 0, 0, 0, 0, 0]
    }

    fn from_bytes(bytes: [u8; 8]) -> Self {
        u16::from_le_bytes([bytes[0], bytes[1]])
    }
}

impl ConstantTimeBytes for u32 {
    fn to_bytes(self) -> [u8; 8] {
        let bytes = self.to_le_bytes();
        [bytes[0], bytes[1], bytes[2], bytes[3], 0, 0, 0, 0]
    }

    fn from_bytes(bytes: [u8; 8]) -> Self {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }
}

impl ConstantTimeBytes for u64 {
    fn to_bytes(self) -> [u8; 8] {
        self.to_le_bytes()
    }

    fn from_bytes(bytes: [u8; 8]) -> Self {
        u64::from_le_bytes(bytes)
    }
}

impl ConstantTimeBytes for i8 {
    fn to_bytes(self) -> [u8; 8] {
        (self as u8).to_bytes()
    }

    fn from_bytes(bytes: [u8; 8]) -> Self {
        u8::from_bytes(bytes) as i8
    }
}

impl ConstantTimeBytes for i16 {
    fn to_bytes(self) -> [u8; 8] {
        (self as u16).to_bytes()
    }

    fn from_bytes(bytes: [u8; 8]) -> Self {
        u16::from_bytes(bytes) as i16
    }
}

impl ConstantTimeBytes for i32 {
    fn to_bytes(self) -> [u8; 8] {
        (self as u32).to_bytes()
    }

    fn from_bytes(bytes: [u8; 8]) -> Self {
        u32::from_bytes(bytes) as i32
    }
}

impl ConstantTimeBytes for i64 {
    fn to_bytes(self) -> [u8; 8] {
        (self as u64).to_bytes()
    }

    fn from_bytes(bytes: [u8; 8]) -> Self {
        u64::from_bytes(bytes) as i64
    }
}

impl ConstantTimeBytes for bool {
    fn to_bytes(self) -> [u8; 8] {
        [if self { 1 } else { 0 }, 0, 0, 0, 0, 0, 0, 0]
    }

    fn from_bytes(bytes: [u8; 8]) -> Self {
        bytes[0] != 0
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
        assert!(!constant_time_eq(b, c));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        let a = b"hello";
        let b = b"hell";

        assert!(!constant_time_eq(a, b));
    }

    #[test]
    fn test_constant_time_select() {
        let a = 42u8;
        let b = 24u8;

        assert_eq!(constant_time_select(true, a, b), a);
        assert_eq!(constant_time_select(false, a, b), b);
    }

    #[test]
    fn test_constant_time_copy() {
        let src = [1, 2, 3, 4];
        let mut dst = [0, 0, 0, 0];

        constant_time_copy(true, &src, &mut dst);
        assert_eq!(dst, src);

        let mut dst2 = [5, 6, 7, 8];
        constant_time_copy(false, &src, &mut dst2);
        assert_eq!(dst2, [5, 6, 7, 8]);
    }

    #[test]
    fn test_constant_time_zero() {
        let mut data = [1, 2, 3, 4];

        constant_time_zero(true, &mut data);
        assert_eq!(data, [0, 0, 0, 0]);

        let mut data2 = [1, 2, 3, 4];
        constant_time_zero(false, &mut data2);
        assert_eq!(data2, [1, 2, 3, 4]);
    }

    #[test]
    fn test_constant_time_swap() {
        let mut a = 42u8;
        let mut b = 24u8;

        constant_time_swap(true, &mut a, &mut b);
        assert_eq!(a, 24);
        assert_eq!(b, 42);

        let mut c = 10u8;
        let mut d = 20u8;

        constant_time_swap(false, &mut c, &mut d);
        assert_eq!(c, 10);
        assert_eq!(d, 20);
    }

    #[test]
    fn test_constant_time_increment() {
        let mut value = 5u8;

        constant_time_increment(true, &mut value);
        assert_eq!(value, 6);

        constant_time_increment(false, &mut value);
        assert_eq!(value, 6);
    }

    #[test]
    fn test_constant_time_decrement() {
        let mut value = 5u8;

        constant_time_decrement(true, &mut value);
        assert_eq!(value, 4);

        constant_time_decrement(false, &mut value);
        assert_eq!(value, 4);
    }

    #[test]
    fn test_constant_time_add() {
        let mut value = 5u8;

        constant_time_add(true, &mut value, 3);
        assert_eq!(value, 8);

        constant_time_add(false, &mut value, 2);
        assert_eq!(value, 8);
    }

    #[test]
    fn test_constant_time_subtract() {
        let mut value = 10u8;

        constant_time_subtract(true, &mut value, 3);
        assert_eq!(value, 7);

        constant_time_subtract(false, &mut value, 2);
        assert_eq!(value, 7);
    }

    #[test]
    fn test_constant_time_xor() {
        let mut value = 0b1010u8;

        constant_time_xor(true, &mut value, 0b1100);
        assert_eq!(value, 0b0110);

        constant_time_xor(false, &mut value, 0b1111);
        assert_eq!(value, 0b0110);
    }

    #[test]
    fn test_constant_time_and() {
        let mut value = 0b1010u8;

        constant_time_and(true, &mut value, 0b1100);
        assert_eq!(value, 0b1000);

        constant_time_and(false, &mut value, 0b1111);
        assert_eq!(value, 0b1000);
    }

    #[test]
    fn test_constant_time_or() {
        let mut value = 0b1010u8;

        constant_time_or(true, &mut value, 0b1100);
        assert_eq!(value, 0b1110);

        constant_time_or(false, &mut value, 0b0001);
        assert_eq!(value, 0b1110);
    }

    #[test]
    fn test_constant_time_not() {
        let mut value = 0b1010u8;

        constant_time_not(true, &mut value);
        assert_eq!(value, !0b1010u8); // Should be 0b11110101 (245)

        constant_time_not(false, &mut value);
        assert_eq!(value, !0b1010u8); // Should remain 0b11110101 (245)
    }

    #[test]
    fn test_constant_time_shift_left() {
        let mut value = 0b0001u8;

        constant_time_shift_left(true, &mut value, 2);
        assert_eq!(value, 0b0100);

        constant_time_shift_left(false, &mut value, 1);
        assert_eq!(value, 0b0100);
    }

    #[test]
    fn test_constant_time_shift_right() {
        let mut value = 0b0100u8;

        constant_time_shift_right(true, &mut value, 2);
        assert_eq!(value, 0b0001);

        constant_time_shift_right(false, &mut value, 1);
        assert_eq!(value, 0b0001);
    }
}
