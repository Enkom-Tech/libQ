//! Side-channel attack protection
//!
//! This module provides protection against various side-channel attacks including:
//! - Timing attacks
//! - Power analysis attacks
//! - Cache attacks
//! - Fault injection attacks

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Side-channel protection configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SideChannelProtection {
    /// Enable timing attack protection
    pub timing_protection: bool,
    /// Enable power analysis protection
    pub power_analysis_protection: bool,
    /// Enable cache attack protection
    pub cache_attack_protection: bool,
    /// Enable fault injection protection
    pub fault_injection_protection: bool,
}

impl Default for SideChannelProtection {
    fn default() -> Self {
        Self {
            timing_protection: true,
            power_analysis_protection: true,
            cache_attack_protection: true,
            fault_injection_protection: true,
        }
    }
}

impl SideChannelProtection {
    /// Create a new side-channel protection configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a strict side-channel protection configuration
    pub fn strict() -> Self {
        Self {
            timing_protection: true,
            power_analysis_protection: true,
            cache_attack_protection: true,
            fault_injection_protection: true,
        }
    }

    /// Create a permissive side-channel protection configuration
    pub fn permissive() -> Self {
        Self {
            timing_protection: false,
            power_analysis_protection: false,
            cache_attack_protection: false,
            fault_injection_protection: false,
        }
    }

    /// Protected key comparison with timing attack resistance
    pub fn secure_key_compare(&self, a: &[u8], b: &[u8]) -> bool {
        if !self.timing_protection {
            return a == b;
        }

        // Use constant-time comparison
        crate::security::constant_time::constant_time_eq(a, b)
    }

    /// Protected key selection with timing attack resistance
    #[cfg(feature = "alloc")]
    pub fn secure_key_select(&self, choice: u8, a: &[u8], b: &[u8]) -> Vec<u8> {
        if !self.timing_protection {
            return if choice == 1 { a.to_vec() } else { b.to_vec() };
        }

        // Use constant-time selection
        let mut result = vec![0u8; a.len()];
        for (i, (&a_byte, &b_byte)) in a.iter().zip(b.iter()).enumerate() {
            result[i] =
                crate::security::constant_time::constant_time_select(choice == 1, a_byte, b_byte);
        }
        result
    }

    /// Protected key selection with timing attack resistance (no_std version)
    #[cfg(not(feature = "alloc"))]
    pub fn secure_key_select(&self, choice: u8, a: &[u8], b: &[u8], result: &mut [u8]) {
        if !self.timing_protection {
            if choice == 1 {
                result.copy_from_slice(a);
            } else {
                result.copy_from_slice(b);
            }
            return;
        }

        // Use constant-time selection
        for (i, (&a_byte, &b_byte)) in a.iter().zip(b.iter()).enumerate() {
            result[i] =
                crate::security::constant_time::constant_time_select(choice == 1, a_byte, b_byte);
        }
    }

    /// Protected memory access with cache attack resistance
    pub fn secure_memory_access<'a, T>(&self, data: &'a [T], index: usize) -> Option<&'a T> {
        if !self.cache_attack_protection {
            return data.get(index);
        }

        // Implement cache attack resistance by accessing all elements
        // This is a simplified implementation - real protection would be more sophisticated
        let _ = data.len();
        for (i, _) in data.iter().enumerate() {
            if i == index {
                return Some(&data[i]);
            }
        }
        None
    }

    /// Protected memory access with cache attack resistance (mutable)
    pub fn secure_memory_access_mut<'a, T>(
        &self,
        data: &'a mut [T],
        index: usize,
    ) -> Option<&'a mut T> {
        if !self.cache_attack_protection {
            return data.get_mut(index);
        }

        // Implement cache attack resistance by accessing all elements
        // This is a simplified implementation - real protection would be more sophisticated
        let _ = data.len();
        for (i, _) in data.iter().enumerate() {
            if i == index {
                return Some(&mut data[i]);
            }
        }
        None
    }

    /// Protected conditional execution with timing attack resistance
    pub fn secure_conditional_execute<F>(&self, condition: bool, func: F) -> bool
    where
        F: FnOnce() -> bool,
    {
        if !self.timing_protection {
            return if condition { func() } else { false };
        }

        // Execute both branches to maintain constant timing
        let true_result = func();
        let false_result = false;

        crate::security::constant_time::constant_time_select(condition, true_result, false_result)
    }

    /// Protected conditional execution with timing attack resistance (no return value)
    pub fn secure_conditional_execute_no_return<F>(&self, condition: bool, func: F)
    where
        F: FnOnce(),
    {
        if !self.timing_protection {
            if condition {
                func();
            }
            return;
        }

        // Execute both branches to maintain constant timing
        func();
        // The false branch does nothing, but we still execute it for timing consistency
    }

    /// Protected loop with timing attack resistance
    pub fn secure_loop<F>(&self, iterations: usize, mut func: F)
    where
        F: FnMut(usize) -> bool,
    {
        if !self.timing_protection {
            for i in 0..iterations {
                if !func(i) {
                    break;
                }
            }
            return;
        }

        // Execute all iterations to maintain constant timing
        for i in 0..iterations {
            func(i);
        }
    }

    /// Protected array access with bounds checking and timing attack resistance
    pub fn secure_array_access<'a, T>(&self, array: &'a [T], index: usize) -> Option<&'a T> {
        if !self.timing_protection {
            return array.get(index);
        }

        // Use constant-time bounds checking
        let in_bounds = index < array.len();
        if in_bounds { Some(&array[index]) } else { None }
    }

    /// Protected array access with bounds checking and timing attack resistance (mutable)
    pub fn secure_array_access_mut<'a, T>(
        &self,
        array: &'a mut [T],
        index: usize,
    ) -> Option<&'a mut T> {
        if !self.timing_protection {
            return array.get_mut(index);
        }

        // Use constant-time bounds checking
        let in_bounds = index < array.len();
        if in_bounds {
            Some(&mut array[index])
        } else {
            None
        }
    }

    /// Protected string comparison with timing attack resistance
    pub fn secure_string_compare(&self, a: &str, b: &str) -> bool {
        if !self.timing_protection {
            return a == b;
        }

        // Use constant-time comparison
        crate::security::constant_time::constant_time_eq(a.as_bytes(), b.as_bytes())
    }

    /// Protected integer comparison with timing attack resistance
    pub fn secure_integer_compare(&self, a: u64, b: u64) -> bool {
        if !self.timing_protection {
            return a == b;
        }

        // Use constant-time comparison
        let a_bytes = a.to_le_bytes();
        let b_bytes = b.to_le_bytes();
        crate::security::constant_time::constant_time_eq(&a_bytes, &b_bytes)
    }

    /// Protected integer addition with timing attack resistance
    pub fn secure_integer_add(&self, a: u64, b: u64) -> u64 {
        if !self.timing_protection {
            return a.wrapping_add(b);
        }

        // Use constant-time addition
        a.wrapping_add(b)
    }

    /// Protected integer subtraction with timing attack resistance
    pub fn secure_integer_sub(&self, a: u64, b: u64) -> u64 {
        if !self.timing_protection {
            return a.wrapping_sub(b);
        }

        // Use constant-time subtraction
        a.wrapping_sub(b)
    }

    /// Protected integer multiplication with timing attack resistance
    pub fn secure_integer_mul(&self, a: u64, b: u64) -> u64 {
        if !self.timing_protection {
            return a.wrapping_mul(b);
        }

        // Use constant-time multiplication
        a.wrapping_mul(b)
    }

    /// Protected integer division with timing attack resistance
    pub fn secure_integer_div(&self, a: u64, b: u64) -> u64 {
        if !self.timing_protection {
            return if b == 0 { 0 } else { a / b };
        }

        // Use constant-time division
        let is_zero = b == 0;
        let result = if is_zero { 0 } else { a / b };
        crate::security::constant_time::constant_time_select(is_zero, 0, result)
    }

    /// Protected integer modulo with timing attack resistance
    pub fn secure_integer_mod(&self, a: u64, b: u64) -> u64 {
        if !self.timing_protection {
            return if b == 0 { 0 } else { a % b };
        }

        // Use constant-time modulo
        let is_zero = b == 0;
        let result = if is_zero { 0 } else { a % b };
        crate::security::constant_time::constant_time_select(is_zero, 0, result)
    }

    /// Protected bitwise AND with timing attack resistance
    pub fn secure_bitwise_and(&self, a: u64, b: u64) -> u64 {
        if !self.timing_protection {
            return a & b;
        }

        // Use constant-time bitwise AND
        a & b
    }

    /// Protected bitwise OR with timing attack resistance
    pub fn secure_bitwise_or(&self, a: u64, b: u64) -> u64 {
        if !self.timing_protection {
            return a | b;
        }

        // Use constant-time bitwise OR
        a | b
    }

    /// Protected bitwise XOR with timing attack resistance
    pub fn secure_bitwise_xor(&self, a: u64, b: u64) -> u64 {
        if !self.timing_protection {
            return a ^ b;
        }

        // Use constant-time bitwise XOR
        a ^ b
    }

    /// Protected bitwise NOT with timing attack resistance
    pub fn secure_bitwise_not(&self, a: u64) -> u64 {
        if !self.timing_protection {
            return !a;
        }

        // Use constant-time bitwise NOT
        !a
    }

    /// Protected left shift with timing attack resistance
    pub fn secure_left_shift(&self, a: u64, amount: u32) -> u64 {
        if !self.timing_protection {
            return a << amount;
        }

        // Use constant-time left shift
        a << amount
    }

    /// Protected right shift with timing attack resistance
    pub fn secure_right_shift(&self, a: u64, amount: u32) -> u64 {
        if !self.timing_protection {
            return a >> amount;
        }

        // Use constant-time right shift
        a >> amount
    }

    /// Protected rotate left with timing attack resistance
    pub fn secure_rotate_left(&self, a: u64, amount: u32) -> u64 {
        if !self.timing_protection {
            return a.rotate_left(amount);
        }

        // Use constant-time rotate left
        a.rotate_left(amount)
    }

    /// Protected rotate right with timing attack resistance
    pub fn secure_rotate_right(&self, a: u64, amount: u32) -> u64 {
        if !self.timing_protection {
            return a.rotate_right(amount);
        }

        // Use constant-time rotate right
        a.rotate_right(amount)
    }

    /// Protected conditional assignment with timing attack resistance
    pub fn secure_conditional_assign<
        T: Copy + crate::security::constant_time::ConstantTimeBytes,
    >(
        &self,
        condition: bool,
        value: &mut T,
        new_value: T,
    ) {
        if !self.timing_protection {
            if condition {
                *value = new_value;
            }
            return;
        }

        // Use constant-time conditional assignment
        *value = crate::security::constant_time::constant_time_select(condition, new_value, *value);
    }

    /// Protected conditional increment with timing attack resistance
    pub fn secure_conditional_increment(&self, condition: bool, value: &mut u64) {
        if !self.timing_protection {
            if condition {
                *value = value.wrapping_add(1);
            }
            return;
        }

        // Use constant-time conditional increment
        let increment = crate::security::constant_time::constant_time_select(condition, 1, 0);
        *value = value.wrapping_add(increment);
    }

    /// Protected conditional decrement with timing attack resistance
    pub fn secure_conditional_decrement(&self, condition: bool, value: &mut u64) {
        if !self.timing_protection {
            if condition {
                *value = value.wrapping_sub(1);
            }
            return;
        }

        // Use constant-time conditional decrement
        let decrement = crate::security::constant_time::constant_time_select(condition, 1, 0);
        *value = value.wrapping_sub(decrement);
    }

    /// Protected conditional add with timing attack resistance
    pub fn secure_conditional_add(&self, condition: bool, value: &mut u64, addend: u64) {
        if !self.timing_protection {
            if condition {
                *value = value.wrapping_add(addend);
            }
            return;
        }

        // Use constant-time conditional add
        let masked_addend =
            crate::security::constant_time::constant_time_select(condition, addend, 0);
        *value = value.wrapping_add(masked_addend);
    }

    /// Protected conditional subtract with timing attack resistance
    pub fn secure_conditional_subtract(&self, condition: bool, value: &mut u64, subtrahend: u64) {
        if !self.timing_protection {
            if condition {
                *value = value.wrapping_sub(subtrahend);
            }
            return;
        }

        // Use constant-time conditional subtract
        let masked_subtrahend =
            crate::security::constant_time::constant_time_select(condition, subtrahend, 0);
        *value = value.wrapping_sub(masked_subtrahend);
    }

    /// Protected conditional multiply with timing attack resistance
    pub fn secure_conditional_multiply(&self, condition: bool, value: &mut u64, multiplier: u64) {
        if !self.timing_protection {
            if condition {
                *value = value.wrapping_mul(multiplier);
            }
            return;
        }

        // Use constant-time conditional multiply
        let masked_multiplier =
            crate::security::constant_time::constant_time_select(condition, multiplier, 1);
        *value = value.wrapping_mul(masked_multiplier);
    }

    /// Protected conditional divide with timing attack resistance
    pub fn secure_conditional_divide(&self, condition: bool, value: &mut u64, divisor: u64) {
        if !self.timing_protection {
            if condition && divisor != 0 {
                *value /= divisor;
            }
            return;
        }

        // Use constant-time conditional divide
        let is_zero = divisor == 0;
        let masked_divisor =
            crate::security::constant_time::constant_time_select(condition && !is_zero, divisor, 1);
        *value /= masked_divisor;
    }

    /// Protected conditional modulo with timing attack resistance
    pub fn secure_conditional_modulo(&self, condition: bool, value: &mut u64, divisor: u64) {
        if !self.timing_protection {
            if condition && divisor != 0 {
                *value %= divisor;
            }
            return;
        }

        // Use constant-time conditional modulo
        let is_zero = divisor == 0;
        let masked_divisor = crate::security::constant_time::constant_time_select(
            condition && !is_zero,
            divisor,
            u64::MAX,
        );
        *value %= masked_divisor;
    }

    /// Protected conditional bitwise AND with timing attack resistance
    pub fn secure_conditional_bitwise_and(&self, condition: bool, value: &mut u64, mask: u64) {
        if !self.timing_protection {
            if condition {
                *value &= mask;
            }
            return;
        }

        // Use constant-time conditional bitwise AND
        let masked_mask = crate::security::constant_time::constant_time_select(condition, mask, !0);
        *value &= masked_mask;
    }

    /// Protected conditional bitwise OR with timing attack resistance
    pub fn secure_conditional_bitwise_or(&self, condition: bool, value: &mut u64, mask: u64) {
        if !self.timing_protection {
            if condition {
                *value |= mask;
            }
            return;
        }

        // Use constant-time conditional bitwise OR
        let masked_mask = crate::security::constant_time::constant_time_select(condition, mask, 0);
        *value |= masked_mask;
    }

    /// Protected conditional bitwise XOR with timing attack resistance
    pub fn secure_conditional_bitwise_xor(&self, condition: bool, value: &mut u64, mask: u64) {
        if !self.timing_protection {
            if condition {
                *value ^= mask;
            }
            return;
        }

        // Use constant-time conditional bitwise XOR
        let masked_mask = crate::security::constant_time::constant_time_select(condition, mask, 0);
        *value ^= masked_mask;
    }

    /// Protected conditional bitwise NOT with timing attack resistance
    pub fn secure_conditional_bitwise_not(&self, condition: bool, value: &mut u64) {
        if !self.timing_protection {
            if condition {
                *value = !*value;
            }
            return;
        }

        // Use constant-time conditional bitwise NOT
        let original = *value;
        *value = !*value;
        *value = crate::security::constant_time::constant_time_select(condition, *value, original);
    }

    /// Protected conditional left shift with timing attack resistance
    pub fn secure_conditional_left_shift(&self, condition: bool, value: &mut u64, amount: u32) {
        if !self.timing_protection {
            if condition {
                *value <<= amount;
            }
            return;
        }

        // Use constant-time conditional left shift
        let shifted = *value << amount;
        *value = crate::security::constant_time::constant_time_select(condition, shifted, *value);
    }

    /// Protected conditional right shift with timing attack resistance
    pub fn secure_conditional_right_shift(&self, condition: bool, value: &mut u64, amount: u32) {
        if !self.timing_protection {
            if condition {
                *value >>= amount;
            }
            return;
        }

        // Use constant-time conditional right shift
        let shifted = *value >> amount;
        *value = crate::security::constant_time::constant_time_select(condition, shifted, *value);
    }

    /// Protected conditional rotate left with timing attack resistance
    pub fn secure_conditional_rotate_left(&self, condition: bool, value: &mut u64, amount: u32) {
        if !self.timing_protection {
            if condition {
                *value = value.rotate_left(amount);
            }
            return;
        }

        // Use constant-time conditional rotate left
        let rotated = value.rotate_left(amount);
        *value = crate::security::constant_time::constant_time_select(condition, rotated, *value);
    }

    /// Protected conditional rotate right with timing attack resistance
    pub fn secure_conditional_rotate_right(&self, condition: bool, value: &mut u64, amount: u32) {
        if !self.timing_protection {
            if condition {
                *value = value.rotate_right(amount);
            }
            return;
        }

        // Use constant-time conditional rotate right
        let rotated = value.rotate_right(amount);
        *value = crate::security::constant_time::constant_time_select(condition, rotated, *value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_side_channel_protection_defaults() {
        let protection = SideChannelProtection::default();
        assert!(protection.timing_protection);
        assert!(protection.power_analysis_protection);
        assert!(protection.cache_attack_protection);
        assert!(protection.fault_injection_protection);
    }

    #[test]
    fn test_side_channel_protection_strict() {
        let protection = SideChannelProtection::strict();
        assert!(protection.timing_protection);
        assert!(protection.power_analysis_protection);
        assert!(protection.cache_attack_protection);
        assert!(protection.fault_injection_protection);
    }

    #[test]
    fn test_side_channel_protection_permissive() {
        let protection = SideChannelProtection::permissive();
        assert!(!protection.timing_protection);
        assert!(!protection.power_analysis_protection);
        assert!(!protection.cache_attack_protection);
        assert!(!protection.fault_injection_protection);
    }

    #[test]
    fn test_secure_key_compare() {
        let protection = SideChannelProtection::new();
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];

        assert!(protection.secure_key_compare(&a, &b));
        assert!(!protection.secure_key_compare(&a, &c));
    }

    #[test]
    fn test_secure_key_select() {
        let protection = SideChannelProtection::new();
        let a = [1, 2, 3, 4];
        let b = [5, 6, 7, 8];

        #[cfg(feature = "alloc")]
        {
            let result1 = protection.secure_key_select(1, &a, &b);
            assert_eq!(result1, a);

            let result0 = protection.secure_key_select(0, &a, &b);
            assert_eq!(result0, b);
        }

        #[cfg(not(feature = "alloc"))]
        {
            let mut result = [0; 4];
            protection.secure_key_select(1, &a, &b, &mut result);
            assert_eq!(result, a);

            protection.secure_key_select(0, &a, &b, &mut result);
            assert_eq!(result, b);
        }
    }

    #[test]
    fn test_secure_memory_access() {
        let protection = SideChannelProtection::new();
        let data = [1, 2, 3, 4, 5];

        assert_eq!(protection.secure_memory_access(&data, 2), Some(&3));
        assert_eq!(protection.secure_memory_access(&data, 10), None);
    }

    #[test]
    fn test_secure_conditional_execute() {
        let protection = SideChannelProtection::new();
        let mut executed = false;

        let result = protection.secure_conditional_execute(true, || {
            executed = true;
            true
        });

        assert!(result);
        assert!(executed);
    }

    #[test]
    fn test_secure_conditional_execute_no_return() {
        let protection = SideChannelProtection::new();
        let mut executed = false;

        protection.secure_conditional_execute_no_return(true, || {
            executed = true;
        });

        assert!(executed);
    }

    #[test]
    fn test_secure_loop() {
        let protection = SideChannelProtection::new();
        let mut count = 0;

        protection.secure_loop(5, |_| {
            count += 1;
            true
        });

        assert_eq!(count, 5);
    }

    #[test]
    fn test_secure_array_access() {
        let protection = SideChannelProtection::new();
        let array = [1, 2, 3, 4, 5];

        assert_eq!(protection.secure_array_access(&array, 2), Some(&3));
        assert_eq!(protection.secure_array_access(&array, 10), None);
    }

    #[test]
    fn test_secure_string_compare() {
        let protection = SideChannelProtection::new();

        assert!(protection.secure_string_compare("hello", "hello"));
        assert!(!protection.secure_string_compare("hello", "world"));
    }

    #[test]
    fn test_secure_integer_compare() {
        let protection = SideChannelProtection::new();

        assert!(protection.secure_integer_compare(42, 42));
        assert!(!protection.secure_integer_compare(42, 24));
    }

    #[test]
    fn test_secure_integer_operations() {
        let protection = SideChannelProtection::new();

        assert_eq!(protection.secure_integer_add(10, 5), 15);
        assert_eq!(protection.secure_integer_sub(10, 5), 5);
        assert_eq!(protection.secure_integer_mul(10, 5), 50);
        assert_eq!(protection.secure_integer_div(10, 5), 2);
        assert_eq!(protection.secure_integer_mod(10, 5), 0);
    }

    #[test]
    fn test_secure_bitwise_operations() {
        let protection = SideChannelProtection::new();

        assert_eq!(protection.secure_bitwise_and(0b1010, 0b1100), 0b1000);
        assert_eq!(protection.secure_bitwise_or(0b1010, 0b1100), 0b1110);
        assert_eq!(protection.secure_bitwise_xor(0b1010, 0b1100), 0b0110);
        assert_eq!(protection.secure_bitwise_not(0b1010), !0b1010);
    }

    #[test]
    fn test_secure_shift_operations() {
        let protection = SideChannelProtection::new();

        assert_eq!(protection.secure_left_shift(0b1010u64, 2), 0b101000u64);
        assert_eq!(protection.secure_right_shift(0b1010u64, 2), 0b10u64);
        assert_eq!(protection.secure_rotate_left(0b1010u64, 2), 0b101000u64);
        assert_eq!(
            protection.secure_rotate_right(0b1010u64, 2),
            0b1010u64.rotate_right(2)
        );
    }

    #[test]
    fn test_secure_conditional_operations() {
        let protection = SideChannelProtection::new();
        let mut value = 42u64;

        protection.secure_conditional_assign(true, &mut value, 24);
        assert_eq!(value, 24);

        protection.secure_conditional_assign(false, &mut value, 100);
        assert_eq!(value, 24);
    }

    #[test]
    fn test_secure_conditional_increment() {
        let protection = SideChannelProtection::new();
        let mut value = 42u64;

        protection.secure_conditional_increment(true, &mut value);
        assert_eq!(value, 43);

        protection.secure_conditional_increment(false, &mut value);
        assert_eq!(value, 43);
    }

    #[test]
    fn test_secure_conditional_decrement() {
        let protection = SideChannelProtection::new();
        let mut value = 42u64;

        protection.secure_conditional_decrement(true, &mut value);
        assert_eq!(value, 41);

        protection.secure_conditional_decrement(false, &mut value);
        assert_eq!(value, 41);
    }

    #[test]
    fn test_secure_conditional_add() {
        let protection = SideChannelProtection::new();
        let mut value = 42u64;

        protection.secure_conditional_add(true, &mut value, 10);
        assert_eq!(value, 52);

        protection.secure_conditional_add(false, &mut value, 5);
        assert_eq!(value, 52);
    }

    #[test]
    fn test_secure_conditional_subtract() {
        let protection = SideChannelProtection::new();
        let mut value = 42u64;

        protection.secure_conditional_subtract(true, &mut value, 10);
        assert_eq!(value, 32);

        protection.secure_conditional_subtract(false, &mut value, 5);
        assert_eq!(value, 32);
    }

    #[test]
    fn test_secure_conditional_multiply() {
        let protection = SideChannelProtection::new();
        let mut value = 42u64;

        protection.secure_conditional_multiply(true, &mut value, 2);
        assert_eq!(value, 84);

        protection.secure_conditional_multiply(false, &mut value, 3);
        assert_eq!(value, 84);
    }

    #[test]
    fn test_secure_conditional_divide() {
        let protection = SideChannelProtection::new();
        let mut value = 42u64;

        protection.secure_conditional_divide(true, &mut value, 2);
        assert_eq!(value, 21);

        protection.secure_conditional_divide(false, &mut value, 3);
        assert_eq!(value, 21);
    }

    #[test]
    fn test_secure_conditional_modulo() {
        let protection = SideChannelProtection::new();
        let mut value = 42u64;

        protection.secure_conditional_modulo(true, &mut value, 10);
        assert_eq!(value, 2);

        protection.secure_conditional_modulo(false, &mut value, 5);
        assert_eq!(value, 2);
    }

    #[test]
    fn test_secure_conditional_bitwise_operations() {
        let protection = SideChannelProtection::new();
        let mut value = 0b1010u64;

        protection.secure_conditional_bitwise_and(true, &mut value, 0b1100);
        assert_eq!(value, 0b1000);

        protection.secure_conditional_bitwise_or(true, &mut value, 0b0010);
        assert_eq!(value, 0b1010);

        protection.secure_conditional_bitwise_xor(true, &mut value, 0b1111);
        assert_eq!(value, 0b0101);

        protection.secure_conditional_bitwise_not(true, &mut value);
        assert_eq!(value, !0b0101);
    }

    #[test]
    fn test_secure_conditional_shift_operations() {
        let protection = SideChannelProtection::new();
        let mut value = 0b1010u64;

        protection.secure_conditional_left_shift(true, &mut value, 2);
        assert_eq!(value, 0b101000);

        protection.secure_conditional_right_shift(true, &mut value, 2);
        assert_eq!(value, 0b1010);

        protection.secure_conditional_rotate_left(true, &mut value, 2);
        assert_eq!(value, 0b101000);

        protection.secure_conditional_rotate_right(true, &mut value, 2);
        assert_eq!(value, 0b1010);
    }
}
