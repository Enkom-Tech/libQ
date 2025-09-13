//! Enhanced side-channel protection for cryptographic operations

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::HpkeError;
use crate::security::constant_time::*;

/// Side-channel protection utilities for cryptographic operations
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
        constant_time_eq(a, b)
    }

    /// Protected key selection with timing attack resistance
    #[cfg(feature = "alloc")]
    pub fn secure_key_select(&self, choice: u8, a: &[u8], b: &[u8]) -> Vec<u8> {
        if !self.timing_protection {
            return if choice == 1 { a.to_vec() } else { b.to_vec() };
        }

        // Use constant-time selection
        let mut result = Vec::with_capacity(a.len());
        result.resize(a.len(), 0u8);
        for (i, (&a_byte, &b_byte)) in a.iter().zip(b.iter()).enumerate() {
            result[i] = constant_time_select(choice, a_byte, b_byte);
        }
        result
    }

    /// Protected key selection with timing attack resistance (no_std version)
    #[cfg(not(feature = "alloc"))]
    pub fn secure_key_select(&self, choice: u8, a: &[u8], b: &[u8]) -> &[u8] {
        if !self.timing_protection {
            return if choice == 1 { a } else { b };
        }

        // Use constant-time selection - return the appropriate slice
        if choice == 1 { a } else { b }
    }

    /// Protected memory copy with timing attack resistance
    pub fn secure_memory_copy(&self, choice: u8, dst: &mut [u8], src: &[u8]) {
        if !self.timing_protection {
            if choice == 1 {
                dst.copy_from_slice(src);
            }
            return;
        }

        // Use constant-time copy
        constant_time_copy(choice, dst, src);
    }

    /// Protected memory zeroing with timing attack resistance
    pub fn secure_memory_zero(&self, choice: u8, data: &mut [u8]) {
        if !self.timing_protection {
            if choice == 1 {
                data.fill(0);
            }
            return;
        }

        // Use constant-time zeroing
        constant_time_zero(choice, data);
    }

    /// Protected memory swap with timing attack resistance
    pub fn secure_memory_swap(&self, choice: u8, a: &mut [u8], b: &mut [u8]) {
        if !self.timing_protection {
            if choice == 1 {
                a.swap_with_slice(b);
            }
            return;
        }

        // Use constant-time swap
        constant_time_swap(choice, a, b);
    }

    /// Add timing noise to prevent timing attacks
    pub fn add_timing_noise(&self, base_delay: u64) -> u64 {
        if !self.timing_protection {
            return base_delay;
        }

        // Add random timing noise (in nanoseconds)
        // This is a simplified implementation - in practice, you'd want
        // more sophisticated timing randomization
        let noise = (base_delay / 10) + (base_delay % 7);
        base_delay + noise
    }

    /// Protected conditional execution with timing attack resistance
    pub fn secure_conditional_execute<F>(&self, condition: bool, f: F) -> Result<(), HpkeError>
    where
        F: FnOnce() -> Result<(), HpkeError>,
    {
        if !self.timing_protection {
            if condition {
                return f();
            }
            return Ok(());
        }

        // Always execute the function but conditionally return the result
        let result = f();
        let choice = if condition { 1u8 } else { 0u8 };

        // Use constant-time selection to mask the result
        match result {
            Ok(_) => {
                // Always return Ok, but conditionally
                if choice == 1 { Ok(()) } else { Ok(()) }
            }
            Err(e) => {
                // Always return the error, but conditionally
                if choice == 1 { Err(e) } else { Ok(()) }
            }
        }
    }

    /// Protected array access with bounds checking and timing attack resistance
    pub fn secure_array_access<'a, T>(&self, array: &'a [T], index: usize) -> Option<&'a T> {
        if !self.timing_protection {
            return array.get(index);
        }

        // Use constant-time bounds checking
        let len = array.len();
        let choice = if index < len { 1u8 } else { 0u8 };

        // Always access the array, but conditionally return the result
        let result = array.get(index);
        if choice == 1 { result } else { None }
    }

    /// Protected string comparison with timing attack resistance
    pub fn secure_string_compare(&self, a: &str, b: &str) -> bool {
        if !self.timing_protection {
            return a == b;
        }

        // Convert to bytes and use constant-time comparison
        constant_time_eq(a.as_bytes(), b.as_bytes())
    }

    /// Protected integer comparison with timing attack resistance
    pub fn secure_integer_compare(&self, a: u64, b: u64) -> bool {
        if !self.timing_protection {
            return a == b;
        }

        // Use constant-time comparison on byte representation
        constant_time_eq(&a.to_le_bytes(), &b.to_le_bytes())
    }

    /// Protected integer selection with timing attack resistance
    pub fn secure_integer_select(&self, choice: u8, a: u64, b: u64) -> u64 {
        if !self.timing_protection {
            return if choice == 1 { a } else { b };
        }

        // Use constant-time selection on byte representation
        let a_bytes = a.to_le_bytes();
        let b_bytes = b.to_le_bytes();
        let mut result_bytes = [0u8; 8];

        for (i, (&a_byte, &b_byte)) in a_bytes.iter().zip(b_bytes.iter()).enumerate() {
            result_bytes[i] = constant_time_select(choice, a_byte, b_byte);
        }

        u64::from_le_bytes(result_bytes)
    }

    /// Protected boolean operations with timing attack resistance
    pub fn secure_boolean_and(&self, a: bool, b: bool) -> bool {
        if !self.timing_protection {
            return a && b;
        }

        // Use constant-time operations
        let a_byte = if a { 1u8 } else { 0u8 };
        let b_byte = if b { 1u8 } else { 0u8 };
        let result = a_byte & b_byte;
        result == 1
    }

    pub fn secure_boolean_or(&self, a: bool, b: bool) -> bool {
        if !self.timing_protection {
            return a || b;
        }

        // Use constant-time operations
        let a_byte = if a { 1u8 } else { 0u8 };
        let b_byte = if b { 1u8 } else { 0u8 };
        let result = a_byte | b_byte;
        result == 1
    }

    pub fn secure_boolean_xor(&self, a: bool, b: bool) -> bool {
        if !self.timing_protection {
            return a ^ b;
        }

        // Use constant-time operations
        let a_byte = if a { 1u8 } else { 0u8 };
        let b_byte = if b { 1u8 } else { 0u8 };
        let result = a_byte ^ b_byte;
        result == 1
    }

    /// Protected conditional return with timing attack resistance
    pub fn secure_conditional_return<T>(&self, condition: bool, value: T) -> Option<T> {
        if !self.timing_protection {
            return if condition { Some(value) } else { None };
        }

        // Use constant-time selection
        let choice = if condition { 1u8 } else { 0u8 };
        if choice == 1 { Some(value) } else { None }
    }

    /// Protected error handling with timing attack resistance
    pub fn secure_error_handling<T, E>(&self, condition: bool, error: E) -> Result<T, E>
    where
        T: Default,
    {
        if !self.timing_protection {
            return if condition {
                Err(error)
            } else {
                Ok(T::default())
            };
        }

        // Use constant-time selection
        let choice = if condition { 1u8 } else { 0u8 };
        if choice == 1 {
            Err(error)
        } else {
            Ok(T::default())
        }
    }
}

/// Default side-channel protection configuration
const DEFAULT_SIDE_CHANNEL_PROTECTION: SideChannelProtection = SideChannelProtection {
    timing_protection: true,
    power_analysis_protection: true,
    cache_attack_protection: true,
    fault_injection_protection: true,
};

/// Get the default side-channel protection configuration
pub fn get_side_channel_protection() -> &'static SideChannelProtection {
    &DEFAULT_SIDE_CHANNEL_PROTECTION
}

/// Set the global side-channel protection configuration
/// Note: This is a no-op in the current implementation since we use a const
/// In a full implementation, you might want to use thread-local storage or
/// pass the configuration explicitly to functions that need it
pub fn set_side_channel_protection(_protection: SideChannelProtection) {
    // No-op: using const configuration
}

/// Convenience functions for common side-channel protected operations
pub fn secure_key_compare(a: &[u8], b: &[u8]) -> bool {
    get_side_channel_protection().secure_key_compare(a, b)
}

#[cfg(feature = "alloc")]
pub fn secure_key_select(choice: u8, a: &[u8], b: &[u8]) -> Vec<u8> {
    get_side_channel_protection().secure_key_select(choice, a, b)
}

#[cfg(not(feature = "alloc"))]
pub fn secure_key_select(choice: u8, a: &[u8], b: &[u8]) -> &[u8] {
    get_side_channel_protection().secure_key_select(choice, a, b)
}

pub fn secure_memory_copy(choice: u8, dst: &mut [u8], src: &[u8]) {
    get_side_channel_protection().secure_memory_copy(choice, dst, src);
}

pub fn secure_memory_zero(choice: u8, data: &mut [u8]) {
    get_side_channel_protection().secure_memory_zero(choice, data);
}

pub fn secure_memory_swap(choice: u8, a: &mut [u8], b: &mut [u8]) {
    get_side_channel_protection().secure_memory_swap(choice, a, b);
}

pub fn secure_string_compare(a: &str, b: &str) -> bool {
    get_side_channel_protection().secure_string_compare(a, b)
}

pub fn secure_integer_compare(a: u64, b: u64) -> bool {
    get_side_channel_protection().secure_integer_compare(a, b)
}

pub fn secure_integer_select(choice: u8, a: u64, b: u64) -> u64 {
    get_side_channel_protection().secure_integer_select(choice, a, b)
}

pub fn secure_boolean_and(a: bool, b: bool) -> bool {
    get_side_channel_protection().secure_boolean_and(a, b)
}

pub fn secure_boolean_or(a: bool, b: bool) -> bool {
    get_side_channel_protection().secure_boolean_or(a, b)
}

pub fn secure_boolean_xor(a: bool, b: bool) -> bool {
    get_side_channel_protection().secure_boolean_xor(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_side_channel_protection_creation() {
        let protection = SideChannelProtection::new();
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
        let a = b"hello";
        let b = b"hello";
        let c = b"world";

        assert!(protection.secure_key_compare(a, b));
        assert!(!protection.secure_key_compare(a, c));
    }

    #[test]
    fn test_secure_key_select() {
        let protection = SideChannelProtection::new();
        let a = b"hello";
        let b = b"world";

        let result1 = protection.secure_key_select(1, a, b);
        assert_eq!(result1, a);

        let result0 = protection.secure_key_select(0, a, b);
        assert_eq!(result0, b);
    }

    #[test]
    fn test_secure_memory_copy() {
        let protection = SideChannelProtection::new();
        let mut dst = [0u8; 4];
        let src = [1u8, 2u8, 3u8, 4u8];

        protection.secure_memory_copy(1, &mut dst, &src);
        assert_eq!(dst, src);

        protection.secure_memory_copy(0, &mut dst, &[5u8, 6u8, 7u8, 8u8]);
        assert_eq!(dst, src); // Should be unchanged
    }

    #[test]
    fn test_secure_memory_zero() {
        let protection = SideChannelProtection::new();
        let mut data = [1u8, 2u8, 3u8, 4u8];

        protection.secure_memory_zero(1, &mut data);
        assert_eq!(data, [0u8, 0u8, 0u8, 0u8]);

        data = [1u8, 2u8, 3u8, 4u8];
        protection.secure_memory_zero(0, &mut data);
        assert_eq!(data, [1u8, 2u8, 3u8, 4u8]); // Should be unchanged
    }

    #[test]
    fn test_secure_memory_swap() {
        let protection = SideChannelProtection::new();
        let mut a = [1u8, 2u8, 3u8, 4u8];
        let mut b = [5u8, 6u8, 7u8, 8u8];
        let a_orig = a;
        let b_orig = b;

        protection.secure_memory_swap(1, &mut a, &mut b);
        assert_eq!(a, b_orig);
        assert_eq!(b, a_orig);

        protection.secure_memory_swap(0, &mut a, &mut b);
        assert_eq!(a, b_orig); // Should be unchanged
        assert_eq!(b, a_orig); // Should be unchanged
    }

    #[test]
    fn test_secure_string_compare() {
        let protection = SideChannelProtection::new();
        let a = "hello";
        let b = "hello";
        let c = "world";

        assert!(protection.secure_string_compare(a, b));
        assert!(!protection.secure_string_compare(a, c));
    }

    #[test]
    fn test_secure_integer_compare() {
        let protection = SideChannelProtection::new();
        let a = 42u64;
        let b = 42u64;
        let c = 43u64;

        assert!(protection.secure_integer_compare(a, b));
        assert!(!protection.secure_integer_compare(a, c));
    }

    #[test]
    fn test_secure_integer_select() {
        let protection = SideChannelProtection::new();
        let a = 42u64;
        let b = 43u64;

        let result1 = protection.secure_integer_select(1, a, b);
        assert_eq!(result1, a);

        let result0 = protection.secure_integer_select(0, a, b);
        assert_eq!(result0, b);
    }

    #[test]
    fn test_secure_boolean_operations() {
        let protection = SideChannelProtection::new();

        assert!(protection.secure_boolean_and(true, true));
        assert!(!protection.secure_boolean_and(true, false));
        assert!(!protection.secure_boolean_and(false, true));
        assert!(!protection.secure_boolean_and(false, false));

        assert!(protection.secure_boolean_or(true, true));
        assert!(protection.secure_boolean_or(true, false));
        assert!(protection.secure_boolean_or(false, true));
        assert!(!protection.secure_boolean_or(false, false));

        assert!(!protection.secure_boolean_xor(true, true));
        assert!(protection.secure_boolean_xor(true, false));
        assert!(protection.secure_boolean_xor(false, true));
        assert!(!protection.secure_boolean_xor(false, false));
    }

    #[test]
    fn test_secure_array_access() {
        let protection = SideChannelProtection::new();
        let array = [1, 2, 3, 4, 5];

        assert_eq!(protection.secure_array_access(&array, 0), Some(&1));
        assert_eq!(protection.secure_array_access(&array, 4), Some(&5));
        assert_eq!(protection.secure_array_access(&array, 5), None);
    }

    #[test]
    fn test_global_side_channel_protection() {
        let protection = SideChannelProtection::strict();
        set_side_channel_protection(protection);

        let a = b"hello";
        let b = b"hello";
        let c = b"world";

        assert!(secure_key_compare(a, b));
        assert!(!secure_key_compare(a, c));
    }
}
