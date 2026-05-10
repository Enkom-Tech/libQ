//! Security enhancements for lib-q-aead
//!
//! This module provides comprehensive security features including:
//! - Constant-time operations
//! - Side-channel attack protection
//! - Secure memory handling
//! - Input validation and sanitization
//! - Timing attack protection
//! - Fault injection resistance

pub mod constant_time;
pub mod memory;
pub mod nonce;
pub mod side_channel;
pub mod stack_buffer;
pub mod timing;
pub mod validation;

// Re-export commonly used security functions
// Note: Individual modules are available for specific use cases

/// Security configuration for AEAD operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityConfig {
    /// Enable constant-time operations
    pub constant_time: bool,
    /// Enable side-channel protection
    pub side_channel_protection: bool,
    /// Enable secure memory handling
    pub secure_memory: bool,
    /// Enable comprehensive input validation
    pub strict_validation: bool,
    /// Enable timing attack protection
    pub timing_protection: bool,
    /// Enable fault injection protection
    pub fault_injection_protection: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            constant_time: true,
            side_channel_protection: true,
            secure_memory: true,
            strict_validation: true,
            timing_protection: true,
            fault_injection_protection: true,
        }
    }
}

impl SecurityConfig {
    /// Create a strict security configuration (maximum security)
    pub fn strict() -> Self {
        Self {
            constant_time: true,
            side_channel_protection: true,
            secure_memory: true,
            strict_validation: true,
            timing_protection: true,
            fault_injection_protection: true,
        }
    }

    /// Create a permissive security configuration (performance optimized)
    pub fn permissive() -> Self {
        Self {
            constant_time: false,
            side_channel_protection: false,
            secure_memory: false,
            strict_validation: false,
            timing_protection: false,
            fault_injection_protection: false,
        }
    }

    /// Create a balanced security configuration
    pub fn balanced() -> Self {
        Self {
            constant_time: true,
            side_channel_protection: true,
            secure_memory: true,
            strict_validation: true,
            timing_protection: false,
            fault_injection_protection: false,
        }
    }
}

/// Global security configuration
static mut SECURITY_CONFIG: SecurityConfig = SecurityConfig {
    constant_time: true,
    side_channel_protection: true,
    secure_memory: true,
    strict_validation: true,
    timing_protection: true,
    fault_injection_protection: true,
};

/// Get the current security configuration
pub fn get_security_config() -> SecurityConfig {
    unsafe { SECURITY_CONFIG }
}

/// Set the security configuration
pub fn set_security_config(config: SecurityConfig) {
    unsafe {
        SECURITY_CONFIG = config;
    }
}

/// Security context for cryptographic operations
pub struct SecurityContext {
    config: SecurityConfig,
    operation_id: u64,
    start_time: u64,
}

impl SecurityContext {
    /// Create a new security context
    pub fn new() -> Self {
        Self {
            config: get_security_config(),
            operation_id: Self::generate_operation_id(),
            start_time: Self::get_timestamp(),
        }
    }

    /// Create a security context with custom configuration
    pub fn with_config(config: SecurityConfig) -> Self {
        Self {
            config,
            operation_id: Self::generate_operation_id(),
            start_time: Self::get_timestamp(),
        }
    }

    /// Get the operation ID
    pub fn operation_id(&self) -> u64 {
        self.operation_id
    }

    /// Get the elapsed time since context creation
    pub fn elapsed_time(&self) -> u64 {
        Self::get_timestamp() - self.start_time
    }

    /// Check if constant-time operations are enabled
    pub fn constant_time_enabled(&self) -> bool {
        self.config.constant_time
    }

    /// Check if side-channel protection is enabled
    pub fn side_channel_protection_enabled(&self) -> bool {
        self.config.side_channel_protection
    }

    /// Check if secure memory handling is enabled
    pub fn secure_memory_enabled(&self) -> bool {
        self.config.secure_memory
    }

    /// Check if strict validation is enabled
    pub fn strict_validation_enabled(&self) -> bool {
        self.config.strict_validation
    }

    /// Check if timing protection is enabled
    pub fn timing_protection_enabled(&self) -> bool {
        self.config.timing_protection
    }

    /// Check if fault injection protection is enabled
    pub fn fault_injection_protection_enabled(&self) -> bool {
        self.config.fault_injection_protection
    }

    /// Generate a unique operation ID
    fn generate_operation_id() -> u64 {
        // Use a simple counter for now - in production, this should use
        // cryptographically secure random number generation
        static mut COUNTER: u64 = 0;
        unsafe {
            COUNTER += 1;
            COUNTER
        }
    }

    /// Get current timestamp with high-resolution timing
    fn get_timestamp() -> u64 {
        #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
        {
            use std::time::{
                SystemTime,
                UNIX_EPOCH,
            };
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
        }
        // wasm32-unknown-unknown has no working `SystemTime`; no_std targets
        // have no clock at all. Both fall back to a monotonic counter that
        // still gives consistent relative measurements.
        #[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
        {
            use core::sync::atomic::{
                AtomicU64,
                Ordering,
            };
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            COUNTER.fetch_add(1, Ordering::SeqCst)
        }
    }
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_config_defaults() {
        let config = SecurityConfig::default();
        assert!(config.constant_time);
        assert!(config.side_channel_protection);
        assert!(config.secure_memory);
        assert!(config.strict_validation);
        assert!(config.timing_protection);
        assert!(config.fault_injection_protection);
    }

    #[test]
    fn test_security_config_strict() {
        let config = SecurityConfig::strict();
        assert!(config.constant_time);
        assert!(config.side_channel_protection);
        assert!(config.secure_memory);
        assert!(config.strict_validation);
        assert!(config.timing_protection);
        assert!(config.fault_injection_protection);
    }

    #[test]
    fn test_security_config_permissive() {
        let config = SecurityConfig::permissive();
        assert!(!config.constant_time);
        assert!(!config.side_channel_protection);
        assert!(!config.secure_memory);
        assert!(!config.strict_validation);
        assert!(!config.timing_protection);
        assert!(!config.fault_injection_protection);
    }

    #[test]
    fn test_security_config_balanced() {
        let config = SecurityConfig::balanced();
        assert!(config.constant_time);
        assert!(config.side_channel_protection);
        assert!(config.secure_memory);
        assert!(config.strict_validation);
        assert!(!config.timing_protection);
        assert!(!config.fault_injection_protection);
    }

    #[test]
    fn test_security_context_creation() {
        let ctx = SecurityContext::new();
        assert!(ctx.operation_id() > 0);
        // Note: elapsed_time() returns u64, so it's always >= 0
        // We just verify it's a valid timestamp
        let _elapsed = ctx.elapsed_time();
        assert!(ctx.constant_time_enabled());
    }

    #[test]
    fn test_security_context_with_config() {
        let config = SecurityConfig::permissive();
        let ctx = SecurityContext::with_config(config);
        assert!(!ctx.constant_time_enabled());
        assert!(!ctx.side_channel_protection_enabled());
        assert!(!ctx.secure_memory_enabled());
        assert!(!ctx.strict_validation_enabled());
        assert!(!ctx.timing_protection_enabled());
        assert!(!ctx.fault_injection_protection_enabled());
    }

    #[test]
    fn test_global_security_config() {
        let original_config = get_security_config();

        let new_config = SecurityConfig::permissive();
        set_security_config(new_config);

        let retrieved_config = get_security_config();
        assert_eq!(retrieved_config, new_config);

        // Restore original config
        set_security_config(original_config);
    }
}
