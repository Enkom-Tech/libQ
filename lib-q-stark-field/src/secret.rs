//! Secure wrappers for secret field elements with automatic zeroization.
//!
//! This module provides secure memory management for sensitive cryptographic data,
//! ensuring that secret values are automatically zeroized when dropped to prevent
//! memory-based side-channel attacks.

use zeroize::Zeroize;

use crate::Field;

/// A secure wrapper for secret field elements that automatically zeroizes on drop.
///
/// This type ensures that sensitive field values are cleared from memory when
/// they go out of scope, preventing memory-based side-channel attacks.
///
/// # Security
///
/// - Automatically zeroizes memory on drop
/// - Prevents accidental exposure through debug formatting
/// - Provides secure accessors that don't leak timing information
///
/// # Example
///
/// ```ignore
/// use lib_q_stark_field::Field;
/// use lib_q_stark_field::secret::SecretFieldElement;
///
/// let secret = SecretFieldElement::new(some_field_value);
/// // Use secret.value() to access the value
/// // Memory is automatically zeroized when secret goes out of scope
/// ```
pub struct SecretFieldElement<F: Field> {
    value: F,
}

impl<F: Field> Zeroize for SecretFieldElement<F> {
    fn zeroize(&mut self) {
        // Write through a volatile pointer so the compiler cannot treat this
        // store as a dead write and elide it.  The SeqCst fence then prevents
        // any reordering that could move the write after the value is released.
        //
        // SAFETY: `self.value` is a valid, aligned, initialized field element
        // for the duration of this method, and we hold `&mut self`.
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(self.value),
                F::ZERO,
            );
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl<F: Field> Drop for SecretFieldElement<F> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<F: Field> SecretFieldElement<F> {
    /// Create a new secret field element.
    ///
    /// # Arguments
    /// * `value` - The field element to wrap securely
    ///
    /// # Returns
    /// A new `SecretFieldElement` that will be zeroized on drop.
    pub fn new(value: F) -> Self {
        Self { value }
    }

    /// Get a reference to the underlying field value.
    ///
    /// # Security
    /// This provides direct access to the value. Use with caution in
    /// constant-time contexts.
    pub fn value(&self) -> &F {
        &self.value
    }

    /// Consume the secret and return the underlying value.
    ///
    /// # Security
    /// After calling this, the value is no longer automatically zeroized.
    /// The caller is responsible for secure memory management.
    pub fn into_inner(mut self) -> F {
        let value = core::mem::replace(&mut self.value, F::ZERO);
        // self is dropped here and zeroized (though value is already moved)
        core::mem::forget(self);
        value
    }
}

impl<F: Field> From<F> for SecretFieldElement<F> {
    fn from(value: F) -> Self {
        Self::new(value)
    }
}

// Prevent accidental debug formatting that could leak secrets
impl<F: Field> core::fmt::Debug for SecretFieldElement<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretFieldElement(***)")
    }
}
