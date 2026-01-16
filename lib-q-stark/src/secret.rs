//! Secure wrappers for witness data with automatic zeroization.
//!
//! This module provides secure memory management for sensitive witness data
//! used in STARK proof generation, ensuring that secrets are automatically
//! zeroized when dropped.

extern crate alloc;

use alloc::vec::Vec;

use lib_q_stark_field::Field;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use zeroize::Zeroize;

/// A secure wrapper for witness trace data that automatically zeroizes on drop.
///
/// Witness traces contain sensitive information that must be protected from
/// memory-based side-channel attacks. This wrapper ensures that trace data
/// is automatically cleared from memory when it goes out of scope.
///
/// # Security
///
/// - Automatically zeroizes memory on drop
/// - Prevents accidental exposure through debug formatting
/// - Provides secure accessors
///
/// # Example
///
/// ```ignore
/// use lib_q_stark::secret::SecretWitness;
/// use lib_q_stark_field::extension::Complex;
/// use lib_q_stark_mersenne31::Mersenne31;
/// use lib_q_stark_matrix::dense::RowMajorMatrix;
///
/// type Val = Complex<Mersenne31>;
/// let trace = RowMajorMatrix::new(
///     vec![Val::ZERO, Val::ONE, Val::from(Mersenne31::new(2)), Val::from(Mersenne31::new(3))],
///     2
/// );
/// let secret_witness = SecretWitness::new(trace);
/// // Use secret_witness.trace() to access the trace
/// // Memory is automatically zeroized when secret_witness goes out of scope
/// ```
pub struct SecretWitness<F: Field> {
    trace: RowMajorMatrix<F>,
}

impl<F: Field> Zeroize for SecretWitness<F> {
    fn zeroize(&mut self) {
        // Zeroize the trace matrix by clearing all values
        // RowMajorMatrix stores data in a Vec via the values field
        for value in self.trace.values.iter_mut() {
            *value = F::ZERO;
        }
        // Use compiler barrier to prevent optimization
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl<F: Field> Drop for SecretWitness<F> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<F: Field> SecretWitness<F> {
    /// Create a new secret witness from a trace matrix.
    ///
    /// # Arguments
    /// * `trace` - The witness trace matrix to wrap securely
    ///
    /// # Returns
    /// A new `SecretWitness` that will be zeroized on drop.
    pub fn new(trace: RowMajorMatrix<F>) -> Self {
        Self { trace }
    }

    /// Get a reference to the underlying trace matrix.
    ///
    /// # Security
    /// This provides direct access to the trace. Use with caution in
    /// constant-time contexts.
    pub fn trace(&self) -> &RowMajorMatrix<F> {
        &self.trace
    }

    /// Consume the secret witness and return the underlying trace.
    ///
    /// # Security
    /// After calling this, the trace is no longer automatically zeroized.
    /// The caller is responsible for secure memory management.
    pub fn into_inner(mut self) -> RowMajorMatrix<F> {
        let trace = core::mem::replace(&mut self.trace, RowMajorMatrix::new(Vec::new(), 0));
        // self is dropped here and zeroized (though trace is already moved)
        core::mem::forget(self);
        trace
    }
}

impl<F: Field> From<RowMajorMatrix<F>> for SecretWitness<F> {
    fn from(trace: RowMajorMatrix<F>) -> Self {
        Self::new(trace)
    }
}

// Prevent accidental debug formatting that could leak secrets
impl<F: Field> core::fmt::Debug for SecretWitness<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretWitness(***)")
    }
}

/// A secure wrapper for random coefficients used in proof generation.
///
/// Random coefficients must be kept secret during proof generation and
/// should be zeroized after use to prevent memory-based attacks.
pub struct SecretRandomCoefficients<F: Field> {
    coefficients: Vec<F>,
}

impl<F: Field> Zeroize for SecretRandomCoefficients<F> {
    fn zeroize(&mut self) {
        // Zeroize all coefficients
        for coeff in self.coefficients.iter_mut() {
            *coeff = F::ZERO;
        }
        // Use compiler barrier to prevent optimization
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl<F: Field> Drop for SecretRandomCoefficients<F> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<F: Field> SecretRandomCoefficients<F> {
    /// Create a new secret random coefficients container.
    ///
    /// # Arguments
    /// * `coefficients` - The random coefficients to wrap securely
    ///
    /// # Returns
    /// A new `SecretRandomCoefficients` that will be zeroized on drop.
    pub fn new(coefficients: Vec<F>) -> Self {
        Self { coefficients }
    }

    /// Get a reference to the underlying coefficients.
    pub fn coefficients(&self) -> &[F] {
        &self.coefficients
    }

    /// Consume the secret and return the underlying coefficients.
    ///
    /// # Security
    /// After calling this, the coefficients are no longer automatically zeroized.
    pub fn into_inner(mut self) -> Vec<F> {
        let coefficients = core::mem::take(&mut self.coefficients);
        core::mem::forget(self);
        coefficients
    }
}
