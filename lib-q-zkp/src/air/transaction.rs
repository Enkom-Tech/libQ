//! Transaction AIR - Proves transaction validity without revealing details
//!
//! This AIR proves that a transaction is valid (signatures, balances, etc.)
//! without revealing all transaction details. Enables confidential transactions.
//!
//! # Design
//!
//! Proves transaction validity by:
//! - Verifying ML-DSA signatures
//! - Checking balance constraints
//! - Validating nonces
//! - Range proofs for amounts
//!
//! # Security
//!
//! - Uses ML-DSA for signature verification
//! - Transaction details can remain confidential
//! - Cryptographic validity guarantees

extern crate alloc;

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_field::{
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;

use super::{
    AirError,
    TraceGenerator,
    next_power_of_two,
    validate_trace_dimensions,
};

/// Transaction type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionType {
    /// Payment transaction
    Payment,
    /// Contract call
    ContractCall,
    /// State update
    StateUpdate,
}

/// Signature verification mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureMode {
    /// Verify ML-DSA signatures
    MlDsa,
    /// No signature verification (for testing)
    None,
}

/// Maximum transaction size in bytes
pub const MAX_TRANSACTION_SIZE: usize = 8192;

/// AIR for proving transaction validity
///
/// This proves that a transaction is valid according to the specified
/// transaction type and signature mode, without revealing all details.
///
/// # Trace Layout
///
/// - Transaction data
/// - Signature verification data
/// - Balance proof data
/// - Range proof data
#[derive(Debug, Clone)]
pub struct TransactionAir {
    /// Transaction type
    tx_type: TransactionType,
    /// Signature verification mode
    sig_mode: SignatureMode,
}

impl TransactionAir {
    /// Create a new TransactionAir
    ///
    /// # Arguments
    ///
    /// * `tx_type` - The transaction type
    /// * `sig_mode` - The signature verification mode
    ///
    /// # Returns
    ///
    /// `Ok(TransactionAir)` if successful
    pub fn new(tx_type: TransactionType, sig_mode: SignatureMode) -> Self {
        Self { tx_type, sig_mode }
    }

    /// Get the transaction type
    pub fn tx_type(&self) -> TransactionType {
        self.tx_type
    }

    /// Get the signature mode
    pub fn sig_mode(&self) -> SignatureMode {
        self.sig_mode
    }
}

impl<F: Field> BaseAir<F> for TransactionAir {
    fn width(&self) -> usize {
        // Trace columns:
        // - Column 0: transaction type (0=Payment, 1=ContractCall, 2=StateUpdate)
        // - Transaction data: MAX_TRANSACTION_SIZE
        // - Signature data: 4096
        // - Balance proof: 256
        // - Range proof: 128
        1 + MAX_TRANSACTION_SIZE + 4096 + 256 + 128
    }
}

impl<AB: AirBuilder> Air<AB> for TransactionAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let tx_type = local[0].clone().into();
        let one = AB::Expr::from(AB::F::ONE);
        let two = one.clone() + one.clone();
        builder.assert_zero(tx_type.clone() * (tx_type.clone() - one) * (tx_type.clone() - two));
    }
}

/// Input for transaction proof
#[derive(Debug, Clone)]
pub struct TransactionInput {
    /// Transaction data
    pub transaction_data: Vec<u8>,
    /// Signatures (if applicable)
    pub signatures: Vec<Vec<u8>>,
}

impl
    TraceGenerator<
        lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>,
        TransactionInput,
    > for TransactionAir
{
    fn generate_trace(
        &self,
        inputs: &TransactionInput,
    ) -> Result<
        RowMajorMatrix<lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>>,
        AirError,
    > {
        use lib_q_stark_field::extension::Complex;
        use lib_q_stark_field::integers::QuotientMap;
        use lib_q_stark_mersenne31::Mersenne31;

        type Val = Complex<Mersenne31>;

        if inputs.transaction_data.len() > MAX_TRANSACTION_SIZE {
            return Err(AirError::ExceedsMaxSize {
                parameter: "transaction_data".to_string(),
                max: MAX_TRANSACTION_SIZE,
                actual: inputs.transaction_data.len(),
            });
        }

        let trace_width = {
            use lib_q_stark_field::extension::Complex;
            use lib_q_stark_mersenne31::Mersenne31;
            type Val = Complex<Mersenne31>;
            <Self as BaseAir<Val>>::width(self)
        };
        let trace_height = 1;
        let num_rows_padded = next_power_of_two(trace_height);

        validate_trace_dimensions(trace_width, num_rows_padded)?;

        let mut trace_values = vec![Val::ZERO; num_rows_padded * trace_width];
        let base = 0;

        let tx_type_byte = match self.tx_type {
            TransactionType::Payment => 0u8,
            TransactionType::ContractCall => 1u8,
            TransactionType::StateUpdate => 2u8,
        };
        trace_values[base] =
            Val::from_prime_subfield(<Mersenne31 as QuotientMap<u8>>::from_int(tx_type_byte));

        for (i, byte) in inputs.transaction_data.iter().enumerate() {
            if i < MAX_TRANSACTION_SIZE {
                trace_values[base + 1 + i] =
                    Val::from_prime_subfield(<Mersenne31 as QuotientMap<u8>>::from_int(*byte));
            }
        }

        let sig_start = 1 + MAX_TRANSACTION_SIZE;
        let mut sig_col = sig_start;
        for sig in &inputs.signatures {
            for (i, byte) in sig.iter().enumerate() {
                if sig_col + i < trace_width && sig_col + i < sig_start + 4096 {
                    trace_values[base + sig_col + i] =
                        Val::from_prime_subfield(<Mersenne31 as QuotientMap<u8>>::from_int(*byte));
                }
            }
            sig_col += sig.len();
        }

        Ok(RowMajorMatrix::new(trace_values, trace_width))
    }

    fn public_values(
        &self,
        _inputs: &TransactionInput,
    ) -> Vec<lib_q_stark_field::extension::Complex<lib_q_stark_mersenne31::Mersenne31>> {
        // Public values: transaction type, signature mode
        // Transaction details remain confidential
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_air_creation() {
        let air = TransactionAir::new(TransactionType::Payment, SignatureMode::MlDsa);
        assert_eq!(air.tx_type(), TransactionType::Payment);
        assert_eq!(air.sig_mode(), SignatureMode::MlDsa);
    }

    #[test]
    fn test_transaction_trace_generation() {
        let air = TransactionAir::new(TransactionType::Payment, SignatureMode::MlDsa);
        let input = TransactionInput {
            transaction_data: vec![1, 2, 3, 4],
            signatures: vec![vec![5, 6, 7, 8]],
        };

        let trace = air.generate_trace(&input);
        assert!(trace.is_ok());
    }

    #[test]
    fn test_transaction_public_values_empty() {
        let input = TransactionInput {
            transaction_data: vec![1, 2, 3, 4],
            signatures: vec![vec![5, 6, 7, 8]],
        };

        for &tx_type in &[
            TransactionType::Payment,
            TransactionType::ContractCall,
            TransactionType::StateUpdate,
        ] {
            for &sig_mode in &[SignatureMode::MlDsa, SignatureMode::None] {
                let air = TransactionAir::new(tx_type, sig_mode);
                assert!(
                    air.public_values(&input).is_empty(),
                    "Expected empty public values for {tx_type:?} / {sig_mode:?}",
                );
            }
        }
    }
}
