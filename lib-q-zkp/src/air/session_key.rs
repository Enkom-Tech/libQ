//! Session Key Derivation AIR - Proves correct KDF derivation from an ML-KEM shared secret
//!
//! This AIR proves that session keys were correctly derived from an ML-KEM shared
//! secret using a Poseidon sponge KDF, without revealing the shared secret or the
//! session keys.
//!
//! # Statement
//!
//! Public: `C` — a single field element, `C = Poseidon128(k_0, .., k_{n-1})`, the
//! commitment to the derived key material.
//!
//! Witness: the shared secret `ss`.
//!
//! Proven: there exists `ss` such that squeezing the Poseidon sponge that absorbed
//! `ss` yields key elements `k_0..k_{n-1}`, and hashing those elements yields `C`.
//! Both the derivation (sponge 1) and the commitment (sponge 2) are constrained
//! in-trace, so `C` is bound to the derivation rather than merely accompanying it.
//!
//! # Trace layout
//!
//! Every row carries **two** Poseidon-128 permutations:
//! - **sponge 1** (`s1`) absorbs the shared secret, then pads (10*1) and squeezes.
//!   Each squeeze row's `s1_out[0..2]` is one rate block of key material.
//! - **sponge 2** (`s2`) absorbs those key elements as they are produced — one rate
//!   block per squeeze row, which is why it can be constrained row-locally without
//!   any cross-row copy argument — then pads on the commit row, whose `s2_out[0]`
//!   is bound to the public commitment.
//!
//! Row roles are marked by selector columns (`sel_sq[0..B]`, `sel_commit`) that are
//! forced to be one-hot and consecutive by a chain constraint plus a running-sum
//! column `acc`, so a prover cannot simply zero every selector to escape the
//! commitment binding.
//!
//! # Security
//!
//! - Full Poseidon constraints via `PoseidonGadget` for both permutations per row,
//!   binding the **entire** output state (`constrain_full_state_wide`) so the sponge
//!   capacity cannot be forged between rows.
//! - Shared secret and session keys remain secret in the witness; only `C` is public.

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{
    format,
    vec,
};

use lib_q_poseidon::{
    Poseidon,
    Poseidon128,
    PoseidonField,
    PoseidonSponge,
};
use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_field::{
    BasedVectorSpace,
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::Mersenne31;

use super::poseidon_gadget::PoseidonGadget;
use super::{
    AirError,
    TraceGenerator,
    bytes_to_poseidon_field,
    compute_poseidon_row,
    merkle_root_from_bytes,
    next_power_of_two,
    poseidon_field_to_bytes,
    poseidon_to_field,
    validate_trace_dimensions,
};

/// Poseidon-128 hasher instance
const POSEIDON_128: Poseidon128 = Poseidon128;

/// Poseidon-128 state width (rate 2 + capacity 3).
const STATE_COLS: usize = 5;
/// Absorbed rate elements recorded per row.
const INPUT_COLS: usize = 2;
/// Sponge rate.
const RATE: usize = 2;
/// Bytes per `Complex<Mersenne31>` (4 real + 4 imaginary, little-endian).
const BYTES_PER_ELEM: usize = 8;
/// Key material is squeezed a full rate block at a time, so the output length must be
/// a whole number of rate blocks: `RATE * BYTES_PER_ELEM` bytes.
pub const OUTPUT_LENGTH_GRANULARITY: usize = RATE * BYTES_PER_ELEM;

/// Maximum shared secret size in bytes
pub const MAX_SHARED_SECRET_SIZE: usize = 32;

/// Maximum session key size in bytes
pub const MAX_SESSION_KEY_SIZE: usize = 64;

/// KDF parameters
#[derive(Debug, Clone)]
pub struct KdfParams {
    /// KDF algorithm identifier
    pub algorithm: KdfAlgorithm,
    /// Salt (optional)
    pub salt: Option<Vec<u8>>,
    /// Info (optional context)
    pub info: Option<Vec<u8>>,
    /// Output key length in bytes. Must be a non-zero multiple of
    /// [`OUTPUT_LENGTH_GRANULARITY`] and at most [`MAX_SESSION_KEY_SIZE`].
    pub output_length: usize,
}

/// KDF algorithm types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfAlgorithm {
    /// HKDF-SHA3 (as per IP spec)
    HkdfSha3,
    /// Simplified Poseidon-based KDF for ZKP efficiency
    PoseidonKdf,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: KdfAlgorithm::HkdfSha3,
            salt: None,
            info: None,
            output_length: 32,
        }
    }
}

/// AIR for proving session key derivation via Poseidon sponge.
#[derive(Debug, Clone)]
pub struct SessionKeyDerivationAir {
    kdf_params: KdfParams,
}

impl SessionKeyDerivationAir {
    /// Create a new `SessionKeyDerivationAir`.
    pub fn new(kdf_params: KdfParams) -> Result<Self, AirError> {
        if kdf_params.output_length == 0 {
            return Err(AirError::InvalidDimensions {
                reason: "Output length must be greater than 0".to_string(),
            });
        }

        if kdf_params.output_length > MAX_SESSION_KEY_SIZE {
            return Err(AirError::ExceedsMaxSize {
                parameter: "output_length".to_string(),
                max: MAX_SESSION_KEY_SIZE,
                actual: kdf_params.output_length,
            });
        }

        if !kdf_params
            .output_length
            .is_multiple_of(OUTPUT_LENGTH_GRANULARITY)
        {
            return Err(AirError::InvalidDimensions {
                reason: format!(
                    "Output length {} must be a multiple of {} (one sponge rate block)",
                    kdf_params.output_length, OUTPUT_LENGTH_GRANULARITY
                ),
            });
        }

        Ok(Self { kdf_params })
    }

    /// Get the KDF parameters
    pub fn kdf_params(&self) -> &KdfParams {
        &self.kdf_params
    }

    /// Number of field elements of key material squeezed from sponge 1.
    fn num_key_elements(&self) -> usize {
        self.kdf_params.output_length / BYTES_PER_ELEM
    }

    /// Number of squeeze rows (one rate block each).
    fn num_blocks(&self) -> usize {
        self.num_key_elements() / RATE
    }

    // --- column offsets -------------------------------------------------------

    fn col_s1_in(&self) -> usize {
        0
    }
    fn col_input(&self) -> usize {
        STATE_COLS
    }
    fn col_s1_intermediates(&self) -> usize {
        STATE_COLS + INPUT_COLS
    }
    fn col_s1_out(&self) -> usize {
        self.col_s1_intermediates() + PoseidonGadget::COLUMNS_PER_HASH
    }
    fn col_s2_in(&self) -> usize {
        self.col_s1_out() + STATE_COLS
    }
    fn col_s2_intermediates(&self) -> usize {
        self.col_s2_in() + STATE_COLS
    }
    fn col_s2_out(&self) -> usize {
        self.col_s2_intermediates() + PoseidonGadget::COLUMNS_PER_HASH
    }
    fn col_sel_sq(&self) -> usize {
        self.col_s2_out() + STATE_COLS
    }
    fn col_sel_commit(&self) -> usize {
        self.col_sel_sq() + self.num_blocks()
    }
    fn col_acc(&self) -> usize {
        self.col_sel_commit() + 1
    }

    fn trace_width_inner(&self) -> usize {
        self.col_acc() + 1
    }
}

impl<F: Field + BasedVectorSpace<Mersenne31>> BaseAir<F> for SessionKeyDerivationAir {
    fn width(&self) -> usize {
        self.trace_width_inner()
    }
}

impl<AB: AirBuilder> Air<AB> for SessionKeyDerivationAir
where
    AB::F: Field + BasedVectorSpace<Mersenne31>,
{
    fn eval(&self, builder: &mut AB) {
        let blocks = self.num_blocks();
        let (c_s1_in, c_input, c_s1_int) = (
            self.col_s1_in(),
            self.col_input(),
            self.col_s1_intermediates(),
        );
        let (c_s1_out, c_s2_in, c_s2_int, c_s2_out) = (
            self.col_s1_out(),
            self.col_s2_in(),
            self.col_s2_intermediates(),
            self.col_s2_out(),
        );
        let (c_sel_sq, c_sel_commit, c_acc) =
            (self.col_sel_sq(), self.col_sel_commit(), self.col_acc());

        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();

        let one = AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ONE);
        let get = |slice: &[AB::Var], i: usize| -> AB::Expr { slice[i].into() };

        let s1_in: Vec<AB::Expr> = (0..STATE_COLS).map(|i| get(local, c_s1_in + i)).collect();
        let s1_out: Vec<AB::Expr> = (0..STATE_COLS).map(|i| get(local, c_s1_out + i)).collect();
        let s2_in: Vec<AB::Expr> = (0..STATE_COLS).map(|i| get(local, c_s2_in + i)).collect();
        let s2_out: Vec<AB::Expr> = (0..STATE_COLS).map(|i| get(local, c_s2_out + i)).collect();
        let acc = get(local, c_acc);
        let sel_commit = get(local, c_sel_commit);

        // --- first row ------------------------------------------------------
        // Sponge 1 starts at (input_0, input_1, 0, 0, 0); sponge 2 starts at zero and
        // no role selector may fire before the shared secret has been absorbed.
        {
            let input_0 = get(local, c_input);
            let input_1 = get(local, c_input + 1);
            let mut b = builder.when_first_row();
            b.assert_zero(s1_in[0].clone() - input_0);
            b.assert_zero(s1_in[1].clone() - input_1);
            for s in s1_in.iter().take(STATE_COLS).skip(RATE) {
                b.assert_zero(s.clone());
            }
            for s in s2_in.iter() {
                b.assert_zero(s.clone());
            }
            for j in 0..blocks {
                b.assert_zero(get(local, c_sel_sq + j));
            }
            b.assert_zero(sel_commit.clone());
            b.assert_zero(acc.clone());
        }

        // --- transition -----------------------------------------------------
        {
            let next_sel_sq: Vec<AB::Expr> = (0..blocks).map(|j| get(next, c_sel_sq + j)).collect();
            let next_sel_commit = get(next, c_sel_commit);
            let next_acc = get(next, c_acc);
            let next_s1_in: Vec<AB::Expr> =
                (0..STATE_COLS).map(|i| get(next, c_s1_in + i)).collect();
            let next_s1_out: Vec<AB::Expr> =
                (0..STATE_COLS).map(|i| get(next, c_s1_out + i)).collect();
            let next_s2_in: Vec<AB::Expr> =
                (0..STATE_COLS).map(|i| get(next, c_s2_in + i)).collect();
            let next_input_0 = get(next, c_input);
            let next_input_1 = get(next, c_input + 1);

            let mut b = builder.when_transition();

            for s in next_sel_sq.iter() {
                b.assert_bool(s.clone());
            }
            b.assert_bool(next_sel_commit.clone());

            // Exactly one row may open the squeeze phase: acc is a running count of
            // sel_sq[0], starts at 0 and is checked to be 1 on the last row.
            b.assert_zero(next_acc.clone() - (acc.clone() + next_sel_sq[0].clone()));
            // ... and the remaining role rows are chained to be consecutive after it.
            for j in 1..blocks {
                b.assert_zero(next_sel_sq[j].clone() - get(local, c_sel_sq + j - 1));
            }
            b.assert_zero(next_sel_commit.clone() - get(local, c_sel_sq + blocks - 1));

            // Sponge 1: rate absorbs the next row's input, except on the padding row
            // (sel_sq[0]) where it absorbs the 10*1 pad; capacity always passes through.
            let pad = next_sel_sq[0].clone();
            b.assert_zero(
                next_s1_in[0].clone() -
                    (s1_out[0].clone() +
                        (one.clone() - pad.clone()) * next_input_0.clone() +
                        pad.clone()),
            );
            b.assert_zero(
                next_s1_in[1].clone() -
                    (s1_out[1].clone() +
                        (one.clone() - pad.clone()) * next_input_1.clone() +
                        pad.clone()),
            );
            for i in RATE..STATE_COLS {
                b.assert_zero(next_s1_in[i].clone() - s1_out[i].clone());
            }

            // No secret may be absorbed once the squeeze phase has begun.
            let sq_any = next_sel_sq.iter().cloned().fold(
                AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ZERO),
                |a, s| a + s,
            );
            let non_absorb = sq_any.clone() + next_sel_commit.clone();
            b.assert_zero(non_absorb.clone() * next_input_0);
            b.assert_zero(non_absorb * next_input_1);

            // Sponge 2 is idle (held at zero) until the first squeeze row, then absorbs
            // one rate block of key material per squeeze row, then the 10*1 pad on the
            // commit row. `acc` gates the carry so the idle rows cannot leak in.
            let absorb_0 = sq_any.clone() * next_s1_out[0].clone() + next_sel_commit.clone();
            let absorb_1 = sq_any * next_s1_out[1].clone() + next_sel_commit;
            b.assert_zero(
                next_s2_in[0].clone() -
                    next_acc.clone() * (acc.clone() * s2_out[0].clone() + absorb_0),
            );
            b.assert_zero(
                next_s2_in[1].clone() -
                    next_acc.clone() * (acc.clone() * s2_out[1].clone() + absorb_1),
            );
            for i in RATE..STATE_COLS {
                b.assert_zero(
                    next_s2_in[i].clone() - next_acc.clone() * acc.clone() * s2_out[i].clone(),
                );
            }
        }

        // --- last row -------------------------------------------------------
        // The squeeze phase must have happened, and must have finished strictly before
        // the end of the trace (so the chain above is fully witnessed).
        {
            let mut b = builder.when_last_row();
            b.assert_zero(acc.clone() - one.clone());
            for j in 0..blocks {
                b.assert_zero(get(local, c_sel_sq + j));
            }
            b.assert_zero(sel_commit.clone());
        }

        // --- both permutations ----------------------------------------------
        let gadget = PoseidonGadget::new();
        let s1_ok = gadget
            .constrain_full_state_wide(builder, &s1_in, &s1_out, c_s1_int)
            .is_ok();
        let s2_ok = gadget
            .constrain_full_state_wide(builder, &s2_in, &s2_out, c_s2_int)
            .is_ok();
        if !(s1_ok && s2_ok) {
            builder.assert_zero(one.clone());
        }

        // --- public binding ---------------------------------------------------
        let pubs = builder.public_values();
        if pubs.is_empty() {
            // A missing public value must not silently drop the binding.
            builder.assert_zero(one);
        } else {
            let expected: AB::Expr = pubs[0].into();
            builder
                .when(sel_commit)
                .assert_eq(s2_out[0].clone(), expected);
        }
    }
}

/// Input for session key derivation proof
#[derive(Debug, Clone)]
pub struct SessionKeyInput {
    /// ML-KEM shared secret (absorbed into sponge 1)
    pub shared_secret: Vec<u8>,
    /// Derived session keys. Must equal `derive_session_keys(shared_secret, output_length)`;
    /// `generate_trace` rejects any other value rather than proving a false statement.
    pub session_keys: Vec<u8>,
}

/// Field elements of the shared secret as absorbed by sponge 1 (padded to a whole
/// number of rate blocks, which is what the trace's first rows replay).
fn absorbed_secret_fields(shared_secret: &[u8]) -> Vec<PoseidonField> {
    use lib_q_stark_field::extension::Complex;

    let mut fields = bytes_to_poseidon_field(shared_secret);
    while !fields.len().is_multiple_of(RATE) {
        fields.push(Complex::<Mersenne31>::new_complex(
            Mersenne31::ZERO,
            Mersenne31::ZERO,
        ));
    }
    fields
}

/// The KDF itself: absorb the shared secret, pad, squeeze `num_elements` elements.
fn derive_key_elements(shared_secret: &[u8], num_elements: usize) -> Vec<PoseidonField> {
    let mut sponge = PoseidonSponge::new(Poseidon128::params());
    sponge.absorb(&absorbed_secret_fields(shared_secret));
    sponge.finish_absorbing().squeeze(num_elements)
}

/// Derive `output_length` bytes of session key material from an ML-KEM shared secret.
///
/// This is the function the AIR proves was evaluated correctly. `output_length` must be
/// a multiple of [`OUTPUT_LENGTH_GRANULARITY`].
///
/// # Not injective across secret lengths
///
/// The secret is absorbed one byte per field element and zero-padded to a whole rate
/// block, with no length encoding, so a secret and that same secret with a trailing zero
/// byte derive the SAME key material (`derive_session_keys(&[1, 2, 3], n) ==
/// derive_session_keys(&[1, 2, 3, 0], n)`). This is harmless for fixed-width ML-KEM shared
/// secrets, which is the intended input; do not feed this KDF variable-length secrets whose
/// trailing zero bytes are meaningful.
///
/// Relatedly, [`MAX_SHARED_SECRET_SIZE`] is enforced by `generate_trace`, not by the
/// constraints: the proved statement is "some absorbed sequence yields this commitment",
/// which does not bound the secret's length.
pub fn derive_session_keys(shared_secret: &[u8], output_length: usize) -> Vec<u8> {
    let elements = derive_key_elements(shared_secret, output_length / BYTES_PER_ELEM);
    poseidon_field_to_bytes(&elements)
}

/// Recover the key elements from their canonical byte encoding.
fn key_elements_from_bytes(session_keys: &[u8]) -> Result<Vec<PoseidonField>, AirError> {
    session_keys
        .chunks(BYTES_PER_ELEM)
        .map(merkle_root_from_bytes)
        .collect()
}

impl TraceGenerator<lib_q_stark_field::extension::Complex<Mersenne31>, SessionKeyInput>
    for SessionKeyDerivationAir
{
    fn generate_trace(
        &self,
        inputs: &SessionKeyInput,
    ) -> Result<RowMajorMatrix<lib_q_stark_field::extension::Complex<Mersenne31>>, AirError> {
        use lib_q_stark_field::extension::Complex;

        type Val = Complex<Mersenne31>;

        if inputs.shared_secret.is_empty() {
            return Err(AirError::InvalidInput {
                reason: "Shared secret cannot be empty".to_string(),
            });
        }

        if inputs.shared_secret.len() > MAX_SHARED_SECRET_SIZE {
            return Err(AirError::ExceedsMaxSize {
                parameter: "shared_secret".to_string(),
                max: MAX_SHARED_SECRET_SIZE,
                actual: inputs.shared_secret.len(),
            });
        }

        if inputs.session_keys.len() != self.kdf_params.output_length {
            return Err(AirError::InvalidInput {
                reason: format!(
                    "Session keys length {} must match output_length {}",
                    inputs.session_keys.len(),
                    self.kdf_params.output_length
                ),
            });
        }

        // The AIR proves `session_keys == KDF(shared_secret)`. Refuse to build a trace for
        // any other pair rather than emit one that cannot satisfy the constraints.
        let expected_keys =
            derive_session_keys(&inputs.shared_secret, self.kdf_params.output_length);
        if expected_keys != inputs.session_keys {
            return Err(AirError::InvalidInput {
                reason: "Session keys are not the KDF output of this shared secret".to_string(),
            });
        }

        let zero_f = Complex::<Mersenne31>::new_complex(Mersenne31::ZERO, Mersenne31::ZERO);
        let one_f = Complex::<Mersenne31>::new_complex(Mersenne31::ONE, Mersenne31::ZERO);

        let secret_fields = absorbed_secret_fields(&inputs.shared_secret);
        let num_absorb = core::cmp::max(1, secret_fields.len() / RATE);
        let blocks = self.num_blocks();
        let pad_row = num_absorb; // sponge-1 padding row == first squeeze row
        let commit_row = pad_row + blocks;

        // Height must leave at least one trailing row after `commit_row`; the extra
        // quotient headroom mirrors `IdentityProofAir`.
        const QUOTIENT_CHUNKS_FACTOR: usize = 4;
        let min_height = core::cmp::max(commit_row + 2, num_absorb * QUOTIENT_CHUNKS_FACTOR);
        let num_rows = next_power_of_two(min_height);
        let width = self.trace_width_inner();
        validate_trace_dimensions(width, num_rows)?;

        let params = Poseidon128::params();
        let mut trace_values = vec![Val::ZERO; num_rows * width];

        let mut s1 = vec![zero_f; STATE_COLS];
        let mut s2 = vec![zero_f; STATE_COLS];

        for row in 0..num_rows {
            let (in0, in1) = if row < pad_row {
                (
                    secret_fields.get(row * RATE).copied().unwrap_or(zero_f),
                    secret_fields.get(row * RATE + 1).copied().unwrap_or(zero_f),
                )
            } else {
                (zero_f, zero_f)
            };

            // Sponge 1 input state for this row.
            let s1_in: Vec<PoseidonField> = if row == 0 {
                let mut v = vec![zero_f; STATE_COLS];
                v[0] = in0;
                v[1] = in1;
                v
            } else if row == pad_row {
                // 10*1 padding: `absorbed` is 0 because the secret is padded to whole blocks.
                let mut v = s1.clone();
                v[0] += one_f;
                v[1] += one_f;
                v
            } else {
                let mut v = s1.clone();
                v[0] += in0;
                v[1] += in1;
                v
            };

            let (s1_out, s1_int) = compute_poseidon_row(&s1_in, &params);

            // Sponge 2 input state for this row.
            let s2_in: Vec<PoseidonField> = if row < pad_row {
                vec![zero_f; STATE_COLS]
            } else {
                let base = if row == pad_row {
                    vec![zero_f; STATE_COLS]
                } else {
                    s2.clone()
                };
                let mut v = base;
                if row < commit_row {
                    // squeeze row: absorb this row's freshly squeezed rate block
                    v[0] += s1_out[0];
                    v[1] += s1_out[1];
                } else if row == commit_row {
                    v[0] += one_f;
                    v[1] += one_f;
                }
                v
            };

            let (s2_out, s2_int) = compute_poseidon_row(&s2_in, &params);

            let base = row * width;
            for i in 0..STATE_COLS {
                trace_values[base + self.col_s1_in() + i] = poseidon_to_field(&s1_in[i]);
                trace_values[base + self.col_s1_out() + i] = poseidon_to_field(&s1_out[i]);
                trace_values[base + self.col_s2_in() + i] = poseidon_to_field(&s2_in[i]);
                trace_values[base + self.col_s2_out() + i] = poseidon_to_field(&s2_out[i]);
            }
            trace_values[base + self.col_input()] = poseidon_to_field(&in0);
            trace_values[base + self.col_input() + 1] = poseidon_to_field(&in1);
            for (k, v) in s1_int.iter().enumerate() {
                trace_values[base + self.col_s1_intermediates() + k] = poseidon_to_field(v);
            }
            for (k, v) in s2_int.iter().enumerate() {
                trace_values[base + self.col_s2_intermediates() + k] = poseidon_to_field(v);
            }
            for j in 0..blocks {
                trace_values[base + self.col_sel_sq() + j] = if row == pad_row + j {
                    Val::ONE
                } else {
                    Val::ZERO
                };
            }
            trace_values[base + self.col_sel_commit()] = if row == commit_row {
                Val::ONE
            } else {
                Val::ZERO
            };
            trace_values[base + self.col_acc()] = if row >= pad_row { Val::ONE } else { Val::ZERO };

            s1 = s1_out;
            s2 = s2_out;
        }

        Ok(RowMajorMatrix::new(trace_values, width))
    }

    fn public_values(
        &self,
        inputs: &SessionKeyInput,
    ) -> Vec<lib_q_stark_field::extension::Complex<Mersenne31>> {
        use lib_q_stark_field::extension::Complex;

        type Val = Complex<Mersenne31>;

        // Public value: C = Poseidon128(k_0, .., k_{n-1}) over the key ELEMENTS (not the
        // per-byte encoding), which is exactly what sponge 2 computes in the trace.
        let Ok(key_elements) = key_elements_from_bytes(&inputs.session_keys) else {
            return vec![Val::ZERO];
        };
        let commitment = POSEIDON_128.hash(&key_elements);
        if commitment.is_empty() {
            return vec![Val::ZERO];
        }
        vec![poseidon_to_field(&commitment[0])]
    }
}

#[cfg(test)]
mod tests {
    use lib_q_stark::check_constraints;
    use lib_q_stark_air::BaseAir;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_matrix::Matrix;
    use lib_q_stark_mersenne31::Mersenne31;

    use super::*;

    type TestField = Complex<Mersenne31>;

    fn air(output_length: usize) -> SessionKeyDerivationAir {
        SessionKeyDerivationAir::new(KdfParams {
            output_length,
            ..Default::default()
        })
        .expect("air")
    }

    fn honest_input(air: &SessionKeyDerivationAir, secret: &[u8]) -> SessionKeyInput {
        SessionKeyInput {
            shared_secret: secret.to_vec(),
            session_keys: derive_session_keys(secret, air.kdf_params().output_length),
        }
    }

    fn cell(trace: &RowMajorMatrix<TestField>, row: usize, col: usize) -> TestField {
        trace.values[row * trace.width() + col]
    }

    fn set_cell(trace: &mut RowMajorMatrix<TestField>, row: usize, col: usize, v: TestField) {
        let w = trace.width();
        trace.values[row * w + col] = v;
    }

    #[test]
    fn test_session_key_air_creation() {
        let a = air(32);
        assert_eq!(a.kdf_params().output_length, 32);
        assert_eq!(
            <SessionKeyDerivationAir as BaseAir<TestField>>::width(&a),
            a.trace_width_inner()
        );
    }

    #[test]
    fn test_session_key_air_rejects_invalid_output_length() {
        let zero_len = SessionKeyDerivationAir::new(KdfParams {
            output_length: 0,
            ..Default::default()
        });
        assert!(matches!(zero_len, Err(AirError::InvalidDimensions { .. })));

        let too_large = SessionKeyDerivationAir::new(KdfParams {
            output_length: MAX_SESSION_KEY_SIZE + 1,
            ..Default::default()
        });
        assert!(matches!(too_large, Err(AirError::ExceedsMaxSize { .. })));

        // Not a whole rate block: cannot be squeezed by this trace layout.
        let unaligned = SessionKeyDerivationAir::new(KdfParams {
            output_length: 24,
            ..Default::default()
        });
        assert!(matches!(unaligned, Err(AirError::InvalidDimensions { .. })));
    }

    #[test]
    fn test_session_key_trace_generation() {
        let a = air(32);
        let trace = a.generate_trace(&honest_input(&a, &[1, 2, 3, 4])).unwrap();
        assert_eq!(trace.width(), a.trace_width_inner());
        assert!(trace.height().is_power_of_two());
    }

    #[test]
    fn test_session_key_trace_generation_rejects_invalid_inputs() {
        let a = air(32);

        let empty_secret = SessionKeyInput {
            shared_secret: vec![],
            session_keys: vec![1u8; 32],
        };
        assert!(matches!(
            a.generate_trace(&empty_secret),
            Err(AirError::InvalidInput { .. })
        ));

        let oversized_secret = SessionKeyInput {
            shared_secret: vec![1u8; MAX_SHARED_SECRET_SIZE + 1],
            session_keys: vec![1u8; 32],
        };
        assert!(matches!(
            a.generate_trace(&oversized_secret),
            Err(AirError::ExceedsMaxSize { .. })
        ));

        let wrong_key_len = SessionKeyInput {
            shared_secret: vec![1u8; 4],
            session_keys: vec![1u8; 31],
        };
        assert!(matches!(
            a.generate_trace(&wrong_key_len),
            Err(AirError::InvalidInput { .. })
        ));
    }

    /// The prover must not be able to obtain a trace for keys it did not derive.
    #[test]
    fn test_session_key_trace_rejects_keys_that_are_not_the_kdf_output() {
        let a = air(32);
        let mut input = honest_input(&a, &[1, 2, 3, 4]);
        input.session_keys[0] ^= 1;
        assert!(matches!(
            a.generate_trace(&input),
            Err(AirError::InvalidInput { .. })
        ));
    }

    #[test]
    fn test_session_key_public_values_deterministic() {
        let a = air(32);
        let input = honest_input(&a, &[9, 8, 7, 6]);
        let pv_a = a.public_values(&input);
        let pv_b = a.public_values(&input);
        assert_eq!(pv_a, pv_b);
        assert_eq!(pv_a.len(), 1);
    }

    /// The property the AIR previously did NOT have: an honest trace satisfies it.
    #[test]
    fn test_session_key_trace_satisfies_constraints() {
        for out_len in [16usize, 32, 64] {
            for secret in [&b"k"[..], &b"shared-secret"[..], &[7u8; 32][..]] {
                let a = air(out_len);
                let input = honest_input(&a, secret);
                let trace = a.generate_trace(&input).expect("trace");
                let pubs = a.public_values(&input);
                check_constraints(&a, &trace, &pubs);
            }
        }
    }

    /// The commitment must be bound: a wrong public value must be rejected.
    #[test]
    #[should_panic(expected = "constraints had nonzero value on row")]
    fn test_session_key_rejects_wrong_public_commitment() {
        let a = air(32);
        let input = honest_input(&a, &[1, 2, 3, 4]);
        let trace = a.generate_trace(&input).expect("trace");
        let mut pubs = a.public_values(&input);
        pubs[0] += TestField::ONE;
        check_constraints(&a, &trace, &pubs);
    }

    /// Zeroing the commit selector must not let a prover escape the binding.
    #[test]
    #[should_panic(expected = "constraints had nonzero value on row")]
    fn test_session_key_rejects_disabled_commit_selector() {
        let a = air(32);
        let input = honest_input(&a, &[1, 2, 3, 4]);
        let mut trace = a.generate_trace(&input).expect("trace");
        let commit_row = (0..trace.height())
            .find(|&r| cell(&trace, r, a.col_sel_commit()) == TestField::ONE)
            .expect("commit row");
        set_cell(&mut trace, commit_row, a.col_sel_commit(), TestField::ZERO);
        check_constraints(&a, &trace, &pubs_of(&a, &input));
    }

    /// Zeroing the squeeze selectors (the other way to dodge the binding) must fail too.
    #[test]
    #[should_panic(expected = "constraints had nonzero value on row")]
    fn test_session_key_rejects_disabled_squeeze_selectors() {
        let a = air(32);
        let input = honest_input(&a, &[1, 2, 3, 4]);
        let mut trace = a.generate_trace(&input).expect("trace");
        for row in 0..trace.height() {
            for j in 0..a.num_blocks() {
                set_cell(&mut trace, row, a.col_sel_sq() + j, TestField::ZERO);
            }
            set_cell(&mut trace, row, a.col_sel_commit(), TestField::ZERO);
            set_cell(&mut trace, row, a.col_acc(), TestField::ZERO);
        }
        check_constraints(&a, &trace, &pubs_of(&a, &input));
    }

    /// Corrupting a squeezed key element must break the commitment sponge.
    #[test]
    #[should_panic(expected = "constraints had nonzero value on row")]
    fn test_session_key_rejects_corrupted_key_material() {
        let a = air(32);
        let input = honest_input(&a, &[1, 2, 3, 4]);
        let mut trace = a.generate_trace(&input).expect("trace");
        let v = cell(&trace, 1, a.col_s1_out());
        set_cell(&mut trace, 1, a.col_s1_out(), v + TestField::ONE);
        check_constraints(&a, &trace, &pubs_of(&a, &input));
    }

    /// Corrupting the sponge-1 capacity must be caught (the old AIR left it unbound).
    #[test]
    #[should_panic(expected = "constraints had nonzero value on row")]
    fn test_session_key_rejects_corrupted_capacity() {
        let a = air(32);
        let input = honest_input(&a, &[1, 2, 3, 4]);
        let mut trace = a.generate_trace(&input).expect("trace");
        let col = a.col_s1_out() + RATE;
        let v = cell(&trace, 0, col);
        set_cell(&mut trace, 0, col, v + TestField::ONE);
        check_constraints(&a, &trace, &pubs_of(&a, &input));
    }

    fn pubs_of(a: &SessionKeyDerivationAir, input: &SessionKeyInput) -> Vec<TestField> {
        a.public_values(input)
    }

    #[test]
    fn test_derive_session_keys_is_deterministic_and_secret_dependent() {
        let a = derive_session_keys(b"secret", 32);
        let b = derive_session_keys(b"secret", 32);
        let c = derive_session_keys(b"secreu", 32);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }
}
