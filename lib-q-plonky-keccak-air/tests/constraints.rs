//! Keccak AIR constraint tests: valid trace satisfies constraints, corrupted trace fails.

extern crate alloc;

use alloc::vec::Vec;

use lib_q_plonky_keccak_air::{
    KeccakAir,
    generate_trace_rows,
};
use lib_q_plonky_uni_stark::check_constraints;
use lib_q_stark_field::PrimeCharacteristicRing;
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::Mersenne31;

type F = Mersenne31;

/// Valid Keccak trace: generated trace satisfies AIR constraints.
#[test]
fn valid_keccak_trace_satisfies_constraints() {
    let air = KeccakAir {};
    let input: Vec<[u64; 25]> = vec![[0u64; 25]];
    let trace: RowMajorMatrix<F> = generate_trace_rows(input, 0);
    check_constraints(&air, &trace, &[]);
}

#[test]
#[should_panic(expected = "constraints had nonzero value")]
fn corrupted_keccak_trace_fails_constraints() {
    let air = KeccakAir {};
    let input: Vec<[u64; 25]> = vec![[0u64; 25]];
    let mut trace: RowMajorMatrix<F> = generate_trace_rows(input, 0);
    let row_len = trace.width();
    let corrupt_row = 1usize;
    trace.values[corrupt_row * row_len] = F::ONE; // non-zero to break constraints
    check_constraints(&air, &trace, &[]);
}
