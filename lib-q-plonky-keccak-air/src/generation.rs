use alloc::vec::Vec;
use core::array;

use lib_q_stark_air::utils::{
    u64_to_16_bit_limbs,
    u64_to_bits_le,
};
use lib_q_stark_field::PrimeField64;
use lib_q_stark_matrix::dense::RowMajorMatrix;

use crate::columns::{
    KeccakColsRef,
    KeccakColsRefMut,
    NUM_KECCAK_COLS,
};
use crate::{
    NUM_ROUNDS,
    R,
    RC,
    U64_LIMBS,
};

pub fn generate_trace_rows<F: PrimeField64>(
    inputs: Vec<[u64; 25]>,
    extra_capacity_bits: usize,
) -> RowMajorMatrix<F> {
    let num_rows = (inputs.len() * NUM_ROUNDS).next_power_of_two();
    let trace_length = num_rows * NUM_KECCAK_COLS;

    let mut long_trace = F::zero_vec(trace_length << extra_capacity_bits);
    long_trace.truncate(trace_length);

    let mut trace = RowMajorMatrix::new(long_trace, NUM_KECCAK_COLS);

    let num_padding_inputs = num_rows.div_ceil(NUM_ROUNDS) - inputs.len();
    let padded_inputs = inputs
        .into_iter()
        .chain(core::iter::repeat_n([0; 25], num_padding_inputs));

    let num_chunks = num_rows.div_ceil(NUM_ROUNDS);
    for (chunk_idx, input) in padded_inputs.take(num_chunks).enumerate() {
        let row_start = chunk_idx * NUM_ROUNDS * NUM_KECCAK_COLS;
        let chunk_len = core::cmp::min(NUM_ROUNDS, num_rows - chunk_idx * NUM_ROUNDS);
        let mut current_state: [[u64; 5]; 5] =
            array::from_fn(|x| array::from_fn(|y| input[y * 5 + x]));
        let initial_state: [[[F; U64_LIMBS]; 5]; 5] =
            array::from_fn(|y| array::from_fn(|x| u64_to_16_bit_limbs(current_state[x][y])));

        for round in 0..chunk_len {
            let prev_a_vals: Option<[[[F; U64_LIMBS]; 5]; 5]> = if round == 0 {
                None
            } else {
                let prev_slice = &trace.values[row_start + (round - 1) * NUM_KECCAK_COLS..
                    row_start + round * NUM_KECCAK_COLS];
                let prev = KeccakColsRef::from_row_slice(prev_slice);
                Some(array::from_fn(|y| {
                    array::from_fn(|x| array::from_fn(|limb| prev.a_prime_prime_prime(y, x, limb)))
                }))
            };

            let row_slice = &mut trace.values
                [row_start + round * NUM_KECCAK_COLS..row_start + (round + 1) * NUM_KECCAK_COLS];
            let mut row_view = KeccakColsRefMut::new(row_slice).expect("row length");

            if round == 0 {
                for y in 0..5 {
                    for x in 0..5 {
                        for limb in 0..U64_LIMBS {
                            row_view.set_preimage(y, x, limb, initial_state[y][x][limb]);
                            row_view.set_a(y, x, limb, initial_state[y][x][limb]);
                        }
                    }
                }
            } else {
                let prev_a = prev_a_vals.expect("round > 0");
                for y in 0..5 {
                    for x in 0..5 {
                        for limb in 0..U64_LIMBS {
                            row_view.set_preimage(y, x, limb, initial_state[y][x][limb]);
                            row_view.set_a(y, x, limb, prev_a[y][x][limb]);
                        }
                    }
                }
            }

            generate_trace_row_for_round(&mut row_view, round, &mut current_state);
        }
    }

    trace
}

fn generate_trace_row_for_round<F: PrimeField64>(
    row: &mut KeccakColsRefMut<'_, F>,
    round: usize,
    current_state: &mut [[u64; 5]; 5],
) {
    row.set_step_flag(round, F::ONE);

    let state_c: [u64; 5] = current_state.map(|r| r.iter().fold(0, |acc, y| acc ^ y));
    for (x, elem) in state_c.iter().enumerate() {
        let bits = u64_to_bits_le(*elem);
        for (z, &b) in bits.iter().enumerate() {
            row.set_c(x, z, b);
        }
    }

    let state_c_prime: [u64; 5] =
        array::from_fn(|x| state_c[x] ^ state_c[(x + 4) % 5] ^ state_c[(x + 1) % 5].rotate_left(1));
    for (x, elem) in state_c_prime.iter().enumerate() {
        let bits = u64_to_bits_le(*elem);
        for (z, &b) in bits.iter().enumerate() {
            row.set_c_prime(x, z, b);
        }
    }

    *current_state =
        array::from_fn(|i| array::from_fn(|j| current_state[i][j] ^ state_c[i] ^ state_c_prime[i]));
    for (x, x_row) in current_state.iter().enumerate() {
        for (y, elem) in x_row.iter().enumerate() {
            let bits = u64_to_bits_le(*elem);
            for (z, &b) in bits.iter().enumerate() {
                row.set_a_prime(y, x, z, b);
            }
        }
    }

    *current_state = array::from_fn(|i| {
        array::from_fn(|j| {
            let new_i = (i + 3 * j) % 5;
            let new_j = i;
            current_state[new_i][new_j].rotate_left(R[new_i][new_j] as u32)
        })
    });

    *current_state = array::from_fn(|i| {
        array::from_fn(|j| {
            current_state[i][j] ^ ((!current_state[(i + 1) % 5][j]) & current_state[(i + 2) % 5][j])
        })
    });
    for (x, x_row) in current_state.iter().enumerate() {
        for (y, elem) in x_row.iter().enumerate() {
            let limbs = u64_to_16_bit_limbs(*elem);
            for (limb, &l) in limbs.iter().enumerate() {
                row.set_a_prime_prime(y, x, limb, l);
            }
        }
    }

    let bits_0_0 = u64_to_bits_le(current_state[0][0]);
    for (i, &b) in bits_0_0.iter().enumerate() {
        row.set_a_prime_prime_0_0_bits(i, b);
    }

    current_state[0][0] ^= RC[round];

    let limbs_0_0 = u64_to_16_bit_limbs(current_state[0][0]);
    for (limb, &l) in limbs_0_0.iter().enumerate() {
        row.set_a_prime_prime_prime_0_0_limbs(limb, l);
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use lib_q_stark_mersenne31::Mersenne31;
    use lib_q_stark_symmetric::Permutation;

    use super::*;
    use crate::columns::KeccakColsRef;

    fn extract_output_from_row<F: PrimeField64>(row: KeccakColsRef<'_, F>) -> [u64; 25] {
        let mut output = [0u64; 25];
        for y in 0..5 {
            for x in 0..5 {
                let mut value = 0u64;
                for limb in 0..U64_LIMBS {
                    let limb_val = row.a_prime_prime_prime(y, x, limb).as_canonical_u64();
                    value |= limb_val << (limb * 16);
                }
                output[x + 5 * y] = value;
            }
        }
        output
    }

    fn extract_input_from_row<F: PrimeField64>(row: KeccakColsRef<'_, F>) -> [u64; 25] {
        let mut input = [0u64; 25];
        for y in 0..5 {
            for x in 0..5 {
                let mut value = 0u64;
                for limb in 0..U64_LIMBS {
                    let limb_val = row.preimage(y, x, limb).as_canonical_u64();
                    value |= limb_val << (limb * 16);
                }
                input[x + 5 * y] = value;
            }
        }
        input
    }

    #[test]
    fn test_keccak_permutation_matches_reference() {
        use lib_q_stark_symmetric::KeccakF;

        let input: [u64; 25] = array::from_fn(|i| i as u64 * 0x0123456789ABCDEFu64);

        let mut expected_output = input;
        KeccakF.permute_mut(&mut expected_output);

        let trace = generate_trace_rows::<Mersenne31>(vec![input], 0);
        let first_row = KeccakColsRef::from_row_slice(&trace.values[0..NUM_KECCAK_COLS]);
        let last_row = KeccakColsRef::from_row_slice(
            &trace.values[(NUM_ROUNDS - 1) * NUM_KECCAK_COLS..NUM_ROUNDS * NUM_KECCAK_COLS],
        );

        let stored_input = extract_input_from_row(first_row);
        assert_eq!(
            stored_input, input,
            "Input state should match the provided input"
        );

        let our_output = extract_output_from_row(last_row);
        assert_eq!(
            our_output, expected_output,
            "Keccak-f output should match reference implementation"
        );
    }

    #[test]
    fn test_keccak_permutation_zero_state() {
        use lib_q_stark_symmetric::KeccakF;

        let input = [0u64; 25];

        let mut expected_output = input;
        KeccakF.permute_mut(&mut expected_output);

        let trace = generate_trace_rows::<Mersenne31>(vec![input], 0);
        let last_row = KeccakColsRef::from_row_slice(
            &trace.values[(NUM_ROUNDS - 1) * NUM_KECCAK_COLS..NUM_ROUNDS * NUM_KECCAK_COLS],
        );

        let our_output = extract_output_from_row(last_row);
        assert_eq!(
            our_output, expected_output,
            "Keccak-f on zero state should match reference"
        );
    }

    #[test]
    fn test_keccak_permutation_known_vector() {
        use lib_q_stark_symmetric::KeccakF;

        let mut input = [0u64; 25];
        input[0] = 1;

        let mut expected_output = input;
        KeccakF.permute_mut(&mut expected_output);

        let trace = generate_trace_rows::<Mersenne31>(vec![input], 0);
        let last_row = KeccakColsRef::from_row_slice(
            &trace.values[(NUM_ROUNDS - 1) * NUM_KECCAK_COLS..NUM_ROUNDS * NUM_KECCAK_COLS],
        );

        let our_output = extract_output_from_row(last_row);
        assert_eq!(
            our_output, expected_output,
            "Keccak-f with input[0]=1 should match reference"
        );
    }

    #[test]
    fn test_multiple_permutations() {
        use lib_q_stark_symmetric::KeccakF;

        let inputs: Vec<[u64; 25]> = (0..4)
            .map(|i| array::from_fn(|j| (i * 25 + j) as u64))
            .collect();

        let expected_outputs: Vec<[u64; 25]> = inputs
            .iter()
            .map(|input| {
                let mut output = *input;
                KeccakF.permute_mut(&mut output);
                output
            })
            .collect();

        let trace = generate_trace_rows::<Mersenne31>(inputs, 0);

        for (i, expected) in expected_outputs.iter().enumerate() {
            let start = (i * NUM_ROUNDS + NUM_ROUNDS - 1) * NUM_KECCAK_COLS;
            let last_row =
                KeccakColsRef::from_row_slice(&trace.values[start..start + NUM_KECCAK_COLS]);
            let our_output = extract_output_from_row(last_row);
            assert_eq!(
                our_output, *expected,
                "Permutation {} should match reference",
                i
            );
        }
    }

    #[test]
    fn test_input_output_limb_indexing() {
        let input: [u64; 25] = array::from_fn(|i| i as u64 + 1);
        let trace = generate_trace_rows::<Mersenne31>(vec![input], 0);
        let first_row = KeccakColsRef::from_row_slice(&trace.values[0..NUM_KECCAK_COLS]);

        for (i_u64, &expected_val) in input.iter().enumerate() {
            let y = i_u64 / 5;
            let x = i_u64 % 5;

            let mut stored_value = 0u64;
            for limb in 0..U64_LIMBS {
                let limb_val = first_row.preimage(y, x, limb).as_canonical_u64();
                stored_value |= limb_val << (limb * 16);
            }

            assert_eq!(
                stored_value, expected_val,
                "preimage[{}][{}] should equal input[{}]",
                y, x, i_u64
            );
        }
    }
}
