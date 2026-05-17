//! Challenge sampling (FIPS 204, Algorithm 29) using SHAKE256 in ML-DSA’s incremental block shape.

use lib_q_sha3::{
    ExtendableOutput,
    Shake256,
    Update,
    XofReader,
};

use crate::constants::{
    COEFFICIENTS_IN_RING_ELEMENT,
    SHAKE256_BLOCK_SIZE,
};
use crate::poly::Poly;

fn inside_out_shuffle(
    randomness: &[u8],
    out_index: &mut usize,
    signs: &mut u64,
    result: &mut [i32; COEFFICIENTS_IN_RING_ELEMENT],
) -> bool {
    let mut done = false;
    for &byte in randomness.iter() {
        if !done {
            let sample_at = byte as usize;
            if sample_at <= *out_index {
                result[*out_index] = result[sample_at];
                *out_index += 1;
                result[sample_at] = 1 - 2 * ((*signs & 1) as i32);
                *signs >>= 1;
            }
            done = *out_index == result.len();
        }
    }
    done
}

/// Sample a sparse ternary polynomial with exactly `number_of_ones` coefficients in `{±1}` and the
/// rest `0`, using SHAKE256 in the same block-wise pattern as `lib-q-ml-dsa` (`sample_challenge_ring_element`).
#[must_use]
pub fn sample_in_ball(seed: &[u8], number_of_ones: usize) -> Poly {
    assert!(number_of_ones <= COEFFICIENTS_IN_RING_ELEMENT);

    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();

    let mut first = [0u8; SHAKE256_BLOCK_SIZE];
    reader.read(&mut first);

    let mut signs = u64::from_le_bytes(first[0..8].try_into().expect("8 bytes"));
    let mut result = [0i32; COEFFICIENTS_IN_RING_ELEMENT];
    let mut out_index = COEFFICIENTS_IN_RING_ELEMENT - number_of_ones;
    let mut done = inside_out_shuffle(&first[8..], &mut out_index, &mut signs, &mut result);

    while !done {
        let mut block = [0u8; SHAKE256_BLOCK_SIZE];
        reader.read(&mut block);
        done = inside_out_shuffle(&block, &mut out_index, &mut signs, &mut result);
    }

    Poly::from_coeffs(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_in_ball_kat_tau_39_49_60() {
        // From `lib-q-ml-dsa/src/sample.rs` test vectors.
        let seed39: [u8; 32] = [
            3, 9, 159, 119, 236, 6, 207, 7, 103, 108, 187, 137, 222, 35, 37, 30, 79, 224, 204, 186,
            41, 38, 148, 188, 201, 50, 105, 155, 129, 217, 124, 57,
        ];
        let exp39: [i32; 256] = [
            0, 0, 1, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 1, 0, -1, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, -1,
            -1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, -1,
            -1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, -1, 0, 0, 0, 0, 0, -1, 1,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, 0, -1, 0, 0, -1, 1, 0, 0, 1,
            0, 0, 0, 1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1,
            0,
        ];
        assert_eq!(sample_in_ball(&seed39, 39).coeffs, exp39);

        let seed49: [u8; 32] = [
            147, 7, 165, 152, 200, 20, 4, 38, 107, 110, 111, 176, 108, 84, 109, 201, 232, 125, 52,
            83, 160, 120, 106, 44, 76, 41, 76, 144, 8, 184, 4, 74,
        ];
        let exp49: [i32; 256] = [
            0, 0, 0, 1, 0, 0, 0, -1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, -1, -1, 0,
            1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0,
            -1, 0, 0, 1, 0, 0, 0, 0, 0, 0, -1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, -1, 0, 0, -1, 0, 0, 0, 0, 1, -1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 1, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            -1, 0, 0, 1, 0, 0, -1, -1, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0,
            0, 0, -1, 0, -1, 0, 0, 0, 0, 1, 0, 0, -1, 0, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, 0,
            -1, 0, -1, 0, 0, -1, 0, 0, -1, 0, -1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0,
            0, -1, 0, 0, 0,
        ];
        assert_eq!(sample_in_ball(&seed49, 49).coeffs, exp49);

        let seed60: [u8; 32] = [
            188, 193, 17, 175, 172, 179, 13, 23, 90, 238, 237, 230, 143, 113, 24, 65, 250, 86, 234,
            229, 251, 57, 199, 158, 9, 4, 102, 249, 11, 68, 140, 107,
        ];
        let exp60: [i32; 256] = [
            0, 0, 0, 0, -1, 0, 0, -1, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0,
            0, 0, 1, 1, 0, 0, 0, 0, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, 0, -1, 0, 0, -1,
            0, 0, 0, 0, 0, -1, 0, -1, 0, 0, 0, 0, -1, 0, 0, 0, -1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0,
            0, 0, 0, 0, -1, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, -1, 0, 0, 0, 0, 0, 0, 0, 1,
            0, 0, 0, 1, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0,
            0, 1, 0, -1, 1, 0, 0, 0, 0, 0, 1, 1, -1, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 0, -1, 0, 0, 1, 0, 0, 1, 1, -1, 0,
            0, 0, 0, 1, -1, 0,
        ];
        assert_eq!(sample_in_ball(&seed60, 60).coeffs, exp60);
    }
}
