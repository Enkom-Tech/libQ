//! Vector Operations
//!
//! This module provides vector operations used in the HQC implementation.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "random")]
use lib_q_random::LibQRng;
use rand_core::Rng;

use crate::error::HqcError;

/// Add two vectors (XOR in GF(2))
pub fn vect_add(result: &mut [u8], v1: &[u8], v2: &[u8]) -> Result<(), HqcError> {
    let min_len = result.len().min(v1.len()).min(v2.len());
    for i in 0..min_len {
        result[i] = v1[i] ^ v2[i];
    }
    Ok(())
}

/// Compare two vectors
pub fn vect_compare(v1: &[u8], v2: &[u8]) -> Result<bool, HqcError> {
    Ok(v1 == v2)
}

/// Resize vector by truncating or padding
pub fn vect_resize(output: &mut [u8], input: &[u8]) -> Result<(), HqcError> {
    if output.len() <= input.len() {
        // Truncate
        output.copy_from_slice(&input[..output.len()]);
    } else {
        // Pad with zeros
        output[..input.len()].copy_from_slice(input);
        output[input.len()..].fill(0);
    }
    Ok(())
}

/// Generate random vector
pub fn vect_set_random<R: Rng>(result: &mut [u8], rng: &mut R) -> Result<(), HqcError> {
    rng.fill_bytes(result);
    Ok(())
}

/// Generate random vector with fixed weight using rejection sampling
#[cfg(feature = "random")]
pub fn vect_fixed_weight(
    result: &mut [u8],
    weight: usize,
    rng: &mut LibQRng,
) -> Result<(), HqcError> {
    result.fill(0);

    // Generate random positions using rejection sampling
    #[cfg(feature = "alloc")]
    let mut positions = Vec::with_capacity(weight);
    #[cfg(not(feature = "alloc"))]
    let mut positions = [0u32; 256]; // Fixed size array for no_std
    #[cfg(not(feature = "alloc"))]
    let mut positions_len = 0;

    #[cfg(feature = "alloc")]
    let mut random_bytes = {
        let bytes = vec![0u8; 3 * weight];
        bytes
    };
    #[cfg(not(feature = "alloc"))]
    let mut random_bytes = [0u8; 768]; // Fixed size array for no_std

    rng.fill_bytes(&mut random_bytes);

    let mut j = 0;
    for _i in 0..weight {
        let mut random_data: u32;
        let mut exist;

        loop {
            exist = false;

            if j >= random_bytes.len() {
                rng.fill_bytes(&mut random_bytes);
                j = 0;
            }

            random_data = ((random_bytes[j] as u32) << 16) |
                ((random_bytes[j + 1] as u32) << 8) |
                (random_bytes[j + 2] as u32);
            j += 3;

            let pos = random_data % (result.len() as u32);

            // Check if position already exists
            #[cfg(feature = "alloc")]
            {
                for &existing_pos in &positions {
                    if existing_pos == pos {
                        exist = true;
                        break;
                    }
                }
            }
            #[cfg(not(feature = "alloc"))]
            {
                for &existing_pos in positions.iter().take(positions_len) {
                    if existing_pos == pos {
                        exist = true;
                        break;
                    }
                }
            }

            if !exist {
                #[cfg(feature = "alloc")]
                {
                    positions.push(pos);
                }
                #[cfg(not(feature = "alloc"))]
                {
                    if positions_len < positions.len() {
                        positions[positions_len] = pos;
                        positions_len += 1;
                    }
                }
                result[pos as usize] = 1;
                break;
            }
        }
    }

    Ok(())
}

/// Compute Hamming weight of a vector
pub fn vect_hamming_weight(v: &[u8]) -> usize {
    v.iter().map(|&x| x.count_ones() as usize).sum()
}

/// Check if a vector has the expected weight
pub fn vect_check_weight(v: &[u8], expected_weight: usize) -> bool {
    vect_hamming_weight(v) == expected_weight
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "random")]
    use lib_q_random::LibQRng;

    use super::*;

    #[test]
    fn test_vect_add() {
        let v1 = [1, 0, 1, 0];
        let v2 = [0, 1, 1, 0];
        let mut result = [0u8; 4];
        vect_add(&mut result, &v1, &v2).unwrap();
        assert_eq!(result, [1, 1, 0, 0]);
    }

    #[test]
    fn test_vect_compare() {
        let v1 = [1, 0, 1, 0];
        let v2 = [1, 0, 1, 0];
        let v3 = [0, 1, 1, 0];
        assert!(vect_compare(&v1, &v2).unwrap());
        assert!(!vect_compare(&v1, &v3).unwrap());
    }

    #[test]
    fn test_vect_resize() {
        let input = [1, 2, 3, 4, 5];
        let mut output = [0u8; 3];
        vect_resize(&mut output, &input).unwrap();
        assert_eq!(output, [1, 2, 3]);

        let mut output = [0u8; 7];
        vect_resize(&mut output, &input).unwrap();
        assert_eq!(output, [1, 2, 3, 4, 5, 0, 0]);
    }

    #[test]
    #[cfg(feature = "random")]
    fn test_vect_set_random() {
        let mut result = [0u8; 32];
        let mut rng = LibQRng::new_deterministic([42u8; 32]);
        vect_set_random(&mut result, &mut rng).unwrap();
        // Very unlikely to be all zeros
        assert!(result.iter().any(|&x| x != 0));
    }

    #[test]
    #[cfg(feature = "random")]
    fn test_vect_fixed_weight() {
        let mut result = [0u8; 100];
        let mut rng = LibQRng::new_deterministic([42u8; 32]);
        vect_fixed_weight(&mut result, 10, &mut rng).unwrap();
        assert_eq!(vect_hamming_weight(&result), 10);
    }

    #[test]
    fn test_vect_hamming_weight() {
        let v = [1, 0, 1, 0, 1];
        assert_eq!(vect_hamming_weight(&v), 3);
    }

    #[test]
    fn test_vect_check_weight() {
        let v = [1, 0, 1, 0, 1];
        assert!(vect_check_weight(&v, 3));
        assert!(!vect_check_weight(&v, 2));
    }
}
