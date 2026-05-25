//! `SerializingHasher` parallel path (uses `Mersenne31`).

use core::array;

use lib_q_stark_mersenne31::Mersenne31;
use lib_q_stark_symmetric::{
    CryptographicHasher,
    SerializingHasher,
};

#[derive(Clone)]
struct MockHasher;

impl CryptographicHasher<u8, [u8; 4]> for MockHasher {
    fn hash_iter<I: IntoIterator<Item = u8>>(&self, iter: I) -> [u8; 4] {
        let sum: u8 = iter.into_iter().fold(0, |acc, x| acc.wrapping_add(x));
        [sum; 4]
    }
}

impl CryptographicHasher<[u8; 4], [[u8; 4]; 4]> for MockHasher {
    fn hash_iter<I: IntoIterator<Item = [u8; 4]>>(&self, iter: I) -> [[u8; 4]; 4] {
        let sum: [u8; 4] = iter.into_iter().fold([0, 0, 0, 0], |acc, x| {
            [
                acc[0].wrapping_add(x[0]),
                acc[1].wrapping_add(x[1]),
                acc[2].wrapping_add(x[2]),
                acc[3].wrapping_add(x[3]),
            ]
        });
        [sum; 4]
    }
}

impl CryptographicHasher<u32, [u32; 4]> for MockHasher {
    fn hash_iter<I: IntoIterator<Item = u32>>(&self, iter: I) -> [u32; 4] {
        let sum: u32 = iter.into_iter().fold(0, |acc, x| acc.wrapping_add(x));
        [sum; 4]
    }
}

impl CryptographicHasher<[u32; 4], [[u32; 4]; 4]> for MockHasher {
    fn hash_iter<I: IntoIterator<Item = [u32; 4]>>(&self, iter: I) -> [[u32; 4]; 4] {
        let sum: [u32; 4] = iter.into_iter().fold([0, 0, 0, 0], |acc, x| {
            [
                acc[0].wrapping_add(x[0]),
                acc[1].wrapping_add(x[1]),
                acc[2].wrapping_add(x[2]),
                acc[3].wrapping_add(x[3]),
            ]
        });
        [sum; 4]
    }
}

impl CryptographicHasher<u64, [u64; 4]> for MockHasher {
    fn hash_iter<I: IntoIterator<Item = u64>>(&self, iter: I) -> [u64; 4] {
        let sum: u64 = iter.into_iter().fold(0, |acc, x| acc.wrapping_add(x));
        [sum; 4]
    }
}

impl CryptographicHasher<[u64; 4], [[u64; 4]; 4]> for MockHasher {
    fn hash_iter<I: IntoIterator<Item = [u64; 4]>>(&self, iter: I) -> [[u64; 4]; 4] {
        let sum: [u64; 4] = iter.into_iter().fold([0, 0, 0, 0], |acc, x| {
            [
                acc[0].wrapping_add(x[0]),
                acc[1].wrapping_add(x[1]),
                acc[2].wrapping_add(x[2]),
                acc[3].wrapping_add(x[3]),
            ]
        });
        [sum; 4]
    }
}

#[test]
fn test_parallel_hashers() {
    let mock_hash = MockHasher {};
    let hasher = SerializingHasher::new(mock_hash);
    let input: [Mersenne31; 256] = Mersenne31::new_array(array::from_fn(|x| x as u32));

    let parallel_input: [[Mersenne31; 4]; 64] = unsafe { core::mem::transmute(input) };
    let unzipped_input: [[Mersenne31; 64]; 4] = array::from_fn(|i| parallel_input.map(|x| x[i]));

    let u8_output_parallel: [[u8; 4]; 4] = hasher.hash_iter(parallel_input);
    let u8_output_individual: [[u8; 4]; 4] = unzipped_input.map(|x| hasher.hash_iter(x));
    let u8_output_individual_transposed = array::from_fn(|i| u8_output_individual.map(|x| x[i]));

    let u32_output_parallel: [[u32; 4]; 4] = hasher.hash_iter(parallel_input);
    let u32_output_individual: [[u32; 4]; 4] = unzipped_input.map(|x| hasher.hash_iter(x));
    let u32_output_individual_transposed = array::from_fn(|i| u32_output_individual.map(|x| x[i]));

    let u64_output_parallel: [[u64; 4]; 4] = hasher.hash_iter(parallel_input);
    let u64_output_individual: [[u64; 4]; 4] = unzipped_input.map(|x| hasher.hash_iter(x));
    let u64_output_individual_transposed = array::from_fn(|i| u64_output_individual.map(|x| x[i]));

    assert_eq!(u8_output_parallel, u8_output_individual_transposed);
    assert_eq!(u32_output_parallel, u32_output_individual_transposed);
    assert_eq!(u64_output_parallel, u64_output_individual_transposed);
}
