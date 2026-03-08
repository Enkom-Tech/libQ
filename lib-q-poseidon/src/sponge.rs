//! Poseidon sponge construction for hashing
//!
//! This module implements the sponge construction on top of the Poseidon
//! permutation, providing a standard hash function interface.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use lib_q_stark_field::extension::Complex;
use lib_q_stark_mersenne31::Mersenne31;

use crate::params::{
    Poseidon128,
    Poseidon256,
    PoseidonField,
    PoseidonParams,
};
use crate::permutation::PoseidonPermutation;

/// Poseidon sponge for hashing
///
/// This implements the sponge construction using Poseidon permutation.
/// It absorbs input elements and squeezes output elements.
#[derive(Debug, Clone)]
pub struct PoseidonSponge {
    permutation: PoseidonPermutation,
    state: Vec<PoseidonField>,
    rate: usize,
    capacity: usize,
    absorbed: usize,
}

impl PoseidonSponge {
    /// Create a new Poseidon sponge with the given parameters
    pub fn new(params: PoseidonParams) -> Self {
        use lib_q_stark_field::PrimeCharacteristicRing;
        let state_width = params.state_width;
        Self {
            permutation: PoseidonPermutation::new(params.clone()),
            state: alloc::vec![Complex::<Mersenne31>::ZERO; state_width],
            rate: params.rate,
            capacity: params.capacity,
            absorbed: 0,
        }
    }

    /// Absorb field elements into the sponge
    ///
    /// # Arguments
    ///
    /// * `elements` - Field elements to absorb
    pub fn absorb(&mut self, elements: &[PoseidonField]) {
        for &element in elements {
            // Add element to rate part of state
            self.state[self.absorbed] += element;
            self.absorbed += 1;

            // If rate is full, permute
            if self.absorbed >= self.rate {
                self.state = self.permutation.permute(self.state.clone());
                self.absorbed = 0;
            }
        }
    }

    /// Finish absorbing and apply padding (10*1 in rate only)
    ///
    /// Should be called after all input has been absorbed and before squeezing.
    /// Standard sponge padding: add 1 at `state[absorbed]`; if that does not fill
    /// the rate block (`absorbed + 1 < rate`), add 1 at `state[rate - 1]` to
    /// distinguish single-block from multi-block inputs. Capacity is not written.
    pub fn finish_absorbing(&mut self) {
        use lib_q_stark_field::PrimeCharacteristicRing;

        self.state[self.absorbed] += Complex::<Mersenne31>::ONE;
        if self.absorbed + 1 < self.rate {
            self.state[self.rate - 1] += Complex::<Mersenne31>::ONE;
        }

        self.state = self.permutation.permute(self.state.clone());
        self.absorbed = 0;
    }

    /// Squeeze output elements from the sponge
    ///
    /// # Arguments
    ///
    /// * `num_elements` - Number of field elements to squeeze
    ///
    /// # Returns
    ///
    /// Vector of squeezed field elements
    pub fn squeeze(&mut self, num_elements: usize) -> Vec<PoseidonField> {
        let mut output = Vec::with_capacity(num_elements);
        let mut squeezed = 0;

        while squeezed < num_elements {
            // If we've used all rate elements, permute
            if self.absorbed >= self.rate {
                self.state = self.permutation.permute(self.state.clone());
                self.absorbed = 0;
            }

            // Extract from rate part
            output.push(self.state[self.absorbed]);
            self.absorbed += 1;
            squeezed += 1;
        }

        output
    }

    /// Finalize the sponge (apply padding and final permutation)
    ///
    /// This is a convenience method that calls `finish_absorbing()` and returns the final state.
    /// Use `finish_absorbing()` followed by `squeeze()` if you need to extract output.
    pub fn finalize(mut self) -> Vec<PoseidonField> {
        self.finish_absorbing();
        self.state
    }

    /// Get the capacity value
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get the rate value
    pub fn rate(&self) -> usize {
        self.rate
    }
}

/// High-level Poseidon hash interface
pub trait Poseidon {
    /// Hash a slice of field elements
    ///
    /// # Arguments
    ///
    /// * `input` - Input field elements to hash
    ///
    /// # Returns
    ///
    /// Hash output as field elements
    fn hash(&self, input: &[PoseidonField]) -> Vec<PoseidonField>;

    /// Hash and return a single field element
    ///
    /// # Arguments
    ///
    /// * `input` - Input field elements to hash
    ///
    /// # Returns
    ///
    /// First element of hash output
    fn hash_single(&self, input: &[PoseidonField]) -> PoseidonField {
        self.hash(input)[0]
    }
}

impl Poseidon for Poseidon128 {
    fn hash(&self, input: &[PoseidonField]) -> Vec<PoseidonField> {
        let params = Self::params();
        let mut sponge = PoseidonSponge::new(params);
        sponge.absorb(input);
        sponge.finish_absorbing(); // Apply proper padding
        sponge.squeeze(1) // Default to 1 output element
    }
}

impl Poseidon for Poseidon256 {
    fn hash(&self, input: &[PoseidonField]) -> Vec<PoseidonField> {
        let params = Self::params();
        let mut sponge = PoseidonSponge::new(params);
        sponge.absorb(input);
        sponge.finish_absorbing(); // Apply proper padding
        sponge.squeeze(1) // Default to 1 output element
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sponge_absorb_squeeze() {
        let params = Poseidon128::params();
        let mut sponge = PoseidonSponge::new(params);
        let input = alloc::vec![
            Complex::<Mersenne31>::from(Mersenne31::new(1)),
            Complex::<Mersenne31>::from(Mersenne31::new(2)),
        ];
        sponge.absorb(&input);
        let output = sponge.squeeze(1);
        assert_eq!(output.len(), 1);
    }

    #[test]
    fn test_poseidon_hash_deterministic() {
        use super::Poseidon;
        let hasher = Poseidon128;
        let input = alloc::vec![
            Complex::<Mersenne31>::from(Mersenne31::new(1)),
            Complex::<Mersenne31>::from(Mersenne31::new(2)),
        ];
        let hash1 = hasher.hash(&input);
        let hash2 = hasher.hash(&input);
        assert_eq!(hash1, hash2);
    }
}
