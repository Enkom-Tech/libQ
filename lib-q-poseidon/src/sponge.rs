//! Poseidon sponge construction for hashing
//!
//! This module implements the sponge construction on top of the Poseidon
//! permutation. The API is split into an absorb phase ([`PoseidonSponge`]) and a
//! squeeze phase ([`PoseidonSpongeSqueeze`]) so padding cannot be followed by
//! further absorption (which would depart from the standard sponge).

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

#[derive(Debug, Clone)]
struct SpongeState {
    permutation: PoseidonPermutation,
    state: Vec<PoseidonField>,
    rate: usize,
    capacity: usize,
    absorbed: usize,
}

impl SpongeState {
    fn new(params: PoseidonParams) -> Self {
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

    fn absorb(&mut self, elements: &[PoseidonField]) {
        for &element in elements {
            self.state[self.absorbed] += element;
            self.absorbed += 1;

            if self.absorbed >= self.rate {
                self.state = self.permutation.permute(self.state.clone());
                self.absorbed = 0;
            }
        }
    }

    /// Apply 10*1 padding in the rate, then permute. `absorbed` counts elements in the current rate block.
    fn apply_padding_and_permute(mut self) -> Self {
        use lib_q_stark_field::PrimeCharacteristicRing;

        self.state[self.absorbed] += Complex::<Mersenne31>::ONE;
        if self.absorbed + 1 < self.rate {
            self.state[self.rate - 1] += Complex::<Mersenne31>::ONE;
        }

        self.state = self.permutation.permute(self.state.clone());
        self.absorbed = 0;
        self
    }

    fn squeeze(&mut self, num_elements: usize) -> Vec<PoseidonField> {
        let mut output = Vec::with_capacity(num_elements);
        let mut squeezed = 0;

        while squeezed < num_elements {
            if self.absorbed >= self.rate {
                self.state = self.permutation.permute(self.state.clone());
                self.absorbed = 0;
            }

            output.push(self.state[self.absorbed]);
            self.absorbed += 1;
            squeezed += 1;
        }

        output
    }
}

/// Poseidon sponge in the absorb phase (before padding).
///
/// Call [`Self::finish_absorbing`] when all input has been absorbed to obtain a
/// [`PoseidonSpongeSqueeze`]. Further absorption is rejected by the type system:
/// the sponge state after padding is not a valid absorb continuation.
#[derive(Debug, Clone)]
pub struct PoseidonSponge(SpongeState);

impl PoseidonSponge {
    /// Create a new Poseidon sponge with the given parameters
    pub fn new(params: PoseidonParams) -> Self {
        Self(SpongeState::new(params))
    }

    /// Absorb field elements into the sponge
    ///
    /// # Arguments
    ///
    /// * `elements` - Field elements to absorb
    pub fn absorb(&mut self, elements: &[PoseidonField]) {
        self.0.absorb(elements);
    }

    /// Finish absorbing and apply padding (10*1 in rate only)
    ///
    /// Should be called after all input has been absorbed. Returns a value that
    /// only supports [`PoseidonSpongeSqueeze::squeeze`], so additional [`PoseidonSponge::absorb`]
    /// calls are impossible after padding (they would define a non-standard sponge).
    ///
    /// Standard sponge padding: add 1 at `state[absorbed]`; if that does not fill
    /// the rate block (`absorbed + 1 < rate`), add 1 at `state[rate - 1]` to
    /// distinguish single-block from multi-block inputs. Capacity is not written.
    ///
    /// # Compile-time safety
    ///
    /// After this call, [`PoseidonSponge`] is consumed; [`PoseidonSpongeSqueeze`] has no
    /// `absorb`, so further input cannot be appended after padding:
    ///
    /// ```compile_fail,E0599
    /// use lib_q_poseidon::{Poseidon128, PoseidonSponge};
    /// let params = Poseidon128::params();
    /// let sponge = PoseidonSponge::new(params);
    /// let mut sponge = sponge.finish_absorbing();
    /// sponge.absorb(&[]);
    /// ```
    pub fn finish_absorbing(self) -> PoseidonSpongeSqueeze {
        PoseidonSpongeSqueeze(self.0.apply_padding_and_permute())
    }

    /// Finalize the sponge (apply padding and final permutation)
    ///
    /// Convenience for callers that need the full width state after padding without
    /// squeezing. Otherwise use [`Self::finish_absorbing`] followed by
    /// [`PoseidonSpongeSqueeze::squeeze`].
    pub fn finalize(self) -> Vec<PoseidonField> {
        self.finish_absorbing().into_state()
    }

    /// Get the capacity value
    pub fn capacity(&self) -> usize {
        self.0.capacity
    }

    /// Get the rate value
    pub fn rate(&self) -> usize {
        self.0.rate
    }
}

/// Poseidon sponge after padding: squeeze output only.
///
/// Produced by [`PoseidonSponge::finish_absorbing`]. Absorption is complete; only
/// [`Self::squeeze`] reads from the rate according to the sponge construction.
#[derive(Debug, Clone)]
pub struct PoseidonSpongeSqueeze(SpongeState);

impl PoseidonSpongeSqueeze {
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
        self.0.squeeze(num_elements)
    }

    /// Full permutation state after padding (including capacity cells).
    pub fn into_state(self) -> Vec<PoseidonField> {
        self.0.state
    }

    /// Get the capacity value
    pub fn capacity(&self) -> usize {
        self.0.capacity
    }

    /// Get the rate value
    pub fn rate(&self) -> usize {
        self.0.rate
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
        let mut sponge = sponge.finish_absorbing();
        sponge.squeeze(1)
    }
}

impl Poseidon for Poseidon256 {
    fn hash(&self, input: &[PoseidonField]) -> Vec<PoseidonField> {
        let params = Self::params();
        let mut sponge = PoseidonSponge::new(params);
        sponge.absorb(input);
        let mut sponge = sponge.finish_absorbing();
        sponge.squeeze(1)
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
        let mut sponge = sponge.finish_absorbing();
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
