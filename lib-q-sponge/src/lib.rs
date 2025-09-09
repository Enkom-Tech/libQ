//! lib-Q Sponge - Sponge Functions for lib-Q
//!
//! This crate provides sponge functions including Keccak for use in lib-Q.
//!
//! ## Features
//!
//! - Keccak sponge functions (f1600, f800, f400, f200)
//! - Ascon sponge functions (permute_1, permute_6, permute_8, permute_12)
//! - Optimized implementations for various platforms
//! - Feature detection and automatic selection of best implementation
//! - Comprehensive test coverage

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

// Re-export keccak functions
// Re-export ascon functions
pub use lib_q_ascon::*;
pub use lib_q_keccak::*;

/// Sponge functions for quantum-resistant cryptography
///
/// This module provides a unified interface for sponge functions
/// used in post-quantum cryptographic algorithms.
pub mod sponge {
    use super::*;

    /// Absorb data into a Keccak state
    ///
    /// # Arguments
    ///
    /// * `state` - The Keccak state to absorb into
    /// * `data` - The data to absorb
    /// * `rate` - The rate of absorption (in bytes)
    ///
    /// # Example
    ///
    /// ```
    /// use lib_q_sponge::sponge::absorb_keccak;
    ///
    /// let mut state = [0u64; 25];
    /// let data = [0x01, 0x02, 0x03, 0x04];
    /// absorb_keccak(&mut state, &data, 4);
    /// ```
    pub fn absorb_keccak(state: &mut [u64; 25], data: &[u8], rate: usize) {
        let mut offset = 0;
        let mut remaining = data.len();

        while remaining >= rate {
            for i in 0..rate / 8 {
                let mut v = 0u64;
                for j in 0..8 {
                    v |= (data[offset + i * 8 + j] as u64) << (8 * j);
                }
                state[i] ^= v;
            }

            f1600(state);
            offset += rate;
            remaining -= rate;
        }

        // Handle remaining bytes
        if remaining > 0 {
            for i in 0..remaining / 8 {
                let mut v = 0u64;
                for j in 0..8 {
                    v |= (data[offset + i * 8 + j] as u64) << (8 * j);
                }
                state[i] ^= v;
            }

            // Handle remaining bytes that don't fill a u64
            let extra = remaining % 8;
            if extra > 0 {
                let i = remaining / 8;
                let mut v = 0u64;
                for j in 0..extra {
                    v |= (data[offset + i * 8 + j] as u64) << (8 * j);
                }
                state[i] ^= v;
            }
        }
    }

    /// Absorb data into an Ascon state
    ///
    /// # Arguments
    ///
    /// * `state` - The Ascon state to absorb into
    /// * `data` - The data to absorb
    /// * `rate` - The rate of absorption (in bytes)
    ///
    /// # Example
    ///
    /// ```
    /// use lib_q_sponge::State;
    /// use lib_q_sponge::sponge::absorb_ascon;
    ///
    /// let mut state = State::new(0, 0, 0, 0, 0);
    /// let data = [0x01, 0x02, 0x03, 0x04];
    /// absorb_ascon(&mut state, &data, 4);
    /// ```
    pub fn absorb_ascon(state: &mut State, data: &[u8], rate: usize) {
        let mut offset = 0;
        let mut remaining = data.len();

        while remaining >= rate {
            // Absorb full blocks
            for i in 0..rate / 8 {
                let mut v = 0u64;
                for j in 0..8 {
                    v |= (data[offset + i * 8 + j] as u64) << (56 - 8 * j); // Big-endian
                }
                state[i] ^= v;
            }

            state.permute_12();
            offset += rate;
            remaining -= rate;
        }

        // Handle remaining bytes
        if remaining > 0 {
            for i in 0..remaining / 8 {
                let mut v = 0u64;
                for j in 0..8 {
                    v |= (data[offset + i * 8 + j] as u64) << (56 - 8 * j); // Big-endian
                }
                state[i] ^= v;
            }

            // Handle remaining bytes that don't fill a u64
            let extra = remaining % 8;
            if extra > 0 {
                let i = remaining / 8;
                let mut v = 0u64;
                for j in 0..extra {
                    v |= (data[offset + i * 8 + j] as u64) << (56 - 8 * j); // Big-endian
                }
                state[i] ^= v;
            }
        }
    }

    /// Squeeze data from a Keccak state
    ///
    /// # Arguments
    ///
    /// * `state` - The Keccak state to squeeze from
    /// * `output` - The buffer to squeeze into
    /// * `rate` - The rate of squeezing (in bytes)
    ///
    /// # Example
    ///
    /// ```
    /// use lib_q_sponge::sponge::squeeze_keccak;
    ///
    /// let mut state = [0u64; 25];
    /// let mut output = [0u8; 32];
    /// squeeze_keccak(&mut state, &mut output, 4);
    /// ```
    pub fn squeeze_keccak(state: &mut [u64; 25], output: &mut [u8], rate: usize) {
        let mut offset = 0;
        let mut remaining = output.len();

        while remaining >= rate {
            // Extract full blocks
            for i in 0..rate / 8 {
                let v = state[i];
                for j in 0..8 {
                    output[offset + i * 8 + j] = (v >> (8 * j)) as u8;
                }
            }

            f1600(state);
            offset += rate;
            remaining -= rate;
        }

        // Handle remaining bytes
        if remaining > 0 {
            for i in 0..remaining / 8 {
                let v = state[i];
                for j in 0..8 {
                    output[offset + i * 8 + j] = (v >> (8 * j)) as u8;
                }
            }

            // Handle remaining bytes that don't fill a u64
            let extra = remaining % 8;
            if extra > 0 {
                let i = remaining / 8;
                let v = state[i];
                for j in 0..extra {
                    output[offset + i * 8 + j] = (v >> (8 * j)) as u8;
                }
            }
        }
    }

    /// Squeeze data from an Ascon state
    ///
    /// # Arguments
    ///
    /// * `state` - The Ascon state to squeeze from
    /// * `output` - The buffer to squeeze into
    /// * `rate` - The rate of squeezing (in bytes)
    ///
    /// # Example
    ///
    /// ```
    /// use lib_q_sponge::State;
    /// use lib_q_sponge::sponge::squeeze_ascon;
    ///
    /// let mut state = State::new(0, 0, 0, 0, 0);
    /// let mut output = [0u8; 32];
    /// squeeze_ascon(&mut state, &mut output, 4);
    /// ```
    pub fn squeeze_ascon(state: &mut State, output: &mut [u8], rate: usize) {
        let mut offset = 0;
        let mut remaining = output.len();

        while remaining >= rate {
            // Extract full blocks
            for i in 0..rate / 8 {
                let v = state[i];
                for j in 0..8 {
                    output[offset + i * 8 + j] = (v >> (56 - 8 * j)) as u8; // Big-endian
                }
            }

            state.permute_12();
            offset += rate;
            remaining -= rate;
        }

        // Handle remaining bytes
        if remaining > 0 {
            for i in 0..remaining / 8 {
                let v = state[i];
                for j in 0..8 {
                    output[offset + i * 8 + j] = (v >> (56 - 8 * j)) as u8; // Big-endian
                }
            }

            // Handle remaining bytes that don't fill a u64
            let extra = remaining % 8;
            if extra > 0 {
                let i = remaining / 8;
                let v = state[i];
                for j in 0..extra {
                    output[offset + i * 8 + j] = (v >> (56 - 8 * j)) as u8; // Big-endian
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak_absorb_squeeze() {
        let mut state = [0u64; 25];
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let rate = 8;

        sponge::absorb_keccak(&mut state, &data, rate);

        // Check that state changed
        assert_ne!(state, [0u64; 25]);

        let mut output = [0u8; 8];
        sponge::squeeze_keccak(&mut state, &mut output, rate);

        // Output should not be all zeros
        assert_ne!(output, [0u8; 8]);
    }

    #[test]
    fn test_ascon_absorb_squeeze() {
        let mut state = State::new(0, 0, 0, 0, 0);
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let rate = 8;

        sponge::absorb_ascon(&mut state, &data, rate);

        // Check that state changed
        let zero_state = State::new(0, 0, 0, 0, 0);
        assert!(
            state[0] != zero_state[0] ||
                state[1] != zero_state[1] ||
                state[2] != zero_state[2] ||
                state[3] != zero_state[3] ||
                state[4] != zero_state[4]
        );

        let mut output = [0u8; 8];
        sponge::squeeze_ascon(&mut state, &mut output, rate);

        // Output should not be all zeros
        assert_ne!(output, [0u8; 8]);
    }

    #[test]
    fn test_keccak_absorb_partial() {
        let mut state = [0u64; 25];
        let data = [0x01, 0x02, 0x03]; // Partial block
        let rate = 8;

        sponge::absorb_keccak(&mut state, &data, rate);

        // Check that state changed correctly
        assert_eq!(state[0], 0x030201); // Little-endian

        // Rest of the state should be zeros
        for (i, &value) in state.iter().enumerate().skip(1) {
            assert_eq!(value, 0, "State[{}] should be zero", i);
        }
    }

    #[test]
    fn test_ascon_absorb_partial() {
        let mut state = State::new(0, 0, 0, 0, 0);
        let data = [0x01, 0x02, 0x03]; // Partial block
        let rate = 8;

        sponge::absorb_ascon(&mut state, &data, rate);

        // Check that state changed correctly (big-endian)
        assert_eq!(state[0], 0x0102030000000000); // Big-endian

        // Rest of the state should be zeros
        for i in 1..5 {
            assert_eq!(state[i], 0);
        }
    }

    #[test]
    fn test_keccak_squeeze_partial() {
        let mut state = [0u64; 25];
        state[0] = 0x0102030405060708;

        let mut output = [0u8; 3]; // Partial block
        let rate = 8;

        sponge::squeeze_keccak(&mut state, &mut output, rate);

        // Check output (little-endian)
        assert_eq!(output, [0x08, 0x07, 0x06]);
    }

    #[test]
    fn test_ascon_squeeze_partial() {
        let mut state = State::new(0x0102030405060708, 0, 0, 0, 0);

        let mut output = [0u8; 3]; // Partial block
        let rate = 8;

        sponge::squeeze_ascon(&mut state, &mut output, rate);

        // Check output (big-endian)
        assert_eq!(output, [0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_keccak_multiple_blocks() {
        let mut state = [0u64; 25];
        let data = [0x01; 16]; // Two blocks with rate=8
        let rate = 8;

        sponge::absorb_keccak(&mut state, &data, rate);

        // State should have been permuted at least once
        assert_ne!(state, [0u64; 25]);

        let mut output = [0u8; 16];
        sponge::squeeze_keccak(&mut state, &mut output, rate);

        // Output should not be all zeros
        assert_ne!(output, [0u8; 16]);
    }

    #[test]
    fn test_ascon_multiple_blocks() {
        let mut state = State::new(0, 0, 0, 0, 0);
        let data = [0x01; 16]; // Two blocks with rate=8
        let rate = 8;

        sponge::absorb_ascon(&mut state, &data, rate);

        // State should have been permuted at least once
        let zero_state = State::new(0, 0, 0, 0, 0);
        assert!(
            state[0] != zero_state[0] ||
                state[1] != zero_state[1] ||
                state[2] != zero_state[2] ||
                state[3] != zero_state[3] ||
                state[4] != zero_state[4]
        );

        let mut output = [0u8; 16];
        sponge::squeeze_ascon(&mut state, &mut output, rate);

        // Output should not be all zeros
        assert_ne!(output, [0u8; 16]);
    }
}
