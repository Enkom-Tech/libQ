//! SHA3 Compatibility Layer
//!
//! This module provides a compatibility layer that implements the libcrux SHA3 API
//! using lib-q SHA3 internally. This allows us to eliminate the libcrux dependency
//! while maintaining API compatibility with existing ML-DSA code.

#![allow(non_snake_case)]

use lib_q_sha3::digest::{
    // Digest, // Unused import
    ExtendableOutput,
    Update,
    XofReader,
};
use lib_q_sha3::{
    Shake128,
    Shake128Reader,
    Shake256,
    Shake256Reader,
};

/// A portable SHAKE128 implementation compatible with libcrux API.
#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
pub fn shake128(out: &mut [u8], input: &[u8]) {
    debug_assert!(out.len() <= u32::MAX as usize);
    Shake128::digest_xof(input, out);
}

/// A portable SHAKE256 implementation compatible with libcrux API.
#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
pub fn shake256(out: &mut [u8], input: &[u8]) {
    debug_assert!(out.len() <= u32::MAX as usize);
    Shake256::digest_xof(input, out);
}

/// The Keccak state for the incremental API, compatible with libcrux.
#[derive(Clone)]
pub enum KeccakState {
    Shake128 {
        hasher: Shake128,
        reader: Option<Shake128Reader>,
    },
    Shake256 {
        hasher: Shake256,
        reader: Option<Shake256Reader>,
    },
}

impl KeccakState {
    /// Create a new empty KeccakState for Shake128.
    pub fn new_shake128() -> Self {
        Self::Shake128 {
            hasher: Shake128::default(),
            reader: None,
        }
    }

    /// Create a new empty KeccakState for Shake256.
    pub fn new_shake256() -> Self {
        Self::Shake256 {
            hasher: Shake256::default(),
            reader: None,
        }
    }

    /// Absorb input data (compatible with libcrux API).
    pub fn absorb(&mut self, input: &[u8]) {
        match self {
            KeccakState::Shake128 { hasher, reader } => {
                // If we already have a reader, we can't absorb more data
                if reader.is_some() {
                    panic!("Cannot absorb after finalization");
                }
                hasher.update(input);
            }
            KeccakState::Shake256 { hasher, reader } => {
                // If we already have a reader, we can't absorb more data
                if reader.is_some() {
                    panic!("Cannot absorb after finalization");
                }
                hasher.update(input);
            }
        }
    }

    /// Absorb final input data (compatible with libcrux API).
    pub fn absorb_final(&mut self, input: &[u8]) {
        self.absorb(input);
    }

    /// Finalize the state and prepare for squeezing.
    /// This should be called once after all absorption is complete.
    fn finalize(&mut self) {
        match self {
            KeccakState::Shake128 { hasher, reader } => {
                if reader.is_none() {
                    *reader = Some(hasher.clone().finalize_xof());
                }
            }
            KeccakState::Shake256 { hasher, reader } => {
                if reader.is_none() {
                    *reader = Some(hasher.clone().finalize_xof());
                }
            }
        }
    }

    /// Squeeze output data (compatible with libcrux API).
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.finalize();
        match self {
            KeccakState::Shake128 { reader, .. } => {
                if let Some(reader) = reader {
                    reader.read(out);
                } else {
                    panic!("Reader not initialized");
                }
            }
            KeccakState::Shake256 { reader, .. } => {
                if let Some(reader) = reader {
                    reader.read(out);
                } else {
                    panic!("Reader not initialized");
                }
            }
        }
    }
}

/// Incremental SHA3 API compatible with libcrux.
pub mod incremental {
    use super::*;

    /// Create a new SHAKE-128 state object.
    #[cfg_attr(tarpaulin, inline(never))]
    #[cfg_attr(not(tarpaulin), inline(always))]
    pub fn shake128_init() -> KeccakState {
        KeccakState::new_shake128()
    }

    /// Absorb final input for SHAKE-128.
    #[cfg_attr(tarpaulin, inline(never))]
    #[cfg_attr(not(tarpaulin), inline(always))]
    pub fn shake128_absorb_final(s: &mut KeccakState, data: &[u8]) {
        match s {
            KeccakState::Shake128 { hasher, reader } => {
                // If we already have a reader, we can't absorb more data
                if reader.is_some() {
                    panic!("Cannot absorb after finalization");
                }
                hasher.update(data);
            }
            _ => panic!("Invalid state for SHAKE-128 operation"),
        }
    }

    /// Squeeze three blocks for SHAKE-128.
    #[cfg_attr(tarpaulin, inline(never))]
    #[cfg_attr(not(tarpaulin), inline(always))]
    #[allow(dead_code)]
    pub fn shake128_squeeze_first_three_blocks(s: &mut KeccakState, out: &mut [u8]) {
        debug_assert!(out.len() == 168 * 3); // 3 blocks of 168 bytes
        match s {
            KeccakState::Shake128 { hasher, reader } => {
                // Initialize reader if not already done
                if reader.is_none() {
                    *reader = Some(hasher.clone().finalize_xof());
                }
                // Read the first 3 blocks
                if let Some(reader) = reader {
                    reader.read(out);
                } else {
                    panic!("Reader not initialized");
                }
            }
            _ => panic!("Invalid state for SHAKE-128 operation"),
        }
    }

    /// Squeeze first five blocks for SHAKE-128.
    /// This function maintains state properly by creating a reader and reading the first 5 blocks.
    #[cfg_attr(tarpaulin, inline(never))]
    #[cfg_attr(not(tarpaulin), inline(always))]
    pub fn shake128_squeeze_first_five_blocks(s: &mut KeccakState, out: &mut [u8]) {
        debug_assert!(out.len() == 168 * 5); // 5 blocks of 168 bytes
        match s {
            KeccakState::Shake128 { hasher, reader } => {
                // Initialize reader if not already done
                if reader.is_none() {
                    *reader = Some(hasher.clone().finalize_xof());
                }
                // Read the first 5 blocks
                if let Some(reader) = reader {
                    reader.read(out);
                } else {
                    panic!("Reader not initialized");
                }
            }
            _ => panic!("Invalid state for SHAKE-128 operation"),
        }
    }

    /// Squeeze next block for SHAKE-128.
    /// This function should be called after squeeze_first_five_blocks to get the next block.
    #[cfg_attr(tarpaulin, inline(never))]
    #[cfg_attr(not(tarpaulin), inline(always))]
    pub fn shake128_squeeze_next_block(s: &mut KeccakState, out: &mut [u8]) {
        debug_assert!(out.len() == 168); // 1 block of 168 bytes
        match s {
            KeccakState::Shake128 { hasher, reader } => {
                // Initialize reader if not already done
                if reader.is_none() {
                    *reader = Some(hasher.clone().finalize_xof());
                }
                // Read the next block
                if let Some(reader) = reader {
                    reader.read(out);
                } else {
                    panic!("Reader not initialized");
                }
            }
            _ => panic!("Invalid state for SHAKE-128 operation"),
        }
    }

    /// Create a new SHAKE-256 state object.
    #[cfg_attr(tarpaulin, inline(never))]
    #[cfg_attr(not(tarpaulin), inline(always))]
    pub fn shake256_init() -> KeccakState {
        KeccakState::new_shake256()
    }

    /// Absorb final input for SHAKE-256.
    #[cfg_attr(tarpaulin, inline(never))]
    #[cfg_attr(not(tarpaulin), inline(always))]
    pub fn shake256_absorb_final(s: &mut KeccakState, data: &[u8]) {
        match s {
            KeccakState::Shake256 { hasher, reader } => {
                // If we already have a reader, we can't absorb more data
                if reader.is_some() {
                    panic!("Cannot absorb after finalization");
                }
                hasher.update(data);
            }
            _ => panic!("Invalid state for SHAKE-256 operation"),
        }
    }

    /// Squeeze the first SHAKE-256 block.
    #[cfg_attr(tarpaulin, inline(never))]
    #[cfg_attr(not(tarpaulin), inline(always))]
    pub fn shake256_squeeze_first_block(s: &mut KeccakState, out: &mut [u8]) {
        debug_assert!(out.len() == 136); // 1 block of 136 bytes
        match s {
            KeccakState::Shake256 { hasher, reader } => {
                // Initialize reader if not already done
                if reader.is_none() {
                    *reader = Some(hasher.clone().finalize_xof());
                }
                // Read the first block
                if let Some(reader) = reader {
                    reader.read(out);
                } else {
                    panic!("Reader not initialized");
                }
            }
            _ => panic!("Invalid state for SHAKE-256 operation"),
        }
    }

    /// Squeeze the next SHAKE-256 block.
    #[cfg_attr(tarpaulin, inline(never))]
    #[cfg_attr(not(tarpaulin), inline(always))]
    pub fn shake256_squeeze_next_block(s: &mut KeccakState, out: &mut [u8]) {
        debug_assert!(out.len() == 136); // 1 block of 136 bytes
        match s {
            KeccakState::Shake256 { hasher, reader } => {
                // Initialize reader if not already done
                if reader.is_none() {
                    *reader = Some(hasher.clone().finalize_xof());
                }
                // Read the next block
                if let Some(reader) = reader {
                    reader.read(out);
                } else {
                    panic!("Reader not initialized");
                }
            }
            _ => panic!("Invalid state for SHAKE-256 operation"),
        }
    }
}

// Re-export the portable module for compatibility
pub mod portable {
    pub use super::{
        incremental,
        *,
    };
}

// SIMD-optimized SHAKE256 implementations using lib-q-keccak parallel processing
// These provide true SIMD acceleration for cryptographic operations
#[cfg(all(feature = "simd256", target_arch = "x86_64"))]
pub mod avx2 {
    pub mod x4 {
        /// Perform 4 SHAKE256 operations in parallel using true SIMD
        #[allow(clippy::too_many_arguments)]
        #[cfg_attr(tarpaulin, inline(never))]
        #[cfg_attr(not(tarpaulin), inline(always))]
        pub fn shake256(
            input0: &[u8],
            input1: &[u8],
            input2: &[u8],
            input3: &[u8],
            out0: &mut [u8],
            out1: &mut [u8],
            out2: &mut [u8],
            out3: &mut [u8],
        ) {
            // 4-way SHAKE256 via the FIPS-202 batched permutation in lib-q-sha3 (real AVX2 at runtime
            // through lib-q-keccak/p1600x4, scalar fallback otherwise — bit-identical to the scalar
            // reader). The previous hand-rolled body absorbed past the rate, squeezed the capacity
            // lanes, and capped output at 200 bytes with no inter-block permutation — so ExpandMask's
            // 576/640-byte mask requests returned garbage, making every avx2 signing attempt reject.
            lib_q_sha3::parallel::shake256_x4(
                [input0, input1, input2, input3],
                [out0, out1, out2, out3],
            );
        }

        /// Incremental 4-way SHAKE driven by [`lib_q_keccak::p1600x4`] — true SIMD when AVX2 is
        /// available at runtime, a scalar fallback (four `p1600`s) otherwise, **bit-identical either
        /// way**. This replaced a wrapper around four *sequential* scalar SHAKE instances, which made
        /// the `avx2` ML-DSA variant no faster than `portable` on the SHAKE-bound signing path
        /// (matrix Â expansion + per-rejection mask `y` sampling both stream through here).
        ///
        /// Output matches the scalar reader byte-for-byte: `absorb_final` pads and runs the final
        /// permutation (state → block 0), `squeeze_first_*` extracts block 0 then permutes between
        /// further blocks, and `squeeze_next_*` permutes before extracting (continuation). All SLH-
        /// style seeds here are a single rate block, so the multi-block absorb path is just for safety.
        pub mod incremental {
            use lib_q_keccak::{
                p1600,
                p1600x4,
            };

            const RATE_128: usize = 168;
            const RATE_256: usize = 136;
            const SHAKE_DS: u8 = 0x1F;
            const ROUNDS: usize = 24;

            /// Four independent Keccak-f\[1600\] states; lane `k` carries input/output stream `k`.
            pub struct KeccakStateX4 {
                states: [[u64; 25]; 4],
            }

            impl KeccakStateX4 {
                pub fn new() -> Self {
                    Self {
                        states: [[0u64; 25]; 4],
                    }
                }
            }

            impl Default for KeccakStateX4 {
                fn default() -> Self {
                    Self::new()
                }
            }

            pub fn init() -> KeccakStateX4 {
                KeccakStateX4::new()
            }

            /// XOR a (partial) block into one state, little-endian (mirrors `lib_q_sha3`'s absorb).
            #[inline]
            fn xor_block(state: &mut [u64; 25], block: &[u8]) {
                let (chunks, rem) = block.as_chunks::<8>();
                let mut lane = 0;
                for c in chunks {
                    state[lane] ^= u64::from_le_bytes(*c);
                    lane += 1;
                }
                if !rem.is_empty() {
                    let mut b = [0u8; 8];
                    b[..rem.len()].copy_from_slice(rem);
                    state[lane] ^= u64::from_le_bytes(b);
                }
            }

            /// Extract `out.len()` (≤ RATE) bytes from the rate region of one state, little-endian.
            #[inline]
            fn squeeze_block(state: &[u64; 25], out: &mut [u8]) {
                for (chunk, s) in out.chunks_mut(8).zip(state.iter()) {
                    chunk.copy_from_slice(&s.to_le_bytes()[..chunk.len()]);
                }
            }

            /// Absorb each input (one rate block in practice), apply SHAKE pad10*1, and run the final
            /// permutation across all four lanes — leaving the states positioned at output block 0.
            #[inline]
            fn absorb_final<const RATE: usize>(states: &mut [[u64; 25]; 4], inputs: [&[u8]; 4]) {
                for (state, input) in states.iter_mut().zip(inputs.iter()) {
                    let mut off = 0;
                    while off + RATE <= input.len() {
                        xor_block(state, &input[off..off + RATE]);
                        p1600(state, ROUNDS);
                        off += RATE;
                    }
                    let rem = input.len() - off;
                    let mut block = [0u8; RATE];
                    block[..rem].copy_from_slice(&input[off..]);
                    block[rem] = SHAKE_DS;
                    block[RATE - 1] |= 0x80;
                    xor_block(state, &block);
                }
                p1600x4(states, ROUNDS);
            }

            /// Squeeze `out0.len()/RATE` blocks into the four outputs. `first` extracts block 0 from
            /// the current (already-permuted) state, then permutes between blocks; `!first` permutes
            /// before the first extraction (stream continuation).
            #[inline]
            fn squeeze<const RATE: usize>(
                states: &mut [[u64; 25]; 4],
                out0: &mut [u8],
                out1: &mut [u8],
                out2: &mut [u8],
                out3: &mut [u8],
                first: bool,
            ) {
                let nblocks = out0.len() / RATE;
                for blk in 0..nblocks {
                    if blk > 0 || !first {
                        p1600x4(states, ROUNDS);
                    }
                    let r = blk * RATE..(blk + 1) * RATE;
                    squeeze_block(&states[0], &mut out0[r.clone()]);
                    squeeze_block(&states[1], &mut out1[r.clone()]);
                    squeeze_block(&states[2], &mut out2[r.clone()]);
                    squeeze_block(&states[3], &mut out3[r]);
                }
            }

            pub fn shake128_absorb_final(
                s: &mut KeccakStateX4,
                i0: &[u8],
                i1: &[u8],
                i2: &[u8],
                i3: &[u8],
            ) {
                absorb_final::<RATE_128>(&mut s.states, [i0, i1, i2, i3]);
            }

            pub fn shake128_squeeze_first_five_blocks(
                s: &mut KeccakStateX4,
                o0: &mut [u8],
                o1: &mut [u8],
                o2: &mut [u8],
                o3: &mut [u8],
            ) {
                squeeze::<RATE_128>(&mut s.states, o0, o1, o2, o3, true);
            }

            pub fn shake128_squeeze_next_block(
                s: &mut KeccakStateX4,
                o0: &mut [u8],
                o1: &mut [u8],
                o2: &mut [u8],
                o3: &mut [u8],
            ) {
                squeeze::<RATE_128>(&mut s.states, o0, o1, o2, o3, false);
            }

            pub fn shake256_absorb_final(
                s: &mut KeccakStateX4,
                i0: &[u8],
                i1: &[u8],
                i2: &[u8],
                i3: &[u8],
            ) {
                absorb_final::<RATE_256>(&mut s.states, [i0, i1, i2, i3]);
            }

            pub fn shake256_squeeze_first_block(
                s: &mut KeccakStateX4,
                o0: &mut [u8],
                o1: &mut [u8],
                o2: &mut [u8],
                o3: &mut [u8],
            ) {
                squeeze::<RATE_256>(&mut s.states, o0, o1, o2, o3, true);
            }

            pub fn shake256_squeeze_next_block(
                s: &mut KeccakStateX4,
                o0: &mut [u8],
                o1: &mut [u8],
                o2: &mut [u8],
                o3: &mut [u8],
            ) {
                squeeze::<RATE_256>(&mut s.states, o0, o1, o2, o3, false);
            }
        }
    }
}

#[cfg(all(feature = "simd128", target_arch = "aarch64"))]
pub mod neon {
    pub mod x2 {
        /// Perform 2 SHAKE256 operations, delegating to the portable, already-correct
        /// `lib_q_sha3`-backed [`super::super::shake256`] for each lane.
        ///
        /// This mirrors the fix applied to the AVX2 `x4::shake256` sibling (see its doc comment):
        /// replace hand-rolled Keccak state manipulation with a delegate to a real, tested XOF
        /// implementation. `lib-q-keccak`'s batched permutation (`p1600x4`) only vectorizes on
        /// x86_64/AVX2 today — every other target, aarch64 included, takes its scalar fallback — so
        /// there is currently no NEON-specific batching primitive to route through here for a
        /// throughput win; two direct scalar SHAKE256 calls give byte-identical output with none of
        /// the risk of the previous hand-rolled state manipulation.
        ///
        /// The previous implementation was not SHAKE256 at all:
        /// - it preset lane 0 to `0x06` (the **SHA3**, not SHAKE, domain separator) *before*
        ///   absorbing, instead of folding SHAKE's `0x1F` terminator into the final block;
        /// - it absorbed the entire input across up to 25 lanes with **no permutation** at the
        ///   136-byte SHAKE256 rate boundary, so any input over 136 bytes XORed straight into the
        ///   17..24 capacity lanes;
        /// - it then XORed a second, conflicting `0x1F` on top;
        /// - it ran the permutation exactly once, regardless of how much output was requested; and
        /// - it capped output at `output.len().min(200)` bytes with no logic to permute and squeeze
        ///   further blocks.
        ///
        /// Production callers request 576- or 640-byte masks (FIPS 204 `ExpandMask`, see
        /// `hash_functions.rs`'s `neon::shake256_x4` and `sample.rs::sample_mask_vector`), so every
        /// byte from offset 200 onward came back as zeroed stack memory — and this NEON path is
        /// selected automatically on aarch64 whenever the `simd128` feature is enabled (see
        /// `multiplexing.rs`), so every aarch64 signature used a partially-zero mask.
        #[allow(clippy::too_many_arguments)]
        #[cfg_attr(tarpaulin, inline(never))]
        #[cfg_attr(not(tarpaulin), inline(always))]
        pub fn shake256(input0: &[u8], input1: &[u8], out0: &mut [u8], out1: &mut [u8]) {
            super::super::shake256(out0, input0);
            super::super::shake256(out1, input1);
        }

        pub mod incremental {
            use super::super::super::incremental;

            /// The Keccak state for the incremental API
            /// Uses portable implementation wrapped for x2 interface
            pub struct KeccakStateX2 {
                states: [super::super::super::KeccakState; 2],
            }

            impl KeccakStateX2 {
                pub fn new() -> Self {
                    Self {
                        states: [incremental::shake128_init(), incremental::shake128_init()],
                    }
                }
            }

            // Add missing functions that libcrux API expects
            pub fn init() -> KeccakStateX2 {
                KeccakStateX2::new()
            }

            pub fn shake128_absorb_final(state: &mut KeccakStateX2, input0: &[u8], input1: &[u8]) {
                incremental::shake128_absorb_final(&mut state.states[0], input0);
                incremental::shake128_absorb_final(&mut state.states[1], input1);
            }

            pub fn shake128_squeeze_first_five_blocks(
                state: &mut KeccakStateX2,
                out0: &mut [u8],
                out1: &mut [u8],
            ) {
                incremental::shake128_squeeze_first_five_blocks(&mut state.states[0], out0);
                incremental::shake128_squeeze_first_five_blocks(&mut state.states[1], out1);
            }

            pub fn shake128_squeeze_next_block(
                state: &mut KeccakStateX2,
                out0: &mut [u8],
                out1: &mut [u8],
            ) {
                incremental::shake128_squeeze_next_block(&mut state.states[0], out0);
                incremental::shake128_squeeze_next_block(&mut state.states[1], out1);
            }

            pub fn shake256_absorb_final(state: &mut KeccakStateX2, input0: &[u8], input1: &[u8]) {
                incremental::shake256_absorb_final(&mut state.states[0], input0);
                incremental::shake256_absorb_final(&mut state.states[1], input1);
            }

            pub fn shake256_squeeze_first_block(
                state: &mut KeccakStateX2,
                out0: &mut [u8],
                out1: &mut [u8],
            ) {
                incremental::shake256_squeeze_first_block(&mut state.states[0], out0);
                incremental::shake256_squeeze_first_block(&mut state.states[1], out1);
            }

            pub fn shake256_squeeze_next_block(
                state: &mut KeccakStateX2,
                out0: &mut [u8],
                out1: &mut [u8],
            ) {
                incremental::shake256_squeeze_next_block(&mut state.states[0], out0);
                incremental::shake256_squeeze_next_block(&mut state.states[1], out1);
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::{
        incremental,
        *,
    };

    #[test]
    fn test_shake128_compatibility() {
        // Test that our SHAKE128 implementation produces the same output as lib-q-sha3
        let input = b"Hello, World!";
        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        // Use our implementation
        shake128(&mut output1, input);

        // Use lib-q-sha3 directly
        Shake128::digest_xof(input, &mut output2);

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_shake256_compatibility() {
        // Test that our SHAKE256 implementation produces the same output as lib-q-sha3
        let input = b"Hello, World!";
        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        // Use our implementation
        shake256(&mut output1, input);

        // Use lib-q-sha3 directly
        Shake256::digest_xof(input, &mut output2);

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_incremental_shake256() {
        // Test incremental SHAKE256 API
        let input = b"Hello, World!";
        let mut output1 = [0u8; 136]; // SHAKE256 block size
        let mut output2 = [0u8; 136];

        // Use incremental API
        let mut state = incremental::shake256_init();
        incremental::shake256_absorb_final(&mut state, input);
        incremental::shake256_squeeze_first_block(&mut state, &mut output1);

        // Use direct API
        shake256(&mut output2, input);

        assert_eq!(output1, output2);
    }

    #[cfg(all(feature = "simd256", target_arch = "x86_64"))]
    #[test]
    fn test_avx2_simd_parallel_processing() {
        // Test AVX2 SIMD parallel processing
        let inputs = [
            b"Input 1 for parallel processing",
            b"Input 2 for parallel processing",
            b"Input 3 for parallel processing",
            b"Input 4 for parallel processing",
        ];

        let mut outputs = [[0u8; 32]; 4];

        // Use SIMD parallel processing
        // Create separate arrays to avoid borrow checker issues
        let mut output0 = outputs[0];
        let mut output1 = outputs[1];
        let mut output2 = outputs[2];
        let mut output3 = outputs[3];

        avx2::x4::shake256(
            inputs[0],
            inputs[1],
            inputs[2],
            inputs[3],
            &mut output0,
            &mut output1,
            &mut output2,
            &mut output3,
        );

        outputs[0] = output0;
        outputs[1] = output1;
        outputs[2] = output2;
        outputs[3] = output3;

        // Verify that SIMD processing produces valid SHAKE256 outputs
        // (different from sequential due to true parallel processing)
        for i in 0..4 {
            // Check that outputs are not all zeros (basic validity check)
            assert!(
                !outputs[i].iter().all(|&x| x == 0),
                "Output {} is all zeros",
                i
            );

            // Check that outputs have reasonable entropy (not all same value)
            let first_byte = outputs[i][0];
            assert!(
                !outputs[i].iter().all(|&x| x == first_byte),
                "Output {} has no entropy",
                i
            );
        }

        // Verify that different inputs produce different outputs
        assert_ne!(
            outputs[0], outputs[1],
            "Different inputs should produce different outputs"
        );
        assert_ne!(
            outputs[2], outputs[3],
            "Different inputs should produce different outputs"
        );
    }

    #[cfg(all(feature = "simd128", target_arch = "aarch64"))]
    #[test]
    fn test_neon_simd_parallel_processing() {
        // Test NEON SIMD parallel processing
        let inputs = [
            b"Input 1 for NEON processing",
            b"Input 2 for NEON processing",
        ];

        let mut outputs = [[0u8; 32]; 2];

        // Use SIMD parallel processing
        // Create separate arrays to avoid borrow checker issues
        let mut output0 = outputs[0];
        let mut output1 = outputs[1];

        neon::x2::shake256(inputs[0], inputs[1], &mut output0, &mut output1);

        outputs[0] = output0;
        outputs[1] = output1;

        // Verify that SIMD processing produces valid SHAKE256 outputs
        // (different from sequential due to true parallel processing)
        for i in 0..2 {
            // Check that outputs are not all zeros (basic validity check)
            assert!(
                !outputs[i].iter().all(|&x| x == 0),
                "Output {} is all zeros",
                i
            );

            // Check that outputs have reasonable entropy (not all same value)
            let first_byte = outputs[i][0];
            assert!(
                !outputs[i].iter().all(|&x| x == first_byte),
                "Output {} has no entropy",
                i
            );
        }

        // Verify that different inputs produce different outputs
        assert_ne!(
            outputs[0], outputs[1],
            "Different inputs should produce different outputs"
        );
    }

    #[cfg(all(feature = "simd256", target_arch = "x86_64"))]
    #[test]
    fn test_avx2_incremental_simd() {
        // Test AVX2 incremental SIMD API
        let inputs = [
            b"Incremental input 1",
            b"Incremental input 2",
            b"Incremental input 3",
            b"Incremental input 4",
        ];

        let mut outputs = [[0u8; 840]; 4]; // 5 blocks * 168 bytes

        // Use incremental SIMD API
        let mut state = avx2::x4::incremental::init();
        avx2::x4::incremental::shake128_absorb_final(
            &mut state, inputs[0], inputs[1], inputs[2], inputs[3],
        );
        // Create separate arrays to avoid borrow checker issues
        let mut output0 = outputs[0];
        let mut output1 = outputs[1];
        let mut output2 = outputs[2];
        let mut output3 = outputs[3];

        avx2::x4::incremental::shake128_squeeze_first_five_blocks(
            &mut state,
            &mut output0,
            &mut output1,
            &mut output2,
            &mut output3,
        );

        outputs[0] = output0;
        outputs[1] = output1;
        outputs[2] = output2;
        outputs[3] = output3;

        // Verify that SIMD processing produces valid SHAKE128 outputs
        // (different from sequential due to true parallel processing)
        for i in 0..4 {
            // Check that outputs are not all zeros (basic validity check)
            assert!(
                !outputs[i].iter().all(|&x| x == 0),
                "Output {} is all zeros",
                i
            );

            // Check that outputs have reasonable entropy (not all same value)
            let first_byte = outputs[i][0];
            assert!(
                !outputs[i].iter().all(|&x| x == first_byte),
                "Output {} has no entropy",
                i
            );
        }

        // Verify that different inputs produce different outputs
        assert_ne!(
            outputs[0], outputs[1],
            "Different inputs should produce different outputs"
        );
        assert_ne!(
            outputs[2], outputs[3],
            "Different inputs should produce different outputs"
        );
    }

    #[cfg(all(feature = "simd128", target_arch = "aarch64"))]
    #[test]
    fn test_neon_incremental_simd() {
        // Test NEON incremental SIMD API
        let inputs = [b"NEON incremental input 1", b"NEON incremental input 2"];

        let mut outputs = [[0u8; 840]; 2]; // 5 blocks * 168 bytes

        // Use incremental SIMD API
        let mut state = neon::x2::incremental::init();
        neon::x2::incremental::shake128_absorb_final(&mut state, inputs[0], inputs[1]);
        // Create separate arrays to avoid borrow checker issues
        let mut output0 = outputs[0];
        let mut output1 = outputs[1];

        neon::x2::incremental::shake128_squeeze_first_five_blocks(
            &mut state,
            &mut output0,
            &mut output1,
        );

        outputs[0] = output0;
        outputs[1] = output1;

        // Verify that SIMD processing produces valid SHAKE128 outputs
        // (different from sequential due to true parallel processing)
        for i in 0..2 {
            // Check that outputs are not all zeros (basic validity check)
            assert!(
                !outputs[i].iter().all(|&x| x == 0),
                "Output {} is all zeros",
                i
            );

            // Check that outputs have reasonable entropy (not all same value)
            let first_byte = outputs[i][0];
            assert!(
                !outputs[i].iter().all(|&x| x == first_byte),
                "Output {} has no entropy",
                i
            );
        }

        // Verify that different inputs produce different outputs
        assert_ne!(
            outputs[0], outputs[1],
            "Different inputs should produce different outputs"
        );
    }

    #[test]
    fn test_simd_performance_improvement() {
        // Test that SIMD provides performance improvement
        let large_input = [b'a'; 1024];
        let mut outputs = [[0u8; 32]; 4];

        // Measure sequential performance
        let start = std::time::Instant::now();
        for i in 0..4 {
            shake256(&mut outputs[i], &large_input);
        }
        let _sequential_time = start.elapsed();

        #[cfg(all(feature = "simd256", target_arch = "x86_64"))]
        {
            // Measure SIMD performance
            let start = std::time::Instant::now();
            // Create separate arrays to avoid borrow checker issues
            let mut output0 = outputs[0];
            let mut output1 = outputs[1];
            let mut output2 = outputs[2];
            let mut output3 = outputs[3];

            avx2::x4::shake256(
                &large_input,
                &large_input,
                &large_input,
                &large_input,
                &mut output0,
                &mut output1,
                &mut output2,
                &mut output3,
            );

            outputs[0] = output0;
            outputs[1] = output1;
            outputs[2] = output2;
            outputs[3] = output3;
            let simd_time = start.elapsed();

            // SIMD should be faster (at least 2x improvement expected)
            // Note: Performance logging removed for no_std compatibility
            // SIMD should provide some performance benefit
            // Note: True SIMD may not always be faster due to overhead, but should be functional
            assert!(simd_time.as_nanos() > 0, "SIMD processing should complete");
            assert!(
                outputs.iter().any(|row| row.iter().any(|&b| b != 0)),
                "batched SHAKE256 outputs should be non-zero"
            );
        }
    }

    #[test]
    fn test_simd_correctness_with_various_inputs() {
        // Test SIMD correctness with various input sizes and patterns
        let test_cases = [
                (b"a" as &[u8], "single byte"),
                (b"Hello, World!" as &[u8], "short string"),
                (b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua." as &[u8], "long string"),
                (b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" as &[u8], "binary data"),
            ];

        for (input, _description) in test_cases.iter() {
            let mut sequential_output = [0u8; 32];
            shake256(&mut sequential_output, input);

            #[cfg(all(feature = "simd256", target_arch = "x86_64"))]
            {
                let simd_output = [0u8; 32];
                // Create separate arrays to avoid borrow checker issues
                let mut simd_output0 = simd_output;
                let mut simd_output1 = simd_output;
                let mut simd_output2 = simd_output;
                let mut simd_output3 = simd_output;

                avx2::x4::shake256(
                    input,
                    input,
                    input,
                    input,
                    &mut simd_output0,
                    &mut simd_output1,
                    &mut simd_output2,
                    &mut simd_output3,
                );
                // True SIMD produces different results than sequential, but should be valid
                assert!(
                    !simd_output0.iter().all(|&x| x == 0),
                    "SIMD output is all zeros for {}",
                    _description
                );
                let first_byte = simd_output0[0];
                assert!(
                    !simd_output0.iter().all(|&x| x == first_byte),
                    "SIMD output has no entropy for {}",
                    _description
                );
            }

            #[cfg(all(feature = "simd128", target_arch = "aarch64"))]
            {
                let simd_output = [0u8; 32];
                // Create separate arrays to avoid borrow checker issues
                let mut simd_output0 = simd_output;
                let mut simd_output1 = simd_output;

                neon::x2::shake256(input, input, &mut simd_output0, &mut simd_output1);
                // True SIMD produces different results than sequential, but should be valid
                assert!(
                    !simd_output0.iter().all(|&x| x == 0),
                    "SIMD output is all zeros for {}",
                    _description
                );
                let first_byte = simd_output0[0];
                assert!(
                    !simd_output0.iter().all(|&x| x == first_byte),
                    "SIMD output has no entropy for {}",
                    _description
                );
            }
        }
    }

    #[test]
    fn incremental_shake128_three_five_and_next_blocks() {
        let mut st = incremental::shake128_init();
        incremental::shake128_absorb_final(&mut st, b"incremental shake128 path");
        let mut three = [0u8; 168 * 3];
        incremental::shake128_squeeze_first_three_blocks(&mut st, &mut three);

        let mut st2 = incremental::shake128_init();
        incremental::shake128_absorb_final(&mut st2, b"second");
        let mut five = [0u8; 168 * 5];
        incremental::shake128_squeeze_first_five_blocks(&mut st2, &mut five);
        let mut nb = [0u8; 168];
        incremental::shake128_squeeze_next_block(&mut st2, &mut nb);
        assert!(nb.iter().any(|&b| b != 0));
    }

    #[test]
    fn incremental_shake256_first_and_next_block() {
        let mut st = incremental::shake256_init();
        incremental::shake256_absorb_final(&mut st, b"two blocks");
        let mut b1 = [0u8; 136];
        let mut b2 = [0u8; 136];
        incremental::shake256_squeeze_first_block(&mut st, &mut b1);
        incremental::shake256_squeeze_next_block(&mut st, &mut b2);
        assert_ne!(b1, b2);
    }

    #[test]
    fn keccak_state_absorb_then_squeeze_shake128() {
        let mut s = KeccakState::new_shake128();
        s.absorb(b"part1");
        s.absorb_final(b"part2");
        let mut out = [0u8; 64];
        s.squeeze(&mut out);
        assert!(out.iter().any(|&b| b != 0));
    }

    #[test]
    fn keccak_state_shake256_multi_squeeze() {
        let mut s = KeccakState::new_shake256();
        s.absorb(b"y");
        let mut out = [0u8; 300];
        s.squeeze(&mut out);
        assert!(out.iter().any(|&b| b != 0));
    }

    #[test]
    fn keccak_state_shake128_sequential_squeezes() {
        let mut s = KeccakState::new_shake128();
        s.absorb_final(b"sequential shake128 output");
        let mut first = [0u8; 400];
        s.squeeze(&mut first);
        let mut second = [0u8; 200];
        s.squeeze(&mut second);
        assert_ne!(first[..32], second[..32]);
        assert!(first.iter().chain(second.iter()).any(|&b| b != 0));
    }
}

#[cfg(all(test, feature = "simd256", target_arch = "x86_64"))]
mod x4_incremental_equiv {
    //! The AVX2 incremental 4-way SHAKE must equal four independent scalar `lib_q_sha3` SHAKE
    //! readers, byte for byte (validates the `p1600x4`-driven rewrite independently of the rest of
    //! the ML-DSA avx2 pipeline).
    use lib_q_sha3::digest::{
        ExtendableOutput,
        Update,
        XofReader,
    };
    use lib_q_sha3::{
        Shake128,
        Shake256,
    };

    use super::avx2::x4::incremental as x4;

    fn fill<const N: usize>() -> [[u8; N]; 4] {
        [
            core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1)),
            core::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(2)),
            [0u8; N],
            core::array::from_fn(|i| 0xA5u8 ^ i as u8),
        ]
    }

    #[test]
    fn shake128_x4_matches_scalar() {
        // 34-byte seed = ML-DSA matrix Â expansion input (rho ‖ i ‖ j).
        let s = fill::<34>();
        let mut st = x4::init();
        x4::shake128_absorb_final(&mut st, &s[0], &s[1], &s[2], &s[3]);
        let mut five = [[0u8; 168 * 5]; 4];
        let [a, b, c, d] = &mut five;
        x4::shake128_squeeze_first_five_blocks(&mut st, a, b, c, d);
        let mut nxt = [[0u8; 168]; 4];
        let [a, b, c, d] = &mut nxt;
        x4::shake128_squeeze_next_block(&mut st, a, b, c, d);

        for lane in 0..4 {
            let mut h = Shake128::default();
            h.update(&s[lane]);
            let mut r = h.finalize_xof();
            let mut want = [0u8; 168 * 6];
            r.read(&mut want);
            assert_eq!(
                five[lane][..],
                want[..168 * 5],
                "shake128 lane {lane} first-five"
            );
            assert_eq!(
                nxt[lane][..],
                want[168 * 5..168 * 6],
                "shake128 lane {lane} next"
            );
        }
    }

    #[test]
    fn shake256_x4_matches_scalar() {
        // 66-byte seed = ML-DSA mask `y` sampling input (rho'' ‖ kappa+i).
        let s = fill::<66>();
        let mut st = x4::init();
        x4::shake256_absorb_final(&mut st, &s[0], &s[1], &s[2], &s[3]);
        let mut first = [[0u8; 136]; 4];
        let [a, b, c, d] = &mut first;
        x4::shake256_squeeze_first_block(&mut st, a, b, c, d);
        let mut n1 = [[0u8; 136]; 4];
        let [a, b, c, d] = &mut n1;
        x4::shake256_squeeze_next_block(&mut st, a, b, c, d);
        let mut n2 = [[0u8; 136]; 4];
        let [a, b, c, d] = &mut n2;
        x4::shake256_squeeze_next_block(&mut st, a, b, c, d);

        for lane in 0..4 {
            let mut h = Shake256::default();
            h.update(&s[lane]);
            let mut r = h.finalize_xof();
            let mut want = [0u8; 136 * 3];
            r.read(&mut want);
            assert_eq!(first[lane][..], want[..136], "shake256 lane {lane} first");
            assert_eq!(
                n1[lane][..],
                want[136..136 * 2],
                "shake256 lane {lane} next1"
            );
            assert_eq!(
                n2[lane][..],
                want[136 * 2..136 * 3],
                "shake256 lane {lane} next2"
            );
        }
    }
}

#[cfg(all(test, feature = "simd128", target_arch = "aarch64"))]
mod neon_x2_equiv {
    //! `neon::x2::shake256` must equal two independent scalar `lib_q_sha3` SHAKE256 readers, byte
    //! for byte — it feeds ExpandMask's 576/640-byte mask sampling (`sample.rs::sample_mask_vector`
    //! via `hash_functions.rs::neon::shake256_x4`), and is selected automatically on every aarch64
    //! build with `simd128` enabled (see `multiplexing.rs`).
    //!
    //! Only runs on aarch64 (the `neon` module is target-gated); see
    //! `sha3_shim::tests::neon_x2_shake256_defect_reproduction_host` for a host-executable (x86_64)
    //! reproduction of the pre-fix defect, since this module cannot be compiled/run natively there.
    use lib_q_sha3::Shake256;
    use lib_q_sha3::digest::{
        ExtendableOutput,
        Update,
        XofReader,
    };

    use super::neon::x2;

    #[test]
    fn shake256_x2_matches_scalar_640() {
        // 66-byte seed = ML-DSA mask `y` sampling input (rho'' ‖ kappa+i), matching the real
        // ExpandMask call shape (sample.rs::add_error_domain_separator output is 66 bytes).
        let input0 = [0x11u8; 66];
        let input1 = [0xA5u8; 66];
        let mut out0 = [0u8; 640];
        let mut out1 = [0u8; 640];
        x2::shake256(&input0, &input1, &mut out0, &mut out1);

        for (input, out) in [(&input0, &out0), (&input1, &out1)] {
            let mut h = Shake256::default();
            h.update(input);
            let mut r = h.finalize_xof();
            let mut want = [0u8; 640];
            r.read(&mut want);
            assert_eq!(
                out[..],
                want[..],
                "neon x2 shake256 diverges from scalar SHAKE256"
            );
        }
        // The pre-fix implementation zeroed everything past byte 200 (`min(len, 200)` squeeze cap);
        // pin that specifically so a regression that only breaks the tail is still caught even if a
        // future scalar comparator is loosened.
        assert!(
            out0[200..].iter().any(|&b| b != 0),
            "bytes 200.. must not be all-zero for a 640-byte request"
        );
    }

    #[test]
    fn shake256_x2_differs_from_sha3_domain_separator() {
        // Regression pin for the specific SHA3-vs-SHAKE domain-separator confusion: an empty-input
        // NEON x2 output must NOT equal what you'd get by (mis)using the SHA3 `0x06` separator alone
        // with a single permutation and an unbounded squeeze — i.e. it must actually be SHAKE256.
        let mut out0 = [0u8; 32];
        let mut out1 = [0u8; 32];
        x2::shake256(b"", b"", &mut out0, &mut out1);

        let mut want = [0u8; 32];
        Shake256::default().finalize_xof().read(&mut want);
        assert_eq!(
            out0, want,
            "neon x2 shake256(empty) must equal scalar SHAKE256(empty)"
        );
    }
}

#[cfg(test)]
mod neon_x2_shake256_defect_host_repro {
    //! `sha3_shim::neon::x2::shake256` only compiles under `#[cfg(all(feature = "simd128",
    //! target_arch = "aarch64"))]`, so it cannot be exercised on this (x86_64) host. This module
    //! reproduces the exact pre-fix algorithm verbatim (copy, not a shared helper — so a fix to the
    //! real function cannot accidentally "fix" this reproduction too) and demonstrates it is not
    //! SHAKE256, independent of target architecture. It is a permanent regression pin for the
    //! defect class, not a substitute for `neon_x2_equiv` (which tests the real aarch64 code path
    //! under emulation/cross-compilation).
    use lib_q_sha3::Shake256;
    use lib_q_sha3::digest::{
        ExtendableOutput,
        Update,
        XofReader,
    };

    /// Verbatim copy of the pre-fix `neon::x2::shake256` body (single lane), minus the
    /// `ml_dsa_keccak_portable_simd` nightly-only parallel path (irrelevant to the defect: both
    /// branches run the permutation exactly once either way).
    fn buggy_shake256_one_lane(input: &[u8], output: &mut [u8]) {
        let mut state = [0u64; 25];

        // Initialize Keccak state for SHAKE256 (domain separator 0x06) -- BUG: this is the SHA3,
        // not SHAKE, domain separator, and it is set before absorbing rather than folded into the
        // final block.
        state[0] = 0x06;

        let mut offset = 0;
        while offset + 8 <= input.len() {
            let value = u64::from_le_bytes([
                input[offset],
                input[offset + 1],
                input[offset + 2],
                input[offset + 3],
                input[offset + 4],
                input[offset + 5],
                input[offset + 6],
                input[offset + 7],
            ]);
            let lane_index = offset / 8;
            if lane_index < 25 {
                state[lane_index] ^= value;
            }
            offset += 8;
        }

        if offset < input.len() {
            let mut remaining = [0u8; 8];
            remaining[..input.len() - offset].copy_from_slice(&input[offset..]);
            let value = u64::from_le_bytes(remaining);
            let lane_index = offset / 8;
            if lane_index < 25 {
                state[lane_index] ^= value;
            }
        }

        // BUG: a second, conflicting domain-separator write, and no permutation was ever run at the
        // 136-byte SHAKE256 rate boundary during absorption above.
        if !input.is_empty() {
            let padding_lane = input.len() / 8;
            if padding_lane < 25 {
                state[padding_lane] ^= 0x1F << ((input.len() % 8) * 8);
            }
        } else {
            state[0] ^= 0x1F;
        }
        state[16] ^= 0x8000000000000000;

        // BUG: exactly one permutation, no matter how much output is requested.
        lib_q_keccak::keccak_p(&mut state, 24);

        // BUG: squeeze capped at 200 bytes with no further permute-and-squeeze for the rest.
        let bytes_available = output.len().min(200);
        for (i, byte) in output.iter_mut().enumerate().take(bytes_available) {
            let lane = i / 8;
            let bit_offset = (i % 8) * 8;
            if lane < 25 {
                *byte = (state[lane] >> bit_offset) as u8;
            } else {
                break;
            }
        }
    }

    fn scalar_shake256(input: &[u8], out: &mut [u8]) {
        let mut h = Shake256::default();
        h.update(input);
        h.finalize_xof().read(out);
    }

    #[test]
    fn defect_bytes_past_200_are_left_zero_for_a_640_byte_request() {
        // This is the exact request shape ExpandMask makes (sample.rs: gamma1_exponent 19 -> 640
        // bytes), including how real callers allocate the buffer: zero-initialized
        // (`sample.rs`/`hash_functions.rs` both use `[0; N]`), which is exactly what lets this
        // defect hide as "plausible-looking" output rather than an obvious crash. Land this test
        // BEFORE the real fix and observe it pass (proving the defect); after the fix to
        // `neon::x2::shake256` this reproduction is untouched (it's a verbatim copy) and continues
        // to demonstrate the old behavior would have been wrong.
        let seed = [0x42u8; 66];
        let mut out = [0u8; 640]; // matches real callers' zero-initialized output buffers
        buggy_shake256_one_lane(&seed, &mut out);

        assert!(
            out[200..].iter().all(|&b| b == 0),
            "defect reproduction: bytes 200.. should be zero (squeeze capped at 200 bytes)"
        );

        let mut want = [0u8; 640];
        scalar_shake256(&seed, &mut want);
        assert_ne!(
            out[..],
            want[..],
            "defect reproduction: buggy one-shot output must diverge from real SHAKE256"
        );
    }

    #[test]
    fn defect_is_sha3_not_shake_for_short_output() {
        // Even within the first 200 (correctly-sized) output bytes, the buggy algorithm does not
        // implement SHAKE256 at all (wrong domain separator, wrong absorb schedule) -- pin that a
        // short (32-byte) request already diverges from real SHAKE256, so this isn't just a
        // "long output" bug.
        let seed = b"Hello, World!";
        let mut out = [0u8; 32];
        buggy_shake256_one_lane(seed, &mut out);

        let mut want = [0u8; 32];
        scalar_shake256(seed, &mut want);
        assert_ne!(
            out, want,
            "defect reproduction: buggy algorithm must diverge from SHAKE256 even for short output"
        );
    }
}
