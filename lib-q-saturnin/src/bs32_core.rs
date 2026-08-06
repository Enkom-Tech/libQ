/*!
 * Saturnin block cipher implementation using bs32 (bitslice-32) representation.
 * This implementation exactly matches the reference bs32 implementation
 * used to generate the KAT test vectors.
 */

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::{
    Error,
    Result,
};

/// Saturnin block cipher core using bs32 representation
pub struct SaturninBs32Core {
    round_constants: Vec<u32>,
    num_super_rounds: usize,
}

impl SaturninBs32Core {
    /// Create a new Saturnin core with the specified number of super-rounds
    ///
    /// # Arguments
    /// * `num_super_rounds` - Number of super-rounds (0-31)
    /// * `domain` - Domain parameter (0-15)
    pub fn new(num_super_rounds: usize, domain: u8) -> Result<Self> {
        if num_super_rounds > 31 {
            return Err(Error::InvalidAlgorithm {
                algorithm: "Number of super-rounds must be <= 31",
            });
        }

        if domain > 15 {
            return Err(Error::InvalidAlgorithm {
                algorithm: "Domain must be <= 15",
            });
        }

        let round_constants = Self::packed_round_constants(num_super_rounds, domain);

        Ok(Self {
            round_constants,
            num_super_rounds,
        })
    }

    /// The packed round constants this core was built with — `(RC1 << 16) | RC0` per
    /// super-round. Mirrors [`crate::core::SaturninCore::round_constants`].
    pub fn round_constants(&self) -> &[u32] {
        &self.round_constants
    }

    /// Generate the packed bs32 round constants for the given number of super-rounds and domain.
    ///
    /// Always derived from the specification's LFSR — there are no special cases, and there must
    /// not be. `docs/HARDWARE.md` says this in as many words ("generate constants, don't ROM
    /// them"): a ROM table is exactly the trap that lets a broken generator go unnoticed, which is
    /// what happened here.
    ///
    /// This function previously special-cased `(16, 7)` and `(16, 8)` with tables hand-copied from
    /// the designers' bit-sliced reference "for hash compatibility". The tables themselves were
    /// correct — but the LFSR beneath them was not: it kept its shift-register state in a `u32`
    /// that was never truncated back to the specification's 16 bits, and
    /// `0x2D & (!(x0 >> 15).wrapping_add(1))` does not parse as the intended two's-complement mask
    /// `0x2D & (-(x0 >> 15))` (method-call precedence binds `.wrapping_add(1)` before the `!`, so
    /// the expression computes `!((x0 >> 15) + 1)` instead of `!(x0 >> 15) + 1`). The ROM tables
    /// silently masked both bugs at exactly the two configurations the crate ships (Saturnin-Hash),
    /// while every other `(rounds, domain)` pair — reachable through this same public API — got a
    /// permutation that is not Saturnin. See `tests/bs32_lfsr_and_inverse.rs`, which fails on the
    /// broken LFSR across a grid of non-hash-domain configurations (the two ROM configurations
    /// alone cannot exercise this bug, precisely because the ROM was masking it).
    ///
    /// One derivation rule, one point of truth — the same precedent `core.rs` already adopted for
    /// `SaturninCore`.
    fn packed_round_constants(num_super_rounds: usize, domain: u8) -> Vec<u32> {
        let mut constants = Vec::with_capacity(num_super_rounds);
        let mut x0: u16 = (domain as u16)
            .wrapping_add((num_super_rounds as u16) << 4)
            .wrapping_add(0xFE00);
        let mut x1: u16 = x0;

        for _ in 0..num_super_rounds {
            // Clock 16 times per super-round; state stays truncated to 16 bits every step
            // (`u16` arithmetic), matching the specification's two 16-bit shift registers.
            for _ in 0..16 {
                x0 = (x0 << 1) ^ (0x2D & (x0 >> 15).wrapping_neg());
                x1 = (x1 << 1) ^ (0x53 & (x1 >> 15).wrapping_neg());
            }
            constants.push(((x1 as u32) << 16) | (x0 as u32));
        }
        constants
    }

    /// Encrypt a single block using bs32 representation
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    /// * `block` - 32-byte block to encrypt (modified in place)
    pub fn encrypt_block(&self, key: &[u8], block: &mut [u8]) -> Result<()> {
        if key.len() != 32 {
            return Err(Error::InvalidKeySize {
                expected: 32,
                actual: key.len(),
            });
        }

        if block.len() != 32 {
            return Err(Error::InvalidMessageSize {
                max: 32,
                actual: block.len(),
            });
        }

        // Decode key into 8 32-bit words with rotated versions
        let mut keybuf = [0u32; 16];
        for i in 0..8 {
            let w = (key[i << 1] as u32) |
                ((key[(i << 1) + 1] as u32) << 8) |
                ((key[(i << 1) + 16] as u32) << 16) |
                ((key[(i << 1) + 17] as u32) << 24);
            keybuf[i] = w;
            keybuf[i + 8] = ((w & 0x001F001F) << 11) | ((w >> 5) & 0x07FF07FF);
        }

        // Decode block into 8 32-bit words
        let mut q = [0u32; 8];
        self.decode_block(block, &mut q);

        // XOR key
        for i in 0..8 {
            q[i] ^= keybuf[i];
        }

        // Run all rounds (two super-rounds per loop iteration)
        for i in (0..self.num_super_rounds).step_by(2) {
            // First super-round
            self.apply_sbox(&mut q);
            self.apply_mds(&mut q);

            self.apply_sbox(&mut q);
            self.apply_shift_rows_slice(&mut q);
            self.apply_mds(&mut q);
            self.apply_shift_rows_slice_inv(&mut q);
            q[0] ^= self.round_constants[i];
            for j in 0..8 {
                q[j] ^= keybuf[j + 8];
            }

            // Second super-round (if we have enough rounds)
            if i + 1 < self.num_super_rounds {
                self.apply_sbox(&mut q);
                self.apply_mds(&mut q);

                self.apply_sbox(&mut q);
                self.apply_shift_rows_sheet(&mut q);
                self.apply_mds(&mut q);
                self.apply_shift_rows_sheet_inv(&mut q);
                q[0] ^= self.round_constants[i + 1];
                for j in 0..8 {
                    q[j] ^= keybuf[j];
                }
            }
        }

        // Encode result back to bytes
        self.encode_block(&q, block);

        Ok(())
    }

    /// Decrypt a single block using bs32 representation
    ///
    /// # Arguments
    /// * `key` - 32-byte decryption key
    /// * `block` - 32-byte block to decrypt (modified in place)
    ///
    /// # Returns
    /// Result indicating success or failure
    pub fn decrypt_block(&self, key: &[u8], block: &mut [u8]) -> Result<()> {
        if key.len() != 32 {
            return Err(Error::InvalidKeySize {
                expected: 32,
                actual: key.len(),
            });
        }

        if block.len() != 32 {
            return Err(Error::InvalidMessageSize {
                max: 32,
                actual: block.len(),
            });
        }

        // Decode key into keybuf (8 words + 8 rotated words)
        let mut keybuf = [0u32; 16];
        for i in 0..8 {
            let w = (key[i << 1] as u32) |
                ((key[(i << 1) + 1] as u32) << 8) |
                ((key[(i << 1) + 16] as u32) << 16) |
                ((key[(i << 1) + 17] as u32) << 24);
            keybuf[i] = w;
            keybuf[i + 8] = ((w & 0x001F001F) << 11) | ((w >> 5) & 0x07FF07FF);
        }

        // Decode block into 8 32-bit words
        let mut q = [0u32; 8];
        self.decode_block(block, &mut q);

        // NOTE: no initial key XOR here. Encrypt's *first* action is
        // `q[j] ^= keybuf[j]` (the normal key) before round 0 runs; that XOR is undone by the
        // final `keybuf[0..8]` XOR below, symmetrically, only after every round has been undone
        // in reverse order.
        //
        // Each super-round `i` (single-stepped, not paired — pairing the reverse loop by twos
        // with `step_by(2)` is what silently dropped one super-round whenever
        // `num_super_rounds` was even) is undone by first reversing the key/constant XOR that
        // encrypt applies *after* that round's transform (rotated key on even `i`, normal key on
        // odd `i` — see `encrypt_block`), then reversing the transform itself:
        // `SR(forward); MDS_INV; SR_INV` mirrors encrypt's `SR; MDS; SR_INV` because MDS is the
        // only non-involutory step in that triple, and finally undoing the leading/trailing S-box
        // pair with the real `SBOX_INV`/`MDS_INV` circuits (S-box and MDS are emphatically not
        // their own inverses in Saturnin).
        for i in (0..self.num_super_rounds).rev() {
            if i % 2 == 0 {
                // Undo the rotated-key XOR encrypt applies after an even (slice) super-round.
                for j in 0..8 {
                    q[j] ^= keybuf[j + 8];
                }
                q[0] ^= self.round_constants[i];
                self.apply_shift_rows_slice(&mut q);
                self.apply_mds_inv(&mut q);
                self.apply_shift_rows_slice_inv(&mut q);
            } else {
                // Undo the normal-key XOR encrypt applies after an odd (sheet) super-round.
                for j in 0..8 {
                    q[j] ^= keybuf[j];
                }
                q[0] ^= self.round_constants[i];
                self.apply_shift_rows_sheet(&mut q);
                self.apply_mds_inv(&mut q);
                self.apply_shift_rows_sheet_inv(&mut q);
            }

            self.apply_sbox_inv(&mut q);
            self.apply_mds_inv(&mut q);
            self.apply_sbox_inv(&mut q);
        }

        // Undo encrypt's initial XOR with the normal key.
        for i in 0..8 {
            q[i] ^= keybuf[i];
        }

        // Encode result back to bytes
        self.encode_block(&q, block);

        Ok(())
    }

    /// Decode block from bytes to 8 32-bit words
    fn decode_block(&self, src: &[u8], q: &mut [u32; 8]) {
        q[0] = (src[0] as u32) |
            ((src[1] as u32) << 8) |
            ((src[16] as u32) << 16) |
            ((src[17] as u32) << 24);
        q[1] = (src[2] as u32) |
            ((src[3] as u32) << 8) |
            ((src[18] as u32) << 16) |
            ((src[19] as u32) << 24);
        q[2] = (src[4] as u32) |
            ((src[5] as u32) << 8) |
            ((src[20] as u32) << 16) |
            ((src[21] as u32) << 24);
        q[3] = (src[6] as u32) |
            ((src[7] as u32) << 8) |
            ((src[22] as u32) << 16) |
            ((src[23] as u32) << 24);
        q[4] = (src[8] as u32) |
            ((src[9] as u32) << 8) |
            ((src[24] as u32) << 16) |
            ((src[25] as u32) << 24);
        q[5] = (src[10] as u32) |
            ((src[11] as u32) << 8) |
            ((src[26] as u32) << 16) |
            ((src[27] as u32) << 24);
        q[6] = (src[12] as u32) |
            ((src[13] as u32) << 8) |
            ((src[28] as u32) << 16) |
            ((src[29] as u32) << 24);
        q[7] = (src[14] as u32) |
            ((src[15] as u32) << 8) |
            ((src[30] as u32) << 16) |
            ((src[31] as u32) << 24);
    }

    /// Encode 8 32-bit words back to bytes
    fn encode_block(&self, q: &[u32; 8], dst: &mut [u8]) {
        dst[0] = q[0] as u8;
        dst[1] = (q[0] >> 8) as u8;
        dst[16] = (q[0] >> 16) as u8;
        dst[17] = (q[0] >> 24) as u8;
        dst[2] = q[1] as u8;
        dst[3] = (q[1] >> 8) as u8;
        dst[18] = (q[1] >> 16) as u8;
        dst[19] = (q[1] >> 24) as u8;
        dst[4] = q[2] as u8;
        dst[5] = (q[2] >> 8) as u8;
        dst[20] = (q[2] >> 16) as u8;
        dst[21] = (q[2] >> 24) as u8;
        dst[6] = q[3] as u8;
        dst[7] = (q[3] >> 8) as u8;
        dst[22] = (q[3] >> 16) as u8;
        dst[23] = (q[3] >> 24) as u8;
        dst[8] = q[4] as u8;
        dst[9] = (q[4] >> 8) as u8;
        dst[24] = (q[4] >> 16) as u8;
        dst[25] = (q[4] >> 24) as u8;
        dst[10] = q[5] as u8;
        dst[11] = (q[5] >> 8) as u8;
        dst[26] = (q[5] >> 16) as u8;
        dst[27] = (q[5] >> 24) as u8;
        dst[12] = q[6] as u8;
        dst[13] = (q[6] >> 8) as u8;
        dst[28] = (q[6] >> 16) as u8;
        dst[29] = (q[6] >> 24) as u8;
        dst[14] = q[7] as u8;
        dst[15] = (q[7] >> 8) as u8;
        dst[30] = (q[7] >> 16) as u8;
        dst[31] = (q[7] >> 24) as u8;
    }

    /// Apply S-box transformation
    fn apply_sbox(&self, q: &mut [u32; 8]) {
        // sigma_0 on q0-q3
        let mut a = q[0];
        let mut b = q[1];
        let mut c = q[2];
        let mut d = q[3];
        a ^= b & c;
        b ^= a | d;
        d ^= b | c;
        c ^= b & d;
        b ^= a | c;
        a ^= b | d;
        q[0] = b;
        q[1] = c;
        q[2] = d;
        q[3] = a;

        // sigma_1 on q4-q7
        a = q[4];
        b = q[5];
        c = q[6];
        d = q[7];
        a ^= b & c;
        b ^= a | d;
        d ^= b | c;
        c ^= b & d;
        b ^= a | c;
        a ^= b | d;
        q[4] = d;
        q[5] = b;
        q[6] = a;
        q[7] = c;
    }

    /// Apply MDS transformation
    fn apply_mds(&self, q: &mut [u32; 8]) {
        // MDS transformation matching the bs32 implementation
        q[0] ^= q[4];
        q[1] ^= q[5];
        q[2] ^= q[6];
        q[3] ^= q[7];

        self.mul_column_4_7(q);

        q[4] ^= self.swap_words(q[0]);
        q[5] ^= self.swap_words(q[1]);
        q[6] ^= self.swap_words(q[2]);
        q[7] ^= self.swap_words(q[3]);

        self.mul_column_0_3(q);
        self.mul_column_0_3(q);

        q[0] ^= q[4];
        q[1] ^= q[5];
        q[2] ^= q[6];
        q[3] ^= q[7];

        q[4] ^= self.swap_words(q[0]);
        q[5] ^= self.swap_words(q[1]);
        q[6] ^= self.swap_words(q[2]);
        q[7] ^= self.swap_words(q[3]);
    }

    /// Multiply column 4-7 (MDS operation)
    fn mul_column_4_7(&self, q: &mut [u32; 8]) {
        let tmp = q[4];
        q[4] = q[5];
        q[5] = q[6];
        q[6] = q[7];
        q[7] = tmp ^ q[4];
    }

    /// Multiply column 0-3 (MDS operation)
    fn mul_column_0_3(&self, q: &mut [u32; 8]) {
        let tmp = q[0];
        q[0] = q[1];
        q[1] = q[2];
        q[2] = q[3];
        q[3] = tmp ^ q[0];
    }

    /// Inverse of [`Self::mul_column_4_7`] (`MUL_INV` from the designers' bs32 reference,
    /// `crypto_aead/saturninctrcascadev2/bs32/encrypt.c`). `mul_column_4_7` maps
    /// `(a, b, c, d) -> (b, c, d, a^b)`; this maps that result back to `(a, b, c, d)`.
    fn mul_column_4_7_inv(&self, q: &mut [u32; 8]) {
        let (t0, t1, t2, t3) = (q[4], q[5], q[6], q[7]);
        q[4] = t3 ^ t0;
        q[5] = t0;
        q[6] = t1;
        q[7] = t2;
    }

    /// Inverse of [`Self::mul_column_0_3`] — see [`Self::mul_column_4_7_inv`].
    fn mul_column_0_3_inv(&self, q: &mut [u32; 8]) {
        let (t0, t1, t2, t3) = (q[0], q[1], q[2], q[3]);
        q[0] = t3 ^ t0;
        q[1] = t0;
        q[2] = t1;
        q[3] = t2;
    }

    /// Swap words (SW operation)
    fn swap_words(&self, x: u32) -> u32 {
        x.rotate_left(16)
    }

    /// Apply shift rows slice transformation
    fn apply_shift_rows_slice(&self, q: &mut [u32; 8]) {
        // SR_SLICE transformation - exact match to reference
        q[0] = (q[0] & 0xFFFF) | ((q[0] & 0x33330000) << 2) | ((q[0] >> 2) & 0x33330000);
        q[1] = (q[1] & 0xFFFF) | ((q[1] & 0x33330000) << 2) | ((q[1] >> 2) & 0x33330000);
        q[2] = (q[2] & 0xFFFF) | ((q[2] & 0x33330000) << 2) | ((q[2] >> 2) & 0x33330000);
        q[3] = (q[3] & 0xFFFF) | ((q[3] & 0x33330000) << 2) | ((q[3] >> 2) & 0x33330000);
        q[4] = ((q[4] & 0x00007777) << 1) |
            ((q[4] >> 3) & 0x00001111) |
            ((q[4] & 0x11110000) << 3) |
            ((q[4] >> 1) & 0x77770000);
        q[5] = ((q[5] & 0x00007777) << 1) |
            ((q[5] >> 3) & 0x00001111) |
            ((q[5] & 0x11110000) << 3) |
            ((q[5] >> 1) & 0x77770000);
        q[6] = ((q[6] & 0x00007777) << 1) |
            ((q[6] >> 3) & 0x00001111) |
            ((q[6] & 0x11110000) << 3) |
            ((q[6] >> 1) & 0x77770000);
        q[7] = ((q[7] & 0x00007777) << 1) |
            ((q[7] >> 3) & 0x00001111) |
            ((q[7] & 0x11110000) << 3) |
            ((q[7] >> 1) & 0x77770000);
    }

    /// Apply inverse shift rows slice transformation
    fn apply_shift_rows_slice_inv(&self, q: &mut [u32; 8]) {
        // SR_SLICE_INV transformation - exact match to reference
        q[0] = (q[0] & 0xFFFF) | ((q[0] & 0x33330000) << 2) | ((q[0] >> 2) & 0x33330000);
        q[1] = (q[1] & 0xFFFF) | ((q[1] & 0x33330000) << 2) | ((q[1] >> 2) & 0x33330000);
        q[2] = (q[2] & 0xFFFF) | ((q[2] & 0x33330000) << 2) | ((q[2] >> 2) & 0x33330000);
        q[3] = (q[3] & 0xFFFF) | ((q[3] & 0x33330000) << 2) | ((q[3] >> 2) & 0x33330000);
        q[4] = ((q[4] & 0x00001111) << 3) |
            ((q[4] >> 1) & 0x00007777) |
            ((q[4] & 0x77770000) << 1) |
            ((q[4] >> 3) & 0x11110000);
        q[5] = ((q[5] & 0x00001111) << 3) |
            ((q[5] >> 1) & 0x00007777) |
            ((q[5] & 0x77770000) << 1) |
            ((q[5] >> 3) & 0x11110000);
        q[6] = ((q[6] & 0x00001111) << 3) |
            ((q[6] >> 1) & 0x00007777) |
            ((q[6] & 0x77770000) << 1) |
            ((q[6] >> 3) & 0x11110000);
        q[7] = ((q[7] & 0x00001111) << 3) |
            ((q[7] >> 1) & 0x00007777) |
            ((q[7] & 0x77770000) << 1) |
            ((q[7] >> 3) & 0x11110000);
    }

    /// Apply shift rows sheet transformation
    fn apply_shift_rows_sheet(&self, q: &mut [u32; 8]) {
        // SR_SHEET transformation - exact match to reference
        q[0] = (q[0] & 0xFFFF) | ((q[0] & 0x00FF0000) << 8) | ((q[0] >> 8) & 0x00FF0000);
        q[1] = (q[1] & 0xFFFF) | ((q[1] & 0x00FF0000) << 8) | ((q[1] >> 8) & 0x00FF0000);
        q[2] = (q[2] & 0xFFFF) | ((q[2] & 0x00FF0000) << 8) | ((q[2] >> 8) & 0x00FF0000);
        q[3] = (q[3] & 0xFFFF) | ((q[3] & 0x00FF0000) << 8) | ((q[3] >> 8) & 0x00FF0000);
        q[4] = ((q[4] & 0x00000FFF) << 4) |
            ((q[4] >> 12) & 0x0000000F) |
            ((q[4] & 0x000F0000) << 12) |
            ((q[4] >> 4) & 0x0FFF0000);
        q[5] = ((q[5] & 0x00000FFF) << 4) |
            ((q[5] >> 12) & 0x0000000F) |
            ((q[5] & 0x000F0000) << 12) |
            ((q[5] >> 4) & 0x0FFF0000);
        q[6] = ((q[6] & 0x00000FFF) << 4) |
            ((q[6] >> 12) & 0x0000000F) |
            ((q[6] & 0x000F0000) << 12) |
            ((q[6] >> 4) & 0x0FFF0000);
        q[7] = ((q[7] & 0x00000FFF) << 4) |
            ((q[7] >> 12) & 0x0000000F) |
            ((q[7] & 0x000F0000) << 12) |
            ((q[7] >> 4) & 0x0FFF0000);
    }

    /// Apply inverse shift rows sheet transformation
    fn apply_shift_rows_sheet_inv(&self, q: &mut [u32; 8]) {
        // SR_SHEET_INV transformation - exact match to reference
        q[0] = (q[0] & 0xFFFF) | ((q[0] & 0x00FF0000) << 8) | ((q[0] >> 8) & 0x00FF0000);
        q[1] = (q[1] & 0xFFFF) | ((q[1] & 0x00FF0000) << 8) | ((q[1] >> 8) & 0x00FF0000);
        q[2] = (q[2] & 0xFFFF) | ((q[2] & 0x00FF0000) << 8) | ((q[2] >> 8) & 0x00FF0000);
        q[3] = (q[3] & 0xFFFF) | ((q[3] & 0x00FF0000) << 8) | ((q[3] >> 8) & 0x00FF0000);
        q[4] = ((q[4] & 0x0000000F) << 12) |
            ((q[4] >> 4) & 0x00000FFF) |
            ((q[4] & 0x0FFF0000) << 4) |
            ((q[4] >> 12) & 0x000F0000);
        q[5] = ((q[5] & 0x0000000F) << 12) |
            ((q[5] >> 4) & 0x00000FFF) |
            ((q[5] & 0x0FFF0000) << 4) |
            ((q[5] >> 12) & 0x000F0000);
        q[6] = ((q[6] & 0x0000000F) << 12) |
            ((q[6] >> 4) & 0x00000FFF) |
            ((q[6] & 0x0FFF0000) << 4) |
            ((q[6] >> 12) & 0x000F0000);
        q[7] = ((q[7] & 0x0000000F) << 12) |
            ((q[7] >> 4) & 0x00000FFF) |
            ((q[7] & 0x0FFF0000) << 4) |
            ((q[7] >> 12) & 0x000F0000);
    }

    /// Apply the inverse S-box transformation.
    ///
    /// Neither the S-box nor the MDS layer is its own inverse in Saturnin — the designers ship
    /// distinct `SBOX_INV` / `MDS_INV` circuits in their own bs32 reference
    /// (`crypto_aead/saturninctrcascadev2/bs32/encrypt.c:133-201`), which this and
    /// [`Self::apply_mds_inv`] transliterate. (Refuted exhaustively: forward S-box applied twice,
    /// and forward MDS applied twice, do not return the identity.)
    fn apply_sbox_inv(&self, q: &mut [u32; 8]) {
        // inv_sigma_0 on q0-q3
        let (mut b, mut c, mut d, mut a) = (q[0], q[1], q[2], q[3]);
        a ^= b | d;
        b ^= a | c;
        c ^= b & d;
        d ^= b | c;
        b ^= a | d;
        a ^= b & c;
        q[0] = a;
        q[1] = b;
        q[2] = c;
        q[3] = d;

        // inv_sigma_1 on q4-q7 — same six operations, different register wiring in/out.
        let (mut d2, mut b2, mut a2, mut c2) = (q[4], q[5], q[6], q[7]);
        a2 ^= b2 | d2;
        b2 ^= a2 | c2;
        c2 ^= b2 & d2;
        d2 ^= b2 | c2;
        b2 ^= a2 | d2;
        a2 ^= b2 & c2;
        q[4] = a2;
        q[5] = b2;
        q[6] = c2;
        q[7] = d2;
    }

    /// Apply the inverse MDS transformation (`MDS_INV` — see [`Self::apply_sbox_inv`] for why
    /// this is not just [`Self::apply_mds`] again).
    fn apply_mds_inv(&self, q: &mut [u32; 8]) {
        q[4] ^= self.swap_words(q[0]);
        q[5] ^= self.swap_words(q[1]);
        q[6] ^= self.swap_words(q[2]);
        q[7] ^= self.swap_words(q[3]);

        q[0] ^= q[4];
        q[1] ^= q[5];
        q[2] ^= q[6];
        q[3] ^= q[7];

        self.mul_column_0_3_inv(q);
        self.mul_column_0_3_inv(q);

        q[4] ^= self.swap_words(q[0]);
        q[5] ^= self.swap_words(q[1]);
        q[6] ^= self.swap_words(q[2]);
        q[7] ^= self.swap_words(q[3]);

        self.mul_column_4_7_inv(q);

        q[0] ^= q[4];
        q[1] ^= q[5];
        q[2] ^= q[6];
        q[3] ^= q[7];
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use std::eprintln;

    use super::*;

    #[test]
    fn test_bs32_core_creation() {
        let core = SaturninBs32Core::new(16, 8).unwrap();
        assert_eq!(core.num_super_rounds, 16);
        assert_eq!(core.round_constants.len(), 16);
    }

    #[test]
    fn test_bs32_round_trip() {
        let core = SaturninBs32Core::new(16, 8).unwrap();
        let key = [0u8; 32];
        let mut block = [0u8; 32];

        // Test that encryption changes the block
        let original = block;
        core.encrypt_block(&key, &mut block).unwrap();
        assert_ne!(block, original);

        // decrypt_block is a real inverse of encrypt_block (see tests/bs32_lfsr_and_inverse.rs
        // for the same property checked across the full (rounds, domain) grid, plus
        // cross-checked against `crate::core::SaturninCore`).
        core.decrypt_block(&key, &mut block).unwrap();
        assert_eq!(block, original);
    }

    #[test]
    fn test_bs32_hash_case() {
        // Test the exact case from hash: encrypt [0x80, 0, 0, ...] with all-zero key
        let core = SaturninBs32Core::new(16, 8).unwrap();
        let mut block = [
            0x80u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let key = [0u8; 32];

        #[cfg(feature = "std")]
        eprintln!("Input block: {:02X?}", &block[0..8]);
        core.encrypt_block(&key, &mut block).unwrap();
        #[cfg(feature = "std")]
        {
            eprintln!("Encrypted: {:02X?}", &block[0..8]);
            eprintln!("Expected from KAT: [83, B1, 56, 41, B0, 95, 69, B0]");
        }
    }

    #[test]
    fn test_bs32_round_constants() {
        let core = SaturninBs32Core::new(16, 8).unwrap();

        // Compare with expected values from bs32 reference
        let expected = [
            0x3C9B19A7, 0xA9098694, 0x23F878DA, 0xA7B647D3, 0x74FC9D78, 0xEACAAE11, 0x2F31A677,
            0x4CC8C054, 0x2F51CA05, 0x5268F195, 0x4F5B8A2B, 0xF614B4AC, 0xF1D95401, 0x764D2568,
            0x6A493611, 0x8EEF9C3E,
        ];

        #[cfg(feature = "std")]
        {
            eprintln!("Round constants for domain 8:");
            for (i, &constant) in core.round_constants.iter().enumerate() {
                eprintln!("  RC[{}] = 0x{:08X}", i, constant);
            }

            eprintln!("\nExpected round constants:");
            for (i, &constant) in expected.iter().enumerate() {
                eprintln!("  RC[{}] = 0x{:08X}", i, constant);
            }
        }

        assert_eq!(core.round_constants, expected);
    }

    #[test]
    fn test_bs32_data_encoding() {
        // Test that encoding and decoding preserves data
        let core = SaturninBs32Core::new(16, 8).unwrap();

        // Test with a known pattern
        let original = [
            0x80u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let mut q = [0u32; 8];
        core.decode_block(&original, &mut q);

        let mut decoded = [0u8; 32];
        core.encode_block(&q, &mut decoded);

        #[cfg(feature = "std")]
        {
            eprintln!("Original: {:02X?}", &original[0..8]);
            eprintln!("Decoded:  {:02X?}", &decoded[0..8]);
            eprintln!("q[0] = 0x{:08X}", q[0]);
            eprintln!("q[1] = 0x{:08X}", q[1]);
        }

        assert_eq!(original, decoded);
    }
}
