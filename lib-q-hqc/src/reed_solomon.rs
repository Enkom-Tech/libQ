//! Reed-Solomon Code Implementation
//!
//! This module implements Reed-Solomon codes over GF(2^8) as used in HQC.
//! Based on the reference implementation in the HQC specification.

use core::fmt;

use crate::gf as ctgf;
use crate::params::HqcParams;

/// Branch-free "not equal to zero" mask over `u8`: returns `0xFF` if `x != 0`, else `0x00`.
/// Standard "is this word nonzero" trick via `wrapping_neg`, matching the idiom used throughout
/// `reference/hqc/src/ref/reed_solomon.c` and `lib-q-hqc/src/gf.rs`'s `eq_select`.
#[inline]
fn ct_mask_nonzero_u8(x: u8) -> u8 {
    (((x as u16).wrapping_neg()) >> 8) as u8
}

/// Branch-free "not equal to zero" mask over `u16`: returns `0xFFFF` if `x != 0`, else `0x0000`.
/// Port of the `mask1 = -((uint16_t)-d >> 15)` idiom in
/// `reference/hqc/src/ref/reed_solomon.c:176`.
#[inline]
fn ct_mask_nonzero_u16(x: u16) -> u16 {
    let neg = 0u16.wrapping_sub(x);
    0u16.wrapping_sub(neg >> 15)
}

/// Branch-free "less-than" mask: returns `0xFFFF` if `a < b`, else `0x0000`. Used for the
/// Berlekamp-Massey `deg_X_sigma_p > deg_sigma` test
/// (`reference/hqc/src/ref/reed_solomon.c:179`, called with `a = deg_sigma`, `b = deg_X_sigma_p`)
/// and the `i < delta_real_value` test in `compute_error_values`
/// (`reference/hqc/src/ref/reed_solomon.c:306`).
#[inline]
fn ct_mask_lt_u16(a: u16, b: u16) -> u16 {
    let diff = a.wrapping_sub(b);
    0u16.wrapping_sub(diff >> 15)
}

/// Branch-free "less-or-equal" mask: returns `0xFFFF` if `i <= bound`, else `0x0000`. Port of
/// `mask = -((uint16_t)(i - degree - 1) >> 15)` in
/// `reference/hqc/src/ref/reed_solomon.c:239,246`.
#[inline]
fn ct_mask_le_u16(i: u16, bound: u16) -> u16 {
    let diff = i.wrapping_sub(bound).wrapping_sub(1);
    0u16.wrapping_sub(diff >> 15)
}

/// Branch-free equality mask: returns `0xFFFF` if `a == b`, else `0x0000`. Port of
/// `mask2 = ~((uint16_t)(-((int32_t)j ^ delta_counter) >> 31))` in
/// `reference/hqc/src/ref/reed_solomon.c:284` (also line 316) — `j == delta_counter`, where
/// `delta_counter` is a secret-dependent running count and `j` is a public loop counter, so this
/// must be an arithmetic mask rather than a branch.
#[inline]
fn ct_eq_mask_u16(a: u16, b: u16) -> u16 {
    let diff = (a as u32) ^ (b as u32);
    let is_nonzero = (diff | diff.wrapping_neg()) >> 31; // 1 if diff != 0, else 0
    (0u32.wrapping_sub(1u32.wrapping_sub(is_nonzero))) as u16
}

/// Reed-Solomon code implementation
pub struct ReedSolomon<P: HqcParams> {
    _params: core::marker::PhantomData<P>,
    // Generator polynomial coefficients
    generator_poly: [u8; 64], // Max size for G=31 (HQC-1)
    // Galois field tables
    gf_exp: [u8; 511], // 2 * GF_MUL_ORDER + 1 (for GF(2^8))
    gf_log: [u8; 256], // GF_MUL_ORDER + 1 (for GF(2^8))
}

impl<P: HqcParams> ReedSolomon<P> {
    /// Create a new Reed-Solomon code instance
    pub fn new() -> Result<Self, ReedSolomonError> {
        let mut rs = Self {
            _params: core::marker::PhantomData,
            generator_poly: [0u8; 64], // Max size for G=59 (HQC-5)
            gf_exp: [0u8; 511],        // Size for GF(2^8) - 2 * GF_MUL_ORDER + 1
            gf_log: [0u8; 256],        // Size for GF(2^8) - GF_MUL_ORDER + 1
        };

        rs.init_gf_tables()?;
        rs.compute_generator_polynomial()?;

        Ok(rs)
    }

    /// Initialize Galois field tables
    fn init_gf_tables(&mut self) -> Result<(), ReedSolomonError> {
        let gf_poly = P::GF_POLY;
        let gf_mul_order = P::GF_MUL_ORDER;

        // Initialize gf_exp and gf_log tables
        self.gf_exp[0] = 1;
        for i in 1..gf_mul_order {
            let temp = (self.gf_exp[i - 1] as u16) << 1;
            if temp >= (1 << P::M) {
                self.gf_exp[i] = (temp ^ gf_poly) as u8;
            } else {
                self.gf_exp[i] = temp as u8;
            }
        }

        // Fill the rest of gf_exp (for multiplication)
        for i in 0..gf_mul_order {
            self.gf_exp[gf_mul_order + i] = self.gf_exp[i];
        }
        self.gf_exp[2 * gf_mul_order] = 1;

        // Initialize gf_log
        self.gf_log[0] = 0; // log(0) is undefined, but we set it to 0
        for (i, &exp_value) in self.gf_exp.iter().enumerate().take(gf_mul_order) {
            self.gf_log[exp_value as usize] = i as u8;
        }

        Ok(())
    }

    /// Compute the generator polynomial
    fn compute_generator_polynomial(&mut self) -> Result<(), ReedSolomonError> {
        let delta = P::DELTA;
        let g = P::G;

        // Initialize generator polynomial
        self.generator_poly[0] = 1;
        for i in 1..g {
            self.generator_poly[i] = 0;
        }

        // Compute generator polynomial: g(x) = (x - α^1)(x - α^2)...(x - α^(2*delta))
        for i in 1..=2 * delta {
            // Multiply by (x - α^i)
            let alpha_i = self.gf_exp[i % P::GF_MUL_ORDER];
            self.multiply_by_x_minus_alpha(alpha_i);
        }

        Ok(())
    }

    /// Multiply generator polynomial by (x - alpha)
    fn multiply_by_x_minus_alpha(&mut self, alpha: u8) {
        let g = P::G;
        let mut temp = [0u8; 64]; // Size to match generator_poly

        // temp = generator_poly * x
        temp[1..(g + 1)].copy_from_slice(&self.generator_poly[..g]);
        temp[0] = 0;

        // temp = temp - alpha * generator_poly
        for (_i, (temp_item, &gen_poly_item)) in temp
            .iter_mut()
            .zip(self.generator_poly.iter())
            .enumerate()
            .take(g)
        {
            *temp_item ^= self.gf_multiply(gen_poly_item, alpha);
        }

        // Copy back
        self.generator_poly[..g].copy_from_slice(&temp[..g]);
    }

    /// Galois field multiplication.
    ///
    /// Delegates to [`ctgf::gf_mul`] (table-free, branch-free — see `lib-q-hqc/src/gf.rs`)
    /// instead of the `gf_log`/`gf_exp` table lookup this used to do directly. The old body was
    /// `if a == 0 || b == 0 { return 0 }` followed by two table loads (`gf_log[a]`, `gf_log[b]`)
    /// and a third (`gf_exp[log_a + log_b]`) — a data-dependent branch plus secret-indexed loads
    /// whenever either operand is secret. That matters here because [`Self::encode`]'s LFSR
    /// (`gate_value = message[..] ^ ...`) calls this with a message byte as `a`, and `encode` is
    /// itself on HQC's decapsulation re-encryption path (`Hqc::decapsulate` re-encrypts the
    /// recovered plaintext to check it against the received ciphertext), so `a` there is
    /// attacker-observable-timing-sensitive secret data. `self.gf_log`/`self.gf_exp` remain in
    /// use elsewhere in this type only for public-index lookups (init-time table construction,
    /// and indexing by public loop counters in decode), which is safe and unaffected by this
    /// change.
    fn gf_multiply(&self, a: u8, b: u8) -> u8 {
        ctgf::gf_mul(a, b)
    }

    /// Galois field division. Delegates to [`ctgf::gf_mul`] + [`ctgf::gf_inverse`], both
    /// table-free and branch-free, for the same reason as [`Self::gf_multiply`] above:
    /// `ctgf::gf_inverse(0) == 0` by construction (see its doc comment), so `gf_mul(a, inv_b)`
    /// already yields `0` whenever `a == 0` or `b == 0` without any explicit zero check.
    #[allow(dead_code)] // Required by HQC Reed-Solomon specification
    fn gf_divide(&self, a: u8, b: u8) -> u8 {
        ctgf::gf_mul(a, ctgf::gf_inverse(b))
    }

    /// Encode a message using Reed-Solomon code (LFSR-based systematic encoding)
    pub fn encode(&self, message: &[u8], codeword: &mut [u8]) -> Result<(), ReedSolomonError> {
        let k = P::K;
        let n1 = P::N1;
        let g = P::G;

        if message.len() < k {
            return Err(ReedSolomonError::InvalidMessageLength);
        }
        if codeword.len() < n1 {
            return Err(ReedSolomonError::InvalidCodewordLength);
        }

        // Initialize codeword with zeros
        for item in codeword.iter_mut().take(n1) {
            *item = 0;
        }

        // Copy message to the end of codeword (systematic positions)
        for (i, &msg_byte) in message.iter().enumerate().take(k) {
            codeword[n1 - k + i] = msg_byte;
        }

        // Use LFSR to compute parity bytes
        for (i, _) in (0..k).enumerate() {
            let gate_value = message[k - 1 - i] ^ codeword[n1 - k - 1];

            // Compute tmp[j] = gate_value * PARAM_RS_POLY[j] for j = 0 to G-1
            let mut tmp = [0u8; 64]; // Max G (increased for HQC-5)
            for (j, &poly_coef) in P::RS_POLY_COEFS.iter().enumerate().take(g) {
                tmp[j] = self.gf_multiply(gate_value, poly_coef);
            }

            // Update codeword using LFSR feedback
            for k_pos in (1..(n1 - k)).rev() {
                codeword[k_pos] = codeword[k_pos - 1] ^ tmp[k_pos];
            }
            codeword[0] = tmp[0];
        }

        Ok(())
    }

    /// Decode a codeword using Reed-Solomon code
    pub fn decode(&self, codeword: &[u8], message: &mut [u8]) -> Result<(), ReedSolomonError> {
        let k = P::K;
        let n1 = P::N1;
        let delta = P::DELTA;

        if codeword.len() < n1 {
            return Err(ReedSolomonError::InvalidCodewordLength);
        }
        if message.len() < k {
            return Err(ReedSolomonError::InvalidMessageLength);
        }

        let mut syndromes = [0u16; 128]; // Max 2*delta (HQC-5: 2*29=58)
        let mut sigma = [0u16; 128]; // Max delta + 1
        let mut error = [0u8; 128]; // Indicator array over codeword positions: error[i] in {0,1}
        let mut z_poly = [0u16; 128]; // Max delta + 1
        let mut error_values = [0u16; 128]; // Indexed by codeword position, size n1

        // Six unconditional stages, run identically regardless of how many errors are present
        // (or none at all) — no early return, no skipped stage. Mirrors
        // `reference/hqc/src/ref/reed_solomon.c:353-385` (`reed_solomon_decode`). The previous
        // "all syndromes zero -> return early" fast path and the "found_errors == deg_sigma ->
        // else skip correction" gate have both been removed: they were the dominant timing
        // leaks (t_2d79cd69), and the reference has no such guards — a beyond-capacity error
        // pattern simply produces a wrong correction here, which the FO transform's
        // re-encryption check rejects at a higher layer via implicit rejection.

        // 1. Syndromes.
        self.compute_syndromes_u16(&mut syndromes, codeword)?;

        // 2. Error locator polynomial (Berlekamp-Massey).
        let deg_sigma = self.compute_elp_u16(&mut sigma, &syndromes)?;

        // 3. Root finding (Chien search in place of the reference's additive FFT — justified
        //    below in `find_error_positions_chien`'s doc comment). Produces a 0/1 indicator
        //    array over all N1 codeword positions; evaluates every position, no early exit.
        self.find_error_positions_chien(&mut error, &sigma, n1, delta)?;

        // 4. Error evaluator polynomial z(x).
        self.compute_z_poly(&mut z_poly, &sigma, deg_sigma, &syndromes)?;

        // 5. Error values, gathered into `error_values` indexed by codeword position (not by a
        //    compact "which error is this" index), so step 6 needs no secret-indexed write.
        self.compute_error_values(&mut error_values, &z_poly, &error, n1, delta)?;

        // 6. Correction: unconditional XOR across all N1 positions.
        let mut corrected_codeword = [0u8; 512]; // Max n1 (HQC-5: 90)
        corrected_codeword[..n1].copy_from_slice(&codeword[..n1]);
        for i in 0..n1 {
            corrected_codeword[i] ^= error_values[i] as u8;
        }

        // Extract message from corrected codeword with proper offset
        let offset = P::G - 1;
        message[..k].copy_from_slice(&corrected_codeword[offset..(k + offset)]);

        Ok(())
    }

    /// Compute syndromes using precomputed alpha_ij_pow table (u8 version for compatibility)
    #[allow(dead_code)] // Required by HQC Reed-Solomon specification
    fn compute_syndromes(
        &self,
        syndromes: &mut [u8],
        codeword: &[u8],
    ) -> Result<(), ReedSolomonError> {
        let n1 = P::N1;
        let delta = P::DELTA;

        for (i, _) in (0..2 * delta).enumerate() {
            syndromes[i] = 0;
            #[allow(clippy::needless_range_loop)]
            for j in 1..n1 {
                syndromes[i] ^= self.gf_multiply(codeword[j], P::ALPHA_IJ_POW[i][j - 1] as u8);
            }
            syndromes[i] ^= codeword[0];
        }

        Ok(())
    }

    /// Compute syndromes using precomputed alpha_ij_pow table (u16 version for main algorithm)
    fn compute_syndromes_u16(
        &self,
        syndromes: &mut [u16],
        codeword: &[u8],
    ) -> Result<(), ReedSolomonError> {
        let n1 = P::N1;
        let delta = P::DELTA;

        for (i, _) in (0..2 * delta).enumerate() {
            // Add bounds checking for syndromes array
            if i < syndromes.len() {
                syndromes[i] = 0;
                #[allow(clippy::needless_range_loop)]
                for j in 1..n1 {
                    // Add bounds checking to prevent index out of bounds
                    if i < P::ALPHA_IJ_POW.len() && (j - 1) < P::ALPHA_IJ_POW[i].len() {
                        syndromes[i] ^=
                            ctgf::gf_mul(codeword[j], P::ALPHA_IJ_POW[i][j - 1] as u8) as u16;
                    } else {
                        let alpha_power = ((i + 1) * j) % P::GF_MUL_ORDER;
                        let alpha_val = self.gf_exp[alpha_power];
                        syndromes[i] ^= ctgf::gf_mul(codeword[j], alpha_val) as u16;
                    }
                }
                syndromes[i] ^= codeword[0] as u16;
            }
        }

        Ok(())
    }

    /// Compute error locator polynomial using constant-time Berlekamp-Massey algorithm (u16 version)
    fn compute_elp_u16(
        &self,
        sigma: &mut [u16],
        syndromes: &[u16],
    ) -> Result<usize, ReedSolomonError> {
        let delta = P::DELTA;
        let mut sigma_copy = [0u16; 64];
        let mut x_sigma_p = [0u16; 64];
        x_sigma_p[1] = 1;

        let mut deg_sigma = 0usize;
        let mut deg_sigma_p = 0usize;
        let mut pp = 0xFFFFu16; // 2*rho initialized to -1
        let mut d_p = 1u16;
        let mut d = syndromes[0];

        sigma[0] = 1;

        for mu in 0..(2 * delta) {
            // Save sigma in case we need it to update X_sigma_p
            sigma_copy[..=delta].copy_from_slice(&sigma[..=delta]);
            let deg_sigma_copy = deg_sigma;

            let dd = ctgf::gf_mul(d as u8, ctgf::gf_inverse(d_p as u8)) as u16;

            for i in 1..=(mu + 1).min(delta) {
                sigma[i] ^= ctgf::gf_mul(dd as u8, x_sigma_p[i] as u8) as u16;
            }

            let deg_x = (mu as u16).wrapping_sub(pp);
            let deg_x_sigma_p = deg_x + deg_sigma_p as u16;

            // mask1 = 0xffff if(d != 0) and 0 otherwise. Arithmetic mask, no branch on the
            // secret-derived discrepancy `d` (reference/hqc/src/ref/reed_solomon.c:176).
            let mask1 = ct_mask_nonzero_u16(d);

            // mask2 = 0xffff if(deg_x_sigma_p > deg_sigma) and 0 otherwise. Arithmetic mask
            // (reference/hqc/src/ref/reed_solomon.c:179) instead of a value-producing `if`.
            let mask2 = ct_mask_lt_u16(deg_sigma as u16, deg_x_sigma_p);

            // mask12 = 0xffff if the deg_sigma increased and 0 otherwise
            let mask12 = mask1 & mask2;
            deg_sigma ^= (mask12 & (deg_x_sigma_p ^ deg_sigma as u16)) as usize;

            if mu == (2 * delta - 1) {
                break;
            }

            pp ^= mask12 & ((mu as u16) ^ pp);
            d_p ^= mask12 & (d ^ d_p);

            for i in (1..=delta).rev() {
                x_sigma_p[i] = (mask12 & sigma_copy[i - 1]) ^ (!mask12 & x_sigma_p[i - 1]);
            }
            x_sigma_p[0] = 0;

            deg_sigma_p ^= (mask12 & ((deg_sigma_copy ^ deg_sigma_p) as u16)) as usize;

            d = syndromes[mu + 1];
            for i in 1..=(mu + 1).min(delta) {
                d ^= ctgf::gf_mul(sigma[i] as u8, syndromes[mu + 1 - i] as u8) as u16;
            }
        }

        Ok(deg_sigma)
    }

    /// Find error positions using a Chien search, producing a 0/1 indicator array over every
    /// codeword position (no compact "list of positions found so far").
    ///
    /// **Choice of Chien search over the reference's additive FFT:** the reference
    /// (`reference/hqc/src/ref/fft.c`) evaluates sigma at all `2^PARAM_M = 256` field elements via
    /// an additive FFT, which is asymptotically the right call at its scale. HQC's `N1` is only
    /// 46/56/90 — far below 256 — so a direct Chien search evaluating sigma at exactly the `N1`
    /// codeword positions actually needed is cheaper here (`O(N1 * (delta+1))` field
    /// multiplications vs. `O(M * 2^M)` FFT butterfly steps) while being simpler to keep
    /// branch-free: every position is evaluated, unconditionally, with no early exit and no
    /// counter used as a downstream loop bound — satisfying the same constant-time requirement
    /// the FFT gives the reference.
    ///
    /// Evaluates every one of the `delta+1` sigma coefficients at every one of the `n1`
    /// positions with no skip (`sigma[j] == 0` for `j > deg_sigma` falls out of Berlekamp-Massey
    /// automatically — see module tests — so omitting a `degree`-bounded skip does not change the
    /// result, only removes a secret-dependent branch). The zero-test on each position's
    /// accumulated sum is the branch-free [`ct_mask_nonzero_u8`], not an `if`.
    ///
    /// **Root convention** (verified empirically against KATs in
    /// `test_reed_solomon_error_correction` and the crate's KAT/roundtrip suite, not merely
    /// asserted): a root of sigma at `alpha^(-i)` is treated as an error at codeword position
    /// `i`, i.e. `beta_j = gf_exp[i]` for a detected position `i` — matching the reference's
    /// `fft_retrieve_error_poly`, which sets `error[index]` for `index = GF_MUL_ORDER -
    /// gf_log[gamma]` when `gamma` is a root (so `gamma = alpha^(-index)`), and whose
    /// `compute_error_values` then uses `beta_j[...] = gf_exp[i]` for that same position `i`.
    fn find_error_positions_chien(
        &self,
        error: &mut [u8],
        sigma: &[u16],
        n1: usize,
        delta: usize,
    ) -> Result<(), ReedSolomonError> {
        let mut sigma_u8 = [0u8; 64];
        for i in 0..=delta {
            sigma_u8[i] = sigma[i] as u8;
        }

        for i in 0..n1 {
            let mut sum = 0u8;
            let k = (P::GF_MUL_ORDER - i) % P::GF_MUL_ORDER;
            #[allow(clippy::needless_range_loop)]
            for j in 0..=delta {
                let alpha_power = (k * j) % P::GF_MUL_ORDER;
                let alpha_val = self.gf_exp[alpha_power];
                sum ^= ctgf::gf_mul(sigma_u8[j], alpha_val);
            }

            // error[i] = 1 if sum == 0 (root found -> error at position i), else 0. Branch-free:
            // ct_mask_nonzero_u8(sum) is 0xFF/0x00, `& 1` reduces it to 1/0, `1 ^ ..` flips it.
            error[i] = 1u8 ^ (ct_mask_nonzero_u8(sum) & 1);
        }

        Ok(())
    }

    /// Compute z polynomial (error evaluator). Port of `compute_z_poly` in
    /// `reference/hqc/src/ref/reed_solomon.c:232-253`: the `i <= degree` gate is an arithmetic
    /// mask ([`ct_mask_le_u16`]), not a value-producing `if`, since `degree` (the ELP's degree)
    /// is derived from secret syndromes.
    fn compute_z_poly(
        &self,
        z: &mut [u16],
        sigma: &[u16],
        degree: usize,
        syndromes: &[u16],
    ) -> Result<(), ReedSolomonError> {
        let delta = P::DELTA;
        let degree_u16 = degree as u16;

        z[0] = 1;

        for i in 1..=delta {
            let mask = ct_mask_le_u16(i as u16, degree_u16);
            z[i] = mask & sigma[i];
        }

        z[1] ^= syndromes[0];

        for i in 2..=delta {
            let mask = ct_mask_le_u16(i as u16, degree_u16);
            z[i] ^= mask & syndromes[i - 1];

            for j in 1..i {
                z[i] ^= mask & (ctgf::gf_mul(sigma[j] as u8, syndromes[i - j - 1] as u8) as u16);
            }
        }

        Ok(())
    }

    /// Compute error values, following `compute_error_values` in
    /// `reference/hqc/src/ref/reed_solomon.c:264-322` verbatim in spirit: gather the `beta_j`
    /// values (the field elements at detected error positions) into a compact `delta`-sized
    /// array via a `delta_counter`/`mask1`/`mask2` running-index gather rather than a
    /// secret-indexed write, compute each error value from `z` and `beta_j`, then scatter the
    /// compact `e_j` values back out to `error_values` indexed by codeword position using the
    /// same gather pattern run a second time.
    ///
    /// Unfilled `beta_j` slots (positions past `delta_real_value`, when fewer than `delta` errors
    /// are found) stay `0`: in the denominator product, `gf_mul(inverse, 0) = 0` so the factor
    /// `1 ^ gf_mul(inverse, beta_j[k]) = 1` for those slots (a no-op factor), and the numerator
    /// path for those slots is masked off entirely by `i < delta_real_value` before it can reach
    /// `error_values`/`e_j`. So the harmless-zero-factor property holds *and* is redundant with
    /// the final mask — checked directly by `test_reed_solomon_error_correction` (fewer errors
    /// than `delta`) still round-tripping correctly.
    fn compute_error_values(
        &self,
        error_values: &mut [u16],
        z: &[u16],
        error: &[u8],
        n1: usize,
        delta: usize,
    ) -> Result<(), ReedSolomonError> {
        let mut beta_j = [0u16; 64];
        let mut e_j = [0u16; 64];

        // Gather: beta_j[delta_counter] = gf_exp[i] for each position i where error[i] == 1,
        // via an equality mask on the public loop counter j vs. the secret running count
        // delta_counter, rather than a secret-indexed write `beta_j[delta_counter] = ...`.
        let mut delta_counter: u16 = 0;
        for i in 0..n1 {
            let mask1 = 0u16.wrapping_sub(error[i] as u16); // error[i] in {0,1}: 0xFFFF or 0
            let mut found: u16 = 0;
            for j in 0..delta {
                let mask2 = ct_eq_mask_u16(j as u16, delta_counter);
                beta_j[j] = beta_j[j].wrapping_add(mask1 & mask2 & (self.gf_exp[i] as u16));
                found = found.wrapping_add(mask1 & mask2 & 1);
            }
            delta_counter = delta_counter.wrapping_add(found);
        }
        let delta_real_value = delta_counter;

        // For each of the (up to) delta gathered error positions, compute e_j = z(beta_j^-1) /
        // prod_{k != j} (1 + beta_j^-1 * beta_k), excluding self via beta_j[(i+k) % delta] for
        // k in 1..delta (reference/hqc/src/ref/reed_solomon.c:303-304) rather than an `if k != i`
        // branch.
        for i in 0..delta {
            let inverse = ctgf::gf_inverse(beta_j[i] as u8);

            let mut tmp1 = 1u16; // z[0] = 1
            let mut inverse_power_j = 1u8;
            for j in 1..=delta {
                inverse_power_j = ctgf::gf_mul(inverse_power_j, inverse);
                tmp1 ^= ctgf::gf_mul(inverse_power_j, z[j] as u8) as u16;
            }

            let mut tmp2 = 1u8;
            for kk in 1..delta {
                let idx = (i + kk) % delta;
                tmp2 = ctgf::gf_mul(tmp2, 1u8 ^ ctgf::gf_mul(inverse, beta_j[idx] as u8));
            }

            // mask1 = 0xffff if i < delta_real_value, else 0 (reference line 306).
            let mask1 = ct_mask_lt_u16(i as u16, delta_real_value);
            e_j[i] = mask1 & (ctgf::gf_mul(tmp1 as u8, ctgf::gf_inverse(tmp2)) as u16);
        }

        // Scatter: error_values[i] = e_j[delta_counter] for each position i where error[i] == 1,
        // running the identical gather pattern a second time so the write into `error_values` is
        // never indexed by a secret position — every position is visited unconditionally, and
        // `error[i] == 0` positions accumulate nothing (mask1 == 0 for every j).
        delta_counter = 0;
        for i in 0..n1 {
            let mask1 = 0u16.wrapping_sub(error[i] as u16);
            let mut found: u16 = 0;
            for j in 0..delta {
                let mask2 = ct_eq_mask_u16(j as u16, delta_counter);
                error_values[i] = error_values[i].wrapping_add(mask1 & mask2 & e_j[j]);
                found = found.wrapping_add(mask1 & mask2 & 1);
            }
            delta_counter = delta_counter.wrapping_add(found);
        }

        Ok(())
    }
}

/// Reed-Solomon error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReedSolomonError {
    InvalidMessageLength,
    InvalidCodewordLength,
    DecodingFailed,
    InvalidParameters,
}

impl fmt::Display for ReedSolomonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReedSolomonError::InvalidMessageLength => write!(f, "Invalid message length"),
            ReedSolomonError::InvalidCodewordLength => write!(f, "Invalid codeword length"),
            ReedSolomonError::DecodingFailed => write!(f, "Reed-Solomon decoding failed"),
            ReedSolomonError::InvalidParameters => write!(f, "Invalid Reed-Solomon parameters"),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::string::ToString;

    use super::*;
    use crate::params::Hqc1Params;

    /// `ReedSolomonError::Display` is never invoked anywhere in the crate (no caller ever
    /// formats one; production code only matches/propagates the enum), and
    /// `DecodingFailed`/`InvalidParameters` are never constructed by any real code path (only
    /// `InvalidMessageLength`/`InvalidCodewordLength` are, from `encode`/`decode`'s length
    /// checks). Construct-and-check directly.
    #[test]
    fn test_reed_solomon_error_display_all_variants() {
        assert_eq!(
            ReedSolomonError::InvalidMessageLength.to_string(),
            "Invalid message length"
        );
        assert_eq!(
            ReedSolomonError::InvalidCodewordLength.to_string(),
            "Invalid codeword length"
        );
        assert_eq!(
            ReedSolomonError::DecodingFailed.to_string(),
            "Reed-Solomon decoding failed"
        );
        assert_eq!(
            ReedSolomonError::InvalidParameters.to_string(),
            "Invalid Reed-Solomon parameters"
        );
    }

    /// Real-path negative test: `encode`/`decode` must reject undersized buffers via the actual
    /// length checks (not just construct the error type by hand).
    #[test]
    fn test_reed_solomon_rejects_undersized_buffers() {
        let rs = ReedSolomon::<Hqc1Params>::new().unwrap();
        let short_message = [0u8; 4]; // K = 16 for HQC-1
        let mut codeword = [0u8; 46];
        assert_eq!(
            rs.encode(&short_message, &mut codeword).unwrap_err(),
            ReedSolomonError::InvalidMessageLength
        );

        let message = [0u8; 16];
        let mut short_codeword = [0u8; 4]; // N1 = 46 for HQC-1
        assert_eq!(
            rs.encode(&message, &mut short_codeword).unwrap_err(),
            ReedSolomonError::InvalidCodewordLength
        );

        let codeword = [0u8; 46];
        let mut short_message_out = [0u8; 4];
        assert_eq!(
            rs.decode(&codeword, &mut short_message_out).unwrap_err(),
            ReedSolomonError::InvalidMessageLength
        );

        let short_codeword_in = [0u8; 4];
        let mut message_out = [0u8; 16];
        assert_eq!(
            rs.decode(&short_codeword_in, &mut message_out).unwrap_err(),
            ReedSolomonError::InvalidCodewordLength
        );
    }

    #[test]
    fn test_reed_solomon_creation() {
        let rs = ReedSolomon::<Hqc1Params>::new();
        assert!(rs.is_ok());
    }

    #[test]
    fn test_reed_solomon_encode_decode() {
        let rs = ReedSolomon::<Hqc1Params>::new().unwrap();

        // Test message
        let message = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];

        // Encode
        let mut codeword = [0u8; 46]; // N1 for HQC-1
        rs.encode(&message, &mut codeword).unwrap();

        // Check if encoding produces valid codeword (all syndromes should be zero)
        let mut syndromes = [0u16; 32];
        rs.compute_syndromes_u16(&mut syndromes, &codeword).unwrap();

        let mut all_zero = true;
        for (i, _) in (0..30).enumerate() {
            // 2*DELTA = 30 for HQC-1
            if syndromes[i] != 0 {
                all_zero = false;
                break;
            }
        }

        // For now, just assert that all syndromes should be zero
        assert!(all_zero, "Syndromes should be zero after encoding");

        // Decode
        let mut decoded_message = [0u8; 16]; // K for HQC-1
        rs.decode(&codeword, &mut decoded_message).unwrap();

        // Verify
        assert_eq!(message, decoded_message);
    }

    #[test]
    fn test_reed_solomon_error_correction() {
        let rs = ReedSolomon::<Hqc1Params>::new().unwrap();

        // Test message
        let message = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];

        // Encode
        let mut codeword = [0u8; 46];
        rs.encode(&message, &mut codeword).unwrap();

        // Introduce a small error at position 20
        codeword[20] ^= 0x01;

        // Debug: Check syndromes before decoding
        let mut syndromes = [0u16; 32];
        rs.compute_syndromes_u16(&mut syndromes, &codeword).unwrap();

        // Check if we have non-zero syndromes (should have errors)
        let mut has_errors = false;
        for (i, _) in (0..30).enumerate() {
            // 2*DELTA = 30 for HQC-1
            if syndromes[i] != 0 {
                has_errors = true;
                break;
            }
        }

        // For debugging, we know there should be errors
        assert!(has_errors, "Should detect errors after introducing them");

        // Decode (should correct the error)
        let mut decoded_message = [0u8; 16];
        rs.decode(&codeword, &mut decoded_message).unwrap();

        // Verify
        assert_eq!(message, decoded_message);
    }

    /// Exactly `DELTA` (15) distinct symbol errors for HQC-1 — the RS correction capacity boundary.
    /// The rewritten decoder runs the same unconditional stage sequence regardless of error count,
    /// so this must still recover the message exactly.
    #[test]
    fn test_reed_solomon_decode_at_capacity_hqc1() {
        let rs = ReedSolomon::<Hqc1Params>::new().unwrap();
        let message = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x01,
        ];
        let mut codeword = [0u8; 46];
        rs.encode(&message, &mut codeword).unwrap();

        // DELTA = 15 for HQC-1: flip exactly 15 distinct positions.
        for i in 0..15 {
            codeword[i * 3] ^= 0x01;
        }

        let mut decoded_message = [0u8; 16];
        rs.decode(&codeword, &mut decoded_message).unwrap();
        assert_eq!(
            message, decoded_message,
            "at-capacity (15 errors) decode must still recover the message"
        );
    }

    /// Deliberately adversarial: far more symbol errors than HQC-1's correction capacity
    /// (`DELTA = 15`) — 30 of the 46 codeword bytes flipped. `decode()` must not panic, must not
    /// index out of bounds, and must not hang; producing a wrong message is the expected and
    /// acceptable outcome (the reference has no beyond-capacity guard either — the FO transform's
    /// re-encryption check is what rejects this case at a higher layer, not this decoder).
    #[test]
    fn test_reed_solomon_decode_beyond_capacity_does_not_panic_hqc1() {
        let rs = ReedSolomon::<Hqc1Params>::new().unwrap();
        let message = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x01,
        ];
        let mut codeword = [0u8; 46];
        rs.encode(&message, &mut codeword).unwrap();

        for i in 0..30 {
            codeword[i] ^= 0xFF;
        }

        let mut decoded_message = [0u8; 16];
        let result = rs.decode(&codeword, &mut decoded_message);
        assert!(
            result.is_ok(),
            "decode must return Ok (not panic/hang) even for a beyond-capacity error pattern"
        );
    }

    /// Same beyond-capacity adversarial probe as `..._hqc1`, but for HQC-3 (`DELTA = 16`,
    /// `N1 = 56`) and HQC-5 (`DELTA = 29`, `N1 = 90`) — the two parameter sets that were not
    /// individually named in `test_reed_solomon_decode_beyond_capacity_does_not_panic_hqc1`, and
    /// for HQC-5 specifically the set whose undersized `ALPHA_IJ_POW` table forces a different
    /// `compute_syndromes_u16` code path (see module-level trap note in the calling card).
    #[test]
    fn test_reed_solomon_decode_beyond_capacity_does_not_panic_hqc3_hqc5() {
        {
            let rs = ReedSolomon::<crate::params::Hqc3Params>::new().unwrap();
            let message = [0xAAu8; 24];
            let mut codeword = [0u8; 56];
            rs.encode(&message, &mut codeword).unwrap();
            for i in 0..40 {
                codeword[i] ^= 0xFF;
            }
            let mut decoded = [0u8; 24];
            assert!(
                rs.decode(&codeword, &mut decoded).is_ok(),
                "HQC-3 beyond-capacity decode must return Ok"
            );
        }
        {
            let rs = ReedSolomon::<crate::params::Hqc5Params>::new().unwrap();
            let message = [0x55u8; 32];
            let mut codeword = [0u8; 90];
            rs.encode(&message, &mut codeword).unwrap();
            for i in 0..70 {
                codeword[i] ^= 0xFF;
            }
            let mut decoded = [0u8; 32];
            assert!(
                rs.decode(&codeword, &mut decoded).is_ok(),
                "HQC-5 beyond-capacity decode must return Ok"
            );
        }
    }
}
