//! Shared Romulus primitives: padding, rho, GF(2^56) counter, tweakey, TBC wrapper.

#![deny(unsafe_code)]
// AD/message entry points mirror the Romulus reference (many explicit parameters).
#![allow(clippy::too_many_arguments)]

use crate::skinny::skinny_128_384_plus_enc;

pub(crate) const AD_BLK_ODD: usize = 16;
pub(crate) const AD_BLK_EVN: usize = 16;
pub(crate) const MSG_BLK: usize = 16;

#[inline]
pub(crate) fn pad(m: &[u8], mp: &mut [u8], l: usize, len8: usize) {
    for i in 0..l {
        if i < len8 {
            mp[i] = m[i];
        } else if i == l - 1 {
            mp[i] = (len8 & 0x0F) as u8;
        } else {
            mp[i] = 0x00;
        }
    }
}

#[inline]
pub(crate) fn g8a(s: &[u8; 16], c: &mut [u8; 16]) {
    for i in 0..16 {
        c[i] = (s[i] >> 1) ^ (s[i] & 0x80) ^ ((s[i] & 0x01) << 7);
    }
}

#[inline]
pub(crate) fn rho_ad(m: &[u8], s: &mut [u8; 16], len8: usize, ver: usize) {
    let mut mp = [0u8; 16];
    pad(m, &mut mp, ver, len8);
    for i in 0..ver {
        s[i] ^= mp[i];
    }
}

#[inline]
pub(crate) fn rho(m: &[u8], c: &mut [u8], s: &mut [u8; 16], len8: usize, ver: usize) {
    let mut mp = [0u8; 16];
    pad(m, &mut mp, ver, len8);
    let mut gs = [0u8; 16];
    g8a(s, &mut gs);
    for i in 0..ver {
        s[i] ^= mp[i];
        if i < len8 {
            c[i] = gs[i] ^ mp[i];
        } else {
            c[i] = 0;
        }
    }
}

#[inline]
pub(crate) fn irho(m: &mut [u8], c: &[u8], s: &mut [u8; 16], len8: usize, ver: usize) {
    let mut cp = [0u8; 16];
    pad(c, &mut cp, ver, len8);
    let mut ks = [0u8; 16];
    g8a(s, &mut ks);
    for i in 0..ver {
        if i < len8 {
            s[i] ^= cp[i] ^ ks[i];
        } else {
            s[i] ^= cp[i];
        }
        if i < len8 {
            m[i] = ks[i] ^ cp[i];
        } else {
            m[i] = 0;
        }
    }
}

#[inline]
pub(crate) fn reset_lfsr_gf56(cnt: &mut [u8; 7]) {
    cnt[0] = 0x01;
    cnt[1..7].fill(0);
}

#[inline]
pub(crate) fn lfsr_gf56(cnt: &mut [u8; 7]) {
    let fb0 = cnt[6] >> 7;
    cnt[6] = (cnt[6] << 1) | (cnt[5] >> 7);
    cnt[5] = (cnt[5] << 1) | (cnt[4] >> 7);
    cnt[4] = (cnt[4] << 1) | (cnt[3] >> 7);
    cnt[3] = (cnt[3] << 1) | (cnt[2] >> 7);
    cnt[2] = (cnt[2] << 1) | (cnt[1] >> 7);
    cnt[1] = (cnt[1] << 1) | (cnt[0] >> 7);
    if fb0 == 1 {
        cnt[0] = (cnt[0] << 1) ^ 0x95;
    } else {
        cnt[0] <<= 1;
    }
}

#[inline]
pub(crate) fn compose_tweakey(
    kt: &mut [u8; 48],
    k: &[u8; 16],
    t: &[u8],
    cnt: &[u8; 7],
    d: u8,
    tlen: usize,
) {
    kt[..7].copy_from_slice(&cnt[..7]);
    kt[7] = d;
    kt[8..16].fill(0);
    kt[16..16 + tlen].copy_from_slice(&t[..tlen]);
    kt[16 + tlen..16 + tlen + 16].copy_from_slice(k);
}

#[inline]
pub(crate) fn block_cipher(
    s: &mut [u8; 16],
    k: &[u8; 16],
    t: &[u8],
    cnt: &mut [u8; 7],
    d: u8,
    tlen: usize,
) {
    let mut kt = [0u8; 48];
    compose_tweakey(&mut kt, k, t, cnt, d, tlen);
    skinny_128_384_plus_enc(s, &kt);
}

#[inline]
pub(crate) fn nonce_encryption(
    n: &[u8; 16],
    cnt: &mut [u8; 7],
    s: &mut [u8; 16],
    k: &[u8; 16],
    t: usize,
    d: u8,
) {
    let mut tw = [0u8; 16];
    tw[..t].copy_from_slice(&n[..t]);
    block_cipher(s, k, &tw[..t], cnt, d, t);
}

/// Romulus-N / shared AD path: domain `d` for inner TBC (0x08 for N, 0x28 for M MAC AD).
pub(crate) fn ad_encryption(
    a: &[u8],
    a_off: &mut usize,
    s: &mut [u8; 16],
    k: &[u8; 16],
    mut adlen: u64,
    cnt: &mut [u8; 7],
    d: u8,
    n: usize,
    t: usize,
) -> u64 {
    let len8 = if adlen >= n as u64 { n } else { adlen as usize };
    if adlen >= n as u64 {
        adlen -= n as u64;
    } else {
        adlen = 0;
    }
    rho_ad(&a[*a_off..*a_off + len8], s, len8, n);
    *a_off += len8;
    lfsr_gf56(cnt);

    if adlen != 0 {
        let len8b = if adlen >= t as u64 { t } else { adlen as usize };
        if adlen >= t as u64 {
            adlen -= t as u64;
        } else {
            adlen = 0;
        }
        let mut tw = [0u8; 16];
        pad(&a[*a_off..*a_off + len8b], &mut tw, t, len8b);
        *a_off += len8b;
        block_cipher(s, k, &tw[..t], cnt, d, t);
        lfsr_gf56(cnt);
    }

    adlen
}

/// Romulus-N message path on a single buffer (`off` advances). Stack scratch avoids aliasing.
pub(crate) fn msg_encryption_n_inplace(
    buf: &mut [u8],
    off: &mut usize,
    n: &[u8; 16],
    cnt: &mut [u8; 7],
    s: &mut [u8; 16],
    k: &[u8; 16],
    blk_n: usize,
    t: usize,
    domain: u8,
    mut mlen: u64,
    decrypt: bool,
) -> u64 {
    let len8 = if mlen >= blk_n as u64 {
        blk_n
    } else {
        mlen as usize
    };
    if mlen >= blk_n as u64 {
        mlen -= blk_n as u64;
    } else {
        mlen = 0;
    }
    let mut tmp = [0u8; 16];
    tmp[..len8].copy_from_slice(&buf[*off..*off + len8]);
    if !decrypt {
        let mut ctmp = [0u8; 16];
        rho(&tmp[..len8], &mut ctmp, s, len8, blk_n);
        buf[*off..*off + len8].copy_from_slice(&ctmp[..len8]);
    } else {
        let mut ptmp = [0u8; 16];
        irho(&mut ptmp, &tmp[..len8], s, len8, blk_n);
        buf[*off..*off + len8].copy_from_slice(&ptmp[..len8]);
    }
    *off += len8;
    lfsr_gf56(cnt);
    nonce_encryption(n, cnt, s, k, t, domain);
    mlen
}

/// Romulus-M encryption message blocks on one buffer.
pub(crate) fn msg_encryption_m_inplace(
    buf: &mut [u8],
    off: &mut usize,
    n: &[u8; 16],
    cnt: &mut [u8; 7],
    s: &mut [u8; 16],
    k: &[u8; 16],
    blk_n: usize,
    t: usize,
    domain: u8,
    mut mlen: u64,
) -> u64 {
    let len8 = if mlen >= blk_n as u64 {
        blk_n
    } else {
        mlen as usize
    };
    if mlen >= blk_n as u64 {
        mlen -= blk_n as u64;
    } else {
        mlen = 0;
    }
    let mut tmp = [0u8; 16];
    tmp[..len8].copy_from_slice(&buf[*off..*off + len8]);
    let mut ctmp = [0u8; 16];
    rho(&tmp[..len8], &mut ctmp, s, len8, blk_n);
    buf[*off..*off + len8].copy_from_slice(&ctmp[..len8]);
    *off += len8;
    lfsr_gf56(cnt);
    nonce_encryption(n, cnt, s, k, t, domain);
    mlen
}

/// Romulus-M decryption message blocks on one buffer.
pub(crate) fn msg_decryption_m_inplace(
    buf: &mut [u8],
    off: &mut usize,
    n: &[u8; 16],
    cnt: &mut [u8; 7],
    s: &mut [u8; 16],
    k: &[u8; 16],
    blk_n: usize,
    t: usize,
    domain: u8,
    mut clen: u64,
) -> u64 {
    let len8 = if clen >= blk_n as u64 {
        blk_n
    } else {
        clen as usize
    };
    if clen >= blk_n as u64 {
        clen -= blk_n as u64;
    } else {
        clen = 0;
    }
    let mut tmp = [0u8; 16];
    tmp[..len8].copy_from_slice(&buf[*off..*off + len8]);
    let mut ptmp = [0u8; 16];
    irho(&mut ptmp, &tmp[..len8], s, len8, blk_n);
    buf[*off..*off + len8].copy_from_slice(&ptmp[..len8]);
    *off += len8;
    lfsr_gf56(cnt);
    nonce_encryption(n, cnt, s, k, t, domain);
    clen
}

/// Bridge when AD block count is odd (Romulus-M MAC phase).
pub(crate) fn ad2msg_encryption(
    m: &[u8],
    m_off: &mut usize,
    cnt: &mut [u8; 7],
    s: &mut [u8; 16],
    k: &[u8; 16],
    t: usize,
    d: u8,
    mut mlen: u64,
) -> u64 {
    let len8 = if mlen <= t as u64 { mlen as usize } else { t };
    if mlen <= t as u64 {
        mlen = 0;
    } else {
        mlen -= t as u64;
    }
    let mut tw = [0u8; 16];
    pad(&m[*m_off..*m_off + len8], &mut tw, t, len8);
    *m_off += len8;
    block_cipher(s, k, &tw[..t], cnt, d, t);
    lfsr_gf56(cnt);
    mlen
}

/// Compute final MAC domain byte `w` for Romulus-M (matches reference C).
pub(crate) fn romulus_m_compute_w(adlen: u64, xlen: u64, n: usize, t: usize) -> u8 {
    let mut w: u8 = 48;
    let nt = (n + t) as u64;

    if adlen == 0 {
        w ^= 2;
        if xlen == 0 {
            w ^= 1;
        } else if xlen.is_multiple_of(nt) {
            w ^= 4;
        } else if xlen % nt < t as u64 {
            w ^= 1;
        } else if xlen % nt == t as u64 {
            w ^= 0;
        } else {
            w ^= 5;
        }
    } else if adlen.is_multiple_of(nt) {
        w ^= 8;
        if xlen == 0 {
            w ^= 1;
        } else if xlen.is_multiple_of(nt) {
            w ^= 4;
        } else if xlen % nt < n as u64 {
            w ^= 1;
        } else if xlen % nt == n as u64 {
            w ^= 0;
        } else {
            w ^= 5;
        }
    } else if adlen % nt < n as u64 {
        w ^= 2;
        if xlen == 0 {
            w ^= 1;
        } else if xlen.is_multiple_of(nt) {
            w ^= 4;
        } else if xlen % nt < t as u64 {
            w ^= 1;
        } else if xlen % nt == t as u64 {
            w ^= 0;
        } else {
            w ^= 5;
        }
    } else if adlen % nt == n as u64 {
        w ^= 0;
        if xlen == 0 {
            w ^= 1;
        } else if xlen.is_multiple_of(nt) {
            w ^= 4;
        } else if xlen % nt < t as u64 {
            w ^= 1;
        } else if xlen % nt == t as u64 {
            w ^= 0;
        } else {
            w ^= 5;
        }
    } else {
        w ^= 10;
        if xlen == 0 {
            w ^= 1;
        } else if xlen.is_multiple_of(nt) {
            w ^= 4;
        } else if xlen % nt < n as u64 {
            w ^= 1;
        } else if xlen % nt == n as u64 {
            w ^= 0;
        } else {
            w ^= 5;
        }
    }
    w
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- pad: padding and domain-separation byte handling ----

    #[test]
    fn pad_full_block_copies_verbatim_no_length_marker() {
        let m: [u8; 16] = core::array::from_fn(|i| i as u8);
        let mut mp = [0u8; 16];
        pad(&m, &mut mp, 16, 16);
        assert_eq!(mp, m, "a full block must not carry a length-nibble marker");
    }

    #[test]
    fn pad_partial_block_zero_fills_and_marks_length() {
        let m = [0xAAu8; 16];
        let mut mp = [0u8; 16];
        pad(&m, &mut mp, 16, 5);
        assert_eq!(&mp[..5], &m[..5], "data bytes must be copied verbatim");
        assert_eq!(&mp[5..15], &[0u8; 10], "gap bytes must be zero");
        assert_eq!(mp[15], 5, "last byte carries the length nibble");
    }

    #[test]
    fn pad_empty_input_is_all_zero_with_zero_length_marker() {
        let m: [u8; 0] = [];
        let mut mp = [0xFFu8; 16];
        pad(&m, &mut mp, 16, 0);
        assert_eq!(mp, [0u8; 16]);
    }

    #[test]
    fn pad_boundary_len8_equals_l_minus_one() {
        // len8 == l - 1: the very last slot is the marker, not a data byte.
        let m = [0x11u8; 15];
        let mut mp = [0u8; 16];
        pad(&m, &mut mp, 16, 15);
        assert_eq!(&mp[..15], &m[..]);
        assert_eq!(mp[15], 15 & 0x0F);
    }

    // ---- g8a: linear diffusion step used by rho/irho ----

    /// g8a must be a bijection on bytes (each output byte determines the input uniquely).
    /// Independent inverse formula: old_bits(7..1) = new_bits(6..0); old_bit0 = new_bit7
    /// ^ new_bit6. Derived from g8a's definition and brute-force-verified over all 256
    /// byte values (standalone, outside this crate) before writing this assertion.
    #[test]
    fn g8a_is_a_bijection_with_known_inverse() {
        for b in 0u8..=255 {
            let s = [b; 16];
            let mut c = [0u8; 16];
            g8a(&s, &mut c);
            let new = c[0];
            let bit6 = (new >> 6) & 1;
            let bit7 = (new >> 7) & 1;
            let old_bit0 = bit7 ^ bit6;
            let old_bits_7_1 = new & 0x7F;
            let recovered = (old_bits_7_1 << 1) | old_bit0;
            assert_eq!(
                recovered, b,
                "g8a inverse formula failed to recover {b:#04x}"
            );
        }
    }

    // ---- reset_lfsr_gf56 / lfsr_gf56: GF(2^56) counter used for domain separation ----

    #[test]
    fn reset_lfsr_gf56_is_one_followed_by_zeros() {
        let mut cnt = [0xFFu8; 7];
        reset_lfsr_gf56(&mut cnt);
        assert_eq!(cnt, [0x01, 0, 0, 0, 0, 0, 0]);
    }

    /// Hand-derived transitions (not produced by running this crate's code): the register
    /// is a 56-bit value stored little-endian across `cnt[0..7]`, shifted left by one bit
    /// per call, with the bit shifted out of the MSB conditionally XORing 0x95 into the
    /// new LSB byte.
    #[test]
    fn lfsr_gf56_simple_doubling_without_feedback() {
        // value 1 -> 2, no byte-boundary carry, no feedback (top bit of cnt[6] is 0).
        let mut cnt = [0x01, 0, 0, 0, 0, 0, 0];
        lfsr_gf56(&mut cnt);
        assert_eq!(cnt, [0x02, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn lfsr_gf56_carries_across_a_byte_boundary() {
        // value 0x80 (bit7 of byte0 set) -> 0x100: carry into byte1, byte0 wraps to 0.
        let mut cnt = [0x80, 0, 0, 0, 0, 0, 0];
        lfsr_gf56(&mut cnt);
        assert_eq!(cnt, [0x00, 0x01, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn lfsr_gf56_propagates_carry_through_every_byte() {
        // Every byte except the top has its MSB set: shifting must carry byte-to-byte in
        // strict top-down order (cnt[6] computed from the *old* cnt[5], etc.) — an
        // implementation that updated bottom-up would read already-shifted inputs and
        // produce a different result.
        let mut cnt = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00];
        lfsr_gf56(&mut cnt);
        assert_eq!(cnt, [0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]);
    }

    #[test]
    fn lfsr_gf56_feedback_polynomial_applies_on_msb_overflow() {
        // Top bit of cnt[6] set (fb0 = 1): the new LSB byte becomes 0x95 (the feedback
        // constant), not a plain shift.
        let mut cnt = [0, 0, 0, 0, 0, 0, 0x80];
        lfsr_gf56(&mut cnt);
        assert_eq!(cnt, [0x95, 0, 0, 0, 0, 0, 0]);
    }

    /// Structural invariant: this is a maximal-length LFSR over a nonzero multiplicative
    /// group element, so starting from the nonzero reset state it must never reach the
    /// all-zero state (which is a fixed point: 0 maps to 0), and consecutive short-run
    /// states must not repeat.
    #[test]
    #[cfg(feature = "alloc")]
    fn lfsr_gf56_never_hits_zero_and_does_not_short_cycle() {
        let mut cnt = [0u8; 7];
        reset_lfsr_gf56(&mut cnt);
        let mut seen = alloc::collections::BTreeSet::new();
        for step in 0..20_000u32 {
            assert_ne!(cnt, [0u8; 7], "LFSR hit the all-zero state at step {step}");
            assert!(
                seen.insert(cnt),
                "LFSR repeated a state within 20000 steps at step {step}"
            );
            lfsr_gf56(&mut cnt);
        }
    }

    // ---- rho / irho: the core state-update (encryption/decryption) primitive ----

    /// rho (encrypt direction) and irho (decrypt direction) must be exact inverses: given
    /// the same starting state, rho(m) -> (c, s1) and irho(c) -> (m', s1') must satisfy
    /// m' == m and s1' == s1, for every padding boundary case. Verified standalone before
    /// writing this test.
    #[test]
    fn rho_and_irho_round_trip_for_all_padding_boundaries() {
        let s0: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(1));
        let m_full: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
        for len8 in [0usize, 1, 5, 15, 16] {
            let ver = 16;
            let m = &m_full[..len8];

            let mut c = [0u8; 16];
            let mut s_enc = s0;
            rho(m, &mut c, &mut s_enc, len8, ver);

            let mut m_rec = [0u8; 16];
            let mut s_dec = s0;
            irho(&mut m_rec, &c, &mut s_dec, len8, ver);

            assert_eq!(
                &m_rec[..len8],
                m,
                "irho failed to recover plaintext at len8={len8}"
            );
            assert_eq!(
                s_dec, s_enc,
                "irho produced a different resulting state at len8={len8}"
            );
        }
    }

    // ---- compose_tweakey: byte-layout / domain-separation of the 384-bit tweakey ----

    #[test]
    fn compose_tweakey_lays_out_counter_domain_tweak_and_key() {
        let cnt: [u8; 7] = [1, 2, 3, 4, 5, 6, 7];
        let k: [u8; 16] = core::array::from_fn(|i| 0xB0 + i as u8);
        let t: [u8; 4] = [0xAA, 0xBB, 0xCC, 0xDD];
        let d: u8 = 0x2C;
        let mut kt = [0u8; 48];
        compose_tweakey(&mut kt, &k, &t, &cnt, d, t.len());

        assert_eq!(&kt[0..7], &cnt, "counter must occupy bytes 0..7");
        assert_eq!(kt[7], d, "domain byte must occupy byte 7");
        assert_eq!(&kt[8..16], &[0u8; 8], "bytes 8..16 must be zero-filled");
        assert_eq!(&kt[16..20], &t, "tweak bytes must follow at byte 16");
        assert_eq!(
            &kt[20..36],
            &k,
            "key must immediately follow the tweak bytes"
        );
        assert_eq!(
            &kt[36..48],
            &[0u8; 12],
            "trailing bytes are untouched (zero-initialized)"
        );
    }

    // ---- romulus_m_compute_w: Romulus-M's final MAC domain-separation byte ----

    /// Full boundary matrix over the five mutually-exclusive `adlen` branches x five
    /// `xlen` branches (n = t = 16 in this crate, so nt = 32). Expected values were
    /// computed by an independent re-transcription of the function and cross-checked
    /// against the branch algebra by hand before being hardcoded; this locks in exact
    /// domain-byte behavior at every branch boundary (multiples of nt, exactly n, exactly
    /// t, and the "else" gaps) so a `<` vs `<=` or `n` vs `t` slip is caught.
    #[test]
    fn compute_w_boundary_matrix() {
        const N: usize = AD_BLK_ODD;
        const T: usize = AD_BLK_EVN;
        let cases: &[(u64, u64, u8)] = &[
            (0, 0, 51),
            (0, 32, 54),
            (0, 5, 51),
            (0, 16, 50),
            (0, 20, 55),
            (32, 0, 57),
            (32, 32, 60),
            (32, 5, 57),
            (32, 16, 56),
            (32, 20, 61),
            (5, 0, 51),
            (5, 32, 54),
            (5, 5, 51),
            (5, 16, 50),
            (5, 20, 55),
            (16, 0, 49),
            (16, 32, 52),
            (16, 5, 49),
            (16, 16, 48),
            (16, 20, 53),
            (20, 0, 59),
            (20, 32, 62),
            (20, 5, 59),
            (20, 16, 58),
            (20, 20, 63),
        ];
        for &(adlen, xlen, expected) in cases {
            let got = romulus_m_compute_w(adlen, xlen, N, T);
            assert_eq!(
                got, expected,
                "romulus_m_compute_w(adlen={adlen}, xlen={xlen}) = {got}, expected {expected}"
            );
        }
    }
}
