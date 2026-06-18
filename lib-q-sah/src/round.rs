//! S-A-H permutation (spec section 3): AddRC -> ARX -> S-box -> linear.
//!
//! Operates on the 8x64-bit state in place. Fully constant-time: no
//! secret-dependent branches or memory indices (the S-box is the bitsliced
//! Boyar–Peralta circuit, not a table lookup — see `sbox`).

use crate::params::{
    ARX_TUPLES,
    PI,
    RHO,
    ROTATIONS,
    ROUND_CONSTANTS,
};
use crate::sbox::layer_bitsliced;

#[inline(always)]
fn g(s: &mut [u64; 8], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_right(ROTATIONS[0]);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(ROTATIONS[1]);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_right(ROTATIONS[2]);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(ROTATIONS[3]);
}

#[inline]
pub(crate) fn arx_layer(s: &mut [u64; 8]) {
    for t in ARX_TUPLES {
        g(s, t[0], t[1], t[2], t[3]);
    }
}

#[inline]
pub(crate) fn sbox_layer(s: &mut [u64; 8]) {
    // Constant-time AES S-box (bitsliced Boyar–Peralta circuit). Byte-identical
    // to the table substitution, so the wire format and KAT vectors are
    // unchanged; only the implementation is now constant-time.
    layer_bitsliced(s);
}

#[inline]
pub(crate) fn linear_layer(s: &mut [u64; 8]) {
    let mut t = [0u64; 8];
    for i in 0..8 {
        t[i] = s[PI[i]].rotate_left(RHO[i]);
    }
    *s = t;
}

/// Apply rounds 0..n-1. RC is indexed by position within this call.
#[inline]
pub(crate) fn permute(s: &mut [u64; 8], n: u8) {
    for &rc in &ROUND_CONSTANTS[..n as usize] {
        s[0] ^= rc;
        arx_layer(s);
        sbox_layer(s);
        linear_layer(s);
    }
}
