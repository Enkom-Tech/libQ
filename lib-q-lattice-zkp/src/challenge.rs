//! ML-DSA–compatible sparse ternary challenges.

use alloc::boxed::Box;
use alloc::vec::Vec;

use lib_q_ring::constants::COEFFICIENTS_IN_RING_ELEMENT;
use lib_q_ring::encoding::simple_bit_pack_len;
use lib_q_ring::{
    Poly,
    sample_in_ball,
};

/// Sparse ternary challenge polynomial plus a packed bit representation.
#[derive(Clone, Debug)]
pub struct MlDsaCompatibleChallenge {
    /// Challenge in `R_q` (time domain, sparse ±1 / 0).
    pub poly: Poly,
    /// `SimpleBitPack` of unsigned coefficient form (0,1,2 encoding of -1,0,1) at `w=2` bits for KAT hooks.
    pub packed: Box<[u8]>,
}

impl MlDsaCompatibleChallenge {
    /// Derive challenge from XOF input bytes and Hamming weight `tau`.
    #[must_use]
    pub fn derive(xof_input: &[u8], tau: usize) -> Self {
        let poly = sample_in_ball(xof_input, tau);
        let packed = pack_ternary_for_wire(&poly);
        Self { poly, packed }
    }

    /// Prefix a protocol domain string, then derive using SHAKE256 over `prefix || stmt` (caller hashes).
    #[must_use]
    pub fn derive_with_prefix(prefix: &[u8], statement: &[u8], tau: usize) -> Self {
        let mut buf = Vec::with_capacity(prefix.len() + statement.len());
        buf.extend_from_slice(prefix);
        buf.extend_from_slice(statement);
        Self::derive(&buf, tau)
    }
}

/// Map {-1,0,1} → {0,1,2} and `SimpleBitPack` with `w=2`.
fn pack_ternary_for_wire(p: &Poly) -> Box<[u8]> {
    let mut u = [0i32; COEFFICIENTS_IN_RING_ELEMENT];
    for (i, &c) in p.coeffs.iter().enumerate() {
        u[i] = match c {
            0 => 0,
            1 => 1,
            -1 => 2,
            _ => 0,
        };
    }
    let mut out = alloc::vec![0u8; simple_bit_pack_len(2)];
    lib_q_ring::encoding::simple_bit_pack(2, &u, &mut out);
    out.into_boxed_slice()
}
