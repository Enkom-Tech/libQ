//! Four-way batched TurboSHAKE, driven by [`lib_q_keccak::p1600x4`].
//!
//! TurboSHAKE (and therefore KangarooTwelve's leaf hashing) absorbs each message
//! through an identical block schedule — only the data differs. Running four
//! independent messages in the four lanes of one AVX2 register is the
//! [XKCP `KeccakP1600times4`](https://github.com/XKCP/XKCP) win, exposed here as a
//! small, fixed-function primitive.
//!
//! The result is **bit-for-bit identical** to running four scalar
//! [`TurboShake128`](crate::TurboShake128) / [`TurboShake256`](crate::TurboShake256)
//! instances; on targets without AVX2 the underlying permutation simply falls
//! back to four scalar permutations, so output never changes.
//!
//! All four inputs must share one length, and all four outputs one length — this
//! is exactly the shape of KangarooTwelve's uniform 8192-byte leaves. Ragged
//! groups (e.g. a short final leaf) should use the scalar path.

use crate::{
    PLEN,
    xor_block,
};

const TURBO_SHAKE_ROUND_COUNT: usize = 12;
/// Full Keccak-f\[1600\] round count, used by SHAKE (FIPS 202).
const KECCAK_F_ROUND_COUNT: usize = 24;

/// SHAKE / TurboSHAKE128 rate in bytes (1600 − 2·128 bits).
const RATE_128: usize = 168;
/// SHAKE / TurboSHAKE256 rate in bytes (1600 − 2·256 bits).
const RATE_256: usize = 136;

/// FIPS 202 SHAKE domain-separation byte (`0b…1111` suffix folded with the first pad bit).
const SHAKE_DS: u8 = 0x1F;

/// Four-way TurboSHAKE128 with domain byte `ds`.
///
/// Hashes the four equal-length `inputs` and writes the requested XOF bytes into
/// the four equal-length `outputs`. Equivalent to four independent
/// [`TurboShake128`](crate::TurboShake128)`::<DS>` instances.
///
/// # Panics
/// Panics if `ds` is outside `0x01..=0x7F`, if the four inputs are not all the
/// same length, or if the four outputs are not all the same length.
#[inline]
pub fn turbo_shake128_x4(ds: u8, inputs: [&[u8]; 4], outputs: [&mut [u8]; 4]) {
    assert!(
        (0x01..=0x7F).contains(&ds),
        "invalid TurboSHAKE domain separator"
    );
    keccak_xof_x4::<RATE_128>(ds, TURBO_SHAKE_ROUND_COUNT, inputs, outputs);
}

/// Four-way TurboSHAKE256 with domain byte `ds`.
///
/// Hashes the four equal-length `inputs` and writes the requested XOF bytes into
/// the four equal-length `outputs`. Equivalent to four independent
/// [`TurboShake256`](crate::TurboShake256)`::<DS>` instances.
///
/// # Panics
/// Panics if `ds` is outside `0x01..=0x7F`, if the four inputs are not all the
/// same length, or if the four outputs are not all the same length.
#[inline]
pub fn turbo_shake256_x4(ds: u8, inputs: [&[u8]; 4], outputs: [&mut [u8]; 4]) {
    assert!(
        (0x01..=0x7F).contains(&ds),
        "invalid TurboSHAKE domain separator"
    );
    keccak_xof_x4::<RATE_256>(ds, TURBO_SHAKE_ROUND_COUNT, inputs, outputs);
}

/// Four-way SHAKE128 (FIPS 202).
///
/// Hashes the four equal-length `inputs` and writes the requested XOF bytes into the four
/// equal-length `outputs`. Equivalent to four independent [`Shake128`](crate::Shake128) instances.
///
/// # Panics
/// Panics if the four inputs are not all the same length, or the four outputs are not all the same
/// length.
#[inline]
pub fn shake128_x4(inputs: [&[u8]; 4], outputs: [&mut [u8]; 4]) {
    keccak_xof_x4::<RATE_128>(SHAKE_DS, KECCAK_F_ROUND_COUNT, inputs, outputs);
}

/// Four-way SHAKE256 (FIPS 202).
///
/// Hashes the four equal-length `inputs` and writes the requested XOF bytes into the four
/// equal-length `outputs`. Equivalent to four independent [`Shake256`](crate::Shake256) instances.
///
/// This is the batched primitive behind SLH-DSA's independent WOTS+/FORS hash chains.
///
/// # Panics
/// Panics if the four inputs are not all the same length, or the four outputs are not all the same
/// length.
#[inline]
pub fn shake256_x4(inputs: [&[u8]; 4], outputs: [&mut [u8]; 4]) {
    keccak_xof_x4::<RATE_256>(SHAKE_DS, KECCAK_F_ROUND_COUNT, inputs, outputs);
}

/// Serialize the rate region of one state into `out` (`out.len() <= RATE`),
/// matching the scalar XOF reader's little-endian lane extraction.
#[inline]
fn squeeze_into(state: &[u64; PLEN], out: &mut [u8]) {
    for (chunk, s) in out.chunks_mut(8).zip(state.iter()) {
        chunk.copy_from_slice(&s.to_le_bytes()[..chunk.len()]);
    }
}

/// Four-way Keccak-based XOF sponge: absorb four equal-length inputs through identical block
/// schedules, then squeeze. `RATE` selects the capacity (rate in bytes), `ds` the domain byte, and
/// `rounds` the permutation round count (12 for TurboSHAKE, 24 for FIPS-202 SHAKE). Bit-identical to
/// four scalar instances of the corresponding XOF.
fn keccak_xof_x4<const RATE: usize>(
    ds: u8,
    rounds: usize,
    inputs: [&[u8]; 4],
    mut outputs: [&mut [u8]; 4],
) {
    debug_assert!(
        (0x01..=0xFF).contains(&ds),
        "domain separator byte must be non-zero"
    );
    let in_len = inputs[0].len();
    assert!(
        inputs.iter().all(|i| i.len() == in_len),
        "turbo_shake_x4 requires all inputs to share one length"
    );
    let out_len = outputs[0].len();
    assert!(
        outputs.iter().all(|o| o.len() == out_len),
        "turbo_shake_x4 requires all outputs to share one length"
    );

    let mut states = [[0u64; PLEN]; 4];

    // Absorb whole rate blocks across all four lanes in lockstep.
    let mut off = 0;
    while off + RATE <= in_len {
        for (state, input) in states.iter_mut().zip(inputs.iter()) {
            xor_block(state, &input[off..off + RATE]);
        }
        lib_q_keccak::p1600x4(&mut states, rounds);
        off += RATE;
    }

    // Final block: trailing bytes, the domain byte, then the pad10*1 terminator.
    let rem = in_len - off;
    for (state, input) in states.iter_mut().zip(inputs.iter()) {
        let mut block = [0u8; RATE];
        block[..rem].copy_from_slice(&input[off..]);
        block[rem] = ds;
        block[RATE - 1] |= 0x80;
        xor_block(state, &block);
    }
    lib_q_keccak::p1600x4(&mut states, rounds);

    // Squeeze, permuting between rate-sized output blocks.
    let mut produced = 0;
    loop {
        let n = core::cmp::min(RATE, out_len - produced);
        for (state, out) in states.iter().zip(outputs.iter_mut()) {
            squeeze_into(state, &mut out[produced..produced + n]);
        }
        produced += n;
        if produced >= out_len {
            break;
        }
        lib_q_keccak::p1600x4(&mut states, rounds);
    }
}
