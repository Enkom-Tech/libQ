//! SHAKE-256 sponge construction on top of the audited Keccak-f\[1600\] permutation AIR
//! (`lib-q-plonky-keccak-air`).
//!
//! The permutation AIR proves a single Keccak-f permutation (24 rows, 2633 columns). It does **not**
//! prove the sponge *around* the permutation: pad10\*1 padding with the SHAKE domain suffix, the rate
//! XOR of each absorbed block, the squeeze extraction, or the cross-permutation state chaining. This
//! module builds exactly that sponge.
//!
//! This file provides the **trace-generation and extraction** half (byte-exact, validated against
//! `lib_q_sha3::Shake256` by a KAT). The AIR constraint layer that *proves* the chaining/padding in
//! zero knowledge (design §3.2) is built on top of these row conventions.
//!
//! Layout recap (SHAKE-256): rate `r = 1088 bits = 136 bytes = 17` lanes; capacity `c = 512 bits =
//! 8` lanes; state `= 25` lanes of 64 bits. Lane `(x, y)` sits at flat index `5y + x`; the rate is
//! the first 17 lanes. Each lane serializes little-endian, matching `rq`/`u64` byte order.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use lib_q_plonky_keccak_air::{
    KeccakColsRef,
    NUM_KECCAK_COLS,
    NUM_ROUNDS,
    U64_LIMBS,
    generate_trace_rows,
};
use lib_q_stark_field::PrimeField64;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_stark_symmetric::{
    KeccakF,
    Permutation,
};

/// SHAKE-256 rate in bytes (`r = 1088 bits`).
pub const RATE_BYTES: usize = 136;

/// SHAKE-256 rate in 64-bit lanes (`136 / 8`).
pub const RATE_LANES: usize = RATE_BYTES / 8; // 17

/// SHAKE domain-separation / padding suffix byte (the `1111` suffix of pad10\*1 for XOFs).
pub const SHAKE_PAD: u8 = 0x1F;

/// Final-byte padding bit (the trailing `1` of pad10\*1).
pub const SHAKE_PAD_FINAL: u8 = 0x80;

/// `pad10*1` with the SHAKE suffix. Returns a byte string whose length is a positive multiple of
/// [`RATE_BYTES`]. This is the padding the sponge AIR's boundary constraints must enforce on the
/// first absorbed block (design §3.2, constraint 1).
fn shake256_pad(input: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();
    out.push(SHAKE_PAD);
    while !out.len().is_multiple_of(RATE_BYTES) {
        out.push(0);
    }
    let last = out.len() - 1;
    out[last] |= SHAKE_PAD_FINAL;
    out
}

/// Number of absorb blocks (padded input length divided by the rate).
fn num_absorb_blocks(input_len: usize) -> usize {
    // `shake256_pad` appends at least one byte (the `0x1F`), then rounds up to a rate multiple.
    (input_len + 1).div_ceil(RATE_BYTES)
}

/// Number of squeeze output blocks needed for `out_len` bytes (at least one).
fn num_output_blocks(out_len: usize) -> usize {
    out_len.div_ceil(RATE_BYTES).max(1)
}

/// Total number of Keccak-f permutations a SHAKE-256 computation over an `input_len`-byte input
/// needs to produce `out_len` output bytes: one per absorb block, plus `output_blocks - 1` squeeze
/// permutations. This is the permutation-block count the sponge trace occupies (design §7 cost).
pub fn num_permutations(input_len: usize, out_len: usize) -> usize {
    num_absorb_blocks(input_len) + num_output_blocks(out_len) - 1
}

/// XOR a 136-byte rate block into the first 17 lanes of the state (little-endian per lane).
fn xor_block_into(state: &mut [u64; 25], block: &[u8]) {
    debug_assert!(block.len() >= RATE_BYTES);
    for (lane, dst) in state.iter_mut().enumerate().take(RATE_LANES) {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&block[lane * 8..lane * 8 + 8]);
        *dst ^= u64::from_le_bytes(bytes);
    }
}

/// Apply the Keccak-f\[1600\] permutation (same reference the permutation AIR is validated against).
fn keccak_f(mut state: [u64; 25]) -> [u64; 25] {
    KeccakF.permute_mut(&mut state);
    state
}

/// Build the ordered list of Keccak-f permutation **input** states for the SHAKE-256 sponge over
/// `input`, sized to yield `out_len` output bytes.
///
/// Sponge semantics (single running state `S`):
/// - Absorb block `b`: `S ^= block_b` (into the rate), the permutation *input* is this post-XOR `S`,
///   then `S = Keccak-f(S)`.
/// - After the last absorb, `S` is the squeeze-0 source; each further output block adds one squeeze
///   permutation `S = Keccak-f(S)`.
///
/// The permutation at index `num_absorb - 1 + j` has as its **output** the source of output block
/// `j` (see [`extract_squeeze`]).
fn permutation_input_states(input: &[u8], out_len: usize) -> Vec<[u64; 25]> {
    let padded = shake256_pad(input);
    let num_absorb = padded.len() / RATE_BYTES;
    let num_out = num_output_blocks(out_len);

    let mut inputs = Vec::with_capacity(num_absorb + num_out - 1);
    let mut state = [0u64; 25];

    // Absorb: each block's permutation input is the running state AFTER the block is XORed in.
    for b in 0..num_absorb {
        xor_block_into(&mut state, &padded[b * RATE_BYTES..]);
        inputs.push(state);
        state = keccak_f(state);
    }
    // `state` is now the squeeze-0 source (= output of the final absorb permutation).
    // Extra squeeze permutations for output blocks 1..num_out.
    for _ in 1..num_out {
        inputs.push(state);
        state = keccak_f(state);
    }
    inputs
}

/// The ordered Keccak-f permutation **input** states of the SHAKE-256 sponge over `input`, extended
/// by squeeze continuation to **exactly `count` permutations** (`count ≥ num_absorb_blocks`). The
/// first `num_permutations(input.len(), out_len)` states are the real absorb + squeeze sequence; any
/// beyond that are further squeeze steps whose output is ignored.
///
/// This is used to build a **power-of-two-height** sponge trace in which *every* permutation boundary
/// is a genuine sponge step, so the `ShakeSpongeAir` squeeze-chaining constraint holds uniformly
/// without any padding selector: instead of the audited generator's zero-input padding permutations,
/// the padding rows carry real continuation permutations (see `sponge_air::generate_provable_sponge_trace`).
pub fn sponge_permutation_states(input: &[u8], count: usize) -> Vec<[u64; 25]> {
    let padded = shake256_pad(input);
    let num_absorb = padded.len() / RATE_BYTES;
    debug_assert!(count >= num_absorb, "count must cover the absorb blocks");

    let mut states = Vec::with_capacity(count);
    let mut state = [0u64; 25];
    for b in 0..num_absorb {
        xor_block_into(&mut state, &padded[b * RATE_BYTES..]);
        states.push(state);
        state = keccak_f(state);
    }
    while states.len() < count {
        states.push(state);
        state = keccak_f(state);
    }
    states
}

/// Generate the SHAKE-256 sponge trace for `input`, sized to yield `out_len` output bytes.
///
/// The result is a chained sequence of Keccak-f permutation blocks over `Mersenne31` (24 rows each),
/// produced by the audited permutation trace generator. Row block `i` holds permutation `i`; its
/// preimage equals permutation `i-1`'s output (the sponge chaining the AIR must enforce).
pub fn generate_sponge_trace(input: &[u8], out_len: usize) -> RowMajorMatrix<Mersenne31> {
    let inputs = permutation_input_states(input, out_len);
    generate_trace_rows::<Mersenne31>(inputs, 0)
}

/// Read a permutation's output rate lanes (its 136 squeezed bytes) from the block's final round-row.
fn read_output_rate<F: PrimeField64>(
    trace: &RowMajorMatrix<F>,
    perm_idx: usize,
    out: &mut Vec<u8>,
) {
    let last_round = perm_idx * NUM_ROUNDS + (NUM_ROUNDS - 1);
    let start = last_round * NUM_KECCAK_COLS;
    let row = KeccakColsRef::from_row_slice(&trace.values[start..start + NUM_KECCAK_COLS]);
    for lane in 0..RATE_LANES {
        let x = lane % 5;
        let y = lane / 5;
        let mut value = 0u64;
        for limb in 0..U64_LIMBS {
            let limb_val = row.a_prime_prime_prime(y, x, limb).as_canonical_u64();
            value |= limb_val << (limb * 16);
        }
        out.extend_from_slice(&value.to_le_bytes());
    }
}

/// Extract the SHAKE-256 squeezed output (`out_len` bytes) from a sponge trace produced by
/// [`generate_sponge_trace`] with the same `input_len`/`out_len`.
///
/// Output block `j` is the rate part of permutation `num_absorb - 1 + j`'s output.
pub fn extract_squeeze<F: PrimeField64>(
    trace: &RowMajorMatrix<F>,
    input_len: usize,
    out_len: usize,
) -> Vec<u8> {
    let num_absorb = num_absorb_blocks(input_len);
    let num_out = num_output_blocks(out_len);

    let mut out = Vec::with_capacity(num_out * RATE_BYTES);
    for j in 0..num_out {
        read_output_rate(trace, num_absorb - 1 + j, &mut out);
    }
    out.truncate(out_len);
    out
}

#[cfg(test)]
mod tests {
    use lib_q_sha3::{
        ExtendableOutput,
        Update,
        XofReader,
    };

    use super::*;

    /// Reference SHAKE-256 XOF output via the production sponge (the wire the KEM uses).
    fn shake256_reference(input: &[u8], out_len: usize) -> Vec<u8> {
        let mut h = lib_q_sha3::Shake256::default();
        h.update(input);
        let mut rd = h.finalize_xof();
        let mut out = vec![0u8; out_len];
        rd.read(&mut out);
        out
    }

    fn check(input: &[u8], out_len: usize) {
        let trace = generate_sponge_trace(input, out_len);
        let got = extract_squeeze(&trace, input.len(), out_len);
        let want = shake256_reference(input, out_len);
        assert_eq!(
            got,
            want,
            "SHAKE-256 sponge trace != reference (in {} bytes, out {} bytes)",
            input.len(),
            out_len
        );
    }

    /// The exact encapsulation preimage shape: 38-byte label ‖ 32-byte pk_digest ‖ 32-byte mu.
    #[test]
    fn sponge_matches_reference_on_encap_preimage() {
        let mut input = Vec::new();
        input.extend_from_slice(b"lib-q-threshold-kem-lattice/fo-seed/v1");
        input.extend_from_slice(&[0xABu8; 32]); // stand-in pk_digest
        input.extend_from_slice(&[0x5Cu8; 32]); // stand-in mu
        assert_eq!(input.len(), 102, "encap preimage must be 38+32+32 bytes");

        // Single-block absorb; single and multi-block squeeze, plus a non-block-aligned length.
        for out_len in [32usize, 136, 137, 272, 500, 1088] {
            check(&input, out_len);
        }
    }

    /// Cover the absorb-side edge cases: empty input, exact-fit, and one-past-fit (extra pad block),
    /// plus multi-absorb + multi-squeeze.
    #[test]
    fn sponge_matches_reference_on_edge_inputs() {
        check(b"", 32);
        check(b"", 200);
        check(b"abc", 64);
        check(&[0x11u8; 135], 136); // 135 + 0x1F fits one block exactly
        check(&[0x22u8; 136], 136); // 136 + pad overflows into a second absorb block
        check(&[0x33u8; 300], 400); // multi-absorb and multi-squeeze
        check(&[0x44u8; 271], 1088);
    }

    /// The full encapsulation draw is ~90 KB (≈ 662 permutations); confirm the chaining stays
    /// byte-exact at realistic scale, not just for a few blocks.
    #[test]
    fn sponge_matches_reference_at_encap_draw_scale() {
        let mut input = Vec::new();
        input.extend_from_slice(b"lib-q-threshold-kem-lattice/fo-seed/v1");
        input.extend_from_slice(&[0x01u8; 32]);
        input.extend_from_slice(&[0x02u8; 32]);
        // 12 KB covers many squeeze blocks (~90 permutations) without a multi-minute trace.
        check(&input, 12_288);
    }

    #[test]
    fn permutation_count_matches_layout() {
        // 102-byte input -> 1 absorb block; 1088-byte output -> 8 squeeze blocks -> 8 permutations.
        assert_eq!(num_permutations(102, 1088), 8);
        // 136-byte input -> 2 absorb blocks (pad overflow); 32-byte output -> 1 block.
        assert_eq!(num_permutations(136, 32), 2);
        assert_eq!(num_permutations(0, 1), 1);
    }
}
