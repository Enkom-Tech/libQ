//! Keccak duplex sponge state for AEAD.

use lib_q_keccak::f1600;

use crate::params::{
    KEY_BYTES,
    NONCE_BYTES,
    PLEN,
    RATE_BYTES,
    TAG_BYTES,
};

/// XOR `data` into the first `data.len()` bytes of the sponge rate (little-endian lanes).
pub fn xor_into_rate(state: &mut [u64; PLEN], data: &[u8]) {
    debug_assert!(data.len() <= RATE_BYTES);
    let (chunks, rem) = data.as_chunks::<8>();
    for (s, chunk) in state.iter_mut().zip(chunks) {
        *s ^= u64::from_le_bytes(*chunk);
    }
    if !rem.is_empty() {
        let mut buf = [0u8; 8];
        buf[..rem.len()].copy_from_slice(rem);
        let n = data.len() / 8;
        state[n] ^= u64::from_le_bytes(buf);
    }
}

/// Read the rate (first `RATE_BYTES`) from `state` into `out`.
pub fn rate_to_bytes(state: &[u64; PLEN], out: &mut [u8; RATE_BYTES]) {
    for i in 0..17 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_le_bytes());
    }
}

/// Replace the rate portion of `state` with `new_rate` (capacity lanes unchanged).
pub fn set_rate_from_bytes(state: &mut [u64; PLEN], new_rate: &[u8; RATE_BYTES]) {
    for i in 0..17 {
        state[i] = u64::from_le_bytes(new_rate[i * 8..(i + 1) * 8].try_into().unwrap());
    }
}

/// Absorb `data` with Keccak multi-rate padding (0x01 after payload, 0x80 at last rate byte).
pub fn absorb_all(state: &mut [u64; PLEN], data: &[u8]) {
    let mut i = 0usize;
    while i + RATE_BYTES <= data.len() {
        xor_into_rate(state, &data[i..i + RATE_BYTES]);
        f1600(state);
        i += RATE_BYTES;
    }
    let rest = data.len() - i;
    let mut block = [0u8; RATE_BYTES];
    if rest > 0 {
        block[..rest].copy_from_slice(&data[i..]);
    }
    block[rest] ^= 0x01;
    block[RATE_BYTES - 1] ^= 0x80;
    xor_into_rate(state, &block);
    f1600(state);
}

/// Initialize duplex from key and nonce (single padded rate block).
pub fn init_key_nonce(state: &mut [u64; PLEN], key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES]) {
    *state = [0u64; PLEN];
    let mut block = [0u8; RATE_BYTES];
    block[..KEY_BYTES].copy_from_slice(key.as_slice());
    block[KEY_BYTES..KEY_BYTES + NONCE_BYTES].copy_from_slice(nonce.as_slice());
    block[KEY_BYTES + NONCE_BYTES] ^= 0x01;
    block[RATE_BYTES - 1] ^= 0x80;
    xor_into_rate(state, &block);
    f1600(state);
}

fn absorb_padding_only(state: &mut [u64; PLEN]) {
    let mut pad = [0u8; RATE_BYTES];
    pad[0] ^= 0x01;
    pad[RATE_BYTES - 1] ^= 0x80;
    xor_into_rate(state, &pad);
    f1600(state);
}

/// Duplex encryption step: writes `ct` (same length as `pt`).
pub fn duplex_encrypt_chunk(state: &mut [u64; PLEN], pt: &[u8], ct: &mut [u8]) {
    debug_assert_eq!(pt.len(), ct.len());
    debug_assert!(pt.len() <= RATE_BYTES);
    let mut r = [0u8; RATE_BYTES];
    rate_to_bytes(state, &mut r);

    if pt.len() == RATE_BYTES {
        let mut c_full = [0u8; RATE_BYTES];
        for i in 0..RATE_BYTES {
            c_full[i] = r[i] ^ pt[i];
        }
        ct.copy_from_slice(&c_full);
        set_rate_from_bytes(state, &c_full);
        f1600(state);
        absorb_padding_only(state);
        return;
    }

    let mut padded = [0u8; RATE_BYTES];
    padded[..pt.len()].copy_from_slice(pt);
    padded[pt.len()] ^= 0x01;
    padded[RATE_BYTES - 1] ^= 0x80;

    let mut c_full = [0u8; RATE_BYTES];
    for i in 0..RATE_BYTES {
        c_full[i] = r[i] ^ padded[i];
    }
    ct.copy_from_slice(&c_full[..pt.len()]);
    set_rate_from_bytes(state, &c_full);
    f1600(state);
}

/// Duplex decryption step: recovers plaintext and advances state like encrypt.
pub fn duplex_decrypt_chunk(state: &mut [u64; PLEN], ct: &[u8], pt: &mut [u8]) {
    debug_assert_eq!(ct.len(), pt.len());
    debug_assert!(ct.len() <= RATE_BYTES);
    let mut r = [0u8; RATE_BYTES];
    rate_to_bytes(state, &mut r);

    if ct.len() == RATE_BYTES {
        for i in 0..RATE_BYTES {
            pt[i] = r[i] ^ ct[i];
        }
        let mut c_full = [0u8; RATE_BYTES];
        c_full.copy_from_slice(ct);
        set_rate_from_bytes(state, &c_full);
        f1600(state);
        absorb_padding_only(state);
        return;
    }

    for i in 0..ct.len() {
        pt[i] = r[i] ^ ct[i];
    }
    let mut padded = [0u8; RATE_BYTES];
    padded[..ct.len()].copy_from_slice(pt);
    padded[ct.len()] ^= 0x01;
    padded[RATE_BYTES - 1] ^= 0x80;
    let mut c_full = [0u8; RATE_BYTES];
    for i in 0..RATE_BYTES {
        c_full[i] = r[i] ^ padded[i];
    }
    set_rate_from_bytes(state, &c_full);
    f1600(state);
}

/// Extract tag from the first 32 bytes of the rate (4 lanes).
pub fn tag_from_state(state: &[u64; PLEN]) -> [u8; TAG_BYTES] {
    let mut t = [0u8; TAG_BYTES];
    for i in 0..4 {
        t[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_le_bytes());
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // xor_into_rate / rate_to_bytes / set_rate_from_bytes
    // -----------------------------------------------------------------

    #[test]
    fn xor_into_rate_exact_multiple_of_8_has_no_remainder_lane_touched() {
        let mut state = [0u64; PLEN];
        state[3] = 0xDEAD_BEEF_0000_0000; // lane past the data we XOR in, must stay untouched
        let data: Vec<u8> = (0u8..24).collect(); // 3 full 8-byte lanes, no remainder
        xor_into_rate(&mut state, &data);
        assert_eq!(state[0], u64::from_le_bytes(data[0..8].try_into().unwrap()));
        assert_eq!(state[1], u64::from_le_bytes(data[8..16].try_into().unwrap()));
        assert_eq!(
            state[2],
            u64::from_le_bytes(data[16..24].try_into().unwrap())
        );
        assert_eq!(state[3], 0xDEAD_BEEF_0000_0000, "untouched lane changed");
    }

    #[test]
    fn xor_into_rate_remainder_is_xored_not_overwritten() {
        // data.len() == 10 -> one full 8-byte lane (index 0) plus a 2-byte remainder that must be
        // XORed into lane index 1 (zero-padded to 8 bytes), combining with whatever was already
        // there rather than clobbering it.
        let mut state = [0u64; PLEN];
        state[1] = 0x0102_0304_0506_0708;
        let mut data = vec![0u8; 10];
        data[8] = 0xFF;
        data[9] = 0x00;
        xor_into_rate(&mut state, &data);
        // lane 1 low 2 bytes (LE) XORed with 0x00FF, high 6 bytes untouched.
        let expected_lane1 = 0x0102_0304_0506_0708u64 ^ 0x0000_0000_0000_00FFu64;
        assert_eq!(state[1], expected_lane1);
        assert_eq!(state[0], 0, "unrelated lane must stay zero");
    }

    #[test]
    fn rate_roundtrip_preserves_bytes_and_leaves_capacity_alone() {
        let mut state = [0u64; PLEN];
        for (i, lane) in state.iter_mut().enumerate() {
            *lane = (i as u64 + 1).wrapping_mul(0x1111_1111_1111_1111);
        }
        let capacity_before = state[17..PLEN].to_vec();

        let mut bytes = [0u8; RATE_BYTES];
        rate_to_bytes(&state, &mut bytes);

        let mut state2 = [0u64; PLEN];
        state2[17..PLEN].copy_from_slice(&capacity_before);
        set_rate_from_bytes(&mut state2, &bytes);

        assert_eq!(state2[..17], state[..17], "rate round-trip must be exact");
        assert_eq!(
            state2[17..PLEN],
            capacity_before[..],
            "set_rate_from_bytes must not touch capacity lanes"
        );
    }

    // -----------------------------------------------------------------
    // absorb_all
    // -----------------------------------------------------------------

    #[test]
    fn absorb_all_empty_matches_manual_single_padded_block() {
        let mut got = [0u64; PLEN];
        absorb_all(&mut got, &[]);

        // Manual reference: one all-padding rate block (0x01 at offset 0, 0x80 at the last byte)
        // then one permutation — mirrors what the implementation does for `rest == 0`.
        let mut want = [0u64; PLEN];
        let mut block = [0u8; RATE_BYTES];
        block[0] ^= 0x01;
        block[RATE_BYTES - 1] ^= 0x80;
        xor_into_rate(&mut want, &block);
        f1600(&mut want);

        assert_eq!(got, want);
    }

    #[test]
    fn absorb_all_exact_rate_boundary_adds_a_second_padding_only_block() {
        // data.len() == RATE_BYTES: the main loop consumes exactly one full rate block (XOR + one
        // permutation), then because `rest == 0` a SECOND, purely-padding block still gets
        // absorbed (own XOR + own permutation). If that second block were skipped, this would
        // equal the "one loop iteration only" reference instead.
        let data = [0x5Au8; RATE_BYTES];

        let mut got = [0u64; PLEN];
        absorb_all(&mut got, &data);

        let mut loop_only = [0u64; PLEN];
        xor_into_rate(&mut loop_only, &data);
        f1600(&mut loop_only);
        assert_ne!(
            got, loop_only,
            "absorb_all must apply the trailing padding-only block even on an exact-rate input"
        );

        let mut want = loop_only;
        let mut pad = [0u8; RATE_BYTES];
        pad[0] ^= 0x01;
        pad[RATE_BYTES - 1] ^= 0x80;
        xor_into_rate(&mut want, &pad);
        f1600(&mut want);
        assert_eq!(got, want);
    }

    // -----------------------------------------------------------------
    // init_key_nonce / duplex_encrypt_chunk / duplex_decrypt_chunk / tag_from_state
    // -----------------------------------------------------------------

    fn fresh_state() -> [u64; PLEN] {
        let key = [0x42u8; KEY_BYTES];
        let nonce = [0x24u8; NONCE_BYTES];
        let mut state = [0u64; PLEN];
        init_key_nonce(&mut state, &key, &nonce);
        state
    }

    #[test]
    fn init_key_nonce_is_deterministic_and_key_dependent() {
        let a = fresh_state();
        let b = fresh_state();
        assert_eq!(a, b, "same key/nonce must give the same initial state");

        let mut c = [0u64; PLEN];
        init_key_nonce(&mut c, &[0x43u8; KEY_BYTES], &[0x24u8; NONCE_BYTES]);
        assert_ne!(a, c, "different key must give a different initial state");
    }

    #[test]
    fn duplex_chunk_roundtrip_full_rate() {
        let mut enc_state = fresh_state();
        let mut dec_state = fresh_state();
        let pt = [0xABu8; RATE_BYTES];
        let mut ct = [0u8; RATE_BYTES];
        duplex_encrypt_chunk(&mut enc_state, &pt, &mut ct);
        assert_ne!(ct.as_slice(), pt.as_slice(), "ciphertext must differ from plaintext");

        let mut recovered = [0u8; RATE_BYTES];
        duplex_decrypt_chunk(&mut dec_state, &ct, &mut recovered);
        assert_eq!(recovered, pt);
        assert_eq!(
            enc_state, dec_state,
            "encrypt/decrypt of matching data must leave the duplex states in sync"
        );
    }

    #[test]
    fn duplex_chunk_roundtrip_partial() {
        for len in [1usize, 17, RATE_BYTES - 1] {
            let mut enc_state = fresh_state();
            let mut dec_state = fresh_state();
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut ct = vec![0u8; len];
            duplex_encrypt_chunk(&mut enc_state, &pt, &mut ct);

            let mut recovered = vec![0u8; len];
            duplex_decrypt_chunk(&mut dec_state, &ct, &mut recovered);
            assert_eq!(recovered, pt, "len={len}");
            assert_eq!(enc_state, dec_state, "len={len}");
        }
    }

    #[test]
    fn duplex_chunk_roundtrip_empty_does_not_panic() {
        let mut enc_state = fresh_state();
        let mut dec_state = fresh_state();
        let pt: [u8; 0] = [];
        let mut ct: [u8; 0] = [];
        duplex_encrypt_chunk(&mut enc_state, &pt, &mut ct);
        let mut recovered: [u8; 0] = [];
        duplex_decrypt_chunk(&mut dec_state, &ct, &mut recovered);
        assert_eq!(enc_state, dec_state);
    }

    #[test]
    fn tag_from_state_reads_first_four_lanes_little_endian() {
        let mut state = [0u64; PLEN];
        state[0] = 0x0102_0304_0506_0708;
        state[1] = 0x1112_1314_1516_1718;
        state[2] = 0x2122_2324_2526_2728;
        state[3] = 0x3132_3334_3536_3738;
        state[4] = 0x4142_4344_4546_4748; // must NOT be included in the tag
        let tag = tag_from_state(&state);
        let mut expected = [0u8; TAG_BYTES];
        expected[0..8].copy_from_slice(&state[0].to_le_bytes());
        expected[8..16].copy_from_slice(&state[1].to_le_bytes());
        expected[16..24].copy_from_slice(&state[2].to_le_bytes());
        expected[24..32].copy_from_slice(&state[3].to_le_bytes());
        assert_eq!(tag, expected);
    }
}
