//! Seed expansion primitives: SHAKE256 (secret-key / message hashing) and
//! AES-128-CTR (public matrix expansion, zero IV, big-endian block counter —
//! matching `aes128ctr.c` in the MAYO reference implementation).

use lib_q_sha3::Shake256;
use lib_q_sha3::digest::{
    ExtendableOutput,
    Update,
    XofReader,
};

/// SHAKE256 over the concatenation of `parts`, filling `out`.
pub fn shake256(parts: &[&[u8]], out: &mut [u8]) {
    let mut h = Shake256::default();
    for p in parts {
        h.update(p);
    }
    h.finalize_xof().read(out);
}

/// AES-128-CTR keystream with zero IV/nonce: `out = E_k(0), E_k(1), ...`
/// with the 128-bit counter incremented big-endian.
#[cfg_attr(not(test), allow(dead_code))]
pub fn aes128_ctr(key: &[u8; 16], out: &mut [u8]) {
    use aes::cipher::{
        BlockCipherEncrypt,
        KeyInit,
    };
    use aes::{
        Aes128,
        Block,
    };

    let cipher = Aes128::new_from_slice(key).expect("16-byte key");
    let mut ctr: u128 = 0;
    for chunk in out.chunks_mut(16) {
        let mut block = Block::from(ctr.to_be_bytes());
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block[..chunk.len()]);
        ctr = ctr.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_ctr_fips197_vector() {
        // FIPS-197 appendix C.1 style check: E_k(0) with the well-known
        // key 000102...0f equals the single-block ECB encryption of the
        // all-zero block; cross-checked against the `aes` crate itself.
        use aes::cipher::{
            BlockCipherEncrypt,
            KeyInit,
        };
        use aes::{
            Aes128,
            Block,
        };

        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let mut ks = [0u8; 40];
        aes128_ctr(&key, &mut ks);

        let cipher = Aes128::new_from_slice(&key).unwrap();
        let mut b0 = Block::from(0u128.to_be_bytes());
        let mut b1 = Block::from(1u128.to_be_bytes());
        let mut b2 = Block::from(2u128.to_be_bytes());
        cipher.encrypt_block(&mut b0);
        cipher.encrypt_block(&mut b1);
        cipher.encrypt_block(&mut b2);
        assert_eq!(&ks[..16], b0.as_slice());
        assert_eq!(&ks[16..32], b1.as_slice());
        assert_eq!(&ks[32..40], &b2.as_slice()[..8]);
    }

    #[test]
    fn shake256_multi_part_equals_one_shot() {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        shake256(&[b"hello ", b"world"], &mut a);
        shake256(&[b"hello world"], &mut b);
        assert_eq!(a, b);
    }
}
