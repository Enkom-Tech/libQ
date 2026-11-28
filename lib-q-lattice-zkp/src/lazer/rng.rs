//! LaZer's pseudorandom generator, `RNG == RNG_AES256CTR` (LaZer `config.h` default).
//!
//! Reference: LaZer `src/rng.c` (`_rng_init`, `_rng_urandom`) and `src/aes256ctr.c`
//! (`_aes256ctr_init`, `_aes256ctr_stream`, `incbe`) at commit
//! `10eafeca4cd53ff4fc54193dce904dbd0026fefd`.
//!
//! * key   = the 32-byte seed;
//! * nonce = `le64(dom) || 0^8` (LaZer: `uint64_t nonce[2] = { htole64(dom), 0 }`);
//! * the 16-byte counter block is incremented as one 128-bit **big-endian** integer after
//!   every block (`incbe`);
//! * output is one continuous keystream: a short read keeps the unused tail of the block for
//!   the next read, exactly as `_aes256ctr_stream` keeps `cache`.
//!
//! This is a public-randomness expander for LaZer interoperability, not a DRBG: it has no
//! reseeding, no backtracking resistance and no prediction resistance.

use aes::Aes256;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use zeroize::Zeroize;

/// AES-256-CTR keystream with LaZer's nonce layout and counter increment.
pub struct LazerRng {
    cipher: Aes256,
    counter: [u8; 16],
    cache: [u8; 16],
    /// Unread bytes at the end of `cache`.
    cached: usize,
}

impl LazerRng {
    /// `rng_init(state, seed, dom)`.
    pub fn new(seed: &[u8; 32], dom: u64) -> Self {
        let mut counter = [0u8; 16];
        counter[..8].copy_from_slice(&dom.to_le_bytes());
        Self {
            cipher: Aes256::new(seed.into()),
            counter,
            cache: [0u8; 16],
            cached: 0,
        }
    }

    fn next_block(&mut self) -> [u8; 16] {
        let mut block = aes::Block::from(self.counter);
        self.cipher.encrypt_block(&mut block);
        increment_be(&mut self.counter);
        block.into()
    }

    /// `rng_urandom(state, out, outlen)`.
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut out = out;
        let take = core::cmp::min(self.cached, out.len());
        if take > 0 {
            let start = 16 - self.cached;
            out[..take].copy_from_slice(&self.cache[start..start + take]);
            self.cached -= take;
            out = &mut out[take..];
        }
        while out.len() >= 16 {
            let block = self.next_block();
            out[..16].copy_from_slice(&block);
            out = &mut out[16..];
        }
        if !out.is_empty() {
            self.cache = self.next_block();
            let n = out.len();
            out.copy_from_slice(&self.cache[..n]);
            self.cached = 16 - n;
        }
    }
}

impl Drop for LazerRng {
    fn drop(&mut self) {
        self.counter.zeroize();
        self.cache.zeroize();
    }
}

/// LaZer `incbe`: add one to the 16-byte block read as a big-endian integer.
fn increment_be(n: &mut [u8; 16]) {
    for byte in n.iter_mut().rev() {
        let (v, carry) = byte.overflowing_add(1);
        *byte = v;
        if !carry {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increment_carries_across_bytes() {
        let mut n = [0u8; 16];
        n[14] = 0x01;
        n[15] = 0xFF;
        increment_be(&mut n);
        assert_eq!((n[14], n[15]), (0x02, 0x00));
        let mut all = [0xFFu8; 16];
        increment_be(&mut all);
        assert_eq!(all, [0u8; 16]);
    }

    #[test]
    fn split_reads_equal_one_read() {
        let seed = [7u8; 32];
        let mut whole = [0u8; 100];
        LazerRng::new(&seed, 5).fill(&mut whole);
        let mut parts = [0u8; 100];
        let mut rng = LazerRng::new(&seed, 5);
        // 3 + 13 + 16 + 1 + 40 + 27 = 100: crosses block boundaries in both directions.
        let mut pos = 0;
        for chunk in [3usize, 13, 16, 1, 40, 27] {
            rng.fill(&mut parts[pos..pos + chunk]);
            pos += chunk;
        }
        assert_eq!(pos, 100);
        assert_eq!(whole, parts);
    }
}
