//! Saturnin tweakable block cipher (TBC)
//!
//! The "An Update on Saturnin" note defines the tweakable block cipher used by
//! [`Saturnin-QCB`](crate::qcb) as
//!
//! ```text
//! TBC_d(K, T)(M) = Saturnin16^d_{K ⊕ T}(M)
//! ```
//!
//! where:
//!
//! - `Saturnin16` is Saturnin run with **16 super-rounds** (the related-key-secure variant,
//!   the same number of super-rounds used by `Saturnin-Hash`),
//! - `d` is a **4-bit domain separator** (`0..=15`),
//! - `K` is the 256-bit (32-byte) key,
//! - `T` is a **256-bit (32-byte) tweak**, XORed into the key, and
//! - `M` is a 256-bit (32-byte) block.
//!
//! The tweak space is therefore 260 bits (256-bit `T` plus the 4-bit domain `d`). Because the
//! key schedule of Saturnin is linear, "rekeying" with a new tweak only changes the value XORed
//! into the key, exactly as the update note describes.
//!
//! This primitive is unambiguously specified by the update note and is the only part of
//! Saturnin-QCB that does not require interpreting the (separate) QCB mode paper. It is exposed
//! publicly so it can be reused and independently tested.

use lib_q_core::Result;
use zeroize::Zeroize;

use crate::core::SaturninCore;

/// Number of super-rounds for the QCB tweakable block cipher (`Saturnin16`).
pub const TBC_SUPER_ROUNDS: usize = 16;

/// Block / key / tweak size in bytes (256 bits).
pub const TBC_BLOCK_BYTES: usize = 32;

/// A Saturnin tweakable block cipher instance for a fixed 4-bit domain separator.
///
/// One instance pre-builds the round constants for its domain, so encrypting or decrypting many
/// blocks under different tweaks (the common case in QCB) does not reallocate.
#[derive(Clone)]
pub struct SaturninTbc {
    core: SaturninCore,
    domain: u8,
}

impl SaturninTbc {
    /// Create a TBC instance for the given 4-bit domain separator.
    ///
    /// # Errors
    /// Returns [`Error::InvalidAlgorithm`] if `domain > 15`.
    pub fn new(domain: u8) -> Result<Self> {
        let core = SaturninCore::new(TBC_SUPER_ROUNDS, domain)?;
        Ok(Self { core, domain })
    }

    /// The 4-bit domain separator this instance was built for.
    pub fn domain(&self) -> u8 {
        self.domain
    }

    /// Encrypt one 256-bit block in place: `block <- Saturnin16^d_{key ⊕ tweak}(block)`.
    pub fn encrypt_block(
        &self,
        key: &[u8; TBC_BLOCK_BYTES],
        tweak: &[u8; TBC_BLOCK_BYTES],
        block: &mut [u8; TBC_BLOCK_BYTES],
    ) -> Result<()> {
        let mut keyed = combine(key, tweak);
        let res = self.core.encrypt_block_32(&keyed, block);
        keyed.zeroize();
        res
    }

    /// Decrypt one 256-bit block in place: `block <- (Saturnin16^d_{key ⊕ tweak})^{-1}(block)`.
    pub fn decrypt_block(
        &self,
        key: &[u8; TBC_BLOCK_BYTES],
        tweak: &[u8; TBC_BLOCK_BYTES],
        block: &mut [u8; TBC_BLOCK_BYTES],
    ) -> Result<()> {
        let mut keyed = combine(key, tweak);
        let res = self.core.decrypt_block_32(&keyed, block);
        keyed.zeroize();
        res
    }
}

/// Compute the per-tweak key `K ⊕ T` (the linear rekeying of Saturnin's key schedule).
#[inline]
fn combine(key: &[u8; TBC_BLOCK_BYTES], tweak: &[u8; TBC_BLOCK_BYTES]) -> [u8; TBC_BLOCK_BYTES] {
    let mut out = [0u8; TBC_BLOCK_BYTES];
    for i in 0..TBC_BLOCK_BYTES {
        out[i] = key[i] ^ tweak[i];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tbc_round_trip() -> Result<()> {
        let tbc = SaturninTbc::new(9)?;
        let key = [0x11u8; 32];
        let tweak = {
            let mut t = [0u8; 32];
            t[0] = 0xAB;
            t[31] = 0x07;
            t
        };
        let original = [0x42u8; 32];
        let mut block = original;
        tbc.encrypt_block(&key, &tweak, &mut block)?;
        assert_ne!(block, original, "encryption must change the block");
        tbc.decrypt_block(&key, &tweak, &mut block)?;
        assert_eq!(block, original, "decrypt must invert encrypt");
        Ok(())
    }

    #[test]
    fn tweak_xor_equals_keyed_saturnin() -> Result<()> {
        // The TBC is by definition Saturnin16 keyed with K ⊕ T; verify against a direct core call.
        let tbc = SaturninTbc::new(9)?;
        let key = [0x5Au8; 32];
        let tweak = [0x3Cu8; 32];
        let mut via_tbc = [0u8; 32];
        tbc.encrypt_block(&key, &tweak, &mut via_tbc)?;

        let core = SaturninCore::new(TBC_SUPER_ROUNDS, 9)?;
        let combined = combine(&key, &tweak);
        let mut via_core = [0u8; 32];
        core.encrypt_block_32(&combined, &mut via_core)?;

        assert_eq!(via_tbc, via_core);
        Ok(())
    }

    #[test]
    fn distinct_domains_differ() -> Result<()> {
        let key = [0u8; 32];
        let tweak = [0u8; 32];
        let mut b9 = [0u8; 32];
        let mut b10 = [0u8; 32];
        SaturninTbc::new(9)?.encrypt_block(&key, &tweak, &mut b9)?;
        SaturninTbc::new(10)?.encrypt_block(&key, &tweak, &mut b10)?;
        assert_ne!(b9, b10, "domain separation must change the permutation");
        Ok(())
    }

    #[test]
    fn distinct_tweaks_differ() -> Result<()> {
        let tbc = SaturninTbc::new(9)?;
        let key = [0u8; 32];
        let mut t0 = [0u8; 32];
        let mut t1 = [0u8; 32];
        let mut tw1 = [0u8; 32];
        tw1[31] = 1;
        tbc.encrypt_block(&key, &[0u8; 32], &mut t0)?;
        tbc.encrypt_block(&key, &tw1, &mut t1)?;
        assert_ne!(t0, t1, "different tweaks must give different outputs");
        Ok(())
    }

    #[test]
    fn invalid_domain_rejected() {
        assert!(SaturninTbc::new(16).is_err());
    }

    #[test]
    fn domain_getter_reports_configured_domain() -> Result<()> {
        assert_eq!(SaturninTbc::new(9)?.domain(), 9);
        assert_eq!(SaturninTbc::new(11)?.domain(), 11);
        Ok(())
    }
}
