//! Romulus-N: nonce-based AEAD (Romulus v1.3).

#![deny(unsafe_code)]

use aead::consts::{
    U0,
    U16,
};
use aead::{
    AeadCore,
    AeadInPlace,
    Error,
    Key,
    KeyInit,
    KeySizeUser,
    Nonce,
    Tag,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::backend::{
    AD_BLK_EVN,
    AD_BLK_ODD,
    MSG_BLK,
    ad_encryption,
    g8a,
    lfsr_gf56,
    msg_encryption_n_inplace,
    nonce_encryption,
    reset_lfsr_gf56,
};

/// Romulus-N AEAD with 128-bit key, 128-bit nonce, 128-bit tag.
#[derive(Clone)]
pub struct RomulusN {
    key: Key<Self>,
}

impl Drop for RomulusN {
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}

impl KeySizeUser for RomulusN {
    type KeySize = U16;
}

impl KeyInit for RomulusN {
    fn new(key: &Key<Self>) -> Self {
        Self { key: *key }
    }
}

impl AeadCore for RomulusN {
    type NonceSize = U16;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl AeadInPlace for RomulusN {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>, Error> {
        let k = self.key.as_slice().try_into().map_err(|_| Error)?;
        let n = nonce.as_slice().try_into().map_err(|_| Error)?;
        let tag = romulus_n_encrypt(k, n, associated_data, buffer)?;
        Ok(Tag::<Self>::from(tag))
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<(), Error> {
        let k = self.key.as_slice().try_into().map_err(|_| Error)?;
        let n = nonce.as_slice().try_into().map_err(|_| Error)?;
        let tg: [u8; 16] = tag.as_slice().try_into().map_err(|_| Error)?;
        romulus_n_decrypt(k, n, associated_data, buffer, &tg)
    }
}

/// Encrypt plaintext in `buf` in place; ciphertext is written to `buf`. Returns authentication tag.
pub(crate) fn romulus_n_encrypt(
    key: &[u8; 16],
    nonce: &[u8; 16],
    ad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; 16], Error> {
    let mut s = [0u8; 16];
    let mut cnt = [0u8; 7];
    reset_lfsr_gf56(&mut cnt);
    let n_ad = AD_BLK_ODD;
    let t_ad = AD_BLK_EVN;
    let mut a_off = 0usize;
    let mut adlen = ad.len() as u64;

    if adlen == 0 {
        lfsr_gf56(&mut cnt);
        nonce_encryption(nonce, &mut cnt, &mut s, key, t_ad, 0x1A);
    } else {
        while adlen > 0 {
            if adlen < n_ad as u64 {
                adlen = ad_encryption(
                    ad, &mut a_off, &mut s, key, adlen, &mut cnt, 0x08, n_ad, t_ad,
                );
                nonce_encryption(nonce, &mut cnt, &mut s, key, t_ad, 0x1A);
            } else if adlen == n_ad as u64 {
                adlen = ad_encryption(
                    ad, &mut a_off, &mut s, key, adlen, &mut cnt, 0x08, n_ad, t_ad,
                );
                nonce_encryption(nonce, &mut cnt, &mut s, key, t_ad, 0x18);
            } else if adlen < (n_ad + t_ad) as u64 {
                adlen = ad_encryption(
                    ad, &mut a_off, &mut s, key, adlen, &mut cnt, 0x08, n_ad, t_ad,
                );
                nonce_encryption(nonce, &mut cnt, &mut s, key, t_ad, 0x1A);
            } else if adlen == (n_ad + t_ad) as u64 {
                adlen = ad_encryption(
                    ad, &mut a_off, &mut s, key, adlen, &mut cnt, 0x08, n_ad, t_ad,
                );
                nonce_encryption(nonce, &mut cnt, &mut s, key, t_ad, 0x18);
            } else {
                adlen = ad_encryption(
                    ad, &mut a_off, &mut s, key, adlen, &mut cnt, 0x08, n_ad, t_ad,
                );
            }
        }
    }

    reset_lfsr_gf56(&mut cnt);
    let msg_n = MSG_BLK;
    let mut mlen = buf.len() as u64;
    let mut off = 0usize;

    if mlen == 0 {
        lfsr_gf56(&mut cnt);
        nonce_encryption(nonce, &mut cnt, &mut s, key, t_ad, 0x15);
    } else {
        while mlen > 0 {
            if mlen < msg_n as u64 {
                mlen = msg_encryption_n_inplace(
                    buf, &mut off, nonce, &mut cnt, &mut s, key, msg_n, t_ad, 0x15, mlen, false,
                );
            } else if mlen == msg_n as u64 {
                mlen = msg_encryption_n_inplace(
                    buf, &mut off, nonce, &mut cnt, &mut s, key, msg_n, t_ad, 0x14, mlen, false,
                );
            } else {
                mlen = msg_encryption_n_inplace(
                    buf, &mut off, nonce, &mut cnt, &mut s, key, msg_n, t_ad, 0x04, mlen, false,
                );
            }
        }
    }

    let mut tag = [0u8; 16];
    g8a(&s, &mut tag);
    Ok(tag)
}

/// Decrypt ciphertext in `buffer` to plaintext in place; verify `tag`.
///
/// On failure, `buffer` is zeroized. For Layer B semantic outcomes without double decryption,
/// use [`romulus_n_decrypt_core`] and map the `bool` yourself.
pub(crate) fn romulus_n_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 16],
    ad: &[u8],
    ct: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), Error> {
    let ok = romulus_n_decrypt_core(key, nonce, ad, ct, tag);
    if ok {
        Ok(())
    } else {
        ct.zeroize();
        Err(Error)
    }
}

/// In-place Romulus-N decrypt; returns whether `tag` matches after the decrypt schedule.
pub(crate) fn romulus_n_decrypt_core(
    key: &[u8; 16],
    nonce: &[u8; 16],
    ad: &[u8],
    ct: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    let mut s = [0u8; 16];
    let mut cnt = [0u8; 7];
    reset_lfsr_gf56(&mut cnt);
    let n_ad = AD_BLK_ODD;
    let t_ad = AD_BLK_EVN;
    let mut a_off = 0usize;
    let mut adlen = ad.len() as u64;

    if adlen == 0 {
        lfsr_gf56(&mut cnt);
        nonce_encryption(nonce, &mut cnt, &mut s, key, t_ad, 0x1A);
    } else {
        while adlen > 0 {
            if adlen < n_ad as u64 {
                adlen = ad_encryption(
                    ad, &mut a_off, &mut s, key, adlen, &mut cnt, 0x08, n_ad, t_ad,
                );
                nonce_encryption(nonce, &mut cnt, &mut s, key, t_ad, 0x1A);
            } else if adlen == n_ad as u64 {
                adlen = ad_encryption(
                    ad, &mut a_off, &mut s, key, adlen, &mut cnt, 0x08, n_ad, t_ad,
                );
                nonce_encryption(nonce, &mut cnt, &mut s, key, t_ad, 0x18);
            } else if adlen < (n_ad + t_ad) as u64 {
                adlen = ad_encryption(
                    ad, &mut a_off, &mut s, key, adlen, &mut cnt, 0x08, n_ad, t_ad,
                );
                nonce_encryption(nonce, &mut cnt, &mut s, key, t_ad, 0x1A);
            } else if adlen == (n_ad + t_ad) as u64 {
                adlen = ad_encryption(
                    ad, &mut a_off, &mut s, key, adlen, &mut cnt, 0x08, n_ad, t_ad,
                );
                nonce_encryption(nonce, &mut cnt, &mut s, key, t_ad, 0x18);
            } else {
                adlen = ad_encryption(
                    ad, &mut a_off, &mut s, key, adlen, &mut cnt, 0x08, n_ad, t_ad,
                );
            }
        }
    }

    reset_lfsr_gf56(&mut cnt);
    let msg_n = MSG_BLK;
    let mut mlen = ct.len() as u64;
    let mut off = 0usize;

    if mlen == 0 {
        lfsr_gf56(&mut cnt);
        nonce_encryption(nonce, &mut cnt, &mut s, key, t_ad, 0x15);
    } else {
        while mlen > 0 {
            if mlen < msg_n as u64 {
                mlen = msg_encryption_n_inplace(
                    ct, &mut off, nonce, &mut cnt, &mut s, key, msg_n, t_ad, 0x15, mlen, true,
                );
            } else if mlen == msg_n as u64 {
                mlen = msg_encryption_n_inplace(
                    ct, &mut off, nonce, &mut cnt, &mut s, key, msg_n, t_ad, 0x14, mlen, true,
                );
            } else {
                mlen = msg_encryption_n_inplace(
                    ct, &mut off, nonce, &mut cnt, &mut s, key, msg_n, t_ad, 0x04, mlen, true,
                );
            }
        }
    }

    let mut calc = [0u8; 16];
    g8a(&s, &mut calc);
    bool::from(calc.ct_eq(tag))
}
