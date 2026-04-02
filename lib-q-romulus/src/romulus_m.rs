//! Romulus-M: nonce-misuse-resistant AEAD (Romulus v1.3).

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
    ad2msg_encryption,
    g8a,
    lfsr_gf56,
    msg_decryption_m_inplace,
    msg_encryption_m_inplace,
    nonce_encryption,
    reset_lfsr_gf56,
    rho,
    romulus_m_compute_w,
};

/// Romulus-M AEAD with 128-bit key, 128-bit nonce, 128-bit tag.
#[derive(Clone)]
pub struct RomulusM {
    key: Key<Self>,
}

impl Drop for RomulusM {
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}

impl KeySizeUser for RomulusM {
    type KeySize = U16;
}

impl KeyInit for RomulusM {
    fn new(key: &Key<Self>) -> Self {
        Self { key: *key }
    }
}

impl AeadCore for RomulusM {
    type NonceSize = U16;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl AeadInPlace for RomulusM {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>, Error> {
        let k = self.key.as_slice().try_into().map_err(|_| Error)?;
        let n = nonce.as_slice().try_into().map_err(|_| Error)?;
        let tag = romulus_m_encrypt(k, n, associated_data, buffer)?;
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
        romulus_m_decrypt(k, n, associated_data, buffer, &tg)
    }
}

/// Encrypt plaintext in `buf` in place to ciphertext; return tag.
pub(crate) fn romulus_m_encrypt(
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
    let mlen_u = buf.len() as u64;
    let xlen_init = mlen_u;
    let mut ad_off = 0usize;
    let mut adlen = ad.len() as u64;

    let w = romulus_m_compute_w(adlen, xlen_init, n_ad, t_ad);

    if adlen == 0 {
        lfsr_gf56(&mut cnt);
    } else {
        while adlen > 0 {
            adlen = ad_encryption(
                ad,
                &mut ad_off,
                &mut s,
                key,
                adlen,
                &mut cnt,
                40,
                n_ad,
                t_ad,
            );
        }
    }

    let mut mac_off = 0usize;
    let mut xlen = mlen_u;

    if w & 8 == 0 {
        xlen = ad2msg_encryption(buf, &mut mac_off, &mut cnt, &mut s, key, t_ad, 44, xlen);
    } else if mlen_u == 0 {
        lfsr_gf56(&mut cnt);
    }

    while xlen > 0 {
        xlen = ad_encryption(
            buf,
            &mut mac_off,
            &mut s,
            key,
            xlen,
            &mut cnt,
            44,
            n_ad,
            t_ad,
        );
    }

    nonce_encryption(nonce, &mut cnt, &mut s, key, t_ad, w);

    let mut tag = [0u8; 16];
    g8a(&s, &mut tag);

    reset_lfsr_gf56(&mut cnt);
    s.copy_from_slice(&tag);

    let msg_n = MSG_BLK;
    let mut enc_off = 0usize;

    if mlen_u > 0 {
        nonce_encryption(nonce, &mut cnt, &mut s, key, t_ad, 36);
        let mut rem = mlen_u;
        while rem > msg_n as u64 {
            rem = msg_encryption_m_inplace(
                buf,
                &mut enc_off,
                nonce,
                &mut cnt,
                &mut s,
                key,
                msg_n,
                t_ad,
                36,
                rem,
            );
        }
        let r = rem as usize;
        let mut last = [0u8; 16];
        last[..r].copy_from_slice(&buf[enc_off..enc_off + r]);
        let mut ctmp = [0u8; 16];
        rho(&last[..r], &mut ctmp, &mut s, r, 16);
        buf[enc_off..enc_off + r].copy_from_slice(&ctmp[..r]);
    }

    Ok(tag)
}

/// Decrypt ciphertext in `buffer` in place; verify `tag`.
pub(crate) fn romulus_m_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 16],
    ad: &[u8],
    ct: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), Error> {
    let body_len = ct.len();
    let xlen = body_len as u64;

    let mut s = [0u8; 16];
    let mut cnt = [0u8; 7];
    reset_lfsr_gf56(&mut cnt);
    let n_ad = AD_BLK_ODD;
    let t_ad = AD_BLK_EVN;

    s.copy_from_slice(tag);

    let msg_n = MSG_BLK;
    let mut clen = body_len as u64;
    let mut off = 0usize;

    if clen > 0 {
        nonce_encryption(nonce, &mut cnt, &mut s, key, t_ad, 36);
        while clen > msg_n as u64 {
            clen = msg_decryption_m_inplace(
                ct, &mut off, nonce, &mut cnt, &mut s, key, msg_n, t_ad, 36, clen,
            );
        }
        let r = clen as usize;
        let mut tmp = [0u8; 16];
        tmp[..r].copy_from_slice(&ct[off..off + r]);
        let mut ptmp = [0u8; 16];
        crate::backend::irho(&mut ptmp, &tmp[..r], &mut s, r, 16);
        ct[off..off + r].copy_from_slice(&ptmp[..r]);
    }

    s.fill(0);
    reset_lfsr_gf56(&mut cnt);

    let mut ad_off = 0usize;
    let mut adlen = ad.len() as u64;
    let w = romulus_m_compute_w(adlen, xlen, n_ad, t_ad);

    if adlen == 0 {
        lfsr_gf56(&mut cnt);
    } else {
        while adlen > 0 {
            adlen = ad_encryption(
                ad,
                &mut ad_off,
                &mut s,
                key,
                adlen,
                &mut cnt,
                40,
                n_ad,
                t_ad,
            );
        }
    }

    let mut mac_off = 0usize;
    let mut xrem = xlen;

    if w & 8 == 0 {
        xrem = ad2msg_encryption(ct, &mut mac_off, &mut cnt, &mut s, key, t_ad, 44, xrem);
    } else if body_len == 0 {
        lfsr_gf56(&mut cnt);
    }

    while xrem > 0 {
        xrem = ad_encryption(
            ct,
            &mut mac_off,
            &mut s,
            key,
            xrem,
            &mut cnt,
            44,
            n_ad,
            t_ad,
        );
    }

    nonce_encryption(nonce, &mut cnt, &mut s, key, t_ad, w);

    let mut calc = [0u8; 16];
    g8a(&s, &mut calc);
    let ok = bool::from(calc.ct_eq(tag));
    if !ok {
        ct.zeroize();
        return Err(Error);
    }
    Ok(())
}
