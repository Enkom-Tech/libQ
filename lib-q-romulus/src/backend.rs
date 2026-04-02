//! Shared Romulus primitives: padding, rho, GF(2^56) counter, tweakey, TBC wrapper.

#![deny(unsafe_code)]

use crate::skinny::skinny_128_384_plus_enc;

pub(crate) const AD_BLK_ODD: usize = 16;
pub(crate) const AD_BLK_EVN: usize = 16;
pub(crate) const MSG_BLK: usize = 16;

#[inline]
pub(crate) fn pad(m: &[u8], mp: &mut [u8], l: usize, len8: usize) {
    for i in 0..l {
        if i < len8 {
            mp[i] = m[i];
        } else if i == l - 1 {
            mp[i] = (len8 & 0x0F) as u8;
        } else {
            mp[i] = 0x00;
        }
    }
}

#[inline]
pub(crate) fn g8a(s: &[u8; 16], c: &mut [u8; 16]) {
    for i in 0..16 {
        c[i] = (s[i] >> 1) ^ (s[i] & 0x80) ^ ((s[i] & 0x01) << 7);
    }
}

#[inline]
pub(crate) fn rho_ad(m: &[u8], s: &mut [u8; 16], len8: usize, ver: usize) {
    let mut mp = [0u8; 16];
    pad(m, &mut mp, ver, len8);
    for i in 0..ver {
        s[i] ^= mp[i];
    }
}

#[inline]
pub(crate) fn rho(m: &[u8], c: &mut [u8], s: &mut [u8; 16], len8: usize, ver: usize) {
    let mut mp = [0u8; 16];
    pad(m, &mut mp, ver, len8);
    let mut gs = [0u8; 16];
    g8a(s, &mut gs);
    for i in 0..ver {
        s[i] ^= mp[i];
        if i < len8 {
            c[i] = gs[i] ^ mp[i];
        } else {
            c[i] = 0;
        }
    }
}

#[inline]
pub(crate) fn irho(m: &mut [u8], c: &[u8], s: &mut [u8; 16], len8: usize, ver: usize) {
    let mut cp = [0u8; 16];
    pad(c, &mut cp, ver, len8);
    let mut ks = [0u8; 16];
    g8a(s, &mut ks);
    for i in 0..ver {
        if i < len8 {
            s[i] ^= cp[i] ^ ks[i];
        } else {
            s[i] ^= cp[i];
        }
        if i < len8 {
            m[i] = ks[i] ^ cp[i];
        } else {
            m[i] = 0;
        }
    }
}

#[inline]
pub(crate) fn reset_lfsr_gf56(cnt: &mut [u8; 7]) {
    cnt[0] = 0x01;
    cnt[1..7].fill(0);
}

#[inline]
pub(crate) fn lfsr_gf56(cnt: &mut [u8; 7]) {
    let fb0 = cnt[6] >> 7;
    cnt[6] = (cnt[6] << 1) | (cnt[5] >> 7);
    cnt[5] = (cnt[5] << 1) | (cnt[4] >> 7);
    cnt[4] = (cnt[4] << 1) | (cnt[3] >> 7);
    cnt[3] = (cnt[3] << 1) | (cnt[2] >> 7);
    cnt[2] = (cnt[2] << 1) | (cnt[1] >> 7);
    cnt[1] = (cnt[1] << 1) | (cnt[0] >> 7);
    if fb0 == 1 {
        cnt[0] = (cnt[0] << 1) ^ 0x95;
    } else {
        cnt[0] <<= 1;
    }
}

#[inline]
pub(crate) fn compose_tweakey(
    kt: &mut [u8; 48],
    k: &[u8; 16],
    t: &[u8],
    cnt: &[u8; 7],
    d: u8,
    tlen: usize,
) {
    kt[..7].copy_from_slice(&cnt[..7]);
    kt[7] = d;
    kt[8..16].fill(0);
    for i in 0..tlen {
        kt[16 + i] = t[i];
    }
    for i in 0..16 {
        kt[16 + tlen + i] = k[i];
    }
}

#[inline]
pub(crate) fn block_cipher(
    s: &mut [u8; 16],
    k: &[u8; 16],
    t: &[u8],
    cnt: &mut [u8; 7],
    d: u8,
    tlen: usize,
) {
    let mut kt = [0u8; 48];
    compose_tweakey(&mut kt, k, t, cnt, d, tlen);
    skinny_128_384_plus_enc(s, &kt);
}

#[inline]
pub(crate) fn nonce_encryption(
    n: &[u8; 16],
    cnt: &mut [u8; 7],
    s: &mut [u8; 16],
    k: &[u8; 16],
    t: usize,
    d: u8,
) {
    let mut tw = [0u8; 16];
    tw[..t].copy_from_slice(&n[..t]);
    block_cipher(s, k, &tw[..t], cnt, d, t);
}

/// Romulus-N / shared AD path: domain `d` for inner TBC (0x08 for N, 0x28 for M MAC AD).
pub(crate) fn ad_encryption(
    a: &[u8],
    a_off: &mut usize,
    s: &mut [u8; 16],
    k: &[u8; 16],
    mut adlen: u64,
    cnt: &mut [u8; 7],
    d: u8,
    n: usize,
    t: usize,
) -> u64 {
    let len8 = if adlen >= n as u64 { n } else { adlen as usize };
    if adlen >= n as u64 {
        adlen -= n as u64;
    } else {
        adlen = 0;
    }
    rho_ad(&a[*a_off..*a_off + len8], s, len8, n);
    *a_off += len8;
    lfsr_gf56(cnt);

    if adlen != 0 {
        let len8b = if adlen >= t as u64 { t } else { adlen as usize };
        if adlen >= t as u64 {
            adlen -= t as u64;
        } else {
            adlen = 0;
        }
        let mut tw = [0u8; 16];
        pad(&a[*a_off..*a_off + len8b], &mut tw, t, len8b);
        *a_off += len8b;
        block_cipher(s, k, &tw[..t], cnt, d, t);
        lfsr_gf56(cnt);
    }

    adlen
}

/// Romulus-N message path on a single buffer (`off` advances). Stack scratch avoids aliasing.
pub(crate) fn msg_encryption_n_inplace(
    buf: &mut [u8],
    off: &mut usize,
    n: &[u8; 16],
    cnt: &mut [u8; 7],
    s: &mut [u8; 16],
    k: &[u8; 16],
    blk_n: usize,
    t: usize,
    domain: u8,
    mut mlen: u64,
    decrypt: bool,
) -> u64 {
    let len8 = if mlen >= blk_n as u64 {
        blk_n
    } else {
        mlen as usize
    };
    if mlen >= blk_n as u64 {
        mlen -= blk_n as u64;
    } else {
        mlen = 0;
    }
    let mut tmp = [0u8; 16];
    tmp[..len8].copy_from_slice(&buf[*off..*off + len8]);
    if !decrypt {
        let mut ctmp = [0u8; 16];
        rho(&tmp[..len8], &mut ctmp, s, len8, blk_n);
        buf[*off..*off + len8].copy_from_slice(&ctmp[..len8]);
    } else {
        let mut ptmp = [0u8; 16];
        irho(&mut ptmp, &tmp[..len8], s, len8, blk_n);
        buf[*off..*off + len8].copy_from_slice(&ptmp[..len8]);
    }
    *off += len8;
    lfsr_gf56(cnt);
    nonce_encryption(n, cnt, s, k, t, domain);
    mlen
}

/// Romulus-M encryption message blocks on one buffer.
pub(crate) fn msg_encryption_m_inplace(
    buf: &mut [u8],
    off: &mut usize,
    n: &[u8; 16],
    cnt: &mut [u8; 7],
    s: &mut [u8; 16],
    k: &[u8; 16],
    blk_n: usize,
    t: usize,
    domain: u8,
    mut mlen: u64,
) -> u64 {
    let len8 = if mlen >= blk_n as u64 {
        blk_n
    } else {
        mlen as usize
    };
    if mlen >= blk_n as u64 {
        mlen -= blk_n as u64;
    } else {
        mlen = 0;
    }
    let mut tmp = [0u8; 16];
    tmp[..len8].copy_from_slice(&buf[*off..*off + len8]);
    let mut ctmp = [0u8; 16];
    rho(&tmp[..len8], &mut ctmp, s, len8, blk_n);
    buf[*off..*off + len8].copy_from_slice(&ctmp[..len8]);
    *off += len8;
    lfsr_gf56(cnt);
    nonce_encryption(n, cnt, s, k, t, domain);
    mlen
}

/// Romulus-M decryption message blocks on one buffer.
pub(crate) fn msg_decryption_m_inplace(
    buf: &mut [u8],
    off: &mut usize,
    n: &[u8; 16],
    cnt: &mut [u8; 7],
    s: &mut [u8; 16],
    k: &[u8; 16],
    blk_n: usize,
    t: usize,
    domain: u8,
    mut clen: u64,
) -> u64 {
    let len8 = if clen >= blk_n as u64 {
        blk_n
    } else {
        clen as usize
    };
    if clen >= blk_n as u64 {
        clen -= blk_n as u64;
    } else {
        clen = 0;
    }
    let mut tmp = [0u8; 16];
    tmp[..len8].copy_from_slice(&buf[*off..*off + len8]);
    let mut ptmp = [0u8; 16];
    irho(&mut ptmp, &tmp[..len8], s, len8, blk_n);
    buf[*off..*off + len8].copy_from_slice(&ptmp[..len8]);
    *off += len8;
    lfsr_gf56(cnt);
    nonce_encryption(n, cnt, s, k, t, domain);
    clen
}

/// Bridge when AD block count is odd (Romulus-M MAC phase).
pub(crate) fn ad2msg_encryption(
    m: &[u8],
    m_off: &mut usize,
    cnt: &mut [u8; 7],
    s: &mut [u8; 16],
    k: &[u8; 16],
    t: usize,
    d: u8,
    mut mlen: u64,
) -> u64 {
    let len8 = if mlen <= t as u64 { mlen as usize } else { t };
    if mlen <= t as u64 {
        mlen = 0;
    } else {
        mlen -= t as u64;
    }
    let mut tw = [0u8; 16];
    pad(&m[*m_off..*m_off + len8], &mut tw, t, len8);
    *m_off += len8;
    block_cipher(s, k, &tw[..t], cnt, d, t);
    lfsr_gf56(cnt);
    mlen
}

/// Compute final MAC domain byte `w` for Romulus-M (matches reference C).
pub(crate) fn romulus_m_compute_w(adlen: u64, xlen: u64, n: usize, t: usize) -> u8 {
    let mut w: u8 = 48;
    let nt = (n + t) as u64;

    if adlen == 0 {
        w ^= 2;
        if xlen == 0 {
            w ^= 1;
        } else if xlen % nt == 0 {
            w ^= 4;
        } else if xlen % nt < t as u64 {
            w ^= 1;
        } else if xlen % nt == t as u64 {
            w ^= 0;
        } else {
            w ^= 5;
        }
    } else if adlen % nt == 0 {
        w ^= 8;
        if xlen == 0 {
            w ^= 1;
        } else if xlen % nt == 0 {
            w ^= 4;
        } else if xlen % nt < n as u64 {
            w ^= 1;
        } else if xlen % nt == n as u64 {
            w ^= 0;
        } else {
            w ^= 5;
        }
    } else if adlen % nt < n as u64 {
        w ^= 2;
        if xlen == 0 {
            w ^= 1;
        } else if xlen % nt == 0 {
            w ^= 4;
        } else if xlen % nt < t as u64 {
            w ^= 1;
        } else if xlen % nt == t as u64 {
            w ^= 0;
        } else {
            w ^= 5;
        }
    } else if adlen % nt == n as u64 {
        w ^= 0;
        if xlen == 0 {
            w ^= 1;
        } else if xlen % nt == 0 {
            w ^= 4;
        } else if xlen % nt < t as u64 {
            w ^= 1;
        } else if xlen % nt == t as u64 {
            w ^= 0;
        } else {
            w ^= 5;
        }
    } else {
        w ^= 10;
        if xlen == 0 {
            w ^= 1;
        } else if xlen % nt == 0 {
            w ^= 4;
        } else if xlen % nt < n as u64 {
            w ^= 1;
        } else if xlen % nt == n as u64 {
            w ^= 0;
        } else {
            w ^= 5;
        }
    }
    w
}
