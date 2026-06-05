//! Shared KAT helpers.

use lib_q_mac::{
    QcwMac,
    QcwMacKey,
};
use lib_q_random::{
    LibQRng,
    new_deterministic_rng,
};

const KAT_SEED: [u8; 32] = [
    0x71, 0x63, 0x77, 0x2D, 0x6D, 0x61, 0x63, 0x2D, 0x76, 0x31, 0x2D, 0x6B, 0x61, 0x74, 0x2D, 0x73,
    0x65, 0x65, 0x64, 0x2D, 0x30, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[allow(dead_code)]
pub fn kat_rng() -> LibQRng {
    new_deterministic_rng(KAT_SEED)
}

pub fn kat_key() -> QcwMacKey {
    QcwMacKey::from_bytes(KAT_SEED)
}

pub type KatCase = (String, Vec<u8>, Vec<u8>, Vec<u8>);

pub fn kat_positive_cases() -> Vec<KatCase> {
    let key = kat_key();
    let cases: [(&str, &[u8], &[u8]); 3] = [
        ("baseline", b"hello quantum mac", b"ad0"),
        ("empty_ad", b"payload", b""),
        ("empty_msg", b"", b"associated"),
    ];
    cases
        .into_iter()
        .map(|(name, msg, ad)| {
            let tag = QcwMac::sign(&key, msg, ad);
            (name.to_string(), msg.to_vec(), ad.to_vec(), tag)
        })
        .collect()
}
