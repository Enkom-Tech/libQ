use lib_q_ml_kem::{
    B32,
    KemCore,
    MlKem768,
};
use lib_q_random::{
    LibQRng,
    new_deterministic_rng,
};
use lib_q_sha3::sha3_256;

const KAT_SEED: [u8; 32] = [
    0x64, 0x6F, 0x75, 0x62, 0x6C, 0x65, 0x2D, 0x6B, 0x65, 0x6D, 0x2D, 0x76, 0x31, 0x2D, 0x6B, 0x61,
    0x74, 0x2D, 0x73, 0x65, 0x65, 0x64, 0x2D, 0x30, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[allow(dead_code)]
pub fn kat_rng() -> LibQRng {
    new_deterministic_rng(KAT_SEED)
}

fn b32_from_tag(tag: &[u8]) -> B32 {
    let mut material = [0u8; 64];
    material[..KAT_SEED.len()].copy_from_slice(&KAT_SEED);
    let copy_len = core::cmp::min(tag.len(), 32);
    material[32..32 + copy_len].copy_from_slice(&tag[..copy_len]);
    let digest = sha3_256(&material);
    digest.into_iter().collect()
}

pub fn kat_keys() -> (
    <MlKem768 as KemCore>::DecapsulationKey,
    <MlKem768 as KemCore>::EncapsulationKey,
    <MlKem768 as KemCore>::DecapsulationKey,
    <MlKem768 as KemCore>::EncapsulationKey,
) {
    let d1 = b32_from_tag(b"double-kem-kat-d1");
    let z1 = b32_from_tag(b"double-kem-kat-z1");
    let d2 = b32_from_tag(b"double-kem-kat-d2");
    let z2 = b32_from_tag(b"double-kem-kat-z2");
    let (dk_a, ek_a) = MlKem768::generate_deterministic(&d1, &z1);
    let (dk_b, ek_b) = MlKem768::generate_deterministic(&d2, &z2);
    (dk_a, ek_a, dk_b, ek_b)
}
