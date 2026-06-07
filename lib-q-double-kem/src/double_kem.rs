//! Core MAUL-v1 double encapsulation operations.

use lib_q_ml_kem::{
    B32,
    Ciphertext,
    Decapsulate,
    Encapsulate,
    EncapsulateDeterministic,
    KemCore,
    MlKem768,
};
use lib_q_sha3::{
    Digest,
    Sha3_256,
};
use rand_core::{
    CryptoRng,
    Rng,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::DoubleKemError;
use crate::profile::{
    MAUL_HINT_BYTES,
    MAUL_WIRE_BODY_BYTES,
    MaulProfileV1,
};
use crate::wire::MaulEncapWire;

const DOMAIN_SECOND_MESSAGE: &[u8] = b"libq-double-kem-maul-v1-m2";
const DOMAIN_CK_FO_UPGRADE: &[u8] = b"libq-double-kem-maul-v1-kdf";

fn derive_second_message(body: &[u8; MAUL_WIRE_BODY_BYTES], hint: &[u8; MAUL_HINT_BYTES]) -> B32 {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, DOMAIN_SECOND_MESSAGE);
    Digest::update(&mut hasher, hint);
    Digest::update(&mut hasher, body);
    let digest: [u8; 32] = hasher.finalize().into();
    digest.into_iter().collect()
}

fn body_to_ciphertext(body: &[u8; MAUL_WIRE_BODY_BYTES]) -> Ciphertext<MlKem768> {
    body.iter().copied().collect()
}

fn shared_key_to_array(shared: &lib_q_ml_kem::SharedKey<MlKem768>) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.as_ref());
    out
}

/// Upgrade two ML-KEM shared secrets with a domain-separated CK/FO KDF.
#[must_use]
pub fn ck_fo_upgrade(ss_a: &[u8; 32], ss_b: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, DOMAIN_CK_FO_UPGRADE);
    Digest::update(&mut hasher, ss_a);
    Digest::update(&mut hasher, ss_b);
    hasher.finalize().into()
}

/// Perform MAUL-v1 double encapsulation and return fixed-size wire payload plus upgraded secret.
pub fn double_encap<R: CryptoRng + Rng + ?Sized>(
    _profile: MaulProfileV1,
    ek_a: &<MlKem768 as KemCore>::EncapsulationKey,
    ek_b: &<MlKem768 as KemCore>::EncapsulationKey,
    rng: &mut R,
) -> Result<(MaulEncapWire, [u8; 32]), DoubleKemError> {
    let (ct_a, ss_a) = ek_a
        .encapsulate(rng)
        .map_err(|_| DoubleKemError::EncapsulationFailed)?;

    let mut hint = [0u8; MAUL_HINT_BYTES];
    rng.fill_bytes(&mut hint);

    let mut body = [0u8; MAUL_WIRE_BODY_BYTES];
    body.copy_from_slice(ct_a.as_ref());

    let m2 = derive_second_message(&body, &hint);
    let (_ct_b, ss_b) = ek_b
        .encapsulate_deterministic(&m2)
        .map_err(|_| DoubleKemError::EncapsulationFailed)?;

    let ss_a_arr = shared_key_to_array(&ss_a);
    let ss_b_arr = shared_key_to_array(&ss_b);
    let upgraded = ck_fo_upgrade(&ss_a_arr, &ss_b_arr);

    Ok((MaulEncapWire::from_parts(hint, body), upgraded))
}

/// Decapsulate MAUL-v1 wire payload and recover the upgraded shared secret.
pub fn double_decap(
    _profile: MaulProfileV1,
    wire: &MaulEncapWire,
    dk_a: &<MlKem768 as KemCore>::DecapsulationKey,
    dk_b: &<MlKem768 as KemCore>::DecapsulationKey,
) -> Result<[u8; 32], DoubleKemError> {
    let ct_a = body_to_ciphertext(&wire.body);
    let ss_a = dk_a
        .decapsulate(&ct_a)
        .map_err(|_| DoubleKemError::DecapsulationFailed)?;

    let m2 = derive_second_message(&wire.body, &wire.hint);
    let ek_b = dk_b.encapsulation_key();
    let (_ct_b, ss_b) = ek_b
        .encapsulate_deterministic(&m2)
        .map_err(|_| DoubleKemError::EncapsulationFailed)?;

    let mut ss_a_arr = shared_key_to_array(&ss_a);
    let mut ss_b_arr = shared_key_to_array(&ss_b);
    let upgraded = ck_fo_upgrade(&ss_a_arr, &ss_b_arr);

    ss_a_arr.zeroize();
    ss_b_arr.zeroize();

    let choice = upgraded.ct_eq(&upgraded);
    if bool::from(choice) {
        Ok(upgraded)
    } else {
        Err(DoubleKemError::InvalidWireEncoding)
    }
}
