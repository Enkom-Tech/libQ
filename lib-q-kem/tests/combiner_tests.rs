//! ML-KEM-1024 + HQC-256 combiner: round trip, failure behaviour, and the
//! "one component broken" acceptance tests.
//!
//! Run with: cargo test -p lib-q-kem --features combiner-kat --test combiner_tests
#![cfg(feature = "combiner-kat")]

use lib_q_core::{Algorithm, KemOperations, KemPublicKey, KemSecretKey};
use lib_q_hqc::LibQHqcProvider;
use lib_q_kem::combiner::{
    self, CIPHERTEXT_SIZE, ENCAPS_COINS_SIZE, HQC256_CIPHERTEXT_SIZE, HQC256_PUBLIC_KEY_SIZE,
    KEYGEN_SEED_SIZE, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SHARED_SECRET_SIZE,
};
use lib_q_ml_kem::array::Array;
use lib_q_ml_kem::{
    B32, Decapsulate, EncapsulateDeterministic, KemCore, MLKEM1024_CIPHERTEXT_SIZE,
    MLKEM1024_PUBLIC_KEY_SIZE, MLKEM1024_SECRET_KEY_SIZE, MlKem1024,
};

type MlKemDk = <MlKem1024 as KemCore>::DecapsulationKey;
type MlKemEk = <MlKem1024 as KemCore>::EncapsulationKey;

fn pattern<const N: usize>(base: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = base.wrapping_add((i as u8).wrapping_mul(7));
    }
    out
}

fn xor32(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

struct Fixture {
    pk: Vec<u8>,
    sk: Vec<u8>,
    ct: Vec<u8>,
    ss: [u8; SHARED_SECRET_SIZE],
}

fn fixture() -> Fixture {
    let kp = combiner::generate_keypair_from_seed(&pattern::<KEYGEN_SEED_SIZE>(0x11)).unwrap();
    let (ct, ss) =
        combiner::encapsulate_with_coins(&kp.public_key, &pattern::<ENCAPS_COINS_SIZE>(0x5A))
            .unwrap();
    Fixture {
        pk: kp.public_key.clone(),
        sk: kp.secret_key.to_vec(),
        ct,
        ss: *ss,
    }
}

// ---- component oracles -------------------------------------------------------------------------
//
// "Component X is broken" is modelled by giving the attacker an oracle that returns X's shared
// secret for any X-ciphertext. The oracle is built from X's secret-key half ONLY; the other
// component's secret key is never touched by the attacker.

fn hqc_sk(sk: &[u8]) -> KemSecretKey {
    KemSecretKey::new(sk[MLKEM1024_SECRET_KEY_SIZE..].to_vec())
}

/// Oracle for a broken HQC-256.
fn broken_hqc(sk: &[u8], ct_hqc: &[u8]) -> Vec<u8> {
    LibQHqcProvider::new()
        .unwrap()
        .decapsulate(Algorithm::Hqc256, &hqc_sk(sk), ct_hqc)
        .unwrap()
}

/// Oracle for a broken ML-KEM-1024.
fn broken_mlkem(sk: &[u8], ct_mlkem: &[u8]) -> Vec<u8> {
    let enc = Array::try_from(&sk[..MLKEM1024_SECRET_KEY_SIZE]).unwrap();
    let dk = MlKemDk::try_from_bytes(&enc).unwrap();
    let ct = Array::try_from(ct_mlkem).unwrap();
    dk.decapsulate(&ct).unwrap().to_vec()
}

/// A fresh, honestly formed HQC-256 ciphertext to `pk_hqc` whose secret the attacker knows.
fn attacker_hqc_ct(pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let pk_hqc = KemPublicKey::new(pk[MLKEM1024_PUBLIC_KEY_SIZE..].to_vec());
    LibQHqcProvider::new()
        .unwrap()
        .encapsulate(Algorithm::Hqc256, &pk_hqc, Some(&pattern::<48>(0xC3)))
        .unwrap()
}

/// A fresh, honestly formed ML-KEM-1024 ciphertext to `pk_mlkem` whose secret the attacker knows.
fn attacker_mlkem_ct(pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let enc = Array::try_from(&pk[..MLKEM1024_PUBLIC_KEY_SIZE]).unwrap();
    let ek = MlKemEk::try_from_bytes(&enc).unwrap();
    let m: B32 = Array::from(pattern::<32>(0x3C));
    let (ct, ss) = ek.encapsulate_deterministic(&m).unwrap();
    (ct.to_vec(), ss.to_vec())
}

// ---- acceptance: a ciphertext forged for one component alone does not yield the combined secret

/// HQC broken, ML-KEM sound. The attacker keeps the challenge's ML-KEM ciphertext, replaces the
/// HQC half with one it formed itself, asks the decapsulation oracle about that (legal: it differs
/// from the challenge), then strips the HQC contributions it can compute.
///
/// Against `ss = ss_mlkem XOR ss_hqc` this recovers the challenge secret exactly, so the combined
/// KEM is no stronger than the broken component. Binding both ciphertexts into the KDF defeats it.
#[test]
fn hqc_forgery_with_challenge_mlkem_ct_does_not_yield_combined_secret() {
    let f = fixture();
    let (ct_mlkem_star, ct_hqc_star) = f.ct.split_at(MLKEM1024_CIPHERTEXT_SIZE);

    let (ct_hqc_forged, ss_hqc_forged) = attacker_hqc_ct(&f.pk);
    assert_ne!(
        ct_hqc_forged.as_slice(),
        ct_hqc_star,
        "forged half must differ"
    );
    let forged = [ct_mlkem_star, ct_hqc_forged.as_slice()].concat();
    assert_ne!(forged, f.ct);

    let k_forged = combiner::decapsulate(&f.sk, &forged).expect("well-formed forgery decapsulates");
    let ss_hqc_star = broken_hqc(&f.sk, ct_hqc_star);
    let guess = xor32(&xor32(k_forged.as_slice(), &ss_hqc_forged), &ss_hqc_star);

    assert_ne!(
        k_forged.as_slice(),
        f.ss.as_slice(),
        "forged ciphertext decapsulated to the challenge secret"
    );
    assert_ne!(
        guess, f.ss,
        "HQC-only forgery recovered the combined secret (combiner is not binding)"
    );
}

/// The mirror case: ML-KEM broken, HQC sound.
#[test]
fn mlkem_forgery_with_challenge_hqc_ct_does_not_yield_combined_secret() {
    let f = fixture();
    let (ct_mlkem_star, ct_hqc_star) = f.ct.split_at(MLKEM1024_CIPHERTEXT_SIZE);

    let (ct_mlkem_forged, ss_mlkem_forged) = attacker_mlkem_ct(&f.pk);
    assert_ne!(
        ct_mlkem_forged.as_slice(),
        ct_mlkem_star,
        "forged half must differ"
    );
    let forged = [ct_mlkem_forged.as_slice(), ct_hqc_star].concat();

    let k_forged = combiner::decapsulate(&f.sk, &forged).expect("well-formed forgery decapsulates");
    let ss_mlkem_star = broken_mlkem(&f.sk, ct_mlkem_star);
    let guess = xor32(
        &xor32(k_forged.as_slice(), &ss_mlkem_forged),
        &ss_mlkem_star,
    );

    assert_ne!(
        k_forged.as_slice(),
        f.ss.as_slice(),
        "forged ciphertext decapsulated to the challenge secret"
    );
    assert_ne!(
        guess, f.ss,
        "ML-KEM-only forgery recovered the combined secret (combiner is not binding)"
    );
}

/// Keeps the two tests above honest: the attack harness, run against an explicit XOR combiner
/// over the same component values, DOES recover the challenge secret. If a refactor ever made the
/// oracles return something unrelated, this fails instead of the acceptance tests passing vacuously.
#[test]
fn attack_harness_recovers_the_secret_from_a_naive_xor_combiner() {
    let f = fixture();
    let (ct_mlkem_star, ct_hqc_star) = f.ct.split_at(MLKEM1024_CIPHERTEXT_SIZE);
    let ss_mlkem_star = broken_mlkem(&f.sk, ct_mlkem_star);
    let ss_hqc_star = broken_hqc(&f.sk, ct_hqc_star);
    let xor_challenge = xor32(&ss_mlkem_star, &ss_hqc_star);

    let (ct_hqc_forged, ss_hqc_forged) = attacker_hqc_ct(&f.pk);
    assert_eq!(
        broken_hqc(&f.sk, &ct_hqc_forged),
        ss_hqc_forged,
        "HQC oracle disagrees with encaps"
    );
    // What a naive XOR combiner's decapsulation oracle would answer for the forgery.
    let xor_oracle_answer = xor32(&broken_mlkem(&f.sk, ct_mlkem_star), &ss_hqc_forged);
    let guess = xor32(&xor32(&xor_oracle_answer, &ss_hqc_forged), &ss_hqc_star);
    assert_eq!(
        guess, xor_challenge,
        "harness must break the naive XOR combiner"
    );
}

// ---- functional ---------------------------------------------------------------------------------

#[test]
fn sizes_are_the_component_sums() {
    assert_eq!(
        PUBLIC_KEY_SIZE,
        MLKEM1024_PUBLIC_KEY_SIZE + HQC256_PUBLIC_KEY_SIZE
    );
    assert_eq!(
        CIPHERTEXT_SIZE,
        MLKEM1024_CIPHERTEXT_SIZE + HQC256_CIPHERTEXT_SIZE
    );
    let f = fixture();
    assert_eq!(f.pk.len(), PUBLIC_KEY_SIZE);
    assert_eq!(f.sk.len(), SECRET_KEY_SIZE);
    assert_eq!(f.ct.len(), CIPHERTEXT_SIZE);
}

#[test]
fn seeded_round_trip_and_determinism() {
    let f = fixture();
    assert_eq!(
        combiner::decapsulate(&f.sk, &f.ct).unwrap().as_slice(),
        f.ss.as_slice()
    );
    let g = fixture();
    assert_eq!(
        (f.pk, f.ct, f.ss),
        (g.pk, g.ct, g.ss),
        "explicit seed/coins must be deterministic"
    );
}

#[test]
fn os_entropy_round_trip() {
    let kp = combiner::generate_keypair().unwrap();
    let (ct, ss) = combiner::encapsulate(&kp.public_key).unwrap();
    assert_eq!(
        combiner::decapsulate(&kp.secret_key, &ct)
            .unwrap()
            .as_slice(),
        ss.as_slice()
    );
    let (ct2, ss2) = combiner::encapsulate(&kp.public_key).unwrap();
    assert_ne!(ct, ct2);
    assert_ne!(ss.as_slice(), ss2.as_slice());
}

#[test]
fn tampering_either_half_changes_the_secret_without_error() {
    let f = fixture();
    for idx in [
        0,
        MLKEM1024_CIPHERTEXT_SIZE - 1,
        MLKEM1024_CIPHERTEXT_SIZE,
        CIPHERTEXT_SIZE - 1,
    ] {
        let mut ct = f.ct.clone();
        ct[idx] ^= 0x01;
        let k = combiner::decapsulate(&f.sk, &ct).expect("implicit rejection, not an error");
        assert_ne!(
            k.as_slice(),
            f.ss.as_slice(),
            "flip at byte {idx} left the secret unchanged"
        );
    }
}

#[test]
fn wrong_lengths_fail_the_whole_exchange() {
    let f = fixture();
    assert!(combiner::decapsulate(&f.sk, &f.ct[..CIPHERTEXT_SIZE - 1]).is_err());
    assert!(
        combiner::decapsulate(&f.sk, &f.ct[..MLKEM1024_CIPHERTEXT_SIZE]).is_err(),
        "ML-KEM half alone"
    );
    assert!(combiner::decapsulate(&f.sk[..SECRET_KEY_SIZE - 1], &f.ct).is_err());
    assert!(
        combiner::encapsulate(&f.pk[..MLKEM1024_PUBLIC_KEY_SIZE]).is_err(),
        "ML-KEM key alone"
    );
    assert!(combiner::encapsulate(&[f.pk.as_slice(), &[0u8]].concat()).is_err());
}

#[test]
fn non_canonical_mlkem_public_key_is_refused() {
    let f = fixture();
    let mut pk = f.pk.clone();
    // First 12-bit coefficient := 0xFFF (>= q = 3329): fails the FIPS 203 modulus check.
    pk[0] = 0xFF;
    pk[1] |= 0x0F;
    assert!(combiner::encapsulate(&pk).is_err());
}

#[test]
fn corrupted_mlkem_decapsulation_key_is_refused() {
    let f = fixture();
    let mut sk = f.sk.clone();
    // Flip a byte of the embedded H(ek): FIPS 203 decapsulation-key check must fail.
    sk[MLKEM1024_SECRET_KEY_SIZE - 40] ^= 0x01;
    assert!(combiner::decapsulate(&sk, &f.ct).is_err());
}
