#![cfg(feature = "hardened")]

use lib_q_lattice_zkp::hardened::{
    TEST_FIXED_PROVE_ATTEMPTS,
    new_secure_rng,
};
use lib_q_lattice_zkp::{
    AjtaiCommitmentKey,
    LatticeZkpProfileV0,
    TOKEN_EPOCH_LEN,
    TOKEN_ORIGIN_LEN,
    TOKEN_SERIAL_LEN,
    commit,
    opening_from_token_fields,
    prove_opening,
    verify_opening,
};

const KEY_SEED: [u8; 32] = [0x42u8; 32];

#[test]
fn hardened_prove_opening_roundtrip() {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    let key = AjtaiCommitmentKey {
        seed: KEY_SEED,
        params: profile.ajtai.clone(),
    };
    let serial = [0x11u8; TOKEN_SERIAL_LEN];
    let origin = [0x22u8; TOKEN_ORIGIN_LEN];
    let epoch = [0x33u8; TOKEN_EPOCH_LEN];
    let opening =
        opening_from_token_fields(2, 1, &serial, &origin, &epoch).expect("token opening layout");
    let com = commit(&key, &opening);
    let ctx = b"hardened-masked-roundtrip";
    let mut rng = new_secure_rng().expect("secure rng");
    let proof = prove_opening(
        &mut rng,
        &key,
        &opening,
        &com,
        ctx,
        profile.tau,
        profile.z_inf_bound,
        TEST_FIXED_PROVE_ATTEMPTS,
    )
    .expect("hardened prove");
    verify_opening(&key, &com, &proof, ctx, profile.tau, profile.z_inf_bound)
        .expect("verify hardened proof");
}

#[test]
fn hardened_first_accept_matches_single_successful_attempt() {
    use lib_q_random::new_deterministic_rng;

    let profile = LatticeZkpProfileV0::token_spend_v0();
    let key = AjtaiCommitmentKey {
        seed: KEY_SEED,
        params: profile.ajtai.clone(),
    };
    let opening = opening_from_token_fields(
        2,
        1,
        &[0xAAu8; TOKEN_SERIAL_LEN],
        &[0xBBu8; TOKEN_ORIGIN_LEN],
        &[0xCCu8; TOKEN_EPOCH_LEN],
    )
    .expect("opening");
    let com = commit(&key, &opening);
    let ctx = b"hardened-first-accept";

    let seed = (0u8..=255)
        .map(|byte| [byte; 32])
        .find(|seed| {
            let mut rng = new_deterministic_rng(*seed);
            prove_opening(
                &mut rng,
                &key,
                &opening,
                &com,
                ctx,
                profile.tau,
                profile.z_inf_bound,
                1,
            )
            .is_ok()
        })
        .expect("fixture must admit a first-attempt accepting seed");

    let mut rng_one = new_deterministic_rng(seed);
    let proof_one = prove_opening(
        &mut rng_one,
        &key,
        &opening,
        &com,
        ctx,
        profile.tau,
        profile.z_inf_bound,
        1,
    )
    .expect("single-attempt prove");
    let mut rng_many = new_deterministic_rng(seed);
    let proof_many = prove_opening(
        &mut rng_many,
        &key,
        &opening,
        &com,
        ctx,
        profile.tau,
        profile.z_inf_bound,
        TEST_FIXED_PROVE_ATTEMPTS,
    )
    .expect("fixed-iteration prove");
    assert_eq!(proof_one, proof_many);
}

#[test]
fn hardened_amortise_batch_roundtrip() {
    use lib_q_lattice_zkp::{
        AjtaiOpening,
        AjtaiParameters,
        amortise,
        verify_aggregate,
    };
    use lib_q_random::new_deterministic_rng;
    use lib_q_ring::{
        ModuleVec,
        Poly,
    };

    let params = AjtaiParameters::new(2, 1);
    let key = AjtaiCommitmentKey {
        seed: KEY_SEED,
        params,
    };
    let mut m1 = vec![Poly::zero(), Poly::zero()];
    m1[0].coeffs[0] = 2;
    let mut r1 = vec![Poly::zero()];
    r1[0].coeffs[0] = 9;
    let o1 = AjtaiOpening {
        message: ModuleVec(m1),
        randomness: ModuleVec(r1),
    };
    let mut m2 = vec![Poly::zero(), Poly::zero()];
    m2[1].coeffs[0] = 3;
    let mut r2 = vec![Poly::zero()];
    r2[0].coeffs[0] = 7;
    let o2 = AjtaiOpening {
        message: ModuleVec(m2),
        randomness: ModuleVec(r2),
    };
    let c1 = commit(&key, &o1);
    let c2 = commit(&key, &o2);
    let commitments = vec![c1.clone(), c2.clone()];
    let mut rng = new_deterministic_rng([0xA5u8; 32]);
    let proof = amortise(
        &mut rng,
        &key,
        &[o1, o2],
        &commitments,
        b"hardened-amortise",
        39,
        100_000_000,
    )
    .expect("hardened amortise");
    verify_aggregate(&key, &commitments, &proof, 39, 100_000_000).expect("verify aggregate");
}
