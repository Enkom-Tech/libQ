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
use lib_q_sca_test::dudect::timing_passes_loose;

const KEY_SEED: [u8; 32] = [0x42u8; 32];

#[test]
fn hardened_dudect_smoke_verify_opening() {
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
    let ctx = b"libq-hardened-lattice-zkp-smoke";
    let mut rng = new_secure_rng().expect("hardened prove path requires lib-q-random CSPRNG");
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
    .expect("prove opening");

    let mut valid = Vec::with_capacity(200);
    let mut invalid = Vec::with_capacity(200);
    for i in 0..100u8 {
        let start = std::time::Instant::now();
        let _ = verify_opening(&key, &com, &proof, ctx, profile.tau, profile.z_inf_bound);
        valid.push(start.elapsed().as_secs_f64());

        let mut bad = proof.clone();
        bad.z.0[0].coeffs[0] ^= i.wrapping_add(1) as i32;
        let start = std::time::Instant::now();
        let _ = verify_opening(&key, &com, &bad, ctx, profile.tau, profile.z_inf_bound);
        invalid.push(start.elapsed().as_secs_f64());
    }
    let mut samples = valid;
    samples.extend(invalid);
    assert!(
        timing_passes_loose(6.0, &samples),
        "hardened lattice-ZKP verify timing smoke failed (loose gate)"
    );
}

#[test]
fn hardened_dudect_smoke_prove_opening() {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    let key = AjtaiCommitmentKey {
        seed: KEY_SEED,
        params: profile.ajtai.clone(),
    };
    let ctx = b"libq-hardened-lattice-zkp-prove-smoke";
    let mut rng = new_secure_rng().expect("secure rng");

    let fixed_serial = [0x11u8; TOKEN_SERIAL_LEN];
    let fixed_origin = [0x22u8; TOKEN_ORIGIN_LEN];
    let fixed_epoch = [0x33u8; TOKEN_EPOCH_LEN];
    let fixed_opening = opening_from_token_fields(2, 1, &fixed_serial, &fixed_origin, &fixed_epoch)
        .expect("fixed opening");
    let fixed_com = commit(&key, &fixed_opening);

    let mut fixed_times = Vec::with_capacity(50);
    for _ in 0..25 {
        let start = std::time::Instant::now();
        let _ = prove_opening(
            &mut rng,
            &key,
            &fixed_opening,
            &fixed_com,
            ctx,
            profile.tau,
            profile.z_inf_bound,
            TEST_FIXED_PROVE_ATTEMPTS,
        );
        fixed_times.push(start.elapsed().as_secs_f64());
    }

    let mut random_times = Vec::with_capacity(50);
    for i in 0u8..25 {
        let serial = [i.wrapping_add(1); TOKEN_SERIAL_LEN];
        let origin = [i.wrapping_add(2); TOKEN_ORIGIN_LEN];
        let epoch = [i.wrapping_add(3); TOKEN_EPOCH_LEN];
        let opening =
            opening_from_token_fields(2, 1, &serial, &origin, &epoch).expect("random opening");
        let com = commit(&key, &opening);
        let start = std::time::Instant::now();
        let _ = prove_opening(
            &mut rng,
            &key,
            &opening,
            &com,
            ctx,
            profile.tau,
            profile.z_inf_bound,
            TEST_FIXED_PROVE_ATTEMPTS,
        );
        random_times.push(start.elapsed().as_secs_f64());
    }

    let mut samples = fixed_times;
    samples.extend(random_times);
    assert!(
        timing_passes_loose(6.0, &samples),
        "hardened lattice-ZKP prove timing smoke failed (loose gate)"
    );
}
