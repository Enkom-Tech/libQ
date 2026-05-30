#![no_main]

use lib_q_lattice_zkp::{
    AjtaiOpening,
    AjtaiParameters,
    BlindIssuance,
    BlindResponse,
    IssuerCommitmentParams,
    LatticeZkpProfileV0,
    MlDsaCompatibleChallenge,
    OpeningProof,
    UnblindedIssuance,
    commit,
};
use lib_q_ring::{
    constants::FIELD_MODULUS,
    ModuleVec,
    Poly,
};

fn take_u32(data: &mut &[u8]) -> u32 {
    if data.len() < 4 {
        return 0;
    }
    let v = u32::from_le_bytes(data[..4].try_into().unwrap());
    *data = &data[4..];
    v
}

fn poly_from_stream(data: &mut &[u8]) -> Poly {
    let q = FIELD_MODULUS as u32;
    let mut coeffs = [0i32; 256];
    for c in &mut coeffs {
        *c = (take_u32(data) % q) as i32;
    }
    Poly::from_coeffs(coeffs)
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut data = data;
    if data.len() < 120 {
        return;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[..32]);
    data = &data[32..];

    let taus = [39usize, 49, 60];
    let tau = taus[(take_u32(&mut data) as usize) % taus.len()];
    let _ = MlDsaCompatibleChallenge::derive(&seed, tau);

    let params = AjtaiParameters::new(2, 1);
    let issuer_params = IssuerCommitmentParams {
        issuer_matrix_seed: seed,
        params,
        profile_id: LatticeZkpProfileV0::token_spend_v0().profile_id,
    };
    let key = issuer_params.commitment_key();

    let m0 = poly_from_stream(&mut data);
    let m1 = poly_from_stream(&mut data);
    let r0 = poly_from_stream(&mut data);
    let token_opening = AjtaiOpening {
        message: ModuleVec(vec![m0, m1]),
        randomness: ModuleVec(vec![r0]),
    };
    let com_blinded = commit(&key, &token_opening);

    let iw0 = poly_from_stream(&mut data);
    let iw1 = poly_from_stream(&mut data);
    let iz0 = poly_from_stream(&mut data);
    let iz1 = poly_from_stream(&mut data);
    let iz2 = poly_from_stream(&mut data);

    let resp = BlindResponse {
        issuer_com: commit(
            &key,
            &AjtaiOpening {
                message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
                randomness: ModuleVec(vec![Poly::zero()]),
            },
        ),
        issuer_proof: OpeningProof {
            w: ModuleVec(vec![iw0, iw1]),
            z: ModuleVec(vec![iz0, iz1, iz2]),
        },
    };

    let bundle = UnblindedIssuance {
        com_blinded,
        token_opening,
        issuer_com: resp.issuer_com.clone(),
        issuer_proof: resp.issuer_proof,
    };

    let z_bound = (take_u32(&mut data) % 5_000_000) as i32 + 1;
    let base_ctx = data;
    let _ = BlindIssuance::verify(&issuer_params, &bundle, base_ctx, tau, z_bound);
});
