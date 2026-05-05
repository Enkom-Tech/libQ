#![no_main]

use lib_q_lattice_zkp::{
    AjtaiCommitmentKey,
    AjtaiOpening,
    AjtaiParameters,
    MlDsaCompatibleChallenge,
    OpeningProof,
    commit,
};
use lib_q_ring::{
    constants::FIELD_MODULUS,
    ModuleVec,
    Poly,
};
use lib_q_ring_sig::verify_federation_opening;

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
    if data.len() < 80 {
        return;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[..32]);
    data = &data[32..];

    let taus = [39usize, 49, 60];
    let tau = taus[(take_u32(&mut data) as usize) % taus.len()];
    let _ = MlDsaCompatibleChallenge::derive(&seed, tau);

    let params = AjtaiParameters::new(2, 1);
    let key = AjtaiCommitmentKey { seed, params };

    let mut ring = Vec::new();
    for _ in 0..3 {
        if data.len() < 3 * 256 * 4 {
            return;
        }
        let m0 = poly_from_stream(&mut data);
        let m1 = poly_from_stream(&mut data);
        let r0 = poly_from_stream(&mut data);
        let o = AjtaiOpening {
            message: ModuleVec(vec![m0, m1]),
            randomness: ModuleVec(vec![r0]),
        };
        ring.push(commit(&key, &o));
    }

    let signer_index = (take_u32(&mut data) as usize) % ring.len();
    let w0 = poly_from_stream(&mut data);
    let w1 = poly_from_stream(&mut data);
    let z0 = poly_from_stream(&mut data);
    let z1 = poly_from_stream(&mut data);
    let z2 = poly_from_stream(&mut data);
    let proof = OpeningProof {
        w: ModuleVec(vec![w0, w1]),
        z: ModuleVec(vec![z0, z1, z2]),
    };

    let z_bound = (take_u32(&mut data) % 5_000_000) as i32 + 1;
    let msg = data;
    let _ = verify_federation_opening(&key, &ring, signer_index, msg, &proof, tau, z_bound);
});
