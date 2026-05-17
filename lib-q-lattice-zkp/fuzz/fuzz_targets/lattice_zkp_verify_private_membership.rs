#![no_main]

use std::vec::Vec;

use lib_q_lattice_zkp::{
    AjtaiCommitmentKey,
    AjtaiOpening,
    AjtaiParameters,
    CrtPackedNormProof,
    MerklePath,
    MlDsaCompatibleChallenge,
    OpeningProof,
    PrivateMembershipProof,
    PVTN_CLEARANCE_MARGIN_NORM_BETA,
    commit,
    verify_private_membership,
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
    if data.len() < 200 {
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

    let m0 = poly_from_stream(&mut data);
    let m1 = poly_from_stream(&mut data);
    let r0 = poly_from_stream(&mut data);
    let opening = AjtaiOpening {
        message: ModuleVec(vec![m0, m1]),
        randomness: ModuleVec(vec![r0]),
    };
    let credential_com = commit(&key, &opening);

    let mut leaf_digest = [0u8; 32];
    leaf_digest.copy_from_slice(&data[..32]);
    data = &data[32..];

    let mut role_tag = [0u8; 16];
    role_tag.copy_from_slice(&data[..16]);
    data = &data[16..];

    let mut parent_digest = [0u8; 32];
    parent_digest.copy_from_slice(&data[..32]);
    data = &data[32..];

    let mut tree_root = [0u8; 32];
    tree_root.copy_from_slice(&data[..32]);
    data = &data[32..];

    let clearance_level = take_u32(&mut data);
    let min_clearance = take_u32(&mut data);

    let depth = (take_u32(&mut data) as usize) % 8 + 1;
    let mut directions = Vec::new();
    let mut siblings = Vec::new();
    for _ in 0..depth {
        if data.is_empty() {
            return;
        }
        directions.push((data[0] & 1) == 1);
        data = &data[1..];
        if data.len() < 32 {
            return;
        }
        let mut s = [0u8; 32];
        s.copy_from_slice(&data[..32]);
        data = &data[32..];
        siblings.push(s);
    }
    let merkle_path = MerklePath {
        directions,
        siblings,
    };

    let w0 = poly_from_stream(&mut data);
    let w1 = poly_from_stream(&mut data);
    let z0 = poly_from_stream(&mut data);
    let z1 = poly_from_stream(&mut data);
    let z2 = poly_from_stream(&mut data);

    let n_slots = (take_u32(&mut data) as usize) % 4 + 1;
    let mut slot_bounds = Vec::new();
    for _ in 0..n_slots {
        slot_bounds.push((take_u32(&mut data) % 5000) as i32);
    }
    let max_norm = *slot_bounds.iter().max().unwrap_or(&0);
    let clearance_margin_norm = CrtPackedNormProof {
        slot_bounds,
        beta: PVTN_CLEARANCE_MARGIN_NORM_BETA,
        max_norm,
    };

    let margin_poly = poly_from_stream(&mut data);
    let clearance_margin_witness_polys = vec![margin_poly];

    let proof = PrivateMembershipProof {
        merkle_path,
        leaf_digest,
        clearance_level,
        role_tag,
        parent_digest,
        credential_com,
        opening_proof: OpeningProof {
            w: ModuleVec(vec![w0, w1]),
            z: ModuleVec(vec![z0, z1, z2]),
        },
        clearance_margin_norm,
        clearance_margin_witness_polys,
    };

    let z_bound = (take_u32(&mut data) % 5_000_000) as i32 + 1;
    let base_ctx = data;
    let _ = verify_private_membership(
        &key,
        &proof,
        &tree_root,
        min_clearance,
        base_ctx,
        tau,
        z_bound,
    );
});
