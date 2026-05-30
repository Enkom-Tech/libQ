#![no_main]

use lib_q_lattice_zkp::{
    commit,
    decode_private_membership_proof_v0,
    AjtaiCommitmentKey,
    AjtaiOpening,
    LatticeZkpProfileV0,
};
use lib_q_ring::{
    ModuleVec,
    Poly,
};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let profile = LatticeZkpProfileV0::pvtn_membership_v0();
    let key = AjtaiCommitmentKey {
        seed: [0u8; 32],
        params: profile.ajtai.clone(),
    };
    let com = commit(
        &key,
        &AjtaiOpening {
            message: ModuleVec(vec![Poly::zero()]),
            randomness: ModuleVec(vec![Poly::zero()]),
        },
    );
    let _ = decode_private_membership_proof_v0(data, 0, &[0u8; 32], com);
});
