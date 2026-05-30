#![no_main]

use lib_q_lattice_zkp::decode_witness_nullifier_opening_proof_v0;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = decode_witness_nullifier_opening_proof_v0(data);
});
