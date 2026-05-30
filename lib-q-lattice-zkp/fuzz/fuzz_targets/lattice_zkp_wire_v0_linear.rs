#![no_main]

use lib_q_lattice_zkp::decode_linear_relation_proof_v0;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = decode_linear_relation_proof_v0(data);
});
