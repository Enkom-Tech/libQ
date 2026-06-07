#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = lib_q_zkp::wire::decode_recovery_zk_proof_v0(data);
    let _ = lib_q_zkp::wire::decode_recovery_zk_proof_v1(data);
});
