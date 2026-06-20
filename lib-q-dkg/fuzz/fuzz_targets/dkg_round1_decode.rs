#![no_main]

//! Fuzz the round-1 commitment broadcast decoder against arbitrary bytes: it must never panic and
//! must reject malformed input gracefully.

use lib_q_dkg::decode_round1_commitments;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = decode_round1_commitments(data);
});
