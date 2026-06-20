#![no_main]

//! Fuzz the complaint decoder (which carries a disclosed share value, randomness, and proof)
//! against arbitrary bytes: it must never panic and must reject malformed input gracefully.

use lib_q_dkg::decode_complaint;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = decode_complaint(data);
});
