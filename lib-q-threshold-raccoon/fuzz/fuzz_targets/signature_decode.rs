#![no_main]

//! Fuzz the signature decoder against arbitrary bytes: it must never panic and must reject malformed
//! input gracefully.

use lib_q_threshold_raccoon::decode_signature;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = decode_signature(data);
});
