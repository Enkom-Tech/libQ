#![no_main]

use lib_q_threshold_sig::{
    decode_threshold_sig_wire_v1,
    setup,
};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let profile = setup();
    let _ = decode_threshold_sig_wire_v1(&profile, data);
});
