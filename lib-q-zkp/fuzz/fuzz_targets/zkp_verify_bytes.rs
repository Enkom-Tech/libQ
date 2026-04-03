#![no_main]

use lib_q_stark::Proof;
use lib_q_stark_field::{
    PrimeCharacteristicRing,
    extension::Complex,
};
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_zkp::air::ArithmeticAir;
use lib_q_zkp::stark::{
    DefaultConfig,
    StarkVerifier,
    default_config,
};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Ok(proof) = postcard::from_bytes::<Proof<DefaultConfig>>(data) else {
        return;
    };
    let Ok(air) = ArithmeticAir::new(1) else {
        return;
    };
    let pv = vec![<Complex<Mersenne31> as PrimeCharacteristicRing>::ZERO];
    let _ = StarkVerifier::new(default_config()).verify(&air, &proof, &pv);
});
