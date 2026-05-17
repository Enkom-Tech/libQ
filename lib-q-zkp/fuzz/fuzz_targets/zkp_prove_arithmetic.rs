#![no_main]

use lib_q_stark_field::extension::Complex;
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_zkp::air::{
    ArithmeticAir,
    TraceGenerator,
};
use lib_q_zkp::stark::{
    StarkProver,
    default_config,
};

type Val = Complex<Mersenne31>;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.len() > 32 {
        return;
    }
    let a = data.first().copied().unwrap_or(0) as u32;
    let b = data.get(1).copied().unwrap_or(0) as u32;
    let Ok(air) = ArithmeticAir::new(1) else {
        return;
    };
    let inputs = vec![(Val::from(Mersenne31::new(a)), Val::from(Mersenne31::new(b)))];
    let Ok(trace) = air.generate_trace(&inputs) else {
        return;
    };
    let public_values = vec![Val::from(Mersenne31::new(a * b))];
    let _ = StarkProver::new(default_config()).prove(&air, trace, &public_values);
});
