//! Deterministic checks of Legendre multiplicativity on the pilot field.

use crypto_bigint::{
    CtEq,
    U256,
};
use lib_q_prf::field::legendre_symbol_monty;
use lib_q_prf::{
    LegendrePrfParams256,
    to_monty,
};

#[test]
fn legendre_multiplicative_sampled() {
    let params = LegendrePrfParams256::pilot();
    for seed in 1u64..=64u64 {
        let a = U256::from(seed)
            .wrapping_mul(&U256::from(0x9E37_79B9_7F4A_7C15u64))
            .rem_vartime(&params.p);
        let b = U256::from(seed.wrapping_mul(3))
            .wrapping_add(&U256::from(11u64))
            .rem_vartime(&params.p);
        if bool::from(a.ct_eq(&U256::ZERO)) || bool::from(b.ct_eq(&U256::ZERO)) {
            continue;
        }
        let am = to_monty(&a, &params.monty);
        let bm = to_monty(&b, &params.monty);
        let ab = am.mul(&bm);
        let la = legendre_symbol_monty(&am).expect("la");
        let lb = legendre_symbol_monty(&bm).expect("lb");
        let lab = legendre_symbol_monty(&ab).expect("lab");
        assert_eq!(lab, la.wrapping_mul(lb), "seed {seed}");
    }
}
