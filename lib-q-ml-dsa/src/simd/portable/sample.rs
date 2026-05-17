use crate::constants::FIELD_MODULUS;
#[cfg(hax)]
use crate::specs::simd::portable::sample::*;

#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
#[hax_lib::requires(rejection_sample_less_than_field_modulus_pre(randomness, out))]
#[hax_lib::ensures(|r| rejection_sample_less_than_field_modulus_post(randomness, future(out), r))]
pub fn rejection_sample_less_than_field_modulus(randomness: &[u8], out: &mut [i32]) -> usize {
    let mut sampled = 0;

    #[cfg(hax)]
    let _out_len = out.len();
    hax_lib::fstar!(
        r#"Spec.Utils.eq_repeati0 (sz 0) (Spec.MLDSA.Math.rejection_sample_field_modulus_inner $randomness) Seq.empty"#
    );

    for i in 0..randomness.len() / 3 {
        hax_lib::loop_invariant!(|i: usize| {
            fstar!(
                r#"
              v $sampled <= v $i /\
              Seq.length $out == v $_out_len /\
              (let samples = Spec.Utils.repeati ($i)
                (Spec.MLDSA.Math.rejection_sample_field_modulus_inner $randomness) Seq.empty in
              v $sampled == Seq.length samples /\
              Seq.slice $out 0 (Seq.length samples) == samples)"#
            )
        });

        let b0 = randomness[i * 3] as i32;
        let b1 = randomness[i * 3 + 1] as i32;
        let b2 = randomness[i * 3 + 2] as i32;
        let coefficient = ((b2 << 16) | (b1 << 8) | b0) & 0x00_7F_FF_FF;

        hax_lib::fstar!(
            r#"Spec.MLDSA.Math.rejection_sample_coefficient_lemma $randomness ($i);
            Spec.Utils.unfold_repeati ($i +! sz 1) 
                (Spec.MLDSA.Math.rejection_sample_field_modulus_inner $randomness) Seq.empty ($i)"#
        );

        if coefficient < FIELD_MODULUS {
            out[sampled] = coefficient;
            sampled += 1;
        }

        hax_lib::fstar!(
            r#"let samples = Spec.Utils.repeati ($i +! sz 1)
                (Spec.MLDSA.Math.rejection_sample_field_modulus_inner $randomness) Seq.empty in
            eq_intro (Seq.slice $out 0 (Seq.length samples)) samples"#
        );
    }

    sampled
}

#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
#[hax_lib::fstar::options("--z3rlimit 800 --ext context_pruning --z3refresh")]
#[hax_lib::requires(rejection_sample_less_than_eta_equals_2_pre(randomness, out))]
#[hax_lib::ensures(|r| rejection_sample_less_than_eta_equals_2_post(randomness, future(out), r))]
pub fn rejection_sample_less_than_eta_equals_2(randomness: &[u8], out: &mut [i32]) -> usize {
    let mut sampled = 0;

    #[cfg(hax)]
    let _out_len = out.len();
    hax_lib::fstar!(
        r#"Spec.Utils.eq_repeati0 (sz 0) (Spec.MLDSA.Math.rejection_sample_eta_2_inner $randomness) Seq.empty"#
    );

    #[allow(clippy::needless_range_loop)]
    for i in 0..randomness.len() {
        hax_lib::loop_invariant!(|i: usize| {
            fstar!(
                r#"
              v $i >= 0 /\ v $i <= Seq.length $randomness /\
              v $sampled <= v $i * 2 /\
              Seq.length $out == v $_out_len /\
              (let samples = Spec.Utils.repeati ($i)
                (Spec.MLDSA.Math.rejection_sample_eta_2_inner $randomness) Seq.empty in
              v $sampled == Seq.length samples /\
              Seq.slice $out 0 (Seq.length samples) == samples)"#
            )
        });

        let byte = randomness[i];
        let try_0 = byte & 0xF;
        let try_1 = byte >> 4;

        hax_lib::fstar!(
            r#"Spec.Utils.unfold_repeati ($i +! sz 1) 
                (Spec.MLDSA.Math.rejection_sample_eta_2_inner $randomness) Seq.empty ($i)"#
        );

        if try_0 < 15 {
            let try_0 = try_0 as i32;
            // (try_0 * 26) >> 7 computes ⌊try_0 / 5⌋
            let try_0_mod_5 = try_0 - ((try_0 * 26) >> 7) * 5;

            hax_lib::fstar!(
                r#"assert ($try_0_mod_5 == ($try_0 %! mk_i32 5));
                assert ((mk_i32 2 -. $try_0_mod_5) == (mk_i32 2 -! $try_0_mod_5))"#
            );

            out[sampled] = 2 - try_0_mod_5;
            sampled += 1;
        }

        if try_1 < 15 {
            let try_1 = try_1 as i32;
            let try_1_mod_5 = try_1 - ((try_1 * 26) >> 7) * 5;

            hax_lib::fstar!(
                r#"assert ($try_1_mod_5 == ($try_1 %! mk_i32 5));
                assert ((mk_i32 2 -. $try_1_mod_5) == (mk_i32 2 -! $try_1_mod_5))"#
            );

            out[sampled] = 2 - try_1_mod_5;
            sampled += 1;
        }

        hax_lib::fstar!(
            r#"let samples = Spec.Utils.repeati ($i +! sz 1)
                (Spec.MLDSA.Math.rejection_sample_eta_2_inner $randomness) Seq.empty in
            eq_intro (Seq.slice $out 0 (Seq.length samples)) samples"#
        );
    }

    sampled
}

#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
#[hax_lib::fstar::options("--ext context_pruning --z3refresh")]
#[hax_lib::requires(rejection_sample_less_than_eta_equals_4_pre(randomness, out))]
#[hax_lib::ensures(|r| rejection_sample_less_than_eta_equals_4_post(randomness, future(out), r))]
pub fn rejection_sample_less_than_eta_equals_4(randomness: &[u8], out: &mut [i32]) -> usize {
    let mut sampled = 0;

    #[cfg(hax)]
    let _out_len = out.len();
    hax_lib::fstar!(
        r#"Spec.Utils.eq_repeati0 (sz 0) (Spec.MLDSA.Math.rejection_sample_eta_4_inner $randomness) Seq.empty"#
    );

    #[allow(clippy::needless_range_loop)]
    for i in 0..randomness.len() {
        hax_lib::loop_invariant!(|i: usize| {
            fstar!(
                r#"
              v $i >= 0 /\ v $i <= Seq.length $randomness /\
              v $sampled <= v $i * 2 /\
              Seq.length $out == v $_out_len /\
              (let samples = Spec.Utils.repeati ($i)
                (Spec.MLDSA.Math.rejection_sample_eta_4_inner $randomness) Seq.empty in
              v $sampled == Seq.length samples /\
              Seq.slice $out 0 (Seq.length samples) == samples)"#
            )
        });

        let byte = randomness[i];
        let try_0 = byte & 0xF;
        let try_1 = byte >> 4;

        hax_lib::fstar!(
            r#"Spec.Utils.unfold_repeati ($i +! sz 1) 
                (Spec.MLDSA.Math.rejection_sample_eta_4_inner $randomness) Seq.empty ($i)"#
        );

        if try_0 < 9 {
            out[sampled] = 4 - (try_0 as i32);
            sampled += 1;
        }
        if try_1 < 9 {
            out[sampled] = 4 - (try_1 as i32);
            sampled += 1;
        }

        hax_lib::fstar!(
            r#"let samples = Spec.Utils.repeati ($i +! sz 1)
                (Spec.MLDSA.Math.rejection_sample_eta_4_inner $randomness) Seq.empty in
            eq_intro (Seq.slice $out 0 (Seq.length samples)) samples"#
        );
    }

    sampled
}

#[cfg(test)]
mod tests {
    use super::{
        rejection_sample_less_than_eta_equals_2,
        rejection_sample_less_than_eta_equals_4,
        rejection_sample_less_than_field_modulus,
    };
    use crate::constants::FIELD_MODULUS;

    #[test]
    fn rejection_field_modulus_accepts_and_rejects() {
        let mut out = [0i32; 8];
        // One triplet below modulus, one above (23-bit candidate >= FIELD_MODULUS).
        let rnd = [1u8, 0, 0, 0xFF, 0xFF, 0x7F];
        let n = rejection_sample_less_than_field_modulus(&rnd, &mut out);
        assert!(n >= 1);
        assert!(out[0] < FIELD_MODULUS);
        let n2 = rejection_sample_less_than_field_modulus(&[0xFF, 0xFF, 0x7F], &mut out);
        assert_eq!(n2, 0);
    }

    #[test]
    fn rejection_eta2_nibbles_high_and_low() {
        let mut out = [0i32; 64];
        // 0xF0: high nibble 15 (reject), low 0 (accept path for try_0 < 15).
        // 0x0F: low nibble 15 (reject), high 0 (accept).
        let rnd = [0xF0u8, 0x0F, 0x11];
        let n = rejection_sample_less_than_eta_equals_2(&rnd, &mut out);
        assert!(n >= 2);
        for &x in &out[..n] {
            assert!((-2..=2).contains(&x));
        }
    }

    #[test]
    fn rejection_eta4_both_halves() {
        let mut out = [0i32; 64];
        // try_0=8 -> 4-8=-4, try_1=8 -> -4; both < 9.
        let rnd = [0x88u8, 0xFF, 0xFF];
        let n = rejection_sample_less_than_eta_equals_4(&rnd, &mut out);
        assert!(n >= 2);
        for &x in &out[..n] {
            assert!((-4..=4).contains(&x));
        }
    }
}
