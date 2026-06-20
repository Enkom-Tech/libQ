use crate::constants::{
    GAMMA2_V95_232,
    GAMMA2_V261_888,
};
use crate::simd::traits::*;

fn test_decompose_generic<SIMDUnit: Operations>() {
    // When GAMMA2 = 95,232
    let mut input = SIMDUnit::zero();
    SIMDUnit::from_coefficient_array(
        &[
            5520769, 5416853, 180455, 8127421, 5159850, 5553986, 3391280, 3968290,
        ],
        &mut input,
    );

    let expected_low = [-2687, 83861, -10009, -62531, 17322, 30530, -37072, -31454];
    let expected_high = [29, 28, 1, 43, 27, 29, 18, 21];

    let (mut low, mut high) = (SIMDUnit::zero(), SIMDUnit::zero());
    SIMDUnit::decompose(GAMMA2_V95_232, &input, &mut low, &mut high);

    let mut out = [0i32; COEFFICIENTS_IN_SIMD_UNIT];
    SIMDUnit::to_coefficient_array(&low, &mut out);
    assert_eq!(out, expected_low);

    let mut out = [0i32; COEFFICIENTS_IN_SIMD_UNIT];
    SIMDUnit::to_coefficient_array(&high, &mut out);
    assert_eq!(out, expected_high);

    // When GAMMA2 = 261,888
    let mut input = SIMDUnit::zero();
    SIMDUnit::from_coefficient_array(
        &[
            2108939, 7162128, 6506792, 7957464, 2350341, 8333084, 496214, 2168929,
        ],
        &mut input,
    );

    let expected_low = [
        13835, -170736, 221480, 100824, 255237, -47333, -27562, 73825,
    ];
    let expected_high = [4, 14, 12, 15, 4, 0, 1, 4];

    SIMDUnit::decompose(GAMMA2_V261_888, &input, &mut low, &mut high);

    let mut out = [0i32; COEFFICIENTS_IN_SIMD_UNIT];
    SIMDUnit::to_coefficient_array(&low, &mut out);
    assert_eq!(out, expected_low);

    let mut out = [0i32; COEFFICIENTS_IN_SIMD_UNIT];
    SIMDUnit::to_coefficient_array(&high, &mut out);
    assert_eq!(out, expected_high);
}

fn test_power2round_generic<SIMDUnit: Operations>() {
    let mut input = SIMDUnit::zero();
    SIMDUnit::from_coefficient_array(
        &[
            6950677, 3362411, 5783989, 5909314, 6459529, 5751812, 864332, 3667708,
        ],
        &mut input,
    );

    let expected_low = [3861, 3691, 437, 2882, -3959, 1028, -4020, -2308];
    let expected_high = [848, 410, 706, 721, 789, 702, 106, 448];

    let mut high = SIMDUnit::zero();
    SIMDUnit::from_coefficient_array(&[0; 8], &mut high);
    SIMDUnit::power2round(&mut input, &mut high);
    let low = input;

    let mut out = [0i32; COEFFICIENTS_IN_SIMD_UNIT];
    SIMDUnit::to_coefficient_array(&low, &mut out);
    assert_eq!(out, expected_low);

    let mut out = [0i32; COEFFICIENTS_IN_SIMD_UNIT];
    SIMDUnit::to_coefficient_array(&high, &mut out);
    assert_eq!(out, expected_high);
}

#[cfg(not(feature = "simd256"))]
mod portable {
    use super::{
        test_decompose_generic,
        test_power2round_generic,
    };

    #[test]
    fn test_decompose() {
        test_decompose_generic::<crate::simd::portable::PortableSIMDUnit>();
    }
    #[test]
    fn test_power2round() {
        test_power2round_generic::<crate::simd::portable::PortableSIMDUnit>();
    }
}

#[cfg(feature = "simd256")]
mod avx2 {
    use super::{
        test_decompose_generic,
        test_power2round_generic,
    };

    #[test]
    fn test_decompose() {
        test_decompose_generic::<crate::simd::avx2::AVX2SIMDUnit>();
    }
    #[test]
    fn test_power2round() {
        test_power2round_generic::<crate::simd::avx2::AVX2SIMDUnit>();
    }
}

// Differential tests: the AVX2 backend must agree byte-for-byte with the portable backend on every
// sign/verify-relevant op. (keygen already matches, so NTT/multiply/sampling are fine; this pins the
// remaining ops that only sign/verify exercise.) Both backends compile together under `simd256`.
#[cfg(feature = "simd256")]
mod avx2_vs_portable {
    use crate::simd::avx2::AVX2SIMDUnit;
    use crate::simd::portable::PortableSIMDUnit;
    use crate::simd::traits::{
        COEFFICIENTS_IN_SIMD_UNIT as N,
        Operations,
    };

    // Deterministic SplitMix64 — reproducible pseudo-random inputs without an rng dep.
    fn next(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn load<S: Operations>(coeffs: &[i32; N]) -> S {
        let mut u = S::zero();
        S::from_coefficient_array(coeffs, &mut u);
        u
    }

    #[test]
    fn commitment_serialize_matches() {
        let mut st = 0x1234_5678_9ABC_DEF0u64;
        // ML-DSA-44: w1 in [0, 43], packed 6 bits/coeff -> 6 bytes (serialize_6 path).
        for _ in 0..2000 {
            let coeffs: [i32; N] = core::array::from_fn(|_| (next(&mut st) % 44) as i32);
            let mut po = [0u8; 6];
            let mut ao = [0u8; 6];
            PortableSIMDUnit::commitment_serialize(&load::<PortableSIMDUnit>(&coeffs), &mut po);
            AVX2SIMDUnit::commitment_serialize(&load::<AVX2SIMDUnit>(&coeffs), &mut ao);
            assert_eq!(po, ao, "commitment_serialize(6B) mismatch for {coeffs:?}");
        }
        // ML-DSA-65/87: w1 in [0, 15], packed 4 bits/coeff -> 4 bytes (serialize_4 path).
        for _ in 0..2000 {
            let coeffs: [i32; N] = core::array::from_fn(|_| (next(&mut st) % 16) as i32);
            let mut po = [0u8; 4];
            let mut ao = [0u8; 4];
            PortableSIMDUnit::commitment_serialize(&load::<PortableSIMDUnit>(&coeffs), &mut po);
            AVX2SIMDUnit::commitment_serialize(&load::<AVX2SIMDUnit>(&coeffs), &mut ao);
            assert_eq!(po, ao, "commitment_serialize(4B) mismatch for {coeffs:?}");
        }
    }

    fn dump<S: Operations>(u: &S) -> [i32; N] {
        let mut out = [0i32; N];
        S::to_coefficient_array(u, &mut out);
        out
    }

    #[test]
    fn gamma1_serialize_matches() {
        let mut st = 0xDEAD_BEEF_CAFE_0001u64;
        // exp 17: coeff = 2^17 - r, r in [0, 2^18) -> 18-byte output. exp 19: 2^19 - r, r in [0,2^20) -> 20B.
        for &(exp, bytes, bits) in &[(17usize, 18usize, 18u32), (19, 20, 20)] {
            let gamma1 = 1i32 << exp;
            for _ in 0..2000 {
                let coeffs: [i32; N] =
                    core::array::from_fn(|_| gamma1 - (next(&mut st) % (1 << bits)) as i32);
                let (mut po, mut ao) = ([0u8; 20], [0u8; 20]);
                PortableSIMDUnit::gamma1_serialize(
                    &load::<PortableSIMDUnit>(&coeffs),
                    &mut po[..bytes],
                    exp,
                );
                AVX2SIMDUnit::gamma1_serialize(
                    &load::<AVX2SIMDUnit>(&coeffs),
                    &mut ao[..bytes],
                    exp,
                );
                assert_eq!(
                    po, ao,
                    "gamma1_serialize(exp={exp}) mismatch for {coeffs:?}"
                );
            }
        }
    }

    #[test]
    fn decompose_full_range_matches() {
        use crate::constants::FIELD_MODULUS;
        let mut st = 0x0BAD_F00D_0000_0003u64;
        for gamma2 in [
            crate::constants::GAMMA2_V95_232,
            crate::constants::GAMMA2_V261_888,
        ] {
            for _ in 0..20000 {
                let coeffs: [i32; N] =
                    core::array::from_fn(|_| (next(&mut st) % FIELD_MODULUS as u64) as i32);
                let (mut pl, mut ph) = (PortableSIMDUnit::zero(), PortableSIMDUnit::zero());
                let (mut al, mut ah) = (AVX2SIMDUnit::zero(), AVX2SIMDUnit::zero());
                PortableSIMDUnit::decompose(
                    gamma2,
                    &load::<PortableSIMDUnit>(&coeffs),
                    &mut pl,
                    &mut ph,
                );
                AVX2SIMDUnit::decompose(gamma2, &load::<AVX2SIMDUnit>(&coeffs), &mut al, &mut ah);
                assert_eq!(
                    dump(&pl),
                    dump(&al),
                    "decompose low mismatch for {coeffs:?}"
                );
                assert_eq!(
                    dump(&ph),
                    dump(&ah),
                    "decompose high mismatch for {coeffs:?}"
                );
            }
        }
    }

    #[test]
    fn infinity_norm_matches() {
        let mut st = 0xABCD_1234_0000_0004u64;
        // signed centered coefficients and a spread of bounds.
        for _ in 0..20000 {
            let coeffs: [i32; N] =
                core::array::from_fn(|_| (next(&mut st) % 8_380_417) as i32 - 4_190_208);
            for &bound in &[1i32, 2, 1024, 95_232, 131_072, 261_888, 1 << 20] {
                let p = PortableSIMDUnit::infinity_norm_exceeds(
                    &load::<PortableSIMDUnit>(&coeffs),
                    bound,
                );
                let a = AVX2SIMDUnit::infinity_norm_exceeds(&load::<AVX2SIMDUnit>(&coeffs), bound);
                assert_eq!(
                    p, a,
                    "infinity_norm_exceeds(bound={bound}) mismatch for {coeffs:?}"
                );
            }
        }
    }

    #[test]
    fn compute_and_use_hint_match() {
        use crate::constants::FIELD_MODULUS;
        // compute_hint runs in the signing rejection loop; use_hint runs in verify.
        for &(g2enum, g2raw) in &[
            (crate::constants::GAMMA2_V95_232, 95_232i32),
            (crate::constants::GAMMA2_V261_888, 261_888i32),
        ] {
            let mut st = 0x5151_2727_0000_0005u64;
            for _ in 0..20000 {
                // make_hint receives `low`/`high` that are NOT decompose outputs: `low` can exceed
                // gamma2 (that's what sets a hint). Feed independent values spanning +/- ~2*gamma2 so
                // both the hint bits AND the returned count are exercised (a decompose-bounded `low`
                // would never set a hint, hiding count bugs).
                let span = (4 * g2raw) as u64;
                let low: [i32; N] =
                    core::array::from_fn(|_| (next(&mut st) % span) as i32 - 2 * g2raw);
                let high: [i32; N] = core::array::from_fn(|_| (next(&mut st) % 45) as i32 - 1);
                let (mut phint, mut ahint) = (PortableSIMDUnit::zero(), AVX2SIMDUnit::zero());
                let pn = PortableSIMDUnit::compute_hint(
                    &load::<PortableSIMDUnit>(&low),
                    &load::<PortableSIMDUnit>(&high),
                    g2raw,
                    &mut phint,
                );
                let an = AVX2SIMDUnit::compute_hint(
                    &load::<AVX2SIMDUnit>(&low),
                    &load::<AVX2SIMDUnit>(&high),
                    g2raw,
                    &mut ahint,
                );
                assert_eq!(
                    pn, an,
                    "compute_hint count mismatch (g2={g2raw}) low {low:?} high {high:?}"
                );
                assert_eq!(
                    dump(&phint),
                    dump(&ahint),
                    "compute_hint bits mismatch (g2={g2raw})"
                );

                // use_hint: random coeff + random 0/1 hint bits.
                let coeffs: [i32; N] =
                    core::array::from_fn(|_| (next(&mut st) % FIELD_MODULUS as u64) as i32);
                let bits: [i32; N] = core::array::from_fn(|_| (next(&mut st) & 1) as i32);
                let mut ph2 = load::<PortableSIMDUnit>(&bits);
                let mut ah2 = load::<AVX2SIMDUnit>(&bits);
                PortableSIMDUnit::use_hint(g2enum, &load::<PortableSIMDUnit>(&coeffs), &mut ph2);
                AVX2SIMDUnit::use_hint(g2enum, &load::<AVX2SIMDUnit>(&coeffs), &mut ah2);
                assert_eq!(
                    dump(&ph2),
                    dump(&ah2),
                    "use_hint mismatch (g2={g2raw}) coeffs {coeffs:?} bits {bits:?}"
                );
            }
        }
    }

    #[test]
    fn ntt_invntt_reduce_full_ring_match() {
        use crate::constants::FIELD_MODULUS;
        use crate::simd::traits::SIMD_UNITS_IN_RING_ELEMENT as U;
        let mut st = 0xC0FF_EE00_0000_0008u64;
        for _ in 0..2000 {
            // 256 coefficients spanning the full reduced range (signing feeds large values).
            let coeffs: [[i32; N]; U] = core::array::from_fn(|_| {
                core::array::from_fn(|_| {
                    (next(&mut st) % FIELD_MODULUS as u64) as i32 - (FIELD_MODULUS / 2)
                })
            });
            let mut pr: [PortableSIMDUnit; U] =
                core::array::from_fn(|i| load::<PortableSIMDUnit>(&coeffs[i]));
            let mut ar: [AVX2SIMDUnit; U] =
                core::array::from_fn(|i| load::<AVX2SIMDUnit>(&coeffs[i]));
            PortableSIMDUnit::ntt(&mut pr);
            AVX2SIMDUnit::ntt(&mut ar);
            for i in 0..U {
                assert_eq!(dump(&pr[i]), dump(&ar[i]), "ntt mismatch unit {i}");
            }
            PortableSIMDUnit::invert_ntt_montgomery(&mut pr);
            AVX2SIMDUnit::invert_ntt_montgomery(&mut ar);
            for i in 0..U {
                assert_eq!(dump(&pr[i]), dump(&ar[i]), "invntt mismatch unit {i}");
            }
            PortableSIMDUnit::reduce(&mut pr);
            AVX2SIMDUnit::reduce(&mut ar);
            for i in 0..U {
                assert_eq!(dump(&pr[i]), dump(&ar[i]), "reduce mismatch unit {i}");
            }
        }
    }

    #[test]
    fn montgomery_multiply_matches() {
        // Signing multiplies large (gamma1-bounded) operands that keygen (eta-bounded) never hits.
        let mut st = 0x7777_6666_0000_0007u64;
        for _ in 0..40000 {
            let a: [i32; N] =
                core::array::from_fn(|_| (next(&mut st) % 8_380_417) as i32 - 4_190_208);
            let b: [i32; N] =
                core::array::from_fn(|_| (next(&mut st) % 8_380_417) as i32 - 4_190_208);
            let mut pa = load::<PortableSIMDUnit>(&a);
            let mut aa = load::<AVX2SIMDUnit>(&a);
            PortableSIMDUnit::montgomery_multiply(&mut pa, &load::<PortableSIMDUnit>(&b));
            AVX2SIMDUnit::montgomery_multiply(&mut aa, &load::<AVX2SIMDUnit>(&b));
            assert_eq!(
                dump(&pa),
                dump(&aa),
                "montgomery_multiply mismatch a={a:?} b={b:?}"
            );
        }
    }

    #[test]
    fn shift_left_then_reduce_matches() {
        let mut st = 0x9999_8888_0000_0006u64;
        // SHIFT_BY = 13 (BITS_IN_LOWER_PART_OF_T), the t1*2^d reconstruction used in verify.
        // Domain: t1 coefficients are 10-bit ([0, 2^10)).
        for _ in 0..20000 {
            let coeffs: [i32; N] = core::array::from_fn(|_| (next(&mut st) % (1 << 10)) as i32);
            let mut p = load::<PortableSIMDUnit>(&coeffs);
            let mut a = load::<AVX2SIMDUnit>(&coeffs);
            PortableSIMDUnit::shift_left_then_reduce::<13>(&mut p);
            AVX2SIMDUnit::shift_left_then_reduce::<13>(&mut a);
            assert_eq!(
                dump(&p),
                dump(&a),
                "shift_left_then_reduce<13> mismatch for {coeffs:?}"
            );
        }
    }

    #[test]
    fn error_and_t0_deserialize_match() {
        use crate::constants::Eta;
        let mut st = 0x3141_5926_0000_0009u64;
        // s1/s2 decode (error_deserialize) and t0 decode (t0_deserialize) run ONLY in signing
        // (reading the secret key) — keygen encodes, verify never touches them.
        for &(eta, bytes) in &[(Eta::Two, 3usize), (Eta::Four, 4usize)] {
            for _ in 0..4000 {
                let mut ser = [0u8; 4];
                for b in ser[..bytes].iter_mut() {
                    *b = (next(&mut st) & 0xFF) as u8;
                }
                let mut p = PortableSIMDUnit::zero();
                let mut a = AVX2SIMDUnit::zero();
                PortableSIMDUnit::error_deserialize(eta, &ser[..bytes], &mut p);
                AVX2SIMDUnit::error_deserialize(eta, &ser[..bytes], &mut a);
                assert_eq!(
                    dump(&p),
                    dump(&a),
                    "error_deserialize(eta {bytes}B) mismatch bytes {:?}",
                    &ser[..bytes]
                );
            }
        }
        // t0: 13 bits/coeff -> 13 bytes per SIMD unit.
        for _ in 0..4000 {
            let mut ser = [0u8; 13];
            for b in ser.iter_mut() {
                *b = (next(&mut st) & 0xFF) as u8;
            }
            let mut p = PortableSIMDUnit::zero();
            let mut a = AVX2SIMDUnit::zero();
            PortableSIMDUnit::t0_deserialize(&ser, &mut p);
            AVX2SIMDUnit::t0_deserialize(&ser, &mut a);
            assert_eq!(dump(&p), dump(&a), "t0_deserialize mismatch bytes {ser:?}");
        }
    }

    #[test]
    fn gamma1_deserialize_matches() {
        let mut st = 0xFEED_FACE_0000_0002u64;
        // ExpandMask (sign) and z-decode (verify) both route through this; keygen never does.
        for &(exp, bytes) in &[(17usize, 18usize), (19, 20)] {
            for _ in 0..2000 {
                let mut ser = [0u8; 20];
                for b in ser[..bytes].iter_mut() {
                    *b = (next(&mut st) & 0xFF) as u8;
                }
                let mut p = PortableSIMDUnit::zero();
                let mut a = AVX2SIMDUnit::zero();
                PortableSIMDUnit::gamma1_deserialize(&ser[..bytes], &mut p, exp);
                AVX2SIMDUnit::gamma1_deserialize(&ser[..bytes], &mut a, exp);
                assert_eq!(
                    dump(&p),
                    dump(&a),
                    "gamma1_deserialize(exp={exp}) mismatch for bytes {:?}",
                    &ser[..bytes]
                );
            }
        }
    }
}
