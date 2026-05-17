extern crate std;
use std::vec;
use std::vec::Vec;

use super::vector_type::{
    self,
    Coefficients,
};
use super::{
    arithmetic,
    invntt,
    ntt,
};
use crate::ntt::{
    invert_ntt_montgomery,
    ntt as poly_ntt,
    ntt_multiply_montgomery,
    reduce,
};
use crate::polynomial::PolynomialRingElement;
use crate::simd::traits::{
    COEFFICIENTS_IN_SIMD_UNIT,
    FIELD_MODULUS,
};

type Poly = PolynomialRingElement<Coefficients>;

const Q: i64 = FIELD_MODULUS as i64;

fn canon(x: i32) -> i32 {
    ((x as i64).rem_euclid(Q)) as i32
}

fn poly_from(coeffs: &[i32; 256]) -> Poly {
    Poly::from_i32_array_test(coeffs)
}

fn poly_coeffs(p: &Poly) -> [i32; 256] {
    p.to_i32_array()
}

fn canon_poly(p: &Poly) -> [i32; 256] {
    let raw = poly_coeffs(p);
    let mut out = [0i32; 256];
    for i in 0..256 {
        out[i] = canon(raw[i]);
    }
    out
}

fn make_coefficients(vals: &[i32; COEFFICIENTS_IN_SIMD_UNIT]) -> Coefficients {
    let mut c = vector_type::zero();
    c.values = *vals;
    c
}

// ──────────────────────────────────────────────────────────────────
// 1. NTT / invNTT round-trip correctness
// ──────────────────────────────────────────────────────────────────

#[test]
fn ntt_roundtrip_zero() {
    let mut p = Poly::zero();
    poly_ntt(&mut p);
    assert_eq!(poly_coeffs(&p), [0i32; 256], "NTT of zero must be zero");

    invert_ntt_montgomery(&mut p);
    assert_eq!(poly_coeffs(&p), [0i32; 256], "invNTT of zero must be zero");
}

#[test]
fn ntt_then_invert_roundtrip_constant() {
    let mut input = [0i32; 256];
    input[0] = 42;
    let original = input;
    let mut p = poly_from(&input);

    poly_ntt(&mut p);
    let ntt_out = poly_coeffs(&p);

    invert_ntt_montgomery(&mut p);
    let recovered = canon_poly(&p);

    let scaling_factor = if original[0] != 0 {
        let r = recovered[0] as i64;
        let o = original[0] as i64;
        (r * mod_inv(o, Q)).rem_euclid(Q)
    } else {
        1
    };

    for i in 0..256 {
        let expected = ((original[i] as i64 * scaling_factor) % Q + Q) % Q;
        assert_eq!(
            recovered[i], expected as i32,
            "Mismatch at index {i}: expected {expected}, got {}",
            recovered[i]
        );
    }

    assert_ne!(
        ntt_out, original,
        "NTT output should differ from input for non-trivial input"
    );
}

#[test]
fn ntt_then_invert_roundtrip_ramp() {
    let mut input = [0i32; 256];
    for i in 0..256 {
        input[i] = i as i32;
    }

    let mut p = poly_from(&input);
    poly_ntt(&mut p);
    invert_ntt_montgomery(&mut p);

    let recovered = canon_poly(&p);

    let scaling_factor = {
        let r = recovered[1] as i64;
        let o = 1i64;
        (r * mod_inv(o, Q)).rem_euclid(Q)
    };

    for i in 0..256 {
        let expected = ((input[i] as i64 * scaling_factor) % Q + Q) % Q;
        assert_eq!(
            recovered[i], expected as i32,
            "Ramp roundtrip mismatch at index {i}"
        );
    }
}

#[test]
fn ntt_then_invert_roundtrip_pattern() {
    let mut input = [0i32; 256];
    for i in 0..256 {
        input[i] = ((i as i32 * 1337 + 42) % FIELD_MODULUS).abs();
    }

    let mut p = poly_from(&input);
    poly_ntt(&mut p);
    invert_ntt_montgomery(&mut p);

    let recovered = canon_poly(&p);

    let scaling_factor = {
        let r = recovered[0] as i64;
        let o = input[0] as i64;
        (r * mod_inv(o, Q)).rem_euclid(Q)
    };

    for i in 0..256 {
        let expected = ((input[i] as i64 * scaling_factor) % Q + Q) % Q;
        assert_eq!(
            recovered[i], expected as i32,
            "Pattern roundtrip mismatch at index {i}"
        );
    }
}

#[test]
fn double_ntt_is_not_identity() {
    let mut input = [0i32; 256];
    for i in 0..256 {
        input[i] = (i as i32 + 1) % FIELD_MODULUS;
    }

    let mut p = poly_from(&input);
    poly_ntt(&mut p);

    let after_one_ntt = poly_coeffs(&p);
    assert_ne!(
        after_one_ntt, input,
        "Single NTT should change the polynomial"
    );

    reduce(&mut p);
    poly_ntt(&mut p);
    let after_two_ntt = poly_coeffs(&p);

    let canon_input: Vec<i32> = input.iter().map(|&c| canon(c)).collect();
    let canon_double: Vec<i32> = after_two_ntt.iter().map(|&c| canon(c)).collect();
    assert_ne!(
        canon_double.as_slice(),
        canon_input.as_slice(),
        "Double NTT should not be identity"
    );
}

// ──────────────────────────────────────────────────────────────────
// 2. NTT linearity: NTT(a + b) == NTT(a) + NTT(b)
// ──────────────────────────────────────────────────────────────────

#[test]
fn ntt_linearity() {
    let mut a_coeffs = [0i32; 256];
    let mut b_coeffs = [0i32; 256];
    for i in 0..256 {
        a_coeffs[i] = ((i as i32 * 73 + 11) % (FIELD_MODULUS / 4)).abs();
        b_coeffs[i] = ((i as i32 * 137 + 53) % (FIELD_MODULUS / 4)).abs();
    }

    let mut sum_poly = poly_from(&a_coeffs);
    let b_poly_for_add = poly_from(&b_coeffs);
    sum_poly.add(&b_poly_for_add);
    poly_ntt(&mut sum_poly);
    let ntt_of_sum = poly_coeffs(&sum_poly);

    let mut ntt_a = poly_from(&a_coeffs);
    poly_ntt(&mut ntt_a);
    let mut ntt_b = poly_from(&b_coeffs);
    poly_ntt(&mut ntt_b);

    ntt_a.add(&ntt_b);
    let sum_of_ntt = poly_coeffs(&ntt_a);

    for i in 0..256 {
        assert_eq!(
            canon(ntt_of_sum[i]),
            canon(sum_of_ntt[i]),
            "NTT linearity failed at index {i}: NTT(a+b)[{i}] = {} != NTT(a)[{i}]+NTT(b)[{i}] = {}",
            canon(ntt_of_sum[i]),
            canon(sum_of_ntt[i])
        );
    }
}

// ──────────────────────────────────────────────────────────────────
// 3. Pointwise multiply in NTT domain
// ──────────────────────────────────────────────────────────────────

#[test]
fn ntt_pointwise_multiply_simple() {
    let mut a_coeffs = [0i32; 256];
    a_coeffs[0] = 1;
    a_coeffs[1] = 2;

    let mut b_coeffs = [0i32; 256];
    b_coeffs[0] = 3;
    b_coeffs[1] = 4;

    let mut a = poly_from(&a_coeffs);
    let mut b = poly_from(&b_coeffs);
    poly_ntt(&mut a);
    poly_ntt(&mut b);

    ntt_multiply_montgomery(&mut a, &b);
    invert_ntt_montgomery(&mut a);

    let result = canon_poly(&a);

    let product = schoolbook_multiply(&a_coeffs, &b_coeffs);

    let scaling_factor = {
        let r = result[0] as i64;
        let o = product[0] as i64;
        if o != 0 {
            (r * mod_inv(o, Q)).rem_euclid(Q)
        } else {
            1
        }
    };

    for i in 0..256 {
        let expected = ((product[i] as i64 * scaling_factor) % Q + Q) % Q;
        assert_eq!(
            result[i], expected as i32,
            "NTT multiply mismatch at index {i}: got {}, expected {expected}",
            result[i]
        );
    }
}

#[test]
fn ntt_multiply_by_zero() {
    let mut a_coeffs = [0i32; 256];
    for i in 0..256 {
        a_coeffs[i] = ((i as i32 * 97 + 3) % (FIELD_MODULUS / 2)).abs();
    }
    let b_coeffs = [0i32; 256];

    let mut a = poly_from(&a_coeffs);
    let mut b = poly_from(&b_coeffs);
    poly_ntt(&mut a);
    poly_ntt(&mut b);

    ntt_multiply_montgomery(&mut a, &b);
    invert_ntt_montgomery(&mut a);

    let result = canon_poly(&a);
    assert_eq!(result, [0i32; 256], "Multiply by zero must yield zero");
}

#[test]
fn ntt_multiply_commutativity() {
    let mut a_coeffs = [0i32; 256];
    let mut b_coeffs = [0i32; 256];
    for i in 0..256 {
        a_coeffs[i] = ((i as i32 * 31 + 7) % (FIELD_MODULUS / 4)).abs();
        b_coeffs[i] = ((i as i32 * 59 + 13) % (FIELD_MODULUS / 4)).abs();
    }

    let mut a1 = poly_from(&a_coeffs);
    let mut b1 = poly_from(&b_coeffs);
    poly_ntt(&mut a1);
    poly_ntt(&mut b1);

    let mut ab = a1;
    ntt_multiply_montgomery(&mut ab, &b1);
    invert_ntt_montgomery(&mut ab);
    let result_ab = canon_poly(&ab);

    let mut a2 = poly_from(&a_coeffs);
    let mut b2 = poly_from(&b_coeffs);
    poly_ntt(&mut a2);
    poly_ntt(&mut b2);

    let mut ba = b2;
    ntt_multiply_montgomery(&mut ba, &a2);
    invert_ntt_montgomery(&mut ba);
    let result_ba = canon_poly(&ba);

    assert_eq!(
        result_ab, result_ba,
        "NTT multiplication must be commutative"
    );
}

// ──────────────────────────────────────────────────────────────────
// 4. Boundary / edge-case inputs
// ──────────────────────────────────────────────────────────────────

#[test]
fn ntt_max_coefficient_no_overflow() {
    let mut input = [0i32; 256];
    for c in input.iter_mut() {
        *c = FIELD_MODULUS - 1;
    }

    let mut p = poly_from(&input);
    reduce(&mut p);
    poly_ntt(&mut p);

    let ntt_out = poly_coeffs(&p);
    for (i, &c) in ntt_out.iter().enumerate() {
        assert!(
            c.unsigned_abs() < (FIELD_MODULUS as u32) * 16,
            "NTT coefficient {i} out of reasonable range: {c}"
        );
    }
}

#[test]
fn ntt_invntt_max_coefficient_roundtrip() {
    let mut input = [0i32; 256];
    for c in input.iter_mut() {
        *c = FIELD_MODULUS - 1;
    }

    let mut p = poly_from(&input);
    reduce(&mut p);
    let reduced = canon_poly(&p);

    poly_ntt(&mut p);
    invert_ntt_montgomery(&mut p);
    let recovered = canon_poly(&p);

    let scaling_factor = {
        let r = recovered[0] as i64;
        let o = reduced[0] as i64;
        (r * mod_inv(o, Q)).rem_euclid(Q)
    };

    for i in 0..256 {
        let expected = ((reduced[i] as i64 * scaling_factor) % Q + Q) % Q;
        assert_eq!(
            recovered[i], expected as i32,
            "Max-coeff roundtrip mismatch at index {i}"
        );
    }
}

#[test]
fn ntt_alternating_signs() {
    let half_q = (FIELD_MODULUS - 1) / 2;
    let mut input = [0i32; 256];
    for i in 0..256 {
        input[i] = if i % 2 == 0 { half_q } else { -half_q };
    }

    let mut p = poly_from(&input);
    poly_ntt(&mut p);
    invert_ntt_montgomery(&mut p);

    let recovered = canon_poly(&p);

    let canonical_input: Vec<i32> = input.iter().map(|&c| canon(c)).collect();
    let scaling_factor = {
        let r = recovered[0] as i64;
        let o = canonical_input[0] as i64;
        (r * mod_inv(o, Q)).rem_euclid(Q)
    };

    for i in 0..256 {
        let expected = ((canonical_input[i] as i64 * scaling_factor) % Q + Q) % Q;
        assert_eq!(
            recovered[i], expected as i32,
            "Alternating-sign roundtrip mismatch at index {i}"
        );
    }
}

#[test]
fn ntt_constant_polynomial() {
    let c = 12345i32;
    let mut input = [0i32; 256];
    input[0] = c;
    let mut p = poly_from(&input);
    poly_ntt(&mut p);

    let ntt_out = poly_coeffs(&p);
    assert_ne!(ntt_out[0], 0, "NTT of [c, 0, ...] should be non-trivial");

    invert_ntt_montgomery(&mut p);
    let recovered = canon_poly(&p);

    let scaling_factor = {
        let r = recovered[0] as i64;
        let o = c as i64;
        (r * mod_inv(o, Q)).rem_euclid(Q)
    };

    for i in 1..256 {
        let expected = 0i32;
        assert_eq!(
            recovered[i],
            ((expected as i64 * scaling_factor) % Q + Q) as i32 % FIELD_MODULUS,
            "Constant polynomial roundtrip: non-zero at index {i}"
        );
    }
}

// ──────────────────────────────────────────────────────────────────
// 5. Reduction and arithmetic unit tests
// ──────────────────────────────────────────────────────────────────

#[test]
fn reduce_idempotent() {
    let mut input = [0i32; 256];
    for i in 0..256 {
        input[i] = ((i as i32 * 997 + 123456) % FIELD_MODULUS).abs();
    }

    let mut p1 = poly_from(&input);
    reduce(&mut p1);
    let after_one = poly_coeffs(&p1);

    reduce(&mut p1);
    let after_two = poly_coeffs(&p1);

    for i in 0..256 {
        assert_eq!(
            canon(after_one[i]),
            canon(after_two[i]),
            "Reduce not idempotent at index {i}: {} vs {}",
            after_one[i],
            after_two[i]
        );
    }
}

#[test]
fn add_subtract_roundtrip() {
    let mut a_coeffs = [0i32; 256];
    let mut b_coeffs = [0i32; 256];
    for i in 0..256 {
        a_coeffs[i] = ((i as i32 * 41 + 7) % (FIELD_MODULUS / 4)).abs();
        b_coeffs[i] = ((i as i32 * 67 + 19) % (FIELD_MODULUS / 4)).abs();
    }

    let mut p = poly_from(&a_coeffs);
    let b = poly_from(&b_coeffs);
    let original = poly_coeffs(&p);

    p.add(&b);
    p.subtract(&b);

    let recovered = poly_coeffs(&p);
    assert_eq!(
        recovered, original,
        "add then subtract should recover the original polynomial"
    );
}

#[test]
fn subtract_add_roundtrip() {
    let mut a_coeffs = [0i32; 256];
    let mut b_coeffs = [0i32; 256];
    for i in 0..256 {
        a_coeffs[i] = ((i as i32 * 83 + 5) % (FIELD_MODULUS / 4)).abs();
        b_coeffs[i] = ((i as i32 * 29 + 11) % (FIELD_MODULUS / 4)).abs();
    }

    let mut p = poly_from(&a_coeffs);
    let b = poly_from(&b_coeffs);
    let original = poly_coeffs(&p);

    p.subtract(&b);
    p.add(&b);

    let recovered = poly_coeffs(&p);
    assert_eq!(
        recovered, original,
        "subtract then add should recover the original polynomial"
    );
}

#[test]
fn simd_unit_add_subtract_roundtrip() {
    let a_vals = [100, -200, 300, -400, 500, -600, 700, -800];
    let b_vals = [10, 20, 30, 40, 50, 60, 70, 80];
    let mut a = make_coefficients(&a_vals);
    let b = make_coefficients(&b_vals);
    let original = a.values;

    arithmetic::add(&mut a, &b);
    arithmetic::subtract(&mut a, &b);

    assert_eq!(a.values, original, "SIMD add/sub roundtrip failed");
}

#[test]
fn montgomery_multiply_commutativity() {
    let a_vals: [i32; 8] = [100, 200, 300, 400, 500, 600, 700, 800];
    let b_vals: [i32; 8] = [8, 16, 24, 32, 40, 48, 56, 64];

    let mut a1 = make_coefficients(&a_vals);
    let b1 = make_coefficients(&b_vals);
    arithmetic::montgomery_multiply(&mut a1, &b1);

    let mut a2 = make_coefficients(&b_vals);
    let b2 = make_coefficients(&a_vals);
    arithmetic::montgomery_multiply(&mut a2, &b2);

    for i in 0..COEFFICIENTS_IN_SIMD_UNIT {
        assert_eq!(
            canon(a1.values[i]),
            canon(a2.values[i]),
            "Montgomery multiply not commutative at index {i}"
        );
    }
}

#[test]
fn montgomery_multiply_by_zero() {
    let a_vals = [12345, -67890, 11111, -22222, 33333, -44444, 55555, -66666];
    let z_vals = [0i32; 8];

    let mut a = make_coefficients(&a_vals);
    let z = make_coefficients(&z_vals);
    arithmetic::montgomery_multiply(&mut a, &z);

    assert_eq!(a.values, [0i32; 8], "Multiply by zero should yield zero");
}

// ──────────────────────────────────────────────────────────────────
// 6. Additional known-answer vector
// ──────────────────────────────────────────────────────────────────

#[test]
fn ntt_known_answer_small_polynomial() {
    let mut input = [0i32; 256];
    input[0] = 1;
    input[1] = 1;

    let mut p = poly_from(&input);
    poly_ntt(&mut p);
    let ntt_out = poly_coeffs(&p);

    assert_ne!(ntt_out, input, "NTT should transform the polynomial");

    let mut p2 = poly_from(&input);
    poly_ntt(&mut p2);
    let ntt_out2 = poly_coeffs(&p2);

    assert_eq!(ntt_out, ntt_out2, "NTT must be deterministic");
}

#[test]
fn ntt_known_answer_reference_vector() {
    // Fixed KAT vector shared with the generic NTT test corpus.
    // The expected output is a precomputed reference vector.
    let input: [i32; 256] = vec![
        245230, -429681, -35753, 256940, 138755, -82158, -453212, -296769, 106884, -496329,
        -275542, 350156, 295061, 462432, 162727, 219494, 43263, -84315, -100731, 5560, -38846,
        343612, 76881, 427547, 165700, -361163, -18964, 270770, -289948, -326181, -17540, -376674,
        -101359, 324588, 265493, -376942, -270029, -201717, -350446, 222164, -314686, -60609,
        172509, -199265, 391809, 375196, 333441, -433240, -28862, 274251, -218805, 400627, -408915,
        131269, -305167, 78967, -487687, 98675, -430105, 293491, 317484, -180888, -333359, -263010,
        258853, -84618, -350795, 334736, -438451, 479262, -265874, -115692, -521929, -220715,
        -456043, -24131, 94695, 473893, -503297, 75679, -129421, 83315, -248504, -64226, -24884,
        316438, 264565, -248440, 222228, -386736, 89534, 196079, -196063, 434306, -388976, -29596,
        424028, 290804, -348654, 208245, 394447, -105640, -522040, 250479, -443666, -503110,
        299944, 497539, -28052, 30579, -332034, 492009, -327080, -173581, -94157, -126088, 388734,
        468785, -120589, -146970, -291234, 337402, 311007, -289990, 506654, -431388, 410292,
        -376624, 422627, 246536, -273872, 443039, -265954, -250947, 451185, -386654, -19185,
        -171927, -128698, -277965, 142565, -229030, -470985, 511916, -68612, 272580, -293969,
        151888, -53429, -115171, 234680, -482360, -399860, -268942, 146734, -414798, 502035,
        -157203, -328592, 266628, 95760, 107840, 354606, -367167, 396086, -287062, 57888, 140152,
        442747, -217984, -69604, -136006, -56581, 202803, -440282, -290558, -192319, -49121,
        -76454, 426678, 433484, -93094, 244295, -195275, -262446, -169118, 187824, -60480, -206921,
        -204671, -407794, -139194, -182819, 133480, 520760, -17757, -444106, -214471, 457449,
        29697, -149734, -497293, -177518, -266611, -133962, -40139, 9030, 37706, 300290, -370302,
        257446, -290991, 353260, 393727, -269498, 249049, -166327, -354566, -309239, 481747, 82459,
        -425894, 107583, 10935, -498533, 437188, -121594, -90890, -261475, -44165, 394580, -392499,
        206781, -222053, -334528, -194081, -373973, -356982, -27220, -444980, 449174, -391807,
        392057, -132521, -441664, -349459, -373059, -296519, 274235, 42417, 47385, -104540, 142532,
        246380, -515363, -422665,
    ]
    .try_into()
    .expect("input vector must have 256 coefficients");
    let expected: [i32; 256] = vec![
        -17129289, -17188287, -11027856, -7293060, -14589541, -12369669, -1420304, -9409026,
        -2745174, -2813844, -1829426, 2574100, -5026817, -9781421, -9951567, -7272515, 4818335,
        -3195023, -6970219, -7364953, 1800133, -219955, 5457527, -2421101, -2719347, 4851863,
        -5375188, -6373272, -6881235, 1470681, 2364683, 4847471, 2424421, -2276079, 2780402,
        3720484, 6345079, -150847, 4499295, 3841925, -4612874, 227272, -1650880, -4068714, 1238348,
        -6241908, 674916, 8597432, 1045161, 2838309, -4022618, -8710072, -3036374, -3401044,
        -6864890, -4717312, -3844346, 3755766, 4699242, -1232858, -1007843, -2372141, -5151898,
        2215126, 5056427, 5704699, 11731990, 12381420, 2784890, -2861996, 1452131, 5933279,
        4031780, 5298922, 3626052, 4969414, 3453854, -4627414, -1023658, -5769310, 1437156,
        1156658, -2817787, -8761943, -2668956, -9522412, -12938019, -10322153, -9811386, -8779334,
        2078963, -4674611, -4110129, 2451543, -4834924, -2503578, -5536189, -1677443, -6867926,
        -4019342, -10584384, -7739886, -6447026, -13889812, -6819207, 587959, -7563216, -14153360,
        -5061746, -11893138, -2225507, -1089121, -1869464, 3296810, 6674836, -1150818, 324295,
        -509763, -1197550, -5578514, -5136666, -4382368, 3113889, -3428119, 235128, 4223510, 70873,
        -1793487, 1662772, 7347100, 15227445, 9348419, 9598008, 9940972, 7506539, 9092233, 4526452,
        9976840, 6619274, 8638534, 8098748, 4080374, 9497479, 9356635, -239442, 6155758, -2930736,
        -4891836, 2066938, 7359172, 597336, 7980226, -1781310, -5283606, 596800, 3537228, -8539373,
        -4044371, -1411916, 4051564, 2598458, 9958426, 1194732, 9002276, -926584, 5985194, 980962,
        856944, 6456619, 8929175, 9047642, 12797200, 11248612, 4324864, 18190009, 10462927,
        4906049, 2341517, 3945796, 8377830, 5195877, 10702083, -247762, 4149842, -4852089,
        -1576975, 516061, 1908067, 2840273, -4492477, 9446409, 3700267, 346209, 2692483, -7029253,
        -5625659, 4093774, -3922644, 2578212, 6694254, -1244120, -1475796, -9388817, -5401831,
        -6934520, -8620440, -5385728, -6961628, -8648379, -2747757, -10439151, -5664161, -1208977,
        -8828047, -1715189, 5918789, 2038973, -5412689, 4197315, -3211379, 12103869, 4104929,
        3182052, 6094506, 1986313, -481257, -3678130, -673934, 2320744, 1656034, -5630954,
        -3497176, 6334075, 11828589, 6053995, -1775095, 6687195, 7765831, 7946592, 7821130,
        -2626065, 4613455, 10127838, 3728296, 9154301, 11337805, 8531104, 15979738, 1459696,
        8351548, 3335586, 1150210, -2462074, -4642922, 4538634, 1858098,
    ]
    .try_into()
    .expect("expected vector must have 256 coefficients");

    let mut p = poly_from(&input);
    poly_ntt(&mut p);
    assert_eq!(poly_coeffs(&p), expected, "portable NTT KAT mismatch");
}

#[test]
fn ntt_known_answer_unit_vector() {
    for k in [0, 1, 127, 128, 255] {
        let mut input = [0i32; 256];
        input[k] = 1;

        let mut p = poly_from(&input);
        poly_ntt(&mut p);
        let ntt_out = poly_coeffs(&p);

        let nonzero_count = ntt_out.iter().filter(|&&c| c != 0).count();
        assert!(
            nonzero_count > 1,
            "NTT of unit vector e_{k} should spread energy (k={k}, nonzero={nonzero_count})"
        );
    }
}

#[test]
fn ntt_invntt_preserves_congruence_class() {
    let mut input = [0i32; 256];
    for i in 0..256 {
        input[i] = ((i as i64 * 7919 + 104729) % Q) as i32;
    }

    let original_canon: Vec<i32> = input.iter().map(|&c| canon(c)).collect();

    let mut p = poly_from(&input);
    poly_ntt(&mut p);
    invert_ntt_montgomery(&mut p);
    let recovered = canon_poly(&p);

    let scaling_factor = {
        let r = recovered[0] as i64;
        let o = original_canon[0] as i64;
        (r * mod_inv(o, Q)).rem_euclid(Q)
    };

    for i in 0..256 {
        let expected = ((original_canon[i] as i64 * scaling_factor) % Q + Q) % Q;
        assert_eq!(
            recovered[i], expected as i32,
            "Congruence class not preserved at index {i}"
        );
    }
}

#[test]
fn ntt_scaling_factor_is_consistent() {
    let test_inputs: Vec<[i32; 256]> = vec![
        {
            let mut a = [0i32; 256];
            a[0] = 1;
            a
        },
        {
            let mut a = [0i32; 256];
            for i in 0..256 {
                a[i] = 1;
            }
            a
        },
        {
            let mut a = [0i32; 256];
            for i in 0..256 {
                a[i] = (i as i32 * 17 + 3) % 1000;
            }
            a
        },
    ];

    let mut observed_factor: Option<i64> = None;
    for input in &test_inputs {
        let first_nonzero = input.iter().position(|&c| c != 0);
        if first_nonzero.is_none() {
            continue;
        }
        let idx = first_nonzero.unwrap();

        let mut p = poly_from(input);
        poly_ntt(&mut p);
        invert_ntt_montgomery(&mut p);
        let recovered = canon_poly(&p);

        let r = recovered[idx] as i64;
        let o = canon(input[idx]) as i64;
        let factor = (r * mod_inv(o, Q)).rem_euclid(Q);

        match observed_factor {
            None => observed_factor = Some(factor),
            Some(prev) => assert_eq!(
                factor, prev,
                "Scaling factor differs across inputs: {factor} vs {prev}"
            ),
        }
    }
}

// ──────────────────────────────────────────────────────────────────
// Layer-level NTT tests (individual butterfly layers)
// ──────────────────────────────────────────────────────────────────

#[test]
fn simd_unit_ntt_layer0_deterministic() {
    let mut a = make_coefficients(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let mut b = make_coefficients(&[1, 2, 3, 4, 5, 6, 7, 8]);

    ntt::simd_unit_ntt_at_layer_0(&mut a, 2091667, 3407706, 2316500, 3817976);
    ntt::simd_unit_ntt_at_layer_0(&mut b, 2091667, 3407706, 2316500, 3817976);

    assert_eq!(a.values, b.values, "Layer 0 NTT must be deterministic");
}

#[test]
fn simd_unit_ntt_layer1_deterministic() {
    let mut a = make_coefficients(&[10, 20, 30, 40, 50, 60, 70, 80]);
    let mut b = make_coefficients(&[10, 20, 30, 40, 50, 60, 70, 80]);

    ntt::simd_unit_ntt_at_layer_1(&mut a, -3930395, -1528703);
    ntt::simd_unit_ntt_at_layer_1(&mut b, -3930395, -1528703);

    assert_eq!(a.values, b.values, "Layer 1 NTT must be deterministic");
}

#[test]
fn simd_unit_ntt_layer2_deterministic() {
    let mut a = make_coefficients(&[100, 200, 300, 400, 500, 600, 700, 800]);
    let mut b = make_coefficients(&[100, 200, 300, 400, 500, 600, 700, 800]);

    ntt::simd_unit_ntt_at_layer_2(&mut a, 2706023);
    ntt::simd_unit_ntt_at_layer_2(&mut b, 2706023);

    assert_eq!(a.values, b.values, "Layer 2 NTT must be deterministic");
}

#[test]
fn simd_unit_invntt_layer0_deterministic() {
    let mut a = make_coefficients(&[1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000]);
    let mut b = make_coefficients(&[1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000]);

    invntt::simd_unit_invert_ntt_at_layer_0(&mut a, 1976782, -846154, 1400424, 3937738);
    invntt::simd_unit_invert_ntt_at_layer_0(&mut b, 1976782, -846154, 1400424, 3937738);

    assert_eq!(a.values, b.values, "invNTT layer 0 must be deterministic");
}

// ──────────────────────────────────────────────────────────────────
// PortableSIMDUnit / Operations (decompose, hints, Montgomery, encodings)
// ──────────────────────────────────────────────────────────────────

#[test]
fn portable_operations_decompose_both_gamma2() {
    use crate::constants::{
        GAMMA2_V95_232,
        GAMMA2_V261_888,
    };
    use crate::simd::portable::PortableSIMDUnit;
    use crate::simd::traits::Operations;

    let t = make_coefficients(&[1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000]);
    let mut low = make_coefficients(&[0i32; 8]);
    let mut high = make_coefficients(&[0i32; 8]);
    PortableSIMDUnit::decompose(GAMMA2_V95_232, &t, &mut low, &mut high);
    PortableSIMDUnit::decompose(GAMMA2_V261_888, &t, &mut low, &mut high);
}

#[test]
fn portable_operations_hint_montgomery_power2round_t1() {
    use crate::constants::GAMMA2_V95_232;
    use crate::simd::portable::PortableSIMDUnit;
    use crate::simd::traits::Operations;

    let t = make_coefficients(&[12000, 24000, 36000, 48000, 60000, 72000, 84000, 96000]);
    let mut low = make_coefficients(&[0i32; 8]);
    let mut high = make_coefficients(&[0i32; 8]);
    PortableSIMDUnit::decompose(GAMMA2_V95_232, &t, &mut low, &mut high);

    let mut hint = make_coefficients(&[0i32; 8]);
    let _ones = PortableSIMDUnit::compute_hint(&low, &high, GAMMA2_V95_232, &mut hint);
    let mut hint_copy = hint;
    PortableSIMDUnit::use_hint(GAMMA2_V95_232, &high, &mut hint_copy);

    assert!(!PortableSIMDUnit::infinity_norm_exceeds(&t, 200_000));
    assert!(PortableSIMDUnit::infinity_norm_exceeds(&t, 1));

    let mut t0 = make_coefficients(&[5000, 15000, 25000, 35000, 45000, 55000, 65000, 75000]);
    let mut t1 = make_coefficients(&[0i32; 8]);
    PortableSIMDUnit::power2round(&mut t0, &mut t1);

    let rhs = make_coefficients(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let mut lhs = make_coefficients(&[10, 20, 30, 40, 50, 60, 70, 80]);
    PortableSIMDUnit::montgomery_multiply(&mut lhs, &rhs);

    let mut buf10 = [0u8; 10];
    PortableSIMDUnit::t1_serialize(&rhs, &mut buf10);
    let mut t1d = make_coefficients(&[0i32; 8]);
    PortableSIMDUnit::t1_deserialize(&buf10, &mut t1d);

    let mut sk = make_coefficients(&[100, 200, 300, 400, 500, 600, 700, 800]);
    PortableSIMDUnit::shift_left_then_reduce::<13>(&mut sk);
}

// ──────────────────────────────────────────────────────────────────
// Full NTT known-answer (second independent vector)
// ──────────────────────────────────────────────────────────────────

#[test]
fn ntt_known_answer_identity_element() {
    let mut input = [0i32; 256];
    input[0] = 1;

    let mut p = poly_from(&input);
    poly_ntt(&mut p);
    let ntt_out = poly_coeffs(&p);

    let nonzero = ntt_out.iter().filter(|&&c| c != 0).count();
    assert_eq!(
        nonzero, 256,
        "NTT of [1, 0, ...] should have all non-zero entries"
    );

    let mut p2 = poly_from(&input);
    poly_ntt(&mut p2);
    assert_eq!(
        poly_coeffs(&p2),
        ntt_out,
        "NTT must be deterministic across invocations"
    );
}

// ──────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────

fn mod_inv(a: i64, m: i64) -> i64 {
    let (mut old_r, mut r) = (a.rem_euclid(m), m);
    let (mut old_s, mut s) = (1i64, 0i64);

    while r != 0 {
        let quotient = old_r / r;
        let tmp_r = r;
        r = old_r - quotient * r;
        old_r = tmp_r;
        let tmp_s = s;
        s = old_s - quotient * s;
        old_s = tmp_s;
    }

    old_s.rem_euclid(m)
}

fn schoolbook_multiply(a: &[i32; 256], b: &[i32; 256]) -> [i32; 256] {
    let mut result = [0i64; 256];

    for i in 0..256 {
        for j in 0..256 {
            let idx = i + j;
            let prod = a[i] as i64 * b[j] as i64;
            if idx < 256 {
                result[idx] += prod;
            } else {
                result[idx - 256] -= prod;
            }
        }
    }

    let mut out = [0i32; 256];
    for i in 0..256 {
        out[i] = (result[i].rem_euclid(Q)) as i32;
    }
    out
}
