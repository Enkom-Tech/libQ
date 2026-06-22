//! BabyBear parameters for the generic `lib-q-stark-monty31` Montgomery-31 field.
//!
//! `p = 2^31 - 2^27 + 1 = 2013265921 = 0x78000001`, two-adicity 27, multiplicative
//! generator 31. Constants are produced and validated by `tools/gen_constants.py`
//! (run it to regenerate / re-verify against the canonical Plonky3 reference values).

use lib_q_stark_monty31::{
    BarrettParameters,
    FieldParameters,
    MontyField31,
    MontyParameters,
    PackedMontyParameters,
    TwoAdicData,
};

/// The BabyBear field `F_p`, `p = 2^31 - 2^27 + 1`.
pub type BabyBear = MontyField31<BabyBearParameters>;

/// Parameter marker for the BabyBear instance of `MontyField31`.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
pub struct BabyBearParameters;

impl MontyParameters for BabyBearParameters {
    /// `p = 2^31 - 2^27 + 1 = 2013265921`.
    const PRIME: u32 = 0x7800_0001;
    const MONTY_BITS: u32 = 32;
    /// `MONTY_MU = p^{-1} (mod 2^32)` (non-negated convention, see `data_traits.rs`).
    const MONTY_MU: u32 = 0x8800_0001;
}

// On the default host build and on `wasm32-unknown-unknown`, neither avx2/avx512/neon
// is enabled, so `PackedMontyParameters` reduces to `MontyParameters` (scalar backend).
// SIMD packing (which would require `MontyParametersAVX2`/etc. with vectorized constants)
// is an out-of-scope optional optimization — see the build spec's measurement section.
impl PackedMontyParameters for BabyBearParameters {}

impl BarrettParameters for BabyBearParameters {}

impl FieldParameters for BabyBearParameters {
    /// Multiplicative generator `31`, supplied in canonical form (`new` -> Monty form).
    const MONTY_GEN: MontyField31<Self> = MontyField31::new(31);
}

impl TwoAdicData for BabyBearParameters {
    const TWO_ADICITY: usize = 27;

    type ArrayLike = &'static [MontyField31<BabyBearParameters>];

    /// `TWO_ADIC_GENERATORS[i]` is a primitive `2^i`-th root of unity, with
    /// `TWO_ADIC_GENERATORS[i]^2 == TWO_ADIC_GENERATORS[i-1]` and `[27] = 0x1a427a41`.
    const TWO_ADIC_GENERATORS: Self::ArrayLike = &[
        MontyField31::new(1),
        MontyField31::new(2013265920),
        MontyField31::new(1728404513),
        MontyField31::new(1592366214),
        MontyField31::new(196396260),
        MontyField31::new(760005850),
        MontyField31::new(1721589904),
        MontyField31::new(397765732),
        MontyField31::new(1732600167),
        MontyField31::new(1753498361),
        MontyField31::new(341742893),
        MontyField31::new(1340477990),
        MontyField31::new(1282623253),
        MontyField31::new(298008106),
        MontyField31::new(1657000625),
        MontyField31::new(2009781145),
        MontyField31::new(1421947380),
        MontyField31::new(1286330022),
        MontyField31::new(1559589183),
        MontyField31::new(1049899240),
        MontyField31::new(195061667),
        MontyField31::new(414040701),
        MontyField31::new(570250684),
        MontyField31::new(1267047229),
        MontyField31::new(1003846038),
        MontyField31::new(1149491290),
        MontyField31::new(975630072),
        MontyField31::new(440564289),
    ];

    /// First three 8th-roots of unity `[1, w8, w8^2]`; `ROOTS_8[1] == TWO_ADIC_GENERATORS[3]`.
    const ROOTS_8: Self::ArrayLike = &[
        MontyField31::new(1),
        MontyField31::new(1592366214),
        MontyField31::new(1728404513),
    ];

    const INV_ROOTS_8: Self::ArrayLike = &[
        MontyField31::new(1),
        MontyField31::new(1801542727),
        MontyField31::new(284861408),
    ];

    /// First seven 16th-roots of unity `[1, w16, ..., w16^6]`; `ROOTS_16[1] == TWO_ADIC_GENERATORS[4]`.
    const ROOTS_16: Self::ArrayLike = &[
        MontyField31::new(1),
        MontyField31::new(196396260),
        MontyField31::new(1592366214),
        MontyField31::new(78945800),
        MontyField31::new(1728404513),
        MontyField31::new(1400279418),
        MontyField31::new(211723194),
    ];

    const INV_ROOTS_16: Self::ArrayLike = &[
        MontyField31::new(1),
        MontyField31::new(567209306),
        MontyField31::new(1801542727),
        MontyField31::new(612986503),
        MontyField31::new(284861408),
        MontyField31::new(1934320121),
        MontyField31::new(420899707),
    ];
}

#[cfg(test)]
mod tests {
    use lib_q_stark_field::PrimeCharacteristicRing;
    use lib_q_stark_field_testing::{
        test_field,
        test_prime_field,
        test_prime_field_32,
        test_prime_field_64,
        test_two_adic_field,
    };
    use num_bigint::BigUint;

    use crate::BabyBear;

    // BabyBear has a unique (canonical, < P) representation of zero and of one.
    const ZEROS: [BabyBear; 1] = [BabyBear::ZERO];
    const ONES: [BabyBear; 1] = [BabyBear::ONE];

    // Prime factorization of |F_p^*| = p - 1 = 2^27 * 3 * 5.
    fn multiplicative_group_prime_factorization() -> [(BigUint, u32); 3] {
        [
            (BigUint::from(2u8), 27),
            (BigUint::from(3u8), 1),
            (BigUint::from(5u8), 1),
        ]
    }

    test_field!(
        crate::BabyBear,
        &super::ZEROS,
        &super::ONES,
        &super::multiplicative_group_prime_factorization()
    );
    test_prime_field!(crate::BabyBear);
    test_prime_field_64!(crate::BabyBear, &super::ZEROS, &super::ONES);
    test_prime_field_32!(crate::BabyBear, &super::ZEROS, &super::ONES);
    test_two_adic_field!(crate::BabyBear);
}
