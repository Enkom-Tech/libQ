//! Test-only field parameters instantiating the generic Monty31 backend directly.
//!
//! `lib-q-stark-monty31` is a *generic* Montgomery-31 backend: it defines no concrete field of its
//! own — concrete instances (BabyBear, KoalaBear, ...) live in downstream crates such as
//! `lib-q-stark-baby-bear`. That means, prior to this module, every line of arithmetic, DFT, MDS,
//! extension-field and SIMD-packing code in this crate had never been exercised by a `#[test]`
//! *inside this crate* — only indirectly, via a downstream crate's own test suite (and for the
//! SIMD backends specifically, not even that: no downstream crate's default `cargo test` enables
//! `avx2`/`avx512f`/`neon`).
//!
//! To close that gap without editing a crate outside this one's lane, this module reproduces the
//! independently-validated BabyBear parameters (`p = 2^31 - 2^27 + 1`) so this crate's own tests
//! can drive the generic code directly. Every constant below is copied verbatim from
//! `lib-q-stark-baby-bear/src/baby_bear.rs` (see that file's doc comments for provenance —
//! `tools/gen_constants.py` / `tools/gen_quintic_constants.py` validation against canonical
//! Plonky3 reference values and, for the quintic extension, independent SageMath verification).
//! Reusing already-validated numeric constants here (rather than deriving new ones) means any test
//! failure below points at *this crate's* generic code, not at a freshly-invented and unverified
//! parameter set.

use lib_q_stark_field::extension::BinomialExtensionField;
use lib_q_stark_mds::util::first_row_to_first_col;

use crate::{
    BarrettParameters,
    BinomialExtensionData,
    FieldParameters,
    MDSUtils,
    MontyField31,
    MontyParameters,
    PackedMontyParameters,
    TwoAdicData,
};

/// Parameter marker mirroring `lib-q-stark-baby-bear`'s `BabyBearParameters`, reproduced here so
/// this crate's generic code can be exercised without a cross-crate (and cyclic) test dependency.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
pub(crate) struct TestFP;

impl MontyParameters for TestFP {
    /// `p = 2^31 - 2^27 + 1 = 2013265921`.
    const PRIME: u32 = 0x7800_0001;
    const MONTY_BITS: u32 = 32;
    const MONTY_MU: u32 = 0x8800_0001;
}

// `PackedMontyParameters` reduces to `MontyParameters` on the default (no_packing) build. Under a
// forced `+avx2`/`+avx512f`/`+neon` build, the relevant `MontyParameters{AVX2,AVX512,Neon}`
// supertrait is additionally required — each is provided by a blanket impl over any
// `MontyParameters` (see `x86_64_avx2/packing.rs`, `x86_64_avx512/packing.rs`,
// `aarch64_neon/packing.rs`), so this empty impl suffices on every backend.
impl PackedMontyParameters for TestFP {}

impl BarrettParameters for TestFP {}

impl FieldParameters for TestFP {
    /// Multiplicative generator `31`, supplied in canonical form (`new` -> Monty form).
    const MONTY_GEN: MontyField31<Self> = MontyField31::new(31);
}

impl TwoAdicData for TestFP {
    const TWO_ADICITY: usize = 27;

    type ArrayLike = &'static [MontyField31<TestFP>];

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

    const ROOTS_8: Self::ArrayLike = &[
        MontyField31::new(1),
        MontyField31::new(1592366214),
        MontyField31::new(1728404513),
        MontyField31::new(211723194),
    ];

    const INV_ROOTS_8: Self::ArrayLike = &[
        MontyField31::new(1),
        MontyField31::new(1801542727),
        MontyField31::new(284861408),
        MontyField31::new(420899707),
    ];

    const ROOTS_16: Self::ArrayLike = &[
        MontyField31::new(1),
        MontyField31::new(196396260),
        MontyField31::new(1592366214),
        MontyField31::new(78945800),
        MontyField31::new(1728404513),
        MontyField31::new(1400279418),
        MontyField31::new(211723194),
        MontyField31::new(1446056615),
    ];

    const INV_ROOTS_16: Self::ArrayLike = &[
        MontyField31::new(1),
        MontyField31::new(567209306),
        MontyField31::new(1801542727),
        MontyField31::new(612986503),
        MontyField31::new(284861408),
        MontyField31::new(1934320121),
        MontyField31::new(420899707),
        MontyField31::new(1816869661),
    ];
}

/// Degree-4 binomial extension `F_{p^4} = F_p[x]/(x^4 - 11)`, used to exercise `extension.rs`'s
/// `quartic_mul_packed` dispatch (portable and, when built with `+avx2`/`+avx512f`, the SIMD path).
impl BinomialExtensionData<4> for TestFP {
    const W: MontyField31<Self> = MontyField31::new(11);
    const DTH_ROOT: MontyField31<Self> = MontyField31::new(1728404513);
    const EXT_GENERATOR: [MontyField31<Self>; 4] = [
        MontyField31::new(8),
        MontyField31::new(1),
        MontyField31::new(0),
        MontyField31::new(0),
    ];
    const EXT_TWO_ADICITY: usize = 29;

    type ArrayLike = [[MontyField31<Self>; 4]; 2];
    const TWO_ADIC_EXTENSION_GENERATORS: Self::ArrayLike = [
        [
            MontyField31::new(0),
            MontyField31::new(0),
            MontyField31::new(1996171314),
            MontyField31::new(0),
        ],
        [
            MontyField31::new(0),
            MontyField31::new(0),
            MontyField31::new(0),
            MontyField31::new(124907976),
        ],
    ];
}

/// Degree-5 binomial extension `F_{p^5} = F_p[x]/(x^5 - 2)`, used to exercise
/// `quintic_mul_packed`.
impl BinomialExtensionData<5> for TestFP {
    const W: MontyField31<Self> = MontyField31::new(2);
    const DTH_ROOT: MontyField31<Self> = MontyField31::new(815036133);
    const EXT_GENERATOR: [MontyField31<Self>; 5] = [
        MontyField31::new(8),
        MontyField31::new(1),
        MontyField31::new(0),
        MontyField31::new(0),
        MontyField31::new(0),
    ];
    const EXT_TWO_ADICITY: usize = 27;

    type ArrayLike = [[MontyField31<Self>; 5]; 0];
    const TWO_ADIC_EXTENSION_GENERATORS: Self::ArrayLike = [];
}

pub(crate) type TestField = MontyField31<TestFP>;
pub(crate) type TestEF4 = BinomialExtensionField<TestField, 4>;
pub(crate) type TestEF5 = BinomialExtensionField<TestField, 5>;

/// MDS matrix columns, copied verbatim from upstream Plonky3's `baby-bear/src/mds.rs`
/// (`MDSBabyBearData`). `TestFP` uses the identical prime, so the upstream known-answer
/// `permute()` input/output vectors (reproduced in `mds.rs`'s test module) remain valid unchanged.
#[derive(Clone, Default)]
pub(crate) struct TestMDS;

impl MDSUtils for TestMDS {
    const MATRIX_CIRC_MDS_8_COL: [i64; 8] = first_row_to_first_col(&[7, 1, 3, 8, 8, 3, 4, 9]);
    const MATRIX_CIRC_MDS_12_COL: [i64; 12] =
        first_row_to_first_col(&[1, 1, 2, 1, 8, 9, 10, 7, 5, 9, 4, 10]);
    const MATRIX_CIRC_MDS_16_COL: [i64; 16] =
        first_row_to_first_col(&[1, 1, 51, 1, 11, 17, 2, 1, 101, 63, 15, 2, 67, 22, 13, 3]);
    const MATRIX_CIRC_MDS_24_COL: [i64; 24] = first_row_to_first_col(&[
        0x2D0AAAAB, 0x64850517, 0x17F5551D, 0x04ECBEB5, 0x6D91A8D5, 0x60703026, 0x18D6F3CA,
        0x729601A7, 0x77CDA9E2, 0x3C0F5038, 0x26D52A61, 0x0360405D, 0x68FC71C8, 0x2495A71D,
        0x5D57AFC2, 0x1689DD98, 0x3C2C3DBE, 0x0C23DC41, 0x0524C7F2, 0x6BE4DF69, 0x0A6E572C,
        0x5C7790FA, 0x17E118F6, 0x0878A07F,
    ]);
    const MATRIX_CIRC_MDS_32_COL: [i64; 32] = first_row_to_first_col(&[
        0x0BC00000, 0x2BED8F81, 0x337E0652, 0x4C4535D1, 0x4AF2DC32, 0x2DB4050F, 0x676A7CE3,
        0x3A06B68E, 0x5E95C1B1, 0x2C5F54A0, 0x2332F13D, 0x58E757F1, 0x3AA6DCCE, 0x607EE630,
        0x4ED57FF0, 0x6E08555B, 0x4C155556, 0x587FD0CE, 0x462F1551, 0x032A43CC, 0x5E2E43EA,
        0x71609B02, 0x0ED97E45, 0x562CA7E9, 0x2CB70B1D, 0x4E941E23, 0x174A61C1, 0x117A9426,
        0x73562137, 0x54596086, 0x487C560B, 0x68A4ACAB,
    ]);
    const MATRIX_CIRC_MDS_64_COL: [i64; 64] = first_row_to_first_col(&[
        0x39577778, 0x0072F4E1, 0x0B1B8404, 0x041E9C88, 0x32D22F9F, 0x4E4BF946, 0x20C7B6D7,
        0x0587C267, 0x55877229, 0x4D186EC4, 0x4A19FD23, 0x1A64A20F, 0x2965CA4D, 0x16D98A5A,
        0x471E544A, 0x193D5C8B, 0x6E66DF0C, 0x28BF1F16, 0x26DB0BC8, 0x5B06CDDB, 0x100DCCA2,
        0x65C268AD, 0x199F09E7, 0x36BA04BE, 0x06C393F2, 0x51B06DFD, 0x6951B0C4, 0x6683A4C2,
        0x3B53D11B, 0x26E5134C, 0x45A5F1C5, 0x6F4D2433, 0x3CE2D82E, 0x36309A7D, 0x3DD9B459,
        0x68051E4C, 0x5C3AA720, 0x11640517, 0x0634D995, 0x1B0F6406, 0x72A18430, 0x26513CC5,
        0x67C0B93C, 0x548AB4A3, 0x6395D20D, 0x3E5DBC41, 0x332AF630, 0x3C5DDCB3, 0x0AA95792,
        0x66EB5492, 0x3F78DDDC, 0x5AC41627, 0x16CD5124, 0x3564DA96, 0x461867C9, 0x157B4E11,
        0x1AA486C8, 0x0C5095A9, 0x3833C0C6, 0x008FEBA5, 0x52ECBE2E, 0x1D178A67, 0x58B3C04B,
        0x6E95CB51,
    ]);
}
