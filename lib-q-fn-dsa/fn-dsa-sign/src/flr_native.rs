#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

// ========================================================================
// Floating-point operations: native
// ========================================================================

// This file implements the Flr type for IEEE-754:2008 operations, with
// the requirements listed in flr.rs (in particular, there is no support
// for denormals, infinites or NaNs). The implementation uses the native
// 'f64' type; it should be used only for architectures for which the
// hardware can be assumed to operate in a sufficiently constant-time way.

#[derive(Clone, Copy, Debug)]
pub(crate) struct Flr(f64);

impl Flr {
    pub(crate) const ZERO: Self = Self(0.0);
    pub(crate) const NZERO: Self = Self(-0.0);
    pub(crate) const ONE: Self = Self(1.0);

    // Hardcoded powers of 2 for 2^(+127) to 2^(-128). This is used to
    // implement some operations where the exponent is not secret.
    // Values here were computed with 140 bits of precision, which is
    // overkill (such powers of 2 are exact in IEEE-754 'binary64'
    // format).
    pub(crate) const INV_POW2: [f64; 256] = [
        1.701_411_834_604_692_3e38,
        8.507_059_173_023_462e37,
        4.253_529_586_511_731e37,
        2.126_764_793_255_865_4e37,
        1.063_382_396_627_932_7e37,
        5.316_911_983_139_664e36,
        2.658_455_991_569_832e36,
        1.329_227_995_784_916e36,
        6.646_139_978_924_58e35,
        3.323_069_989_462_29e35,
        1.661_534_994_731_145e35,
        8.307_674_973_655_724e34,
        4.153_837_486_827_862e34,
        2.076_918_743_413_931e34,
        1.038_459_371_706_965_5e34,
        5.192_296_858_534_828e33,
        2.596_148_429_267_414e33,
        1.298_074_214_633_707e33,
        6.490_371_073_168_535e32,
        3.245_185_536_584_267_3e32,
        1.622_592_768_292_133_6e32,
        8.112_963_841_460_668e31,
        4.056_481_920_730_334e31,
        2.028_240_960_365_167e31,
        1.014_120_480_182_583_5e31,
        5.070_602_400_912_918e30,
        2.535_301_200_456_459e30,
        1.267_650_600_228_229_4e30,
        6.338_253_001_141_147e29,
        3.169_126_500_570_573_5e29,
        1.584_563_250_285_286_8e29,
        7.922_816_251_426_434e28,
        3.961_408_125_713_217e28,
        1.980_704_062_856_608_4e28,
        9.903_520_314_283_042e27,
        4.951_760_157_141_521e27,
        2.475_880_078_570_760_5e27,
        1.237_940_039_285_380_3e27,
        6.189_700_196_426_902e26,
        3.094_850_098_213_451e26,
        1.547_425_049_106_725_3e26,
        7.737_125_245_533_627e25,
        3.868_562_622_766_813_4e25,
        1.934_281_311_383_406_7e25,
        9.671_406_556_917_033e24,
        4.835_703_278_458_517e24,
        2.417_851_639_229_258_3e24,
        1.208_925_819_614_629_2e24,
        6.044_629_098_073_146e23,
        3.022_314_549_036_573e23,
        1.511_157_274_518_286_5e23,
        7.555_786_372_591_432e22,
        3.777_893_186_295_716e22,
        1.888_946_593_147_858e22,
        9.444_732_965_739_29e21,
        4.722_366_482_869_645e21,
        2.361_183_241_434_822_6e21,
        1.180_591_620_717_411_3e21,
        5.902_958_103_587_057e20,
        2.951_479_051_793_528_3e20,
        1.475_739_525_896_764_1e20,
        7.378_697_629_483_821e19,
        3.689_348_814_741_910_3e19,
        1.844_674_407_370_955_2e19,
        9.223_372_036_854_776e18,
        4.611_686_018_427_388e18,
        2.305_843_009_213_694e18,
        1.152_921_504_606_847e18,
        5.764_607_523_034_235e17,
        2.882_303_761_517_117_4e17,
        1.441_151_880_758_558_7e17,
        7.205_759_403_792_794e16,
        3.602_879_701_896_397e16,
        1.801_439_850_948_198_4e16,
        9.007_199_254_740_992e15,
        4.503_599_627_370_496e15,
        2.251_799_813_685_248e15,
        1.125_899_906_842_624e15,
        5.629_499_534_213_12e14,
        2.814_749_767_106_56e14,
        1.407_374_883_553_28e14,
        7.036_874_417_766_4e13,
        3.518_437_208_883_2e13,
        1.759_218_604_441_6e13,
        8.796_093_022_208e12,
        4.398_046_511_104e12,
        2.199_023_255_552e12,
        1.099_511_627_776e12,
        5.497_558_138_88e11,
        2.748_779_069_44e11,
        1.374_389_534_72e11,
        6.871_947_673_6e10,
        3.435_973_836_8e10,
        1.717_986_918_4e10,
        8.589_934_592e9,
        4.294_967_296e9,
        2.147_483_648e9,
        1.073_741_824e9,
        5.368_709_12e8,
        2.684_354_56e8,
        1.342_177_28e8,
        6.710_886_4e7,
        3.355_443_2e7,
        1.677_721_6e7,
        8.388_608e6,
        4.194_304e6,
        2.097_152e6,
        1.048_576e6,
        524288.00000000000000000000000000000000000,
        262144.00000000000000000000000000000000000,
        131072.00000000000000000000000000000000000,
        65536.000000000000000000000000000000000000,
        32768.000000000000000000000000000000000000,
        16384.000000000000000000000000000000000000,
        8192.0000000000000000000000000000000000000,
        4096.0000000000000000000000000000000000000,
        2048.0000000000000000000000000000000000000,
        1024.0000000000000000000000000000000000000,
        512.00000000000000000000000000000000000000,
        256.00000000000000000000000000000000000000,
        128.00000000000000000000000000000000000000,
        64.000000000000000000000000000000000000000,
        32.000000000000000000000000000000000000000,
        16.000000000000000000000000000000000000000,
        8.0000000000000000000000000000000000000000,
        4.0000000000000000000000000000000000000000,
        2.0000000000000000000000000000000000000000,
        1.0000000000000000000000000000000000000000,
        0.5,
        0.25,
        0.125,
        0.062_5,
        0.031_25,
        0.015_625,
        0.007_812_5,
        0.003_906_25,
        0.001_953_125,
        0.000_976_562_5,
        0.000_488_281_25,
        0.000_244_140_625,
        0.000_122_070_312_5,
        0.000_061_035_156_25,
        0.000_030_517_578_125,
        0.000_015_258_789_062_5,
        7.629_394_531_25e-6,
        3.814_697_265_625e-6,
        1.907_348_632_812_5e-6,
        9.536_743_164_062_5e-7,
        4.768_371_582_031_25e-7,
        2.384_185_791_015_625e-7,
        1.192_092_895_507_812_5e-7,
        5.960_464_477_539_063e-8,
        2.980_232_238_769_531_3e-8,
        1.490_116_119_384_765_6e-8,
        7.450_580_596_923_828e-9,
        3.725_290_298_461_914e-9,
        1.862_645_149_230_957e-9,
        9.313_225_746_154_785e-10,
        4.656_612_873_077_393e-10,
        2.328_306_436_538_696_3e-10,
        1.164_153_218_269_348_1e-10,
        5.820_766_091_346_741e-11,
        2.910_383_045_673_370_4e-11,
        1.455_191_522_836_685_2e-11,
        7.275_957_614_183_426e-12,
        3.637_978_807_091_713e-12,
        1.818_989_403_545_856_5e-12,
        9.094_947_017_729_282e-13,
        4.547_473_508_864_641e-13,
        2.273_736_754_432_320_6e-13,
        1.136_868_377_216_160_3e-13,
        5.684_341_886_080_802e-14,
        2.842_170_943_040_401e-14,
        1.421_085_471_520_200_4e-14,
        7.105_427_357_601_002e-15,
        3.552_713_678_800_501e-15,
        1.776_356_839_400_250_5e-15,
        8.881_784_197_001_252e-16,
        4.440_892_098_500_626e-16,
        2.220_446_049_250_313e-16,
        1.110_223_024_625_156_5e-16,
        5.551_115_123_125_783e-17,
        2.775_557_561_562_891_4e-17,
        1.387_778_780_781_445_7e-17,
        6.938_893_903_907_228e-18,
        3.469_446_951_953_614e-18,
        1.734_723_475_976_807e-18,
        8.673_617_379_884_035e-19,
        4.336_808_689_942_018e-19,
        2.168_404_344_971_009e-19,
        1.084_202_172_485_504_4e-19,
        5.421_010_862_427_522e-20,
        2.710_505_431_213_761e-20,
        1.355_252_715_606_880_5e-20,
        6.776_263_578_034_403e-21,
        3.388_131_789_017_201_4e-21,
        1.694_065_894_508_600_7e-21,
        8.470_329_472_543_003e-22,
        4.235_164_736_271_502e-22,
        2.117_582_368_135_751e-22,
        1.058_791_184_067_875_4e-22,
        5.293_955_920_339_377e-23,
        2.646_977_960_169_688_6e-23,
        1.323_488_980_084_844_3e-23,
        6.617_444_900_424_222e-24,
        3.308_722_450_212_111e-24,
        1.654_361_225_106_055_3e-24,
        8.271_806_125_530_277e-25,
        4.135_903_062_765_138_4e-25,
        2.067_951_531_382_569_2e-25,
        1.033_975_765_691_284_6e-25,
        5.169_878_828_456_423e-26,
        2.584_939_414_228_211_5e-26,
        1.292_469_707_114_105_7e-26,
        6.462_348_535_570_529e-27,
        3.231_174_267_785_264_4e-27,
        1.615_587_133_892_632_2e-27,
        8.077_935_669_463_161e-28,
        4.038_967_834_731_580_4e-28,
        2.019_483_917_365_790_2e-28,
        1.009_741_958_682_895_1e-28,
        5.048_709_793_414_476e-29,
        2.524_354_896_707_238e-29,
        1.262_177_448_353_619e-29,
        6.310_887_241_768_095e-30,
        3.155_443_620_884_047_2e-30,
        1.577_721_810_442_023_6e-30,
        7.888_609_052_210_118e-31,
        3.944_304_526_105_059e-31,
        1.972_152_263_052_529_5e-31,
        9.860_761_315_262_648e-32,
        4.930_380_657_631_324e-32,
        2.465_190_328_815_662e-32,
        1.232_595_164_407_831e-32,
        6.162_975_822_039_155e-33,
        3.081_487_911_019_577_4e-33,
        1.540_743_955_509_788_7e-33,
        7.703_719_777_548_943e-34,
        3.851_859_888_774_472e-34,
        1.925_929_944_387_236e-34,
        9.629_649_721_936_18e-35,
        4.814_824_860_968_09e-35,
        2.407_412_430_484_045e-35,
        1.203_706_215_242_022_4e-35,
        6.018_531_076_210_112e-36,
        3.009_265_538_105_056e-36,
        1.504_632_769_052_528e-36,
        7.523_163_845_262_64e-37,
        3.761_581_922_631_32e-37,
        1.880_790_961_315_66e-37,
        9.403_954_806_578_3e-38,
        4.701_977_403_289_15e-38,
        2.350_988_701_644_575e-38,
        1.175_494_350_822_287_5e-38,
        5.877_471_754_111_438e-39,
        2.938_735_877_055_719e-39,
    ];

    #[inline(always)]
    pub(crate) const fn from_i64(j: i64) -> Self {
        Self(j as f64)
    }

    #[inline(always)]
    pub(crate) const fn from_i32(j: i32) -> Self {
        Self(j as f64)
    }

    // Specialized code (e.g. AVX2 on x86_64) may access the inner f64
    // value directly.
    #[allow(dead_code)]
    #[inline(always)]
    pub(crate) const fn to_f64(self) -> f64 {
        self.0
    }

    #[inline(always)]
    pub(crate) const fn scaled(j: i64, sc: i32) -> Self {
        // Since from_i32() and from_i64() use direct integer-to-float
        // conversions, this function will be called only for evaluating
        // compile-time constants. However, there are limitations to what
        // can be done in const functions; in particular, loops are not
        // allowed. We could use recursion, but it seems simpler to
        // hardcode some scaling factors since all the 'sc' values in
        // practice will be in a limited range.
        //
        // Largest range for sc is [+127, -128].
        Self((j as f64) * Self::INV_POW2[(127 - sc) as usize])
    }

    // Encode to 8 bytes (IEEE-754 binary64 format, little-endian).
    // This is meant for tests only; this function does not need to be
    // constant-time.
    #[allow(dead_code)]
    pub(crate) fn encode(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    // Decode from 8 bytes (IEEE-754 binary64 format, little-endian).
    // This is meant for tests only; this function does not need to be
    // constant-time.
    #[allow(dead_code)]
    pub(crate) fn decode(src: &[u8]) -> Option<Self> {
        match src.len() {
            8 => Some(Self(f64::from_le_bytes(
                *<&[u8; 8]>::try_from(src).unwrap(),
            ))),
            _ => None,
        }
    }

    // Return self / 2.
    #[inline(always)]
    pub(crate) fn half(self) -> Self {
        Self(self.0 * 0.5)
    }

    // Return self * 2.
    // (used in some tests)
    #[allow(dead_code)]
    #[inline(always)]
    pub(crate) fn double(self) -> Self {
        Self(self.0 * 2.0)
    }

    // Multiply this value by 2^63.
    #[inline(always)]
    pub(crate) fn mul2p63(self) -> Self {
        Self(self.0 * 9223372036854775808.0)
    }

    // Divide all values in the provided slice with 2^e, for e in the
    // 1 to 9 range (inclusive). The value of e is not considered secret.
    // This is a helper function used in the implementation of the FFT
    // and included in the Flr API because different implementations might
    // do it very differently.
    #[allow(dead_code)]
    pub(crate) fn slice_div2e(f: &mut [Flr], e: u32) {
        let ee = Self::INV_POW2[(e + 127) as usize];
        for item in &mut *f {
            *item = Self(item.0 * ee);
        }
    }

    #[inline]
    pub(crate) fn rint(self) -> i64 {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            use core::arch::x86_64::*;

            // On x86_64, we have SSE2, and there is an opcode that
            // does exactly what we need. The conversion from f64 to
            // __m128d is really a no-op, since f64 is itself backed
            // by SSE2.
            _mm_cvtsd_si64(_mm_set_sd(self.0))
        }

        #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
        unsafe {
            use core::arch::aarch64::*;

            // On aarch64, we use the NEON opcodes.
            return vcvtnd_s64_f64(self.0);
        }

        #[cfg(target_arch = "riscv64")]
        unsafe {
            use core::arch::asm;
            let mut d: i64;
            asm!("fcvt.l.d {d}, {a}, rne", a = in(freg) self.0, d = out(reg) d);
            return d;
        }

        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm64ec",
            target_arch = "riscv64"
        )))]
        {
            // Suppose that x >= 0. If x >= 2^52, then it is already an
            // integer. Otherwise, computing x + 2^52 will yield a value
            // that is rounded to the nearest integer with exactly the right
            // rules (roundTiesToEven). For constant-time processing we must
            // do the computation for both x >= 0 and x < 0 cases, then
            // select the right output.
            let x = self.0;
            let sx = (x - 1.0) as i64;
            let tx = x as i64;
            let rp = ((x + 4503599627370496.0) as i64) - 4503599627370496;
            let rn = ((x - 4503599627370496.0) as i64) + 4503599627370496;

            // Assuming that |x| < 2^52:
            // If sx >= 0, then the result is rp; otherwise, result is rn.
            // We use the fact that when x is close to 0 (|x| <= 0.25), then
            // both rp and rn are correct (they are both zero); but if x is
            // not close to 0, then trunc(x - 1.0) (i.e. sx) has the correct
            // sign. Thus, we use rp if sx >= 0, rn otherwise.
            let z = rp ^ ((sx >> 63) & (rp ^ rn));

            // If the twelve upper bits of tx are not all-zeros or all-ones,
            // then tx >= 2^52 or tx < -2^52, and is exact; in that case,
            // we replace z with tx.
            let hi = (tx as u64).wrapping_add(1u64 << 52) >> 52;
            let m = (hi.wrapping_sub(2) as i64) >> 16;
            return tx ^ (m & (z ^ tx));
        }
    }

    #[inline(always)]
    pub(crate) fn floor(self) -> i64 {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            use core::arch::x86_64::*;
            let x = self.0;
            let r = x as i64;
            let t = _mm_comilt_sd(_mm_set_sd(x), _mm_cvtsi64x_sd(_mm_setzero_pd(), r));
            r - (t as i64)
        }

        #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
        unsafe {
            use core::arch::aarch64::*;
            return vcvtmd_s64_f64(self.0);
        }

        #[cfg(target_arch = "riscv64")]
        unsafe {
            use core::arch::asm;
            let mut d: i64;
            asm!("fcvt.l.d {d}, {a}, rdn", a = in(freg) self.0, d = out(reg) d);
            return d;
        }

        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm64ec",
            target_arch = "riscv64"
        )))]
        {
            // We use the native conversion (which is a trunc()) and then
            // subtract 1 if that yields a value greater than the source.
            // On x86_64, comparison uses SSE2 opcode cmpsd which is then
            // extracted into an integer register as 0 or -1, so the
            // final subtraction will be done in a branchless way.
            // On aarch64, the comparison should use fcmp, and then use the
            // flags in a csel, cset, adc or sbc opcode.
            let x = self.0;
            let r = x as i64;
            return r - ((x < (r as f64)) as i64);
        }
    }

    #[inline(always)]
    pub(crate) fn trunc(self) -> i64 {
        self.0 as i64
    }

    #[inline(always)]
    pub(crate) fn set_add(&mut self, other: Self) {
        self.0 += other.0;
    }

    #[inline(always)]
    pub(crate) fn set_sub(&mut self, other: Self) {
        self.0 -= other.0;
    }

    // Negation.
    #[inline(always)]
    pub(crate) fn set_neg(&mut self) {
        self.0 = -self.0;
    }

    #[inline(always)]
    pub(crate) fn set_mul(&mut self, other: Self) {
        self.0 *= other.0;
    }

    #[inline(always)]
    pub(crate) fn square(self) -> Self {
        Self(self.0 * self.0)
    }

    #[cfg(feature = "div_emu")]
    #[inline]
    pub(crate) fn set_div(&mut self, other: Self) {
        let x = u64::from_le_bytes(self.0.to_le_bytes());
        let y = u64::from_le_bytes(other.0.to_le_bytes());
        let z = Self::div_emu(x, y);
        self.0 = f64::from_le_bytes(z.to_le_bytes());
    }

    #[cfg(not(feature = "div_emu"))]
    #[inline(always)]
    pub(crate) fn set_div(&mut self, other: Self) {
        self.0 /= other.0;
    }

    #[allow(dead_code)]
    pub(crate) fn abs(self) -> Self {
        // This is for tests, thus it does not need to be constant-time.
        // (it could be made constant-time with intrinsics)
        if self.0 < 0.0 { Self(-self.0) } else { self }
    }

    pub(crate) fn sqrt(self) -> Self {
        #[cfg(not(feature = "sqrt_emu"))]
        {
            // f64::sqrt() is in std but not in core. We use the
            // architecture-specific intrinsics.
            #[cfg(target_arch = "x86_64")]
            unsafe {
                // x86 (64-bit): use SSE2
                use core::arch::x86_64::*;
                let x = _mm_set_sd(self.0);
                let x = _mm_sqrt_pd(x);
                Self(_mm_cvtsd_f64(x))
            }

            #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
            unsafe {
                // An f64 is already in a SIMD register, we use a transmute
                // to make it look like a float64x1_t, but that should be
                // a no-op in compiled code.
                use core::arch::aarch64::*;
                let x: float64x1_t = core::mem::transmute(self.0);
                let x = vsqrt_f64(x);
                return Self(core::mem::transmute(x));
            }

            #[cfg(target_arch = "riscv64")]
            unsafe {
                use core::arch::asm;
                let mut d: f64;
                asm!("fsqrt.d {d}, {a}", a = in(freg) self.0, d = out(freg) d);
                return Self(d);
            }
        }

        #[cfg(any(
            feature = "sqrt_emu",
            not(any(
                target_arch = "x86_64",
                target_arch = "aarch64",
                target_arch = "arm64ec",
                target_arch = "riscv64"
            ))
        ))]
        {
            let x = u64::from_le_bytes(self.0.to_le_bytes());
            let z = Self::sqrt_emu(x);
            Self(f64::from_le_bytes(z.to_le_bytes()))
        }
    }

    // Emulated division with integer operations only; this is meant for
    // architectures where native floating-point can be used, but the
    // division operation is not constant-time enough.
    #[cfg(feature = "div_emu")]
    fn div_emu(x: u64, y: u64) -> u64 {
        // see Flr::set_div() in flr_emu.rs for details
        const M52: u64 = 0x000FFFFFFFFFFFFF;
        let mut xu = (x & M52) | (1u64 << 52);
        let yu = (y & M52) | (1u64 << 52);

        let mut q = 0;
        for _ in 0..55 {
            let b = (xu.wrapping_sub(yu) >> 63).wrapping_sub(1);
            xu -= b & yu;
            q |= b & 1;
            xu <<= 1;
            q <<= 1;
        }

        q |= (xu | xu.wrapping_neg()) >> 63;

        let es = ((q >> 55) as u32) & 1;
        q = (q >> es) | (q & 1);

        let ex = ((x >> 52) as i32) & 0x7FF;
        let ey = ((y >> 52) as i32) & 0x7FF;
        let e = ex - ey - 55 + (es as i32);

        let s = (x ^ y) >> 63;

        let dz = (ex - 1) >> 16;
        let e = e ^ (dz & (e ^ -1076));
        let dm = !((dz as i64) as u64);
        let s = s & dm;
        q &= dm;
        let cc = (0xC8u64 >> ((q as u32) & 7)) & 1;
        (s << 63) + (((e + 1076) as u64) << 52) + (q >> 2) + cc
    }

    // Emulated square root with integer operations only; this is meant for
    // architectures where native floating-point can be used, but the
    // square root operation is not constant-time enough. It is also used
    // for architecture other than the ones supported directly in sqrt()
    // (square root extraction normally uses a standard library function,
    // which we cannot use since this is a no_std library).
    #[cfg(any(
        feature = "sqrt_emu",
        not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm64ec",
            target_arch = "riscv64"
        ))
    ))]
    fn sqrt_emu(x: u64) -> u64 {
        // see Flr::sqrt() in flr_emu.rs for details
        const M52: u64 = 0x000FFFFFFFFFFFFF;
        let mut xu = (x & M52) | (1u64 << 52);
        let ex = ((x >> 52) as u32) & 0x7FF;
        let mut e = (ex as i32) - 1023;

        xu += ((-(e & 1) as i64) as u64) & xu;
        e >>= 1;

        xu <<= 1;

        let mut q = 0;
        let mut s = 0;
        let mut r = 1u64 << 53;
        for _ in 0..54 {
            let t = s + r;
            let b = (xu.wrapping_sub(t) >> 63).wrapping_sub(1);
            s += (r << 1) & b;
            xu -= t & b;
            q += r & b;
            xu <<= 1;
            r >>= 1;
        }

        q <<= 1;
        q |= (xu | xu.wrapping_neg()) >> 63;

        e -= 54;

        q &= (((ex + 0x7FF) >> 11) as u64).wrapping_neg();
        let t = ((q >> 54) as u32).wrapping_neg();
        let e = ((e + 1076) as u32) & t;
        let cc = (0xC8u64 >> ((q as u32) & 7)) & 1;
        ((e as u64) << 52) + (q >> 2) + cc
    }

    pub(crate) fn expm_p63(self, ccs: Self) -> u64 {
        // For full reproducibility of test vectors, we should take care
        // to always return the same values as the emulated code.

        // The polynomial approximation of exp(-x) is from FACCT:
        //   https://eprint.iacr.org/2018/1234
        // Specifically, the values are extracted from the implementation
        // referenced by FACCT, available at:
        //   https://github.com/raykzhao/gaussian
        let mut y = Self::EXPM_COEFFS[0];
        let z = (self.mul2p63().trunc() as u64) << 1;

        // On 64-bit platforms, we assume that 64x64->128 multiplications
        // are constant-time. This is known to be slightly wrong on some
        // low-end aarch64 (e.g. ARM Cortex A53 and A55), where
        // multiplications are a bit faster when operands are small (i.e.
        // fit on 32 bits).
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm64ec",
            target_arch = "riscv64"
        ))]
        {
            for i in 1..Self::EXPM_COEFFS.len() {
                // Compute z*y over 128 bits, but keep only the top 64 bits.
                let yy = (z as u128) * (y as u128);
                y = Self::EXPM_COEFFS[i].wrapping_sub((yy >> 64) as u64);
            }

            // The scaling factor must be applied at the end. Since y is now
            // in fixed-point notation, we have to convert the factor to the
            // same format, and we do an extra integer multiplication.
            let z = (ccs.mul2p63().trunc() as u64) << 1;
            (((z as u128) * (y as u128)) >> 64) as u64
        }

        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm64ec",
            target_arch = "riscv64"
        )))]
        {
            let (z0, z1) = (z as u32, (z >> 32) as u32);
            for i in 1..Self::EXPM_COEFFS.len() {
                // Compute z*y over 128 bits, but keep only the top 64 bits.
                // We stick to 32-bit multiplications for the same reasons
                // as in set_mul().
                let (y0, y1) = (y as u32, (y >> 32) as u32);
                let f = (z0 as u64) * (y0 as u64);
                let a = (z0 as u64) * (y1 as u64) + (f >> 32);
                let b = (z1 as u64) * (y0 as u64);
                let c = (a >> 32) +
                    (b >> 32) +
                    ((((a as u32) as u64) + ((b as u32) as u64)) >> 32) +
                    (z1 as u64) * (y1 as u64);
                y = Self::EXPM_COEFFS[i].wrapping_sub(c);
            }

            // The scaling factor must be applied at the end. Since y is now
            // in fixed-point notation, we have to convert the factor to the
            // same format, and we do an extra integer multiplication.
            let z = (ccs.mul2p63().trunc() as u64) << 1;
            let (z0, z1) = (z as u32, (z >> 32) as u32);
            let (y0, y1) = (y as u32, (y >> 32) as u32);
            let f = (z0 as u64) * (y0 as u64);
            let a = (z0 as u64) * (y1 as u64) + (f >> 32);
            let b = (z1 as u64) * (y0 as u64);
            let y = (a >> 32) +
                (b >> 32) +
                ((((a as u32) as u64) + ((b as u32) as u64)) >> 32) +
                (z1 as u64) * (y1 as u64);
            return y;
        }
    }

    const EXPM_COEFFS: [u64; 13] = [
        0x00000004741183A3,
        0x00000036548CFC06,
        0x0000024FDCBF140A,
        0x0000171D939DE045,
        0x0000D00CF58F6F84,
        0x000680681CF796E3,
        0x002D82D8305B0FEA,
        0x011111110E066FD0,
        0x0555555555070F00,
        0x155555555581FF00,
        0x400000000002B400,
        0x7FFFFFFFFFFF4800,
        0x8000000000000000,
    ];
}
