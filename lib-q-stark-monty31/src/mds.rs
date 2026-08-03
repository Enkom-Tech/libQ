use core::marker::PhantomData;

use lib_q_stark_mds::MdsPermutation;
use lib_q_stark_mds::karatsuba_convolution::Convolve;
use lib_q_stark_mds::util::dot_product;
use lib_q_stark_symmetric::Permutation;

use crate::{
    BarrettParameters,
    MontyField31,
    MontyParameters,
};

/// A collection of circulant MDS matrices saved using their left most column.
pub trait MDSUtils: Clone + Sync {
    const MATRIX_CIRC_MDS_8_COL: [i64; 8];
    const MATRIX_CIRC_MDS_12_COL: [i64; 12];
    const MATRIX_CIRC_MDS_16_COL: [i64; 16];
    const MATRIX_CIRC_MDS_24_COL: [i64; 24];
    const MATRIX_CIRC_MDS_32_COL: [i64; 32];
    const MATRIX_CIRC_MDS_64_COL: [i64; 64];
}

#[derive(Clone, Debug, Default)]
pub struct MdsMatrixMontyField31<MU: MDSUtils> {
    _phantom: PhantomData<MU>,
}

/// Instantiate convolution for "small" RHS vectors over a 31-bit MONTY_FIELD.
///
/// Here "small" means N = len(rhs) <= 16 and sum(r for r in rhs) <
/// 2^24 (roughly), though in practice the sum will be less than 2^9.
struct SmallConvolveMontyField31;

impl<FP: MontyParameters> Convolve<MontyField31<FP>, i64, i64, i64> for SmallConvolveMontyField31 {
    /// Return the lift of a Monty31 element, satisfying 0 <=
    /// input.value < P < 2^31. Note that Monty31 elements are
    /// represented in Monty form.
    #[inline(always)]
    fn read(input: MontyField31<FP>) -> i64 {
        input.value as i64
    }

    /// For a convolution of size N, |x| < N * 2^31 and (as per the
    /// assumption above), |y| < 2^24. So the product is at most N * 2^55
    /// which will not overflow for N <= 16.
    ///
    /// Note that the LHS element is in Monty form, while the RHS
    /// element is a "plain integer". This informs the implementation
    /// of `reduce()` below.
    #[inline(always)]
    fn parity_dot<const N: usize>(u: [i64; N], v: [i64; N]) -> i64 {
        dot_product(u, v)
    }

    /// The assumptions above mean z < N^2 * 2^55, which is at most
    /// 2^63 when N <= 16.
    ///
    /// Because the LHS elements were in Monty form and the RHS
    /// elements were plain integers, reduction is simply the usual
    /// reduction modulo P, rather than "Monty reduction".
    ///
    /// NB: Even though intermediate values could be negative, the
    /// output must be non-negative since the inputs were
    /// non-negative.
    #[inline(always)]
    fn reduce(z: i64) -> MontyField31<FP> {
        debug_assert!(z >= 0);

        MontyField31::new_monty((z as u64 % FP::PRIME as u64) as u32)
    }
}

/// Given |x| < 2^80 compute x' such that:
/// |x'| < 2**50
/// x' = x mod p
/// x' = x mod 2^10
/// See Thm 1 (Below function) for a proof that this function is correct.
#[inline(always)]
const fn barrett_red_monty31<BP: BarrettParameters>(input: i128) -> i64 {
    // input = input_low + beta*input_high
    // So input_high < 2**63 and fits in an i64.
    let input_high = (input >> BP::N) as i64; // input_high < input / beta < 2**{80 - N}

    // I, input_high are i64's so this multiplication can't overflow.
    let quot = (((input_high as i128) * (BP::PSEUDO_INV as i128)) >> BP::N) as i64;

    // Replace quot by a close value which is divisible by 2^10.
    let quot_2adic = quot & BP::MASK;

    // quot_2adic, P are i64's so this can't overflow.
    // sub is by construction divisible by both P and 2^10.
    let sub = (quot_2adic as i128) * BP::PRIME_I128;

    (input - sub) as i64
}

// Theorem 1:
// Given |x| < 2^80, barrett_red(x) computes an x' such that:
//       x' = x mod p
//       x' = x mod 2^10
//       |x'| < 2**50.
///////////////////////////////////////////////////////////////////////////////////////
// PROOF:
// By construction P, 2**10 | sub and so we immediately see that
// x' = x mod p
// x' = x mod 2^10.
//
// It remains to prove that |x'| < 2**50.
//
// We start by introducing some simple inequalities and relations between our variables:
//
// First consider the relationship between bit-shift and division.
// It's easy to check that for all x:
// 1: (x >> N) <= x / 2**N <= 1 + (x >> N)
//
// Similarly, as our mask just 0's the last 10 bits,
// 2: x + 1 - 2^10 <= x & mask <= x
//
// Now if x, y are positive integers then
// (x / y) - 1 <= x // y <= x / y
// Where // denotes integer division.
//
// From this last inequality we immediately derive:
// 3: (2**{2N} / P) - 1 <= I <= (2**{2N} / P)
// 3a: 2**{2N} - P <= PI
//
// Finally, note that by definition:
// input = input_high*(2**N) + input_low
// Hence a simple rearrangement gets us
// 4: input_high*(2**N) = input - input_low
//
//
// We now need to split into cases depending on the sign of input.
// Note that if x = 0 then x' = 0 so that case is trivial.
///////////////////////////////////////////////////////////////////////////
// CASE 1: input > 0
//
// If input > 0 then:
// sub = Q*P = ((((input >> N) * I) >> N) & mask) * P <= P * (input / 2**{N}) * (2**{2N} / P) / 2**{N} = input
// So input - sub >= 0.
//
// We need to improve our bound on Q. Observe that:
// Q = (((input_high * I) >> N) & mask)
// --(2)   => Q + (2^10 - 1) >= (input_high * I) >> N)
// --(1)   => Q + 2^10 >= (I*x_high)/(2**N)
//         => (2**N)*Q + 2^10*(2**N) >= I*x_high
//
// Hence we find that:
// (2**N)*Q*P + 2^10*(2**N)*P >= input_high*I*P
// --(3a)                     >= input_high*2**{2N} - P*input_high
// --(4)                      >= (2**N)*input - (2**N)*input_low - (2**N)*input_high   (Assuming P < 2**N)
//
// Dividing by 2**N we get
// Q*P + 2^{10}*P >= input - input_low - input_high
// which rearranges to
// x' = input - Q*P <= 2^{10}*P + input_low + input_high
//
// Picking N = 40 we see that 2^{10}*P, input_low, input_high are all bounded by 2**40
// Hence x' < 2**42 < 2**50 as desired.
//
//
//
///////////////////////////////////////////////////////////////////////////
// CASE 2: input < 0
//
// This case will be similar but all our inequalities will change slightly as negatives complicate things.
// First observe that:
// (input >> N) * I   >= (input >> N) * 2**(2N) / P
//                    >= (1 + (input / 2**N)) * 2**(2N) / P
//                    >= (2**N + input) * 2**N / P
//
// Thus:
// Q = ((input >> N) * I) >> N >= ((2**N + input) * 2**N / P) >> N
//                             >= ((2**N + input) / P) - 1
//
// And so sub = Q*P >= 2**N - P + input.
// Hence input - sub < 2**N - P.
//
// Thus if input - sub > 0 then |input - sub| < 2**50.
// Thus we are left with bounding -(input - sub) = (sub - input).
// Again we will proceed by improving our bound on Q.
//
// Q = (((input_high * I) >> N) & mask)
// --(2)   => Q <= (input_high * I) >> N) <= (I*x_high)/(2**N)
// --(1)   => Q <= (I*x_high)/(2**N)
//         => (2**N)*Q <= I*x_high
//
// Hence we find that:
// (2**N)*Q*P <= input_high*I*P
// --(3a)     <= input_high*2**{2N} - P*input_high
// --(4)      <= (2**N)*input - (2**N)*input_low - (2**N)*input_high   (Assuming P < 2**N)
//
// Dividing by 2**N we get
// Q*P <= input - input_low - input_high
// which rearranges to
// -x' = -input + Q*P <= -input_high - input_low < 2**50
//
// This completes the proof.

/// Instantiate convolution for "large" RHS vectors over Mersenne31.
///
/// Here "large" means the elements can be as big as the field
/// characteristic, and the size N of the RHS is <= 64.
#[derive(Debug, Clone, Default)]
struct LargeConvolveMontyField31;

impl<FP> Convolve<MontyField31<FP>, i64, i64, i64> for LargeConvolveMontyField31
where
    FP: BarrettParameters,
{
    /// Return the lift of a MontyField31 element, satisfying
    /// 0 <= input.value < P < 2^31.
    /// Note that MontyField31 elements are represented in Monty form.
    #[inline(always)]
    fn read(input: MontyField31<FP>) -> i64 {
        input.value as i64
    }

    #[inline(always)]
    fn parity_dot<const N: usize>(u: [i64; N], v: [i64; N]) -> i64 {
        // For a convolution of size N, |x|, |y| < N * 2^31, so the
        // product could be as much as N^2 * 2^62. This will overflow an
        // i64, so we first widen to i128. Note that N^2 * 2^62 < 2^80
        // for N <= 64, as required by `barrett_red_monty31()`.

        let mut dp = 0i128;
        for i in 0..N {
            dp += u[i] as i128 * v[i] as i128;
        }
        barrett_red_monty31::<FP>(dp)
    }

    #[inline(always)]
    fn reduce(z: i64) -> MontyField31<FP> {
        // After the barrett reduction method, the output z of parity
        // dot satisfies |z| < 2^50 (See Thm 1 above).
        //
        // In the recombining steps, conv_n maps (wo, w1) ->
        // ((wo + w1)/2, (wo + w1)/2) which has no effect on the maximal
        // size. (Indeed, it makes sizes almost strictly smaller).
        //
        // On the other hand, negacyclic_conv_n (ignoring the re-index)
        // recombines as: (w0, w1, w2) -> (w0 + w1, w2 - w0 - w1).
        // Hence if the input is <= K, the output is <= 3K.
        //
        // Thus the values appearing at the end are bounded by 3^n 2^50
        // where n is the maximal number of negacyclic_conv
        // recombination steps. When N = 64, we need to recombine for
        // signed_conv_32, signed_conv_16, signed_conv_8 so the
        // overall bound will be 3^3 2^50 < 32 * 2^50 < 2^55.
        debug_assert!(z > -(1i64 << 55));
        debug_assert!(z < (1i64 << 55));

        // Note we do NOT move it into MONTY form. We assume it is already
        // in this form.
        let red = (z % (FP::PRIME as i64)) as u32;

        // If z >= 0: 0 <= red < P is the correct value and P + red will
        // not overflow.
        // If z < 0: -P < red < 0 and the value we want is P + red.
        // On bits, + acts identically for i32 and u32. Hence we can use
        // u32's and just check for overflow.

        let (corr, over) = red.overflowing_add(FP::PRIME);
        let value = if over { corr } else { red };
        MontyField31::new_monty(value)
    }
}

impl<FP: MontyParameters, MU: MDSUtils> Permutation<[MontyField31<FP>; 8]>
    for MdsMatrixMontyField31<MU>
{
    fn permute(&self, input: [MontyField31<FP>; 8]) -> [MontyField31<FP>; 8] {
        SmallConvolveMontyField31::apply(
            input,
            MU::MATRIX_CIRC_MDS_8_COL,
            <SmallConvolveMontyField31 as Convolve<MontyField31<FP>, i64, i64, i64>>::conv8,
        )
    }
}
impl<FP: MontyParameters, MU: MDSUtils> MdsPermutation<MontyField31<FP>, 8>
    for MdsMatrixMontyField31<MU>
{
}

impl<FP: MontyParameters, MU: MDSUtils> Permutation<[MontyField31<FP>; 12]>
    for MdsMatrixMontyField31<MU>
{
    fn permute(&self, input: [MontyField31<FP>; 12]) -> [MontyField31<FP>; 12] {
        SmallConvolveMontyField31::apply(
            input,
            MU::MATRIX_CIRC_MDS_12_COL,
            <SmallConvolveMontyField31 as Convolve<MontyField31<FP>, i64, i64, i64>>::conv12,
        )
    }
}
impl<FP: MontyParameters, MU: MDSUtils> MdsPermutation<MontyField31<FP>, 12>
    for MdsMatrixMontyField31<MU>
{
}

impl<FP: MontyParameters, MU: MDSUtils> Permutation<[MontyField31<FP>; 16]>
    for MdsMatrixMontyField31<MU>
{
    fn permute(&self, input: [MontyField31<FP>; 16]) -> [MontyField31<FP>; 16] {
        SmallConvolveMontyField31::apply(
            input,
            MU::MATRIX_CIRC_MDS_16_COL,
            <SmallConvolveMontyField31 as Convolve<MontyField31<FP>, i64, i64, i64>>::conv16,
        )
    }
}
impl<FP: MontyParameters, MU: MDSUtils> MdsPermutation<MontyField31<FP>, 16>
    for MdsMatrixMontyField31<MU>
{
}

impl<FP, MU: MDSUtils> Permutation<[MontyField31<FP>; 24]> for MdsMatrixMontyField31<MU>
where
    FP: BarrettParameters,
{
    fn permute(&self, input: [MontyField31<FP>; 24]) -> [MontyField31<FP>; 24] {
        LargeConvolveMontyField31::apply(
            input,
            MU::MATRIX_CIRC_MDS_24_COL,
            <LargeConvolveMontyField31 as Convolve<MontyField31<FP>, i64, i64, i64>>::conv24,
        )
    }
}
impl<FP: BarrettParameters, MU: MDSUtils> MdsPermutation<MontyField31<FP>, 24>
    for MdsMatrixMontyField31<MU>
{
}

impl<FP: BarrettParameters, MU: MDSUtils> Permutation<[MontyField31<FP>; 32]>
    for MdsMatrixMontyField31<MU>
{
    fn permute(&self, input: [MontyField31<FP>; 32]) -> [MontyField31<FP>; 32] {
        LargeConvolveMontyField31::apply(
            input,
            MU::MATRIX_CIRC_MDS_32_COL,
            <LargeConvolveMontyField31 as Convolve<MontyField31<FP>, i64, i64, i64>>::conv32,
        )
    }
}
impl<FP: BarrettParameters, MU: MDSUtils> MdsPermutation<MontyField31<FP>, 32>
    for MdsMatrixMontyField31<MU>
{
}

impl<FP: BarrettParameters, MU: MDSUtils> Permutation<[MontyField31<FP>; 64]>
    for MdsMatrixMontyField31<MU>
{
    fn permute(&self, input: [MontyField31<FP>; 64]) -> [MontyField31<FP>; 64] {
        LargeConvolveMontyField31::apply(
            input,
            MU::MATRIX_CIRC_MDS_64_COL,
            <LargeConvolveMontyField31 as Convolve<MontyField31<FP>, i64, i64, i64>>::conv64,
        )
    }
}
impl<FP: BarrettParameters, MU: MDSUtils> MdsPermutation<MontyField31<FP>, 64>
    for MdsMatrixMontyField31<MU>
{
}

/// Known-answer tests for `MdsMatrixMontyField31::permute` at every supported width (8, 12, 16,
/// 24, 32, 64), using `crate::test_utils::TestMDS` (the same circulant-matrix columns as upstream
/// Plonky3's `MDSBabyBearData`). Because `TestFP` uses the identical prime as BabyBear, the
/// upstream input/output vectors are reused unchanged — this is a genuine cross-implementation
/// check (this crate's generic `SmallConvolveMontyField31`/`LargeConvolveMontyField31` +
/// Karatsuba-convolution `permute` vs. upstream's independently-computed expected outputs), not a
/// vector generated by the code under test.
///
/// 24/32/64 additionally exercise the Barrett-reduction path (`barrett_red_monty31`,
/// `LargeConvolveMontyField31`) which 8/12/16 (`SmallConvolveMontyField31`) do not touch at all.
#[cfg(test)]
mod tests {
    use lib_q_stark_symmetric::Permutation;

    use crate::MdsMatrixMontyField31;
    use crate::test_utils::{
        TestField,
        TestMDS,
    };

    type MdsMatrixTest = MdsMatrixMontyField31<TestMDS>;

    #[test]
    fn width_8() {
        let input: [TestField; 8] = TestField::new_array([
            391474477, 1174409341, 666967492, 1852498830, 1801235316, 820595865, 585587525,
            1348326858,
        ]);
        let expected: [TestField; 8] = TestField::new_array([
            1752937716, 1801468855, 1102954394, 284747746, 1636355768, 205443234, 1235359747,
            1159982032,
        ]);
        let mds: MdsMatrixTest = Default::default();
        assert_eq!(mds.permute(input), expected);
    }

    #[test]
    fn width_12() {
        let input: [TestField; 12] = TestField::new_array([
            918423259, 673549090, 364157140, 9832898, 493922569, 1171855651, 246075034, 1542167926,
            1787615541, 1696819900, 1884530130, 422386768,
        ]);
        let expected: [TestField; 12] = TestField::new_array([
            1631062293, 890348490, 1304705406, 1888740923, 845648570, 717048224, 1082440815,
            914769887, 1872991191, 1366539339, 1805116914, 1998032485,
        ]);
        let mds: MdsMatrixTest = Default::default();
        assert_eq!(mds.permute(input), expected);
    }

    #[test]
    fn width_16() {
        let input: [TestField; 16] = TestField::new_array([
            1983708094, 1477844074, 1638775686, 98517138, 70746308, 968700066, 275567720,
            1359144511, 960499489, 1215199187, 474302783, 79320256, 1923147803, 1197733438,
            1638511323, 303948902,
        ]);
        let expected: [TestField; 16] = TestField::new_array([
            1497569692, 1038070871, 669165859, 456905446, 1116763366, 1267622262, 1985953057,
            1060497461, 704264985, 306103349, 1271339089, 1551541970, 1796459417, 889229849,
            1731972538, 439594789,
        ]);
        let mds: MdsMatrixTest = Default::default();
        assert_eq!(mds.permute(input), expected);
    }

    #[test]
    fn width_24() {
        let input: [TestField; 24] = TestField::new_array([
            1307148929, 1603957607, 1515498600, 1412393512, 785287979, 988718522, 1750345556,
            853137995, 534387281, 930390055, 1600030977, 903985158, 1141020507, 636889442,
            966037834, 1778991639, 1440427266, 1379431959, 853403277, 959593575, 733455867,
            908584009, 817124993, 418826476,
        ]);
        let expected: [TestField; 24] = TestField::new_array([
            1537871777, 1626055274, 1705000179, 1426678258, 1688760658, 1347225494, 1291221794,
            1224656589, 1791446853, 1978133881, 1820380039, 1366829700, 27479566, 409595531,
            1223347944, 1752750033, 594548873, 1447473111, 1385412872, 1111945102, 1366585917,
            138866947, 1326436332, 656898133,
        ]);
        let mds: MdsMatrixTest = Default::default();
        assert_eq!(mds.permute(input), expected);
    }

    #[test]
    fn width_32() {
        let input: [TestField; 32] = TestField::new_array([
            1346087634, 1511946000, 1883470964, 54906057, 233060279, 5304922, 1881494193,
            743728289, 404047361, 1148556479, 144976634, 1726343008, 29659471, 1350407160,
            1636652429, 385978955, 327649601, 1248138459, 1255358242, 84164877, 1005571393,
            1713215328, 72913800, 1683904606, 904763213, 316800515, 656395998, 788184609,
            1824512025, 1177399063, 1358745087, 444151496,
        ]);
        let expected: [TestField; 32] = TestField::new_array([
            1359576919, 1657405784, 1031581836, 212090105, 699048671, 877916349, 205627787,
            1211567750, 210807569, 1696391051, 558468987, 161148427, 304343518, 76611896,
            532792005, 1963649139, 1283500358, 250848292, 1109842541, 2007388683, 433801252,
            1189712914, 626158024, 1436409738, 456315160, 1836818120, 1645024941, 925447491,
            1599571860, 1055439714, 353537136, 379644130,
        ]);
        let mds: MdsMatrixTest = Default::default();
        assert_eq!(mds.permute(input), expected);
    }

    #[test]
    fn width_64() {
        let input: [TestField; 64] = TestField::new_array([
            1931358930, 1322576114, 1658000717, 134388215, 1517892791, 1486447670, 93570662,
            898466034, 1576905917, 283824713, 1433559150, 1730678909, 155340881, 1978472263,
            1980644590, 1814040165, 654743892, 849954227, 323176597, 146970735, 252703735,
            1856579399, 162749290, 986745196, 352038183, 1239527508, 828473247, 1184743572,
            1017249065, 36804843, 1378131210, 1286724687, 596095979, 1916924908, 528946791,
            397247884, 23477278, 299412064, 415288430, 935825754, 1218003667, 1954592289,
            1594612673, 664096455, 958392778, 497208288, 1544504580, 1829423324, 956111902,
            458327015, 1736664598, 430977734, 599887171, 1100074154, 1197653896, 427838651,
            466509871, 1236918100, 940670246, 1421951147, 255557957, 1374188100, 315300068,
            623354170,
        ]);
        let expected: [TestField; 64] = TestField::new_array([
            442300274, 756862170, 167612495, 1103336044, 546496433, 1211822920, 329094196,
            1334376959, 944085937, 977350947, 1445060130, 918469957, 800346119, 1957918170,
            739098112, 1862817833, 1831589884, 1673860978, 698081523, 1128978338, 387929536,
            1106772486, 1367460469, 1911237185, 362669171, 819949894, 1801786287, 1943505026,
            586738185, 996076080, 1641277705, 1680239311, 1005815192, 63087470, 593010310,
            364673774, 543368618, 1576179136, 47618763, 1990080335, 1608655220, 499504830,
            861863262, 765074289, 139277832, 1139970138, 1510286607, 244269525, 43042067,
            119733624, 1314663255, 893295811, 1444902994, 914930267, 1675139862, 1148717487,
            1601328192, 534383401, 296215929, 1924587380, 1336639141, 34897994, 2005302060,
            1780337352,
        ]);
        let mds: MdsMatrixTest = Default::default();
        assert_eq!(mds.permute(input), expected);
    }
}
