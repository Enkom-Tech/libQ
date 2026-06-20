use core::fmt::Debug;

use const_oid::db::fips205;
use digest::{
    ExtendableOutput,
    Update,
};
use hybrid_array::typenum::consts::{
    U16,
    U30,
    U32,
};
use hybrid_array::typenum::{
    U24,
    U34,
    U39,
    U42,
    U47,
    U49,
};
use hybrid_array::{
    Array,
    ArraySize,
};
use lib_q_sha3::Shake256;
use lib_q_sha3::parallel::shake256_x4;
use typenum::U;

use crate::address::Address;
use crate::fors::ForsParams;
use crate::hashes::HashSuite;
use crate::hypertree::HypertreeParams;
use crate::wots::WotsParams;
use crate::xmss::XmssParams;
use crate::{
    ParameterSet,
    PkSeed,
    SkPrf,
    SkSeed,
};

/// Implementation of the component hash functions using SHAKE256
///
/// Follows section 10.1 of FIPS-205.
///
/// SHAKE256 has no SHA-2-style block midstate to cache, so the suite simply stores the
/// pre-built `Shake256` absorbing `pk_seed` and clones it per call. This keeps parity with
/// the SHA-2 suites' instance-method API at negligible cost.
#[derive(Debug, Clone)]
pub struct Shake<N: ArraySize, M> {
    /// `Shake256` pre-updated with `pk_seed`; cloned by `f`/`h`/`t`/`prf_sk`.
    shake256: Shake256,
    /// Raw `pk_seed`, needed by `h_msg` (which absorbs `rand` before `pk_seed`).
    pk_seed: PkSeed<N>,
    _m: core::marker::PhantomData<M>,
}

impl<N: ArraySize, M: ArraySize> HashSuite for Shake<N, M>
where
    N: Debug + Clone + PartialEq + Eq,
    M: Debug + Clone + PartialEq + Eq,
{
    type N = N;
    type M = M;

    fn new_from_pk_seed(pk_seed: &PkSeed<Self::N>) -> Self {
        let mut shake256 = Shake256::default();
        shake256.update(pk_seed.as_ref());
        Self {
            shake256,
            pk_seed: pk_seed.clone(),
            _m: core::marker::PhantomData,
        }
    }

    fn prf_msg(
        &self,
        sk_prf: &SkPrf<Self::N>,
        opt_rand: &Array<u8, Self::N>,
        msg: &[&[impl AsRef<[u8]>]],
    ) -> Array<u8, Self::N> {
        let mut hasher = Shake256::default();
        hasher.update(sk_prf.as_ref());
        hasher.update(opt_rand.as_slice());
        msg.iter()
            .copied()
            .flatten()
            .for_each(|msg_part| hasher.update(msg_part.as_ref()));
        let mut output = Array::<u8, Self::N>::default();
        hasher.finalize_xof_into(&mut output);
        output
    }

    fn h_msg(
        &self,
        rand: &Array<u8, Self::N>,
        pk_root: &Array<u8, Self::N>,
        msg: &[&[impl AsRef<[u8]>]],
    ) -> Array<u8, Self::M> {
        // `rand` precedes `pk_seed`, so the cached `shake256` state cannot be reused here.
        let mut hasher = Shake256::default();
        hasher.update(rand.as_slice());
        hasher.update(self.pk_seed.as_ref());
        hasher.update(pk_root.as_ref());
        msg.iter()
            .copied()
            .flatten()
            .for_each(|msg_part| hasher.update(msg_part.as_ref()));
        let mut output = Array::<u8, Self::M>::default();
        hasher.finalize_xof_into(&mut output);
        output
    }

    fn prf_sk(&self, sk_seed: &SkSeed<Self::N>, adrs: &impl Address) -> Array<u8, Self::N> {
        let mut hasher = self.shake256.clone();
        hasher.update(adrs.as_ref());
        hasher.update(sk_seed.as_ref());
        let mut output = Array::<u8, Self::N>::default();
        hasher.finalize_xof_into(&mut output);
        output
    }

    fn t<L: ArraySize>(
        &self,
        adrs: &impl Address,
        m: &Array<Array<u8, Self::N>, L>,
    ) -> Array<u8, Self::N> {
        let mut hasher = self.shake256.clone();
        hasher.update(adrs.as_ref());
        for i in 0..L::USIZE {
            hasher.update(m[i].as_slice());
        }
        let mut output = Array::<u8, Self::N>::default();
        hasher.finalize_xof_into(&mut output);
        output
    }

    fn h(
        &self,
        adrs: &impl Address,
        m1: &Array<u8, Self::N>,
        m2: &Array<u8, Self::N>,
    ) -> Array<u8, Self::N> {
        let mut hasher = self.shake256.clone();
        hasher.update(adrs.as_ref());
        hasher.update(m1.as_slice());
        hasher.update(m2.as_slice());
        let mut output = Array::<u8, Self::N>::default();
        hasher.finalize_xof_into(&mut output);
        output
    }

    fn f(&self, adrs: &impl Address, m: &Array<u8, Self::N>) -> Array<u8, Self::N> {
        let mut hasher = self.shake256.clone();
        hasher.update(adrs.as_ref());
        hasher.update(m.as_slice());
        let mut output = Array::<u8, Self::N>::default();
        hasher.finalize_xof_into(&mut output);
        output
    }

    /// Batched `f` over four independent WOTS+/FORS hash inputs — `SHAKE256(pk_seed ‖ adrs ‖ m)`,
    /// bit-for-bit identical to four scalar [`f`](Self::f) calls (the permutation falls back to four
    /// scalar rounds without AVX2, so this is never slower and never differs).
    fn f_x4<A: Address>(
        &self,
        adrs: &[A; 4],
        m: &[Array<u8, Self::N>; 4],
    ) -> [Array<u8, Self::N>; 4] {
        Self::batch_shake256_x4(|lane, buf| {
            let pk = self.pk_seed.as_ref();
            let mut p = write_at(buf, 0, pk);
            p = write_at(buf, p, adrs[lane].as_ref());
            write_at(buf, p, m[lane].as_slice())
        })
    }

    /// Batched `h` (Merkle node) — `SHAKE256(pk_seed ‖ adrs ‖ m1 ‖ m2)`, used to fold FORS levels.
    fn h_x4<A: Address>(
        &self,
        adrs: &[A; 4],
        m1: &[Array<u8, Self::N>; 4],
        m2: &[Array<u8, Self::N>; 4],
    ) -> [Array<u8, Self::N>; 4] {
        Self::batch_shake256_x4(|lane, buf| {
            let pk = self.pk_seed.as_ref();
            let mut p = write_at(buf, 0, pk);
            p = write_at(buf, p, adrs[lane].as_ref());
            p = write_at(buf, p, m1[lane].as_slice());
            write_at(buf, p, m2[lane].as_slice())
        })
    }

    /// Batched `prf_sk` — `SHAKE256(pk_seed ‖ adrs ‖ sk_seed)`, used to generate four FORS/WOTS
    /// secret values at once.
    fn prf_sk_x4<A: Address>(
        &self,
        sk_seed: &SkSeed<Self::N>,
        adrs: &[A; 4],
    ) -> [Array<u8, Self::N>; 4] {
        Self::batch_shake256_x4(|lane, buf| {
            let pk = self.pk_seed.as_ref();
            let mut p = write_at(buf, 0, pk);
            p = write_at(buf, p, adrs[lane].as_ref());
            write_at(buf, p, sk_seed.as_ref())
        })
    }
}

/// Copy `src` into `buf` starting at `off`, returning the new offset. Small inline cursor used by
/// the batched SHAKE builders.
#[inline]
fn write_at(buf: &mut [u8], off: usize, src: &[u8]) -> usize {
    buf[off..off + src.len()].copy_from_slice(src);
    off + src.len()
}

impl<N: ArraySize, M> Shake<N, M> {
    /// Build four equal-length SHAKE256 input blocks via `fill` (which returns each lane's length),
    /// hash them with [`shake256_x4`], and return the four `N`-byte digests. All SLH-DSA SHAKE
    /// component hashes fit a single 136-byte rate block: `pk_seed (N≤32) + ADRS (32) + up to two
    /// N-byte messages ≤ 128`, so a 128-byte per-lane scratch buffer always suffices.
    #[inline]
    fn batch_shake256_x4<F>(fill: F) -> [Array<u8, N>; 4]
    where
        F: Fn(usize, &mut [u8; 128]) -> usize,
    {
        let mut bufs = [[0u8; 128]; 4];
        let mut len = 0usize;
        for (lane, buf) in bufs.iter_mut().enumerate() {
            len = fill(lane, buf);
        }
        debug_assert!(len <= 128);

        let mut outs: [Array<u8, N>; 4] = core::array::from_fn(|_| Array::default());
        {
            let [o0, o1, o2, o3] = &mut outs;
            shake256_x4(
                [
                    &bufs[0][..len],
                    &bufs[1][..len],
                    &bufs[2][..len],
                    &bufs[3][..len],
                ],
                [
                    o0.as_mut_slice(),
                    o1.as_mut_slice(),
                    o2.as_mut_slice(),
                    o3.as_mut_slice(),
                ],
            );
        }
        outs
    }
}

// TODO: Consolidate parameters between Shake and SHA2 instances

/// SHAKE256 at L1 security with small signatures
pub type Shake128s = Shake<U16, U30>;
impl WotsParams for Shake128s {
    type WotsMsgLen = U<32>;
    type WotsSigLen = U<35>;
}
impl XmssParams for Shake128s {
    type HPrime = U<9>;
}
impl HypertreeParams for Shake128s {
    type D = U<7>;
    type H = U<63>;
}
impl ForsParams for Shake128s {
    type K = U<14>;
    type A = U<12>;
    type MD = U<{ (12 * 14usize).div_ceil(8) }>;
}
impl ParameterSet for Shake128s {
    const NAME: &'static str = "SLH-DSA-SHAKE-128s";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHAKE_128_S;
}

/// SHAKE256 at L1 security with fast signatures
pub type Shake128f = Shake<U16, U34>;
impl WotsParams for Shake128f {
    type WotsMsgLen = U<32>;
    type WotsSigLen = U<35>;
}
impl XmssParams for Shake128f {
    type HPrime = U<3>;
}
impl HypertreeParams for Shake128f {
    type D = U<22>;
    type H = U<66>;
}
impl ForsParams for Shake128f {
    type K = U<33>;
    type A = U<6>;
    type MD = U<25>;
}
impl ParameterSet for Shake128f {
    const NAME: &'static str = "SLH-DSA-SHAKE-128f";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHAKE_128_F;
}

/// SHAKE256 at L3 security with small signatures
pub type Shake192s = Shake<U24, U39>;
impl WotsParams for Shake192s {
    type WotsMsgLen = U<{ 24 * 2 }>;
    type WotsSigLen = U<{ 24 * 2 + 3 }>;
}
impl XmssParams for Shake192s {
    type HPrime = U<9>;
}
impl HypertreeParams for Shake192s {
    type D = U<7>;
    type H = U<63>;
}
impl ForsParams for Shake192s {
    type K = U<17>;
    type A = U<14>;
    type MD = U<{ (14 * 17usize).div_ceil(8) }>;
}
impl ParameterSet for Shake192s {
    const NAME: &'static str = "SLH-DSA-SHAKE-192s";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHAKE_192_S;
}

/// SHAKE256 at L3 security with fast signatures
pub type Shake192f = Shake<U24, U42>;
impl WotsParams for Shake192f {
    type WotsMsgLen = U<{ 24 * 2 }>;
    type WotsSigLen = U<{ 24 * 2 + 3 }>;
}
impl XmssParams for Shake192f {
    type HPrime = U<3>;
}
impl HypertreeParams for Shake192f {
    type D = U<22>;
    type H = U<66>;
}
impl ForsParams for Shake192f {
    type K = U<33>;
    type A = U<8>;
    type MD = U<{ (33 * 8usize).div_ceil(8) }>;
}
impl ParameterSet for Shake192f {
    const NAME: &'static str = "SLH-DSA-SHAKE-192f";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHAKE_192_F;
}

/// SHAKE256 at L5 security with small signatures
pub type Shake256s = Shake<U32, U47>;
impl WotsParams for Shake256s {
    type WotsMsgLen = U<{ 32 * 2 }>;
    type WotsSigLen = U<{ 32 * 2 + 3 }>;
}
impl XmssParams for Shake256s {
    type HPrime = U<8>;
}
impl HypertreeParams for Shake256s {
    type D = U<8>;
    type H = U<64>;
}
impl ForsParams for Shake256s {
    type K = U<22>;
    type A = U<14>;
    type MD = U<{ (14 * 22usize).div_ceil(8) }>;
}
impl ParameterSet for Shake256s {
    const NAME: &'static str = "SLH-DSA-SHAKE-256s";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHAKE_256_S;
}

/// SHAKE256 at L5 security with fast signatures
pub type Shake256f = Shake<U32, U49>;
impl WotsParams for Shake256f {
    type WotsMsgLen = U<{ 32 * 2 }>;
    type WotsSigLen = U<{ 32 * 2 + 3 }>;
}
impl XmssParams for Shake256f {
    type HPrime = U<4>;
}
impl HypertreeParams for Shake256f {
    type D = U<17>;
    type H = U<68>;
}
impl ForsParams for Shake256f {
    type K = U<35>;
    type A = U<9>;
    type MD = U<{ (35 * 9usize).div_ceil(8) }>;
}
impl ParameterSet for Shake256f {
    const NAME: &'static str = "SLH-DSA-SHAKE-256f";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHAKE_256_F;
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;
    fn prf_msg<H: HashSuite>() {
        let sk_prf = SkPrf(Array::<u8, H::N>::from_fn(|_| 0));
        let opt_rand = Array::<u8, H::N>::from_fn(|_| 1);
        let msg = [2u8; 32];
        let pk_seed = PkSeed(Array::<u8, H::N>::from_fn(|_| 0));
        let hasher = H::new_from_pk_seed(&pk_seed);

        let expected = hex!("bc5c062307df0a41aeeae19ad655f7b2");

        let result = hasher.prf_msg(&sk_prf, &opt_rand, &[&[msg]]);

        assert_eq!(result.as_slice(), expected);
    }

    #[test]
    fn prf_msg_16_30() {
        prf_msg::<Shake128f>();
    }
}
