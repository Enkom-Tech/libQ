use core::fmt::Debug;

use const_oid::db::fips205;
use digest::{
    Digest,
    KeyInit,
    Mac,
};
use hmac::Hmac;
use hybrid_array::{
    Array,
    ArraySize,
};
use sha2::{
    Sha256,
    Sha512,
};
use typenum::{
    Diff,
    Sum,
    U,
    U16,
    U24,
    U30,
    U32,
    U34,
    U39,
    U42,
    U47,
    U49,
    U64,
    U128,
};

use crate::address::Address;
use crate::fors::ForsParams;
use crate::hashes::HashSuite;
use crate::hypertree::HypertreeParams;
use crate::util::array_u8_try_from_prefix;
use crate::wots::WotsParams;
use crate::xmss::XmssParams;
use crate::{
    ParameterSet,
    PkSeed,
    SkPrf,
    SkSeed,
};

/// Implementation of the MGF1 XOF
fn mgf1<H: Digest, L: ArraySize>(seed: &[u8]) -> Array<u8, L> {
    let mut result = Array::<u8, L>::default();
    result
        .chunks_mut(<H as Digest>::output_size())
        .enumerate()
        .for_each(|(counter, chunk)| {
            let counter: u32 = counter
                .try_into()
                .expect("L should be less than (2^32 * Digest::output_size) bytes");
            let mut hasher = H::new();
            hasher.update(seed);
            hasher.update(counter.to_be_bytes());
            let result = hasher.finalize();
            chunk.copy_from_slice(&result[..chunk.len()]);
        });
    result
}

/// Implementation of the component hash functions using SHA2 at Security Category 1
///
/// Follows section 10.2 of FIPS-205.
///
/// The `Sha256` state is pre-initialized with the padded `PkSeed` block (FIPS-205 §8.1.6
/// midstate caching): every `f`/`h`/`t`/`prf_sk` call clones this state and only needs to
/// absorb the compressed address and message, producing identical output to recomputing
/// the full hash.
#[derive(Debug, Clone)]
pub struct Sha2L1<N: ArraySize, M> {
    /// `Sha256` pre-updated with `pad(pk_seed)` (`pk_seed` zero-padded to the 64-byte block).
    sha256: Sha256,
    /// Retained so the suite can be cloned / reconstructed and to type the seed length.
    pk_seed: PkSeed<N>,
    _m: core::marker::PhantomData<M>,
}

impl<N: ArraySize, M: ArraySize> HashSuite for Sha2L1<N, M>
where
    N: core::ops::Add<N>,
    Sum<N, N>: ArraySize,
    Sum<N, N>: core::ops::Add<U32>,
    Sum<Sum<N, N>, U32>: ArraySize,
    U64: core::ops::Sub<N>,
    Diff<U64, N>: ArraySize,
    N: Debug + PartialEq + Eq,
    M: Debug + PartialEq + Eq,
{
    type N = N;
    type M = M;

    fn new_from_pk_seed(pk_seed: &PkSeed<Self::N>) -> Self {
        let zeroes = Array::<u8, Diff<U64, N>>::default();
        let sha256 = Sha256::new().chain_update(pk_seed).chain_update(&zeroes);
        Self {
            sha256,
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
        let mut mac = Hmac::<Sha256>::new_from_slice(sk_prf.as_ref()).unwrap();
        mac.update(opt_rand.as_slice());
        msg.iter()
            .copied()
            .flatten()
            .for_each(|msg_part| mac.update(msg_part.as_ref()));
        let result = mac.finalize().into_bytes();
        array_u8_try_from_prefix::<Self::N, _>(&result).expect("HMAC output is at least N bytes")
    }

    fn h_msg(
        &self,
        rand: &Array<u8, Self::N>,
        pk_root: &Array<u8, Self::N>,
        msg: &[&[impl AsRef<[u8]>]],
    ) -> Array<u8, Self::M> {
        let pk_seed = &self.pk_seed;
        let mut h = Sha256::new();
        h.update(rand);
        h.update(pk_seed);
        h.update(pk_root);
        msg.iter()
            .copied()
            .flatten()
            .for_each(|msg_part| h.update(msg_part.as_ref()));
        let result = Array(h.finalize().into());
        let seed = rand.clone().concat(pk_seed.0.clone()).concat(result);
        mgf1::<Sha256, Self::M>(&seed)
    }

    fn prf_sk(&self, sk_seed: &SkSeed<Self::N>, adrs: &impl Address) -> Array<u8, Self::N> {
        let hash = self
            .sha256
            .clone()
            .chain_update(adrs.compressed())
            .chain_update(sk_seed)
            .finalize();
        array_u8_try_from_prefix::<Self::N, _>(&hash).expect("hash output is at least N bytes")
    }

    fn t<L: ArraySize>(
        &self,
        adrs: &impl Address,
        m: &Array<Array<u8, Self::N>, L>,
    ) -> Array<u8, Self::N> {
        let mut sha = self.sha256.clone().chain_update(adrs.compressed());
        m.iter().for_each(|x| sha.update(x.as_slice()));
        let hash = sha.finalize();
        array_u8_try_from_prefix::<Self::N, _>(&hash).expect("hash output is at least N bytes")
    }

    fn h(
        &self,
        adrs: &impl Address,
        m1: &Array<u8, Self::N>,
        m2: &Array<u8, Self::N>,
    ) -> Array<u8, Self::N> {
        let hash = self
            .sha256
            .clone()
            .chain_update(adrs.compressed())
            .chain_update(m1)
            .chain_update(m2)
            .finalize();
        array_u8_try_from_prefix::<Self::N, _>(&hash).expect("hash output is at least N bytes")
    }

    fn f(&self, adrs: &impl Address, m: &Array<u8, Self::N>) -> Array<u8, Self::N> {
        let hash = self
            .sha256
            .clone()
            .chain_update(adrs.compressed())
            .chain_update(m)
            .finalize();
        array_u8_try_from_prefix::<Self::N, _>(&hash).expect("hash output is at least N bytes")
    }
}

/// SHA2 at L1 security with small signatures
pub type Sha2_128s = Sha2L1<U16, U30>;
impl WotsParams for Sha2_128s {
    type WotsMsgLen = U<32>;
    type WotsSigLen = U<35>;
}
impl XmssParams for Sha2_128s {
    type HPrime = U<9>;
}
impl HypertreeParams for Sha2_128s {
    type D = U<7>;
    type H = U<63>;
}
impl ForsParams for Sha2_128s {
    type K = U<14>;
    type A = U<12>;
    type MD = U<{ (12 * 14usize).div_ceil(8) }>;
}
impl ParameterSet for Sha2_128s {
    const NAME: &'static str = "SLH-DSA-SHA2-128s";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHA_2_128_S;
}

/// SHA2 at L1 security with fast signatures
pub type Sha2_128f = Sha2L1<U16, U34>;
impl WotsParams for Sha2_128f {
    type WotsMsgLen = U<32>;
    type WotsSigLen = U<35>;
}
impl XmssParams for Sha2_128f {
    type HPrime = U<3>;
}
impl HypertreeParams for Sha2_128f {
    type D = U<22>;
    type H = U<66>;
}
impl ForsParams for Sha2_128f {
    type K = U<33>;
    type A = U<6>;
    type MD = U<25>;
}
impl ParameterSet for Sha2_128f {
    const NAME: &'static str = "SLH-DSA-SHA2-128f";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHA_2_128_F;
}

/// Implementation of the component hash functions using SHA2 at Security Category 3 and 5
///
/// Follows section 10.2 of FIPS-205.
///
/// Two midstates are cached (FIPS-205 §8.1.6): a `Sha256` pre-updated with the padded
/// `PkSeed` 64-byte block (used by `f`/`prf_sk`) and a `Sha512` pre-updated with the
/// padded `PkSeed` 128-byte block (used by `t`/`h`). Each call clones the relevant
/// midstate, producing output identical to recomputing the full hash.
#[derive(Debug, Clone)]
pub struct Sha2L35<N: ArraySize, M> {
    /// `Sha256` pre-updated with `pad_64(pk_seed)`; used by `f` and `prf_sk`.
    sha256: Sha256,
    /// `Sha512` pre-updated with `pad_128(pk_seed)`; used by `t` and `h`.
    sha512: Sha512,
    /// Retained for `h_msg` (which uses `pk_seed` differently) and to type the seed length.
    pk_seed: PkSeed<N>,
    _m: core::marker::PhantomData<M>,
}

impl<N: ArraySize, M: ArraySize> HashSuite for Sha2L35<N, M>
where
    N: core::ops::Add<N>,
    Sum<N, N>: ArraySize,
    Sum<N, N>: core::ops::Add<U64>,
    Sum<Sum<N, N>, U64>: ArraySize,
    U64: core::ops::Sub<N>,
    Diff<U64, N>: ArraySize,
    U128: core::ops::Sub<N>,
    Diff<U128, N>: ArraySize,
    N: core::fmt::Debug + PartialEq + Eq,
    M: core::fmt::Debug + PartialEq + Eq,
{
    type N = N;
    type M = M;

    fn new_from_pk_seed(pk_seed: &PkSeed<Self::N>) -> Self {
        let zeroes_64 = Array::<u8, Diff<U64, N>>::default();
        let sha256 = Sha256::new().chain_update(pk_seed).chain_update(&zeroes_64);
        let zeroes_128 = Array::<u8, Diff<U128, N>>::default();
        let sha512 = Sha512::new()
            .chain_update(pk_seed)
            .chain_update(&zeroes_128);
        Self {
            sha256,
            sha512,
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
        let mut mac = Hmac::<Sha512>::new_from_slice(sk_prf.as_ref()).unwrap();
        mac.update(opt_rand.as_slice());
        msg.iter()
            .copied()
            .flatten()
            .for_each(|msg_part| mac.update(msg_part.as_ref()));
        let result = mac.finalize().into_bytes();
        array_u8_try_from_prefix::<Self::N, _>(&result).expect("HMAC output is at least N bytes")
    }

    fn h_msg(
        &self,
        rand: &Array<u8, Self::N>,
        pk_root: &Array<u8, Self::N>,
        msg: &[&[impl AsRef<[u8]>]],
    ) -> Array<u8, Self::M> {
        let pk_seed = &self.pk_seed;
        let mut h = Sha512::new();
        h.update(rand);
        h.update(pk_seed);
        h.update(pk_root);
        msg.iter()
            .copied()
            .flatten()
            .for_each(|msg_part| h.update(msg_part.as_ref()));
        let result = Array(h.finalize().into());
        let seed = rand.clone().concat(pk_seed.0.clone()).concat(result);
        mgf1::<Sha512, Self::M>(&seed)
    }

    fn prf_sk(&self, sk_seed: &SkSeed<Self::N>, adrs: &impl Address) -> Array<u8, Self::N> {
        let hash = self
            .sha256
            .clone()
            .chain_update(adrs.compressed())
            .chain_update(sk_seed)
            .finalize();
        array_u8_try_from_prefix::<Self::N, _>(&hash).expect("hash output is at least N bytes")
    }

    fn t<L: ArraySize>(
        &self,
        adrs: &impl Address,
        m: &Array<Array<u8, Self::N>, L>,
    ) -> Array<u8, Self::N> {
        let mut sha = self.sha512.clone().chain_update(adrs.compressed());
        m.iter().for_each(|x| sha.update(x.as_slice()));
        let hash = sha.finalize();
        array_u8_try_from_prefix::<Self::N, _>(&hash).expect("hash output is at least N bytes")
    }

    fn h(
        &self,
        adrs: &impl Address,
        m1: &Array<u8, Self::N>,
        m2: &Array<u8, Self::N>,
    ) -> Array<u8, Self::N> {
        let hash = self
            .sha512
            .clone()
            .chain_update(adrs.compressed())
            .chain_update(m1)
            .chain_update(m2)
            .finalize();
        array_u8_try_from_prefix::<Self::N, _>(&hash).expect("hash output is at least N bytes")
    }

    fn f(&self, adrs: &impl Address, m: &Array<u8, Self::N>) -> Array<u8, Self::N> {
        let hash = self
            .sha256
            .clone()
            .chain_update(adrs.compressed())
            .chain_update(m)
            .finalize();
        array_u8_try_from_prefix::<Self::N, _>(&hash).expect("hash output is at least N bytes")
    }
}

/// SHA2 at L3 security with small signatures
pub type Sha2_192s = Sha2L35<U24, U39>;
impl WotsParams for Sha2_192s {
    type WotsMsgLen = U<{ 24 * 2 }>;
    type WotsSigLen = U<{ 24 * 2 + 3 }>;
}
impl XmssParams for Sha2_192s {
    type HPrime = U<9>;
}
impl HypertreeParams for Sha2_192s {
    type D = U<7>;
    type H = U<63>;
}
impl ForsParams for Sha2_192s {
    type K = U<17>;
    type A = U<14>;
    type MD = U<{ (14 * 17usize).div_ceil(8) }>;
}
impl ParameterSet for Sha2_192s {
    const NAME: &'static str = "SLH-DSA-SHA2-192s";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHA_2_192_S;
}

/// SHA2 at L3 security with fast signatures
pub type Sha2_192f = Sha2L35<U24, U42>;
impl WotsParams for Sha2_192f {
    type WotsMsgLen = U<{ 24 * 2 }>;
    type WotsSigLen = U<{ 24 * 2 + 3 }>;
}
impl XmssParams for Sha2_192f {
    type HPrime = U<3>;
}
impl HypertreeParams for Sha2_192f {
    type D = U<22>;
    type H = U<66>;
}
impl ForsParams for Sha2_192f {
    type K = U<33>;
    type A = U<8>;
    type MD = U<{ (33 * 8usize).div_ceil(8) }>;
}
impl ParameterSet for Sha2_192f {
    const NAME: &'static str = "SLH-DSA-SHA2-192f";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHA_2_192_F;
}

/// SHA2 at L5 security with small signatures
pub type Sha2_256s = Sha2L35<U32, U47>;
impl WotsParams for Sha2_256s {
    type WotsMsgLen = U<{ 32 * 2 }>;
    type WotsSigLen = U<{ 32 * 2 + 3 }>;
}
impl XmssParams for Sha2_256s {
    type HPrime = U<8>;
}
impl HypertreeParams for Sha2_256s {
    type D = U<8>;
    type H = U<64>;
}
impl ForsParams for Sha2_256s {
    type K = U<22>;
    type A = U<14>;
    type MD = U<{ (14 * 22usize).div_ceil(8) }>;
}
impl ParameterSet for Sha2_256s {
    const NAME: &'static str = "SLH-DSA-SHA2-256s";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHA_2_256_S;
}

/// SHA2 at L5 security with fast signatures
pub type Sha2_256f = Sha2L35<U32, U49>;
impl WotsParams for Sha2_256f {
    type WotsMsgLen = U<{ 32 * 2 }>;
    type WotsSigLen = U<{ 32 * 2 + 3 }>;
}
impl XmssParams for Sha2_256f {
    type HPrime = U<4>;
}
impl HypertreeParams for Sha2_256f {
    type D = U<17>;
    type H = U<68>;
}
impl ForsParams for Sha2_256f {
    type K = U<35>;
    type A = U<9>;
    type MD = U<{ (35 * 9usize).div_ceil(8) }>;
}
impl ParameterSet for Sha2_256f {
    const NAME: &'static str = "SLH-DSA-SHA2-256f";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHA_2_256_F;
}
