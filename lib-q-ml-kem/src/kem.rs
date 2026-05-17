use core::marker::PhantomData;

use hybrid_array::typenum::U32;
use rand_core::{
    CryptoRng,
    Rng,
};
use zeroize::{
    Zeroize,
    ZeroizeOnDrop,
    Zeroizing,
};

use crate::crypto::{
    G,
    H,
    J,
    rand,
};
use crate::param::{
    DecapsulationKeySize,
    EncapsulationKeySize,
    EncodedCiphertext,
    KemParams,
};
use crate::pke::{
    DecryptionKey,
    EncryptionKey,
};
use crate::util::{
    B32,
    SecretB32,
};
// Re-export traits from our own implementation
pub use crate::{
    Decapsulate,
    Encapsulate,
};
use crate::{
    Encoded,
    EncodedSizeUser,
};

/// A shared key resulting from an ML-KEM transaction
pub(crate) type SharedKey = B32;

/// A `DecapsulationKey` provides the ability to generate a new key pair, and decapsulate an
/// encapsulated shared key.
#[derive(Clone, Debug, PartialEq)]
pub struct DecapsulationKey<P>
where
    P: KemParams,
{
    dk_pke: DecryptionKey<P>,
    ek: EncapsulationKey<P>,
    z: B32,
}

impl<P> Drop for DecapsulationKey<P>
where
    P: KemParams,
{
    fn drop(&mut self) {
        self.dk_pke.zeroize();
        self.z.zeroize();
    }
}

impl<P> ZeroizeOnDrop for DecapsulationKey<P> where P: KemParams {}

impl<P> EncodedSizeUser for DecapsulationKey<P>
where
    P: KemParams,
{
    type EncodedSize = DecapsulationKeySize<P>;

    #[allow(clippy::similar_names)] // allow dk_pke, ek_pke, following the spec
    fn from_bytes(enc: &Encoded<Self>) -> Self {
        let (dk_pke, ek_pke, h, z) = P::split_dk(enc);
        let ek_pke = EncryptionKey::from_bytes(ek_pke);

        // XXX(RLB): The encoding here is redundant, since `h` can be computed from `ek_pke`.
        // Should we verify that the provided `h` value is valid?

        Self {
            dk_pke: DecryptionKey::from_bytes(dk_pke),
            ek: EncapsulationKey {
                ek_pke,
                h: h.clone(),
            },
            z: z.clone(),
        }
    }

    fn as_bytes(&self) -> Zeroizing<Encoded<Self>> {
        Zeroizing::new(P::concat_dk(
            self.dk_pke.as_bytes(),
            self.ek.ek_pke.as_bytes(),
            self.ek.h.clone(),
            self.z.clone(),
        ))
    }
}

// 0xff if x == y, 0x00 otherwise (non-hardened path; hardened uses `subtle` in `masking`).
#[cfg(not(feature = "hardened"))]
fn constant_time_eq(x: u8, y: u8) -> u8 {
    let diff = x ^ y;
    let is_zero = !diff & diff.wrapping_sub(1);
    0u8.wrapping_sub(is_zero >> 7)
}

impl<P> crate::Decapsulate<EncodedCiphertext<P>, SharedKey> for DecapsulationKey<P>
where
    P: KemParams,
{
    type Error = core::convert::Infallible;

    fn decapsulate(
        &self,
        encapsulated_key: &EncodedCiphertext<P>,
    ) -> Result<SharedKey, Self::Error> {
        let mp = SecretB32::new(self.dk_pke.decrypt(encapsulated_key));
        let (kp, rp_raw) = G(&[&*mp, &self.ek.h]);
        let Kp = SecretB32::new(kp);
        let rp = SecretB32::new(rp_raw);
        let Kbar = SecretB32::new(J(&[self.z.as_slice(), encapsulated_key.as_ref()]));
        let cp = self.ek.ek_pke.encrypt(&mp, &rp);

        // Constant-time version of:
        //
        // if cp == *ct {
        //     Kp
        // } else {
        //     Kbar
        // }
        #[cfg(feature = "hardened")]
        {
            let eq_bytes =
                crate::masking::ciphertexts_equal_ct(cp.as_ref(), encapsulated_key.as_ref());
            let eq_ring =
                crate::masking::ciphertexts_equal_arithmetic_domain_ct::<P>(&cp, encapsulated_key);
            let eq = eq_bytes & eq_ring;
            Ok(crate::masking::select_shared_key_bytes_ct(eq, &Kp, &Kbar))
        }
        #[cfg(not(feature = "hardened"))]
        {
            let equal = cp
                .iter()
                .zip(encapsulated_key.iter())
                .map(|(&x, &y)| constant_time_eq(x, y))
                .fold(0xFF, |x, y| x & y);
            Ok(Kp
                .iter()
                .zip(Kbar.iter())
                .map(|(x, y)| (equal & x) | (!equal & y))
                .collect())
        }
    }
}

impl<P> DecapsulationKey<P>
where
    P: KemParams,
{
    /// Get the [`EncapsulationKey`] which corresponds to this [`DecapsulationKey`].
    pub fn encapsulation_key(&self) -> &EncapsulationKey<P> {
        &self.ek
    }

    pub(crate) fn generate<R: CryptoRng + Rng + ?Sized>(rng: &mut R) -> Self {
        let d: B32 = rand(rng);
        let z: B32 = rand(rng);
        Self::generate_deterministic(&d, &z)
    }

    #[must_use]
    #[allow(clippy::similar_names)] // allow dk_pke, ek_pke, following the spec
    pub(crate) fn generate_deterministic(d: &B32, z: &B32) -> Self {
        let (dk_pke, ek_pke) = DecryptionKey::generate(d);
        let ek = EncapsulationKey::new(ek_pke);
        let z = z.clone();
        Self { dk_pke, ek, z }
    }
}

/// An `EncapsulationKey` provides the ability to encapsulate a shared key so that it can only be
/// decapsulated by the holder of the corresponding decapsulation key.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct EncapsulationKey<P>
where
    P: KemParams,
{
    ek_pke: EncryptionKey<P>,
    h: B32,
}

impl<P> EncapsulationKey<P>
where
    P: KemParams,
{
    fn new(ek_pke: EncryptionKey<P>) -> Self {
        let h = H(ek_pke.as_bytes().as_slice());
        Self { ek_pke, h }
    }

    fn encapsulate_deterministic_inner(&self, m: &B32) -> (EncodedCiphertext<P>, SharedKey) {
        let (K, r) = G(&[m, &self.h]);
        let r = SecretB32::new(r);
        let c = self.ek_pke.encrypt(m, &r);
        (c, K)
    }
}

impl<P> EncodedSizeUser for EncapsulationKey<P>
where
    P: KemParams,
{
    type EncodedSize = EncapsulationKeySize<P>;

    fn from_bytes(enc: &Encoded<Self>) -> Self {
        Self::new(EncryptionKey::from_bytes(enc))
    }

    fn as_bytes(&self) -> Zeroizing<Encoded<Self>> {
        Zeroizing::new(self.ek_pke.as_bytes())
    }
}

impl<P> crate::Encapsulate<EncodedCiphertext<P>, SharedKey> for EncapsulationKey<P>
where
    P: KemParams,
{
    type Error = core::convert::Infallible;

    fn encapsulate<R: CryptoRng + Rng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<(EncodedCiphertext<P>, SharedKey), Self::Error> {
        let m = SecretB32::new(rand(rng));
        Ok(self.encapsulate_deterministic_inner(&m))
    }
}

#[cfg(feature = "deterministic")]
impl<P> crate::EncapsulateDeterministic<EncodedCiphertext<P>, SharedKey> for EncapsulationKey<P>
where
    P: KemParams,
{
    type Error = core::convert::Infallible;

    fn encapsulate_deterministic(
        &self,
        m: &B32,
    ) -> Result<(EncodedCiphertext<P>, SharedKey), Self::Error> {
        Ok(self.encapsulate_deterministic_inner(m))
    }
}

/// An implementation of overall ML-KEM functionality.  Generic over parameter sets, but then ties
/// together all of the other related types and sizes.
#[derive(Clone)]
pub struct Kem<P>
where
    P: KemParams,
{
    _phantom: PhantomData<P>,
}

impl<P> crate::KemCore for Kem<P>
where
    P: KemParams,
{
    type SharedKeySize = U32;
    type CiphertextSize = P::CiphertextSize;
    type DecapsulationKey = DecapsulationKey<P>;
    type EncapsulationKey = EncapsulationKey<P>;

    /// Generate a new (decapsulation, encapsulation) key pair
    fn generate<R: CryptoRng + Rng + ?Sized>(
        rng: &mut R,
    ) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let dk = Self::DecapsulationKey::generate(rng);
        let ek = dk.encapsulation_key().clone();
        (dk, ek)
    }

    #[cfg(feature = "deterministic")]
    fn generate_deterministic(
        d: &B32,
        z: &B32,
    ) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let dk = Self::DecapsulationKey::generate_deterministic(d, z);
        let ek = dk.encapsulation_key().clone();
        (dk, ek)
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "random")]
    use super::*;
    #[cfg(feature = "random")]
    use crate::{
        Decapsulate,
        Encapsulate,
        MlKem512Params,
        MlKem768Params,
        MlKem1024Params,
    };

    #[cfg(feature = "random")]
    fn round_trip_test<P>()
    where
        P: KemParams,
    {
        let mut rng = lib_q_random::LibQRng::new_secure().expect("Failed to create secure RNG");

        let dk = DecapsulationKey::<P>::generate(&mut rng);
        let ek = dk.encapsulation_key();

        let (ct, k_send) = ek.encapsulate(&mut rng).unwrap();
        let k_recv = dk.decapsulate(&ct).unwrap();
        assert_eq!(k_send, k_recv);
    }

    #[test]
    #[cfg(feature = "random")]
    fn round_trip() {
        round_trip_test::<MlKem512Params>();
        round_trip_test::<MlKem768Params>();
        round_trip_test::<MlKem1024Params>();
    }

    #[cfg(feature = "random")]
    fn codec_test<P>()
    where
        P: KemParams,
    {
        let mut rng = lib_q_random::LibQRng::new_secure().expect("Failed to create secure RNG");
        let dk_original = DecapsulationKey::<P>::generate(&mut rng);
        let ek_original = dk_original.encapsulation_key().clone();

        let dk_encoded = dk_original.as_bytes();
        let dk_decoded = DecapsulationKey::from_bytes(&*dk_encoded);
        assert_eq!(dk_original, dk_decoded);

        let ek_encoded = ek_original.as_bytes();
        let ek_decoded = EncapsulationKey::from_bytes(&*ek_encoded);
        assert_eq!(ek_original, ek_decoded);
    }

    #[test]
    #[cfg(feature = "random")]
    fn codec() {
        codec_test::<MlKem512Params>();
        codec_test::<MlKem768Params>();
        codec_test::<MlKem1024Params>();
    }
}
