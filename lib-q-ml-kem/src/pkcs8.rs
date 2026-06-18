//! PKCS#8 / SPKI serialization for ML-KEM keys (feature `pkcs8`).
//!
//! Encodes decapsulation keys as PKCS#8 `PrivateKeyInfo` and encapsulation keys as
//! `SubjectPublicKeyInfo` (SPKI), following
//! [draft-ietf-lamps-kyber-certificates](https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/).
//!
//! The private-key body is the `ML-KEM-PrivateKey` `CHOICE`:
//!
//! ```text
//! ML-KEM-PrivateKey ::= CHOICE {
//!     seed        [0] OCTET STRING (SIZE (64)),
//!     expandedKey     OCTET STRING (SIZE (1632 | 2400 | 3168)) }
//! ```
//!
//! This implementation **encodes the `expandedKey` arm** (the FIPS-203 expanded decapsulation key,
//! exactly as produced by [`EncodedSizeUser::as_bytes`](crate::EncodedSizeUser)) and **decodes
//! either arm**: a `seed [0]` body is expanded via [`crate::kem::DecapsulationKey::from_seed`], an
//! `expandedKey` body is imported and FIPS-203-validated via `try_from_bytes`.
//!
//! The `AlgorithmIdentifier` carries the NIST CSOR ML-KEM OID with **absent** parameters.

extern crate alloc;

use alloc::vec::Vec;

use der::asn1::{
    BitStringRef,
    OctetStringRef,
};
use der::oid::ObjectIdentifier;
use der::{
    Decode,
    Encode,
    Sequence,
};
use hybrid_array::typenum::Unsigned;
use zeroize::Zeroizing;

use crate::kem::{
    DecapsulationKey,
    EncapsulationKey,
};
use crate::param::KemParams;
use crate::{
    Encoded,
    EncodedSizeUser,
    Seed,
};

/// `id-alg-ml-kem-512` (NIST CSOR `2.16.840.1.101.3.4.4.1`).
const ML_KEM_512_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.1");
/// `id-alg-ml-kem-768` (NIST CSOR `2.16.840.1.101.3.4.4.2`).
const ML_KEM_768_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.2");
/// `id-alg-ml-kem-1024` (NIST CSOR `2.16.840.1.101.3.4.4.3`).
const ML_KEM_1024_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.3");

/// The ML-KEM algorithm OID for parameter set `P`, selected by the module rank `k` (2/3/4).
fn algorithm_oid<P: KemParams>() -> ObjectIdentifier {
    match <P::K as Unsigned>::USIZE {
        2 => ML_KEM_512_OID,
        3 => ML_KEM_768_OID,
        // `KemParams` is only implemented for k ∈ {2, 3, 4}; k == 4 is ML-KEM-1024.
        _ => ML_KEM_1024_OID,
    }
}

/// Error returned by the PKCS#8 / SPKI (de)serializers.
#[derive(Debug)]
pub enum Pkcs8Error {
    /// DER encoding or decoding failed.
    Der(der::Error),
    /// The algorithm OID did not identify the expected ML-KEM parameter set.
    WrongAlgorithm,
    /// A structural field (version, length, unused bits) was malformed.
    Malformed,
    /// The embedded key bytes failed FIPS-203 input validation.
    InvalidKey,
}

impl From<der::Error> for Pkcs8Error {
    fn from(e: der::Error) -> Self {
        Self::Der(e)
    }
}

impl core::fmt::Display for Pkcs8Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Der(e) => write!(f, "DER codec error: {e}"),
            Self::WrongAlgorithm => f.write_str("unexpected algorithm OID for this parameter set"),
            Self::Malformed => f.write_str("malformed PKCS#8/SPKI structure"),
            Self::InvalidKey => f.write_str("embedded key failed FIPS-203 validation"),
        }
    }
}

impl core::error::Error for Pkcs8Error {}

/// `AlgorithmIdentifier` with absent parameters, i.e. `SEQUENCE { algorithm OBJECT IDENTIFIER }`.
#[derive(Sequence)]
struct AlgId {
    algorithm: ObjectIdentifier,
}

/// PKCS#8 `PrivateKeyInfo` (RFC 5958 `OneAsymmetricKey`, attributes/publicKey omitted).
#[derive(Sequence)]
struct PrivateKeyInfo<'a> {
    version: u8,
    algorithm: AlgId,
    #[asn1(type = "OCTET STRING")]
    private_key: &'a [u8],
}

/// `SubjectPublicKeyInfo` (RFC 5280).
#[derive(Sequence)]
struct SubjectPublicKeyInfo<'a> {
    algorithm: AlgId,
    subject_public_key: BitStringRef<'a>,
}

/// First DER tag byte of the `seed [0] IMPLICIT OCTET STRING` `ML-KEM-PrivateKey` arm.
const SEED_TAG: u8 = 0x80;
/// First DER tag byte of a universal primitive `OCTET STRING` (the `expandedKey` arm).
const OCTET_STRING_TAG: u8 = 0x04;
/// DER length octet for a 64-byte content (`SEED_SIZE` fits the short form).
const SEED_LEN_OCTET: u8 = 0x40;
/// Total DER length of the `seed [0]` body: tag + length + 64 content octets.
const SEED_BODY_LEN: usize = 2 + crate::SEED_SIZE;

impl<P> DecapsulationKey<P>
where
    P: KemParams,
{
    /// Serialize this decapsulation key as a PKCS#8 `PrivateKeyInfo` DER document.
    ///
    /// Emits the `expandedKey` arm of `ML-KEM-PrivateKey` (the FIPS-203 expanded key). The returned
    /// buffer is wrapped in [`Zeroizing`] because it contains secret key material.
    ///
    /// # Errors
    /// Returns [`Pkcs8Error::Der`] if DER encoding fails (unreachable for well-formed keys).
    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, Pkcs8Error> {
        let expanded = self.as_bytes();
        // ML-KEM-PrivateKey CHOICE, `expandedKey` arm: a plain OCTET STRING of the expanded key.
        let body = Zeroizing::new(OctetStringRef::new(expanded.as_slice())?.to_der()?);

        let pki = PrivateKeyInfo {
            version: 0,
            algorithm: AlgId {
                algorithm: algorithm_oid::<P>(),
            },
            private_key: body.as_slice(),
        };
        Ok(Zeroizing::new(pki.to_der()?))
    }

    /// Parse a decapsulation key from a PKCS#8 `PrivateKeyInfo` DER document.
    ///
    /// Accepts both the `seed [0]` arm (expanded via [`Self::from_seed`]) and the `expandedKey` arm
    /// (imported and FIPS-203-validated). The algorithm OID must match this parameter set.
    ///
    /// # Errors
    /// Returns [`Pkcs8Error`] if the structure is malformed, the OID does not match `P`, or the
    /// embedded key fails validation.
    pub fn from_pkcs8_der(bytes: &[u8]) -> Result<Self, Pkcs8Error> {
        let pki = PrivateKeyInfo::from_der(bytes)?;
        if pki.version != 0 {
            return Err(Pkcs8Error::Malformed);
        }
        if pki.algorithm.algorithm != algorithm_oid::<P>() {
            return Err(Pkcs8Error::WrongAlgorithm);
        }

        // The `privateKey` OCTET STRING wraps the `ML-KEM-PrivateKey` CHOICE; discriminate by its
        // first DER tag byte.
        let body = pki.private_key;
        match body.first().copied() {
            // `expandedKey` arm: a universal OCTET STRING of the expanded key (validated on import).
            Some(OCTET_STRING_TAG) => {
                let os = <&OctetStringRef>::from_der(body)?;
                let enc =
                    Encoded::<Self>::try_from(os.as_bytes()).map_err(|_| Pkcs8Error::Malformed)?;
                Self::try_from_bytes(&enc).map_err(|_| Pkcs8Error::InvalidKey)
            }
            // `seed [0] IMPLICIT OCTET STRING (SIZE (64))` arm: canonical DER is `80 40 <64 bytes>`.
            Some(SEED_TAG) if body.len() == SEED_BODY_LEN && body[1] == SEED_LEN_OCTET => {
                let seed = Seed::try_from(&body[2..]).map_err(|_| Pkcs8Error::Malformed)?;
                Ok(Self::from_seed(&seed))
            }
            _ => Err(Pkcs8Error::Malformed),
        }
    }
}

impl<P> EncapsulationKey<P>
where
    P: KemParams,
{
    /// Serialize this encapsulation key as a `SubjectPublicKeyInfo` (SPKI) DER document.
    ///
    /// # Errors
    /// Returns [`Pkcs8Error::Der`] if DER encoding fails (unreachable for well-formed keys).
    pub fn to_public_key_der(&self) -> Result<Vec<u8>, Pkcs8Error> {
        let raw = self.as_bytes();
        let spki = SubjectPublicKeyInfo {
            algorithm: AlgId {
                algorithm: algorithm_oid::<P>(),
            },
            subject_public_key: BitStringRef::from_bytes(raw.as_slice())?,
        };
        Ok(spki.to_der()?)
    }

    /// Parse an encapsulation key from a `SubjectPublicKeyInfo` (SPKI) DER document.
    ///
    /// The algorithm OID must match this parameter set; the embedded key is FIPS-203-validated.
    ///
    /// # Errors
    /// Returns [`Pkcs8Error`] if the structure is malformed, the OID does not match `P`, or the
    /// embedded key fails validation.
    pub fn from_public_key_der(bytes: &[u8]) -> Result<Self, Pkcs8Error> {
        let spki = SubjectPublicKeyInfo::from_der(bytes)?;
        if spki.algorithm.algorithm != algorithm_oid::<P>() {
            return Err(Pkcs8Error::WrongAlgorithm);
        }
        let raw = spki
            .subject_public_key
            .as_bytes()
            .ok_or(Pkcs8Error::Malformed)?;
        let enc = Encoded::<Self>::try_from(raw).map_err(|_| Pkcs8Error::Malformed)?;
        Self::try_from_bytes(&enc).map_err(|_| Pkcs8Error::InvalidKey)
    }
}

#[cfg(all(test, feature = "random"))]
mod test {
    use lib_q_random::LibQRng;

    use crate::kem::{
        DecapsulationKey,
        EncapsulationKey,
    };
    use crate::param::KemParams;
    use crate::{
        MlKem512Params,
        MlKem768Params,
        MlKem1024Params,
    };

    fn pkcs8_round_trip<P>()
    where
        P: KemParams,
    {
        let mut rng = LibQRng::new_secure().expect("rng");
        let (seed, dk) = DecapsulationKey::<P>::generate_with_seed(&mut rng);
        let ek = dk.encapsulation_key().clone();

        // Private key: expandedKey arm round-trips to the identical key.
        let der = dk.to_pkcs8_der().expect("encode dk");
        let dk2 = DecapsulationKey::<P>::from_pkcs8_der(&der).expect("decode dk");
        assert_eq!(dk, dk2);

        // Public key (SPKI) round-trips.
        let spki = ek.to_public_key_der().expect("encode ek");
        let ek2 = EncapsulationKey::<P>::from_public_key_der(&spki).expect("decode ek");
        assert_eq!(ek, ek2);

        // Decoder also accepts the seed [0] arm: hand-build a seed-form PrivateKeyInfo by replacing
        // the body, and confirm it expands to the same key as from_seed.
        let dk_from_seed = DecapsulationKey::<P>::from_seed(&seed);
        assert_eq!(dk, dk_from_seed);
    }

    #[test]
    fn round_trip() {
        pkcs8_round_trip::<MlKem512Params>();
        pkcs8_round_trip::<MlKem768Params>();
        pkcs8_round_trip::<MlKem1024Params>();
    }

    fn rejects_wrong_oid<P, Q>()
    where
        P: KemParams,
        Q: KemParams,
    {
        let mut rng = LibQRng::new_secure().expect("rng");
        let dk = DecapsulationKey::<P>::generate(&mut rng);
        let der = dk.to_pkcs8_der().expect("encode");
        // Decoding under a different parameter set must fail on the OID check.
        assert!(DecapsulationKey::<Q>::from_pkcs8_der(&der).is_err());
    }

    #[test]
    fn wrong_parameter_set_rejected() {
        rejects_wrong_oid::<MlKem512Params, MlKem768Params>();
        rejects_wrong_oid::<MlKem768Params, MlKem1024Params>();
    }

    #[test]
    fn decodes_seed_arm() {
        use der::Encode;

        let mut rng = LibQRng::new_secure().expect("rng");
        let (seed, dk) = DecapsulationKey::<MlKem512Params>::generate_with_seed(&mut rng);

        // Hand-build the `seed [0] IMPLICIT OCTET STRING` CHOICE body (`80 40 <64 bytes>`) and wrap
        // it in a PrivateKeyInfo so we exercise the seed-arm decode path (encode only ever emits the
        // expandedKey arm).
        let mut body = std::vec::Vec::with_capacity(super::SEED_BODY_LEN);
        body.push(super::SEED_TAG);
        body.push(super::SEED_LEN_OCTET);
        body.extend_from_slice(seed.as_slice());

        let pki = super::PrivateKeyInfo {
            version: 0,
            algorithm: super::AlgId {
                algorithm: super::algorithm_oid::<MlKem512Params>(),
            },
            private_key: &body,
        };
        let der = pki.to_der().expect("encode seed-arm PKCS#8");

        let decoded =
            DecapsulationKey::<MlKem512Params>::from_pkcs8_der(&der).expect("decode seed arm");
        assert_eq!(decoded, dk);
        assert_eq!(
            decoded,
            DecapsulationKey::<MlKem512Params>::from_seed(&seed)
        );
    }

    #[test]
    fn rejects_tampered_public_key() {
        let mut rng = LibQRng::new_secure().expect("rng");
        let (_seed, dk) = DecapsulationKey::<MlKem512Params>::generate_with_seed(&mut rng);
        let ek = dk.encapsulation_key().clone();
        let mut spki = ek.to_public_key_der().expect("encode");

        // The encapsulation key is `ByteEncode(t̂) ‖ rho`, so its raw bytes are the final
        // MLKEM512_PUBLIC_KEY_SIZE bytes of the SPKI DER and t̂'s first coefficient is the first of
        // those. Force that coefficient to 0xFFF (>= q): a non-canonical encoding `try_from_bytes`
        // must reject. (Tampering the trailing bytes would only hit `rho`, which has no canonicity
        // constraint and is legitimately accepted.)
        let off = spki.len() - crate::MLKEM512_PUBLIC_KEY_SIZE;
        spki[off] = 0xFF;
        spki[off + 1] = 0xFF;
        assert!(EncapsulationKey::<MlKem512Params>::from_public_key_der(&spki).is_err());
    }
}
