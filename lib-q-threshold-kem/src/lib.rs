#![forbid(unsafe_code)]

use core::fmt;

use lib_q_ml_kem::{
    Ciphertext,
    Decapsulate,
    Encapsulate,
    Encoded,
    EncodedSizeUser,
    KemCore,
    MlKem768,
};
use lib_q_sha3::sha3_256;
use rand_core::{
    CryptoRng,
    Rng,
};
use subtle::ConstantTimeEq;
use zeroize::{
    Zeroize,
    Zeroizing,
};

pub const PROFILE_ID_V1: u8 = 1;
pub const PROFILE_MAX_THRESHOLD_V1: u8 = 32;
pub const WIRE_VERSION_V1: u8 = 1;
pub const WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES: usize = 30_720;
pub const PARAMETER_SET_CANONICAL_BLOB_V1: &str = "amber-tkem-revised-v1-T32-k128";
pub const PARAMETER_SET_DIGEST_V1: [u8; 32] = [
    0xEB, 0x79, 0xC0, 0xF7, 0x80, 0x47, 0x22, 0xE3, 0x68, 0x35, 0x1A, 0x9C, 0x57, 0x56, 0xDC, 0xAF,
    0xCA, 0xE3, 0xED, 0x2D, 0x46, 0xBC, 0x4C, 0x77, 0xDB, 0xC5, 0x65, 0xB3, 0x18, 0x77, 0x73, 0x6C,
];

const SHARE_COMMITMENT_DOMAIN: &[u8] = b"amber-tkem-share-v1";
const PARTIAL_TAG_DOMAIN: &[u8] = b"amber-tkem-partial-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThresholdKemProfileV1 {
    pub id: u8,
    pub max_threshold: u8,
    pub parameter_set_digest: [u8; 32],
}

impl Default for ThresholdKemProfileV1 {
    fn default() -> Self {
        Self {
            id: PROFILE_ID_V1,
            max_threshold: PROFILE_MAX_THRESHOLD_V1,
            parameter_set_digest: PARAMETER_SET_DIGEST_V1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareVerifier {
    pub index: u8,
    pub commitment: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdKemPublicKey {
    pub profile_id: u8,
    pub threshold: u8,
    pub ml_kem_public_key: Vec<u8>,
    pub share_verifiers: Vec<ShareVerifier>,
}

#[derive(Clone, Debug)]
pub struct SecretShare {
    pub index: u8,
    pub threshold: u8,
    pub verifier_commitment: [u8; 32],
    pub share_bytes: Zeroizing<Vec<u8>>,
}

impl PartialEq for SecretShare {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index &&
            self.threshold == other.threshold &&
            bool::from(self.verifier_commitment.ct_eq(&other.verifier_commitment)) &&
            self.share_bytes.as_slice() == other.share_bytes.as_slice()
    }
}

impl Eq for SecretShare {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeygenSharesOutput {
    pub public_key: ThresholdKemPublicKey,
    pub secret_shares: Vec<SecretShare>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncapOutput {
    pub shared_secret: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub wire: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialDecapShare {
    pub index: u8,
    pub share_bytes: Vec<u8>,
    pub tag: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdKemWireV1 {
    pub ciphertext: Vec<u8>,
    pub shares: Vec<PartialDecapShare>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ThresholdKemError {
    InvalidProfile,
    InvalidThreshold,
    InvalidShareCount,
    InvalidCiphertextLength,
    CiphertextBudgetExceeded { actual: usize, budget: usize },
    WireTruncated,
    WireVersionMismatch { expected: u8, found: u8 },
    WireProfileMismatch { expected: u8, found: u8 },
    ShareNotFound { index: u8 },
    InvalidShareProof { index: u8 },
    DuplicateShareIndex { index: u8 },
    InterpolationFailed,
    MlKemKeyDecodeFailed,
}

impl fmt::Display for ThresholdKemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProfile => write!(f, "invalid threshold KEM profile"),
            Self::InvalidThreshold => write!(f, "invalid threshold"),
            Self::InvalidShareCount => write!(f, "invalid share count"),
            Self::InvalidCiphertextLength => write!(f, "invalid ciphertext length"),
            Self::CiphertextBudgetExceeded { actual, budget } => {
                write!(f, "ciphertext exceeds budget: {actual} > {budget}")
            }
            Self::WireTruncated => write!(f, "wire payload truncated"),
            Self::WireVersionMismatch { expected, found } => {
                write!(
                    f,
                    "wire version mismatch: expected {expected}, found {found}"
                )
            }
            Self::WireProfileMismatch { expected, found } => {
                write!(
                    f,
                    "wire profile mismatch: expected {expected}, found {found}"
                )
            }
            Self::ShareNotFound { index } => {
                write!(f, "share verifier not found for index {index}")
            }
            Self::InvalidShareProof { index } => write!(f, "invalid share proof for index {index}"),
            Self::DuplicateShareIndex { index } => write!(f, "duplicate share index {index}"),
            Self::InterpolationFailed => write!(f, "failed to interpolate secret from shares"),
            Self::MlKemKeyDecodeFailed => write!(f, "failed to decode ML-KEM key material"),
        }
    }
}

impl std::error::Error for ThresholdKemError {}

pub fn setup() -> ThresholdKemProfileV1 {
    ThresholdKemProfileV1::default()
}

pub fn keygen_shares<R: CryptoRng + Rng>(
    profile: &ThresholdKemProfileV1,
    threshold: u8,
    share_count: u16,
    rng: &mut R,
) -> Result<KeygenSharesOutput, ThresholdKemError> {
    validate_profile(profile)?;
    validate_threshold_and_count(profile, threshold, share_count)?;

    let (dk, ek) = MlKem768::generate(rng);
    let dk_encoded = dk.as_bytes();
    let ek_encoded = ek.as_bytes();

    let secret_shards = shamir_split_secret(
        dk_encoded.as_slice(),
        threshold,
        u8::try_from(share_count).map_err(|_| ThresholdKemError::InvalidShareCount)?,
        rng,
    )?;

    let mut public_verifiers = Vec::with_capacity(secret_shards.len());
    let mut secret_shares = Vec::with_capacity(secret_shards.len());

    for (index, shard) in secret_shards {
        let commitment = derive_share_commitment(index, &shard);
        public_verifiers.push(ShareVerifier { index, commitment });
        secret_shares.push(SecretShare {
            index,
            threshold,
            verifier_commitment: commitment,
            share_bytes: Zeroizing::new(shard),
        });
    }

    Ok(KeygenSharesOutput {
        public_key: ThresholdKemPublicKey {
            profile_id: profile.id,
            threshold,
            ml_kem_public_key: ek_encoded.as_slice().to_vec(),
            share_verifiers: public_verifiers,
        },
        secret_shares,
    })
}

pub fn encap<R: CryptoRng + Rng>(
    profile: &ThresholdKemProfileV1,
    public_key: &ThresholdKemPublicKey,
    rng: &mut R,
) -> Result<EncapOutput, ThresholdKemError> {
    validate_profile(profile)?;
    if public_key.profile_id != profile.id {
        return Err(ThresholdKemError::InvalidProfile);
    }

    type Ek = <MlKem768 as KemCore>::EncapsulationKey;
    let ek_bytes = Encoded::<Ek>::try_from(public_key.ml_kem_public_key.as_slice())
        .map_err(|_| ThresholdKemError::MlKemKeyDecodeFailed)?;
    let ek = Ek::from_bytes(&ek_bytes);

    let (ciphertext, shared) = ek
        .encapsulate(rng)
        .map_err(|_| ThresholdKemError::MlKemKeyDecodeFailed)?;
    if ciphertext.len() > WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES {
        return Err(ThresholdKemError::CiphertextBudgetExceeded {
            actual: ciphertext.len(),
            budget: WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES,
        });
    }

    let mut ss = [0u8; 32];
    ss.copy_from_slice(shared.as_slice());

    let ct_vec = ciphertext.as_slice().to_vec();
    let wire = encode_threshold_kem_wire_v1(profile, &ct_vec, &[])?;

    Ok(EncapOutput {
        shared_secret: ss,
        ciphertext: ct_vec,
        wire,
    })
}

pub fn partial_decap(
    secret_share: &SecretShare,
    ciphertext: &[u8],
) -> Result<PartialDecapShare, ThresholdKemError> {
    if ciphertext.is_empty() {
        return Err(ThresholdKemError::InvalidCiphertextLength);
    }
    if ciphertext.len() > WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES {
        return Err(ThresholdKemError::CiphertextBudgetExceeded {
            actual: ciphertext.len(),
            budget: WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES,
        });
    }

    let tag = derive_partial_tag(secret_share.verifier_commitment, ciphertext);
    Ok(PartialDecapShare {
        index: secret_share.index,
        share_bytes: secret_share.share_bytes.as_slice().to_vec(),
        tag,
    })
}

pub fn verify_share(
    verifier: &ShareVerifier,
    ciphertext: &[u8],
    share: &PartialDecapShare,
) -> bool {
    if share.index != verifier.index {
        return false;
    }
    let derived_commitment = derive_share_commitment(share.index, &share.share_bytes);
    if !bool::from(derived_commitment.ct_eq(&verifier.commitment)) {
        return false;
    }
    let expected_tag = derive_partial_tag(verifier.commitment, ciphertext);
    bool::from(expected_tag.ct_eq(&share.tag))
}

pub fn combine_decap(
    profile: &ThresholdKemProfileV1,
    ciphertext: &[u8],
    partials: &[PartialDecapShare],
    verifiers: &[ShareVerifier],
    threshold: u8,
) -> Result<[u8; 32], ThresholdKemError> {
    validate_profile(profile)?;

    if ciphertext.len() > WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES {
        return Err(ThresholdKemError::CiphertextBudgetExceeded {
            actual: ciphertext.len(),
            budget: WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES,
        });
    }
    if ciphertext.len() != lib_q_ml_kem::MLKEM768_CIPHERTEXT_SIZE {
        return Err(ThresholdKemError::InvalidCiphertextLength);
    }
    if threshold == 0 || threshold > PROFILE_MAX_THRESHOLD_V1 {
        return Err(ThresholdKemError::InvalidThreshold);
    }
    if partials.len() < usize::from(threshold) {
        return Err(ThresholdKemError::InvalidShareCount);
    }

    let mut used = Vec::<u8>::new();
    let mut selected: Vec<(u8, Vec<u8>)> = Vec::new();

    for partial in partials {
        if used.contains(&partial.index) {
            return Err(ThresholdKemError::DuplicateShareIndex {
                index: partial.index,
            });
        }
        let verifier = verifiers.iter().find(|v| v.index == partial.index).ok_or(
            ThresholdKemError::ShareNotFound {
                index: partial.index,
            },
        )?;
        if !verify_share(verifier, ciphertext, partial) {
            return Err(ThresholdKemError::InvalidShareProof {
                index: partial.index,
            });
        }
        used.push(partial.index);
        selected.push((partial.index, partial.share_bytes.clone()));
        if selected.len() == usize::from(threshold) {
            break;
        }
    }

    if selected.len() < usize::from(threshold) {
        return Err(ThresholdKemError::InvalidShareCount);
    }

    let dk_bytes = shamir_combine_secret(&selected)?;
    type Dk = <MlKem768 as KemCore>::DecapsulationKey;
    let dk_encoded = Encoded::<Dk>::try_from(dk_bytes.as_slice())
        .map_err(|_| ThresholdKemError::MlKemKeyDecodeFailed)?;
    let dk = Dk::from_bytes(&dk_encoded);
    let ct = Ciphertext::<MlKem768>::try_from(ciphertext)
        .map_err(|_| ThresholdKemError::InvalidCiphertextLength)?;

    let shared = dk
        .decapsulate(&ct)
        .map_err(|_| ThresholdKemError::MlKemKeyDecodeFailed)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.as_slice());
    Ok(out)
}

pub fn encode_threshold_kem_wire_v1(
    profile: &ThresholdKemProfileV1,
    ciphertext: &[u8],
    shares: &[PartialDecapShare],
) -> Result<Vec<u8>, ThresholdKemError> {
    validate_profile(profile)?;
    if ciphertext.len() > WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES {
        return Err(ThresholdKemError::CiphertextBudgetExceeded {
            actual: ciphertext.len(),
            budget: WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES,
        });
    }

    let mut out = Vec::new();
    out.push(WIRE_VERSION_V1);
    out.push(profile.id);
    out.extend_from_slice(
        &u32::try_from(ciphertext.len())
            .map_err(|_| ThresholdKemError::InvalidCiphertextLength)?
            .to_le_bytes(),
    );
    out.extend_from_slice(ciphertext);
    out.extend_from_slice(
        &u16::try_from(shares.len())
            .map_err(|_| ThresholdKemError::InvalidShareCount)?
            .to_le_bytes(),
    );
    for share in shares {
        out.push(share.index);
        out.extend_from_slice(
            &u16::try_from(share.share_bytes.len())
                .map_err(|_| ThresholdKemError::InvalidShareCount)?
                .to_le_bytes(),
        );
        out.extend_from_slice(&share.share_bytes);
        out.extend_from_slice(&share.tag);
    }
    Ok(out)
}

pub fn decode_threshold_kem_wire_v1(
    profile: &ThresholdKemProfileV1,
    wire: &[u8],
) -> Result<ThresholdKemWireV1, ThresholdKemError> {
    validate_profile(profile)?;
    let mut cursor = 0usize;

    let ver = read_byte(wire, &mut cursor)?;
    if ver != WIRE_VERSION_V1 {
        return Err(ThresholdKemError::WireVersionMismatch {
            expected: WIRE_VERSION_V1,
            found: ver,
        });
    }
    let profile_id = read_byte(wire, &mut cursor)?;
    if profile_id != profile.id {
        return Err(ThresholdKemError::WireProfileMismatch {
            expected: profile.id,
            found: profile_id,
        });
    }

    let ct_len = read_u32_le(wire, &mut cursor)? as usize;
    if ct_len > WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES {
        return Err(ThresholdKemError::CiphertextBudgetExceeded {
            actual: ct_len,
            budget: WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES,
        });
    }
    let ciphertext = read_bytes(wire, &mut cursor, ct_len)?.to_vec();
    let share_count = usize::from(read_u16_le(wire, &mut cursor)?);

    let mut shares = Vec::with_capacity(share_count);
    for _ in 0..share_count {
        let index = read_byte(wire, &mut cursor)?;
        let share_len = usize::from(read_u16_le(wire, &mut cursor)?);
        let share_bytes = read_bytes(wire, &mut cursor, share_len)?.to_vec();
        let tag_slice = read_bytes(wire, &mut cursor, 32)?;
        let mut tag = [0u8; 32];
        tag.copy_from_slice(tag_slice);
        shares.push(PartialDecapShare {
            index,
            share_bytes,
            tag,
        });
    }

    if cursor != wire.len() {
        return Err(ThresholdKemError::WireTruncated);
    }

    Ok(ThresholdKemWireV1 { ciphertext, shares })
}

fn validate_profile(profile: &ThresholdKemProfileV1) -> Result<(), ThresholdKemError> {
    if profile.id != PROFILE_ID_V1 ||
        profile.max_threshold != PROFILE_MAX_THRESHOLD_V1 ||
        !bool::from(profile.parameter_set_digest.ct_eq(&PARAMETER_SET_DIGEST_V1))
    {
        return Err(ThresholdKemError::InvalidProfile);
    }
    Ok(())
}

fn validate_threshold_and_count(
    profile: &ThresholdKemProfileV1,
    threshold: u8,
    share_count: u16,
) -> Result<(), ThresholdKemError> {
    if threshold == 0 || threshold > profile.max_threshold {
        return Err(ThresholdKemError::InvalidThreshold);
    }
    let n = u8::try_from(share_count).map_err(|_| ThresholdKemError::InvalidShareCount)?;
    if n < threshold || n == 0 {
        return Err(ThresholdKemError::InvalidShareCount);
    }
    Ok(())
}

fn derive_share_commitment(index: u8, share: &[u8]) -> [u8; 32] {
    let mut material = Vec::with_capacity(SHARE_COMMITMENT_DOMAIN.len() + 1 + share.len());
    material.extend_from_slice(SHARE_COMMITMENT_DOMAIN);
    material.push(index);
    material.extend_from_slice(share);
    sha3_256(&material)
}

fn derive_partial_tag(share_commitment: [u8; 32], ciphertext: &[u8]) -> [u8; 32] {
    let mut material =
        Vec::with_capacity(PARTIAL_TAG_DOMAIN.len() + share_commitment.len() + ciphertext.len());
    material.extend_from_slice(PARTIAL_TAG_DOMAIN);
    material.extend_from_slice(&share_commitment);
    material.extend_from_slice(ciphertext);
    sha3_256(&material)
}

fn read_byte(wire: &[u8], cursor: &mut usize) -> Result<u8, ThresholdKemError> {
    let b = wire
        .get(*cursor)
        .copied()
        .ok_or(ThresholdKemError::WireTruncated)?;
    *cursor += 1;
    Ok(b)
}

fn read_u16_le(wire: &[u8], cursor: &mut usize) -> Result<u16, ThresholdKemError> {
    let bytes = read_bytes(wire, cursor, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(wire: &[u8], cursor: &mut usize) -> Result<u32, ThresholdKemError> {
    let bytes = read_bytes(wire, cursor, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_bytes<'a>(
    wire: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], ThresholdKemError> {
    let end = cursor.saturating_add(len);
    if end > wire.len() {
        return Err(ThresholdKemError::WireTruncated);
    }
    let out = &wire[*cursor..end];
    *cursor = end;
    Ok(out)
}

fn shamir_split_secret<R: CryptoRng + Rng>(
    secret: &[u8],
    threshold: u8,
    share_count: u8,
    rng: &mut R,
) -> Result<Vec<(u8, Vec<u8>)>, ThresholdKemError> {
    if threshold == 0 || share_count == 0 || share_count < threshold {
        return Err(ThresholdKemError::InvalidShareCount);
    }
    let mut shares = Vec::with_capacity(usize::from(share_count));
    for idx in 1..=share_count {
        shares.push((idx, vec![0u8; secret.len()]));
    }

    let mut coeffs = vec![0u8; usize::from(threshold)];
    for byte_index in 0..secret.len() {
        coeffs[0] = secret[byte_index];
        for coeff in coeffs.iter_mut().skip(1) {
            *coeff = rng.next_u32() as u8;
        }
        for (x, out) in &mut shares {
            out[byte_index] = eval_poly_gf256(*x, &coeffs);
        }
    }
    coeffs.zeroize();
    Ok(shares)
}

fn shamir_combine_secret(shares: &[(u8, Vec<u8>)]) -> Result<Vec<u8>, ThresholdKemError> {
    if shares.is_empty() {
        return Err(ThresholdKemError::InterpolationFailed);
    }
    let share_len = shares[0].1.len();
    if share_len == 0 {
        return Err(ThresholdKemError::InterpolationFailed);
    }
    if shares.iter().any(|(_, s)| s.len() != share_len) {
        return Err(ThresholdKemError::InterpolationFailed);
    }

    let mut secret = vec![0u8; share_len];
    for b in 0..share_len {
        let mut acc = 0u8;
        for (i, (x_i, y_i)) in shares.iter().enumerate() {
            let mut num = 1u8;
            let mut den = 1u8;
            for (j, (x_j, _)) in shares.iter().enumerate() {
                if i == j {
                    continue;
                }
                num = gf_mul(num, *x_j);
                den = gf_mul(den, x_j ^ x_i);
            }
            if den == 0 {
                return Err(ThresholdKemError::InterpolationFailed);
            }
            let den_inv = gf_inv(den).ok_or(ThresholdKemError::InterpolationFailed)?;
            let lambda = gf_mul(num, den_inv);
            acc ^= gf_mul(y_i[b], lambda);
        }
        secret[b] = acc;
    }
    Ok(secret)
}

fn eval_poly_gf256(x: u8, coeffs: &[u8]) -> u8 {
    let mut acc = 0u8;
    for coeff in coeffs.iter().rev() {
        acc = gf_mul(acc, x) ^ *coeff;
    }
    acc
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

fn gf_pow(mut a: u8, mut e: u8) -> u8 {
    let mut r = 1u8;
    while e != 0 {
        if (e & 1) != 0 {
            r = gf_mul(r, a);
        }
        a = gf_mul(a, a);
        e >>= 1;
    }
    r
}

fn gf_inv(a: u8) -> Option<u8> {
    if a == 0 {
        return None;
    }
    Some(gf_pow(a, 254))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deterministic_rng(seed_byte: u8) -> lib_q_random::LibQRng {
        lib_q_random::new_deterministic_rng([seed_byte; 32])
    }

    #[test]
    fn wire_roundtrip() {
        let profile = setup();
        let mut rng = deterministic_rng(0x11);
        let keygen = keygen_shares(&profile, 32, 64, &mut rng).expect("keygen_shares failed");
        let enc = encap(&profile, &keygen.public_key, &mut rng).expect("encap failed");

        let partials: Vec<PartialDecapShare> = keygen
            .secret_shares
            .iter()
            .take(usize::from(keygen.public_key.threshold))
            .map(|share| partial_decap(share, &enc.ciphertext).expect("partial_decap failed"))
            .collect();

        let wire = encode_threshold_kem_wire_v1(&profile, &enc.ciphertext, &partials)
            .expect("wire encode failed");
        let decoded = decode_threshold_kem_wire_v1(&profile, &wire).expect("wire decode failed");
        assert_eq!(decoded.ciphertext, enc.ciphertext);
        assert_eq!(decoded.shares, partials);
    }

    #[test]
    fn budget_gates() {
        let profile = setup();
        let oversized = vec![0u8; WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES + 1];
        let err = encode_threshold_kem_wire_v1(&profile, &oversized, &[])
            .expect_err("oversized ciphertext accepted");
        assert!(matches!(
            err,
            ThresholdKemError::CiphertextBudgetExceeded { .. }
        ));

        let mut wire = vec![WIRE_VERSION_V1, PROFILE_ID_V1];
        wire.extend_from_slice(
            &(u32::try_from(WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES + 1).expect("u32 conversion"))
                .to_le_bytes(),
        );
        wire.extend_from_slice(&[]);
        wire.extend_from_slice(&0u16.to_le_bytes());
        let err =
            decode_threshold_kem_wire_v1(&profile, &wire).expect_err("oversized wire accepted");
        assert!(matches!(
            err,
            ThresholdKemError::CiphertextBudgetExceeded { .. }
        ));
    }

    #[test]
    fn kat_vectors() {
        let profile = setup();
        assert_eq!(
            profile.parameter_set_digest,
            sha3_256(PARAMETER_SET_CANONICAL_BLOB_V1.as_bytes()),
            "digest mismatch for canonical profile blob",
        );

        let mut rng = deterministic_rng(0x42);
        let keygen = keygen_shares(&profile, 32, 64, &mut rng).expect("keygen_shares failed");
        let enc = encap(&profile, &keygen.public_key, &mut rng).expect("encap failed");
        assert!(
            enc.ciphertext.len() <= WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES,
            "ciphertext over budget"
        );

        let partials: Vec<PartialDecapShare> = keygen
            .secret_shares
            .iter()
            .take(32)
            .map(|share| partial_decap(share, &enc.ciphertext).expect("partial_decap failed"))
            .collect();

        for (partial, verifier) in partials
            .iter()
            .zip(keygen.public_key.share_verifiers.iter())
        {
            assert!(
                verify_share(verifier, &enc.ciphertext, partial),
                "share failed verification"
            );
        }

        let ss_combined = combine_decap(
            &profile,
            &enc.ciphertext,
            &partials,
            &keygen.public_key.share_verifiers,
            32,
        )
        .expect("combine_decap failed");
        assert_eq!(enc.shared_secret, ss_combined, "combined decap mismatch");

        let mut malicious = partials.clone();
        malicious[0].share_bytes[0] ^= 0x80;
        let verifier0 = &keygen.public_key.share_verifiers[0];
        assert!(!verify_share(verifier0, &enc.ciphertext, &malicious[0]));
        let err = combine_decap(
            &profile,
            &enc.ciphertext,
            &malicious,
            &keygen.public_key.share_verifiers,
            32,
        )
        .expect_err("malicious share should be rejected");
        assert!(matches!(err, ThresholdKemError::InvalidShareProof { .. }));
    }

    #[test]
    #[ignore = "regenerates tests/vectors/threshold-kem-v1.json"]
    fn kat_regenerate_vectors() {
        use std::fs;
        use std::path::Path;

        let profile = setup();
        let mut rng = deterministic_rng(0x55);
        let keygen = keygen_shares(&profile, 32, 64, &mut rng).expect("keygen");
        let enc = encap(&profile, &keygen.public_key, &mut rng).expect("encap");
        let doc = serde_json::json!({
            "format": "threshold-kem-kat-v1",
            "spec_version": "v1",
            "parameter_set_digest": hex::encode(profile.parameter_set_digest),
            "ciphertext_hex": hex::encode(&enc.ciphertext),
            "ciphertext_bytes": enc.ciphertext.len(),
            "threshold": 32,
            "parties": 64,
            "shared_secret_hex": hex::encode(enc.shared_secret),
        });
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
        fs::create_dir_all(&dir).expect("mkdir vectors");
        fs::write(
            dir.join("threshold-kem-v1.json"),
            serde_json::to_string_pretty(&doc).expect("json"),
        )
        .expect("write kat");
        let manifest = serde_json::json!({
            "schema": "threshold-kem-kat-v1",
            "regenerate": "cargo test -p lib-q-threshold-kem kat_regenerate_vectors -- --ignored",
            "ciphertext_bytes": enc.ciphertext.len(),
            "budget_bytes": WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES,
            "parameter_set_digest": hex::encode(profile.parameter_set_digest),
        });
        fs::write(
            dir.join("manifest.json"),
            serde_json::to_string_pretty(&manifest).expect("json"),
        )
        .expect("write manifest");
    }
}
