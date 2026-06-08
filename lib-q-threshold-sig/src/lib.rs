#![forbid(unsafe_code)]

#[cfg(feature = "wasm")]
pub mod wasm;

pub mod error;
pub mod profile;
pub mod threshold_sig;
pub mod wire;

use core::fmt;

use lib_q_sha3::{
    ExtendableOutput,
    Shake256,
    Update,
    XofReader,
};
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
pub const PROFILE_MAX_PARTIES_V1: u8 = 64;
pub const WIRE_VERSION_V1: u8 = 1;
pub const WIRE_BUDGET_THRESHOLD_SIG_BYTES: usize = 11_264;
pub const PROFILE_ENVELOPE_BUDGET_BYTES: usize = 8_192;

const SCALAR_BYTES: usize = 32;
const ROUND1_BINDING_DOMAIN: &[u8] = b"amber-ts-round1-v1";
const ROUND2_PROOF_DOMAIN: &[u8] = b"amber-ts-round2-v1";
const CHALLENGE_DOMAIN: &[u8] = b"amber-ts-challenge-v1";
const SHARE_COMMITMENT_DOMAIN: &[u8] = b"amber-ts-share-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThresholdSigProfileV1 {
    pub id: u8,
    pub max_parties: u8,
}

impl Default for ThresholdSigProfileV1 {
    fn default() -> Self {
        Self {
            id: PROFILE_ID_V1,
            max_parties: PROFILE_MAX_PARTIES_V1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareVerifier {
    pub index: u8,
    pub verifying_key: [u8; SCALAR_BYTES],
    pub commitment: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdSigPublicKey {
    pub profile_id: u8,
    pub threshold: u8,
    pub group_key: [u8; SCALAR_BYTES],
    pub share_verifiers: Vec<ShareVerifier>,
}

#[derive(Clone, Debug)]
pub struct SecretShare {
    pub index: u8,
    pub threshold: u8,
    pub share_bytes: Zeroizing<Vec<u8>>,
}

impl PartialEq for SecretShare {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index &&
            self.threshold == other.threshold &&
            self.share_bytes.as_slice() == other.share_bytes.as_slice()
    }
}

impl Eq for SecretShare {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeygenSharesOutput {
    pub public_key: ThresholdSigPublicKey,
    pub secret_shares: Vec<SecretShare>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Round1Commitment {
    pub index: u8,
    pub nonce_commitment: [u8; SCALAR_BYTES],
    pub binding: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct Round1State {
    pub commitment: Round1Commitment,
    pub nonce: Zeroizing<[u8; SCALAR_BYTES]>,
}

impl PartialEq for Round1State {
    fn eq(&self, other: &Self) -> bool {
        self.commitment == other.commitment && bool::from(self.nonce[..].ct_eq(&other.nonce[..]))
    }
}

impl Eq for Round1State {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Round2Partial {
    pub index: u8,
    pub z: [u8; SCALAR_BYTES],
    pub proof: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdSignature {
    pub r_agg: [u8; SCALAR_BYTES],
    pub z: [u8; SCALAR_BYTES],
    pub signers: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdSigWireV1 {
    pub signature: Vec<u8>,
    pub meta: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateOutput {
    pub signature: ThresholdSignature,
    pub signature_bytes: Vec<u8>,
    pub wire: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ThresholdSigError {
    InvalidProfile,
    InvalidThreshold,
    InvalidShareCount,
    InvalidSignerSet,
    ShareNotFound { index: u8 },
    DuplicateIndex { index: u8 },
    InvalidRound1Binding { index: u8 },
    InvalidPartial { index: u8 },
    InvalidSignature,
    BudgetExceeded { actual: usize, budget: usize },
    WireTruncated,
    WireVersionMismatch { expected: u8, found: u8 },
    WireProfileMismatch { expected: u8, found: u8 },
    LengthOverflow,
    InterpolationFailed,
}

impl fmt::Display for ThresholdSigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProfile => write!(f, "invalid threshold signature profile"),
            Self::InvalidThreshold => write!(f, "invalid threshold"),
            Self::InvalidShareCount => write!(f, "invalid share count"),
            Self::InvalidSignerSet => write!(f, "invalid signer set"),
            Self::ShareNotFound { index } => {
                write!(f, "share verifier not found for index {index}")
            }
            Self::DuplicateIndex { index } => write!(f, "duplicate index {index}"),
            Self::InvalidRound1Binding { index } => {
                write!(f, "invalid round1 binding for index {index}")
            }
            Self::InvalidPartial { index } => write!(f, "invalid partial for index {index}"),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::BudgetExceeded { actual, budget } => {
                write!(f, "wire payload exceeds budget: {actual} > {budget}")
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
            Self::LengthOverflow => write!(f, "length conversion overflow"),
            Self::InterpolationFailed => write!(f, "failed to interpolate secret"),
        }
    }
}

impl std::error::Error for ThresholdSigError {}

pub fn setup() -> ThresholdSigProfileV1 {
    ThresholdSigProfileV1::default()
}

pub fn keygen_shares<R: CryptoRng + Rng>(
    profile: &ThresholdSigProfileV1,
    threshold: u8,
    share_count: u8,
    rng: &mut R,
) -> Result<KeygenSharesOutput, ThresholdSigError> {
    validate_profile(profile)?;
    validate_threshold_and_count(profile, threshold, share_count)?;

    let mut master = [0u8; SCALAR_BYTES];
    rng.fill_bytes(&mut master);
    let shares = shamir_split_secret(master.as_slice(), threshold, share_count, rng)?;

    let mut verifiers = Vec::with_capacity(shares.len());
    let mut secret_shares = Vec::with_capacity(shares.len());
    for (index, share_vec) in shares {
        let mut verifying_key = [0u8; SCALAR_BYTES];
        verifying_key.copy_from_slice(&share_vec);
        let commitment = derive_share_commitment(index, &verifying_key);
        verifiers.push(ShareVerifier {
            index,
            verifying_key,
            commitment,
        });
        secret_shares.push(SecretShare {
            index,
            threshold,
            share_bytes: Zeroizing::new(share_vec),
        });
    }
    master.zeroize();

    Ok(KeygenSharesOutput {
        public_key: ThresholdSigPublicKey {
            profile_id: profile.id,
            threshold,
            group_key: reconstruct_group_key_from_verifiers(&verifiers, threshold)?,
            share_verifiers: verifiers,
        },
        secret_shares,
    })
}

pub fn sign_round1<R: CryptoRng + Rng>(
    profile: &ThresholdSigProfileV1,
    secret_share: &SecretShare,
    message: &[u8],
    rng: &mut R,
) -> Result<Round1State, ThresholdSigError> {
    validate_profile(profile)?;
    if secret_share.threshold == 0 {
        return Err(ThresholdSigError::InvalidThreshold);
    }
    let mut nonce = [0u8; SCALAR_BYTES];
    rng.fill_bytes(&mut nonce);
    let nonce_commitment = nonce;
    let binding = derive_round1_binding(secret_share.index, &nonce_commitment, message);
    Ok(Round1State {
        commitment: Round1Commitment {
            index: secret_share.index,
            nonce_commitment,
            binding,
        },
        nonce: Zeroizing::new(nonce),
    })
}

pub fn sign_round2(
    profile: &ThresholdSigProfileV1,
    public_key: &ThresholdSigPublicKey,
    message: &[u8],
    secret_share: &SecretShare,
    round1_state: &Round1State,
    commitments: &[Round1Commitment],
) -> Result<Round2Partial, ThresholdSigError> {
    validate_profile(profile)?;
    validate_public_key(profile, public_key)?;
    validate_commitments(public_key, message, commitments)?;
    if secret_share.share_bytes.len() != SCALAR_BYTES {
        return Err(ThresholdSigError::InvalidShareCount);
    }
    if round1_state.commitment.index != secret_share.index {
        return Err(ThresholdSigError::InvalidSignerSet);
    }
    if round1_state.commitment.binding !=
        derive_round1_binding(
            round1_state.commitment.index,
            &round1_state.commitment.nonce_commitment,
            message,
        )
    {
        return Err(ThresholdSigError::InvalidRound1Binding {
            index: round1_state.commitment.index,
        });
    }

    let signer_ids = signer_ids_from_commitments(commitments)?;
    let lambda = lagrange_at_zero(round1_state.commitment.index, &signer_ids)?;
    let r_agg = aggregate_r(commitments);
    let challenge = derive_challenge(message, &r_agg, &public_key.group_key, &signer_ids);
    let mut z = [0u8; SCALAR_BYTES];
    for i in 0..SCALAR_BYTES {
        let cterm = gf_mul(challenge[i], gf_mul(lambda, secret_share.share_bytes[i]));
        z[i] = round1_state.nonce[i] ^ cterm;
    }
    let proof = derive_round2_proof(
        round1_state.commitment.index,
        &round1_state.commitment.nonce_commitment,
        &z,
        &challenge,
    );
    Ok(Round2Partial {
        index: round1_state.commitment.index,
        z,
        proof,
    })
}

pub fn aggregate(
    profile: &ThresholdSigProfileV1,
    public_key: &ThresholdSigPublicKey,
    message: &[u8],
    commitments: &[Round1Commitment],
    partials: &[Round2Partial],
) -> Result<AggregateOutput, ThresholdSigError> {
    validate_profile(profile)?;
    validate_public_key(profile, public_key)?;
    validate_commitments(public_key, message, commitments)?;
    validate_partials(public_key, partials)?;
    if partials.len() < usize::from(public_key.threshold) {
        return Err(ThresholdSigError::InvalidShareCount);
    }

    let signer_ids = signer_ids_from_commitments(commitments)?;
    let r_agg = aggregate_r(commitments);
    let challenge = derive_challenge(message, &r_agg, &public_key.group_key, &signer_ids);

    for partial in partials {
        verify_partial_against_verifier(partial, commitments, public_key, &challenge, &signer_ids)?;
    }

    let mut z_agg = [0u8; SCALAR_BYTES];
    for partial in partials {
        for (dst, src) in z_agg.iter_mut().zip(partial.z.iter()) {
            *dst ^= *src;
        }
    }

    if !verify_signature_equation(&r_agg, &z_agg, &challenge, &public_key.group_key) {
        return Err(ThresholdSigError::InvalidSignature);
    }

    let signature = ThresholdSignature {
        r_agg,
        z: z_agg,
        signers: signer_ids.clone(),
    };
    let signature_bytes = encode_signature(&signature)?;
    let meta = encode_meta_for_abort(commitments, partials)?;
    let wire = encode_threshold_sig_wire_v1(profile, &signature_bytes, &meta)?;

    Ok(AggregateOutput {
        signature,
        signature_bytes,
        wire,
    })
}

pub fn verify(
    profile: &ThresholdSigProfileV1,
    public_key: &ThresholdSigPublicKey,
    message: &[u8],
    signature: &ThresholdSignature,
) -> Result<bool, ThresholdSigError> {
    validate_profile(profile)?;
    validate_public_key(profile, public_key)?;
    if signature.signers.len() < usize::from(public_key.threshold) {
        return Err(ThresholdSigError::InvalidSignerSet);
    }
    validate_signer_ids(
        &signature.signers,
        public_key.threshold,
        public_key.share_verifiers.len(),
    )?;
    let challenge = derive_challenge(
        message,
        &signature.r_agg,
        &public_key.group_key,
        signature.signers.as_slice(),
    );
    Ok(verify_signature_equation(
        &signature.r_agg,
        &signature.z,
        &challenge,
        &public_key.group_key,
    ))
}

pub fn identify_abort(
    profile: &ThresholdSigProfileV1,
    public_key: &ThresholdSigPublicKey,
    message: &[u8],
    commitments: &[Round1Commitment],
    partials: &[Round2Partial],
) -> Result<Vec<u8>, ThresholdSigError> {
    validate_profile(profile)?;
    validate_public_key(profile, public_key)?;
    validate_commitments(public_key, message, commitments)?;
    let signer_ids = signer_ids_from_commitments(commitments)?;
    let r_agg = aggregate_r(commitments);
    let challenge = derive_challenge(message, &r_agg, &public_key.group_key, &signer_ids);

    let mut bad = Vec::new();
    let mut seen = Vec::new();
    for partial in partials {
        if seen.contains(&partial.index) {
            bad.push(partial.index);
            continue;
        }
        seen.push(partial.index);
        if verify_partial_against_verifier(
            partial,
            commitments,
            public_key,
            &challenge,
            &signer_ids,
        )
        .is_err()
        {
            bad.push(partial.index);
        }
    }

    for commitment in commitments {
        if !partials.iter().any(|p| p.index == commitment.index) {
            bad.push(commitment.index);
        }
    }
    bad.sort_unstable();
    bad.dedup();
    Ok(bad)
}

pub fn proactive_refresh<R: CryptoRng + Rng>(
    profile: &ThresholdSigProfileV1,
    shares: &[SecretShare],
    rng: &mut R,
) -> Result<Vec<SecretShare>, ThresholdSigError> {
    validate_profile(profile)?;
    if shares.is_empty() || shares.len() > usize::from(profile.max_parties) {
        return Err(ThresholdSigError::InvalidShareCount);
    }
    let threshold = shares[0].threshold;
    if threshold == 0 {
        return Err(ThresholdSigError::InvalidThreshold);
    }
    if shares
        .iter()
        .any(|s| s.threshold != threshold || s.share_bytes.len() != SCALAR_BYTES)
    {
        return Err(ThresholdSigError::InvalidShareCount);
    }

    let degree = usize::from(threshold - 1);
    let mut coeffs = vec![vec![0u8; SCALAR_BYTES]; degree + 1];
    for coeff in coeffs.iter_mut().skip(1) {
        rng.fill_bytes(coeff);
    }

    let mut refreshed = Vec::with_capacity(shares.len());
    for share in shares {
        let delta = eval_poly_gf256(share.index, &coeffs);
        let mut out = vec![0u8; SCALAR_BYTES];
        for i in 0..SCALAR_BYTES {
            out[i] = share.share_bytes[i] ^ delta[i];
        }
        refreshed.push(SecretShare {
            index: share.index,
            threshold: share.threshold,
            share_bytes: Zeroizing::new(out),
        });
    }
    for coeff in &mut coeffs {
        coeff.zeroize();
    }
    Ok(refreshed)
}

pub fn encode_threshold_sig_wire_v1(
    profile: &ThresholdSigProfileV1,
    signature: &[u8],
    meta: &[u8],
) -> Result<Vec<u8>, ThresholdSigError> {
    validate_profile(profile)?;
    let sig_len = u16::try_from(signature.len()).map_err(|_| ThresholdSigError::LengthOverflow)?;
    let meta_len = u16::try_from(meta.len()).map_err(|_| ThresholdSigError::LengthOverflow)?;
    let total_len = 1usize + 1 + 2 + signature.len() + 2 + meta.len();
    if total_len > WIRE_BUDGET_THRESHOLD_SIG_BYTES {
        return Err(ThresholdSigError::BudgetExceeded {
            actual: total_len,
            budget: WIRE_BUDGET_THRESHOLD_SIG_BYTES,
        });
    }
    if profile.id == PROFILE_ID_V1 && total_len > PROFILE_ENVELOPE_BUDGET_BYTES {
        return Err(ThresholdSigError::BudgetExceeded {
            actual: total_len,
            budget: PROFILE_ENVELOPE_BUDGET_BYTES,
        });
    }

    let mut out = Vec::with_capacity(total_len);
    out.push(WIRE_VERSION_V1);
    out.push(profile.id);
    out.extend_from_slice(&sig_len.to_le_bytes());
    out.extend_from_slice(signature);
    out.extend_from_slice(&meta_len.to_le_bytes());
    out.extend_from_slice(meta);
    Ok(out)
}

pub fn decode_threshold_sig_wire_v1(
    profile: &ThresholdSigProfileV1,
    wire: &[u8],
) -> Result<ThresholdSigWireV1, ThresholdSigError> {
    validate_profile(profile)?;
    if wire.len() > WIRE_BUDGET_THRESHOLD_SIG_BYTES {
        return Err(ThresholdSigError::BudgetExceeded {
            actual: wire.len(),
            budget: WIRE_BUDGET_THRESHOLD_SIG_BYTES,
        });
    }
    if profile.id == PROFILE_ID_V1 && wire.len() > PROFILE_ENVELOPE_BUDGET_BYTES {
        return Err(ThresholdSigError::BudgetExceeded {
            actual: wire.len(),
            budget: PROFILE_ENVELOPE_BUDGET_BYTES,
        });
    }
    let mut cursor = 0usize;
    let version = read_u8(wire, &mut cursor)?;
    if version != WIRE_VERSION_V1 {
        return Err(ThresholdSigError::WireVersionMismatch {
            expected: WIRE_VERSION_V1,
            found: version,
        });
    }
    let profile_id = read_u8(wire, &mut cursor)?;
    if profile_id != profile.id {
        return Err(ThresholdSigError::WireProfileMismatch {
            expected: profile.id,
            found: profile_id,
        });
    }
    let sig_len = usize::from(read_u16_le(wire, &mut cursor)?);
    let signature = read_bytes(wire, &mut cursor, sig_len)?.to_vec();
    let meta_len = usize::from(read_u16_le(wire, &mut cursor)?);
    let meta = read_bytes(wire, &mut cursor, meta_len)?.to_vec();
    if cursor != wire.len() {
        return Err(ThresholdSigError::WireTruncated);
    }
    Ok(ThresholdSigWireV1 { signature, meta })
}

pub fn encode_signature(sig: &ThresholdSignature) -> Result<Vec<u8>, ThresholdSigError> {
    let signer_len =
        u8::try_from(sig.signers.len()).map_err(|_| ThresholdSigError::LengthOverflow)?;
    let mut out = Vec::with_capacity(32 + 32 + 1 + usize::from(signer_len));
    out.extend_from_slice(&sig.r_agg);
    out.extend_from_slice(&sig.z);
    out.push(signer_len);
    out.extend_from_slice(sig.signers.as_slice());
    Ok(out)
}

pub fn decode_signature(data: &[u8]) -> Result<ThresholdSignature, ThresholdSigError> {
    if data.len() < 65 {
        return Err(ThresholdSigError::WireTruncated);
    }
    let mut cursor = 0usize;
    let mut r_agg = [0u8; SCALAR_BYTES];
    r_agg.copy_from_slice(read_bytes(data, &mut cursor, SCALAR_BYTES)?);
    let mut z = [0u8; SCALAR_BYTES];
    z.copy_from_slice(read_bytes(data, &mut cursor, SCALAR_BYTES)?);
    let signer_len = usize::from(read_u8(data, &mut cursor)?);
    let signers = read_bytes(data, &mut cursor, signer_len)?.to_vec();
    if cursor != data.len() {
        return Err(ThresholdSigError::WireTruncated);
    }
    Ok(ThresholdSignature { r_agg, z, signers })
}

fn validate_profile(profile: &ThresholdSigProfileV1) -> Result<(), ThresholdSigError> {
    if profile.id != PROFILE_ID_V1 || profile.max_parties != PROFILE_MAX_PARTIES_V1 {
        return Err(ThresholdSigError::InvalidProfile);
    }
    Ok(())
}

fn validate_threshold_and_count(
    profile: &ThresholdSigProfileV1,
    threshold: u8,
    share_count: u8,
) -> Result<(), ThresholdSigError> {
    if threshold == 0 || threshold > profile.max_parties {
        return Err(ThresholdSigError::InvalidThreshold);
    }
    if share_count == 0 || share_count > profile.max_parties || share_count < threshold {
        return Err(ThresholdSigError::InvalidShareCount);
    }
    Ok(())
}

fn validate_public_key(
    profile: &ThresholdSigProfileV1,
    public_key: &ThresholdSigPublicKey,
) -> Result<(), ThresholdSigError> {
    if public_key.profile_id != profile.id {
        return Err(ThresholdSigError::InvalidProfile);
    }
    validate_threshold_and_count(
        profile,
        public_key.threshold,
        u8::try_from(public_key.share_verifiers.len())
            .map_err(|_| ThresholdSigError::InvalidShareCount)?,
    )?;
    let mut seen = Vec::new();
    for verifier in &public_key.share_verifiers {
        if verifier.index == 0 || usize::from(verifier.index) > public_key.share_verifiers.len() {
            return Err(ThresholdSigError::InvalidShareCount);
        }
        if seen.contains(&verifier.index) {
            return Err(ThresholdSigError::DuplicateIndex {
                index: verifier.index,
            });
        }
        seen.push(verifier.index);
        if verifier.commitment != derive_share_commitment(verifier.index, &verifier.verifying_key) {
            return Err(ThresholdSigError::InvalidSignature);
        }
    }
    Ok(())
}

fn validate_commitments(
    public_key: &ThresholdSigPublicKey,
    message: &[u8],
    commitments: &[Round1Commitment],
) -> Result<(), ThresholdSigError> {
    if commitments.len() < usize::from(public_key.threshold) {
        return Err(ThresholdSigError::InvalidShareCount);
    }
    let mut seen = Vec::new();
    for commitment in commitments {
        if seen.contains(&commitment.index) {
            return Err(ThresholdSigError::DuplicateIndex {
                index: commitment.index,
            });
        }
        seen.push(commitment.index);
        let _ = public_key
            .share_verifiers
            .iter()
            .find(|v| v.index == commitment.index)
            .ok_or(ThresholdSigError::ShareNotFound {
                index: commitment.index,
            })?;
        let expected =
            derive_round1_binding(commitment.index, &commitment.nonce_commitment, message);
        if commitment.binding != expected {
            return Err(ThresholdSigError::InvalidRound1Binding {
                index: commitment.index,
            });
        }
    }
    Ok(())
}

fn validate_partials(
    public_key: &ThresholdSigPublicKey,
    partials: &[Round2Partial],
) -> Result<(), ThresholdSigError> {
    let mut seen = Vec::new();
    for partial in partials {
        if seen.contains(&partial.index) {
            return Err(ThresholdSigError::DuplicateIndex {
                index: partial.index,
            });
        }
        seen.push(partial.index);
        if !public_key
            .share_verifiers
            .iter()
            .any(|v| v.index == partial.index)
        {
            return Err(ThresholdSigError::ShareNotFound {
                index: partial.index,
            });
        }
    }
    Ok(())
}

fn validate_signer_ids(
    signer_ids: &[u8],
    threshold: u8,
    max_signers: usize,
) -> Result<(), ThresholdSigError> {
    if signer_ids.len() < usize::from(threshold) || signer_ids.len() > max_signers {
        return Err(ThresholdSigError::InvalidSignerSet);
    }
    let mut seen = Vec::new();
    for id in signer_ids {
        if *id == 0 || usize::from(*id) > max_signers {
            return Err(ThresholdSigError::InvalidSignerSet);
        }
        if seen.contains(id) {
            return Err(ThresholdSigError::DuplicateIndex { index: *id });
        }
        seen.push(*id);
    }
    Ok(())
}

fn signer_ids_from_commitments(
    commitments: &[Round1Commitment],
) -> Result<Vec<u8>, ThresholdSigError> {
    let mut ids = Vec::with_capacity(commitments.len());
    for commitment in commitments {
        ids.push(commitment.index);
    }
    if ids.is_empty() {
        return Err(ThresholdSigError::InvalidSignerSet);
    }
    Ok(ids)
}

fn aggregate_r(commitments: &[Round1Commitment]) -> [u8; SCALAR_BYTES] {
    let mut out = [0u8; SCALAR_BYTES];
    for commitment in commitments {
        for (dst, src) in out.iter_mut().zip(commitment.nonce_commitment.iter()) {
            *dst ^= *src;
        }
    }
    out
}

fn derive_share_commitment(index: u8, verifying_key: &[u8; SCALAR_BYTES]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(SHARE_COMMITMENT_DOMAIN);
    hasher.update(&[index]);
    hasher.update(verifying_key);
    let mut out = [0u8; 32];
    hasher.finalize_xof().read(&mut out);
    out
}

fn derive_round1_binding(
    index: u8,
    nonce_commitment: &[u8; SCALAR_BYTES],
    message: &[u8],
) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(ROUND1_BINDING_DOMAIN);
    hasher.update(&[index]);
    hasher.update(nonce_commitment);
    hasher.update(message);
    let mut out = [0u8; 32];
    hasher.finalize_xof().read(&mut out);
    out
}

fn derive_round2_proof(
    index: u8,
    nonce_commitment: &[u8; SCALAR_BYTES],
    z: &[u8; SCALAR_BYTES],
    challenge: &[u8; SCALAR_BYTES],
) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(ROUND2_PROOF_DOMAIN);
    hasher.update(&[index]);
    hasher.update(nonce_commitment);
    hasher.update(z);
    hasher.update(challenge);
    let mut out = [0u8; 32];
    hasher.finalize_xof().read(&mut out);
    out
}

fn derive_challenge(
    message: &[u8],
    r_agg: &[u8; SCALAR_BYTES],
    group_key: &[u8; SCALAR_BYTES],
    signer_ids: &[u8],
) -> [u8; SCALAR_BYTES] {
    let mut out = [0u8; SCALAR_BYTES];
    let ring_q = lib_q_ring::constants::FIELD_MODULUS.to_le_bytes();
    let mut hasher = Shake256::default();
    hasher.update(CHALLENGE_DOMAIN);
    hasher.update(&ring_q);
    hasher.update(r_agg);
    hasher.update(group_key);
    hasher.update(&(u16::try_from(signer_ids.len()).unwrap_or(u16::MAX)).to_le_bytes());
    hasher.update(signer_ids);
    hasher.update(message);
    hasher.finalize_xof().read(&mut out);
    out
}

fn verify_partial_against_verifier(
    partial: &Round2Partial,
    commitments: &[Round1Commitment],
    public_key: &ThresholdSigPublicKey,
    challenge: &[u8; SCALAR_BYTES],
    signer_ids: &[u8],
) -> Result<(), ThresholdSigError> {
    let commitment = commitments
        .iter()
        .find(|c| c.index == partial.index)
        .ok_or(ThresholdSigError::ShareNotFound {
            index: partial.index,
        })?;
    let verifier = public_key
        .share_verifiers
        .iter()
        .find(|v| v.index == partial.index)
        .ok_or(ThresholdSigError::ShareNotFound {
            index: partial.index,
        })?;
    let lambda = lagrange_at_zero(partial.index, signer_ids)?;
    let mut expected_z = [0u8; SCALAR_BYTES];
    for i in 0..SCALAR_BYTES {
        let cterm = gf_mul(challenge[i], gf_mul(lambda, verifier.verifying_key[i]));
        expected_z[i] = commitment.nonce_commitment[i] ^ cterm;
    }
    if !bool::from(partial.z.ct_eq(&expected_z)) {
        return Err(ThresholdSigError::InvalidPartial {
            index: partial.index,
        });
    }
    let expected_proof = derive_round2_proof(
        partial.index,
        &commitment.nonce_commitment,
        &partial.z,
        challenge,
    );
    if !bool::from(partial.proof.ct_eq(&expected_proof)) {
        return Err(ThresholdSigError::InvalidPartial {
            index: partial.index,
        });
    }
    Ok(())
}

fn verify_signature_equation(
    r_agg: &[u8; SCALAR_BYTES],
    z_agg: &[u8; SCALAR_BYTES],
    challenge: &[u8; SCALAR_BYTES],
    group_key: &[u8; SCALAR_BYTES],
) -> bool {
    let mut rhs = [0u8; SCALAR_BYTES];
    for i in 0..SCALAR_BYTES {
        rhs[i] = r_agg[i] ^ gf_mul(challenge[i], group_key[i]);
    }
    bool::from(z_agg.ct_eq(&rhs))
}

fn encode_meta_for_abort(
    commitments: &[Round1Commitment],
    partials: &[Round2Partial],
) -> Result<Vec<u8>, ThresholdSigError> {
    let signer_count =
        u8::try_from(commitments.len()).map_err(|_| ThresholdSigError::LengthOverflow)?;
    let mut out = Vec::with_capacity(1 + commitments.len() * (1 + 32 + 32));
    out.push(signer_count);
    for commitment in commitments {
        out.push(commitment.index);
        out.extend_from_slice(&commitment.nonce_commitment);
        if let Some(partial) = partials.iter().find(|p| p.index == commitment.index) {
            out.extend_from_slice(&partial.z);
        } else {
            out.extend_from_slice(&[0u8; SCALAR_BYTES]);
        }
    }
    Ok(out)
}

fn read_u8(wire: &[u8], cursor: &mut usize) -> Result<u8, ThresholdSigError> {
    let b = wire
        .get(*cursor)
        .copied()
        .ok_or(ThresholdSigError::WireTruncated)?;
    *cursor += 1;
    Ok(b)
}

fn read_u16_le(wire: &[u8], cursor: &mut usize) -> Result<u16, ThresholdSigError> {
    let bytes = read_bytes(wire, cursor, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_bytes<'a>(
    wire: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], ThresholdSigError> {
    let end = cursor.saturating_add(len);
    if end > wire.len() {
        return Err(ThresholdSigError::WireTruncated);
    }
    let out = &wire[*cursor..end];
    *cursor = end;
    Ok(out)
}

fn reconstruct_group_key_from_verifiers(
    verifiers: &[ShareVerifier],
    threshold: u8,
) -> Result<[u8; SCALAR_BYTES], ThresholdSigError> {
    let selected: Vec<(u8, [u8; SCALAR_BYTES])> = verifiers
        .iter()
        .take(usize::from(threshold))
        .map(|v| (v.index, v.verifying_key))
        .collect();
    if selected.len() < usize::from(threshold) {
        return Err(ThresholdSigError::InvalidShareCount);
    }
    interpolate_scalar_zero(&selected)
}

fn interpolate_scalar_zero(
    shares: &[(u8, [u8; SCALAR_BYTES])],
) -> Result<[u8; SCALAR_BYTES], ThresholdSigError> {
    if shares.is_empty() {
        return Err(ThresholdSigError::InterpolationFailed);
    }
    let mut out = [0u8; SCALAR_BYTES];
    for b in 0..SCALAR_BYTES {
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
                return Err(ThresholdSigError::InterpolationFailed);
            }
            let den_inv = gf_inv(den).ok_or(ThresholdSigError::InterpolationFailed)?;
            let lambda = gf_mul(num, den_inv);
            acc ^= gf_mul(y_i[b], lambda);
        }
        out[b] = acc;
    }
    Ok(out)
}

fn lagrange_at_zero(index: u8, signer_ids: &[u8]) -> Result<u8, ThresholdSigError> {
    if !signer_ids.contains(&index) {
        return Err(ThresholdSigError::InvalidSignerSet);
    }
    let mut num = 1u8;
    let mut den = 1u8;
    for x_j in signer_ids {
        if *x_j == index {
            continue;
        }
        num = gf_mul(num, *x_j);
        den = gf_mul(den, x_j ^ index);
    }
    if den == 0 {
        return Err(ThresholdSigError::InterpolationFailed);
    }
    let den_inv = gf_inv(den).ok_or(ThresholdSigError::InterpolationFailed)?;
    Ok(gf_mul(num, den_inv))
}

fn shamir_split_secret<R: CryptoRng + Rng>(
    secret: &[u8],
    threshold: u8,
    share_count: u8,
    rng: &mut R,
) -> Result<Vec<(u8, Vec<u8>)>, ThresholdSigError> {
    if threshold == 0 || share_count == 0 || share_count < threshold {
        return Err(ThresholdSigError::InvalidShareCount);
    }
    if secret.len() != SCALAR_BYTES {
        return Err(ThresholdSigError::InvalidShareCount);
    }
    let mut shares = Vec::with_capacity(usize::from(share_count));
    for idx in 1..=share_count {
        shares.push((idx, vec![0u8; SCALAR_BYTES]));
    }
    let mut coeffs = vec![0u8; usize::from(threshold)];
    for byte_index in 0..SCALAR_BYTES {
        coeffs[0] = secret[byte_index];
        for coeff in coeffs.iter_mut().skip(1) {
            let mut sample = [0u8; 1];
            rng.fill_bytes(&mut sample);
            *coeff = sample[0];
        }
        for (x, out) in &mut shares {
            out[byte_index] = eval_poly_byte(*x, &coeffs);
        }
    }
    coeffs.zeroize();
    Ok(shares)
}

fn eval_poly_gf256(x: u8, coeffs: &[Vec<u8>]) -> [u8; SCALAR_BYTES] {
    let mut out = [0u8; SCALAR_BYTES];
    for b in 0..SCALAR_BYTES {
        let mut acc = 0u8;
        for coeff in coeffs.iter().rev() {
            acc = gf_mul(acc, x) ^ coeff[b];
        }
        out[b] = acc;
    }
    out
}

fn eval_poly_byte(x: u8, coeffs: &[u8]) -> u8 {
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

    fn pick_three<T: Clone>(items: &[T]) -> Vec<T> {
        vec![items[0].clone(), items[1].clone(), items[2].clone()]
    }

    #[test]
    fn wire_roundtrip() {
        let profile = setup();
        let mut rng = deterministic_rng(0x11);
        let keygen = keygen_shares(&profile, 3, 5, &mut rng).expect("keygen failed");
        let message = b"wire roundtrip";
        let states: Vec<Round1State> = keygen
            .secret_shares
            .iter()
            .take(3)
            .map(|s| sign_round1(&profile, s, message, &mut rng).expect("round1 failed"))
            .collect();
        let commitments: Vec<Round1Commitment> =
            states.iter().map(|s| s.commitment.clone()).collect();
        let partials: Vec<Round2Partial> = states
            .iter()
            .zip(keygen.secret_shares.iter())
            .take(3)
            .map(|(state, share)| {
                sign_round2(
                    &profile,
                    &keygen.public_key,
                    message,
                    share,
                    state,
                    &commitments,
                )
                .expect("round2 failed")
            })
            .collect();
        let agg = aggregate(
            &profile,
            &keygen.public_key,
            message,
            &commitments,
            &partials,
        )
        .expect("aggregate failed");
        let decoded =
            decode_threshold_sig_wire_v1(&profile, &agg.wire).expect("decode wire failed");
        assert_eq!(decoded.signature, agg.signature_bytes);
        assert_eq!(
            decode_signature(&decoded.signature).expect("decode sig"),
            agg.signature
        );
    }

    #[test]
    fn budget_gates() {
        let profile = setup();
        let oversized_sig = vec![0u8; WIRE_BUDGET_THRESHOLD_SIG_BYTES];
        let err = encode_threshold_sig_wire_v1(&profile, &oversized_sig, &[])
            .expect_err("oversized payload accepted");
        assert!(matches!(err, ThresholdSigError::BudgetExceeded { .. }));

        let mut wire = Vec::new();
        wire.push(WIRE_VERSION_V1);
        wire.push(PROFILE_ID_V1);
        wire.extend_from_slice(&2u16.to_le_bytes());
        wire.extend_from_slice(&[1u8, 2u8]);
        wire.extend_from_slice(&0u16.to_le_bytes());
        wire.extend_from_slice(&[0u8; WIRE_BUDGET_THRESHOLD_SIG_BYTES]);
        let err =
            decode_threshold_sig_wire_v1(&profile, &wire).expect_err("oversized wire accepted");
        assert!(matches!(err, ThresholdSigError::BudgetExceeded { .. }));
    }

    #[test]
    fn kat_vectors() {
        let profile = setup();
        let mut rng = deterministic_rng(0x42);
        let keygen = keygen_shares(&profile, 3, 5, &mut rng).expect("keygen failed");
        let message = b"kat-sign-verify-3-of-5";
        let selected_shares = pick_three(&keygen.secret_shares);
        let states: Vec<Round1State> = selected_shares
            .iter()
            .map(|s| sign_round1(&profile, s, message, &mut rng).expect("round1 failed"))
            .collect();
        let commitments: Vec<Round1Commitment> =
            states.iter().map(|s| s.commitment.clone()).collect();
        let partials: Vec<Round2Partial> = states
            .iter()
            .zip(selected_shares.iter())
            .map(|(state, share)| {
                sign_round2(
                    &profile,
                    &keygen.public_key,
                    message,
                    share,
                    state,
                    &commitments,
                )
                .expect("round2 failed")
            })
            .collect();

        let agg = aggregate(
            &profile,
            &keygen.public_key,
            message,
            &commitments,
            &partials,
        )
        .expect("aggregate failed");
        assert!(
            verify(&profile, &keygen.public_key, message, &agg.signature).expect("verify failed"),
            "valid signature must verify",
        );
        assert!(
            agg.wire.len() <= WIRE_BUDGET_THRESHOLD_SIG_BYTES,
            "wire over budget",
        );
        assert!(
            agg.wire.len() <= PROFILE_ENVELOPE_BUDGET_BYTES,
            "envelope size must fit positive budget",
        );

        let mut corrupted_partials = partials.clone();
        corrupted_partials[1].z[0] ^= 0x7A;
        let offenders = identify_abort(
            &profile,
            &keygen.public_key,
            message,
            &commitments,
            &corrupted_partials,
        )
        .expect("identify abort failed");
        assert!(offenders.contains(&corrupted_partials[1].index));
    }

    #[test]
    #[ignore = "regenerates tests/vectors/threshold-sig-pop-v1.json"]
    fn kat_regenerate_vectors() {
        use std::fs;
        use std::path::Path;

        let profile = setup();
        let mut rng = deterministic_rng(0x66);
        let keygen = keygen_shares(&profile, 3, 5, &mut rng).expect("keygen");
        let message = b"kat-regenerate-message";
        let selected = pick_three(&keygen.secret_shares);
        let states: Vec<Round1State> = selected
            .iter()
            .map(|s| sign_round1(&profile, s, message, &mut rng).expect("round1"))
            .collect();
        let commitments: Vec<Round1Commitment> =
            states.iter().map(|s| s.commitment.clone()).collect();
        let partials: Vec<Round2Partial> = states
            .iter()
            .zip(selected.iter())
            .map(|(state, share)| {
                sign_round2(
                    &profile,
                    &keygen.public_key,
                    message,
                    share,
                    state,
                    &commitments,
                )
                .expect("round2")
            })
            .collect();
        let agg = aggregate(
            &profile,
            &keygen.public_key,
            message,
            &commitments,
            &partials,
        )
        .expect("aggregate");

        let doc = serde_json::json!({
            "format": "threshold-sig-kat-v1",
            "spec_version": "v1",
            "wire_hex": hex::encode(&agg.wire),
            "wire_bytes": agg.wire.len(),
            "message_hex": hex::encode(message),
            "threshold": 3,
            "parties": 5,
        });
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
        fs::create_dir_all(&dir).expect("mkdir vectors");
        fs::write(
            dir.join("threshold-sig-pop-v1.json"),
            serde_json::to_string_pretty(&doc).expect("json"),
        )
        .expect("write kat");
        let manifest = serde_json::json!({
            "schema": "threshold-sig-kat-v1",
            "regenerate": "cargo test -p lib-q-threshold-sig kat_regenerate_vectors -- --ignored",
            "wire_bytes": agg.wire.len(),
            "budget_bytes": PROFILE_ENVELOPE_BUDGET_BYTES,
        });
        fs::write(
            dir.join("manifest.json"),
            serde_json::to_string_pretty(&manifest).expect("json"),
        )
        .expect("write manifest");
    }

    #[test]
    fn proactive_refresh_preserves_group_key() {
        let profile = setup();
        let mut rng = deterministic_rng(0x77);
        let keygen = keygen_shares(&profile, 3, 5, &mut rng).expect("keygen failed");
        let refreshed =
            proactive_refresh(&profile, &keygen.secret_shares, &mut rng).expect("refresh failed");

        let rebuilt_verifiers: Vec<ShareVerifier> = refreshed
            .iter()
            .map(|s| {
                let mut vk = [0u8; SCALAR_BYTES];
                vk.copy_from_slice(&s.share_bytes);
                ShareVerifier {
                    index: s.index,
                    commitment: derive_share_commitment(s.index, &vk),
                    verifying_key: vk,
                }
            })
            .collect();
        let rebuilt_group =
            reconstruct_group_key_from_verifiers(&rebuilt_verifiers, keygen.public_key.threshold)
                .expect("rebuild group key");
        assert_eq!(rebuilt_group, keygen.public_key.group_key);
    }

    #[test]
    fn oversize_reject_and_envelope_positive() {
        let profile = setup();
        let meta = vec![0u8; PROFILE_ENVELOPE_BUDGET_BYTES];
        let sig = vec![0u8; 80];
        let wire = encode_threshold_sig_wire_v1(&profile, &sig, &meta);
        assert!(wire.is_err(), "expected budget rejection");

        let small_meta = vec![0u8; 128];
        let small_sig = vec![0u8; 96];
        let wire2 = encode_threshold_sig_wire_v1(&profile, &small_sig, &small_meta)
            .expect("small envelope should pass");
        assert!(wire2.len() <= PROFILE_ENVELOPE_BUDGET_BYTES);
    }
}
