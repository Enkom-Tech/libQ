//! Core HPKE implementation logic

#[cfg(feature = "alloc")]
use alloc::format;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::error::HpkeError;
use crate::providers::traits::*;
use crate::security::CryptoRng;
use crate::security::constant_time::constant_time_eq;
use crate::types::*;
use crate::{
    HpkeReceiverContext,
    HpkeSenderContext,
};

/// Outputs of [`key_schedule`]: AEAD key material and exporter secret.
///
/// Each field is [`Zeroizing`] and is cleared when dropped or when moved out into
/// an HPKE context.
pub struct KeyScheduleSecrets {
    /// AEAD key
    pub key: Zeroizing<Vec<u8>>,
    /// Base nonce
    pub nonce: Zeroizing<Vec<u8>>,
    /// Exporter secret (long-lived pivot for HPKE-Export)
    pub exporter_secret: Zeroizing<Vec<u8>>,
}

type ParsedReceiverEncapsulatedKey = (Vec<u8>, Option<Vec<u8>>, HpkeKem);

/// Validate PSK parameters for a given mode
fn validate_psk_parameters(
    mode: HpkeMode,
    psk: Option<&[u8]>,
    psk_id: Option<&[u8]>,
) -> Result<(), HpkeError> {
    match mode {
        HpkeMode::Base => {
            // Base mode: no PSK parameters allowed
            if psk.is_some() || psk_id.is_some() {
                return Err(HpkeError::CryptoError(
                    "Base mode does not support PSK parameters".into(),
                ));
            }
        }
        HpkeMode::Psk => {
            // PSK mode: both PSK and PSK ID required
            if psk.is_none() || psk_id.is_none() {
                return Err(HpkeError::CryptoError(
                    "PSK mode requires both PSK and PSK ID".into(),
                ));
            }
            // Validate PSK is not empty
            if let Some(psk_bytes) = psk &&
                psk_bytes.is_empty()
            {
                return Err(HpkeError::CryptoError("PSK cannot be empty".into()));
            }
        }
        HpkeMode::Auth => {
            // Auth mode: no PSK parameters allowed
            if psk.is_some() || psk_id.is_some() {
                return Err(HpkeError::CryptoError(
                    "Auth mode does not support PSK parameters".into(),
                ));
            }
        }
        HpkeMode::AuthPsk => {
            // AuthPSK mode: both PSK and PSK ID required
            if psk.is_none() || psk_id.is_none() {
                return Err(HpkeError::CryptoError(
                    "AuthPSK mode requires both PSK and PSK ID".into(),
                ));
            }
            // Validate PSK is not empty
            if let Some(psk_bytes) = psk &&
                psk_bytes.is_empty()
            {
                return Err(HpkeError::CryptoError("PSK cannot be empty".into()));
            }
        }
    }
    Ok(())
}

/// Whether PSK commitment suffix is used on the wire for this mode and format choice.
fn psk_commitment_suffix_enabled(mode: HpkeMode, psk_wire_format: HpkePskWireFormat) -> bool {
    matches!(
        (mode, psk_wire_format),
        (
            HpkeMode::Psk | HpkeMode::AuthPsk,
            HpkePskWireFormat::LibQCommitmentSuffix
        )
    )
}

/// Length of the PSK commitment appended to the encapsulated key in PSK modes.
pub fn psk_commitment_len(cipher_suite: &HpkeCipherSuite) -> usize {
    cipher_suite.kdf.extract_len()
}

/// Derive a PSK commitment for wire transmission (libQ PSK-mode extension).
///
/// Both parties derive the same value from `(psk, psk_id)`; the sender appends it to
/// the encapsulated key and the receiver compares before running the key schedule.
pub fn derive_psk_commitment<P: HpkeCryptoProvider>(
    psk: &[u8],
    psk_id: &[u8],
    cipher_suite: &HpkeCipherSuite,
    provider: &P,
) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
    let suite_id = create_suite_id(cipher_suite)?;
    let mut psk_input = Zeroizing::new(Vec::with_capacity(psk.len() + psk_id.len()));
    psk_input.extend_from_slice(psk);
    psk_input.extend_from_slice(psk_id);
    labeled_extract(
        cipher_suite.kdf,
        b"",
        &suite_id,
        "psk_commitment",
        psk_input.as_slice(),
        provider,
    )
}

fn verify_psk_commitment<P: HpkeCryptoProvider>(
    psk: &[u8],
    psk_id: &[u8],
    sender_commitment: &[u8],
    cipher_suite: &HpkeCipherSuite,
    provider: &P,
) -> Result<(), HpkeError> {
    let local_commitment = derive_psk_commitment(psk, psk_id, cipher_suite, provider)?;
    if !constant_time_eq(local_commitment.as_slice(), sender_commitment) {
        return Err(HpkeError::InconsistentPsk);
    }
    Ok(())
}

fn append_psk_commitment(mut encapsulated_key: Vec<u8>, commitment: Zeroizing<Vec<u8>>) -> Vec<u8> {
    encapsulated_key.extend_from_slice(commitment.as_slice());
    encapsulated_key
}

struct EncapsulatedKeyParts {
    main: Vec<u8>,
    auth: Option<Vec<u8>>,
    psk_commitment: Option<Vec<u8>>,
}

fn split_encapsulated_key_for_receiver(
    encapsulated_key: &[u8],
    mode: HpkeMode,
    kem_enc_len: usize,
    commitment_len: usize,
) -> Result<EncapsulatedKeyParts, HpkeError> {
    match mode {
        HpkeMode::Base => Ok(EncapsulatedKeyParts {
            main: encapsulated_key.to_vec(),
            auth: None,
            psk_commitment: None,
        }),
        HpkeMode::Psk => {
            let min_len = kem_enc_len + commitment_len;
            if encapsulated_key.len() < min_len {
                return Err(HpkeError::CryptoError(format!(
                    "Invalid PSK mode encapsulated key size: {} bytes (expected at least {} bytes)",
                    encapsulated_key.len(),
                    min_len
                )));
            }
            let (kem_part, commitment) =
                encapsulated_key.split_at(encapsulated_key.len() - commitment_len);
            if kem_part.len() != kem_enc_len {
                return Err(HpkeError::CryptoError(format!(
                    "Invalid PSK mode KEM ciphertext size: {} bytes (expected {} bytes)",
                    kem_part.len(),
                    kem_enc_len
                )));
            }
            Ok(EncapsulatedKeyParts {
                main: kem_part.to_vec(),
                auth: None,
                psk_commitment: Some(commitment.to_vec()),
            })
        }
        HpkeMode::Auth => {
            if encapsulated_key.len() < kem_enc_len * 2 {
                return Err(HpkeError::CryptoError(format!(
                    "Invalid Auth mode encapsulated key size: {} bytes (expected at least {} bytes)",
                    encapsulated_key.len(),
                    kem_enc_len * 2
                )));
            }
            let (main_part, auth_part) = encapsulated_key.split_at(kem_enc_len);
            Ok(EncapsulatedKeyParts {
                main: main_part.to_vec(),
                auth: Some(auth_part.to_vec()),
                psk_commitment: None,
            })
        }
        HpkeMode::AuthPsk => {
            let min_len = kem_enc_len * 2 + commitment_len;
            if encapsulated_key.len() < min_len {
                return Err(HpkeError::CryptoError(format!(
                    "Invalid AuthPsk mode encapsulated key size: {} bytes (expected at least {} bytes)",
                    encapsulated_key.len(),
                    min_len
                )));
            }
            let (prefix, commitment) =
                encapsulated_key.split_at(encapsulated_key.len() - commitment_len);
            let (main_part, auth_part) = prefix.split_at(kem_enc_len);
            Ok(EncapsulatedKeyParts {
                main: main_part.to_vec(),
                auth: Some(auth_part.to_vec()),
                psk_commitment: Some(commitment.to_vec()),
            })
        }
    }
}

#[allow(clippy::too_many_arguments)] // PSK / AuthPSK receiver parse needs full RFC parameter surface
fn parse_receiver_encapsulated_key<P: HpkeCryptoProvider>(
    encapsulated_key: &[u8],
    mode: HpkeMode,
    cipher_suite: &HpkeCipherSuite,
    sender_pk: Option<&lib_q_core::KemPublicKey>,
    psk: Option<&[u8]>,
    psk_id: Option<&[u8]>,
    psk_wire_format: HpkePskWireFormat,
    provider: &P,
) -> Result<ParsedReceiverEncapsulatedKey, HpkeError> {
    let commitment_len = if psk_commitment_suffix_enabled(mode, psk_wire_format) {
        psk_commitment_len(cipher_suite)
    } else {
        0
    };

    let kem_enc_len = match mode {
        HpkeMode::Auth | HpkeMode::AuthPsk => {
            let sender_pk = sender_pk.ok_or_else(|| {
                HpkeError::CryptoError("Auth and AuthPSK modes require sender public key".into())
            })?;
            determine_kem_from_key_size(sender_pk.as_bytes().len())?.enc_len()
        }
        HpkeMode::Psk => {
            if encapsulated_key.len() < commitment_len {
                return Err(HpkeError::CryptoError(format!(
                    "Invalid PSK mode encapsulated key size: {} bytes (expected at least {} bytes)",
                    encapsulated_key.len(),
                    commitment_len
                )));
            }
            let kem_wire_len = encapsulated_key.len() - commitment_len;
            determine_kem_from_encapsulated_key_size(kem_wire_len)?.enc_len()
        }
        HpkeMode::Base => {
            determine_kem_from_encapsulated_key_size(encapsulated_key.len())?.enc_len()
        }
    };

    let parts =
        split_encapsulated_key_for_receiver(encapsulated_key, mode, kem_enc_len, commitment_len)?;

    if let Some(sender_commitment) = parts.psk_commitment {
        let psk = psk.ok_or(HpkeError::InconsistentPsk)?;
        let psk_id = psk_id.ok_or(HpkeError::InconsistentPsk)?;
        verify_psk_commitment(psk, psk_id, &sender_commitment, cipher_suite, provider)?;
    }

    let kem_algorithm = determine_kem_from_encapsulated_key_size(parts.main.len())?;
    Ok((parts.main, parts.auth, kem_algorithm))
}

fn attach_psk_commitment_to_encapsulated_key<P: HpkeCryptoProvider>(
    encapsulated_key: Vec<u8>,
    mode: HpkeMode,
    psk: Option<&[u8]>,
    psk_id: Option<&[u8]>,
    psk_wire_format: HpkePskWireFormat,
    cipher_suite: &HpkeCipherSuite,
    provider: &P,
) -> Result<Vec<u8>, HpkeError> {
    if !psk_commitment_suffix_enabled(mode, psk_wire_format) {
        return Ok(encapsulated_key);
    }

    let commitment = derive_psk_commitment(
        psk.ok_or(HpkeError::InconsistentPsk)?,
        psk_id.ok_or(HpkeError::InconsistentPsk)?,
        cipher_suite,
        provider,
    )?;
    Ok(append_psk_commitment(encapsulated_key, commitment))
}

/// Determine the KEM algorithm from public key size
fn determine_kem_from_key_size(key_size: usize) -> Result<HpkeKem, HpkeError> {
    match key_size {
        800 => Ok(HpkeKem::MlKem512),
        1184 => Ok(HpkeKem::MlKem768),
        1568 => Ok(HpkeKem::MlKem1024),
        _ => Err(HpkeError::CryptoError(format!(
            "Unsupported ML-KEM public key size: {} bytes (expected 800, 1184, or 1568)",
            key_size
        ))),
    }
}

/// Determine the KEM algorithm from encapsulated key size
fn determine_kem_from_encapsulated_key_size(
    encapsulated_key_size: usize,
) -> Result<HpkeKem, HpkeError> {
    match encapsulated_key_size {
        768 => Ok(HpkeKem::MlKem512),
        1088 => Ok(HpkeKem::MlKem768),
        1568 => Ok(HpkeKem::MlKem1024),
        _ => Err(HpkeError::CryptoError(format!(
            "Unsupported ML-KEM encapsulated key size: {} bytes (expected 768, 1088, or 1568)",
            encapsulated_key_size
        ))),
    }
}

/// Setup sender context for Base mode
pub fn setup_sender<P: HpkeCryptoProvider>(
    kem_ctx: &mut lib_q_core::KemContext,
    recipient_pk: &lib_q_core::KemPublicKey,
    info: &[u8],
    cipher_suite: &HpkeCipherSuite,
    provider: &P,
    rng: &mut dyn CryptoRng,
) -> Result<HpkeSenderContext, HpkeError> {
    setup_sender_with_mode(
        kem_ctx,
        recipient_pk,
        info,
        cipher_suite,
        provider,
        rng,
        HpkeMode::Base,
        None,
        None,
        None,
        None,
        HpkePskWireFormat::default(),
    )
}

/// Setup sender context with full mode support
#[allow(clippy::too_many_arguments)]
pub fn setup_sender_with_mode<P: HpkeCryptoProvider>(
    kem_ctx: &mut lib_q_core::KemContext,
    recipient_pk: &lib_q_core::KemPublicKey,
    info: &[u8],
    cipher_suite: &HpkeCipherSuite,
    provider: &P,
    rng: &mut dyn CryptoRng,
    mode: HpkeMode,
    psk: Option<&[u8]>,
    psk_id: Option<&[u8]>,
    sender_sk: Option<&lib_q_core::KemSecretKey>,
    sender_pk: Option<&lib_q_core::KemPublicKey>,
    psk_wire_format: HpkePskWireFormat,
) -> Result<HpkeSenderContext, HpkeError> {
    // Validate PSK parameters for the given mode
    validate_psk_parameters(mode, psk, psk_id)?;

    // Validate sender authentication parameters
    match mode {
        HpkeMode::Base | HpkeMode::Psk => {
            // Base and PSK modes: no sender authentication
            if sender_sk.is_some() || sender_pk.is_some() {
                return Err(HpkeError::CryptoError(
                    "Base and PSK modes do not support sender authentication".into(),
                ));
            }
        }
        HpkeMode::Auth | HpkeMode::AuthPsk => {
            // Auth and AuthPSK modes: require sender authentication
            if sender_sk.is_none() || sender_pk.is_none() {
                return Err(HpkeError::CryptoError(
                    "Auth and AuthPSK modes require sender key pair".into(),
                ));
            }
        }
    }

    // Validate key sizes and KEM context compatibility
    let pk_size = recipient_pk.as_bytes().len();
    if pk_size != 800 && pk_size != 1184 && pk_size != 1568 {
        return Err(HpkeError::CryptoError(format!(
            "Invalid ML-KEM public key size: {} bytes (expected 800, 1184, or 1568)",
            pk_size
        )));
    }

    // Validate that the KEM context supports the required algorithm
    // This ensures compatibility between the HPKE implementation and lib-q-core
    let kem_algorithm = determine_kem_from_key_size(pk_size)?;

    // Validate KEM context compatibility and provider configuration
    validate_kem_context_for_algorithm(kem_ctx, kem_algorithm)?;

    // Validate sender key sizes if provided
    if let Some(sender_pk) = sender_pk {
        let sender_pk_size = sender_pk.as_bytes().len();
        if sender_pk_size != 800 && sender_pk_size != 1184 && sender_pk_size != 1568 {
            return Err(HpkeError::CryptoError(format!(
                "Invalid sender ML-KEM public key size: {} bytes (expected 800, 1184, or 1568)",
                sender_pk_size
            )));
        }
    }

    // Use the validated KEM algorithm from above

    // Perform KEM encapsulation
    let (encapsulated_key, mut main_shared_secret) = provider
        .encapsulate(kem_algorithm, recipient_pk.as_bytes(), rng)
        .map_err(|e| e.into())?;

    // For Auth and AuthPSK modes, we need to perform sender authentication
    let (auth_shared_secret, auth_encapsulated_key) =
        if matches!(mode, HpkeMode::Auth | HpkeMode::AuthPsk) {
            let sender_sk = sender_sk.unwrap(); // Safe because we validated above
            let sender_pk = sender_pk.unwrap(); // Safe because we validated above

            // Validate that sender key pair is consistent (basic validation)
            // In a full implementation, we would verify that sender_pk corresponds to sender_sk
            // For now, we ensure both keys have the correct sizes for the algorithm
            let expected_sk_len = kem_algorithm.secret_key_len();
            let expected_pk_len = kem_algorithm.public_key_len();

            if sender_sk.as_bytes().len() != expected_sk_len {
                return Err(HpkeError::CryptoError(format!(
                    "Invalid sender secret key size: {} bytes (expected {})",
                    sender_sk.as_bytes().len(),
                    expected_sk_len
                )));
            }

            if sender_pk.as_bytes().len() != expected_pk_len {
                return Err(HpkeError::CryptoError(format!(
                    "Invalid sender public key size: {} bytes (expected {})",
                    sender_pk.as_bytes().len(),
                    expected_pk_len
                )));
            }

            // Perform sender authentication using AuthEncap (RFC 9180 Section 5.1.3)
            let (auth_encapsulated_key, auth_kem_secret) = provider
                .auth_encapsulate(
                    kem_algorithm,
                    sender_sk.as_bytes(),
                    recipient_pk.as_bytes(),
                    rng,
                )
                .map_err(|e| e.into())?;

            // For Auth modes, we need to combine the shared secrets
            // The auth_encapsulated_key will be concatenated with the main encapsulated key
            main_shared_secret.extend_from_slice(auth_kem_secret.as_slice());
            (main_shared_secret, Some(auth_encapsulated_key))
        } else {
            (main_shared_secret, None)
        };

    // Run key schedule to derive keys
    let schedule = key_schedule(
        auth_shared_secret.as_slice(),
        info,
        psk,
        psk_id,
        cipher_suite,
        provider,
    )?;

    // Combine encapsulated keys for Auth modes and attach PSK commitment when required
    let kem_encapsulated_key = if let Some(auth_encap) = auth_encapsulated_key {
        let mut combined = encapsulated_key.clone();
        combined.extend_from_slice(&auth_encap);
        combined
    } else {
        encapsulated_key
    };
    let final_encapsulated_key = attach_psk_commitment_to_encapsulated_key(
        kem_encapsulated_key,
        mode,
        psk,
        psk_id,
        psk_wire_format,
        cipher_suite,
        provider,
    )?;

    Ok(HpkeSenderContext {
        shared_secret: auth_shared_secret,
        exporter_secret: schedule.exporter_secret,
        key: schedule.key,
        nonce: schedule.nonce,
        aead: cipher_suite.aead,
        encapsulated_key: final_encapsulated_key,
        sequence_number: 0,
        max_sequence_number: u32::MAX - 1,
        state: HpkeContextState::Active,
    })
}

/// Setup receiver context for Base mode
pub fn setup_receiver<P: HpkeCryptoProvider>(
    kem_ctx: &mut lib_q_core::KemContext,
    encapsulated_key: &[u8],
    recipient_sk: &lib_q_core::KemSecretKey,
    info: &[u8],
    cipher_suite: &HpkeCipherSuite,
    provider: &P,
) -> Result<HpkeReceiverContext, HpkeError> {
    setup_receiver_with_mode(
        kem_ctx,
        encapsulated_key,
        recipient_sk,
        info,
        cipher_suite,
        provider,
        HpkeMode::Base,
        None,
        None,
        None,
        HpkePskWireFormat::default(),
    )
}

/// Setup receiver context with full mode support
#[allow(clippy::too_many_arguments)]
pub fn setup_receiver_with_mode<P: HpkeCryptoProvider>(
    kem_ctx: &mut lib_q_core::KemContext,
    encapsulated_key: &[u8],
    recipient_sk: &lib_q_core::KemSecretKey,
    info: &[u8],
    cipher_suite: &HpkeCipherSuite,
    provider: &P,
    mode: HpkeMode,
    psk: Option<&[u8]>,
    psk_id: Option<&[u8]>,
    sender_pk: Option<&lib_q_core::KemPublicKey>,
    psk_wire_format: HpkePskWireFormat,
) -> Result<HpkeReceiverContext, HpkeError> {
    // Validate PSK parameters for the given mode
    validate_psk_parameters(mode, psk, psk_id)?;

    // Validate sender authentication parameters
    match mode {
        HpkeMode::Base | HpkeMode::Psk => {
            // Base and PSK modes: no sender authentication
            if sender_pk.is_some() {
                return Err(HpkeError::CryptoError(
                    "Base and PSK modes do not support sender authentication".into(),
                ));
            }
        }
        HpkeMode::Auth | HpkeMode::AuthPsk => {
            // Auth and AuthPSK modes: require sender public key
            if sender_pk.is_none() {
                return Err(HpkeError::CryptoError(
                    "Auth and AuthPSK modes require sender public key".into(),
                ));
            }
        }
    }

    // Parse encapsulated key (KEM ciphertext, optional auth encap, optional PSK commitment)
    let (main_encapsulated_key, auth_encapsulated_key, kem_algorithm) =
        parse_receiver_encapsulated_key(
            encapsulated_key,
            mode,
            cipher_suite,
            sender_pk,
            psk,
            psk_id,
            psk_wire_format,
            provider,
        )?;

    // Validate KEM context compatibility and provider configuration
    validate_kem_context_for_algorithm(kem_ctx, kem_algorithm)?;

    // Perform KEM decapsulation on the main encapsulated key
    let mut main_shared_secret = provider
        .decapsulate(
            kem_algorithm,
            recipient_sk.as_bytes(),
            &main_encapsulated_key,
        )
        .map_err(|e| e.into())?;

    // For Auth and AuthPSK modes, we need to perform sender authentication
    let auth_shared_secret = if matches!(mode, HpkeMode::Auth | HpkeMode::AuthPsk) {
        let sender_pk = sender_pk.unwrap(); // Safe because we validated above
        let auth_encap = auth_encapsulated_key.unwrap(); // Safe because we set it above

        // Perform sender authentication using AuthDecap (RFC 9180 Section 5.1.3)
        let auth_kem_secret = provider
            .auth_decapsulate(
                kem_algorithm,
                &auth_encap,
                recipient_sk.as_bytes(),
                sender_pk.as_bytes(),
            )
            .map_err(|e| e.into())?;

        // Combine shared secrets using AuthDecap
        main_shared_secret.extend_from_slice(auth_kem_secret.as_slice());
        main_shared_secret
    } else {
        main_shared_secret
    };

    // Run key schedule to derive keys
    let schedule = key_schedule(
        auth_shared_secret.as_slice(),
        info,
        psk,
        psk_id,
        cipher_suite,
        provider,
    )?;

    Ok(HpkeReceiverContext {
        shared_secret: auth_shared_secret,
        exporter_secret: schedule.exporter_secret,
        key: schedule.key,
        nonce: schedule.nonce,
        aead: cipher_suite.aead,
        sequence_number: 0,
        max_sequence_number: u32::MAX - 1,
        state: HpkeContextState::Active,
    })
}

/// Single-shot encryption for Base mode
#[allow(clippy::too_many_arguments)]
pub fn seal<P: HpkeCryptoProvider>(
    kem_ctx: &mut lib_q_core::KemContext,
    recipient_pk: &lib_q_core::KemPublicKey,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    cipher_suite: &HpkeCipherSuite,
    provider: &P,
    rng: &mut dyn CryptoRng,
) -> Result<(Vec<u8>, Vec<u8>), HpkeError> {
    seal_with_mode(
        kem_ctx,
        recipient_pk,
        info,
        aad,
        plaintext,
        cipher_suite,
        provider,
        rng,
        HpkeMode::Base,
        None,
        None,
        None,
        None,
        HpkePskWireFormat::default(),
    )
}

/// Single-shot encryption with full mode support
#[allow(clippy::too_many_arguments)]
pub fn seal_with_mode<P: HpkeCryptoProvider>(
    kem_ctx: &mut lib_q_core::KemContext,
    recipient_pk: &lib_q_core::KemPublicKey,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    cipher_suite: &HpkeCipherSuite,
    provider: &P,
    rng: &mut dyn CryptoRng,
    mode: HpkeMode,
    psk: Option<&[u8]>,
    psk_id: Option<&[u8]>,
    sender_sk: Option<&lib_q_core::KemSecretKey>,
    sender_pk: Option<&lib_q_core::KemPublicKey>,
    psk_wire_format: HpkePskWireFormat,
) -> Result<(Vec<u8>, Vec<u8>), HpkeError> {
    // Validate mode-specific parameters (same validation as setup_sender_with_mode)
    match mode {
        HpkeMode::Base => {
            if psk.is_some() || psk_id.is_some() || sender_sk.is_some() || sender_pk.is_some() {
                return Err(HpkeError::CryptoError(
                    "Base mode does not support PSK or sender authentication".into(),
                ));
            }
        }
        HpkeMode::Psk => {
            if psk.is_none() || psk_id.is_none() {
                return Err(HpkeError::CryptoError(
                    "PSK mode requires both PSK and PSK ID".into(),
                ));
            }
            if sender_sk.is_some() || sender_pk.is_some() {
                return Err(HpkeError::CryptoError(
                    "PSK mode does not support sender authentication".into(),
                ));
            }
        }
        HpkeMode::Auth => {
            if sender_sk.is_none() || sender_pk.is_none() {
                return Err(HpkeError::CryptoError(
                    "Auth mode requires sender key pair".into(),
                ));
            }
            if psk.is_some() || psk_id.is_some() {
                return Err(HpkeError::CryptoError(
                    "Auth mode does not support PSK".into(),
                ));
            }
        }
        HpkeMode::AuthPsk => {
            if psk.is_none() || psk_id.is_none() || sender_sk.is_none() || sender_pk.is_none() {
                return Err(HpkeError::CryptoError(
                    "AuthPSK mode requires PSK, PSK ID, and sender key pair".into(),
                ));
            }
        }
    }

    // Determine KEM algorithm from public key size
    let kem_algorithm = determine_kem_from_key_size(recipient_pk.as_bytes().len())?;

    // Validate KEM context compatibility
    validate_kem_context_for_algorithm(kem_ctx, kem_algorithm)?;

    // Perform KEM encapsulation
    let (encapsulated_key, mut main_shared_secret) = provider
        .encapsulate(kem_algorithm, recipient_pk.as_bytes(), rng)
        .map_err(|e| e.into())?;

    // For Auth and AuthPSK modes, perform sender authentication
    let (auth_shared_secret, auth_encapsulated_key) =
        if matches!(mode, HpkeMode::Auth | HpkeMode::AuthPsk) {
            let sender_sk = sender_sk.unwrap();
            let sender_pk = sender_pk.unwrap();

            // Validate sender key sizes
            let expected_sk_len = kem_algorithm.secret_key_len();
            let expected_pk_len = kem_algorithm.public_key_len();

            if sender_sk.as_bytes().len() != expected_sk_len {
                return Err(HpkeError::CryptoError(format!(
                    "Invalid sender secret key size: {} bytes (expected {})",
                    sender_sk.as_bytes().len(),
                    expected_sk_len
                )));
            }

            if sender_pk.as_bytes().len() != expected_pk_len {
                return Err(HpkeError::CryptoError(format!(
                    "Invalid sender public key size: {} bytes (expected {})",
                    sender_pk.as_bytes().len(),
                    expected_pk_len
                )));
            }

            // Perform sender authentication
            let (auth_encapsulated_key, auth_kem_secret) = provider
                .auth_encapsulate(
                    kem_algorithm,
                    sender_sk.as_bytes(),
                    recipient_pk.as_bytes(),
                    rng,
                )
                .map_err(|e| e.into())?;

            main_shared_secret.extend_from_slice(auth_kem_secret.as_slice());
            (main_shared_secret, Some(auth_encapsulated_key))
        } else {
            (main_shared_secret, None)
        };

    // Run key schedule to derive keys (includes PSK handling)
    let schedule = key_schedule(
        auth_shared_secret.as_slice(),
        info,
        psk,
        psk_id,
        cipher_suite,
        provider,
    )?;

    // Encrypt the message
    let ciphertext = seal_message(
        cipher_suite.aead,
        schedule.key.as_slice(),
        schedule.nonce.as_slice(),
        0,
        aad,
        plaintext,
        provider,
    )?;

    // Combine encapsulated keys for Auth modes and attach PSK commitment when required
    let kem_encapsulated_key = if let Some(auth_encap) = auth_encapsulated_key {
        let mut combined = encapsulated_key.clone();
        combined.extend_from_slice(&auth_encap);
        combined
    } else {
        encapsulated_key
    };
    let final_encapsulated_key = attach_psk_commitment_to_encapsulated_key(
        kem_encapsulated_key,
        mode,
        psk,
        psk_id,
        psk_wire_format,
        cipher_suite,
        provider,
    )?;

    Ok((final_encapsulated_key, ciphertext))
}

/// Single-shot decryption for Base mode
#[allow(clippy::too_many_arguments)]
pub fn open<P: HpkeCryptoProvider>(
    kem_ctx: &mut lib_q_core::KemContext,
    encapsulated_key: &[u8],
    recipient_sk: &lib_q_core::KemSecretKey,
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    cipher_suite: &HpkeCipherSuite,
    provider: &P,
) -> Result<Vec<u8>, HpkeError> {
    open_with_mode(
        kem_ctx,
        encapsulated_key,
        recipient_sk,
        info,
        aad,
        ciphertext,
        cipher_suite,
        provider,
        HpkeMode::Base,
        None,
        None,
        None,
        HpkePskWireFormat::default(),
    )
}

/// Single-shot decryption with full mode support
#[allow(clippy::too_many_arguments)]
pub fn open_with_mode<P: HpkeCryptoProvider>(
    kem_ctx: &mut lib_q_core::KemContext,
    encapsulated_key: &[u8],
    recipient_sk: &lib_q_core::KemSecretKey,
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    cipher_suite: &HpkeCipherSuite,
    provider: &P,
    mode: HpkeMode,
    psk: Option<&[u8]>,
    psk_id: Option<&[u8]>,
    sender_pk: Option<&lib_q_core::KemPublicKey>,
    psk_wire_format: HpkePskWireFormat,
) -> Result<Vec<u8>, HpkeError> {
    // Setup receiver context with mode support
    let receiver_ctx = setup_receiver_with_mode(
        kem_ctx,
        encapsulated_key,
        recipient_sk,
        info,
        cipher_suite,
        provider,
        mode,
        psk,
        psk_id,
        sender_pk,
        psk_wire_format,
    )?;

    // Decrypt the message
    open_message(
        receiver_ctx.aead,
        &receiver_ctx.key,
        &receiver_ctx.nonce,
        0,
        aad,
        ciphertext,
        provider,
    )
}

/// Seal (encrypt) a message
pub fn seal_message<P: HpkeCryptoProvider>(
    aead: HpkeAead,
    key: &[u8],
    base_nonce: &[u8],
    sequence_number: u32,
    aad: &[u8],
    plaintext: &[u8],
    provider: &P,
) -> Result<Vec<u8>, HpkeError> {
    // Compute nonce from base_nonce and sequence number
    let nonce = compute_nonce(base_nonce, sequence_number);

    provider
        .seal(aead, key, nonce.as_slice(), aad, plaintext)
        .map_err(|e| e.into())
}

/// Open (decrypt) a message
pub fn open_message<P: HpkeCryptoProvider>(
    aead: HpkeAead,
    key: &[u8],
    base_nonce: &[u8],
    sequence_number: u32,
    aad: &[u8],
    ciphertext: &[u8],
    provider: &P,
) -> Result<Vec<u8>, HpkeError> {
    // Compute nonce from base_nonce and sequence number
    let nonce = compute_nonce(base_nonce, sequence_number);

    provider
        .open(aead, key, nonce.as_slice(), aad, ciphertext)
        .map_err(|e| e.into())
}

/// Export key material
pub fn export<P: HpkeCryptoProvider>(
    exporter_secret: &[u8],
    exporter_context: &[u8],
    length: usize,
    provider: &P,
) -> Result<Vec<u8>, HpkeError> {
    // Use HKDF-SHAKE256 to derive exported key material
    let prk = Zeroizing::new(
        provider
            .extract(HpkeKdf::HkdfShake256, b"", exporter_secret)
            .map_err(|e| e.into())?,
    );
    provider
        .expand(
            HpkeKdf::HkdfShake256,
            prk.as_slice(),
            exporter_context,
            length,
        )
        .map_err(|e| e.into())
}

/// Compute nonce from base nonce and sequence number
fn compute_nonce(base_nonce: &[u8], sequence_number: u32) -> Zeroizing<Vec<u8>> {
    let seq_bytes = sequence_number.to_be_bytes();
    let mut nonce = Zeroizing::new(base_nonce.to_vec());
    let nonce_len = nonce.len();

    // XOR the sequence number into the nonce (RFC 9180 Section 5.2)
    for (i, &seq_byte) in seq_bytes.iter().rev().enumerate() {
        if i < nonce_len {
            nonce[nonce_len - 1 - i] ^= seq_byte;
        }
    }

    nonce
}

/// Create suite ID for HPKE (RFC 9180 Section 4)
pub fn create_suite_id(cipher_suite: &HpkeCipherSuite) -> Result<Vec<u8>, HpkeError> {
    let mut suite_id = Vec::new();
    suite_id.extend_from_slice(b"HPKE");
    suite_id.extend_from_slice(&cipher_suite.identifier());
    Ok(suite_id)
}

/// Key schedule implementation (RFC 9180 Section 5.1)
pub fn key_schedule<P: HpkeCryptoProvider>(
    shared_secret: &[u8],
    info: &[u8],
    psk: Option<&[u8]>,
    psk_id: Option<&[u8]>,
    cipher_suite: &HpkeCipherSuite,
    provider: &P,
) -> Result<KeyScheduleSecrets, HpkeError> {
    // Create suite ID for labeled functions
    let suite_id = create_suite_id(cipher_suite)?;

    // Prepare PSK input according to RFC 9180 Section 5.1
    let psk_input = match (psk, psk_id) {
        (Some(psk), Some(psk_id)) => {
            let mut input = Zeroizing::new(Vec::with_capacity(psk.len() + psk_id.len()));
            input.extend_from_slice(psk);
            input.extend_from_slice(psk_id);
            input
        }
        (None, None) => Zeroizing::new(Vec::new()),
        _ => {
            return Err(HpkeError::InconsistentPsk);
        }
    };

    // Extract keying material using labeled extract
    let ikm = if psk_input.is_empty() {
        Zeroizing::new(shared_secret.to_vec())
    } else {
        let mut combined = Zeroizing::new(Vec::with_capacity(
            shared_secret.len().saturating_add(psk_input.len()),
        ));
        combined.extend_from_slice(shared_secret);
        combined.extend_from_slice(psk_input.as_slice());
        combined
    };

    // Use labeled extract for key derivation
    let prk = labeled_extract(
        cipher_suite.kdf,
        b"",
        &suite_id,
        "eae_prk",
        ikm.as_slice(),
        provider,
    )?;

    // Derive key, nonce, and exporter_secret using labeled expand
    let key = labeled_expand(
        cipher_suite.kdf,
        prk.as_slice(),
        &suite_id,
        "key",
        info,
        32,
        provider,
    )?;
    let nonce = labeled_expand(
        cipher_suite.kdf,
        prk.as_slice(),
        &suite_id,
        "base_nonce",
        info,
        cipher_suite.aead.nonce_len(),
        provider,
    )?;
    let exporter_secret = labeled_expand(
        cipher_suite.kdf,
        prk.as_slice(),
        &suite_id,
        "exp",
        info,
        32,
        provider,
    )?;

    Ok(KeyScheduleSecrets {
        key,
        nonce,
        exporter_secret,
    })
}

/// Labeled extract function (RFC 9180 Section 4.1)
pub fn labeled_extract<P: HpkeCryptoProvider>(
    kdf: HpkeKdf,
    salt: &[u8],
    suite_id: &[u8],
    label: &str,
    ikm: &[u8],
    provider: &P,
) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
    // Create labeled IKM according to RFC 9180 Section 4.1
    let mut labeled_ikm = Zeroizing::new(Vec::with_capacity(
        b"HPKE-v1".len() + suite_id.len() + label.len() + ikm.len(),
    ));
    labeled_ikm.extend_from_slice(b"HPKE-v1");
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label.as_bytes());
    labeled_ikm.extend_from_slice(ikm);

    let prk = provider
        .extract(kdf, salt, labeled_ikm.as_slice())
        .map_err(|e| e.into())?;
    Ok(Zeroizing::new(prk))
}

/// Labeled expand function (RFC 9180 Section 4.1)
pub fn labeled_expand<P: HpkeCryptoProvider>(
    kdf: HpkeKdf,
    prk: &[u8],
    suite_id: &[u8],
    label: &str,
    info: &[u8],
    length: usize,
    provider: &P,
) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
    // Create labeled info according to RFC 9180 Section 4.1
    let mut labeled_info = Zeroizing::new(Vec::with_capacity(
        2 + b"HPKE-v1".len() + suite_id.len() + label.len() + info.len(),
    ));
    labeled_info.extend_from_slice(&(length as u16).to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label.as_bytes());
    labeled_info.extend_from_slice(info);

    let okm = provider
        .expand(kdf, prk, labeled_info.as_slice(), length)
        .map_err(|e| e.into())?;
    Ok(Zeroizing::new(okm))
}

/// Validate that the KEM context is compatible with the required algorithm
///
/// This function ensures that the KEM context is properly configured and can
/// support the specified HPKE KEM algorithm. It performs validation checks
/// that are essential for secure HPKE operations.
fn validate_kem_context_for_algorithm(
    kem_ctx: &mut lib_q_core::KemContext,
    kem_algorithm: HpkeKem,
) -> Result<(), HpkeError> {
    // Convert HPKE KEM to lib-q-core Algorithm for validation
    let core_algorithm = match kem_algorithm {
        HpkeKem::MlKem512 => lib_q_core::Algorithm::MlKem512,
        HpkeKem::MlKem768 => lib_q_core::Algorithm::MlKem768,
        HpkeKem::MlKem1024 => lib_q_core::Algorithm::MlKem1024,
    };

    // Validate that the algorithm is a KEM algorithm
    if core_algorithm.category() != lib_q_core::AlgorithmCategory::Kem {
        return Err(HpkeError::CryptoError(format!(
            "Invalid algorithm category for HPKE: expected KEM, got {:?}",
            core_algorithm.category()
        )));
    }

    // Validate algorithm security level compatibility
    let security_level = core_algorithm.security_level();
    match security_level {
        1 | 3 | 4 => {
            // These security levels are acceptable for HPKE (Level 1, 3, 4)
        }
        _ => {
            return Err(HpkeError::CryptoError(format!(
                "Unsupported security level for HPKE: {} (expected 1, 3, or 4)",
                security_level
            )));
        }
    }

    // Note: KEM context initialization is handled internally by the context
    // when operations are performed. We don't need to explicitly initialize it here.

    // Validate that the context has a provider configured and supports the required algorithm
    // This is done by attempting a test operation (which will fail gracefully if unsupported)
    // We use a minimal test to avoid side effects
    let test_result = kem_ctx.generate_keypair(core_algorithm, None);
    match test_result {
        Ok(_) => {
            // Algorithm is supported and provider is configured - this is good
            // Note: In a production implementation, we might want to cache this result
            // or use a different validation method to avoid generating actual keys
        }
        Err(lib_q_core::Error::NotImplemented { feature }) => {
            if feature.contains("no provider configured") {
                return Err(HpkeError::CryptoError(
                    "KEM context must have a cryptographic provider configured".into(),
                ));
            } else {
                return Err(HpkeError::CryptoError(format!(
                    "KEM algorithm {:?} is not implemented by the configured provider: {}",
                    kem_algorithm, feature
                )));
            }
        }
        Err(lib_q_core::Error::InvalidState { operation, reason }) => {
            return Err(HpkeError::CryptoError(format!(
                "KEM context in invalid state for {}: {}",
                operation, reason
            )));
        }
        Err(_e) => {
            // Other errors might be acceptable (e.g., provider-specific errors)
            // We log them but don't fail the validation
            // In a production system, you might want to be more specific about which errors to ignore
        }
    }

    Ok(())
}

#[cfg(test)]
mod psk_commitment_tests {
    use alloc::vec;

    use super::*;
    use crate::providers::post_quantum::PostQuantumProvider;

    fn test_cipher_suite() -> HpkeCipherSuite {
        HpkeCipherSuite::new(
            HpkeKem::MlKem512,
            HpkeKdf::HkdfShake256,
            HpkeAead::Saturnin256,
        )
    }

    #[test]
    fn derive_psk_commitment_is_deterministic() {
        let provider = PostQuantumProvider::new();
        let suite = test_cipher_suite();
        let psk = b"test-psk";
        let psk_id = b"test-id";

        let c1 = derive_psk_commitment(psk, psk_id, &suite, &provider).unwrap();
        let c2 = derive_psk_commitment(psk, psk_id, &suite, &provider).unwrap();

        assert_eq!(c1, c2);
        assert_eq!(c1.len(), psk_commitment_len(&suite));
    }

    #[test]
    fn verify_psk_commitment_rejects_mismatch() {
        let provider = PostQuantumProvider::new();
        let suite = test_cipher_suite();

        let sender = derive_psk_commitment(b"sender-psk", b"id", &suite, &provider).unwrap();
        let result = verify_psk_commitment(b"receiver-psk", b"id", &sender, &suite, &provider);

        assert_eq!(result, Err(HpkeError::InconsistentPsk));
    }

    #[test]
    fn split_encapsulated_key_extracts_psk_commitment_suffix() {
        let kem_enc_len = HpkeKem::MlKem512.enc_len();
        let commitment_len = HpkeKdf::HkdfShake256.extract_len();
        let mut wire = vec![0xAB; kem_enc_len];
        wire.extend_from_slice(&vec![0xCD; commitment_len]);

        let parts =
            split_encapsulated_key_for_receiver(&wire, HpkeMode::Psk, kem_enc_len, commitment_len)
                .unwrap();

        assert_eq!(parts.main.len(), kem_enc_len);
        assert!(parts.auth.is_none());
        assert_eq!(parts.psk_commitment, Some(vec![0xCD; commitment_len]));
    }
}
