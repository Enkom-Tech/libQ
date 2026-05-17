//! Interoperability profiles and deterministic suite negotiation (post-quantum HPKE only).
//!
//! This module does **not** implement a transport protocol. Peers must authenticate any
//! negotiation transcript inside their application or handshake protocol.

use alloc::vec::Vec;

use crate::types::{
    HpkeAead,
    HpkeCipherSuite,
    HpkeMode,
    HpkePskWireFormat,
};

/// Documented interoperability profile for HPKE on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeInteropProfile {
    /// RFC 9180 schedule and default PSK wire ([`HpkePskWireFormat::Rfc9180`]); no libQ-only wire extensions.
    RfcStrictPq,
    /// libQ extensions such as [`HpkePskWireFormat::LibQCommitmentSuffix`] and non-IANA `algorithm_id` values.
    LibQExtensions,
}

/// Crate version string tied to interoperability documentation (see workspace `docs/hpke-architecture.md`).
pub const LIBQ_HPKE_INTEROP_PROFILE_DOC: &str = env!("CARGO_PKG_VERSION");

/// Local or remote capability advertisement: ordered preferences and supported modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HpkeCapabilities {
    /// Interop profile this advertisement belongs to.
    pub profile: HpkeInteropProfile,
    /// Preferred cipher suites (first element is most preferred).
    pub suite_preferences: Vec<HpkeCipherSuite>,
    /// HPKE modes this party may use for the negotiated suite.
    pub supported_modes: Vec<HpkeMode>,
    /// Preferred PSK wire encodings for PSK / AuthPSK (first is most preferred).
    pub psk_wire_preferences: Vec<HpkePskWireFormat>,
}

/// Result of [`negotiate_hpke_capabilities`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiatedHpkeParams {
    /// Selected cipher suite.
    pub suite: HpkeCipherSuite,
    /// Selected HPKE mode.
    pub mode: HpkeMode,
    /// Selected PSK wire format (meaningful for PSK / AuthPSK; for Base / Auth use [`HpkePskWireFormat::Rfc9180`]).
    pub psk_wire_format: HpkePskWireFormat,
}

/// Failure to find a deterministic common choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HpkeNegotiationError {
    /// Peers advertised different [`HpkeInteropProfile`] values.
    IncompatibleProfiles {
        /// Local profile.
        local: HpkeInteropProfile,
        /// Remote profile.
        remote: HpkeInteropProfile,
    },
    /// No cipher suite appeared in both advertisements with identical KEM/KDF/AEAD tuple.
    NoCommonSuite,
    /// No [`HpkeMode`] appeared in both advertisements.
    NoCommonMode,
    /// No [`HpkePskWireFormat`] appeared in both advertisements (only checked when needed for PSK modes).
    NoCommonPskWireFormat,
    /// Local build cannot satisfy a suite the local party listed (for example missing `duplex-sponge-aead`).
    LocalSuiteNotBuildable(HpkeCipherSuite),
}

impl core::fmt::Display for HpkeNegotiationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::IncompatibleProfiles { local, remote } => write!(
                f,
                "incompatible HPKE interop profiles: local {:?}, remote {:?}",
                local, remote
            ),
            Self::NoCommonSuite => write!(f, "no common HPKE cipher suite"),
            Self::NoCommonMode => write!(f, "no common HPKE mode"),
            Self::NoCommonPskWireFormat => write!(f, "no common PSK wire format"),
            Self::LocalSuiteNotBuildable(s) => write!(
                f,
                "local HPKE build cannot satisfy advertised suite {:?}/{:?}/{:?}",
                s.kem, s.kdf, s.aead
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HpkeNegotiationError {}

/// Returns `false` when this crate was compiled without the feature required for `suite` (for example duplex AEAD).
pub fn cipher_suite_supported_by_build(suite: &HpkeCipherSuite) -> bool {
    if matches!(suite.aead, HpkeAead::DuplexSpongeAead) {
        #[cfg(feature = "duplex-sponge-aead")]
        {
            return true;
        }
        #[cfg(not(feature = "duplex-sponge-aead"))]
        {
            return false;
        }
    }
    true
}

fn remote_has_suite(remote: &HpkeCapabilities, suite: &HpkeCipherSuite) -> bool {
    remote
        .suite_preferences
        .iter()
        .any(|s| s.kem == suite.kem && s.kdf == suite.kdf && s.aead == suite.aead)
}

fn first_common_mode(local: &HpkeCapabilities, remote: &HpkeCapabilities) -> Option<HpkeMode> {
    for m in &local.supported_modes {
        if remote.supported_modes.contains(m) {
            return Some(*m);
        }
    }
    None
}

fn first_common_psk_wire(
    local: &HpkeCapabilities,
    remote: &HpkeCapabilities,
    profile: HpkeInteropProfile,
) -> Option<HpkePskWireFormat> {
    for w in &local.psk_wire_preferences {
        if !remote.psk_wire_preferences.contains(w) {
            continue;
        }
        if profile == HpkeInteropProfile::RfcStrictPq &&
            *w == HpkePskWireFormat::LibQCommitmentSuffix
        {
            continue;
        }
        return Some(*w);
    }
    None
}

fn psk_wire_needed(mode: HpkeMode) -> bool {
    matches!(mode, HpkeMode::Psk | HpkeMode::AuthPsk)
}

/// Deterministic intersection of two [`HpkeCapabilities`]: local suite order wins; then local mode order;
/// then local PSK wire preference order.
///
/// Both sides must run the same algorithm on the same ordered inputs, or agree out-of-band to swap
/// `local`/`remote` roles consistently.
pub fn negotiate_hpke_capabilities(
    local: &HpkeCapabilities,
    remote: &HpkeCapabilities,
) -> Result<NegotiatedHpkeParams, HpkeNegotiationError> {
    if local.profile != remote.profile {
        return Err(HpkeNegotiationError::IncompatibleProfiles {
            local: local.profile,
            remote: remote.profile,
        });
    }

    let profile = local.profile;

    let mut chosen_suite = None;
    for s in &local.suite_preferences {
        if !cipher_suite_supported_by_build(s) {
            return Err(HpkeNegotiationError::LocalSuiteNotBuildable(*s));
        }
        if remote_has_suite(remote, s) {
            chosen_suite = Some(*s);
            break;
        }
    }

    let suite = chosen_suite.ok_or(HpkeNegotiationError::NoCommonSuite)?;

    let mode = first_common_mode(local, remote).ok_or(HpkeNegotiationError::NoCommonMode)?;

    let psk_wire_format = if psk_wire_needed(mode) {
        first_common_psk_wire(local, remote, profile)
            .ok_or(HpkeNegotiationError::NoCommonPskWireFormat)?
    } else {
        HpkePskWireFormat::Rfc9180
    };

    Ok(NegotiatedHpkeParams {
        suite,
        mode,
        psk_wire_format,
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::types::{
        HpkeKdf,
        HpkeKem,
    };

    fn default_suite() -> HpkeCipherSuite {
        HpkeCipherSuite::new(
            HpkeKem::MlKem512,
            HpkeKdf::HkdfShake256,
            HpkeAead::Saturnin256,
        )
    }

    #[test]
    fn negotiate_roundtrip_equal_capabilities() {
        let cap = HpkeCapabilities {
            profile: HpkeInteropProfile::RfcStrictPq,
            suite_preferences: vec![default_suite()],
            supported_modes: vec![HpkeMode::Base],
            psk_wire_preferences: vec![HpkePskWireFormat::Rfc9180],
        };
        let out = negotiate_hpke_capabilities(&cap, &cap).unwrap();
        assert_eq!(out.suite, default_suite());
        assert_eq!(out.mode, HpkeMode::Base);
        assert_eq!(out.psk_wire_format, HpkePskWireFormat::Rfc9180);
    }

    #[test]
    fn strict_profile_rejects_commitment_suffix_in_preferences() {
        let a = HpkeCapabilities {
            profile: HpkeInteropProfile::RfcStrictPq,
            suite_preferences: vec![default_suite()],
            supported_modes: vec![HpkeMode::Psk],
            psk_wire_preferences: vec![HpkePskWireFormat::LibQCommitmentSuffix],
        };
        let b = HpkeCapabilities {
            profile: HpkeInteropProfile::RfcStrictPq,
            suite_preferences: vec![default_suite()],
            supported_modes: vec![HpkeMode::Psk],
            psk_wire_preferences: vec![
                HpkePskWireFormat::LibQCommitmentSuffix,
                HpkePskWireFormat::Rfc9180,
            ],
        };
        let err = negotiate_hpke_capabilities(&a, &b).unwrap_err();
        assert_eq!(err, HpkeNegotiationError::NoCommonPskWireFormat);
    }
}
