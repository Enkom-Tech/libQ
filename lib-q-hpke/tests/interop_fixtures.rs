//! Frozen JSON fixtures for HPKE interoperability (negotiation and provider wiring).

#![cfg(feature = "std")]

use std::sync::Arc;

use lib_q_hpke::HpkeContext;
use lib_q_hpke::interop::{
    HpkeCapabilities,
    HpkeInteropProfile,
    negotiate_hpke_capabilities,
};
use lib_q_hpke::providers::post_quantum::PostQuantumProvider;
use lib_q_hpke::providers::traits::HpkeCryptoProvider;
use lib_q_hpke::types::{
    HpkeAead,
    HpkeCipherSuite,
    HpkeKdf,
    HpkeKem,
    HpkeMode,
    HpkePskWireFormat,
};
use serde::Deserialize;

const RFC_STRICT_FIXTURE: &str = include_str!("fixtures/negotiated_params_rfc_strict_pq_base.json");

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
enum ProfileWire {
    RfcStrictPq,
    LibQExtensions,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
enum KemWire {
    MlKem512,
    MlKem768,
    MlKem1024,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
enum KdfWire {
    HkdfShake128,
    HkdfShake256,
    HkdfSha3_256,
    HkdfSha3_512,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
enum AeadWire {
    Saturnin256,
    Shake256,
    Export,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
enum ModeWire {
    Base,
    Psk,
    Auth,
    AuthPsk,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
enum PskWireWire {
    Rfc9180,
    LibQCommitmentSuffix,
}

#[derive(Debug, Deserialize)]
struct SuiteWire {
    kem: KemWire,
    kdf: KdfWire,
    aead: AeadWire,
}

#[derive(Debug, Deserialize)]
struct CapWire {
    suite_preferences: Vec<SuiteWire>,
    supported_modes: Vec<ModeWire>,
    psk_wire_preferences: Vec<PskWireWire>,
}

#[derive(Debug, Deserialize)]
struct ExpectedWire {
    kem: KemWire,
    kdf: KdfWire,
    aead: AeadWire,
    mode: ModeWire,
    psk_wire: PskWireWire,
}

#[derive(Debug, Deserialize)]
struct FixtureFile {
    profile: ProfileWire,
    local: CapWire,
    remote: CapWire,
    expected: ExpectedWire,
}

fn profile_from_wire(p: ProfileWire) -> HpkeInteropProfile {
    match p {
        ProfileWire::RfcStrictPq => HpkeInteropProfile::RfcStrictPq,
        ProfileWire::LibQExtensions => HpkeInteropProfile::LibQExtensions,
    }
}

fn kem_from_wire(k: KemWire) -> HpkeKem {
    match k {
        KemWire::MlKem512 => HpkeKem::MlKem512,
        KemWire::MlKem768 => HpkeKem::MlKem768,
        KemWire::MlKem1024 => HpkeKem::MlKem1024,
    }
}

fn kdf_from_wire(k: KdfWire) -> HpkeKdf {
    match k {
        KdfWire::HkdfShake128 => HpkeKdf::HkdfShake128,
        KdfWire::HkdfShake256 => HpkeKdf::HkdfShake256,
        KdfWire::HkdfSha3_256 => HpkeKdf::HkdfSha3_256,
        KdfWire::HkdfSha3_512 => HpkeKdf::HkdfSha3_512,
    }
}

fn aead_from_wire(a: AeadWire) -> HpkeAead {
    match a {
        AeadWire::Saturnin256 => HpkeAead::Saturnin256,
        AeadWire::Shake256 => HpkeAead::Shake256,
        AeadWire::Export => HpkeAead::Export,
    }
}

fn mode_from_wire(m: ModeWire) -> HpkeMode {
    match m {
        ModeWire::Base => HpkeMode::Base,
        ModeWire::Psk => HpkeMode::Psk,
        ModeWire::Auth => HpkeMode::Auth,
        ModeWire::AuthPsk => HpkeMode::AuthPsk,
    }
}

fn psk_wire_from_wire(w: PskWireWire) -> HpkePskWireFormat {
    match w {
        PskWireWire::Rfc9180 => HpkePskWireFormat::Rfc9180,
        PskWireWire::LibQCommitmentSuffix => HpkePskWireFormat::LibQCommitmentSuffix,
    }
}

fn cap_from_wire(profile: HpkeInteropProfile, c: CapWire) -> HpkeCapabilities {
    HpkeCapabilities {
        profile,
        suite_preferences: c
            .suite_preferences
            .into_iter()
            .map(|s| {
                HpkeCipherSuite::new(
                    kem_from_wire(s.kem),
                    kdf_from_wire(s.kdf),
                    aead_from_wire(s.aead),
                )
            })
            .collect(),
        supported_modes: c.supported_modes.into_iter().map(mode_from_wire).collect(),
        psk_wire_preferences: c
            .psk_wire_preferences
            .into_iter()
            .map(psk_wire_from_wire)
            .collect(),
    }
}

#[test]
fn fixture_rfc_strict_pq_negotiation_matches_expected() {
    let f: FixtureFile = serde_json::from_str(RFC_STRICT_FIXTURE).expect("fixture JSON");
    let profile = profile_from_wire(f.profile);
    let local = cap_from_wire(profile, f.local);
    let remote = cap_from_wire(profile, f.remote);
    let out = negotiate_hpke_capabilities(&local, &remote).expect("negotiate");

    assert_eq!(
        out.suite,
        HpkeCipherSuite::new(
            kem_from_wire(f.expected.kem),
            kdf_from_wire(f.expected.kdf),
            aead_from_wire(f.expected.aead),
        )
    );
    assert_eq!(out.mode, mode_from_wire(f.expected.mode));
    assert_eq!(out.psk_wire_format, psk_wire_from_wire(f.expected.psk_wire));
}

#[test]
fn two_independent_post_quantum_providers_support_same_default_suite() {
    let a: Arc<dyn HpkeCryptoProvider + Send + Sync> = Arc::new(PostQuantumProvider::new());
    let b: Arc<dyn HpkeCryptoProvider + Send + Sync> = Arc::new(PostQuantumProvider::new());
    let suite = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );
    assert!(a.supported_algorithms().supports_cipher_suite(&suite));
    assert!(b.supported_algorithms().supports_cipher_suite(&suite));

    let mut ca = HpkeContext::with_hpke_crypto(a.clone());
    let mut cb = HpkeContext::with_hpke_crypto(b.clone());
    ca.set_cipher_suite(suite);
    cb.set_cipher_suite(suite);
}
