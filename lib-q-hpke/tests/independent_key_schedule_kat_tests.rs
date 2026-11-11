//! Independent-implementation KAT for the RFC 9180 key-schedule stage.
//!
//! Unlike `tests/rfc9180_key_schedule_structure_tests.rs` (which computes its "expected" values
//! by calling lib-q-hpke's own `labeled_extract`/`labeled_expand` — self-consistency, not an
//! independent check), this file loads byte vectors computed by a SEPARATE implementation
//! (`tests/fixtures/independent_key_schedule_kat/generate_vectors.py`, using CPython's `hashlib`
//! SHA3-256/512 and SHAKE128/256, not `lib-q-sha3`/`lib-q-keccak`) and asserts
//! `lib_q_hpke::hpke_core`'s `key_schedule`/`labeled_extract`/`labeled_expand` reproduce them
//! byte-for-byte.
//!
//! A change to a label string, the `"HPKE-v1"` version prefix, the `suite_id` layout, the
//! `key_schedule_context` field order, or the underlying SHA3/SHAKE computation breaks this test,
//! because the expected bytes were not derived from the code under test.
//!
//! See `tests/fixtures/independent_key_schedule_kat/PROVENANCE.md` for exactly what is and is not
//! claimed (in particular: this is not an RFC 9180 Appendix A vector — no such vector exists for
//! any KEM/KDF pair lib-q-hpke implements — and it deliberately mirrors lib-q-hpke's own
//! non-RFC-5869 "HKDF" construction rather than real HMAC-based HKDF).

#![cfg(feature = "std")]

use lib_q_hpke::providers::post_quantum::PostQuantumProvider;
use lib_q_hpke::{HpkeAead, HpkeCipherSuite, HpkeKdf, HpkeKem, HpkeMode, hpke_core};
use serde::Deserialize;

const VECTORS_JSON: &str = include_str!("fixtures/independent_key_schedule_kat/vectors.json");

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex string: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

#[derive(Debug, Deserialize)]
struct ExpectedWire {
    suite_id: String,
    psk_id_hash: String,
    info_hash: String,
    key_schedule_context: String,
    secret: String,
    key: String,
    base_nonce: String,
    exporter_secret: String,
}

#[derive(Debug, Deserialize)]
struct CaseWire {
    name: String,
    mode: String,
    kem: String,
    kdf: String,
    aead: String,
    shared_secret: String,
    info: String,
    psk: String,
    psk_id: String,
    expected: ExpectedWire,
}

#[derive(Debug, Deserialize)]
struct VectorsFile {
    cases: Vec<CaseWire>,
}

fn mode_from_wire(m: &str) -> HpkeMode {
    match m {
        "Base" => HpkeMode::Base,
        "Psk" => HpkeMode::Psk,
        other => panic!("unknown mode in fixture: {other}"),
    }
}

fn kem_from_wire(k: &str) -> HpkeKem {
    match k {
        "MlKem512" => HpkeKem::MlKem512,
        "MlKem768" => HpkeKem::MlKem768,
        "MlKem1024" => HpkeKem::MlKem1024,
        other => panic!("unknown kem in fixture: {other}"),
    }
}

fn kdf_from_wire(k: &str) -> HpkeKdf {
    match k {
        "HkdfShake128" => HpkeKdf::HkdfShake128,
        "HkdfShake256" => HpkeKdf::HkdfShake256,
        "HkdfSha3_256" => HpkeKdf::HkdfSha3_256,
        "HkdfSha3_512" => HpkeKdf::HkdfSha3_512,
        other => panic!("unknown kdf in fixture: {other}"),
    }
}

fn aead_from_wire(a: &str) -> HpkeAead {
    match a {
        "Saturnin256" => HpkeAead::Saturnin256,
        "Shake256" => HpkeAead::Shake256,
        "DuplexSpongeAead" => HpkeAead::DuplexSpongeAead,
        other => panic!("unknown aead in fixture: {other}"),
    }
}

/// Every case in `vectors.json` matches lib-q-hpke's own `key_schedule`, `create_suite_id`,
/// `labeled_extract`, and `labeled_expand` byte-for-byte against an independently computed
/// expectation.
#[test]
fn independent_vectors_match_hpke_core() {
    let file: VectorsFile = serde_json::from_str(VECTORS_JSON).expect("parse vectors.json");
    assert_eq!(
        file.cases.len(),
        7,
        "expected 7 frozen cases (see generate_vectors.py::main)"
    );

    let provider = PostQuantumProvider::new();

    for case in &file.cases {
        let mode = mode_from_wire(&case.mode);
        let cipher_suite = HpkeCipherSuite::new(
            kem_from_wire(&case.kem),
            kdf_from_wire(&case.kdf),
            aead_from_wire(&case.aead),
        );
        let shared_secret = decode_hex(&case.shared_secret);
        let info = decode_hex(&case.info);
        let psk = decode_hex(&case.psk);
        let psk_id = decode_hex(&case.psk_id);

        let suite_id = hpke_core::create_suite_id(&cipher_suite)
            .unwrap_or_else(|e| panic!("[{}] create_suite_id: {e}", case.name));
        assert_eq!(
            hex::encode(&suite_id),
            case.expected.suite_id,
            "[{}] suite_id mismatch",
            case.name
        );

        let psk_id_hash = hpke_core::labeled_extract(
            cipher_suite.kdf,
            b"",
            &suite_id,
            "psk_id_hash",
            &psk_id,
            &provider,
        )
        .unwrap_or_else(|e| panic!("[{}] psk_id_hash: {e}", case.name));
        assert_eq!(
            hex::encode(psk_id_hash.as_slice()),
            case.expected.psk_id_hash,
            "[{}] psk_id_hash mismatch",
            case.name
        );

        let info_hash = hpke_core::labeled_extract(
            cipher_suite.kdf,
            b"",
            &suite_id,
            "info_hash",
            &info,
            &provider,
        )
        .unwrap_or_else(|e| panic!("[{}] info_hash: {e}", case.name));
        assert_eq!(
            hex::encode(info_hash.as_slice()),
            case.expected.info_hash,
            "[{}] info_hash mismatch",
            case.name
        );

        let mut context = Vec::new();
        context.push(mode.as_u8());
        context.extend_from_slice(&psk_id_hash);
        context.extend_from_slice(&info_hash);
        assert_eq!(
            hex::encode(&context),
            case.expected.key_schedule_context,
            "[{}] key_schedule_context mismatch",
            case.name
        );

        let psk_opt = if psk.is_empty() {
            None
        } else {
            Some(psk.as_slice())
        };
        let psk_id_opt = if psk_id.is_empty() {
            None
        } else {
            Some(psk_id.as_slice())
        };

        let secret = hpke_core::labeled_extract(
            cipher_suite.kdf,
            &shared_secret,
            &suite_id,
            "secret",
            psk_opt.unwrap_or(b""),
            &provider,
        )
        .unwrap_or_else(|e| panic!("[{}] secret: {e}", case.name));
        assert_eq!(
            hex::encode(secret.as_slice()),
            case.expected.secret,
            "[{}] secret mismatch",
            case.name
        );

        let schedule = hpke_core::key_schedule(
            mode,
            &shared_secret,
            &info,
            psk_opt,
            psk_id_opt,
            &cipher_suite,
            &provider,
        )
        .unwrap_or_else(|e| panic!("[{}] key_schedule: {e}", case.name));

        assert_eq!(
            hex::encode(schedule.key.as_slice()),
            case.expected.key,
            "[{}] key mismatch",
            case.name
        );
        assert_eq!(
            hex::encode(schedule.nonce.as_slice()),
            case.expected.base_nonce,
            "[{}] base_nonce mismatch",
            case.name
        );
        assert_eq!(
            hex::encode(schedule.exporter_secret.as_slice()),
            case.expected.exporter_secret,
            "[{}] exporter_secret mismatch",
            case.name
        );
    }
}

/// Sanity: the fixture actually distinguishes cases (guards against a degenerate generator that
/// emitted the same bytes for every KDF/mode/KEM combination, which would make the equality
/// assertions above vacuous).
#[test]
fn independent_vectors_are_pairwise_distinct_keys() {
    let file: VectorsFile = serde_json::from_str(VECTORS_JSON).expect("parse vectors.json");
    let keys: Vec<&str> = file.cases.iter().map(|c| c.expected.key.as_str()).collect();
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(
                keys[i], keys[j],
                "cases {} and {} produced identical \"key\" output",
                file.cases[i].name, file.cases[j].name
            );
        }
    }
}
