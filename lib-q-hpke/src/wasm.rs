//! JavaScript exports for HPKE (RFC 9180) using lib-Q post-quantum suites.

#![allow(missing_docs)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem;

use lib_q_core::{
    KemPublicKey,
    KemSecretKey,
};
use lib_q_kem::LibQKemProvider;
use serde::Serialize;
use spin::Mutex;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::providers::post_quantum::PostQuantumProvider;
use crate::providers::traits::HpkeCryptoProvider;
use crate::{
    HpkeAead,
    HpkeCipherSuite,
    HpkeContext,
    HpkeContextState,
    HpkeKdf,
    HpkeKem,
    HpkeReceiverContext,
    HpkeSenderContext,
};

fn js_err(e: impl core::fmt::Display) -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_HPKE", e)
}

fn norm(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn parse_kem(s: &str) -> Result<HpkeKem, JsValue> {
    match norm(s).as_str() {
        "mlkem512" => Ok(HpkeKem::MlKem512),
        "mlkem768" => Ok(HpkeKem::MlKem768),
        "mlkem1024" => Ok(HpkeKem::MlKem1024),
        _ => Err(js_err(format!("unknown HPKE KEM: {s}"))),
    }
}

fn parse_kdf(s: &str) -> Result<HpkeKdf, JsValue> {
    match norm(s).as_str() {
        "hkdfshake128" => Ok(HpkeKdf::HkdfShake128),
        "hkdfshake256" => Ok(HpkeKdf::HkdfShake256),
        "hkdfsha3256" => Ok(HpkeKdf::HkdfSha3_256),
        "hkdfsha3512" => Ok(HpkeKdf::HkdfSha3_512),
        _ => Err(js_err(format!("unknown HPKE KDF: {s}"))),
    }
}

fn parse_aead(s: &str) -> Result<HpkeAead, JsValue> {
    match norm(s).as_str() {
        "saturnin256" => Ok(HpkeAead::Saturnin256),
        "shake256" => Ok(HpkeAead::Shake256),
        #[cfg(feature = "duplex-sponge-aead")]
        "duplexspongeaead" => Ok(HpkeAead::DuplexSpongeAead),
        "export" => Ok(HpkeAead::Export),
        #[cfg(not(feature = "duplex-sponge-aead"))]
        "duplexspongeaead" => Err(js_err(
            "Duplex-sponge AEAD requires lib-q-hpke `duplex-sponge-aead` feature",
        )),
        _ => Err(js_err(format!("unknown HPKE AEAD: {s}"))),
    }
}

fn parse_suite(kem: &str, kdf: &str, aead: &str) -> Result<HpkeCipherSuite, JsValue> {
    Ok(HpkeCipherSuite::new(
        parse_kem(kem)?,
        parse_kdf(kdf)?,
        parse_aead(aead)?,
    ))
}

fn kem_to_str(k: HpkeKem) -> &'static str {
    match k {
        HpkeKem::MlKem512 => "mlkem512",
        HpkeKem::MlKem768 => "mlkem768",
        HpkeKem::MlKem1024 => "mlkem1024",
    }
}

fn kdf_to_str(d: HpkeKdf) -> &'static str {
    match d {
        HpkeKdf::HkdfShake128 => "hkdfshake128",
        HpkeKdf::HkdfShake256 => "hkdfshake256",
        HpkeKdf::HkdfSha3_256 => "hkdfsha3256",
        HpkeKdf::HkdfSha3_512 => "hkdfsha3512",
    }
}

fn hpke_ctx() -> Result<HpkeContext, JsValue> {
    let p = LibQKemProvider::new().map_err(js_err)?;
    Ok(HpkeContext::with_provider(Box::new(p)))
}

fn kem_pk_from_hex(hex_pk: &str, kem: HpkeKem) -> Result<KemPublicKey, JsValue> {
    let v = hex::decode(hex_pk.trim()).map_err(js_err)?;
    let expected = kem.public_key_len();
    if v.len() != expected {
        return Err(js_err(format!(
            "public key length {} does not match KEM (expected {})",
            v.len(),
            expected
        )));
    }
    Ok(KemPublicKey::new(v))
}

fn kem_sk_from_hex(hex_sk: &str, kem: HpkeKem) -> Result<KemSecretKey, JsValue> {
    let mut z = Zeroizing::new(hex::decode(hex_sk.trim()).map_err(js_err)?);
    let expected = kem.secret_key_len();
    if z.len() != expected {
        return Err(js_err(format!(
            "secret key length {} does not match KEM (expected {})",
            z.len(),
            expected
        )));
    }
    Ok(KemSecretKey::new(mem::take(&mut *z)))
}

/// Single-shot HPKE seal: returns `{ encapsulatedKeyHex, ciphertextHex }`.
#[wasm_bindgen(js_name = hpkeSeal)]
pub fn hpke_seal(
    kem: &str,
    kdf: &str,
    aead: &str,
    recipient_public_key_hex: &str,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<JsValue, JsValue> {
    let suite = parse_suite(kem, kdf, aead)?;
    let pk = kem_pk_from_hex(recipient_public_key_hex, suite.kem)?;
    let mut ctx = hpke_ctx()?;
    ctx.set_cipher_suite(suite);
    let (enc, ct) = ctx
        .seal(&pk, info, aad, plaintext)
        .map_err(|e: lib_q_core::Error| js_err(e))?;
    let out = serde_json::json!({
        "encapsulatedKeyHex": hex::encode(&enc),
        "ciphertextHex": hex::encode(&ct),
    });
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

/// Single-shot HPKE open: `ciphertext_hex` is AEAD output from [`hpke_seal`].
#[wasm_bindgen(js_name = hpkeOpen)]
#[allow(clippy::too_many_arguments)] // wasm-bindgen mirrors RFC 9180 single-shot API parameters
pub fn hpke_open(
    kem: &str,
    kdf: &str,
    aead: &str,
    encapsulated_key_hex: &str,
    recipient_secret_key_hex: &str,
    info: &[u8],
    aad: &[u8],
    ciphertext_hex: &str,
) -> Result<Vec<u8>, JsValue> {
    let suite = parse_suite(kem, kdf, aead)?;
    let enc = hex::decode(encapsulated_key_hex.trim()).map_err(js_err)?;
    let sk = kem_sk_from_hex(recipient_secret_key_hex, suite.kem)?;
    let ct = hex::decode(ciphertext_hex.trim()).map_err(js_err)?;
    let mut ctx = hpke_ctx()?;
    ctx.set_cipher_suite(suite);
    ctx.open(&enc, &sk, info, aad, &ct)
        .map_err(|e: lib_q_core::Error| js_err(e))
}

fn state_to_str(s: HpkeContextState) -> &'static str {
    match s {
        HpkeContextState::Active => "active",
        HpkeContextState::NeedsRekey => "needs_rekey",
        HpkeContextState::Closed => "closed",
    }
}

fn state_from_str(s: &str) -> Result<HpkeContextState, JsValue> {
    match norm(s).as_str() {
        "active" => Ok(HpkeContextState::Active),
        "needsrekey" => Ok(HpkeContextState::NeedsRekey),
        "closed" => Ok(HpkeContextState::Closed),
        _ => Err(js_err(format!("invalid HPKE context state: {s}"))),
    }
}

fn aead_to_str(a: HpkeAead) -> &'static str {
    match a {
        HpkeAead::Saturnin256 => "saturnin256",
        HpkeAead::Shake256 => "shake256",
        HpkeAead::DuplexSpongeAead => "duplex_sponge_aead",
        HpkeAead::Export => "export",
    }
}

#[derive(Serialize)]
struct SetupSenderOut {
    encapsulated_key_hex: String,
    sender: SenderWire,
}

#[derive(Serialize)]
struct SenderWire {
    encapsulated_key_hex: String,
    shared_secret_hex: String,
    exporter_secret_hex: String,
    key_hex: String,
    nonce_hex: String,
    kem: &'static str,
    kdf: &'static str,
    aead: &'static str,
    sequence_number: u32,
    max_sequence_number: u32,
    state: &'static str,
}

fn sender_to_wire(s: &HpkeSenderContext) -> SenderWire {
    SenderWire {
        encapsulated_key_hex: hex::encode(&s.encapsulated_key),
        shared_secret_hex: hex::encode(s.shared_secret.as_slice()),
        exporter_secret_hex: hex::encode(s.exporter_secret.as_slice()),
        key_hex: hex::encode(s.key.as_slice()),
        nonce_hex: hex::encode(s.nonce.as_slice()),
        kem: kem_to_str(s.cipher_suite.kem),
        kdf: kdf_to_str(s.cipher_suite.kdf),
        aead: aead_to_str(s.aead),
        sequence_number: s.sequence_number,
        max_sequence_number: s.max_sequence_number,
        state: state_to_str(s.state),
    }
}

fn sender_from_wire(w: &serde_json::Value) -> Result<HpkeSenderContext, JsValue> {
    let hex_secret = |k: &str| -> Result<Zeroizing<Vec<u8>>, JsValue> {
        let s = w
            .get(k)
            .and_then(|v| v.as_str())
            .ok_or_else(|| js_err(format!("sender wire missing string field {k}")))?;
        Ok(Zeroizing::new(hex::decode(s.trim()).map_err(js_err)?))
    };
    let hex_encap = |k: &str| -> Result<Vec<u8>, JsValue> {
        let s = w
            .get(k)
            .and_then(|v| v.as_str())
            .ok_or_else(|| js_err(format!("sender wire missing string field {k}")))?;
        hex::decode(s.trim()).map_err(js_err)
    };
    let kem_s = w
        .get("kem")
        .and_then(|v| v.as_str())
        .ok_or_else(|| js_err("sender wire missing kem"))?;
    let kdf_s = w
        .get("kdf")
        .and_then(|v| v.as_str())
        .ok_or_else(|| js_err("sender wire missing kdf"))?;
    let kem = parse_kem(kem_s)?;
    let kdf = parse_kdf(kdf_s)?;
    let aead_s = w
        .get("aead")
        .and_then(|v| v.as_str())
        .ok_or_else(|| js_err("sender wire missing aead"))?;
    let aead = parse_aead(aead_s)?;
    let cipher_suite = HpkeCipherSuite::new(kem, kdf, aead);
    let seq = w
        .get("sequence_number")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| js_err("sender wire missing sequence_number"))?;
    let max_seq = w
        .get("max_sequence_number")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| js_err("sender wire missing max_sequence_number"))?;
    let state_s = w
        .get("state")
        .and_then(|v| v.as_str())
        .ok_or_else(|| js_err("sender wire missing state"))?;
    let hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync> =
        Arc::new(PostQuantumProvider::new());
    Ok(HpkeSenderContext {
        shared_secret: hex_secret("shared_secret_hex")?,
        exporter_secret: hex_secret("exporter_secret_hex")?,
        key: hex_secret("key_hex")?,
        nonce: hex_secret("nonce_hex")?,
        cipher_suite,
        aead,
        encapsulated_key: hex_encap("encapsulated_key_hex")?,
        sequence_number: u32::try_from(seq).map_err(|_| js_err("sequence_number overflow"))?,
        max_sequence_number: u32::try_from(max_seq)
            .map_err(|_| js_err("max_sequence_number overflow"))?,
        state: state_from_str(state_s)?,
        hpke_crypto,
    })
}

/// HPKE base-mode sender setup; returns object with encapsulated key and serialized sender state.
#[wasm_bindgen(js_name = hpkeSetupSender)]
pub fn hpke_setup_sender(
    kem: &str,
    kdf: &str,
    aead: &str,
    recipient_public_key_hex: &str,
    info: &[u8],
) -> Result<JsValue, JsValue> {
    let suite = parse_suite(kem, kdf, aead)?;
    let pk = kem_pk_from_hex(recipient_public_key_hex, suite.kem)?;
    let mut ctx = hpke_ctx()?;
    ctx.set_cipher_suite(suite);
    let sender = ctx
        .setup_sender(&pk, info)
        .map_err(|e: lib_q_core::Error| js_err(e))?;
    let out = SetupSenderOut {
        encapsulated_key_hex: hex::encode(sender.encapsulated_key()),
        sender: sender_to_wire(&sender),
    };
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

#[derive(Serialize)]
struct SealUpdateOut {
    ciphertext_hex: String,
    sender: SenderWire,
}

/// Encrypt one message using a sender state object (from [`hpke_setup_sender`].sender).
#[wasm_bindgen(js_name = hpkeSenderSeal)]
pub fn hpke_sender_seal(sender: JsValue, aad: &[u8], plaintext: &[u8]) -> Result<JsValue, JsValue> {
    let v: serde_json::Value = serde_wasm_bindgen::from_value(sender).map_err(js_err)?;
    let mut sender = sender_from_wire(&v)?;
    let ct = sender
        .seal(aad, plaintext)
        .map_err(|e: lib_q_core::Error| js_err(e))?;
    let out = SealUpdateOut {
        ciphertext_hex: hex::encode(&ct),
        sender: sender_to_wire(&sender),
    };
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

#[derive(Serialize)]
struct ReceiverWire {
    shared_secret_hex: String,
    exporter_secret_hex: String,
    key_hex: String,
    nonce_hex: String,
    kem: &'static str,
    kdf: &'static str,
    aead: &'static str,
    sequence_number: u32,
    max_sequence_number: u32,
    state: &'static str,
}

fn receiver_to_wire(r: &HpkeReceiverContext) -> ReceiverWire {
    ReceiverWire {
        shared_secret_hex: hex::encode(r.shared_secret.as_slice()),
        exporter_secret_hex: hex::encode(r.exporter_secret.as_slice()),
        key_hex: hex::encode(r.key.as_slice()),
        nonce_hex: hex::encode(r.nonce.as_slice()),
        kem: kem_to_str(r.cipher_suite.kem),
        kdf: kdf_to_str(r.cipher_suite.kdf),
        aead: aead_to_str(r.aead),
        sequence_number: r.sequence_number,
        max_sequence_number: r.max_sequence_number,
        state: state_to_str(r.state),
    }
}

fn receiver_from_wire(w: &serde_json::Value) -> Result<HpkeReceiverContext, JsValue> {
    let hex_secret = |k: &str| -> Result<Zeroizing<Vec<u8>>, JsValue> {
        let s = w
            .get(k)
            .and_then(|v| v.as_str())
            .ok_or_else(|| js_err(format!("receiver wire missing string field {k}")))?;
        Ok(Zeroizing::new(hex::decode(s.trim()).map_err(js_err)?))
    };
    let kem_s = w
        .get("kem")
        .and_then(|v| v.as_str())
        .ok_or_else(|| js_err("receiver wire missing kem"))?;
    let kdf_s = w
        .get("kdf")
        .and_then(|v| v.as_str())
        .ok_or_else(|| js_err("receiver wire missing kdf"))?;
    let kem = parse_kem(kem_s)?;
    let kdf = parse_kdf(kdf_s)?;
    let aead_s = w
        .get("aead")
        .and_then(|v| v.as_str())
        .ok_or_else(|| js_err("receiver wire missing aead"))?;
    let aead = parse_aead(aead_s)?;
    let cipher_suite = HpkeCipherSuite::new(kem, kdf, aead);
    let seq = w
        .get("sequence_number")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| js_err("receiver wire missing sequence_number"))?;
    let max_seq = w
        .get("max_sequence_number")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| js_err("receiver wire missing max_sequence_number"))?;
    let state_s = w
        .get("state")
        .and_then(|v| v.as_str())
        .ok_or_else(|| js_err("receiver wire missing state"))?;
    let hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync> =
        Arc::new(PostQuantumProvider::new());
    Ok(HpkeReceiverContext {
        shared_secret: hex_secret("shared_secret_hex")?,
        exporter_secret: hex_secret("exporter_secret_hex")?,
        key: hex_secret("key_hex")?,
        nonce: hex_secret("nonce_hex")?,
        cipher_suite,
        aead,
        sequence_number: u32::try_from(seq).map_err(|_| js_err("sequence_number overflow"))?,
        max_sequence_number: u32::try_from(max_seq)
            .map_err(|_| js_err("max_sequence_number overflow"))?,
        state: state_from_str(state_s)?,
        hpke_crypto,
    })
}

#[derive(Serialize)]
struct SetupReceiverOut {
    receiver: ReceiverWire,
}

/// HPKE base-mode receiver setup from encapsulated key (hex) and recipient secret key (hex).
#[wasm_bindgen(js_name = hpkeSetupReceiver)]
pub fn hpke_setup_receiver(
    kem: &str,
    kdf: &str,
    aead: &str,
    encapsulated_key_hex: &str,
    recipient_secret_key_hex: &str,
    info: &[u8],
) -> Result<JsValue, JsValue> {
    let suite = parse_suite(kem, kdf, aead)?;
    let enc = hex::decode(encapsulated_key_hex.trim()).map_err(js_err)?;
    let sk = kem_sk_from_hex(recipient_secret_key_hex, suite.kem)?;
    let mut ctx = hpke_ctx()?;
    ctx.set_cipher_suite(suite);
    let receiver = ctx
        .setup_receiver(&enc, &sk, info)
        .map_err(|e: lib_q_core::Error| js_err(e))?;
    let out = SetupReceiverOut {
        receiver: receiver_to_wire(&receiver),
    };
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

#[derive(Serialize)]
struct OpenUpdateOut {
    plaintext_hex: String,
    receiver: ReceiverWire,
}

/// Decrypt one message using a receiver state object (from [`hpke_setup_receiver`].receiver).
///
/// Returns `{ plaintextHex, receiver }` with updated receiver state for the next `open`.
#[wasm_bindgen(js_name = hpkeReceiverOpen)]
pub fn hpke_receiver_open(
    receiver: JsValue,
    aad: &[u8],
    ciphertext_hex: &str,
) -> Result<JsValue, JsValue> {
    let v: serde_json::Value = serde_wasm_bindgen::from_value(receiver).map_err(js_err)?;
    let mut receiver = receiver_from_wire(&v)?;
    let ct = hex::decode(ciphertext_hex.trim()).map_err(js_err)?;
    let pt = receiver
        .open(aad, &ct)
        .map_err(|e: lib_q_core::Error| js_err(e))?;
    let out = OpenUpdateOut {
        plaintext_hex: hex::encode(&pt),
        receiver: receiver_to_wire(&receiver),
    };
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

// --- Opaque handle API: sender/receiver state stays in WASM (preferred over JSON wire state on the JS heap).

enum HpkeSlot {
    Sender(HpkeSenderContext),
    Receiver(HpkeReceiverContext),
}

struct HpkeHandleTable {
    next_id: u32,
    slots: BTreeMap<u32, HpkeSlot>,
}

static HPKE_HANDLES: Mutex<Option<HpkeHandleTable>> = Mutex::new(None);

fn with_hpke_handles<R>(f: impl FnOnce(&mut HpkeHandleTable) -> R) -> R {
    let mut guard = HPKE_HANDLES.lock();
    let table = guard.get_or_insert_with(|| HpkeHandleTable {
        next_id: 1,
        slots: BTreeMap::new(),
    });
    f(table)
}

fn alloc_hpke_slot(slot: HpkeSlot) -> u32 {
    with_hpke_handles(|t| {
        let id = t.next_id;
        t.next_id = t.next_id.wrapping_add(1);
        if t.next_id == 0 {
            t.next_id = 1;
        }
        t.slots.insert(id, slot);
        id
    })
}

/// Base-mode sender setup; returns `{ handle, encapsulatedKeyHex }`. Use [`hpke_sender_seal_by_handle`] then [`hpke_drop_handle`].
#[wasm_bindgen(js_name = hpkeSetupSenderHandle)]
pub fn hpke_setup_sender_handle(
    kem: &str,
    kdf: &str,
    aead: &str,
    recipient_public_key_hex: &str,
    info: &[u8],
) -> Result<JsValue, JsValue> {
    let suite = parse_suite(kem, kdf, aead)?;
    let pk = kem_pk_from_hex(recipient_public_key_hex, suite.kem)?;
    let mut ctx = hpke_ctx()?;
    ctx.set_cipher_suite(suite);
    let sender = ctx
        .setup_sender(&pk, info)
        .map_err(|e: lib_q_core::Error| js_err(e))?;
    let enc_hex = hex::encode(sender.encapsulated_key());
    let id = alloc_hpke_slot(HpkeSlot::Sender(sender));
    #[derive(Serialize)]
    struct Out {
        handle: u32,
        encapsulated_key_hex: String,
    }
    let out = Out {
        handle: id,
        encapsulated_key_hex: enc_hex,
    };
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

/// Encrypt using sender state for `handle` (from [`hpke_setup_sender_handle`]). Returns ciphertext hex.
#[wasm_bindgen(js_name = hpkeSenderSealByHandle)]
pub fn hpke_sender_seal_by_handle(
    handle: u32,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<String, JsValue> {
    with_hpke_handles(|t| {
        let slot = t
            .slots
            .get_mut(&handle)
            .ok_or_else(|| js_err("invalid HPKE handle"))?;
        match slot {
            HpkeSlot::Sender(sender) => {
                let ct = sender
                    .seal(aad, plaintext)
                    .map_err(|e: lib_q_core::Error| js_err(e))?;
                Ok(hex::encode(&ct))
            }
            HpkeSlot::Receiver(_) => Err(js_err("HPKE handle is not a sender context")),
        }
    })
}

/// Base-mode receiver setup; returns `{ handle }`. Use [`hpke_receiver_open_by_handle`] then [`hpke_drop_handle`].
#[wasm_bindgen(js_name = hpkeSetupReceiverHandle)]
pub fn hpke_setup_receiver_handle(
    kem: &str,
    kdf: &str,
    aead: &str,
    encapsulated_key_hex: &str,
    recipient_secret_key_hex: &str,
    info: &[u8],
) -> Result<JsValue, JsValue> {
    let suite = parse_suite(kem, kdf, aead)?;
    let enc = hex::decode(encapsulated_key_hex.trim()).map_err(js_err)?;
    let sk = kem_sk_from_hex(recipient_secret_key_hex, suite.kem)?;
    let mut ctx = hpke_ctx()?;
    ctx.set_cipher_suite(suite);
    let receiver = ctx
        .setup_receiver(&enc, &sk, info)
        .map_err(|e: lib_q_core::Error| js_err(e))?;
    let id = alloc_hpke_slot(HpkeSlot::Receiver(receiver));
    #[derive(Serialize)]
    struct Out {
        handle: u32,
    }
    serde_wasm_bindgen::to_value(&Out { handle: id }).map_err(js_err)
}

/// Decrypt using receiver state for `handle`. Returns plaintext hex.
#[wasm_bindgen(js_name = hpkeReceiverOpenByHandle)]
pub fn hpke_receiver_open_by_handle(
    handle: u32,
    aad: &[u8],
    ciphertext_hex: &str,
) -> Result<String, JsValue> {
    let ct = hex::decode(ciphertext_hex.trim()).map_err(js_err)?;
    with_hpke_handles(|t| {
        let slot = t
            .slots
            .get_mut(&handle)
            .ok_or_else(|| js_err("invalid HPKE handle"))?;
        match slot {
            HpkeSlot::Receiver(receiver) => {
                let pt = receiver
                    .open(aad, &ct)
                    .map_err(|e: lib_q_core::Error| js_err(e))?;
                Ok(hex::encode(&pt))
            }
            HpkeSlot::Sender(_) => Err(js_err("HPKE handle is not a receiver context")),
        }
    })
}

/// Drop a handle and its HPKE context (best-effort clearing via Rust drops).
#[wasm_bindgen(js_name = hpkeDropHandle)]
pub fn hpke_drop_handle(handle: u32) -> Result<(), JsValue> {
    with_hpke_handles(|t| {
        t.slots
            .remove(&handle)
            .ok_or_else(|| js_err("invalid HPKE handle"))?;
        Ok(())
    })
}
