//! WASM bindings for Classical McEliece CB-KEM (compile-time variant).

extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;

use js_sys::Uint8Array;
use lib_q_random::LibQRng;
use serde::Serialize;
use wasm_bindgen::prelude::{
    JsValue,
    wasm_bindgen,
};
use zeroize::Zeroizing;

use crate::{
    CRYPTO_CIPHERTEXTBYTES,
    CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES,
    Ciphertext,
    PublicKey,
    SecretKey,
    decapsulate_boxed,
    encapsulate_boxed,
    keypair_boxed,
};

fn js_err(e: impl core::fmt::Display) -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_CB_KEM", e)
}

fn hex_to_array<const N: usize>(s: &str) -> Result<[u8; N], JsValue> {
    let v = Zeroizing::new(hex::decode(s.trim()).map_err(js_err)?);
    if v.len() != N {
        return Err(js_err(format!(
            "expected {} bytes from hex, got {}",
            N,
            v.len()
        )));
    }
    let mut a = [0u8; N];
    a.copy_from_slice(v.as_slice());
    Ok(a)
}

/// Generate a CB-KEM keypair for the variant compiled into this build.
#[wasm_bindgen(js_name = cbKemKeygen)]
pub fn cb_kem_keygen() -> Result<JsValue, JsValue> {
    let mut rng = LibQRng::new_secure().map_err(js_err)?;
    let (pk, sk) = keypair_boxed(&mut rng);
    #[derive(Serialize)]
    struct Out {
        public_key_hex: String,
        secret_key_hex: String,
    }
    let out = Out {
        public_key_hex: hex::encode(pk.as_ref()),
        secret_key_hex: hex::encode(sk.as_ref()),
    };
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

/// Encapsulate to a peer's public key (hex).
#[wasm_bindgen(js_name = cbKemEncapsulate)]
pub fn cb_kem_encapsulate(public_key_hex: &str) -> Result<JsValue, JsValue> {
    let pk_arr = hex_to_array::<CRYPTO_PUBLICKEYBYTES>(public_key_hex)?;
    let pk: PublicKey<'static> = PublicKey::from(Box::new(pk_arr));
    let mut rng = LibQRng::new_secure().map_err(js_err)?;
    let (ct, ss) = encapsulate_boxed(&pk, &mut rng);
    #[derive(Serialize)]
    struct Out {
        ciphertext_hex: String,
        shared_secret_hex: String,
    }
    let out = Out {
        ciphertext_hex: hex::encode(ct.as_ref()),
        shared_secret_hex: hex::encode(ss.as_ref()),
    };
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

#[derive(Serialize)]
struct CbKemDecapHexOut {
    shared_secret_hex: String,
}

/// Decapsulate shared secret from ciphertext (hex) with secret key (hex); returns `{ sharedSecretHex }`.
#[wasm_bindgen(js_name = cbKemDecapsulate)]
pub fn cb_kem_decapsulate(secret_key_hex: &str, ciphertext_hex: &str) -> Result<JsValue, JsValue> {
    let sk_arr = hex_to_array::<CRYPTO_SECRETKEYBYTES>(secret_key_hex)?;
    let ct_arr = hex_to_array::<CRYPTO_CIPHERTEXTBYTES>(ciphertext_hex)?;
    let sk: SecretKey<'static> = SecretKey::from(Box::new(sk_arr));
    let ct = Ciphertext::from(ct_arr);
    let ss = decapsulate_boxed(&ct, &sk);
    let out = CbKemDecapHexOut {
        shared_secret_hex: hex::encode(ss.as_ref()),
    };
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

/// Raw shared secret bytes (decapsulate).
#[wasm_bindgen(js_name = cbKemDecapsulateBytes)]
pub fn cb_kem_decapsulate_bytes(
    secret_key_hex: &str,
    ciphertext_hex: &str,
) -> Result<Uint8Array, JsValue> {
    let sk_arr = hex_to_array::<CRYPTO_SECRETKEYBYTES>(secret_key_hex)?;
    let ct_arr = hex_to_array::<CRYPTO_CIPHERTEXTBYTES>(ciphertext_hex)?;
    let sk: SecretKey<'static> = SecretKey::from(Box::new(sk_arr));
    let ct = Ciphertext::from(ct_arr);
    let ss = decapsulate_boxed(&ct, &sk);
    let bytes = Zeroizing::new(ss.as_ref().to_vec());
    Ok(Uint8Array::from(bytes.as_slice()))
}
