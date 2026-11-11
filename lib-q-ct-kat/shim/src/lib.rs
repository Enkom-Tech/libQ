//! C-ABI wrappers used only by the CT-KAT end-to-end run. Each entry point takes the SECRET as a
//! seed and derives the key inside the call, so keygen is part of the measured/tainted region.
//! Consequence for reading results: a finding may come from key derivation rather than from
//! decapsulation / signing proper. The `extern "C"` surface is the only `unsafe` here.
#![allow(unsafe_code)]

use lib_q_ml_dsa::Zeroizing;
use lib_q_ml_dsa::ml_dsa_44::portable;
use lib_q_ml_kem::{Ciphertext, Decapsulate, KemCore, MlKem768, Seed};

pub const MLKEM768_SEED: usize = 64;
pub const MLKEM768_CT: usize = 1088;
pub const MLKEM768_SS: usize = 32;
pub const MLDSA44_SEED: usize = 32;
pub const MLDSA44_MSG: usize = 32;
pub const MLDSA44_SIG: usize = 2420;

/// out[32] = ML-KEM-768 Decaps(dk(seed), ct). Any ct is valid input (implicit rejection).
///
/// # Safety
/// `seed` -> 64 readable bytes, `ct` -> 1088 readable bytes, `out` -> 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ctkat_mlkem768_decaps(seed: *const u8, ct: *const u8, out: *mut u8) {
    let (seed, ct, out) = unsafe {
        (
            core::slice::from_raw_parts(seed, MLKEM768_SEED),
            core::slice::from_raw_parts(ct, MLKEM768_CT),
            core::slice::from_raw_parts_mut(out, MLKEM768_SS),
        )
    };
    let mut s = Seed::default();
    s.as_mut_slice().copy_from_slice(seed);
    let dk = <MlKem768 as KemCore>::DecapsulationKey::from_seed(&s);
    let mut c = Ciphertext::<MlKem768>::default();
    c.as_mut_slice().copy_from_slice(ct);
    match dk.decapsulate(&c) {
        Ok(ss) => out.copy_from_slice(ss.as_slice()),
        Err(_) => out.fill(0),
    }
}

/// out[2420] = ML-DSA-44 Sign(sk(seed), msg[32]) with fixed rnd = 0^32 (deterministic variant).
/// Writes zeros if signing fails.
///
/// # Safety
/// `seed` -> 32 readable bytes, `msg` -> 32 readable bytes, `out` -> 2420 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ctkat_mldsa44_sign(seed: *const u8, msg: *const u8, out: *mut u8) {
    let (seed, msg, out) = unsafe {
        (
            core::slice::from_raw_parts(seed, MLDSA44_SEED),
            core::slice::from_raw_parts(msg, MLDSA44_MSG),
            core::slice::from_raw_parts_mut(out, MLDSA44_SIG),
        )
    };
    let mut s = [0u8; MLDSA44_SEED];
    s.copy_from_slice(seed);
    let kp = portable::generate_key_pair_from_seed(&Zeroizing::new(s));
    match portable::sign(&kp.signing_key, msg, b"", [0u8; 32]) {
        Ok(sig) => out.copy_from_slice(sig.as_slice()),
        Err(_) => out.fill(0),
    }
}
