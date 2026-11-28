//! Dual-family KEM combiner: **ML-KEM-1024 + HQC-256**.
//!
//! A hedge against a break of the module-lattice assumption: the combined KEM is meant to stay
//! IND-CCA secure if *either* component is IND-CCA secure. ML-KEM-1024 (FIPS 203, module-LWE)
//! and HQC-256 (NIST-selected, quasi-cyclic codes) rest on unrelated hardness assumptions, and
//! both are NIST category 5.
//!
//! # Wire formats (fixed length; every field below has exactly one length per [`COMBINER_LABEL`])
//!
//! ```text
//! pk = pk_mlkem (1568)  || pk_hqc (HQC-256 public key)
//! ct = ct_mlkem (1568)  || ct_hqc (HQC-256 ciphertext)
//! sk = dk_mlkem (3168)  || sk_hqc (HQC-256 secret key)
//! ```
//!
//! # Failure behaviour
//!
//! Any component failure (wrong length, non-canonical ML-KEM key, HQC error) fails the whole
//! operation. There is no single-KEM fallback.
//!
//! # Combining step
//!
//! See [`combine`].
//!
//! # Randomness
//!
//! [`generate_keypair`] draws [`KEYGEN_SEED_SIZE`] bytes from the OS-seeded libQ CSPRNG and runs
//! the seeded key generation on them. [`encapsulate`] runs FIPS 203 randomized encapsulation on
//! the same CSPRNG for the ML-KEM half and draws a fresh [`HQC_SEED_SIZE`]-byte seed for the HQC
//! half. The HQC half therefore always runs on the HQC reference SHAKE256 PRNG seeded with 48
//! fresh bytes, never on `LibQHqcProvider`'s `randomness = None` path;
//! `lib-q-kem/tests/hqc_tests.rs` records "rare OS-RNG encaps/decaps shared-secret mismatches" on
//! that path, without a root cause.
//!
//! # Known-answer entry points (`combiner-kat` feature, tests only)
//!
//! `generate_keypair_from_seed` and `encapsulate_with_coins` take caller-supplied seed and coins,
//! and exist only so the known-answer tests can pin outputs. They are compiled only with the
//! non-default `combiner-kat` feature, which also turns on `lib-q-ml-kem/deterministic`. Do not
//! enable `combiner-kat` in a production build: reused encapsulation coins give away the shared
//! secret. The `combiner` feature alone never compiles either entry point and never turns on
//! `lib-q-ml-kem/deterministic`.
#![allow(clippy::module_name_repetitions)]

extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use lib_q_core::{Error, KemOperations, Result};
use lib_q_hqc::LibQHqcProvider;
use lib_q_hqc::params::{Hqc5Params, HqcParams};
use lib_q_ml_kem::array::Array;
#[cfg(feature = "combiner-kat")]
use lib_q_ml_kem::{B32, EncapsulateDeterministic};
use lib_q_ml_kem::{
    Ciphertext, Decapsulate, Encapsulate, EncodedSizeUser, KemCore, MLKEM1024_CIPHERTEXT_SIZE,
    MLKEM1024_PUBLIC_KEY_SIZE, MLKEM1024_SECRET_KEY_SIZE, MlKem1024, Seed, SharedKey,
};
use lib_q_random::SecureRng;
use lib_q_sha3::{ExtendableOutput, TurboShake256, Update, XofReader};
use zeroize::Zeroizing;

type MlKemDk = <MlKem1024 as KemCore>::DecapsulationKey;
type MlKemEk = <MlKem1024 as KemCore>::EncapsulationKey;
type MlKemCt = Ciphertext<MlKem1024>;
type MlKemSs = SharedKey<MlKem1024>;

/// Combiner label: a fixed 32-byte ASCII string, the first input to the KDF. It names the
/// component pair, their order and the KDF, so a change to any of them is a new label (a registry
/// change), never a silent reinterpretation of old bytes.
pub const COMBINER_LABEL: &[u8; 32] = b"libQ-KEMC-v1 MLKEM1024+HQC256 TS";

/// HQC-256 public key length.
pub const HQC256_PUBLIC_KEY_SIZE: usize = Hqc5Params::PUBLIC_KEY_BYTES;
/// HQC-256 secret key length (libQ encoding: `ek_pke || dk_pke || sigma || seed_kem`).
pub const HQC256_SECRET_KEY_SIZE: usize = Hqc5Params::SECRET_KEY_BYTES;
/// HQC-256 ciphertext length.
pub const HQC256_CIPHERTEXT_SIZE: usize = Hqc5Params::CIPHERTEXT_BYTES;

/// Combined public key length.
pub const PUBLIC_KEY_SIZE: usize = MLKEM1024_PUBLIC_KEY_SIZE + HQC256_PUBLIC_KEY_SIZE;
/// Combined secret key length.
pub const SECRET_KEY_SIZE: usize = MLKEM1024_SECRET_KEY_SIZE + HQC256_SECRET_KEY_SIZE;
/// Combined ciphertext length.
pub const CIPHERTEXT_SIZE: usize = MLKEM1024_CIPHERTEXT_SIZE + HQC256_CIPHERTEXT_SIZE;
/// Combined shared secret length.
pub const SHARED_SECRET_SIZE: usize = 32;
/// Component shared secret length (both ML-KEM and HQC-256 produce 32 bytes).
pub const COMPONENT_SHARED_SECRET_SIZE: usize = 32;

/// Key-generation seed: `d || z` for ML-KEM-1024 (64 bytes) followed by the 48-byte seed of the
/// HQC reference SHAKE256 PRNG.
pub const KEYGEN_SEED_SIZE: usize = 64 + 48;
/// Seed of the HQC reference SHAKE256 PRNG, drawn fresh for every key generation and encapsulation.
pub const HQC_SEED_SIZE: usize = 48;
/// Encapsulation coins of the known-answer entry point: ML-KEM-1024 `m` (32 bytes) followed by the
/// [`HQC_SEED_SIZE`]-byte HQC PRNG seed.
pub const ENCAPS_COINS_SIZE: usize = 32 + HQC_SEED_SIZE;

/// A combined key pair. The secret key is wiped on drop.
pub struct Keypair {
    /// `pk_mlkem || pk_hqc`, [`PUBLIC_KEY_SIZE`] bytes.
    pub public_key: Vec<u8>,
    /// `dk_mlkem || sk_hqc`, [`SECRET_KEY_SIZE`] bytes.
    pub secret_key: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keypair")
            .field("public_key_len", &self.public_key.len())
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

fn err(operation: &str, details: impl Into<String>) -> Error {
    Error::InternalError {
        operation: String::from(operation),
        details: details.into(),
    }
}

fn check_len(what: &'static str, actual: usize, expected: usize) -> Result<()> {
    if actual == expected {
        Ok(())
    } else if what == "ciphertext" {
        Err(Error::InvalidCiphertextSize { expected, actual })
    } else {
        Err(Error::InvalidKeySize { expected, actual })
    }
}

/// View `bytes` as a fixed-length array, with the same errors as [`check_len`].
fn fixed<'a, const N: usize>(what: &'static str, bytes: &'a [u8]) -> Result<&'a [u8; N]> {
    check_len(what, bytes.len(), N)?;
    <&[u8; N]>::try_from(bytes).map_err(|_| Error::InvalidKeySize {
        expected: N,
        actual: bytes.len(),
    })
}

/// TurboSHAKE256 domain byte for the combiner KDF (RFC 9861 default, `0x1F`). Separation from
/// other TurboSHAKE256 uses comes from [`COMBINER_LABEL`], which is always the first 32 input bytes.
pub const KDF_DOMAIN_BYTE: u8 = 0x1F;

/// Combine the component outputs into the shared secret:
///
/// ```text
/// ss = TurboSHAKE256_{D=0x1F}(label || ss_mlkem || ss_hqc || ct_mlkem || ct_hqc || pk_mlkem || pk_hqc, 32)
/// ```
///
/// Every field has a fixed length for a given label, and the parameter types enforce those lengths
/// (fixed-size arrays, so a wrong length does not compile), so the encoding is injective without
/// length prefixes.
///
/// Why each input is there:
/// - **both ciphertexts**: the KDF must change whenever *either* ciphertext changes. Without
///   `ct_hqc`, an attacker who has broken HQC can keep the challenge `ct_mlkem`, pair it with an
///   HQC ciphertext of its own, query decapsulation, and strip the HQC part (see
///   `tests/combiner_tests.rs`, which recovers the secret from an XOR combiner exactly this way).
///   Binding `ct_mlkem` is likewise needed because HQC's FO transform is not proven to bind its
///   ciphertext the way ML-KEM's does; the combiner does not rely on either component's
///   ciphertext-binding property.
/// - **both public keys**: binds the secret to the recipient key pair, so a component key
///   reused under another combiner or another partner key yields an unrelated secret.
/// - **the label**: separates this combiner from any future one (a registry change).
///
/// The function is public so other implementations can check themselves against it with the
/// KATs; callers do not need it.
///
/// A slice of unchecked length is rejected at compile time:
///
/// ```compile_fail
/// use lib_q_kem::combiner::combine;
/// let short: &[u8] = &[0u8; 16];
/// let _ = combine(&[0; 32], &[0; 32], short, short, short, short);
/// ```
pub fn combine(
    ss_mlkem: &[u8; COMPONENT_SHARED_SECRET_SIZE],
    ss_hqc: &[u8; COMPONENT_SHARED_SECRET_SIZE],
    ct_mlkem: &[u8; MLKEM1024_CIPHERTEXT_SIZE],
    ct_hqc: &[u8; HQC256_CIPHERTEXT_SIZE],
    pk_mlkem: &[u8; MLKEM1024_PUBLIC_KEY_SIZE],
    pk_hqc: &[u8; HQC256_PUBLIC_KEY_SIZE],
) -> Zeroizing<[u8; SHARED_SECRET_SIZE]> {
    let mut h = TurboShake256::<KDF_DOMAIN_BYTE>::default();
    h.update(COMBINER_LABEL);
    h.update(ss_mlkem);
    h.update(ss_hqc);
    h.update(ct_mlkem);
    h.update(ct_hqc);
    h.update(pk_mlkem);
    h.update(pk_hqc);
    let mut out = Zeroizing::new([0u8; SHARED_SECRET_SIZE]);
    h.finalize_xof().read(out.as_mut_slice());
    out
}

fn to_ss32(op: &str, bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if bytes.len() != COMPONENT_SHARED_SECRET_SIZE {
        return Err(err(
            op,
            format!("component shared secret is {} bytes", bytes.len()),
        ));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(bytes);
    Ok(out)
}

fn parse_mlkem_ek(pk_mlkem: &[u8]) -> Result<MlKemEk> {
    let enc = Array::try_from(pk_mlkem).map_err(|_| Error::InvalidKeySize {
        expected: MLKEM1024_PUBLIC_KEY_SIZE,
        actual: pk_mlkem.len(),
    })?;
    MlKemEk::try_from_bytes(&enc).map_err(|_| Error::InvalidKey {
        key_type: String::from("ML-KEM-1024 encapsulation key"),
        reason: String::from("FIPS 203 modulus check failed"),
    })
}

/// Seeded key generation, shared by [`generate_keypair`] (fresh seed) and the known-answer entry
/// point.
fn keypair_from_seed(seed: &[u8; KEYGEN_SEED_SIZE]) -> Result<Keypair> {
    const OP: &str = "ML-KEM-1024+HQC-256 key generation";
    let mut mlkem_seed = Zeroizing::new(Seed::default());
    mlkem_seed.copy_from_slice(&seed[..64]);
    let (dk, ek) = MlKem1024::generate_from_seed(&mlkem_seed);

    let hqc = LibQHqcProvider::new()?
        .generate_keypair(lib_q_core::Algorithm::Hqc256, Some(&seed[64..]))
        .map_err(|e| err(OP, format!("HQC-256: {e:?}")))?;
    check_len(
        "HQC-256 public key",
        hqc.public_key.data.len(),
        HQC256_PUBLIC_KEY_SIZE,
    )?;
    check_len(
        "HQC-256 secret key",
        hqc.secret_key.data.len(),
        HQC256_SECRET_KEY_SIZE,
    )?;

    let mut public_key = Vec::with_capacity(PUBLIC_KEY_SIZE);
    public_key.extend_from_slice(ek.as_bytes().as_slice());
    public_key.extend_from_slice(&hqc.public_key.data);

    let mut secret_key = Zeroizing::new(Vec::with_capacity(SECRET_KEY_SIZE));
    secret_key.extend_from_slice(dk.as_bytes().as_slice());
    secret_key.extend_from_slice(&hqc.secret_key.data);

    Ok(Keypair {
        public_key,
        secret_key,
    })
}

/// Known-answer key generation from [`KEYGEN_SEED_SIZE`] bytes of caller-supplied seed.
///
/// Test and KAT use only; compiled only with the `combiner-kat` feature (see the module docs).
/// [`generate_keypair`] runs exactly this key generation on a fresh seed.
#[cfg(feature = "combiner-kat")]
pub fn generate_keypair_from_seed(seed: &[u8; KEYGEN_SEED_SIZE]) -> Result<Keypair> {
    keypair_from_seed(seed)
}

/// Generate a key pair from fresh OS entropy.
pub fn generate_keypair() -> Result<Keypair> {
    let mut seed = Zeroizing::new([0u8; KEYGEN_SEED_SIZE]);
    fresh_bytes(seed.as_mut_slice())?;
    keypair_from_seed(&seed)
}

/// Encapsulation shared by [`encapsulate`] and the known-answer entry point. `mlkem_encaps` runs
/// the ML-KEM-1024 half (randomized or with explicit coins); the HQC half runs on `hqc_seed`.
fn encapsulate_inner<F>(
    public_key: &[u8],
    hqc_seed: &[u8; HQC_SEED_SIZE],
    mlkem_encaps: F,
) -> Result<(Vec<u8>, Zeroizing<[u8; SHARED_SECRET_SIZE]>)>
where
    F: FnOnce(&MlKemEk) -> Result<(MlKemCt, MlKemSs)>,
{
    const OP: &str = "ML-KEM-1024+HQC-256 encapsulation";
    check_len("public key", public_key.len(), PUBLIC_KEY_SIZE)?;
    let (pk_mlkem, pk_hqc) = public_key.split_at(MLKEM1024_PUBLIC_KEY_SIZE);
    let pk_mlkem: &[u8; MLKEM1024_PUBLIC_KEY_SIZE] = fixed("ML-KEM-1024 public key", pk_mlkem)?;
    let pk_hqc: &[u8; HQC256_PUBLIC_KEY_SIZE] = fixed("HQC-256 public key", pk_hqc)?;

    let ek = parse_mlkem_ek(pk_mlkem)?;
    let (ct_mlkem, ss_mlkem) = mlkem_encaps(&ek)?;
    let ss_mlkem = Zeroizing::new(ss_mlkem);
    let ss_mlkem = to_ss32(OP, ss_mlkem.as_slice())?;
    let ct_mlkem: &[u8; MLKEM1024_CIPHERTEXT_SIZE] = fixed("ciphertext", ct_mlkem.as_slice())?;

    let hqc_pk = lib_q_core::KemPublicKey::new(Vec::from(pk_hqc.as_slice()));
    let (ct_hqc, ss_hqc) = LibQHqcProvider::new()?
        .encapsulate(lib_q_core::Algorithm::Hqc256, &hqc_pk, Some(hqc_seed))
        .map_err(|e| err(OP, format!("HQC-256: {e:?}")))?;
    let ss_hqc = to_ss32(OP, &Zeroizing::new(ss_hqc))?;
    let ct_hqc_arr: &[u8; HQC256_CIPHERTEXT_SIZE] = fixed("ciphertext", &ct_hqc)?;

    let ss = combine(&ss_mlkem, &ss_hqc, ct_mlkem, ct_hqc_arr, pk_mlkem, pk_hqc);

    let mut ct = Vec::with_capacity(CIPHERTEXT_SIZE);
    ct.extend_from_slice(ct_mlkem);
    ct.extend_from_slice(ct_hqc_arr);
    Ok((ct, ss))
}

/// Known-answer encapsulation with explicit coins. Returns `(ct, ss)`.
///
/// Test and KAT use only; compiled only with the `combiner-kat` feature (see the module docs).
/// Reusing coins across encapsulations gives away the shared secret.
#[cfg(feature = "combiner-kat")]
pub fn encapsulate_with_coins(
    public_key: &[u8],
    coins: &[u8; ENCAPS_COINS_SIZE],
) -> Result<(Vec<u8>, Zeroizing<[u8; SHARED_SECRET_SIZE]>)> {
    const OP: &str = "ML-KEM-1024+HQC-256 encapsulation";
    let m: Zeroizing<B32> =
        Zeroizing::new(Array::try_from(&coins[..32]).map_err(|_| err(OP, "coins"))?);
    let hqc_seed: &[u8; HQC_SEED_SIZE] = fixed("coins", &coins[32..])?;
    encapsulate_inner(public_key, hqc_seed, |ek| {
        ek.encapsulate_deterministic(&m)
            .map_err(|e| err(OP, format!("ML-KEM-1024: {e:?}")))
    })
}

/// Encapsulate to `public_key` with fresh OS entropy. Returns `(ct, ss)`.
pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; SHARED_SECRET_SIZE]>)> {
    const OP: &str = "ML-KEM-1024+HQC-256 encapsulation";
    let mut hqc_seed = Zeroizing::new([0u8; HQC_SEED_SIZE]);
    fresh_bytes(hqc_seed.as_mut_slice())?;
    let mut rng = secure_rng()?;
    encapsulate_inner(public_key, &hqc_seed, |ek| {
        ek.encapsulate(&mut rng)
            .map_err(|e| err(OP, format!("ML-KEM-1024: {e:?}")))
    })
}

/// Decapsulate `ciphertext` with `secret_key`.
///
/// Both components use implicit rejection, so a well-formed but forged ciphertext yields a
/// pseudorandom secret rather than an error; a malformed one fails the whole operation.
pub fn decapsulate(
    secret_key: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; SHARED_SECRET_SIZE]>> {
    const OP: &str = "ML-KEM-1024+HQC-256 decapsulation";
    check_len("secret key", secret_key.len(), SECRET_KEY_SIZE)?;
    check_len("ciphertext", ciphertext.len(), CIPHERTEXT_SIZE)?;
    let (dk_bytes, sk_hqc) = secret_key.split_at(MLKEM1024_SECRET_KEY_SIZE);
    let (ct_mlkem, ct_hqc) = ciphertext.split_at(MLKEM1024_CIPHERTEXT_SIZE);

    let dk_enc = Zeroizing::new(
        Array::try_from(dk_bytes).map_err(|_| err(OP, "ML-KEM-1024 decapsulation key length"))?,
    );
    let dk = MlKemDk::try_from_bytes(&dk_enc).map_err(|_| Error::InvalidKey {
        key_type: String::from("ML-KEM-1024 decapsulation key"),
        reason: String::from("FIPS 203 key check failed"),
    })?;
    let ct_mlkem: &[u8; MLKEM1024_CIPHERTEXT_SIZE] = fixed("ciphertext", ct_mlkem)?;
    let ct_hqc: &[u8; HQC256_CIPHERTEXT_SIZE] = fixed("ciphertext", ct_hqc)?;
    let ct_arr = Array::try_from(ct_mlkem.as_slice())
        .map_err(|_| err(OP, "ML-KEM-1024 ciphertext length"))?;
    let ss_mlkem = Zeroizing::new(
        dk.decapsulate(&ct_arr)
            .map_err(|e| err(OP, format!("ML-KEM-1024: {e:?}")))?,
    );
    let ss_mlkem = to_ss32(OP, ss_mlkem.as_slice())?;
    let pk_mlkem = dk.encapsulation_key().as_bytes();

    let hqc_sk = lib_q_core::KemSecretKey::new(Vec::from(sk_hqc));
    let provider = LibQHqcProvider::new()?;
    let ss_hqc = provider
        .decapsulate(lib_q_core::Algorithm::Hqc256, &hqc_sk, ct_hqc)
        .map_err(|e| err(OP, format!("HQC-256: {e:?}")))?;
    let ss_hqc = to_ss32(OP, &Zeroizing::new(ss_hqc))?;
    let pk_hqc = provider
        .derive_public_key(lib_q_core::Algorithm::Hqc256, &hqc_sk)
        .map_err(|e| err(OP, format!("HQC-256 public key: {e:?}")))?;
    let pk_mlkem: &[u8; MLKEM1024_PUBLIC_KEY_SIZE] =
        fixed("ML-KEM-1024 public key", pk_mlkem.as_slice())?;
    let pk_hqc: &[u8; HQC256_PUBLIC_KEY_SIZE] = fixed("HQC-256 public key", &pk_hqc.data)?;

    Ok(combine(
        &ss_mlkem, &ss_hqc, ct_mlkem, ct_hqc, pk_mlkem, pk_hqc,
    ))
}

/// The OS-seeded libQ CSPRNG.
fn secure_rng() -> Result<lib_q_random::LibQRng> {
    lib_q_random::new_secure_rng().map_err(|e| Error::RandomGenerationFailed {
        operation: format!("secure RNG: {e}"),
    })
}

/// Fill `dest` from the OS-seeded libQ CSPRNG.
fn fresh_bytes(dest: &mut [u8]) -> Result<()> {
    let mut rng = secure_rng()?;
    rng.fill_bytes_secure(dest)
        .map_err(|e| Error::RandomGenerationFailed {
            operation: format!("secure RNG fill: {e}"),
        })
}
