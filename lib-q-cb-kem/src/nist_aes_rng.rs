//! NIST SP 800-90A Rev. 1 CTR_DRBG (AES-256, no derivation function).
//!
//! This module implements a deterministic random bit generator conforming to
//! NIST SP 800-90A Rev. 1 (June 2015), Section 10.2.1 (CTR_DRBG) with AES-256
//! and without a derivation function. Full entropy seed is required.
//!
//! **Parameters (Table 3, AES-256):** seedlen = 48 bytes, reseed interval = 2^48
//! generate requests, max 8192 bytes per generate request.
//!
//! **Supported:** instantiate with optional personalization string; reseed with
//! optional additional input; generate with optional additional_input (via
//! `try_fill_bytes_with_additional_input`); uninstantiate (zeroize); on-demand
//! health test; error state and recovery (uninstantiate then instantiate).
//!
//! **Usage:** Reseed before exceeding 2^48 requests or handle `ReseedRequired`
//! from `try_fill_bytes`. After health test failure or catastrophic error, call
//! `uninstantiate()` then `instantiate()` to recover. `randombytes_init(entropy)`
//! is equivalent to `instantiate(entropy, None)`.

use core::fmt;

use aes::cipher::{
    BlockCipherEncrypt,
    KeyInit,
};
use rand_core::{
    TryCryptoRng,
    TryRng,
};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// NIST SP 800-90A Table 3 (AES-256): seed length in bytes.
pub const SEEDLEN: usize = 48;

/// NIST SP 800-90A: maximum number of generate requests between reseeds.
pub const RESEED_INTERVAL: u64 = 1_u64 << 48;

/// NIST SP 800-90A: max number of bytes per generate request (2^19 bits).
pub const MAX_BYTES_PER_REQUEST: usize = 8192;

/// Errors from the NIST CTR_DRBG implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NistDrbgError {
    /// Reseed required before more output (reseed_counter > RESEED_INTERVAL).
    ReseedRequired,
    /// Requested byte count exceeds MAX_BYTES_PER_REQUEST.
    RequestTooLong,
    /// DRBG is uninstantiated; call instantiate first.
    DrbgUninstantiated,
    /// DRBG is in error state; call uninstantiate then instantiate to recover.
    DrbgInErrorState,
    /// Personalization string longer than SEEDLEN.
    PersonalizationTooLong,
    /// Additional input longer than SEEDLEN.
    AdditionalInputTooLong,
}

impl fmt::Display for NistDrbgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NistDrbgError::ReseedRequired => write!(f, "CTR_DRBG reseed required"),
            NistDrbgError::RequestTooLong => write!(f, "CTR_DRBG request too long"),
            NistDrbgError::DrbgUninstantiated => write!(f, "CTR_DRBG uninstantiated"),
            NistDrbgError::DrbgInErrorState => write!(f, "CTR_DRBG in error state"),
            NistDrbgError::PersonalizationTooLong => write!(f, "CTR_DRBG personalization too long"),
            NistDrbgError::AdditionalInputTooLong => {
                write!(f, "CTR_DRBG additional input too long")
            }
        }
    }
}

impl core::error::Error for NistDrbgError {}

/// Builds seed_material = entropy XOR padded other (both 48 bytes). Fails if other.len() > 48.
fn build_seed_material(
    entropy: &[u8; SEEDLEN],
    other: Option<&[u8]>,
) -> Result<[u8; SEEDLEN], NistDrbgError> {
    let mut seed = *entropy;
    if let Some(s) = other {
        if s.len() > SEEDLEN {
            return Err(NistDrbgError::PersonalizationTooLong);
        }
        for (i, &b) in s.iter().enumerate() {
            seed[i] ^= b;
        }
        // rest of seed already equals entropy (zero-pad for other)
    }
    Ok(seed)
}

/// NIST SP 800-90A Rev. 1 CTR_DRBG (AES-256, no derivation function).
///
/// Internal state: Key, V, reseed_counter, plus uninstantiated and error-state flags.
/// Use `instantiate` (or `randombytes_init` for entropy-only) then generate;
/// call `reseed` before exceeding `RESEED_INTERVAL` requests or handle `ReseedRequired`.
#[derive(Debug, PartialEq, Eq)]
pub struct AesState {
    pub key: [u8; 32],
    pub v: [u8; 16],
    pub reseed_counter: u64,
    uninstantiated: bool,
    in_error_state: bool,
}

impl AesState {
    /// Returns a fresh, uninstantiated DRBG state.
    pub fn new() -> AesState {
        AesState {
            key: [0; 32],
            v: [0; 16],
            reseed_counter: 0,
            uninstantiated: true,
            in_error_state: false,
        }
    }

    fn aes256_ecb(key: &[u8; 32], ctr: &[u8; 16], buffer: &mut [u8; 16]) {
        let cipher = aes::Aes256::new_from_slice(key).expect("32-byte key");
        buffer.copy_from_slice(ctr);
        let mut block = aes::Block::from(*buffer);
        cipher.encrypt_block(&mut block);
        *buffer = block.into();
    }

    fn aes256_ctr_update(
        provided_data: &mut Option<[u8; SEEDLEN]>,
        key: &mut [u8; 32],
        v: &mut [u8; 16],
    ) {
        let mut temp = [[0u8; 16]; 3];

        for tmp in &mut temp[0..3] {
            let count = u128::from_be_bytes(*v);
            v.copy_from_slice(&(count + 1).to_be_bytes());
            Self::aes256_ecb(key, v, tmp);
        }

        if let Some(d) = provided_data {
            for j in 0..3 {
                for i in 0..16 {
                    temp[j][i] ^= d[16 * j + i];
                }
            }
        }

        key[0..16].copy_from_slice(&temp[0]);
        key[16..32].copy_from_slice(&temp[1]);
        v.copy_from_slice(&temp[2]);
    }

    /// Instantiates the DRBG with entropy and optional personalization string (NIST 10.2.1.3.1).
    /// Fails if in error state or personalization_string.len() > SEEDLEN.
    pub fn instantiate(
        &mut self,
        entropy_input: [u8; SEEDLEN],
        personalization_string: Option<&[u8]>,
    ) -> Result<(), NistDrbgError> {
        if self.in_error_state {
            return Err(NistDrbgError::DrbgInErrorState);
        }
        if personalization_string.map_or(false, |p| p.len() > SEEDLEN) {
            return Err(NistDrbgError::PersonalizationTooLong);
        }

        let seed_material = build_seed_material(&entropy_input, personalization_string)?;
        self.key = [0u8; 32];
        self.v = [0u8; 16];
        self.reseed_counter = 1;
        self.uninstantiated = false;

        let mut sm = Some(seed_material);
        Self::aes256_ctr_update(&mut sm, &mut self.key, &mut self.v);
        Ok(())
    }

    /// Convenience: instantiate with entropy only (personalization = None).
    /// Panics on error (invalid state or input); for fallible init use `instantiate`.
    pub fn randombytes_init(&mut self, entropy_input: [u8; SEEDLEN]) {
        self.instantiate(entropy_input, None)
            .expect("valid instantiate")
    }

    /// Reseeds the DRBG (NIST 10.2.1.4.1). Fails if uninstantiated, in error state, or additional_input.len() > SEEDLEN.
    pub fn reseed(
        &mut self,
        entropy_input: [u8; SEEDLEN],
        additional_input: Option<&[u8]>,
    ) -> Result<(), NistDrbgError> {
        if self.uninstantiated {
            return Err(NistDrbgError::DrbgUninstantiated);
        }
        if self.in_error_state {
            return Err(NistDrbgError::DrbgInErrorState);
        }
        if additional_input.map_or(false, |a| a.len() > SEEDLEN) {
            return Err(NistDrbgError::AdditionalInputTooLong);
        }

        let seed_material = build_seed_material(&entropy_input, additional_input)?;
        let mut sm = Some(seed_material);
        Self::aes256_ctr_update(&mut sm, &mut self.key, &mut self.v);
        self.reseed_counter = 1;
        Ok(())
    }

    /// Erases internal state and marks the DRBG uninstantiated (NIST 9.4). Clears error state.
    pub fn uninstantiate(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.key.zeroize();
            self.v.zeroize();
        }
        #[cfg(not(feature = "zeroize"))]
        {
            self.key = [0; 32];
            self.v = [0; 16];
        }
        self.reseed_counter = 0;
        self.uninstantiated = true;
        self.in_error_state = false;
    }

    /// Core generate: optional additional_input, then output blocks, then Update(0), reseed_counter += 1.
    /// Caller must ensure instantiated, not in error state, reseed_counter <= RESEED_INTERVAL, dest.len() <= MAX_BYTES_PER_REQUEST.
    fn core_generate(
        &mut self,
        dest: &mut [u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), NistDrbgError> {
        if additional_input.map_or(false, |a| a.len() > SEEDLEN) {
            return Err(NistDrbgError::AdditionalInputTooLong);
        }

        if let Some(ai) = additional_input {
            let mut padded = [0u8; SEEDLEN];
            let len = ai.len().min(SEEDLEN);
            padded[..len].copy_from_slice(&ai[..len]);
            let mut pad = Some(padded);
            Self::aes256_ctr_update(&mut pad, &mut self.key, &mut self.v);
        }

        for chunk in dest.chunks_mut(16) {
            let count = u128::from_be_bytes(self.v);
            self.v.copy_from_slice(&(count + 1).to_be_bytes());
            let mut block = [0u8; 16];
            Self::aes256_ecb(&self.key, &self.v, &mut block);
            chunk.copy_from_slice(&block[..chunk.len()]);
        }

        let mut zero = Some([0u8; SEEDLEN]);
        Self::aes256_ctr_update(&mut zero, &mut self.key, &mut self.v);
        self.reseed_counter += 1;
        Ok(())
    }

    /// Generate with optional additional_input (full NIST generate). Use for NIST-complete or health-test KAT.
    pub fn try_fill_bytes_with_additional_input(
        &mut self,
        dest: &mut [u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), NistDrbgError> {
        if self.uninstantiated {
            return Err(NistDrbgError::DrbgUninstantiated);
        }
        if self.in_error_state {
            return Err(NistDrbgError::DrbgInErrorState);
        }
        if self.reseed_counter > RESEED_INTERVAL {
            return Err(NistDrbgError::ReseedRequired);
        }
        if dest.len() > MAX_BYTES_PER_REQUEST {
            return Err(NistDrbgError::RequestTooLong);
        }
        self.core_generate(dest, additional_input)
    }

    /// Runs known-answer health tests (NIST 11.3). Uses a temporary instance so health-test output is never used as random bits.
    /// On failure sets in_error_state and returns Err.
    pub fn run_health_test(&mut self) -> Result<(), NistDrbgError> {
        let mut t = AesState::new();

        // KAT instantiate: fixed entropy, no personalization
        let mut entropy = [0u8; SEEDLEN];
        for i in 0..SEEDLEN {
            entropy[i] = i as u8;
        }
        t.instantiate(entropy, None)?;

        // KAT generate: first 32 bytes
        let mut out = [0u8; 32];
        t.try_fill_bytes_with_additional_input(&mut out, None)?;
        let expected_first: [u8; 32] = [
            0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF,
            0x7A, 0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC,
            0x9A, 0xBC, 0xFD, 0xE7,
        ];
        if out != expected_first {
            self.in_error_state = true;
            return Err(NistDrbgError::DrbgInErrorState);
        }

        // KAT reseed: reseed then generate (verify reseed path runs and produces output)
        for i in 0..SEEDLEN {
            entropy[i] = (i + 10) as u8;
        }
        t.reseed(entropy, None)?;
        t.try_fill_bytes_with_additional_input(&mut out, None)?;
        // Reseed changed state; output must differ from all-zero
        if out == [0u8; 32] {
            self.in_error_state = true;
            return Err(NistDrbgError::DrbgInErrorState);
        }

        Ok(())
    }

    /// Fallible next u32 (little-endian). Returns `NistDrbgError` on reseed/request/state errors.
    #[inline]
    pub fn try_next_u32(&mut self) -> Result<u32, NistDrbgError> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes_with_additional_input(&mut bytes, None)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Fallible next u64 (little-endian). Returns `NistDrbgError` on reseed/request/state errors.
    #[inline]
    pub fn try_next_u64(&mut self) -> Result<u64, NistDrbgError> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes_with_additional_input(&mut bytes, None)?;
        Ok(u64::from_le_bytes(bytes))
    }
}

impl Default for AesState {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AesState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "AesState {{")?;
        writeln!(f, "  reseed_counter = {}", self.reseed_counter)?;
        writeln!(f, "  uninstantiated = {}", self.uninstantiated)?;
        writeln!(f, "  in_error_state = {}", self.in_error_state)?;
        writeln!(f, "}}")
    }
}

impl TryRng for AesState {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.try_fill_bytes_with_additional_input(dest, None)
            .unwrap_or_else(|e| panic!("DRBG: {}", e));
        Ok(())
    }
}

impl TryCryptoRng for AesState {}

#[cfg(feature = "zeroize")]
impl Zeroize for AesState {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.v.zeroize();
        self.reseed_counter = 0;
    }
}

#[cfg(test)]
mod tests {
    use core::convert::TryFrom;

    use rand_core::Rng;

    use super::*;

    const RNG_REF1: &str = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA19810F5392D076276EF41277C3AB6E94A4E3B7DCC104A05BB089D338BF55C72CAB375389A94BB920BD5D6DC9E7F2EC6FDE028B6F5724BB039F3652AD98DF8CE6C97013210B84BBE81388C3D141D61957C73BCDC5E5CD92525F46A2B757B03CAB5C337004A2DA35324A325713564DAE28F57ACC6DBE32A0726190BAA6B8A0A255AA1AD01E8DD569AA36D096256C420718A69D46D8DB1C6DD40606A0BE3C235BEFE623A90593F82D6A8F9F924E44E36BE87F7D26B8445966F9EE329C426C12521E85F6FD4ECD5D566BA0A3487125D79CC64";
    const RNG_REF2: &str = "C17E034061ED5EA817C41D61636281E816F817DCF753A91D97C018FF82FBC9B1728FC66AF114B57978FB6082B70D285140B26725AA5F7BB4409820F67E2D656EDACA30B5BB12EB5249CC3809B188CF0CC95B5AE0EFE8FC5887152CB6601B4CCF9FC411894FA0C0264EB51A481D4D7074FDF065053030C8A92BFCDD06BF18C8489C38D03784FD63001830E5A385A4A37866693F5BDAB8A8A25B519DDBF2D28268601D95BEED647E430484A227C023B0297A282F06C91376433BDE5EC3ABBA8C06B830C26452EA2FA7EDEA8DCFE20EAFCF8980B3D5AECEF89DD861ACEC1F5F7CD2AE6B3CDE3C1D80A2830DD0B9E8468AFAD161981074BEB33DF1CDFF9A5214F9F0";

    #[test]
    fn test_rng_rand_interface() {
        let mut data = [0u8; 256];
        let mut entropy_input = [0u8; 48];
        for i in 0..48 {
            entropy_input[i] = i as u8;
        }
        let mut rng_state = AesState::new();
        rng_state.randombytes_init(entropy_input);

        rng_state.fill_bytes(&mut data);
        let ref1_src = hex::decode(RNG_REF1).unwrap();
        let ref1 = <[u8; 256]>::try_from(ref1_src).unwrap();
        assert_eq!(data, ref1);

        rng_state.fill_bytes(&mut data);
        let ref2_src = hex::decode(RNG_REF2).unwrap();
        let ref2 = <[u8; 256]>::try_from(ref2_src).unwrap();
        assert_eq!(data, ref2);
    }

    #[test]
    fn test_try_next_u32_u64() {
        let mut entropy_input = [0u8; 48];
        for i in 0..48 {
            entropy_input[i] = i as u8;
        }
        let mut rng = AesState::new();
        rng.randombytes_init(entropy_input);
        let _ = rng.try_next_u32().unwrap();
        let _ = rng.try_next_u64().unwrap();
        let mut u32s = [0u32; 10];
        for x in &mut u32s {
            *x = rng.try_next_u32().unwrap();
        }
        let mut u64s = [0u64; 10];
        for x in &mut u64s {
            *x = rng.try_next_u64().unwrap();
        }
        assert_eq!(u32s.len(), 10);
        assert_eq!(u64s.len(), 10);
    }

    #[test]
    fn test_instantiate_personalization() {
        let mut entropy = [0u8; 48];
        for i in 0..48 {
            entropy[i] = i as u8;
        }
        let personalization: [u8; 48] = [0x40u8; 48]; // NIST example style
        let mut rng = AesState::new();
        rng.instantiate(entropy, Some(&personalization)).unwrap();
        let mut out = [0u8; 16];
        rng.try_fill_bytes(&mut out).unwrap();
        // Expected from seed_material = entropy XOR personalization (0x40 repeated); from implementation
        let expected: [u8; 16] = [
            0x07, 0x68, 0x40, 0xC1, 0x38, 0xC7, 0x4B, 0x16, 0x5B, 0x23, 0x7D, 0x82, 0xD4, 0x4C,
            0x2A, 0xCE,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn test_reseed() {
        let mut e1 = [0u8; 48];
        let mut e2 = [0u8; 48];
        for i in 0..48 {
            e1[i] = i as u8;
            e2[i] = (i + 20) as u8;
        }
        let mut rng = AesState::new();
        rng.instantiate(e1, None).unwrap();
        let mut a = [0u8; 32];
        rng.try_fill_bytes(&mut a).unwrap();
        rng.reseed(e2, None).unwrap();
        let mut b = [0u8; 32];
        rng.try_fill_bytes(&mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_reseed_interval() {
        let mut rng = AesState::new();
        let mut entropy = [0u8; 48];
        entropy[0] = 1;
        rng.instantiate(entropy, None).unwrap();

        let mut small_interval_rng = AesState::new();
        small_interval_rng.instantiate(entropy, None).unwrap();
        small_interval_rng.reseed_counter = RESEED_INTERVAL + 1;
        let mut buf = [0u8; 1];
        let err = small_interval_rng
            .try_fill_bytes_with_additional_input(&mut buf, None)
            .unwrap_err();
        assert_eq!(err, NistDrbgError::ReseedRequired);

        let mut entropy2 = [0u8; 48];
        entropy2[0] = 2;
        small_interval_rng.reseed(entropy2, None).unwrap();
        small_interval_rng.try_fill_bytes(&mut buf).unwrap();
    }

    #[test]
    fn test_request_too_long() {
        let mut rng = AesState::new();
        let entropy = [0u8; 48];
        rng.instantiate(entropy, None).unwrap();
        let mut buf = [0u8; MAX_BYTES_PER_REQUEST + 1];
        let err = rng
            .try_fill_bytes_with_additional_input(&mut buf, None)
            .unwrap_err();
        assert_eq!(err, NistDrbgError::RequestTooLong);
    }

    #[test]
    fn test_uninstantiate() {
        let mut rng = AesState::new();
        let entropy = [0u8; 48];
        rng.instantiate(entropy, None).unwrap();
        rng.uninstantiate();
        let mut buf = [0u8; 1];
        assert_eq!(
            rng.try_fill_bytes_with_additional_input(&mut buf, None)
                .unwrap_err(),
            NistDrbgError::DrbgUninstantiated
        );
        rng.instantiate(entropy, None).unwrap();
        rng.try_fill_bytes(&mut buf).unwrap();
    }

    #[test]
    fn test_health_test() {
        let mut rng = AesState::new();
        rng.run_health_test().unwrap();
    }

    #[test]
    fn test_additional_input_too_long() {
        let mut rng = AesState::new();
        let entropy = [0u8; 48];
        rng.instantiate(entropy, None).unwrap();
        let mut buf = [0u8; 1];
        let long: [u8; 49] = [0; 49];
        let err = rng
            .try_fill_bytes_with_additional_input(&mut buf, Some(&long[..]))
            .unwrap_err();
        assert_eq!(err, NistDrbgError::AdditionalInputTooLong);
    }

    #[test]
    fn test_personalization_too_long() {
        let mut rng = AesState::new();
        let entropy = [0u8; 48];
        let long: [u8; 49] = [0; 49];
        let err = rng.instantiate(entropy, Some(&long[..])).unwrap_err();
        assert_eq!(err, NistDrbgError::PersonalizationTooLong);
    }
}
