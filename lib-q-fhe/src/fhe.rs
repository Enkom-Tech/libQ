use sha2::{
    Digest,
    Sha256,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FheSecretKey {
    pub params: FheParams,
    seed: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FheParams {
    pub dimension: usize,
    pub modulus: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    pub params: FheParams,
    pub nonce: u64,
    pub body: Vec<i32>,
    pub mask: Vec<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvalOp {
    AddConstant(i32),
    AddCiphertext(Ciphertext),
    MulConstant(i32),
}

/// Errors produced by this crate's FHE operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FheError {
    /// `body`, `mask`, and `params.dimension` must all be equal in length.
    DimensionMismatch {
        expected: usize,
        body_len: usize,
        mask_len: usize,
    },
    /// The two ciphertexts supplied to `eval` or `decrypt` have different parameter sets.
    ParamMismatch,
}

impl core::fmt::Display for FheError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FheError::DimensionMismatch { expected, body_len, mask_len } => write!(
                f,
                "ciphertext dimension mismatch: params.dimension={expected}, \
                 body.len={body_len}, mask.len={mask_len}"
            ),
            FheError::ParamMismatch => write!(f, "ciphertext parameter mismatch"),
        }
    }
}

/// Validate that `body.len() == mask.len() == params.dimension` for a [`Ciphertext`].
///
/// This must be called before any indexing into `body` or `mask` to prevent
/// out-of-bounds panics on crafted ciphertexts.
pub fn validate_ciphertext(ct: &Ciphertext) -> Result<(), FheError> {
    let dim = ct.params.dimension;
    if ct.body.len() != dim || ct.mask.len() != dim {
        return Err(FheError::DimensionMismatch {
            expected: dim,
            body_len: ct.body.len(),
            mask_len: ct.mask.len(),
        });
    }
    Ok(())
}

impl Ciphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(4 + 4 + 8 + (self.body.len() * 4) + 4 + (self.mask.len() * 4));
        out.extend_from_slice(&(self.params.dimension as u32).to_le_bytes());
        out.extend_from_slice(&self.params.modulus.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&(self.body.len() as u32).to_le_bytes());
        for coeff in &self.body {
            out.extend_from_slice(&coeff.to_le_bytes());
        }
        out.extend_from_slice(&(self.mask.len() as u32).to_le_bytes());
        for coeff in &self.mask {
            out.extend_from_slice(&coeff.to_le_bytes());
        }
        out
    }
}

fn mod_q(x: i64, q: i32) -> i32 {
    let q64 = q as i64;
    let r = x.rem_euclid(q64);
    r as i32
}

fn coeff_from_seed(seed: u64, nonce: u64, index: usize, modulus: i32) -> i32 {
    let mut hasher = Sha256::new();
    hasher.update(seed.to_le_bytes());
    hasher.update(nonce.to_le_bytes());
    hasher.update((index as u64).to_le_bytes());
    let digest = hasher.finalize();
    let mut first8 = [0u8; 8];
    first8.copy_from_slice(&digest[..8]);
    let raw = u64::from_le_bytes(first8);
    mod_q(raw as i64, modulus)
}

pub fn fhe_keygen(seed: u64, dimension: usize, modulus: i32) -> FheSecretKey {
    assert!(dimension > 0, "dimension must be positive");
    assert!(modulus > 1, "modulus must be > 1");
    FheSecretKey {
        params: FheParams { dimension, modulus },
        seed,
    }
}

pub fn encrypt(key: &FheSecretKey, plaintext: &[i32], nonce: u64) -> Ciphertext {
    assert!(
        plaintext.len() <= key.params.dimension,
        "plaintext length exceeds dimension"
    );

    let modulus = key.params.modulus;
    let mut body = vec![0i32; key.params.dimension];
    let mut mask = vec![0i32; key.params.dimension];
    for i in 0..key.params.dimension {
        let plain = plaintext.get(i).copied().unwrap_or(0);
        let mask_i = coeff_from_seed(key.seed, nonce, i, modulus);
        mask[i] = mask_i;
        body[i] = mod_q(plain as i64 + mask_i as i64, modulus);
    }

    Ciphertext {
        params: key.params,
        nonce,
        body,
        mask,
    }
}

/// Homomorphically evaluate `op` on `ciphertext`.
///
/// Returns [`FheError::DimensionMismatch`] if `ciphertext` (or the RHS for
/// `AddCiphertext`) has `body`/`mask` lengths inconsistent with
/// `params.dimension`, preventing an out-of-bounds panic.
pub fn eval(ciphertext: &Ciphertext, op: EvalOp) -> Result<Ciphertext, FheError> {
    validate_ciphertext(ciphertext)?;
    let modulus = ciphertext.params.modulus;
    let mut out = ciphertext.clone();
    match op {
        EvalOp::AddConstant(c) => {
            for i in 0..out.body.len() {
                out.body[i] = mod_q(out.body[i] as i64 + c as i64, modulus);
            }
        }
        EvalOp::MulConstant(c) => {
            for i in 0..out.body.len() {
                out.body[i] = mod_q(out.body[i] as i64 * c as i64, modulus);
                out.mask[i] = mod_q(out.mask[i] as i64 * c as i64, modulus);
            }
        }
        EvalOp::AddCiphertext(ref rhs) => {
            validate_ciphertext(rhs)?;
            if out.params != rhs.params {
                return Err(FheError::ParamMismatch);
            }
            for i in 0..out.body.len() {
                out.body[i] = mod_q(out.body[i] as i64 + rhs.body[i] as i64, modulus);
                out.mask[i] = mod_q(out.mask[i] as i64 + rhs.mask[i] as i64, modulus);
            }
        }
    }
    Ok(out)
}

/// Decrypt `ciphertext` with `key`.
///
/// Returns [`FheError::ParamMismatch`] if the key and ciphertext parameters
/// differ, or [`FheError::DimensionMismatch`] if the ciphertext vectors are
/// inconsistent with `params.dimension`, preventing an out-of-bounds panic.
pub fn decrypt(key: &FheSecretKey, ciphertext: &Ciphertext) -> Result<Vec<i32>, FheError> {
    if key.params != ciphertext.params {
        return Err(FheError::ParamMismatch);
    }
    validate_ciphertext(ciphertext)?;
    let modulus = key.params.modulus;
    let mut plain = vec![0i32; ciphertext.body.len()];
    for (i, p) in plain.iter_mut().enumerate().take(ciphertext.body.len()) {
        *p = mod_q(
            ciphertext.body[i] as i64 - ciphertext.mask[i] as i64,
            modulus,
        );
    }
    Ok(plain)
}
