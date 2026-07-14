//! The dual-Regev / GPV KEM core over the shared ring `R_q` (from `lib-q-dkg`), hardened with an
//! explicit-rejection Fujisaki–Okamoto transform (FO⊥).
//!
//! The group public key is `t0 = B0·r ∈ R_q^MU` — the `t0` half of the DKG group key's BDLOP
//! commitment `T = commit(s; r) = (B0·r, ⟨b1,r⟩ + s)`. The **short** commitment randomness `r` is the
//! decryption key, and `lib-q-dkg` already `t`-of-`n` Shamir-shares it (each `SigningShare`'s `rand`
//! component). Because `t0 = B0·r` is a dual-Regev public key, this is a textbook GPV/dual-Regev KEM
//! whose decryption is the **linear** map `⟨r, ·⟩`, which Shamir-shares homomorphically. See
//! `LIBQ_API.md` §1.
//!
//! ```text
//! encap:   μ ← {0,1}^256 ;  (e, f, g) = XOF(pk, μ)   [e ternary R_q^MU ; f, g uniform [-B, B]]
//!          p = B0ᵀ·e + f  (∈ R_q^KAPPA)
//!          v = ⟨t0, e⟩ + g + encode(μ)  (∈ R_q)
//!          ct = (p, v) ;   K = KDF(pk, μ, ct)
//! decap:   w = v − ⟨r, p⟩ = encode(μ) + (g − ⟨r, f⟩ [+ flooding])   ⇒  μ' = decode(w)
//!          re-encrypt: ct' = Enc(pk, μ') ;  reject unless ct' == ct  (FO⊥) ;  K = KDF(pk, μ', ct)
//! ```
//!
//! **All encryption randomness is derived from `μ` via SHAKE-256 with integer-only rejection
//! sampling** — no floating point — so re-encryption is bit-exact on every platform/build and the
//! FO⊥ check `ct' == ct` is sound across encapsulator/decapsulator boundaries (the classic FO
//! determinism trap with platform-dependent `f64` Gaussians is avoided by construction).
//!
//! Correctness rests on `‖g − ⟨r, f⟩ + flooding‖∞ < q/4` and is **exact** (worst-case, not
//! probabilistic): with `‖r‖∞ ≤ 16` (a sum of ≤ 16 ternary vectors), `‖f‖∞, ‖g‖∞ ≤ B = 2^20` and
//! total flooding `≤ 16·2^40`, the noise is bounded by `≈ 2^44.1 ≪ q/4 ≈ 2^46`, so honest
//! decapsulation never fails and the FO check never falsely rejects (δ = 0). See
//! `SECURITY_ANALYSIS.md` §3.

extern crate alloc;

use alloc::vec::Vec;

use lib_q_dkg::lattice::bdlop::{
    self,
    KAPPA,
    MU,
};
use lib_q_dkg::lattice::ring::{
    N,
    Q,
    RQ_BYTES,
    Rq,
    RqNtt,
    centered_coeffs,
    from_ntt,
    ntt_mul_acc,
    ring_add,
    ring_sub,
    rq_from_le_bytes,
    rq_write_le_bytes,
    to_ntt,
};
use lib_q_sha3::{
    ExtendableOutput,
    Update,
    XofReader,
};
use rand_core::{
    CryptoRng,
    Rng,
};
use zeroize::Zeroize;

use crate::error::ThresholdKemError;

/// Uniform bound `B` on the encryption errors `f, g`: coefficients i.i.d. uniform in `[-B, B]`.
///
/// A dual-Regev ciphertext is a Module-LWE sample under `B0ᵀ` with error `f`; its IND-CPA security
/// is decision-MLWE at this noise level. Uniform (not Gaussian) noise is used so the FO
/// re-encryption is integer-only and platform-exact. The instance
/// `(n = MU·N = 6144, m = (KAPPA+1)·N = 10240, q ≈ 2^48, ternary secret, U(-B, B) error)` is gated
/// with the lattice-estimator — see `SECURITY_ANALYSIS.md` §2 for the archived run and the
/// cost-model spread.
pub const ENC_ERROR_BOUND: i64 = 1 << 20;

/// Uniform bound on the per-partial flooding noise added by
/// [`crate::threshold::partial_decap_masked`]: one ring element with coefficients i.i.d. uniform in
/// `[-FLOOD_BOUND, FLOOD_BOUND]`, drowning the share-dependent decryption noise `g − ⟨r, f⟩`
/// (`≲ 2^37.2`) by a factor `≥ 2^2.8` per partial. Sized so that even `16` flooded partials keep the
/// total decode noise `< q/4` with worst-case margin `≈ 3.9×` (see `SECURITY_ANALYSIS.md` §3–§4).
pub const FLOOD_BOUND: i64 = 1 << 40;

/// Recommended per-key decapsulation budget `Q_d` for the distributed path **when ciphertext
/// senders are authenticated** (only honest, XOF-derived ciphertexts reach `partial_decap*`).
/// Rényi-style leakage budget on the flooded hint `⟨r, f⟩ + flood`; see `SECURITY_ANALYSIS.md` §4
/// / `THRESHOLD_SECURITY.md` §3. Deployments MUST rotate the DKG key (reshare) before exceeding it.
pub const RECOMMENDED_DECAP_BUDGET: u64 = 1 << 20;

/// Conservative per-key decapsulation cap **when ciphertext senders are NOT authenticated** (any
/// partial might be a malformed-ciphertext probe). Set below the `≈63`-query length of the
/// malformed-ct insider probe (`THRESHOLD_SECURITY.md` §4–§5) so the probe can never complete on a
/// single key; the DKG key MUST be rotated (reshared) before this cap. This is a bounded-leakage
/// mitigation, **not** a cryptographic closure — the only assumption-free closure is a proof of
/// correct encryption (knowledge of `μ`); see `THRESHOLD_SECURITY.md` §5.
pub const MALFORMED_PROBE_SAFE_DECAPS: u64 = 32;

/// Number of message bits carried per ciphertext (one per low-order ring coefficient).
pub const MESSAGE_BITS: usize = 256;

const DOM_FO_SEED: &[u8] = b"lib-q-threshold-kem-lattice/fo-seed/v1";
const DOM_KDF: &[u8] = b"lib-q-threshold-kem-lattice/kdf/v1";
const DOM_CT_DIGEST: &[u8] = b"lib-q-threshold-kem-lattice/ct-digest/v1";
const DOM_PK_DIGEST: &[u8] = b"lib-q-threshold-kem-lattice/pk-digest/v1";

/// A KEM ciphertext: `p ∈ R_q^KAPPA` and `v ∈ R_q`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ciphertext {
    /// `p = B0ᵀ·e + f` (`KAPPA` ring elements).
    pub p: Vec<Rq>,
    /// `v = ⟨t0, e⟩ + g + encode(μ)` (one ring element).
    pub v: Rq,
}

impl Ciphertext {
    /// Serialized length in bytes: `(KAPPA + 1)·RQ_BYTES`.
    pub const BYTES: usize = (KAPPA + 1) * RQ_BYTES;

    /// Canonical little-endian serialization (`p` blocks, then `v`).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::BYTES);
        for pk in &self.p {
            rq_write_le_bytes(pk, &mut out);
        }
        rq_write_le_bytes(&self.v, &mut out);
        out
    }

    /// Parse from exactly [`Ciphertext::BYTES`] bytes; rejects non-canonical coefficients.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ThresholdKemError> {
        if bytes.len() != Self::BYTES {
            return Err(ThresholdKemError::EncodingCiphertext);
        }
        let mut p = Vec::with_capacity(KAPPA);
        for k in 0..KAPPA {
            let start = k * RQ_BYTES;
            p.push(
                rq_from_le_bytes(&bytes[start..start + RQ_BYTES])
                    .ok_or(ThresholdKemError::EncodingCiphertext)?,
            );
        }
        let v = rq_from_le_bytes(&bytes[KAPPA * RQ_BYTES..(KAPPA + 1) * RQ_BYTES])
            .ok_or(ThresholdKemError::EncodingCiphertext)?;
        Ok(Ciphertext { p, v })
    }

    /// Structural well-formedness: exactly `KAPPA` `p` elements. [`Ciphertext::from_bytes`]
    /// guarantees this for wire inputs; the check exists because the fields are `pub` and every
    /// secret-touching entry point ([`finish_decap`], the partial-decap functions) must fail
    /// closed on a hand-constructed short/long `p` rather than compute with it.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.p.len() == KAPPA
    }
}

/// Bilinear ring inner product `Σ_i a_i · b_i` (no conjugation). Used for `⟨t0, e⟩` and `⟨r, p⟩`.
///
/// Accumulated in the NTT domain: `2·len` forward transforms and **one** inverse transform total
/// (instead of one inverse per term) — bit-identical to summing individual products. The caller is
/// responsible for equal lengths; the length-validating entry points ([`Ciphertext::from_bytes`],
/// `decode_rand`, `ThresholdKemLatticePublicKey::t0`) establish the invariant for all wire inputs.
#[must_use]
pub fn ring_inner(a: &[Rq], b: &[Rq]) -> Rq {
    assert_eq!(a.len(), b.len(), "ring_inner: operand length mismatch");
    let mut acc = RqNtt::zero();
    for (ai, bi) in a.iter().zip(b.iter()) {
        ntt_mul_acc(&mut acc, &to_ntt(ai), &to_ntt(bi));
    }
    from_ntt(&acc)
}

/// Encode a 32-byte message into a ring element: bit `i` → coefficient `i` set to `⌊q/2⌋` (else 0).
///
/// **Branchless** — this runs on the recovered `μ'` during the FO⊥ re-encryption, so the bit
/// values must not steer control flow.
#[must_use]
pub fn encode_msg(mu: &[u8; 32]) -> Rq {
    let half = Q / 2;
    let mut coeffs = [0i64; N];
    for (i, c) in coeffs.iter_mut().enumerate().take(MESSAGE_BITS) {
        let bit = i64::from((mu[i / 8] >> (i % 8)) & 1);
        *c = half & bit.wrapping_neg(); // -(1) = all-ones mask, -(0) = 0
    }
    Rq::from_coeffs(coeffs)
}

/// Decode a (noisy) ring element back to a 32-byte message: coefficient closer to `±q/2` than to `0`
/// decodes to bit `1`. Robust to `‖noise‖∞ < q/4`.
///
/// **Branchless** — `w` carries the secret message plus decryption noise, so neither the
/// absolute value nor the threshold comparison may branch on it.
#[must_use]
pub fn decode_msg(w: &Rq) -> [u8; 32] {
    let quarter = Q / 4;
    let centered = centered_coeffs(w);
    let mut mu = [0u8; 32];
    for (i, &c) in centered.iter().enumerate().take(MESSAGE_BITS) {
        let s = c >> 63;
        let abs = (c ^ s) - s; // branchless |c|  (|c| ≤ q/2, no i64::MIN edge)
        let bit = ((quarter - abs) >> 63) & 1; // 1 iff |c| > quarter
        mu[i / 8] |= (bit as u8) << (i % 8);
    }
    mu
}

/// Derive the 32-byte shared secret. Binds `K` to the public key, the message, and the ciphertext.
#[must_use]
pub fn kdf(t0: &[Rq], mu: &[u8; 32], ct: &Ciphertext) -> [u8; 32] {
    kdf_with_digest(&pk_digest(t0), mu, ct)
}

/// [`kdf`] with the public-key digest precomputed — lets [`encapsulate`] / [`finish_decap`] hash
/// the ~49 KB `t0` once per operation instead of once per use (same absorbed bytes, same output).
fn kdf_with_digest(pk_dig: &[u8; 32], mu: &[u8; 32], ct: &Ciphertext) -> [u8; 32] {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(DOM_KDF);
    h.update(pk_dig);
    h.update(mu);
    h.update(&ct_digest(ct));
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

fn ct_digest(ct: &Ciphertext) -> [u8; 32] {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(DOM_CT_DIGEST);
    for pk in &ct.p {
        absorb_poly(&mut h, pk);
    }
    absorb_poly(&mut h, &ct.v);
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

/// Compact digest of the public key `t0` (absorbed into the FO seed and the KDF for multi-target
/// separation).
fn pk_digest(t0: &[Rq]) -> [u8; 32] {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(DOM_PK_DIGEST);
    for tk in t0 {
        absorb_poly(&mut h, tk);
    }
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

fn absorb_poly(h: &mut lib_q_sha3::Shake256, p: &Rq) {
    // One buffered update per polynomial (identical absorbed stream to per-coefficient updates,
    // without N=1024 separate calls into the sponge).
    let mut buf = [0u8; 8 * N];
    for (chunk, c) in buf.chunks_exact_mut(8).zip(centered_coeffs(p)) {
        chunk.copy_from_slice(&c.to_le_bytes());
    }
    h.update(&buf);
}

// ---------------------------------------------------------------------------
// Integer-only deterministic samplers (drive the FO re-encryption)
// ---------------------------------------------------------------------------

/// Ternary ring element from the XOF (coefficients i.i.d. uniform in `{-1, 0, +1}`, 2-bit
/// rejection — same distribution as `lib_q_dkg`'s `sample_ternary_poly`, but XOF-driven).
fn xof_ternary_poly(rd: &mut impl XofReader) -> Rq {
    let mut coeffs = [0i64; N];
    for c in &mut coeffs {
        let v = loop {
            let mut b = [0u8; 1];
            rd.read(&mut b);
            let two = b[0] & 0b11;
            if two < 3 {
                break i64::from(two) - 1;
            }
        };
        *c = v.rem_euclid(Q);
    }
    Rq::from_coeffs(coeffs)
}

/// Ring element with coefficients i.i.d. uniform in `[-bound, bound]`, by unbiased rejection over
/// `[0, 2·bound + 1)` from the XOF.
fn xof_bounded_poly(rd: &mut impl XofReader, bound: i64) -> Rq {
    debug_assert!(bound > 0);
    let span = 2 * (bound as u64) + 1;
    let zone = u64::MAX - (u64::MAX % span);
    let mut coeffs = [0i64; N];
    for c in &mut coeffs {
        let v = loop {
            let mut b = [0u8; 8];
            rd.read(&mut b);
            let r = u64::from_le_bytes(b);
            if r < zone {
                break (r % span) as i64 - bound;
            }
        };
        *c = v.rem_euclid(Q);
    }
    Rq::from_coeffs(coeffs)
}

/// Ring element with coefficients i.i.d. uniform in `[-bound, bound]` from an RNG (the flooding
/// noise in [`crate::threshold::partial_decap_masked`] — fresh randomness, not FO-derived).
pub(crate) fn sample_bounded_poly<R: CryptoRng + Rng>(rng: &mut R, bound: i64) -> Rq {
    debug_assert!(bound > 0);
    let span = 2 * (bound as u64) + 1;
    let zone = u64::MAX - (u64::MAX % span);
    let mut coeffs = [0i64; N];
    for c in &mut coeffs {
        let v = loop {
            let mut b = [0u8; 8];
            rng.fill_bytes(&mut b);
            let r = u64::from_le_bytes(b);
            if r < zone {
                break (r % span) as i64 - bound;
            }
        };
        *c = v.rem_euclid(Q);
    }
    Rq::from_coeffs(coeffs)
}

// ---------------------------------------------------------------------------
// Encapsulation / decapsulation (FO⊥)
// ---------------------------------------------------------------------------

/// Deterministic encryption of `μ` under `t0`: all randomness `(e, f, g)` is expanded from
/// `SHAKE-256(dom ‖ pk_digest ‖ μ)` with integer-only sampling, so this function is a bit-exact,
/// platform-independent function of `(t0, μ)` — the property the FO⊥ re-encryption check rests on.
#[must_use]
pub fn encapsulate_derand(t0: &[Rq], mu: &[u8; 32]) -> Ciphertext {
    encapsulate_derand_with_digest(t0, &pk_digest(t0), mu)
}

/// [`encapsulate_derand`] with the public-key digest precomputed (same XOF seed, same output).
///
/// The ephemeral secret `e` is forward-NTT'd **once** and shared by the `B0ᵀ·e` and `⟨t0, e⟩`
/// products (bit-identical values, ~2.4× fewer transforms); `e` and its NTT image are zeroized
/// before returning.
fn encapsulate_derand_with_digest(t0: &[Rq], pk_dig: &[u8; 32], mu: &[u8; 32]) -> Ciphertext {
    assert_eq!(t0.len(), MU, "encapsulate_derand_with_digest: t0 length must be MU");
    let key = bdlop::key();

    let mut h = lib_q_sha3::Shake256::default();
    h.update(DOM_FO_SEED);
    h.update(pk_dig);
    h.update(mu);
    let mut rd = h.finalize_xof();

    // Ephemeral secret e ∈ R_q^MU (ternary) and errors f ∈ R_q^KAPPA, g ∈ R_q (uniform [-B, B]).
    // XOF draw order (e, then f per p element, then g) is wire-frozen by the KATs.
    let mut e: Vec<Rq> = (0..MU).map(|_| xof_ternary_poly(&mut rd)).collect();
    let mut e_ntt: Vec<RqNtt> = e.iter().map(to_ntt).collect();
    let b0te = bdlop::b0_transpose_apply_ntt(key, &e_ntt); // KAPPA elements
    let mut p = Vec::with_capacity(KAPPA);
    for pk in &b0te {
        p.push(ring_add(pk, &xof_bounded_poly(&mut rd, ENC_ERROR_BOUND)));
    }

    // ⟨t0, e⟩, reusing e's forward transform.
    let mut te_acc = RqNtt::zero();
    for (ti, ei) in t0.iter().zip(e_ntt.iter()) {
        ntt_mul_acc(&mut te_acc, &to_ntt(ti), ei);
    }
    let mut te = from_ntt(&te_acc);
    let g = xof_bounded_poly(&mut rd, ENC_ERROR_BOUND);
    let v = ring_add(&ring_add(&te, &g), &encode_msg(mu));

    e.zeroize();
    e_ntt.zeroize();
    te_acc.zeroize();
    te.zeroize();

    Ciphertext { p, v }
}

/// The FO-expanded encryption randomness `(e, f, g)` — the prover's witness for the ZK **proof of
/// correct encryption** (`lib-q-zk-encryption-proof`). Because it is the *deterministic* SHAKE-256
/// expansion of `(t0, μ)`, anyone who knows the secret message `μ` can recompute it (so exposing this
/// leaks no NEW secret — the security rests on `μ`), but it is the ephemeral randomness and so
/// zeroizes on drop. **Prover-only.**
pub struct FoWitness {
    /// Ephemeral secret `e ∈ R_q^MU` (ternary).
    pub e: Vec<Rq>,
    /// Errors `f ∈ R_q^KAPPA` (bounded), one per `p`-component.
    pub f: Vec<Rq>,
    /// Error `g ∈ R_q` (bounded).
    pub g: Rq,
    /// The public key digest `pk_digest(t0)` used in the FO seed `SHAKE256(dom ‖ pk_digest ‖ μ)` — the
    /// second field of the sponge preimage the ZK proof reconstructs. Public (a hash of the public
    /// key), so not zeroized.
    pub pk_digest: [u8; 32],
}

impl Drop for FoWitness {
    fn drop(&mut self) {
        self.e.zeroize();
        self.f.zeroize();
        self.g.zeroize();
    }
}

/// Re-derive the FO encryption witness `(e, f, g)` for `(t0, μ)` — the **exact** expansion
/// [`encapsulate_derand`] uses (draw order: all of `e`, then each `f_k`, then `g`; wire-frozen by the
/// KATs). Exposed for the prover of the ZK proof of correct encryption, which must fold the witness on
/// the same bytes the ciphertext committed. **Prover-only** — it requires the secret `μ`.
#[must_use]
pub fn fo_expand_witness(t0: &[Rq], mu: &[u8; 32]) -> FoWitness {
    assert_eq!(t0.len(), MU, "fo_expand_witness: t0 length must be MU");
    let pk_dig = pk_digest(t0);
    let mut h = lib_q_sha3::Shake256::default();
    h.update(DOM_FO_SEED);
    h.update(&pk_dig);
    h.update(mu);
    let mut rd = h.finalize_xof();
    let e: Vec<Rq> = (0..MU).map(|_| xof_ternary_poly(&mut rd)).collect();
    let f: Vec<Rq> = (0..KAPPA)
        .map(|_| xof_bounded_poly(&mut rd, ENC_ERROR_BOUND))
        .collect();
    let g = xof_bounded_poly(&mut rd, ENC_ERROR_BOUND);
    FoWitness {
        e,
        f,
        g,
        pk_digest: pk_dig,
    }
}

/// Encapsulate to the group public key `t0` (`MU` ring elements): sample a fresh message and produce
/// `(shared_secret, ciphertext)`. `t0` is the `B0·r` half of the DKG group key.
pub fn encapsulate<R: CryptoRng + Rng>(t0: &[Rq], rng: &mut R) -> ([u8; 32], Ciphertext) {
    let mut mu = [0u8; 32];
    rng.fill_bytes(&mut mu);
    let pk_dig = pk_digest(t0);
    let ct = encapsulate_derand_with_digest(t0, &pk_dig, &mu);
    let ss = kdf_with_digest(&pk_dig, &mu, &ct);
    mu.zeroize();
    (ss, ct)
}

/// Recover the shared secret from the ciphertext and the reconstructed inner product `⟨r, p⟩`,
/// enforcing the FO⊥ validity check.
///
/// `rp = ⟨r, p⟩ (+ flooding)` is assembled by the caller from a threshold of partial decapsulations
/// (see [`crate::combine`] / [`crate::decapsulate_reference`]). This decodes `w = v − rp` to `μ'`,
/// **re-encrypts `μ'` and rejects unless the re-encryption equals `ct`** (explicit rejection): a
/// malformed or mauled ciphertext yields [`ThresholdKemError::InvalidCiphertext`], never a key. A
/// structurally malformed `ct` (wrong `p` element count, possible because the fields are `pub`)
/// fails closed with [`ThresholdKemError::EncodingCiphertext`] before any secret is touched.
pub fn finish_decap(t0: &[Rq], ct: &Ciphertext, rp: &Rq) -> Result<[u8; 32], ThresholdKemError> {
    if !ct.is_well_formed() {
        return Err(ThresholdKemError::EncodingCiphertext);
    }
    let pk_dig = pk_digest(t0);
    let mut w = ring_sub(&ct.v, rp);
    let mut mu = decode_msg(&w);
    let mut recheck = encapsulate_derand_with_digest(t0, &pk_dig, &mu);
    let ok = ct_eq(&recheck, ct);
    // The decode input and the re-encryption are μ'-derived; clear them on both paths.
    w.zeroize();
    recheck.p.zeroize();
    recheck.v.zeroize();
    if !ok {
        mu.zeroize();
        return Err(ThresholdKemError::InvalidCiphertext);
    }
    let ss = kdf_with_digest(&pk_dig, &mu, ct);
    mu.zeroize();
    Ok(ss)
}

/// Constant-time ciphertext equality (no early exit within the data): fold the XOR-difference of
/// the coefficient arrays directly — no serialization, no allocation. The FO⊥ comparison must not
/// leak *where* a forged ciphertext diverges. The element-count check is a **hard** (release-
/// enforced) structural guard: a hand-built `ct` with the wrong `p` length compares unequal
/// instead of silently truncating the comparison. Both sides hold canonical `[0, q)` coefficients
/// (`recheck` from the ring ops, `ct` from `from_bytes` / the `is_well_formed`-gated entry), so
/// coefficient equality coincides with serialized-byte equality; a non-canonical hand-built `ct`
/// can only fail closed (reject), never alias to an accept.
fn ct_eq(a: &Ciphertext, b: &Ciphertext) -> bool {
    if a.p.len() != b.p.len() {
        return false;
    }
    let mut diff = 0i64;
    for (ap, bp) in a.p.iter().zip(b.p.iter()) {
        for (x, y) in ap.coeffs.iter().zip(bp.coeffs.iter()) {
            diff |= x ^ y;
        }
    }
    for (x, y) in a.v.coeffs.iter().zip(b.v.coeffs.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
