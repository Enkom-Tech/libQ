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
use zeroize::{
    Zeroize,
    Zeroizing,
};

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

/// Public accessor for the public-key digest of `t0` — `pk_digest(t0)`, the value absorbed into the
/// FO seed `SHAKE256(dom ‖ pk_digest ‖ μ)`. Exposed so an encryption-proof **verifier** (which holds
/// `t0` but never the witness) can rebuild the sponge's pk-binding public values itself, rather than
/// trusting a prover-supplied digest. Thin wrapper over the internal [`pk_digest`].
#[must_use]
pub fn pk_digest_of(t0: &[Rq]) -> [u8; 32] {
    pk_digest(t0)
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
    for (chunk, c) in buf
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip(centered_coeffs(p))
    {
        chunk.copy_from_slice(&c.to_le_bytes());
    }
    h.update(&buf);
}

// ---------------------------------------------------------------------------
// Integer-only deterministic samplers (drive the FO re-encryption)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Constant-time rejection sampling (H1)
// ---------------------------------------------------------------------------
//
// The FO-derived samplers below draw a **fixed** byte budget, process every attempt with no
// early exit and no data-dependent branch, and constant-time-compact the first `n` accepted
// coefficients. Neither the number of XOF bytes consumed nor the accept/reject pattern — both
// deterministic functions of the secret `μ` — is observable through timing or memory-access side
// channels. The emitted coefficients are **bit-identical** to unbounded rejection sampling (they
// are the first `n` accepts of the same byte stream); only the consumed-byte boundary becomes
// fixed. That boundary move shifts where `f`/`g` begin in the XOF stream, so it is a `v1 → v2`
// wire change (regenerate `tests/data/*_v1.bin`; see `tests/kat.rs`). The distribution is exactly
// the analyzed one (uniform ternary / uniform `[-B, B]`), so the core-SVP analysis is unchanged.
//
// Budgets are sized so an underflow (fewer than `n` accepts in the budget) — which would degrade
// to a zero-padded tail — occurs with probability `< 2^-128`, below the scheme's other failure
// terms; a `debug_assert` catches it in tests.

/// Fixed attempt budget for the whole ternary secret `e` (`MU·N` coefficients, 1 byte/attempt).
/// Accept probability 3/4 per attempt; `P(fewer than MU·N=6144 accepts in 9216 attempts) < 2^-140`
/// (Chernoff), and 9216 pads the proof's ternary trace to 16384 rows. **Public** so the ZK
/// encryption-proof composition can slice `e`'s XOF sub-stream at the identical boundary.
pub const E_TERNARY_ATTEMPTS: usize = 9216;
/// Slack attempts added to a bounded draw's coefficient count to fix its byte budget. The bounded
/// rejection probability is `≈ 2^-43`, so 128 extra attempts drive the underflow probability far below
/// `2^-128` for any draw size. **Public** so the ZK encryption-proof composition slices each bounded
/// sub-stream (`f` as one flat `KAPPA·N` draw, `g` as one `N` draw) at the identical boundary.
pub const BOUNDED_SLACK: usize = 128;

/// Fixed bounded-attempt budget (8-byte draws) for a flat draw of `n_coeffs` coefficients.
#[inline]
#[must_use]
pub const fn bounded_attempts(n_coeffs: usize) -> usize {
    n_coeffs + BOUNDED_SLACK
}

/// Rejection-sampling span for the bounded error `[-B, B]`: `2·B + 1`. A **compile-time constant**,
/// so `r % SPAN` lowers to a branch-free multiply–shift (constant-time), unlike the old runtime
/// `bound` parameter.
const SPAN: u64 = 2 * (ENC_ERROR_BOUND as u64) + 1;
/// Unbiased acceptance region: a draw `r` is accepted iff `r < ZONE` (removes modulo bias).
const ZONE: u64 = u64::MAX - (u64::MAX % SPAN);

/// Constant-time equality mask: all-ones (`u64::MAX`) iff `a == b`, else `0`.
#[inline]
fn ct_eq_mask(a: u64, b: u64) -> u64 {
    let d = a ^ b;
    // (d | -d) has its top bit set iff d != 0; shift to bit 0, then `x - 1` flips the sense.
    let nz = ((d | d.wrapping_neg()) >> 63) & 1; // 1 iff d != 0
    nz.wrapping_sub(1) // d != 0 -> 0 ; d == 0 -> all-ones
}

/// Constant-time unsigned less-than mask: all-ones (`u64::MAX`) iff `a < b`, else `0`. Works over the
/// **full** `u64` range (`r` and `ZONE` reach `≈ 2^64`) by comparing 32-bit halves — each half is
/// `< 2^32`, so `wrapping_sub`'s bit 63 is exactly the half's borrow. No branch, no secret index.
#[inline]
fn ct_lt_mask(a: u64, b: u64) -> u64 {
    // 1 iff x < y, for x, y < 2^32.
    let lt32 = |x: u64, y: u64| (x.wrapping_sub(y) >> 63) & 1;
    let (ah, al) = (a >> 32, a & 0xFFFF_FFFF);
    let (bh, bl) = (b >> 32, b & 0xFFFF_FFFF);
    let hi_eq = ct_eq_mask(ah, bh) & 1; // 1 iff high halves equal
    let bit = lt32(ah, bh) | (hi_eq & lt32(al, bl));
    bit.wrapping_neg()
}

/// Constant-time select: `x` where `mask` is all-ones, `y` where `mask` is `0`.
#[inline]
fn ct_select_i64(mask: u64, x: i64, y: i64) -> i64 {
    (((x as u64) & mask) | ((y as u64) & !mask)) as i64
}

/// Constant-time select over `u64`: `x` where `mask` is all-ones, `y` where `mask` is `0`.
#[inline]
fn ct_select_u64(mask: u64, x: u64, y: u64) -> u64 {
    (x & mask) | (y & !mask)
}

/// One oblivious compare-exchange of a sorting network: for indices `a < b`, put the smaller key
/// (and its paired value) at `a`. Fixed indices, branch-free — constant-time.
#[inline]
fn ct_cae(key: &mut [u64], val: &mut [i64], a: usize, b: usize) {
    let swap = ct_lt_mask(key[b], key[a]); // all-ones iff key[b] < key[a] ⇒ swap needed
    let (ka, kb) = (key[a], key[b]);
    key[a] = ct_select_u64(swap, kb, ka);
    key[b] = ct_select_u64(swap, ka, kb);
    let (va, vb) = (val[a], val[b]);
    val[a] = ct_select_i64(swap, vb, va);
    val[b] = ct_select_i64(swap, va, vb);
}

/// Batcher odd–even mergesort over a power-of-two-length `(key, val)` array, ascending by `key`.
/// The comparator sequence depends only on the length (a public quantity), and every exchange is a
/// branch-free [`ct_cae`], so the whole sort is constant-time. `O(n·log²n)` comparators.
fn batcher_sort(key: &mut [u64], val: &mut [i64]) {
    let n = key.len();
    debug_assert!(n.is_power_of_two());
    let mut p = 1;
    while p < n {
        let mut k = p;
        while k >= 1 {
            let mut j = k % p;
            while j + k < n {
                let mut i = 0;
                while i < k {
                    let (a, b) = (i + j, i + j + k);
                    // Guard b < n and the odd–even partition predicate (public indices only).
                    if b < n && (i + j) / (2 * p) == (i + j + k) / (2 * p) {
                        ct_cae(key, val, a, b);
                    }
                    i += 1;
                }
                j += 2 * k;
            }
            k >>= 1;
        }
        p <<= 1;
    }
}

/// Constant-time stable compaction: write the first `out.len()` accepted `vals` (in stream order;
/// `accs[k]` is the all-ones/`0` accept mask of attempt `k`) into `out`.
///
/// Implemented as an oblivious **Batcher sort** (`O(budget·log²budget)` compare-exchanges) rather than
/// the naïve `O(out.len()·budget)` masked scan — for the flat `e`/`f` draws this is ~1–2 M comparators
/// vs ~50–90 M selects per `encapsulate` (run twice per decapsulation via FO re-encryption). Each
/// attempt gets a **distinct** sort key — `k` if accepted, `budget + k` if rejected — so ascending sort
/// carries the accepted values to the front *in original stream order* (identical output to the naïve
/// compaction; the `#[cfg(test)] ct_compact_ref` oracle pins this). The comparator schedule depends
/// only on the (public) budget and every exchange is branch-free, so no secret-dependent branch or
/// memory access remains. If fewer than `out.len()` attempts are accepted (probability `< 2^-128` at
/// the chosen budgets), a rejected (`≥ budget`) key lands in the prefix — caught by the debug assert.
fn ct_compact(vals: &[i64], accs: &[u64], out: &mut [i64]) {
    debug_assert_eq!(vals.len(), accs.len());
    let budget = vals.len();
    let n = out.len();
    let np = budget.next_power_of_two();
    // Distinct keys: accepted → k, rejected → budget + k, padding → u64::MAX (sorts to the tail).
    // `key` encodes the accept pattern (a function of the secret μ), so it is zeroized alongside `val`.
    let mut key = Zeroizing::new(alloc::vec![u64::MAX; np]);
    let mut val = Zeroizing::new(alloc::vec![0i64; np]);
    for k in 0..budget {
        key[k] = ct_select_u64(accs[k], k as u64, (budget + k) as u64);
        val[k] = vals[k];
    }
    batcher_sort(&mut key, &mut val);
    out.copy_from_slice(&val[..n]);
    debug_assert!(
        n == 0 || key[n - 1] < budget as u64,
        "constant-time sampler budget underflow (should be < 2^-128)"
    );
}

/// The ternary secret `e ∈ R_q^MU` (`MU·N` coefficients i.i.d. uniform in `{-1, 0, +1}`), drawn
/// from the XOF in **constant time** (see the module note). Fixed budget [`E_TERNARY_ATTEMPTS`],
/// 2-bit rejection (`two = b & 0b11`, accept iff `two < 3`, value `two − 1`), branch-free.
fn xof_ternary_e(rd: &mut impl XofReader) -> Vec<Rq> {
    let mut buf = Zeroizing::new(alloc::vec![0u8; E_TERNARY_ATTEMPTS]);
    rd.read(&mut buf);
    let mut vals = Zeroizing::new(alloc::vec![0i64; E_TERNARY_ATTEMPTS]);
    let mut accs = Zeroizing::new(alloc::vec![0u64; E_TERNARY_ATTEMPTS]);
    for (k, &b) in buf.iter().enumerate() {
        let two = u64::from(b & 0b11);
        let acc = ct_lt_mask(two, 3); // all-ones iff two < 3
        vals[k] = ct_select_i64(acc, two as i64 - 1, 0);
        accs[k] = acc;
    }
    let mut flat = Zeroizing::new(alloc::vec![0i64; MU * N]);
    ct_compact(&vals, &accs, &mut flat);
    let mut polys = Vec::with_capacity(MU);
    for r in 0..MU {
        let mut coeffs = [0i64; N];
        for (j, c) in coeffs.iter_mut().enumerate() {
            *c = flat[r * N + j].rem_euclid(Q);
        }
        polys.push(Rq::from_coeffs(coeffs));
    }
    polys
}

/// A flat run of bounded error ring elements (`n_polys · N` coefficients i.i.d. uniform in `[-B, B]`,
/// reshaped into `n_polys` ring elements), drawn from the XOF in **constant time**: one fixed budget
/// [`bounded_attempts(n_polys·N)`](bounded_attempts) processed with branch-free 64-bit rejection
/// (accept iff `r < ZONE`, value `(r mod SPAN) − B`) and constant-time compaction. Drawing `f` as one
/// flat block (rather than `KAPPA` per-element draws) lets the ZK encryption proof bind it with a
/// single bounded trace over one contiguous byte range.
fn xof_bounded_flat(rd: &mut impl XofReader, n_polys: usize) -> Vec<Rq> {
    let n_coeffs = n_polys * N;
    let mut buf = Zeroizing::new(alloc::vec![0u8; bounded_attempts(n_coeffs) * 8]);
    rd.read(&mut buf);
    let mut flat = ct_bounded_coeffs(&buf, n_coeffs);
    let mut polys = Vec::with_capacity(n_polys);
    for r in 0..n_polys {
        let mut coeffs = [0i64; N];
        for (j, c) in coeffs.iter_mut().enumerate() {
            *c = flat[r * N + j];
        }
        polys.push(Rq::from_coeffs(coeffs));
    }
    flat.zeroize();
    polys
}

/// One bounded error ring element (the FO error `g`), drawn as a single-element flat run.
fn xof_bounded_poly(rd: &mut impl XofReader) -> Rq {
    let mut polys = xof_bounded_flat(rd, 1);
    polys
        .pop()
        .expect("xof_bounded_flat(1) yields one ring element")
}

/// Ring element with coefficients i.i.d. uniform in `[-bound, bound]` from an RNG (the flooding noise
/// in [`crate::threshold::partial_decap_masked`] — **fresh** per-decap randomness at bound `2^40`, not
/// the FO-derived encryption error). Its randomness is independent of the long-term secret `μ`, so its
/// rejection timing is not an `μ` side channel (the H1 concern); it keeps the classic rejection loop
/// with a runtime `bound`.
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

/// Shared constant-time core of the bounded samplers: interpret `buf` as
/// [`bounded_attempts(n_coeffs)`](bounded_attempts) little-endian `u64` draws and compact the first
/// `n_coeffs` accepted centered coefficients (mod `Q`).
fn ct_bounded_coeffs(buf: &[u8], n_coeffs: usize) -> Vec<i64> {
    let attempts = bounded_attempts(n_coeffs);
    debug_assert_eq!(buf.len(), attempts * 8);
    let mut vals = Zeroizing::new(alloc::vec![0i64; attempts]);
    let mut accs = Zeroizing::new(alloc::vec![0u64; attempts]);
    for k in 0..attempts {
        let mut b8 = [0u8; 8];
        b8.copy_from_slice(&buf[k * 8..k * 8 + 8]);
        let r = u64::from_le_bytes(b8);
        let acc = ct_lt_mask(r, ZONE); // all-ones iff r < ZONE
        // `r % SPAN` is constant-time (SPAN is a compile-time constant); masked out on reject.
        vals[k] = ct_select_i64(acc, (r % SPAN) as i64 - ENC_ERROR_BOUND, 0);
        accs[k] = acc;
    }
    let mut flat = alloc::vec![0i64; n_coeffs];
    ct_compact(&vals, &accs, &mut flat);
    for c in flat.iter_mut() {
        *c = c.rem_euclid(Q);
    }
    flat
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
    assert_eq!(
        t0.len(),
        MU,
        "encapsulate_derand_with_digest: t0 length must be MU"
    );
    let key = bdlop::key();

    let mut h = lib_q_sha3::Shake256::default();
    h.update(DOM_FO_SEED);
    h.update(pk_dig);
    h.update(mu);
    let mut rd = h.finalize_xof();

    // Ephemeral secret e ∈ R_q^MU (ternary) and errors f ∈ R_q^KAPPA, g ∈ R_q (uniform [-B, B]).
    // XOF draw order (e, then f per p element, then g) is wire-frozen by the KATs. All three are
    // drawn in constant time (fixed byte budgets, see the sampler note).
    let mut e: Vec<Rq> = xof_ternary_e(&mut rd);
    let mut e_ntt: Vec<RqNtt> = e.iter().map(to_ntt).collect();
    let b0te = bdlop::b0_transpose_apply_ntt(key, &e_ntt); // KAPPA elements
    let f = xof_bounded_flat(&mut rd, KAPPA); // KAPPA error elements, one flat draw
    let mut p = Vec::with_capacity(KAPPA);
    for (pk, fk) in b0te.iter().zip(f.iter()) {
        p.push(ring_add(pk, fk));
    }

    // ⟨t0, e⟩, reusing e's forward transform.
    let mut te_acc = RqNtt::zero();
    for (ti, ei) in t0.iter().zip(e_ntt.iter()) {
        ntt_mul_acc(&mut te_acc, &to_ntt(ti), ei);
    }
    let mut te = from_ntt(&te_acc);
    let g = xof_bounded_poly(&mut rd);
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
    let e: Vec<Rq> = xof_ternary_e(&mut rd);
    let f: Vec<Rq> = xof_bounded_flat(&mut rd, KAPPA);
    let g = xof_bounded_poly(&mut rd);
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

#[cfg(test)]
mod compaction_tests {
    use super::*;

    /// Reference oracle for [`ct_compact`]: the naïve `O(out·budget)` masked scan the Batcher-sort
    /// implementation replaced. Kept only to pin that the optimized path is **bit-identical**.
    fn ct_compact_ref(vals: &[i64], accs: &[u64], out: &mut [i64]) {
        let n = out.len() as u64;
        let mut w: u64 = 0;
        for k in 0..vals.len() {
            let do_write = accs[k] & ct_lt_mask(w, n);
            for (i, slot) in out.iter_mut().enumerate() {
                let sel = do_write & ct_eq_mask(i as u64, w);
                *slot = ct_select_i64(sel, vals[k], *slot);
            }
            w = w.wrapping_add(do_write & 1);
        }
    }

    // Deterministic xorshift64 — reproducible pseudo-random accept patterns without an rng dep.
    struct Xs(u64);
    impl Xs {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    #[test]
    fn ct_compact_matches_reference_oracle() {
        let mut rng = Xs(0x9E37_79B9_7F4A_7C15);
        // (budget, out) shapes incl. the production draws and small/edge sizes.
        let shapes = [
            (1usize, 1usize),
            (4, 2),
            (16, 9),
            (64, 40),
            (129, 1),
            (9216, 6144),
            (9344, 9216),
        ];
        for &(budget, n) in &shapes {
            // Force ≥ n accepts, then randomly accept the rest, so compaction never underflows.
            let mut accs = alloc::vec![0u64; budget];
            let mut order: alloc::vec::Vec<usize> = (0..budget).collect();
            // Fisher–Yates with the xorshift stream to pick which indices are guaranteed-accepted.
            for i in (1..budget).rev() {
                let j = (rng.next() as usize) % (i + 1);
                order.swap(i, j);
            }
            for &idx in &order[..n] {
                accs[idx] = u64::MAX;
            }
            for a in accs.iter_mut() {
                if *a == 0 && (rng.next() & 1) == 0 {
                    *a = u64::MAX;
                }
            }
            let vals: alloc::vec::Vec<i64> = (0..budget)
                .map(|_| (rng.next() % 2_000_003) as i64 - 1_000_001)
                .collect();

            let mut got = alloc::vec![0i64; n];
            let mut want = alloc::vec![0i64; n];
            ct_compact(&vals, &accs, &mut got);
            ct_compact_ref(&vals, &accs, &mut want);
            assert_eq!(
                got, want,
                "Batcher compaction diverged from oracle at budget={budget} n={n}"
            );
        }
    }

    #[test]
    fn batcher_sort_orders_values_by_key() {
        let mut rng = Xs(0xDEAD_BEEF_CAFE_F00D);
        for &len in &[1usize, 2, 4, 8, 64, 256] {
            let mut key: alloc::vec::Vec<u64> = (0..len).map(|_| rng.next() % 1000).collect();
            let mut val: alloc::vec::Vec<i64> = key.iter().map(|&k| k as i64).collect();
            batcher_sort(&mut key, &mut val);
            for w in key.windows(2) {
                assert!(w[0] <= w[1], "batcher_sort left keys unsorted");
            }
            // paired value must track its key through the exchanges
            for (k, v) in key.iter().zip(val.iter()) {
                assert_eq!(*k as i64, *v);
            }
        }
    }
}
