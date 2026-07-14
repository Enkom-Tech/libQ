//! Distributed **t-of-n** threshold decapsulation — no party reveals its raw share.
//!
//! The reference [`crate::partial_decap`] broadcasts `λ_i·⟨rand(i), p⟩`, which is a linear image of
//! the secret share `rand(i)` and therefore leaks it across many decapsulations. This module hides
//! each contribution with an **additive zero-share** bound to the ciphertext: each party adds a
//! uniform mask `m_i` with `Σ_{i∈S} m_i = 0`, so every broadcast `λ_i·⟨rand(i), p⟩ + m_i` is uniform
//! over `R_q` (revealing nothing individually), yet the masks cancel on aggregation, leaving the
//! exact `Σ_{i∈S} λ_i·⟨rand(i), p⟩ = ⟨r, p⟩`. The technique mirrors `lib-q-threshold-raccoon`'s
//! zero-sharing; here the contribution is a single `R_q` element (no norm bound), so the masks cancel
//! **exactly** and decapsulation stays lossless.
//!
//! Two layers protect the share against a **coalition** (up to `t-1` corrupt parties in the subset,
//! who know every pairwise seed the honest party uses and can therefore strip its zero-share mask):
//!
//! 1. **Flooding**: each partial also adds fresh uniform noise `flood_i` with
//!    `‖flood_i‖∞ ≤ FLOOD_BOUND = 2^40`, drowning the share-dependent decryption noise the
//!    coalition could otherwise read out of the aggregate (Rényi-style budget
//!    [`crate::kem::RECOMMENDED_DECAP_BUDGET`]; `SECURITY_ANALYSIS.md` §4). Flooding is sized so
//!    decapsulation stays **exact** ([`crate::kem::FLOOD_BOUND`]).
//! 2. **FO⊥ at [`crate::combine`]**: a malformed ciphertext never yields a key. Residual boundary:
//!    the coalition still *observes* the flooded partial on a malformed `p` before the combine-time
//!    rejection — an adversarially amplified `p` can overpower flooding, so deployments MUST bound
//!    per-key decapsulations and/or require ciphertext well-formedness proofs at a higher layer.
//!    See `LIBQ_API.md` §7.

extern crate alloc;

use alloc::vec::Vec;

use lib_q_dkg::lattice::ring::{
    N,
    Q,
    RQ_BYTES,
    Rq,
    ring_add,
    ring_sub,
    rq_write_le_bytes,
    scalar_mul,
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
use crate::kem::{
    self,
    Ciphertext,
};
use crate::{
    PartialDecap,
    SecretShare,
    decode_rand,
    validate_share_subset,
};

/// A saturating per-key decapsulation counter that makes the leakage budget
/// (`THRESHOLD_SECURITY.md` §5–§6) **enforceable by construction** rather than a doc-only
/// recommendation. Thread one instance per DKG key through [`partial_decap_masked_budgeted`]; once
/// the cap is reached it refuses further partials ([`ThresholdKemError::BudgetExhausted`]) until the
/// key is rotated (reshared with a fresh `DecapBudget`).
///
/// Pick the cap by sender-trust regime:
/// - [`DecapBudget::authenticated`] (`RECOMMENDED_DECAP_BUDGET = 2^20`) — senders are
///   identity-verified, so only honest XOF-derived ciphertexts reach the partial oracle; the bound
///   is the honest-ciphertext Rényi budget.
/// - [`DecapBudget::untrusted`] (`MALFORMED_PROBE_SAFE_DECAPS = 32`) — any ciphertext might be a
///   malformed-ct probe; the cap sits below the `≈63`-query probe length so it can never complete on
///   one key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecapBudget {
    used: u64,
    cap: u64,
}

impl DecapBudget {
    /// A budget with an explicit cap (number of partials this key may emit before rotation).
    #[must_use]
    pub fn new(cap: u64) -> Self {
        Self { used: 0, cap }
    }

    /// Budget for **authenticated** senders: `RECOMMENDED_DECAP_BUDGET = 2^20`.
    #[must_use]
    pub fn authenticated() -> Self {
        Self::new(kem::RECOMMENDED_DECAP_BUDGET)
    }

    /// Conservative budget for **untrusted** senders: `MALFORMED_PROBE_SAFE_DECAPS = 32`, below the
    /// malformed-ct probe length.
    #[must_use]
    pub fn untrusted() -> Self {
        Self::new(kem::MALFORMED_PROBE_SAFE_DECAPS)
    }

    /// Partials still permitted before rotation is required.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.cap.saturating_sub(self.used)
    }

    /// Partials already emitted against this key.
    #[must_use]
    pub fn used(&self) -> u64 {
        self.used
    }

    /// Charge one decapsulation; `Err(BudgetExhausted)` once the cap is reached.
    fn charge(&mut self) -> Result<(), ThresholdKemError> {
        if self.used >= self.cap {
            return Err(ThresholdKemError::BudgetExhausted);
        }
        self.used += 1;
        Ok(())
    }
}

/// Symmetric pairwise seeds for the additive zero-sharing (one per unordered party pair).
///
/// In a deployment these come from pairwise key agreement during/after the DKG; the [`setup`] helper
/// samples them for testing. `seed(i, j) == seed(j, i)`.
///
/// The per-pair seed bytes are **secret** (they key the zero-share PRF), so the set zeroizes them on
/// drop — see the `Drop` impl below.
#[derive(Clone)]
pub struct ZeroShareSeeds {
    entries: Vec<(u8, u8, [u8; 32])>,
}

impl Drop for ZeroShareSeeds {
    /// Wipe the secret pairwise seed bytes when the set is dropped (a `Clone` wipes its own copy on its
    /// own drop). The `(i, j)` party indices are public and left as-is.
    fn drop(&mut self) {
        for (_, _, seed) in &mut self.entries {
            seed.zeroize();
        }
    }
}

impl ZeroShareSeeds {
    /// Sample fresh pairwise seeds for parties `1..=parties`.
    pub fn setup<R: CryptoRng + Rng>(parties: u8, rng: &mut R) -> Self {
        let mut entries = Vec::new();
        for i in 1..=parties {
            for j in (i + 1)..=parties {
                let mut s = [0u8; 32];
                rng.fill_bytes(&mut s);
                entries.push((i, j, s));
            }
        }
        Self { entries }
    }

    /// Build seeds from **externally derived** symmetric pairwise secrets — the production path, where
    /// each `seed_ij` comes from pairwise key agreement established during the DKG (a shared secret only
    /// parties `i` and `j` can compute), rather than the random [`setup`](Self::setup) test source. Each
    /// entry is the canonical unordered pair `(i, j, seed)` with `0 < i < j`; a zero index, `i >= j`, or a
    /// duplicate pair is rejected ([`ThresholdKemError::InvalidSeedEntry`]) so [`seed`](Self::seed) lookup
    /// is unambiguous and fail-closed. The seed bytes must be a *secret* shared by exactly `i` and `j`;
    /// deriving them from public material would forfeit the per-broadcast uniformity the zero-share
    /// provides (see the module security notes).
    pub fn from_pairwise(entries: Vec<(u8, u8, [u8; 32])>) -> Result<Self, ThresholdKemError> {
        for (idx, (i, j, _)) in entries.iter().enumerate() {
            if *i == 0 || *j == 0 || i >= j {
                return Err(ThresholdKemError::InvalidSeedEntry);
            }
            // Reject a duplicate unordered pair (only the earlier entries need checking).
            if entries[..idx].iter().any(|(a, b, _)| a == i && b == j) {
                return Err(ThresholdKemError::InvalidSeedEntry);
            }
        }
        Ok(Self { entries })
    }

    fn seed(&self, a: u8, b: u8) -> Option<&[u8; 32]> {
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        self.entries
            .iter()
            .find(|(i, j, _)| *i == lo && *j == hi)
            .map(|(_, _, s)| s)
    }
}

/// Privacy-preserving partial decapsulation: `λ_i·⟨rand(i), p⟩ + m_i + flood_i`, with `m_i` a
/// ciphertext-bound zero-share (cancels across the subset) and `flood_i` fresh uniform flooding
/// noise (`‖flood_i‖∞ ≤ FLOOD_BOUND`, absorbed by the decode margin). Feed the result to the shared
/// [`crate::combine`].
///
/// Rejects structurally malformed ciphertexts, zero/duplicate/missing subset indices, and
/// sub-threshold subsets before touching the share; every share-linear intermediate (the decoded
/// share, `⟨rand(i), p⟩`, the pre-mask weighted value, the mask, and the flooding polynomial) is
/// zeroized before returning — only the fully masked broadcast value survives.
pub fn partial_decap_masked<R: CryptoRng + Rng>(
    share: &SecretShare,
    subset: &[u8],
    ct: &Ciphertext,
    seeds: &ZeroShareSeeds,
    rng: &mut R,
) -> Result<PartialDecap, ThresholdKemError> {
    validate_share_subset(share, subset)?;
    if !ct.is_well_formed() {
        return Err(ThresholdKemError::EncodingCiphertext);
    }
    let rand = decode_rand(&share.share_bytes)?; // Zeroizing — cleared on drop
    let lambda = lib_q_dkg::lagrange_coeff_at_zero(subset, share.index)
        .map_err(|_| ThresholdKemError::InvalidSubset)?;
    let mut rp = kem::ring_inner(&rand, &ct.p); // ⟨rand(i), p⟩
    let mut weighted = scalar_mul(&rp, lambda); // λ_i·⟨rand(i), p⟩
    let mut m = zero_share(seeds, share.index, subset, &session_bytes(ct))?;
    let mut flood = kem::sample_bounded_poly(rng, kem::FLOOD_BOUND);
    let value = ring_add(&ring_add(&weighted, &m), &flood);
    rp.zeroize();
    weighted.zeroize();
    m.zeroize();
    flood.zeroize();
    Ok(PartialDecap {
        index: share.index,
        value,
    })
}

/// Budget-enforced [`partial_decap_masked`]: charges one decapsulation against `budget` and refuses
/// with [`ThresholdKemError::BudgetExhausted`] once the per-key cap is reached, so a deployment
/// **cannot** silently exceed its leakage budget (`THRESHOLD_SECURITY.md` §6). The budget is only
/// charged for a successfully emitted partial — a structurally invalid ciphertext or bad subset
/// returns its own error without consuming a slot. This is the recommended distributed entry point;
/// the un-budgeted [`partial_decap_masked`] is retained for callers that track the budget elsewhere.
pub fn partial_decap_masked_budgeted<R: CryptoRng + Rng>(
    share: &SecretShare,
    subset: &[u8],
    ct: &Ciphertext,
    seeds: &ZeroShareSeeds,
    rng: &mut R,
    budget: &mut DecapBudget,
) -> Result<PartialDecap, ThresholdKemError> {
    if budget.remaining() == 0 {
        return Err(ThresholdKemError::BudgetExhausted);
    }
    let partial = partial_decap_masked(share, subset, ct, seeds, rng)?;
    // `remaining() > 0` was just checked and `budget` is `&mut`, so this cannot fail; propagate
    // rather than `expect` to keep the path panic-free.
    budget.charge()?;
    Ok(partial)
}

/// Additive zero-share for party `i` over `subset`, bound to the ciphertext session:
/// `m_i = Σ_{j∈S, j≠i} ε(i,j)·PRF(seed_{ij}, session)` with `ε(i,j) = +1 if i<j else −1`, so
/// `Σ_{i∈S} m_i = 0`. Uniform over `R_q`, hiding the contribution.
fn zero_share(
    seeds: &ZeroShareSeeds,
    i: u8,
    subset: &[u8],
    session: &[u8; 32],
) -> Result<Rq, ThresholdKemError> {
    let mut m = Rq::zero();
    for &j in subset {
        if j == i {
            continue;
        }
        let seed = seeds.seed(i, j).ok_or(ThresholdKemError::MissingSeed)?;
        let contrib = prf_rq(seed, session);
        m = if i < j {
            ring_add(&m, &contrib)
        } else {
            ring_sub(&m, &contrib)
        };
    }
    Ok(m)
}

/// Deterministic uniform `R_q` element from `(seed, session)` via SHAKE-256 rejection sampling.
fn prf_rq(seed: &[u8; 32], session: &[u8; 32]) -> Rq {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(b"lib-q-threshold-kem-lattice/zero-share-prf/v1");
    h.update(seed);
    h.update(session);
    let mut rd = h.finalize_xof();
    let q = Q as u64;
    let zone = u64::MAX - (u64::MAX % q);
    let mut coeffs = [0i64; N];
    for cf in &mut coeffs {
        let v = loop {
            let mut b = [0u8; 8];
            XofReader::read(&mut rd, &mut b);
            let r = u64::from_le_bytes(b);
            if r < zone {
                break r % q;
            }
        };
        *cf = v as i64;
    }
    Rq::from_coeffs(coeffs)
}

/// Session identifier binding the zero-shares to this ciphertext.
///
/// Absorbs exactly the bytes of `ct.to_bytes()` (the mask derivation is version-locked to that
/// stream — parties on different encodings would derive non-cancelling masks), but element by
/// element through one reused `RQ_BYTES` buffer instead of one full-ciphertext allocation.
fn session_bytes(ct: &Ciphertext) -> [u8; 32] {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(b"lib-q-threshold-kem-lattice/session/v1");
    let mut buf = Vec::with_capacity(RQ_BYTES);
    for pk in &ct.p {
        buf.clear();
        rq_write_le_bytes(pk, &mut buf);
        h.update(&buf);
    }
    buf.clear();
    rq_write_le_bytes(&ct.v, &mut buf);
    h.update(&buf);
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}
