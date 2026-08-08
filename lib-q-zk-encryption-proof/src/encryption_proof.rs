//! Production entry-point assembly for the **byte-provenance** encryption proof (task #26): the
//! composition that binds the ciphertext's witness `e` to the deterministic FO expansion
//! `e = XOF(DOM_FO_SEED ‖ pk_digest ‖ μ)` AND proves `e` ternary, then feeds those *bound* `e_r`
//! folds into the R3b relation `v = Σ_r t0_r·e_r + g + encode(μ)`. This is the layer that makes the
//! partial-decap gate ([`crate::gate`]) non-vacuous for the `e`-probe class: a witness `e` that is not
//! the genuine SHAKE output (or not ternary) cannot produce a verifying proof, because the join
//! balances / sampler range constraints reject it.
//!
//! ## The layers, and which one this is
//! The sponge (`ShakeSpongeAir`), the squeeze-byte bridge (`SqueezeByteAir`) and the samplers
//! (`TernarySamplerAir`/`BoundedSamplerAir`) are wired by the LogUp joins
//! (SQUEEZE_LIMB → XOF_STREAM → COEFF_E/F/G → FOLD_E), so the coefficient columns the R3 relations
//! consume are provably the XOF-derived `e` (ternary) and `f`,`g` (bounded). This module composes that
//! byte-provenance layer with the relation layer into one `prove_batch`.
//!
//! A relation-only entry point (`crate::prove`) used to exist alongside this one. It has been
//! **removed**: it proved the R3 relations over free `(e, f, g)` with no joins, which its own docs
//! admitted was vacuous as a malformed-ciphertext closure — an unsound path kept in a public crate is
//! a path someone eventually calls.
//!
//! ## Config-agnostic assembly
//! `lib_q_plonky_batch_stark::prove_batch<SC, A>` is bounded by a folder type the batch crate does not
//! re-export, and the FRI/MMCS/challenger crates are dev-dependencies, so this module cannot construct
//! the config or name the `prove_batch` bound. It therefore exposes the (config-independent) assembly:
//! [`assemble_e_provenance_prover`] (needs the witness) and [`assemble_e_provenance_verifier`] (public
//! inputs + the [`EncProofShape`] only). The caller runs `build_preprocessed` + `prove_batch` /
//! `verify_batch` with the config it chose (test or **production** FRI params — see the module tests for
//! both, and the gate-wiring test that turns this into a sound `proof_verifies` closure).
//!
//! ## Three tiers (cheapest → complete)
//! 1. [`assemble_e_provenance_prover`] — binds `e` (ternary) + proves R3b. `g`/`f` fed directly.
//!    Cheapest (sponge covers only `e`'s ~8 KB). The `e`-probe closure + spike harness.
//! 2. [`assemble_r3a_f_provenance_prover`] — binds `e` AND `f` (bounded, at the XOF offset after `e`)
//!    for selected R3a columns; the harness for the classic `f = δ·unitₖ` spike test. Sponge covers
//!    `e` + the covered `f` prefix.
//! 3. [`assemble_full_provenance_prover`] — the **COMPLETE** closure: binds `e` + ALL `f_k` + `g` and
//!    proves every R3a `p_k` AND R3b, over `num_challenges` independent Fiat–Shamir challenges, in one
//!    batch. One verifying proof certifies the entire witness is `(e,f,g) = XOF(pk‖μ)` with `e` ternary
//!    and `f,g` bounded — no component left free to spike. Sponge covers the full ~90 KB (`e`+`f`+`g`).
//!
//! ## Soundness (tier 3, the production closure)
//! * Each challenge checks two ρ-batched residuals — `⟨D_v, κ⟩ = 0` (R3b) and
//!   `Σ_k ρ_k·⟨D_{p_k}, κ⟩ = 0` (R3a) — over coefficient columns that are ALL pinned: `e` via
//!   COEFF_E, `f_k` via COEFF_F, `g` via COEFF_G, and `encode(μ)`'s bits via MU_BIT_BUS back to the
//!   sponge preimage. **No term is prover-chosen.** For a fixed malformed ciphertext each check is a
//!   fixed linear test that fails except with probability ≤ `2/q` ≈ 2^-47 over `(κ, ρ)`. Grinding
//!   `ct` redraws `(κ, ρ)` and changes the residuals, so forging costs ≈ `(q/2)^m`; `m = 3` ⇒ ≈ 2^141.
//! * **The amplification is real only because nothing is free**, and that has been got wrong twice in
//!   this crate. The superseded evaluation-at-`ζ` design gave each challenge its own free quotient
//!   fold, so `m` challenges were `m` independent one-unknown solves — a malformed ciphertext verified
//!   at `m = 1` AND `m = 3` at production FRI parameters. The first pass of the fix left
//!   `EncodeMuFoldAir`'s 256 μ-bits free, which is the same defect wearing a different hat: linear in
//!   public coefficients, chosen after `κ`, and solvable by subset-sum for an arbitrary malformed `v`.
//!   Both are closed. If you add a per-challenge witness column that no bus pins, you have
//!   reintroduced the bug — `tests::no_fold_instance_is_left_unbound` exists to catch exactly that,
//!   and it deliberately has no exemptions.
//! * The byte-provenance joins are exact multiset (LogUp) checks whose soundness is the config's FRI
//!   soundness (~128 bits at production params). The ternary/bounded sampler AIRs pin `e ∈ {-1,0,1}`
//!   and `f,g ∈ [-B,B]`; the sponge pins the XOF preimage to `DOM ‖ pk_digest ‖ μ` (pk-bound public
//!   values, verifier-built from `ct`). The `m` per-challenge folds Receive the shared sampler
//!   coefficients once each via the samplers' repeated Sends, so every COEFF bus balances.
//! * **Verifier obligation, load-bearing:** every fold's public multiplier `ψ` lives in a
//!   **preprocessed** trace. The verifier MUST commit that trace itself, from its own AIRs built from
//!   public data, and MUST NOT reuse the prover's preprocessed `CommonData` — otherwise the prover
//!   chooses the linear functional and every relation is vacuous. This holds on the hiding-FRI path
//!   too: `tests::e_provenance_zero_knowledge_round_trip` rebuilds it verifier-side (the "S2 fix"),
//!   and that is the pattern a deployment must copy. Note the rebuild currently reproduces the hiding
//!   commitment by restarting the MMCS RNG at a fixed seed; a deployment wanting genuinely random
//!   witness blinding needs preprocessed committed under a separate NON-hiding sub-commitment instead
//!   (`ψ` is public, so it needs no blinding). This remains a cryptographer sign-off item.
//! * **Zero-knowledge (task #32):** the assembly runs unchanged under a hiding-FRI config
//!   (`is_zk() == 1`), which blinds every committed matrix and randomizes the quotient. `κ`, `ρ` and
//!   `ψ` are public functions of the statement and leak nothing about `μ`. Demonstrated (for
//!   completeness, not soundness) by `tests::e_provenance_zero_knowledge_round_trip`.
//! * **The crate is still RED.** The remaining obligations are a human cryptographer's: the
//!   Fiat–Shamir/grinding bound in the (Q)ROM, the `κ ⊥ ρ` independence given a shared statement
//!   hash, and the preprocessed obligation above. Nothing here has been reviewed by one.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use lib_q_dkg::lattice::bdlop::{
    KAPPA,
    MU,
    key,
};
use lib_q_dkg::lattice::ring::{
    N,
    Rq,
};
use lib_q_plonky_keccak_air::{
    NUM_KECCAK_COLS,
    NUM_ROUNDS,
};
use lib_q_plonky_lookup::Lookup;
use lib_q_stark_field::PrimeCharacteristicRing;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_threshold_kem_lattice::kem::{
    Ciphertext,
    E_TERNARY_ATTEMPTS,
    bounded_attempts,
    encapsulate_derand,
    fo_expand_witness,
};
use lib_q_zkp::stark::ConfigVal;
use zeroize::Zeroizing;

use crate::compose::EncProofAir;
use crate::error::EncProofError;
use crate::logup_join::{
    COEFF_E_BUS,
    COEFF_F_BUS,
    COEFF_G_BUS,
    FOLD_E_BUS,
    fc,
};
use crate::mu_bits::{
    MuBitsAir,
    generate_mu_bits_trace,
    mu_bits_lookups,
};
use crate::relation_assembly::{
    combine_public_multipliers,
    corr_negacyclic,
    dot_zq,
    rq_coeffs_zq,
    statement_kappas,
    statement_rhos,
};
use crate::sampler::{
    BOUNDED_WIDTH,
    BoundedSamplerAir,
    SAMPLER_WIDTH,
    TernarySamplerAir,
    bounded_coeff_send_lookups_col,
    bounded_public_values,
    bounded_receive_lookup_at,
    generate_bounded_trace,
    generate_ternary_trace,
    ternary_coeff_send_lookups_at,
    ternary_public_values,
    ternary_receive_lookup,
};
use crate::sponge::RATE_BYTES;
use crate::sponge_air::{
    ShakeSpongeAir,
    encap_preimage,
    generate_provable_sponge_trace,
    sponge_limb_send_lookups,
    sponge_mu_limb_send_lookups,
    sponge_public_values,
};
use crate::squeeze_byte::{
    SqueezeByteAir,
    generate_squeeze_byte_trace_partial,
    squeeze_byte_limb_receive_lookup,
    squeeze_byte_send_lookup,
};
use crate::zq::{
    DotFoldAir,
    EncodeMuFoldAir,
    MSG_BITS,
    Q,
    REL_MAX_TERMS,
    RelationCheckAir,
    encode_mu_bit_receive_lookup,
    fold_coeff_receive_lookups_at,
    fold_result_send_lookups_at,
    generate_dot_trace,
    generate_encode_mu_trace,
    generate_relation_trace,
};

/// The **public** shape parameters of a byte-provenance proof: the sizes the prover chose (sponge
/// height / squeeze coverage / consumed-byte count) that the verifier must rebuild the AIRs and
/// lookups against. These are NOT secret — they are a function of `e`'s XOF rejection-sampling byte
/// consumption (a mild `μ`-dependent leak addressed by the hiding-FRI ZK path, task #32, not a
/// soundness issue: the joins enforce that the sponge covers every consumed byte regardless of the
/// declared sizes). Communicated alongside the proof; the verifier feeds them to
/// [`assemble_e_provenance_verifier`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncProofShape {
    /// Row count of the sponge trace (a power of two ≥ the squeeze coverage of the consumed bytes).
    pub sponge_height: usize,
    /// Ternary `e`-sampler coefficient count (`MU · N`).
    pub num_e_coeffs: usize,
    /// Bounded `f`-sampler coefficient count (`KAPPA · N`). `f` is NOT folded by this tier; the
    /// sampler exists only to drain `f`'s XOF bytes so `g`'s draw sits at its true offset.
    pub num_f_coeffs: usize,
    /// Bounded `g`-sampler coefficient count (`N`).
    pub num_g_coeffs: usize,
    /// The number of 16-bit limbs the squeeze-byte table covers (the sponge's full squeeze).
    pub sponge_full_limbs: usize,
    /// The number of XOF bytes forwarded to the samplers (`e` + `f` + `g`).
    pub consumed_bytes: usize,
    /// Absolute XOF byte offset where `f`'s draw begins (= `e`'s consumed byte count).
    pub f_offset: usize,
    /// Absolute XOF byte offset where `g`'s draw begins (= `e_bytes + f_bytes`).
    pub g_offset: usize,
}

/// The assembled instances of the byte-provenance ⇒ R3b layer (prover side): parallel vectors indexed
/// by batch instance. Build `StarkInstance`s by zipping these (the traces are owned here and borrowed
/// by the instances), then call `prove_batch`.
///
/// **Zeroization (closes C3 for the returned traces):** the `traces` hold witness-derived field
/// elements (`e`/`f`/`g` coefficients, μ's encoding, the quotients). On drop — after `prove_batch` has
/// consumed them — every trace cell is overwritten with zero (see the [`Drop`] impl), so the secret
/// witness does not linger in the returned artifact. Keep the value alive only as long as proving needs
/// it. (The intermediate coefficient copies inside the assembly functions are additionally wrapped in
/// [`Zeroizing`].)
pub struct EncProvenanceProver {
    /// One enum-wrapped AIR per instance.
    pub airs: Vec<EncProofAir>,
    /// The witness trace for each instance (borrowed by the `StarkInstance`s).
    pub traces: Vec<RowMajorMatrix<ConfigVal>>,
    /// Public values per instance.
    pub public_values: Vec<Vec<ConfigVal>>,
    /// Global-bus lookups per instance (also the verifier-trusted `CommonData` lookups).
    pub lookups: Vec<Vec<Lookup<ConfigVal>>>,
}

impl Drop for EncProvenanceProver {
    fn drop(&mut self) {
        // Wipe the witness-bearing trace cells. `black_box` keeps the store from being elided as a
        // dead write (the crate is `no_std`-compatible; this is a best-effort scrub, not a
        // constant-time guarantee — see the H1 note in the security review).
        for t in &mut self.traces {
            t.values.fill(ConfigVal::ZERO);
            core::hint::black_box(t.values.as_ptr());
        }
    }
}

/// The assembled instances (verifier side): no traces; the sponge public values are rebuilt from
/// `ct.pk_digest` (the load-bearing pk binding) and the relation public coefficients from
/// `(t0, ct, ζ)`. Feed to `verify_batch`.
pub struct EncProvenanceVerifier {
    /// One enum-wrapped AIR per instance (same order as the prover).
    pub airs: Vec<EncProofAir>,
    /// Public values per instance.
    pub public_values: Vec<Vec<ConfigVal>>,
    /// Global-bus lookups per instance (the verifier-trusted `CommonData` lookups).
    pub lookups: Vec<Vec<Lookup<ConfigVal>>>,
}

/// The relation-instance public values (`a_j` limbs low-to-high, then `c` limbs) — the verifier
/// rebuild of what `generate_relation_trace` returns, from the recomputed public coefficients. (Same
/// layout the relation AIR emits, rebuilt from the recomputed public coefficients.)
fn relation_public_values(a: &[u64], c: u64) -> Vec<ConfigVal> {
    let mut pubs = Vec::with_capacity((a.len() + 1) * 4);
    for &x in a {
        for limb in 0..4 {
            pubs.push(fc((x >> (12 * limb)) & 0xFFF));
        }
    }
    for limb in 0..4 {
        pubs.push(fc((c >> (12 * limb)) & 0xFFF));
    }
    pubs
}

/// Pad a height-2 relation trace to 64 rows by repeating the `is_first = 0` replica row (matches the
/// composition tests' relation height).
const RELATION_HEIGHT: usize = 64;
fn pad_relation(rm: &RowMajorMatrix<ConfigVal>) -> RowMajorMatrix<ConfigVal> {
    let w = rm.width;
    let mut vals = Vec::with_capacity(RELATION_HEIGHT * w);
    vals.extend_from_slice(&rm.values[0..w]);
    for _ in 0..RELATION_HEIGHT - 1 {
        vals.extend_from_slice(&rm.values[w..2 * w]);
    }
    RowMajorMatrix::new(vals, w)
}

/// Count active (real, non-padding) rows of a sampler trace (column 0 = the active flag).
fn active_rows(trace: &RowMajorMatrix<ConfigVal>, width: usize) -> usize {
    (0..trace.values.len() / width)
        .filter(|&r| trace.values[r * width] == ConfigVal::ONE)
        .count()
}

/// The verifier-recomputable public data of the R3b linear functional at one challenge.
///
/// Built by [`r3b_public`] on BOTH sides, so a prover/verifier divergence in the challenge derivation
/// is a structural impossibility rather than a review obligation. Nothing here depends on the witness.
struct R3bPublic {
    /// The challenge vector `κ ∈ Z_q^N` — also the multiplier for the `g` and `encode(μ)` folds.
    kappa: Vec<u64>,
    /// `ψ_r = corr_negacyclic(t0_r, κ)`, the public multiplier vector of the `e_r` fold.
    psi: Vec<Vec<u64>>,
    /// Relation coefficients — `MU + 2` ones, since every term enters the functional with weight 1.
    a: Vec<u64>,
    /// `c = q − ⟨v, κ⟩`, the public side of the residual.
    c: u64,
}

/// Assemble [`R3bPublic`] from public data only. The relation this pins is
/// `Σ_r ⟨e_r, ψ_r⟩ + ⟨g, κ⟩ + ⟨encode(μ), κ⟩ − ⟨v, κ⟩ ≡ 0 (mod q)`, which is `⟨D, κ⟩ = 0` for the ring
/// residual `D = Σ_r t0_r·e_r + g + encode(μ) − v` — see
/// [`crate::relation_assembly::corr_negacyclic`] for the correlation identity that makes the `t0` side
/// public, and for why this replaced the evaluation-at-`ζ` form.
fn r3b_public(t0_cols: &[&[u64]], v_z: &[u64], kappa: Vec<u64>) -> R3bPublic {
    let psi: Vec<Vec<u64>> = t0_cols
        .iter()
        .map(|t| corr_negacyclic(t, &kappa, N))
        .collect();
    let a = alloc::vec![1u64; MU + 2];
    let c = (Q - dot_zq(v_z, &kappa)) % Q;
    R3bPublic { kappa, psi, a, c }
}

/// **Prover** assembly of the `e`-byte-provenance ⇒ R3b layer for `(t0, μ)`.
///
/// Derives the ciphertext + witness (`encapsulate_derand` / `fo_expand_witness`), builds the SHAKE
/// sponge over the real FO preimage covering `e`'s consumed bytes, the squeeze-byte bridge, the ternary
/// `e`-sampler (`MU·N` coeffs), the `MU` `e_r` folds (byte-bound via join 2 at per-ring-element bases),
/// the `g`/`encode(μ)` folds, and the R3b relation receiving all `MU+2` folds (join 3). Returns the
/// ciphertext, the [`EncProofShape`] the verifier needs, and the assembled instances.
///
/// The Fiat–Shamir challenge is the vector `κ = statement_kappas(pk_digest, ct)[0]` — over the
/// statement `(pk_digest ‖ ct)`, not the ciphertext alone — verifier-recomputable, never
/// prover-supplied. There is **no quotient fold**: see [`crate::relation_assembly::corr_negacyclic`].
///
/// # Errors
/// [`EncProofError::TraceGeneration`] if a trace generator rejects its inputs.
pub fn assemble_e_provenance_prover(
    t0: &[Rq],
    mu: &[u8; 32],
) -> Result<(Ciphertext, EncProofShape, EncProvenanceProver), EncProofError> {
    let ct = encapsulate_derand(t0, mu);
    let w = fo_expand_witness(t0, mu);
    let input = encap_preimage(&w.pk_digest, mu);

    // Samplers over the real XOF at the KEM's fixed budgets, in the order the KEM draws them:
    // e (ternary), f (bounded), g (bounded). `f` is NOT folded by this tier — its sampler exists to
    // DRAIN f's bytes so that (a) the squeeze table's forwarded prefix stays balanced and (b) `g`'s
    // draw sits at its true absolute offset. Binding `g` is what stops its fold being a free column;
    // it costs the full e+f+g sponge, so this tier is no longer the cheap one.
    let num_e = MU * N;
    let num_f = KAPPA * N;
    let num_g = N;
    let e_budget = E_TERNARY_ATTEMPTS;
    let f_budget_bytes = bounded_attempts(num_f) * 8;
    let g_budget_bytes = bounded_attempts(num_g) * 8;
    let bytes = shake256_xof(&input, e_budget + f_budget_bytes + g_budget_bytes);
    let e_sampler = generate_ternary_trace(&bytes[..e_budget], num_e)?;
    let e_bytes = active_rows(&e_sampler, SAMPLER_WIDTH);
    let f_sampler = generate_bounded_trace(&bytes[e_budget..e_budget + f_budget_bytes], num_f)?;
    let f_bytes = active_rows(&f_sampler, BOUNDED_WIDTH) * 8;
    let g_sampler = generate_bounded_trace(
        &bytes[e_budget + f_budget_bytes..e_budget + f_budget_bytes + g_budget_bytes],
        num_g,
    )?;
    let g_bytes = active_rows(&g_sampler, BOUNDED_WIDTH) * 8;
    let consumed = e_bytes + f_bytes + g_bytes;
    let sponge = generate_provable_sponge_trace(&input, consumed + RATE_BYTES);
    let height = sponge.values.len() / NUM_KECCAK_COLS;
    let blocks = sponge_squeeze_blocks(height);
    let full_limbs = blocks * (RATE_BYTES / 2);
    let squeeze = generate_squeeze_byte_trace_partial(&input, full_limbs, consumed);

    // Public side (identical on the verifier).
    let t0_cols_owned: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();
    let t0_cols: Vec<&[u64]> = t0_cols_owned.iter().map(|v| v.as_slice()).collect();
    let v_z = rq_coeffs_zq(&ct.v);
    let kappa = one_kappa(&w.pk_digest, &ct);
    let pubdata = r3b_public(&t0_cols, &v_z, kappa);

    // Witness side.
    let e_lifts: Zeroizing<Vec<Vec<u64>>> = Zeroizing::new(w.e.iter().map(rq_coeffs_zq).collect());
    let g_z: Zeroizing<Vec<u64>> = Zeroizing::new(rq_coeffs_zq(&w.g));

    let mut e_fold_traces = Vec::with_capacity(MU);
    let mut w_terms = Vec::with_capacity(MU + 2);
    for (e, psi_r) in e_lifts.iter().zip(pubdata.psi.iter()) {
        let (t, ev) = generate_dot_trace(e, psi_r)?;
        e_fold_traces.push(t);
        w_terms.push(ev);
    }
    let (g_trace, g_ev) = generate_dot_trace(&g_z, &pubdata.kappa)?;
    let (enc_trace, enc_ev) = generate_encode_mu_trace(mu, &pubdata.kappa[..MSG_BITS])?;
    w_terms.push(g_ev);
    w_terms.push(enc_ev);

    let rc = RelationCheckAir { num_terms: MU + 2 };
    let (rm, rel_pubs) = generate_relation_trace(&pubdata.a, &w_terms, pubdata.c)?;
    let relation = pad_relation(&rm);

    let airs = e_provenance_airs(height, num_e, num_f, num_g, &pubdata, &rc);
    let lookups = e_provenance_lookups(e_bytes as u64, (e_bytes + f_bytes) as u64, &rc);

    let mut traces: Vec<RowMajorMatrix<ConfigVal>> = Vec::from([
        sponge,
        squeeze,
        e_sampler,
        f_sampler,
        g_sampler,
        generate_mu_bits_trace(mu),
    ]);
    traces.extend(e_fold_traces);
    traces.push(g_trace);
    traces.push(enc_trace);
    traces.push(relation);

    let public_values = e_provenance_public_values(&w.pk_digest, num_e, num_f, num_g, &rel_pubs);

    let shape = EncProofShape {
        sponge_height: height,
        num_e_coeffs: num_e,
        num_f_coeffs: num_f,
        num_g_coeffs: num_g,
        sponge_full_limbs: full_limbs,
        consumed_bytes: consumed,
        f_offset: e_bytes,
        g_offset: e_bytes + f_bytes,
    };
    Ok((
        ct,
        shape,
        EncProvenanceProver {
            airs,
            traces,
            public_values,
            lookups,
        },
    ))
}

/// **Verifier** assembly for `(t0, ct, shape)`: recomputes `κ` over `pk_digest_of(t0)`, rebuilds every
/// AIR from the public [`EncProofShape`] (including each fold's preprocessed `ψ` column — the binding
/// that makes the functional public), the sponge public values from the rebuilt `pk_digest` (the
/// load-bearing pk binding — NEVER prover-supplied), and the relation's `(a, c)` from `(t0, ct, κ)`.
/// Rebuilds the lookups (deterministic, witness-free) in the SAME order as
/// [`assemble_e_provenance_prover`]. Feed to `verify_batch`.
pub fn assemble_e_provenance_verifier(
    t0: &[Rq],
    ct: &Ciphertext,
    shape: EncProofShape,
) -> EncProvenanceVerifier {
    let pk_digest = lib_q_threshold_kem_lattice::kem::pk_digest_of(t0);
    let t0_cols_owned: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();
    let t0_cols: Vec<&[u64]> = t0_cols_owned.iter().map(|v| v.as_slice()).collect();
    let v_z = rq_coeffs_zq(&ct.v);
    let kappa = one_kappa(&pk_digest, ct);
    let pubdata = r3b_public(&t0_cols, &v_z, kappa);
    let rc = RelationCheckAir { num_terms: MU + 2 };

    let airs = e_provenance_airs(
        shape.sponge_height,
        shape.num_e_coeffs,
        shape.num_f_coeffs,
        shape.num_g_coeffs,
        &pubdata,
        &rc,
    );
    let lookups = e_provenance_lookups(shape.f_offset as u64, shape.g_offset as u64, &rc);
    // pk_digest is rebuilt from `t0` — the verifier does NOT trust a prover-supplied value
    // (adversarial-review 2026-07-11: the single most important obligation). `ct` is bound because κ,
    // `⟨v, κ⟩` and every ψ are recomputed from it above.
    let rel_pubs = relation_public_values(&pubdata.a, pubdata.c);
    let public_values = e_provenance_public_values(
        &pk_digest,
        shape.num_e_coeffs,
        shape.num_f_coeffs,
        shape.num_g_coeffs,
        &rel_pubs,
    );

    EncProvenanceVerifier {
        airs,
        public_values,
        lookups,
    }
}

/// The single challenge vector of a one-challenge tier.
fn one_kappa(pk_digest: &[u8; 32], ct: &Ciphertext) -> Vec<u64> {
    let mut ks = statement_kappas(pk_digest, &ct.to_bytes(), 1, N);
    ks.pop()
        .expect("statement_kappas(.., 1, ..) yields one vector")
}

/// The AIR list, in canonical order — built identically by prover and verifier. Each fold carries its
/// own public `ψ` (materialised as that instance's preprocessed column), which is what makes the
/// verifier's independently committed preprocessed trace the binding for the linear functional.
fn e_provenance_airs(
    sponge_height: usize,
    num_e: usize,
    num_f: usize,
    num_g: usize,
    pubdata: &R3bPublic,
    rc: &RelationCheckAir,
) -> Vec<EncProofAir> {
    let mut airs = Vec::from([
        EncProofAir::Sponge(ShakeSpongeAir {
            height: sponge_height,
        }),
        EncProofAir::SqueezeByte(SqueezeByteAir),
        EncProofAir::Ternary(TernarySamplerAir { num_coeffs: num_e }),
        EncProofAir::Bounded(BoundedSamplerAir { num_coeffs: num_f }),
        EncProofAir::Bounded(BoundedSamplerAir { num_coeffs: num_g }),
        EncProofAir::MuBits(MuBitsAir),
    ]);
    for psi_r in &pubdata.psi {
        airs.push(EncProofAir::DotFold(DotFoldAir::new(psi_r.clone())));
    }
    airs.push(EncProofAir::DotFold(DotFoldAir::new(pubdata.kappa.clone()))); // g
    airs.push(EncProofAir::EncodeMuFold(EncodeMuFoldAir::new(
        pubdata.kappa[..MSG_BITS].to_vec(),
    ))); // encode
    airs.push(EncProofAir::RelationCheck(rc.clone()));
    airs
}

/// The per-instance lookup lists (identical for prover and verifier — no witness data). Order matches
/// the AIR order: sponge (limb Sends), squeeze (limb Receive + byte Send), e-sampler (byte Receive +
/// coeff Send), `MU` e_r folds (coeff Receive at base `r·N·4` + `E`-Send to R3b term `r`), g/encode
/// folds (`E`-Send to terms `MU`/`MU+1`), R3b relation (`w`-Receive of all terms).
fn e_provenance_lookups(
    f_offset: u64,
    g_offset: u64,
    rc: &RelationCheckAir,
) -> Vec<Vec<Lookup<ConfigVal>>> {
    let mut lookups: Vec<Vec<Lookup<ConfigVal>>> = Vec::new();
    let mut sponge_lk = sponge_limb_send_lookups();
    sponge_lk.extend(sponge_mu_limb_send_lookups()); // μ binding (card t_a73aaed2, GAP 2)
    lookups.push(sponge_lk);
    lookups.push(Vec::from([
        squeeze_byte_send_lookup(),
        squeeze_byte_limb_receive_lookup(),
    ]));
    let mut e_samp = Vec::from([ternary_receive_lookup()]); // byte Receive (aux col 0)
    e_samp.extend(ternary_coeff_send_lookups_at(0, 1)); // coeff Send (aux cols 1..5)
    lookups.push(e_samp);
    // f-sampler: byte-Receives ONLY. Its coefficients are deliberately not Sent — this tier does not
    // fold `f`, and an unmatched COEFF_F Send would unbalance that bus. It is here to drain f's bytes.
    lookups.push(bounded_receive_lookup_at(f_offset));
    // g-sampler: byte-Receives + coefficient Sends on COEFF_G, which is what pins the g fold below.
    let mut g_samp = bounded_receive_lookup_at(g_offset);
    g_samp.extend(bounded_coeff_send_lookups_col(COEFF_G_BUS, 0, 8));
    lookups.push(g_samp);
    lookups.push(mu_bits_lookups(1)); // μ limb→bit bridge (one encode fold in this tier)
    for r in 0..MU {
        // e_r fold: join-2 receive at base r·N·4 (cols 0..4) + join-3 send to R3b term r (cols 4..8).
        let mut fl = fold_coeff_receive_lookups_at(COEFF_E_BUS, (r as u64) * (N as u64) * 4);
        fl.extend(fold_result_send_lookups_at(FOLD_E_BUS, 0, r, 4));
        lookups.push(fl);
    }
    // g fold: COEFF_G receive (cols 0..4) + send to term MU (cols 4..8). WITHOUT the receive this
    // column is free and the whole R3b relation is solvable for any ciphertext — see
    // `no_fold_instance_is_left_unbound`, which is the test that caught exactly that.
    let mut gl = fold_coeff_receive_lookups_at(COEFF_G_BUS, 0);
    gl.extend(fold_result_send_lookups_at(FOLD_E_BUS, 0, MU, 4));
    lookups.push(gl);
    // encode fold → term MU+1, PLUS the μ-bit Receive that ties its bits to the sponge's μ.
    let mut enc_lk = fold_result_send_lookups_at(FOLD_E_BUS, 0, MU + 1, 0);
    enc_lk.extend(encode_mu_bit_receive_lookup(4));
    lookups.push(enc_lk);
    lookups.push(rc.relation_w_receive_lookups_at(FOLD_E_BUS, 0));
    lookups
}

/// The per-instance public values, in AIR order. `pk_digest` pins the sponge (ciphertext binding);
/// `rel_pubs` pins the relation. The folds carry NO public values — their `ψ` is preprocessed, which
/// is what lets a per-row public multiplier exist at all (a row-local constraint cannot index a
/// public-value slice by row).
fn e_provenance_public_values(
    pk_digest: &[u8; 32],
    num_e: usize,
    num_f: usize,
    num_g: usize,
    rel_pubs: &[ConfigVal],
) -> Vec<Vec<ConfigVal>> {
    let mut pubs: Vec<Vec<ConfigVal>> = Vec::from([
        sponge_public_values(pk_digest),
        Vec::new(),
        ternary_public_values(num_e),
        bounded_public_values(num_f),
        bounded_public_values(num_g),
        Vec::new(), // μ bridge
    ]);
    for _ in 0..MU + 2 {
        pubs.push(Vec::new()); // MU e_r folds + g + encode
    }
    pubs.push(rel_pubs.to_vec()); // relation
    pubs
}

// ══════════════════════════════════════════════════════════════════════════════════════════════════
// R3a + f byte-provenance — binds BOTH e (ternary) AND f (bounded) to the XOF, proving the R3a
// `p_k = Σ_r B0_{r,k}·e_r + f_k` equations. This is what closes the classic `f = δ·unitₖ` insider
// spike: f_k is pinned to the bounded rejection-sampling of the XOF bytes drawn AFTER e (absolute
// offset `e_bytes`), so a spike f (out of range, or ≠ the XOF output) cannot produce a verifying proof.
//
// The selected columns are ρ-BATCHED into ONE relation (`Σ_k ρ_k·⟨D_{p_k}, κ⟩ = 0`). That is not a
// size optimisation: `corr_negacyclic` is linear in its public argument, so batching lets the `MU`
// `e_r` folds stay SHARED across the columns (one `ψ_r = corr(Σ_k ρ_k·B0_{r,k}, κ)` instead of one per
// column). Without it each column would need its own `MU` e-folds.
// ══════════════════════════════════════════════════════════════════════════════════════════════════

/// Public shape of an R3a+f byte-provenance proof — the sizes the verifier rebuilds AIRs/lookups
/// against (see [`EncProofShape`] for why these are public, not secret).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R3aProofShape {
    /// Sponge trace row count.
    pub sponge_height: usize,
    /// Ternary `e`-sampler coefficient count (`MU · N`).
    pub e_num_coeffs: usize,
    /// Bounded `f`-sampler coefficient count (`(max(columns)+1) · N`).
    pub f_num_coeffs: usize,
    /// Squeeze-byte limb coverage (sponge full squeeze).
    pub sponge_full_limbs: usize,
    /// Total XOF bytes consumed = `e`'s bytes + `f`'s bytes (the forwarded byte prefix).
    pub consumed_bytes: usize,
    /// Absolute XOF byte offset at which `f`'s draw begins (= `e`'s consumed byte count). The `f`
    /// sampler's byte-Receives are placed here on the shared absolute axis.
    pub f_offset: usize,
    /// The R3a columns `k` proven (each `p_k`). Must be the prefix `0..=max` that `f`'s coverage spans.
    pub columns: Vec<usize>,
}

/// The verifier-recomputable public data of a ρ-batched R3a proof at one challenge.
struct R3aPublic {
    /// The challenge vector `κ ∈ Z_q^N` — the multiplier for every `f_k` fold.
    kappa: Vec<u64>,
    /// `ψ_r = corr_negacyclic(Σ_k ρ_k·B0_{r,k}, κ)` — one per shared `e_r` fold.
    psi: Vec<Vec<u64>>,
    /// Relation coefficients: `MU` ones (the `e_r` terms) then `ρ_k` per selected column.
    a: Vec<u64>,
    /// `c = q − Σ_k ρ_k·⟨p_k, κ⟩`.
    c: u64,
}

/// Assemble [`R3aPublic`] from public data only (`B0`, the ciphertext's `p_k`, and the statement
/// challenges). `columns[i]`'s batching scalar is `rhos[i]`.
fn r3a_public(
    b0_cols_all: &[Vec<Vec<u64>>],
    p_all: &[Vec<u64>],
    columns: &[usize],
    kappa: Vec<u64>,
    rhos: &[u64],
) -> R3aPublic {
    // ψ_r = corr(Σ_k ρ_k·B0_{r,k}, κ). Linearity of `corr_negacyclic` in its first argument is what
    // makes the combine-then-correlate order valid (and what keeps the e-folds shared).
    let zero: Vec<u64> = alloc::vec![0u64; N];
    let psi: Vec<Vec<u64>> = (0..MU)
        .map(|r| {
            let cols: Vec<&[u64]> = columns
                .iter()
                .enumerate()
                .map(|(i, _)| b0_cols_all[i][r].as_slice())
                .collect();
            let combined = combine_public_multipliers(&zero, rhos, &cols, N);
            corr_negacyclic(&combined, &kappa, N)
        })
        .collect();

    let mut a = alloc::vec![1u64; MU];
    a.extend_from_slice(&rhos[..columns.len()]);

    let mut rhs: u128 = 0;
    let qq = u128::from(Q);
    for (i, _) in columns.iter().enumerate() {
        rhs = (rhs + u128::from(rhos[i]) * u128::from(dot_zq(&p_all[i], &kappa))) % qq;
    }
    let c = ((qq - rhs) % qq) as u64;

    R3aPublic { kappa, psi, a, c }
}

/// **Prover** assembly of the R3a+f byte-provenance layer for `(t0, μ, columns)`. Binds `e` (all
/// `MU·N` ternary coeffs) AND `f` (the bounded coeffs of `f_0..=f_max`, drawn at absolute offset
/// `e_bytes`) to the genuine SHAKE output, and proves the ρ-batched combination of
/// `p_k = Σ_r B0_{r,k}·e_r + f_k` over `columns`.
///
/// `columns` must be a prefix `0..=max` (the `f` sampler draws `f_0, f_1, …` in order, so covering
/// `f_max` requires covering all earlier `f_j`). Returns the ciphertext, the [`R3aProofShape`], and the
/// assembled instances.
///
/// # Panics
/// If `columns` is empty.
///
/// # Errors
/// [`EncProofError::TraceGeneration`] on a rejected trace or an exhausted XOF.
pub fn assemble_r3a_f_provenance_prover(
    t0: &[Rq],
    mu: &[u8; 32],
    columns: &[usize],
) -> Result<(Ciphertext, R3aProofShape, EncProvenanceProver), EncProofError> {
    assert!(!columns.is_empty(), "columns must be non-empty");
    let max_col = *columns.iter().max().unwrap();
    let f_cols = max_col + 1;
    let f_num = f_cols * N;

    let ct = encapsulate_derand(t0, mu);
    let w = fo_expand_witness(t0, mu);
    let input = encap_preimage(&w.pk_digest, mu);
    let b0 = key().b0();

    // Samplers over the real XOF at the KEM's fixed budgets: e (ternary), then the whole flat f block.
    // The f-sampler processes the KEM's entire `KAPPA·N` flat draw but *emits* only the first
    // `f_num = f_cols·N` coefficients (`f_0..f_max`); the remaining accepts are drained (byte-Received
    // for sponge balance, not folded), so a prefix of `f` is bound at a fixed byte boundary.
    let e_num = MU * N;
    let e_budget = E_TERNARY_ATTEMPTS;
    let f_budget_bytes = bounded_attempts(KAPPA * N) * 8;
    let bytes = shake256_xof(&input, e_budget + f_budget_bytes);
    let e_sampler = generate_ternary_trace(&bytes[..e_budget], e_num)?;
    let e_bytes = active_rows(&e_sampler, SAMPLER_WIDTH);
    let f_sampler = generate_bounded_trace(&bytes[e_budget..e_budget + f_budget_bytes], f_num)?;
    let f_bytes = active_rows(&f_sampler, BOUNDED_WIDTH) * 8;
    let total_consumed = e_bytes + f_bytes;

    let sponge = generate_provable_sponge_trace(&input, total_consumed + RATE_BYTES);
    let height = sponge.values.len() / NUM_KECCAK_COLS;
    let blocks = sponge_squeeze_blocks(height);
    let full_limbs = blocks * (RATE_BYTES / 2);
    let squeeze = generate_squeeze_byte_trace_partial(&input, full_limbs, total_consumed);

    // Public side (identical on the verifier).
    let (b0_cols_all, p_all) = r3a_public_columns(b0, &ct, columns);
    let (kappa, rhos) = statement_challenges(&w.pk_digest, &ct, 1, columns.len());
    let pubdata = r3a_public(&b0_cols_all, &p_all, columns, kappa[0].clone(), &rhos[0]);

    // Witness side: shared e_r folds (byte-bound), one f_k fold per column (byte-bound).
    let e_lifts: Zeroizing<Vec<Vec<u64>>> = Zeroizing::new(w.e.iter().map(rq_coeffs_zq).collect());
    let mut fold_traces = Vec::with_capacity(MU + columns.len());
    let mut w_terms = Vec::with_capacity(MU + columns.len());
    for (e, psi_r) in e_lifts.iter().zip(pubdata.psi.iter()) {
        let (t, ev) = generate_dot_trace(e, psi_r)?;
        fold_traces.push(t);
        w_terms.push(ev);
    }
    let mut f_traces = Vec::with_capacity(columns.len());
    for &k in columns {
        let f_k: Zeroizing<Vec<u64>> = Zeroizing::new(rq_coeffs_zq(&w.f[k]));
        let (t, ev) = generate_dot_trace(&f_k, &pubdata.kappa)?;
        f_traces.push(t);
        w_terms.push(ev);
    }

    let rc = RelationCheckAir {
        num_terms: MU + columns.len(),
    };
    let (rm, rel_pubs) = generate_relation_trace(&pubdata.a, &w_terms, pubdata.c)?;

    let airs = r3a_f_airs(height, e_num, f_num, columns.len(), &pubdata, &rc);
    let lookups = r3a_f_lookups(columns, e_bytes as u64, &rc);

    let mut traces: Vec<RowMajorMatrix<ConfigVal>> =
        Vec::from([sponge, squeeze, e_sampler, f_sampler]);
    traces.extend(fold_traces);
    traces.extend(f_traces);
    traces.push(pad_relation(&rm));

    let public_values = r3a_f_public_values(&w.pk_digest, e_num, f_num, columns.len(), &rel_pubs);

    let shape = R3aProofShape {
        sponge_height: height,
        e_num_coeffs: e_num,
        f_num_coeffs: f_num,
        sponge_full_limbs: full_limbs,
        consumed_bytes: total_consumed,
        f_offset: e_bytes,
        columns: columns.to_vec(),
    };
    Ok((
        ct,
        shape,
        EncProvenanceProver {
            airs,
            traces,
            public_values,
            lookups,
        },
    ))
}

/// **Verifier** assembly for the R3a+f layer: rebuilds every AIR from the public [`R3aProofShape`]
/// (including each fold's preprocessed `ψ`), the sponge pk-binding public values from
/// `pk_digest_of(t0)`, and the relation's `(a, c)` from `(B0, ct, κ, ρ)` — never prover-supplied.
/// Lookups rebuilt identically. Feed to `verify_batch`.
pub fn assemble_r3a_f_provenance_verifier(
    t0: &[Rq],
    ct: &Ciphertext,
    shape: &R3aProofShape,
) -> EncProvenanceVerifier {
    let pk_digest = lib_q_threshold_kem_lattice::kem::pk_digest_of(t0);
    let b0 = key().b0();
    let (b0_cols_all, p_all) = r3a_public_columns(b0, ct, &shape.columns);
    let (kappa, rhos) = statement_challenges(&pk_digest, ct, 1, shape.columns.len());
    let pubdata = r3a_public(
        &b0_cols_all,
        &p_all,
        &shape.columns,
        kappa[0].clone(),
        &rhos[0],
    );
    let rc = RelationCheckAir {
        num_terms: MU + shape.columns.len(),
    };

    let airs = r3a_f_airs(
        shape.sponge_height,
        shape.e_num_coeffs,
        shape.f_num_coeffs,
        shape.columns.len(),
        &pubdata,
        &rc,
    );
    let lookups = r3a_f_lookups(&shape.columns, shape.f_offset as u64, &rc);
    let rel_pubs = relation_public_values(&pubdata.a, pubdata.c);
    let public_values = r3a_f_public_values(
        &pk_digest,
        shape.e_num_coeffs,
        shape.f_num_coeffs,
        shape.columns.len(),
        &rel_pubs,
    );

    EncProvenanceVerifier {
        airs,
        public_values,
        lookups,
    }
}

/// The public per-column data of the R3a relations: `B0_{·,k}`'s coefficient columns and `p_k`, for
/// each selected column, in `columns` order.
fn r3a_public_columns(
    b0: &[Rq],
    ct: &Ciphertext,
    columns: &[usize],
) -> (Vec<Vec<Vec<u64>>>, Vec<Vec<u64>>) {
    let mut b0_cols_all = Vec::with_capacity(columns.len());
    let mut p_all = Vec::with_capacity(columns.len());
    for &k in columns {
        b0_cols_all.push(
            (0..MU)
                .map(|r| rq_coeffs_zq(&b0[r * KAPPA + k]))
                .collect::<Vec<Vec<u64>>>(),
        );
        p_all.push(rq_coeffs_zq(&ct.p[k]));
    }
    (b0_cols_all, p_all)
}

/// The R3a+f AIR list, in canonical order — built identically by prover and verifier.
fn r3a_f_airs(
    sponge_height: usize,
    e_num: usize,
    f_num: usize,
    n_cols: usize,
    pubdata: &R3aPublic,
    rc: &RelationCheckAir,
) -> Vec<EncProofAir> {
    let mut airs = Vec::from([
        EncProofAir::Sponge(ShakeSpongeAir {
            height: sponge_height,
        }),
        EncProofAir::SqueezeByte(SqueezeByteAir),
        EncProofAir::Ternary(TernarySamplerAir { num_coeffs: e_num }),
        EncProofAir::Bounded(BoundedSamplerAir { num_coeffs: f_num }),
    ]);
    for psi_r in &pubdata.psi {
        airs.push(EncProofAir::DotFold(DotFoldAir::new(psi_r.clone())));
    }
    for _ in 0..n_cols {
        airs.push(EncProofAir::DotFold(DotFoldAir::new(pubdata.kappa.clone())));
    }
    airs.push(EncProofAir::RelationCheck(rc.clone()));
    airs
}

/// The per-instance lookup lists for the R3a+f layer (identical prover/verifier — no witness). Order:
/// sponge, squeeze, e-sampler, f-sampler, `MU` shared e_r folds, one `f_k` fold per column, relation.
fn r3a_f_lookups(
    columns: &[usize],
    f_offset: u64,
    rc: &RelationCheckAir,
) -> Vec<Vec<Lookup<ConfigVal>>> {
    let mut lookups: Vec<Vec<Lookup<ConfigVal>>> = Vec::new();
    lookups.push(sponge_limb_send_lookups());
    lookups.push(Vec::from([
        squeeze_byte_send_lookup(),
        squeeze_byte_limb_receive_lookup(),
    ]));
    // e-sampler: byte-Receive (col 0) + coeff-Send (cols 1..5) on COEFF_E_BUS.
    let mut e_samp = Vec::from([ternary_receive_lookup()]);
    e_samp.extend(ternary_coeff_send_lookups_at(0, 1));
    lookups.push(e_samp);
    // f-sampler: 8 byte-Receives (cols 0..8) at absolute offset + coeff-Send (cols 8..12) on COEFF_F_BUS.
    let mut f_samp = bounded_receive_lookup_at(f_offset);
    f_samp.extend(bounded_coeff_send_lookups_col(COEFF_F_BUS, 0, 8));
    lookups.push(f_samp);
    // Shared e_r folds: coeff-Receive (cols 0..4) + one E-Send into the single batched relation.
    for r in 0..MU {
        let mut fl = fold_coeff_receive_lookups_at(COEFF_E_BUS, (r as u64) * (N as u64) * 4);
        fl.extend(fold_result_send_lookups_at(FOLD_E_BUS, 0, r, 4));
        lookups.push(fl);
    }
    // f_k folds: coeff-Receive from COEFF_F at base k·N·4 + E-Send to term MU+i.
    for (i, &k) in columns.iter().enumerate() {
        let mut fl = fold_coeff_receive_lookups_at(COEFF_F_BUS, (k as u64) * (N as u64) * 4);
        fl.extend(fold_result_send_lookups_at(FOLD_E_BUS, 0, MU + i, 4));
        lookups.push(fl);
    }
    lookups.push(rc.relation_w_receive_lookups_at(FOLD_E_BUS, 0));
    lookups
}

/// Per-instance public values for the R3a+f layer, in AIR order. Folds carry none (ψ is preprocessed).
fn r3a_f_public_values(
    pk_digest: &[u8; 32],
    e_num: usize,
    f_num: usize,
    n_cols: usize,
    rel_pubs: &[ConfigVal],
) -> Vec<Vec<ConfigVal>> {
    let mut pubs: Vec<Vec<ConfigVal>> = Vec::from([
        sponge_public_values(pk_digest),
        Vec::new(),
        ternary_public_values(e_num),
        bounded_public_values(f_num),
    ]);
    for _ in 0..MU + n_cols {
        pubs.push(Vec::new());
    }
    pubs.push(rel_pubs.to_vec());
    pubs
}

// ══════════════════════════════════════════════════════════════════════════════════════════════════
// FULL byte-provenance — the COMPLETE malformed-ciphertext closure, with m-challenge soundness.
//
// Binds e (ternary) + ALL f_k (bounded) + g (bounded) to the single XOF stream, and proves ALL KAPPA
// R3a `p_k` equations AND the R3b `v` equation, in ONE batch, over `m` independent Fiat–Shamir
// challenge VECTORS κ_0..κ_{m-1}. One verifying proof certifies the whole ciphertext is a genuine
// `(e,f,g) = XOF(pk‖μ)` encryption with e ternary and f,g bounded.
//
// ## Why `m` challenges — and why the amplification is real now
// Each challenge checks the ρ-batched residual `⟨D_v, κ⟩ + Σ_k ρ_k·⟨D_{p_k}, κ⟩ = 0`. Every operand
// of that functional is a coefficient column pinned by the byte-provenance buses, so for a fixed
// (malformed) ciphertext the check is a FIXED linear test with no prover freedom: it fails except with
// probability ≤ 2/q ≈ 2^-47 over (κ, ρ) — 1/q that the ρ-combination cancels a nonzero
// `⟨D_j, κ⟩`, plus 1/q that every `⟨D_j, κ⟩` vanished. Grinding `ct` redraws (κ, ρ) AND changes D, so
// m challenges cost ≈ (q/2)^m to forge; m = 3 ⇒ ≈ 2^141.
//
// This is the property the SUPERSEDED evaluation-at-ζ design did NOT have. There, each challenge
// carried its own free quotient fold, so the m equations were m independent one-unknown solves and m
// bought nothing — confirmed by exploit at m = 1 AND m = 3 at production FRI parameters (card
// `t_a73aaed2`). If you are tempted to reintroduce a per-challenge witness column that the buses do
// not pin, that is the bug.
//
// Sampler coefficient Sends are repeated `m×` (distinct aux columns), so the `m` per-challenge fold
// sets each Receive the (shared) coefficients once and every COEFF bus balances.
// ══════════════════════════════════════════════════════════════════════════════════════════════════

/// Witness terms in a challenge's R3b relation: `MU` `e_r`, `g`, `encode(μ)`.
const R3B_TERMS: usize = MU + 2;
/// Witness terms in a challenge's ρ-batched R3a relation: `MU` `e_r`, `KAPPA` `f_k`.
const R3A_TERMS: usize = MU + KAPPA;

// The two relations are NOT merged into one `MU + KAPPA + 2`-term check, even though the algebra
// allows it: `RelationCheckAir`'s honest carries are `≤ 4L·2^12` and must fit its `2^18` signed-carry
// offset, capping `L` at [`REL_MAX_TERMS`] = 15. A merged relation would be 17 terms and
// `generate_relation_trace` would reject it. Splitting costs one extra set of `MU` e-folds per
// challenge (their `ψ` differs between the two relations) and leaves the audited relation AIR
// untouched — the right trade in a soundness fix. These asserts turn a future `MU`/`KAPPA` bump into a
// build error rather than a runtime trace-generation failure.
const _: () = assert!(R3B_TERMS <= REL_MAX_TERMS);
const _: () = assert!(R3A_TERMS <= REL_MAX_TERMS);

/// FOLD_E_BUS span reserved per Fiat–Shamir challenge: challenge `i`'s R3b relation occupies
/// `[i·CHALLENGE_SPAN, … + 4·R3B_TERMS)` and its R3a relation the next `4·R3A_TERMS`, disjoint across
/// challenges.
const R3A_BASE_OFFSET: u64 = (R3B_TERMS as u64) * 4;
const CHALLENGE_SPAN: u64 = R3A_BASE_OFFSET + (R3A_TERMS as u64) * 4;

/// Public shape of a full-provenance proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FullProofShape {
    /// Sponge trace row count.
    pub sponge_height: usize,
    /// Ternary `e`-sampler coeff count (`MU·N`).
    pub e_num_coeffs: usize,
    /// Bounded `f`-sampler coeff count (`KAPPA·N`).
    pub f_num_coeffs: usize,
    /// Bounded `g`-sampler coeff count (`N`).
    pub g_num_coeffs: usize,
    /// Squeeze-byte limb coverage.
    pub sponge_full_limbs: usize,
    /// Total consumed XOF bytes (`e` + all `f` + `g`).
    pub consumed_bytes: usize,
    /// Absolute XOF offset where `f`'s draw begins (= `e_bytes`).
    pub f_offset: usize,
    /// Absolute XOF offset where `g`'s draw begins (= `e_bytes + f_bytes`).
    pub g_offset: usize,
    /// Number of independent Fiat–Shamir challenges (soundness amplification factor).
    pub num_challenges: usize,
}

/// The `m` challenge vectors `κ_i` and per-challenge batching scalars `ρ_i` of the statement
/// `(pk_digest ‖ ct)`.
///
/// Absorbing `pk_digest` alongside the ciphertext gives multi-target separation (the H4 transcript
/// half); the verifier recomputes both identically from `(t0, ct)`, so neither is prover-supplied.
/// `κ` and `ρ` are drawn under SEPARATE domain tags — the soundness bound treats them as independent.
///
/// // WIRE CHANGE (card `t_a73aaed2`): this replaces `statement_zetas`, which produced scalar
/// // evaluation points for the unsound quotient-witnessed relation. Proofs produced by earlier code
/// // do NOT verify under this code and vice versa. No KAT in this repo pins the old transcript; the
/// // crate is RED/unsigned and pre-1.0 with zero consumers.
fn statement_challenges(
    pk_digest: &[u8; 32],
    ct: &Ciphertext,
    m: usize,
    n_rho: usize,
) -> (Vec<Vec<u64>>, Vec<Vec<u64>>) {
    let ct_bytes = ct.to_bytes();
    (
        statement_kappas(pk_digest, &ct_bytes, m, N),
        statement_rhos(pk_digest, &ct_bytes, m, n_rho.max(1)),
    )
}

/// The verifier-recomputable public data of one challenge's two relations.
struct FullPublic {
    /// The challenge vector `κ ∈ Z_q^N` — multiplier for the `f_k`, `g` and `encode(μ)` folds.
    kappa: Vec<u64>,
    /// R3b: `ψ_r = corr_negacyclic(t0_r, κ)`.
    psi_b: Vec<Vec<u64>>,
    /// R3a: `ψ_r = corr_negacyclic(Σ_k ρ_k·B0_{r,k}, κ)` — the ρ-batching that keeps ONE set of
    /// `e_r` folds serving all `KAPPA` columns.
    psi_a: Vec<Vec<u64>>,
    /// R3b coefficients (`MU + 2` ones) and `c_b = q − ⟨v, κ⟩`.
    a_b: Vec<u64>,
    c_b: u64,
    /// R3a coefficients (`MU` ones then `ρ_k`) and `c_a = q − Σ_k ρ_k·⟨p_k, κ⟩`.
    a_a: Vec<u64>,
    c_a: u64,
}

/// Assemble [`FullPublic`] from public data only.
fn full_public(
    t0_cols: &[Vec<u64>],
    b0_cols_all: &[Vec<Vec<u64>>],
    p_all: &[Vec<u64>],
    v_z: &[u64],
    kappa: Vec<u64>,
    rhos: &[u64],
) -> FullPublic {
    let zero: Vec<u64> = alloc::vec![0u64; N];
    let psi_b: Vec<Vec<u64>> = (0..MU)
        .map(|r| corr_negacyclic(&t0_cols[r], &kappa, N))
        .collect();
    let psi_a: Vec<Vec<u64>> = (0..MU)
        .map(|r| {
            let cols: Vec<&[u64]> = (0..KAPPA).map(|k| b0_cols_all[k][r].as_slice()).collect();
            corr_negacyclic(
                &combine_public_multipliers(&zero, rhos, &cols, N),
                &kappa,
                N,
            )
        })
        .collect();

    let a_b = alloc::vec![1u64; R3B_TERMS];
    let c_b = (Q - dot_zq(v_z, &kappa)) % Q;

    let mut a_a = alloc::vec![1u64; MU];
    a_a.extend_from_slice(&rhos[..KAPPA]);
    let qq = u128::from(Q);
    let mut rhs: u128 = 0;
    for k in 0..KAPPA {
        rhs = (rhs + u128::from(rhos[k]) * u128::from(dot_zq(&p_all[k], &kappa))) % qq;
    }
    let c_a = ((qq - rhs) % qq) as u64;

    FullPublic {
        kappa,
        psi_b,
        psi_a,
        a_b,
        c_b,
        a_a,
        c_a,
    }
}

/// **Prover** assembly of the FULL `m`-challenge byte-provenance proof for `(t0, μ)`. Binds `e`, all
/// `KAPPA` `f_k`, and `g` to the single SHAKE stream (offsets `0`, `e_bytes`, `e_bytes+f_bytes`), and
/// proves R3b plus the ρ-batched R3a over all `KAPPA` columns, at each of `num_challenges`
/// independent challenges. Returns the ciphertext, the [`FullProofShape`], and the instances.
///
/// # Panics
/// If `num_challenges == 0`.
///
/// # Errors
/// [`EncProofError::TraceGeneration`] on a rejected trace or exhausted XOF.
pub fn assemble_full_provenance_prover(
    t0: &[Rq],
    mu: &[u8; 32],
    num_challenges: usize,
) -> Result<(Ciphertext, FullProofShape, EncProvenanceProver), EncProofError> {
    assert!(num_challenges >= 1, "num_challenges must be ≥ 1");
    let m = num_challenges;
    let ct = encapsulate_derand(t0, mu);
    let w = fo_expand_witness(t0, mu);
    let input = encap_preimage(&w.pk_digest, mu);
    let b0 = key().b0();

    // Samplers over the real XOF at the KEM's fixed budgets: e (ternary), the flat f block (all KAPPA
    // elements), then g — each a contiguous fixed-width byte range matching the constant-time sampler.
    let e_num = MU * N;
    let f_num = KAPPA * N;
    let g_num = N;
    let e_budget = E_TERNARY_ATTEMPTS;
    let f_budget_bytes = bounded_attempts(f_num) * 8;
    let g_budget_bytes = bounded_attempts(g_num) * 8;
    let bytes = shake256_xof(&input, e_budget + f_budget_bytes + g_budget_bytes);
    let e_sampler = generate_ternary_trace(&bytes[..e_budget], e_num)?;
    let e_bytes = active_rows(&e_sampler, SAMPLER_WIDTH);
    let f_sampler = generate_bounded_trace(&bytes[e_budget..e_budget + f_budget_bytes], f_num)?;
    let f_bytes = active_rows(&f_sampler, BOUNDED_WIDTH) * 8;
    let g_sampler = generate_bounded_trace(
        &bytes[e_budget + f_budget_bytes..e_budget + f_budget_bytes + g_budget_bytes],
        g_num,
    )?;
    let g_bytes = active_rows(&g_sampler, BOUNDED_WIDTH) * 8;
    let total_consumed = e_bytes + f_bytes + g_bytes;

    let sponge = generate_provable_sponge_trace(&input, total_consumed + RATE_BYTES);
    let height = sponge.values.len() / NUM_KECCAK_COLS;
    let blocks = sponge_squeeze_blocks(height);
    let full_limbs = blocks * (RATE_BYTES / 2);
    let squeeze = generate_squeeze_byte_trace_partial(&input, full_limbs, total_consumed);

    // Public side, per challenge (identical on the verifier).
    let all_columns: Vec<usize> = (0..KAPPA).collect();
    let (b0_cols_all, p_all) = r3a_public_columns(b0, &ct, &all_columns);
    let t0_cols: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();
    let v_z = rq_coeffs_zq(&ct.v);
    let (kappas, rhos) = statement_challenges(&w.pk_digest, &ct, m, KAPPA);
    let pubdata: Vec<FullPublic> = (0..m)
        .map(|i| {
            full_public(
                &t0_cols,
                &b0_cols_all,
                &p_all,
                &v_z,
                kappas[i].clone(),
                &rhos[i],
            )
        })
        .collect();

    // Witness side (computed once; folded per challenge).
    let e_lifts: Zeroizing<Vec<Vec<u64>>> = Zeroizing::new(w.e.iter().map(rq_coeffs_zq).collect());
    let g_z: Zeroizing<Vec<u64>> = Zeroizing::new(rq_coeffs_zq(&w.g));
    let f_lifts: Vec<Zeroizing<Vec<u64>>> = (0..KAPPA)
        .map(|k| Zeroizing::new(rq_coeffs_zq(&w.f[k])))
        .collect();

    let rc_b = RelationCheckAir {
        num_terms: R3B_TERMS,
    };
    let rc_a = RelationCheckAir {
        num_terms: R3A_TERMS,
    };
    let mut per_challenge_traces: Vec<Vec<RowMajorMatrix<ConfigVal>>> = Vec::with_capacity(m);
    let mut per_challenge_relpubs: Vec<(Vec<ConfigVal>, Vec<ConfigVal>)> = Vec::with_capacity(m);
    for pd in &pubdata {
        let mut traces_i: Vec<RowMajorMatrix<ConfigVal>> = Vec::new();

        // R3b block: MU e-folds (ψ from t0), g, encode, relation.
        let mut w_b = Vec::with_capacity(R3B_TERMS);
        for (e, psi_r) in e_lifts.iter().zip(pd.psi_b.iter()) {
            let (t, ev) = generate_dot_trace(e, psi_r)?;
            traces_i.push(t);
            w_b.push(ev);
        }
        let (g_trace, g_ev) = generate_dot_trace(&g_z, &pd.kappa)?;
        let (enc_trace, enc_ev) = generate_encode_mu_trace(mu, &pd.kappa[..MSG_BITS])?;
        w_b.push(g_ev);
        w_b.push(enc_ev);
        traces_i.push(g_trace);
        traces_i.push(enc_trace);
        let (rm_b, relpubs_b) = generate_relation_trace(&pd.a_b, &w_b, pd.c_b)?;
        traces_i.push(pad_relation(&rm_b));

        // R3a block: MU e-folds (ψ from the ρ-combined B0), KAPPA f-folds, relation.
        let mut w_a = Vec::with_capacity(R3A_TERMS);
        for (e, psi_r) in e_lifts.iter().zip(pd.psi_a.iter()) {
            let (t, ev) = generate_dot_trace(e, psi_r)?;
            traces_i.push(t);
            w_a.push(ev);
        }
        for f_k in &f_lifts {
            let (t, ev) = generate_dot_trace(f_k, &pd.kappa)?;
            traces_i.push(t);
            w_a.push(ev);
        }
        let (rm_a, relpubs_a) = generate_relation_trace(&pd.a_a, &w_a, pd.c_a)?;
        traces_i.push(pad_relation(&rm_a));

        per_challenge_traces.push(traces_i);
        per_challenge_relpubs.push((relpubs_b, relpubs_a));
    }

    let airs = full_airs(height, e_num, f_num, g_num, &pubdata, &rc_b, &rc_a);
    let lookups = full_lookups(m, e_bytes as u64, (e_bytes + f_bytes) as u64, &rc_b, &rc_a);

    let mut traces: Vec<RowMajorMatrix<ConfigVal>> = Vec::from([
        sponge,
        squeeze,
        e_sampler,
        f_sampler,
        g_sampler,
        generate_mu_bits_trace(mu),
    ]);
    for ti in per_challenge_traces {
        traces.extend(ti);
    }

    let public_values =
        full_public_values(&w.pk_digest, e_num, f_num, g_num, &per_challenge_relpubs);

    let shape = FullProofShape {
        sponge_height: height,
        e_num_coeffs: e_num,
        f_num_coeffs: f_num,
        g_num_coeffs: g_num,
        sponge_full_limbs: full_limbs,
        consumed_bytes: total_consumed,
        f_offset: e_bytes,
        g_offset: e_bytes + f_bytes,
        num_challenges: m,
    };
    Ok((
        ct,
        shape,
        EncProvenanceProver {
            airs,
            traces,
            public_values,
            lookups,
        },
    ))
}

/// **Verifier** assembly of the full `m`-challenge proof: rebuilds every AIR from [`FullProofShape`]
/// (including every fold's preprocessed `ψ`), the sponge pk-binding pubs from `pk_digest_of(t0)`, and
/// each challenge's relation coefficients from `(B0, t0, ct, κ_i, ρ_i)`. Feed to `verify_batch`.
pub fn assemble_full_provenance_verifier(
    t0: &[Rq],
    ct: &Ciphertext,
    shape: &FullProofShape,
) -> EncProvenanceVerifier {
    let m = shape.num_challenges;
    let pk_digest = lib_q_threshold_kem_lattice::kem::pk_digest_of(t0);
    let b0 = key().b0();
    let all_columns: Vec<usize> = (0..KAPPA).collect();
    let (b0_cols_all, p_all) = r3a_public_columns(b0, ct, &all_columns);
    let t0_cols: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();
    let v_z = rq_coeffs_zq(&ct.v);
    let (kappas, rhos) = statement_challenges(&pk_digest, ct, m, KAPPA);
    let pubdata: Vec<FullPublic> = (0..m)
        .map(|i| {
            full_public(
                &t0_cols,
                &b0_cols_all,
                &p_all,
                &v_z,
                kappas[i].clone(),
                &rhos[i],
            )
        })
        .collect();

    let rc_b = RelationCheckAir {
        num_terms: R3B_TERMS,
    };
    let rc_a = RelationCheckAir {
        num_terms: R3A_TERMS,
    };
    let airs = full_airs(
        shape.sponge_height,
        shape.e_num_coeffs,
        shape.f_num_coeffs,
        shape.g_num_coeffs,
        &pubdata,
        &rc_b,
        &rc_a,
    );
    let lookups = full_lookups(
        m,
        shape.f_offset as u64,
        shape.g_offset as u64,
        &rc_b,
        &rc_a,
    );
    let per_challenge_relpubs: Vec<(Vec<ConfigVal>, Vec<ConfigVal>)> = pubdata
        .iter()
        .map(|pd| {
            (
                relation_public_values(&pd.a_b, pd.c_b),
                relation_public_values(&pd.a_a, pd.c_a),
            )
        })
        .collect();
    let public_values = full_public_values(
        &pk_digest,
        shape.e_num_coeffs,
        shape.f_num_coeffs,
        shape.g_num_coeffs,
        &per_challenge_relpubs,
    );

    EncProvenanceVerifier {
        airs,
        public_values,
        lookups,
    }
}

/// The full-tier AIR list, in canonical order — built identically by prover and verifier.
fn full_airs(
    sponge_height: usize,
    e_num: usize,
    f_num: usize,
    g_num: usize,
    pubdata: &[FullPublic],
    rc_b: &RelationCheckAir,
    rc_a: &RelationCheckAir,
) -> Vec<EncProofAir> {
    let mut airs = Vec::from([
        EncProofAir::Sponge(ShakeSpongeAir {
            height: sponge_height,
        }),
        EncProofAir::SqueezeByte(SqueezeByteAir),
        EncProofAir::Ternary(TernarySamplerAir { num_coeffs: e_num }),
        EncProofAir::Bounded(BoundedSamplerAir { num_coeffs: f_num }),
        EncProofAir::Bounded(BoundedSamplerAir { num_coeffs: g_num }),
        EncProofAir::MuBits(MuBitsAir),
    ]);
    for pd in pubdata {
        for psi_r in &pd.psi_b {
            airs.push(EncProofAir::DotFold(DotFoldAir::new(psi_r.clone())));
        }
        airs.push(EncProofAir::DotFold(DotFoldAir::new(pd.kappa.clone()))); // g
        airs.push(EncProofAir::EncodeMuFold(EncodeMuFoldAir::new(
            pd.kappa[..MSG_BITS].to_vec(),
        ))); // encode
        airs.push(EncProofAir::RelationCheck(rc_b.clone()));
        for psi_r in &pd.psi_a {
            airs.push(EncProofAir::DotFold(DotFoldAir::new(psi_r.clone())));
        }
        for _ in 0..KAPPA {
            airs.push(EncProofAir::DotFold(DotFoldAir::new(pd.kappa.clone())));
        }
        airs.push(EncProofAir::RelationCheck(rc_a.clone()));
    }
    airs
}

/// Per-instance lookups for the full `m`-challenge proof (identical prover/verifier).
///
/// The `e`-sampler Sends each coefficient `2m×` — TWICE per challenge, because a challenge has two
/// sets of `e_r` folds (one per relation, with different `ψ`) and each Receives the coefficients
/// once. The `f`/`g` samplers Send `m×`. Getting these multiplicities wrong unbalances a COEFF bus,
/// which `verify_batch` rejects — so the counts here are load-bearing, not bookkeeping.
fn full_lookups(
    m: usize,
    f_offset: u64,
    g_offset: u64,
    rc_b: &RelationCheckAir,
    rc_a: &RelationCheckAir,
) -> Vec<Vec<Lookup<ConfigVal>>> {
    let mut lookups: Vec<Vec<Lookup<ConfigVal>>> = Vec::new();
    let mut sponge_lk = sponge_limb_send_lookups();
    sponge_lk.extend(sponge_mu_limb_send_lookups()); // μ binding (card t_a73aaed2, GAP 2)
    lookups.push(sponge_lk);
    lookups.push(Vec::from([
        squeeze_byte_send_lookup(),
        squeeze_byte_limb_receive_lookup(),
    ]));
    let mut e_samp = Vec::from([ternary_receive_lookup()]);
    for i in 0..2 * m {
        e_samp.extend(ternary_coeff_send_lookups_at(0, 1 + 4 * i));
    }
    lookups.push(e_samp);
    let mut f_samp = bounded_receive_lookup_at(f_offset);
    for i in 0..m {
        f_samp.extend(bounded_coeff_send_lookups_col(COEFF_F_BUS, 0, 8 + 4 * i));
    }
    lookups.push(f_samp);
    let mut g_samp = bounded_receive_lookup_at(g_offset);
    for i in 0..m {
        g_samp.extend(bounded_coeff_send_lookups_col(COEFF_G_BUS, 0, 8 + 4 * i));
    }
    lookups.push(g_samp);
    lookups.push(mu_bits_lookups(m)); // μ bridge Sends the 256 bits once per challenge's encode fold

    for i in 0..m {
        let base_b = (i as u64) * CHALLENGE_SPAN;
        let base_a = base_b + R3A_BASE_OFFSET;
        // R3b: MU e-folds, g, encode, relation.
        for r in 0..MU {
            let mut fl = fold_coeff_receive_lookups_at(COEFF_E_BUS, (r as u64) * (N as u64) * 4);
            fl.extend(fold_result_send_lookups_at(FOLD_E_BUS, base_b, r, 4));
            lookups.push(fl);
        }
        let mut gl = fold_coeff_receive_lookups_at(COEFF_G_BUS, 0);
        gl.extend(fold_result_send_lookups_at(FOLD_E_BUS, base_b, MU, 4));
        lookups.push(gl);
        let mut enc_lk = fold_result_send_lookups_at(FOLD_E_BUS, base_b, MU + 1, 0);
        enc_lk.extend(encode_mu_bit_receive_lookup(4)); // μ-bit Receive
        lookups.push(enc_lk);
        lookups.push(rc_b.relation_w_receive_lookups_at(FOLD_E_BUS, base_b));
        // R3a: MU e-folds (different ψ, same committed coefficients), KAPPA f-folds, relation.
        for r in 0..MU {
            let mut fl = fold_coeff_receive_lookups_at(COEFF_E_BUS, (r as u64) * (N as u64) * 4);
            fl.extend(fold_result_send_lookups_at(FOLD_E_BUS, base_a, r, 4));
            lookups.push(fl);
        }
        for k in 0..KAPPA {
            let mut fl = fold_coeff_receive_lookups_at(COEFF_F_BUS, (k as u64) * (N as u64) * 4);
            fl.extend(fold_result_send_lookups_at(FOLD_E_BUS, base_a, MU + k, 4));
            lookups.push(fl);
        }
        lookups.push(rc_a.relation_w_receive_lookups_at(FOLD_E_BUS, base_a));
    }
    lookups
}

/// Per-instance public values for the full `m`-challenge proof, in AIR order.
fn full_public_values(
    pk_digest: &[u8; 32],
    e_num: usize,
    f_num: usize,
    g_num: usize,
    per_challenge_relpubs: &[(Vec<ConfigVal>, Vec<ConfigVal>)],
) -> Vec<Vec<ConfigVal>> {
    let mut pubs: Vec<Vec<ConfigVal>> = Vec::from([
        sponge_public_values(pk_digest),
        Vec::new(),
        ternary_public_values(e_num),
        bounded_public_values(f_num),
        bounded_public_values(g_num),
        Vec::new(), // μ bridge
    ]);
    for (relpubs_b, relpubs_a) in per_challenge_relpubs {
        for _ in 0..R3B_TERMS {
            pubs.push(Vec::new()); // MU e-folds + g + encode
        }
        pubs.push(relpubs_b.clone());
        for _ in 0..R3A_TERMS {
            pubs.push(Vec::new()); // MU e-folds + KAPPA f-folds
        }
        pubs.push(relpubs_a.clone());
    }
    pubs
}

/// Reference SHAKE-256 XOF of `input` (`n` bytes) — the ground-truth squeeze stream the sampler and
/// squeeze-byte table consume.
fn shake256_xof(input: &[u8], n: usize) -> Vec<u8> {
    use lib_q_sha3::{
        ExtendableOutput,
        Update,
        XofReader,
    };
    let mut h = lib_q_sha3::Shake256::default();
    h.update(input);
    let mut rd = h.finalize_xof();
    #[cfg(not(feature = "std"))]
    let mut out = alloc::vec![0u8; n];
    #[cfg(feature = "std")]
    let mut out = vec![0u8; n];
    rd.read(&mut out);
    out
}

/// Number of squeeze blocks (final-step rows) in a sponge trace of `height` rows.
fn sponge_squeeze_blocks(height: usize) -> usize {
    (0..height)
        .filter(|r| r % NUM_ROUNDS == NUM_ROUNDS - 1)
        .count()
}

#[cfg(test)]
mod tests {
    use lib_q_plonky_batch_stark::{
        CommonData,
        ProverData,
        ProverOnlyData,
        StarkInstance,
        prove_batch,
        verify_batch,
    };
    use lib_q_plonky_uni_stark::StarkConfig;
    use lib_q_stark_challenger::{
        ComplexFieldChallenger,
        Shake256Challenger32,
    };
    use lib_q_stark_fri::{
        FriParameters,
        create_test_fri_params,
    };
    use lib_q_stark_mersenne31::Mersenne31;
    use lib_q_stark_shake256::Shake256Hash;
    use lib_q_threshold_kem_lattice::kem::encode_msg;
    use lib_q_zkp::stark::{
        ConfigChallenge,
        ConfigDft,
        DefaultValMmcs,
        MembershipChallengeMmcs,
        MembershipPcs,
    };

    use super::*;
    use crate::logup_join::MU_BIT_BUS;

    type TestChallenger = ComplexFieldChallenger<Shake256Challenger32<Mersenne31>>;
    // S1 fix (SECURITY_REVIEW §8): the composed proof runs over the degree-3 challenge extension
    // `ConfigChallenge = GF(p^6)` (~186 bits), NOT the value field `ConfigVal = GF(p^2)` (~62 bits).
    // The 62-bit challenge field was a hard ceiling on Fiat–Shamir/DEEP/FRI-fold soundness far below
    // 128, un-rescued by the m-challenge (which only amplifies the Layer-A ciphertext-grind term).
    // `MembershipPcs` is the same value field / DFT / Merkle commitment as `DefaultPcs`; only the
    // FRI challenge field is the larger extension. Mirrors the sibling membership STARK.
    type Cfg = StarkConfig<MembershipPcs, ConfigChallenge, TestChallenger>;

    /// Assemble a `StarkConfig` from a set of FRI parameters (shared plumbing for the test and
    /// production configs).
    fn config_from_fri(
        fri_params: FriParameters<MembershipChallengeMmcs>,
        val_mmcs: DefaultValMmcs,
    ) -> Cfg {
        let dft = ConfigDft::default();
        let pcs = MembershipPcs::new(dft, val_mmcs, fri_params);
        let base = Shake256Challenger32::<Mersenne31>::from_hasher(Vec::new(), Shake256Hash);
        StarkConfig::new(pcs, ComplexFieldChallenger::new(base))
    }

    fn mmcs_pair() -> (DefaultValMmcs, MembershipChallengeMmcs) {
        let shake = Shake256Hash {};
        let hash = lib_q_stark_symmetric::SerializingHasher::<Shake256Hash>::new(shake);
        let compress =
            lib_q_stark_symmetric::CompressionFunctionFromHasher::<Shake256Hash, 2, 32>::new(shake);
        let val_mmcs = DefaultValMmcs::new(hash, compress);
        let challenge_mmcs = MembershipChallengeMmcs::new(val_mmcs.clone());
        (val_mmcs, challenge_mmcs)
    }

    /// **Test** FRI params (2 queries, 1 PoW bit) — fast, NOT production-sound.
    fn test_batch_config() -> Cfg {
        let (val_mmcs, challenge_mmcs) = mmcs_pair();
        config_from_fri(create_test_fri_params(challenge_mmcs, 2), val_mmcs)
    }

    /// **Production-grade** FRI params. `log_blowup = 2` (rate 1/4) with `num_queries = 64` gives a
    /// conjectured FRI soundness of ≈ `num_queries · log_blowup = 128` bits (list-decoding-regime
    /// caveats apply — this is the standard STARK conjecture, not a proven bound), plus a 16-bit
    /// grinding (`proof_of_work_bits`) factor against query-grinding. These are the parameters the
    /// composed encryption proof must remain sound at; the round-trip and spike-rejection tests below
    /// run against this config (behind `#[ignore]` only for wall-clock, not soundness, reasons).
    fn production_batch_config() -> Cfg {
        let (val_mmcs, challenge_mmcs) = mmcs_pair();
        let fri_params = FriParameters {
            log_blowup: 2,
            log_final_poly_len: 0,
            num_queries: 64,
            proof_of_work_bits: 16,
            mmcs: challenge_mmcs,
        };
        config_from_fri(fri_params, val_mmcs)
    }

    /// Hand-assemble the batch prover's committed preprocessed data (the batch API provides no
    /// builder). For each AIR that returns a `preprocessed_trace()`, commit its matrix through the
    /// config's PCS; AIRs without one get a `None` slot. (Lifted verbatim from `compose::tests`.)
    fn build_preprocessed<SC, A>(
        config: &SC,
        airs: &[A],
    ) -> (
        Option<lib_q_plonky_batch_stark::common::GlobalPreprocessed<SC>>,
        ProverOnlyData<SC>,
    )
    where
        SC: lib_q_plonky_uni_stark::StarkGenericConfig,
        A: BaseAir<lib_q_plonky_uni_stark::Val<SC>>,
    {
        use lib_q_plonky_batch_stark::common::{
            GlobalPreprocessed,
            PreprocessedInstanceMeta,
        };
        use lib_q_stark_commit::Pcs;

        let pcs = config.pcs();
        let is_zk = config.is_zk();
        let mut inputs = Vec::new();
        let mut instances = Vec::with_capacity(airs.len());
        let mut matrix_to_instance = Vec::new();
        for (i, air) in airs.iter().enumerate() {
            match air.preprocessed_trace() {
                Some(mat) => {
                    let width = mat.width;
                    let height = mat.values.len() / width;
                    let degree_bits = height.trailing_zeros() as usize;
                    let ext_db = degree_bits + is_zk;
                    let domain = pcs.natural_domain_for_degree(1usize << ext_db);
                    let matrix_index = inputs.len();
                    inputs.push((domain, mat));
                    instances.push(Some(PreprocessedInstanceMeta {
                        matrix_index,
                        width,
                        degree_bits: ext_db,
                    }));
                    matrix_to_instance.push(i);
                }
                None => instances.push(None),
            }
        }
        if inputs.is_empty() {
            return (None, ProverOnlyData::empty());
        }
        let (commitment, prover_data) = pcs.commit(inputs);
        (
            Some(GlobalPreprocessed {
                commitment,
                instances,
                matrix_to_instance,
            }),
            ProverOnlyData {
                preprocessed_prover_data: Some(prover_data),
            },
        )
    }

    use lib_q_stark_air::BaseAir;

    /// A small, structured `t0` public key for deterministic tests.
    fn test_t0() -> Vec<Rq> {
        (0..MU)
            .map(|r| {
                let mut c = [0i64; N];
                for (i, ci) in c.iter_mut().enumerate() {
                    *ci = (i as i64 * 31 + r as i64 * 7) % lib_q_dkg::lattice::ring::Q;
                }
                Rq::from_coeffs(c)
            })
            .collect()
    }

    /// Build the prover `StarkInstance`s from an assembled prover layer + preprocessed data.
    fn prover_instances<'a>(
        prover: &'a EncProvenanceProver,
    ) -> Vec<StarkInstance<'a, Cfg, EncProofAir>> {
        prover
            .airs
            .iter()
            .zip(prover.traces.iter())
            .zip(prover.public_values.iter())
            .zip(prover.lookups.iter())
            .map(|(((air, trace), pv), lk)| StarkInstance {
                air,
                trace,
                public_values: pv.clone(),
                lookups: lk.clone(),
            })
            .collect()
    }

    /// Prove + verify the composed byte-provenance proof for `(t0, μ)` under `config`, rebuilding the
    /// verifier side from public inputs only. Returns whether `verify_batch` accepted. Panics on a
    /// prove error (a well-formed witness must always prove).
    fn prove_and_verify(config: &Cfg, t0: &[Rq], mu: &[u8; 32]) -> bool {
        let (ct, shape, prover) = assemble_e_provenance_prover(t0, mu)
            .expect("prover assembly for a well-formed witness");
        let (global, prover_only) = build_preprocessed(config, &prover.airs);
        let common = CommonData::new(global, prover.lookups.clone());
        let prover_data = ProverData {
            common,
            prover_only,
        };
        let instances = prover_instances(&prover);
        let proof = prove_batch(config, &instances, &prover_data).expect("prove_batch");

        // Verifier: rebuild entirely from public inputs (t0, ct, shape) — no witness, no prover data.
        let verifier = assemble_e_provenance_verifier(t0, &ct, shape);
        let (vglobal, _) = build_preprocessed(config, &verifier.airs);
        let vcommon = CommonData::new(vglobal, verifier.lookups.clone());
        verify_batch(
            config,
            &verifier.airs,
            &proof,
            &verifier.public_values,
            &vcommon,
        )
        .is_ok()
    }

    // ── Hiding-FRI (zero-knowledge) config (task #32): blinds the witness so the proof reveals nothing
    //    about μ beyond the statement. Mirrors `compose::tests::test_batch_config_zk`. ──
    type ZkValMmcs = lib_q_stark_merkle::MerkleTreeHidingMmcs<
        <ConfigVal as lib_q_stark_field::Field>::Packing,
        u8,
        lib_q_stark_symmetric::SerializingHasher<Shake256Hash>,
        lib_q_stark_symmetric::CompressionFunctionFromHasher<Shake256Hash, 2, 32>,
        lib_q_random::DeterministicRng,
        32,
        4,
    >;
    // S1 fix (SECURITY_REVIEW §8): ZK path also runs over the GF(p^6) challenge extension, not the
    // ~62-bit value field. Mirrors `MembershipZkChallengeMmcs`/`MembershipZkConfig`.
    type ZkChallengeMmcs = lib_q_stark_commit::ExtensionMmcs<ConfigVal, ConfigChallenge, ZkValMmcs>;
    type ZkPcs = lib_q_stark_fri::HidingFriPcs<
        ConfigVal,
        ConfigDft,
        ZkValMmcs,
        ZkChallengeMmcs,
        lib_q_random::DeterministicRng,
    >;
    type ZkCfg = StarkConfig<ZkPcs, ConfigChallenge, TestChallenger>;

    /// A hiding-FRI (zero-knowledge) config at test FRI params: `is_zk() == 1`, so the batch prover
    /// blinds the trace + randomizes the quotient (μ is blinded). The ZK code path a deployment uses.
    fn zk_batch_config() -> ZkCfg {
        use lib_q_random::DeterministicRng;
        let shake = Shake256Hash {};
        let hash = lib_q_stark_symmetric::SerializingHasher::<Shake256Hash>::new(shake);
        let compress =
            lib_q_stark_symmetric::CompressionFunctionFromHasher::<Shake256Hash, 2, 32>::new(shake);
        let val_mmcs = ZkValMmcs::new(hash, compress, DeterministicRng::seed_from_u64(1));
        let challenge_mmcs = ZkChallengeMmcs::new(val_mmcs.clone());
        let dft = ConfigDft::default();
        let fri_params = lib_q_stark_fri::create_test_fri_params_zk(challenge_mmcs);
        let pcs = ZkPcs::new(
            dft,
            val_mmcs,
            fri_params,
            4,
            DeterministicRng::seed_from_u64(1),
        );
        let base = Shake256Challenger32::<Mersenne31>::from_hasher(Vec::new(), Shake256Hash);
        StarkConfig::new(pcs, ComplexFieldChallenger::new(base))
    }

    /// **Zero-knowledge round-trip (task #32).** The `e`-provenance proof proven + verified under the
    /// **hiding-FRI** config (`is_zk() == 1`): the prover blinds every committed matrix and randomizes
    /// the quotient, so the proof is zero-knowledge (μ is not revealed) while remaining sound. This
    /// exercises the ZK code path the deployment gate uses; `#[ignore]` for wall-clock.
    #[test]
    #[ignore = "heavy: hiding-FRI ZK config over the N=1024 e-provenance batch"]
    fn e_provenance_zero_knowledge_round_trip() {
        let t0 = test_t0();
        let mu = [0x6Bu8; 32];
        let config = zk_batch_config();
        let (ct, shape, prover) = assemble_e_provenance_prover(&t0, &mu).expect("prover assembly");
        let (global, prover_only) = build_preprocessed(&config, &prover.airs);
        let common = CommonData::new(global, prover.lookups.clone());
        let prover_data = ProverData {
            common,
            prover_only,
        };
        let instances: Vec<StarkInstance<'_, ZkCfg, EncProofAir>> = prover
            .airs
            .iter()
            .zip(prover.traces.iter())
            .zip(prover.public_values.iter())
            .zip(prover.lookups.iter())
            .map(|(((air, trace), pv), lk)| StarkInstance {
                air,
                trace,
                public_values: pv.clone(),
                lookups: lk.clone(),
            })
            .collect();
        let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch ZK");
        // S2 fix (SECURITY_REVIEW §8): the verifier MUST NOT trust the prover's committed preprocessed
        // (`prover_data.common`). The preprocessed carries the sponge round-constants / position column
        // that pin `e = XOF(pk‖μ)`; trusting a prover-supplied commitment lets a malicious prover doctor
        // it and make the sponge AIR accept `e ≠ XOF(pk‖μ)`. Instead the verifier REBUILDS the
        // preprocessed independently from its own (public) AIRs, exactly as the non-ZK path does. This
        // is sound AND loses no zero-knowledge: the preprocessed is public and secret-free, so its
        // commitment is a deterministic function of the AIR set and reproducing it reveals nothing about
        // μ — only the witness-bearing main/aux/quotient matrices need (and keep) their blinding. A fresh
        // `zk_batch_config()` restarts the hiding MMCS's RNG at its fixed seed, so the verifier's
        // preprocessed commitment is bit-identical to the prover's canonical one.
        let verifier = assemble_e_provenance_verifier(&t0, &ct, shape);
        let vconfig = zk_batch_config();
        let (vglobal, _) = build_preprocessed(&vconfig, &verifier.airs);
        let vcommon = CommonData::new(vglobal, verifier.lookups.clone());
        assert!(
            verify_batch(
                &config,
                &verifier.airs,
                &proof,
                &verifier.public_values,
                &vcommon
            )
            .is_ok(),
            "the e-provenance proof must verify under the hiding-FRI (zero-knowledge) config with a \
             verifier-rebuilt (not prover-trusted) preprocessed commitment"
        );
    }

    /// **Round-trip through the real library API (task #26).** A genuine ciphertext's `e`
    /// byte-provenance ⇒ R3b proof, assembled via [`assemble_e_provenance_prover`], proven, and verified
    /// via the verifier side rebuilt from public inputs by [`assemble_e_provenance_verifier`] — the
    /// composition lifted out of `#[cfg(test)]` into callable API, at test FRI params.
    #[test]
    fn e_provenance_round_trip_test_params() {
        let t0 = test_t0();
        let mu = [0x6Bu8; 32];
        assert!(
            prove_and_verify(&test_batch_config(), &t0, &mu),
            "honest e-provenance proof must verify at test params"
        );
    }

    /// **Same proof at PRODUCTION FRI params** (128-bit-conjectured soundness, 16-bit grinding). Closes
    /// the "test params only" gap: the byte-provenance composition is sound at production parameters,
    /// not merely at the 2-query test config. `#[ignore]` for wall-clock only — run with
    /// `cargo test --release -- --ignored e_provenance_round_trip_production_params`.
    #[test]
    #[ignore = "heavy: production FRI params over the full N=1024 e-provenance batch"]
    fn e_provenance_round_trip_production_params() {
        let t0 = test_t0();
        let mu = [0x6Bu8; 32];
        assert!(
            prove_and_verify(&production_batch_config(), &t0, &mu),
            "honest e-provenance proof must verify at production params"
        );
    }

    /// **Spike / tampered-witness rejection — the non-vacuousness proof (closes the C1 vacuous-gate
    /// finding for the `e`-probe class).** Assemble an honest proof, then tamper ONE `e_r` fold's
    /// coefficient so the folded witness no longer equals the XOF-derived `e` the sampler emitted. The
    /// byte-provenance binding must reject it: either the fold's internal Horner constraint fails at
    /// prove time (a `check_constraints` panic — caught here), or the COEFF_E_BUS join-2 unbalances and
    /// `verify_batch` rejects. Under a relation-only proof over free `(e,f,g)` the same
    /// tamper would still verify (free `(e,f,g)`). This is what makes the gate non-vacuous: a prover
    /// cannot substitute a witness that deviates from `XOF(pk ‖ μ)`.
    #[test]
    fn spike_tampered_e_witness_rejected() {
        let t0 = test_t0();
        let mu = [0x6Bu8; 32];
        let config = test_batch_config();

        let (ct, shape, mut prover) =
            assemble_e_provenance_prover(&t0, &mu).expect("prover assembly");

        // Sanity: the honest proof verifies (guards against a false-positive rejection below).
        {
            let (global, prover_only) = build_preprocessed(&config, &prover.airs);
            let common = CommonData::new(global, prover.lookups.clone());
            let prover_data = ProverData {
                common,
                prover_only,
            };
            let instances = prover_instances(&prover);
            let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch honest");
            let verifier = assemble_e_provenance_verifier(&t0, &ct, shape);
            let (vglobal, _) = build_preprocessed(&config, &verifier.airs);
            let vcommon = CommonData::new(vglobal, verifier.lookups.clone());
            assert!(
                verify_batch(
                    &config,
                    &verifier.airs,
                    &proof,
                    &verifier.public_values,
                    &vcommon
                )
                .is_ok(),
                "control: honest proof must verify before we tamper"
            );
        }

        // Tamper: corrupt the first e_r fold trace (instance index 3 = first HornerFold; indices
        // 0=sponge, 1=squeeze, 2=e-sampler). Bump a `w`-limb cell so the folded coefficient differs
        // from the sampler's XOF-derived Send. This breaks the fold's own Horner recurrence and/or the
        // COEFF_E_BUS multiset balance.
        let e0_fold = &mut prover.traces[3];
        e0_fold.values[0] += ConfigVal::ONE;

        // The tampered proof must NOT verify. A `check_constraints` panic inside `prove_batch` (debug)
        // counts as rejection, so catch it; in release, `prove_batch` succeeds but `verify_batch` must
        // reject (unbalanced join / failed relation).
        let tampered_ok = {
            let prev = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_| {}));
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let (global, prover_only) = build_preprocessed(&config, &prover.airs);
                let common = CommonData::new(global, prover.lookups.clone());
                let prover_data = ProverData {
                    common,
                    prover_only,
                };
                let instances = prover_instances(&prover);
                let proof = prove_batch(&config, &instances, &prover_data).ok()?;
                let verifier = assemble_e_provenance_verifier(&t0, &ct, shape);
                let (vglobal, _) = build_preprocessed(&config, &verifier.airs);
                let vcommon = CommonData::new(vglobal, verifier.lookups.clone());
                verify_batch(
                    &config,
                    &verifier.airs,
                    &proof,
                    &verifier.public_values,
                    &vcommon,
                )
                .ok()
            }));
            std::panic::set_hook(prev);
            matches!(r, Ok(Some(())))
        };
        assert!(
            !tampered_ok,
            "a witness that deviates from XOF(pk‖μ) must NOT produce a verifying byte-provenance proof"
        );
    }

    /// Prove + verify the R3a+f byte-provenance proof for `(t0, μ, columns)` under `config`, rebuilding
    /// the verifier from public inputs. Returns whether `verify_batch` accepted.
    fn prove_and_verify_r3a(config: &Cfg, t0: &[Rq], mu: &[u8; 32], columns: &[usize]) -> bool {
        let (ct, shape, prover) = assemble_r3a_f_provenance_prover(t0, mu, columns)
            .expect("R3a prover assembly for a well-formed witness");
        let (global, prover_only) = build_preprocessed(config, &prover.airs);
        let common = CommonData::new(global, prover.lookups.clone());
        let prover_data = ProverData {
            common,
            prover_only,
        };
        let instances = prover_instances(&prover);
        let proof = prove_batch(config, &instances, &prover_data).expect("prove_batch R3a");

        let verifier = assemble_r3a_f_provenance_verifier(t0, &ct, &shape);
        let (vglobal, _) = build_preprocessed(config, &verifier.airs);
        let vcommon = CommonData::new(vglobal, verifier.lookups.clone());
        verify_batch(
            config,
            &verifier.airs,
            &proof,
            &verifier.public_values,
            &vcommon,
        )
        .is_ok()
    }

    /// **R3a+f round-trip (binds `f`).** A real ciphertext's R3a `p_0 = Σ_r B0_{r,0}·e_r + f_0` proven
    /// with BOTH `e` (ternary) and `f_0` (bounded) byte-bound to the SHAKE output (`f_0` at the absolute
    /// XOF offset after `e`). Verifier rebuilt from `(t0, ct)`. This is the machinery that closes the
    /// `f = δ·unitₖ` spike.
    #[test]
    fn r3a_f_round_trip_test_params() {
        let t0 = test_t0();
        let mu = [0x6Bu8; 32];
        assert!(
            prove_and_verify_r3a(&test_batch_config(), &t0, &mu, &[0]),
            "honest R3a+f proof must verify at test params"
        );
    }

    /// Same at **production FRI params**. `#[ignore]` for wall-clock only.
    #[test]
    #[ignore = "heavy: production FRI params over the R3a+f byte-provenance batch"]
    fn r3a_f_round_trip_production_params() {
        let t0 = test_t0();
        let mu = [0x6Bu8; 32];
        assert!(
            prove_and_verify_r3a(&production_batch_config(), &t0, &mu, &[0]),
            "honest R3a+f proof must verify at production params"
        );
    }

    /// Prove + verify the full `m`-challenge closure under `config`; rebuild the verifier from public
    /// inputs. Returns whether `verify_batch` accepted.
    fn prove_and_verify_full(config: &Cfg, t0: &[Rq], mu: &[u8; 32], m: usize) -> bool {
        let (ct, shape, prover) =
            assemble_full_provenance_prover(t0, mu, m).expect("full prover assembly");
        let (global, prover_only) = build_preprocessed(config, &prover.airs);
        let common = CommonData::new(global, prover.lookups.clone());
        let prover_data = ProverData {
            common,
            prover_only,
        };
        let instances = prover_instances(&prover);
        let proof = prove_batch(config, &instances, &prover_data).expect("prove_batch full");
        let verifier = assemble_full_provenance_verifier(t0, &ct, &shape);
        let (vglobal, _) = build_preprocessed(config, &verifier.airs);
        let vcommon = CommonData::new(vglobal, verifier.lookups.clone());
        verify_batch(
            config,
            &verifier.airs,
            &proof,
            &verifier.public_values,
            &vcommon,
        )
        .is_ok()
    }

    /// **FULL closure — e + all f + g, all R3a + R3b in one proof.** The complete malformed-ciphertext
    /// closure: one verifying proof certifies the entire witness is `(e,f,g) = XOF(pk‖μ)` with `e`
    /// ternary and `f,g` bounded, leaving no component free to spike. Single challenge (structural).
    /// Heavy (~90 KB sponge); `#[ignore]` for wall-clock/memory.
    #[test]
    #[ignore = "heavy: ~90 KB sponge (e+f+g) over all KAPPA R3a + R3b in one batch"]
    fn full_provenance_round_trip() {
        let t0 = test_t0();
        let mu = [0x6Bu8; 32];
        assert!(
            prove_and_verify_full(&production_batch_config(), &t0, &mu, 1),
            "the full e+f+g / all-R3a+R3b proof must verify at production params"
        );
    }

    /// **Production-sound full closure — 3 Fiat–Shamir challenges (closes H4).** The complete closure at
    /// `m = 3` independent challenges, so the relation check's soundness is ≈ `(deg/|F|)^3 ≈ 2^-156`
    /// (vs ~2^-52 at a single grindable challenge), on top of the config's ~128-bit FRI/byte-provenance
    /// soundness. This is the production-shaped sound proof. Very heavy; `#[ignore]`.
    #[test]
    #[ignore = "very heavy: 3-challenge full closure over the ~90 KB sponge"]
    fn full_provenance_sound_multichallenge() {
        let t0 = test_t0();
        let mu = [0x6Bu8; 32];
        assert!(
            prove_and_verify_full(&production_batch_config(), &t0, &mu, 3),
            "the 3-challenge full closure must verify at production params"
        );
    }

    /// **The classic `f = δ·unitₖ` spike rejection — closes C1 for the `f`-probe (R3a) class.** Assemble
    /// an honest R3a+f proof for `p_0`, then tamper the `f_0` fold so the folded `f_0` no longer equals
    /// the bounded XOF draw the sampler emitted (a spike). The byte-provenance binding rejects it: the
    /// `f_0` fold's Horner recurrence fails at prove time (caught) or the COEFF_F_BUS join-2 unbalances
    /// and `verify_batch` rejects. A prover therefore cannot substitute a spike `f` — exactly the insider
    /// probe the gate exists to stop, and which the relation-only proof (`prove_relation_layer`) admits.
    #[test]
    fn spike_tampered_f_witness_rejected() {
        let t0 = test_t0();
        let mu = [0x6Bu8; 32];
        let config = test_batch_config();

        let (ct, shape, mut prover) =
            assemble_r3a_f_provenance_prover(&t0, &mu, &[0]).expect("R3a prover assembly");

        // Control: honest proof verifies.
        {
            let (global, prover_only) = build_preprocessed(&config, &prover.airs);
            let common = CommonData::new(global, prover.lookups.clone());
            let prover_data = ProverData {
                common,
                prover_only,
            };
            let instances = prover_instances(&prover);
            let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch honest");
            let verifier = assemble_r3a_f_provenance_verifier(&t0, &ct, &shape);
            let (vglobal, _) = build_preprocessed(&config, &verifier.airs);
            let vcommon = CommonData::new(vglobal, verifier.lookups.clone());
            assert!(
                verify_batch(
                    &config,
                    &verifier.airs,
                    &proof,
                    &verifier.public_values,
                    &vcommon
                )
                .is_ok(),
                "control: honest R3a+f proof must verify before we tamper"
            );
        }

        // Tamper the f_0 fold (instance index 4 + MU: 0=sponge,1=squeeze,2=e-sampler,3=f-sampler,
        // 4..4+MU = e folds, 4+MU = f_0 fold). Corrupting a `w` cell spikes the folded f_0 away from the
        // sampler's XOF-bound value → COEFF_F join-2 unbalances / Horner constraint fails.
        let f0_idx = 4 + MU;
        prover.traces[f0_idx].values[0] += ConfigVal::ONE;

        let tampered_ok = {
            let prev = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_| {}));
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let (global, prover_only) = build_preprocessed(&config, &prover.airs);
                let common = CommonData::new(global, prover.lookups.clone());
                let prover_data = ProverData {
                    common,
                    prover_only,
                };
                let instances = prover_instances(&prover);
                let proof = prove_batch(&config, &instances, &prover_data).ok()?;
                let verifier = assemble_r3a_f_provenance_verifier(&t0, &ct, &shape);
                let (vglobal, _) = build_preprocessed(&config, &verifier.airs);
                let vcommon = CommonData::new(vglobal, verifier.lookups.clone());
                verify_batch(
                    &config,
                    &verifier.airs,
                    &proof,
                    &verifier.public_values,
                    &vcommon,
                )
                .ok()
            }));
            std::panic::set_hook(prev);
            matches!(r, Ok(Some(())))
        };
        assert!(
            !tampered_ok,
            "a spike f_0 (deviating from the bounded XOF draw) must NOT produce a verifying proof"
        );
    }

    /// **Gate wired to the sound closure (task #33 closure for the `e`-probe class).** The partial-decap
    /// gate ([`crate::gate::gated_partial_decap_masked`]) is driven by a `proof_verifies` closure that
    /// runs the COMPOSED byte-provenance `verify_batch` (not the vacuous relation-only path). A proof
    /// built for `ct` verifies for `ct` (gate forwards); a proof verified against a DIFFERENT ciphertext
    /// fails ⇒ the gate refuses with `ProofRejected` before the share is read. This demonstrates the
    /// gate is non-vacuous when handed the sound closure this module provides.
    #[test]
    fn gate_uses_composed_byte_provenance_closure() {
        use lib_q_random::new_deterministic_rng;
        use lib_q_threshold_kem_lattice::SecretShare;
        use lib_q_threshold_kem_lattice::threshold::ZeroShareSeeds;
        use zeroize::Zeroizing;

        use crate::gate::gated_partial_decap_masked;

        let t0 = test_t0();
        let mu = [0x6Bu8; 32];
        let config = test_batch_config();

        let (ct, shape, prover) = assemble_e_provenance_prover(&t0, &mu).expect("prover assembly");
        let (global, prover_only) = build_preprocessed(&config, &prover.airs);
        let common = CommonData::new(global, prover.lookups.clone());
        let prover_data = ProverData {
            common,
            prover_only,
        };
        let instances = prover_instances(&prover);
        let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch");

        // The sound closure: rebuild the verifier from public inputs for `ct_for_verify` and run the
        // composed verify_batch. Binds the proof to a specific ciphertext (ζ, v, pk_digest all from it).
        let verify_against = |ct_for_verify: &Ciphertext| -> bool {
            let v = assemble_e_provenance_verifier(&t0, ct_for_verify, shape);
            let (vglobal, _) = build_preprocessed(&config, &v.airs);
            let vcommon = CommonData::new(vglobal, v.lookups.clone());
            verify_batch(&config, &v.airs, &proof, &v.public_values, &vcommon).is_ok()
        };

        // A placeholder share (a full DKG share is exercised by the KEM's own tests); we only assert
        // the gate's ACCEPT/REJECT decision, which happens before the share is read.
        let share = SecretShare {
            index: 1,
            threshold: 1,
            share_bytes: Zeroizing::new(vec![0u8; 1]),
        };
        let seeds = ZeroShareSeeds::from_pairwise(Vec::new()).expect("empty seed set is canonical");

        // Accept path: proof verifies for `ct` ⇒ gate forwards past verification (then errors on the
        // placeholder share) ⇒ NOT ProofRejected.
        let mut rng = new_deterministic_rng([7u8; 32]);
        let forwarded = gated_partial_decap_masked(
            || verify_against(&ct),
            &share,
            &[1u8],
            &ct,
            &seeds,
            &mut rng,
        );
        assert!(
            !matches!(forwarded, Err(EncProofError::ProofRejected)),
            "a composed proof that verifies for this ciphertext must forward past the gate"
        );

        // Reject path: verify the SAME proof against a DIFFERENT ciphertext ⇒ fails ⇒ ProofRejected
        // before the share is touched.
        let other_ct = encapsulate_derand(&t0, &[0xD9u8; 32]);
        let mut rng2 = new_deterministic_rng([9u8; 32]);
        let refused = gated_partial_decap_masked(
            || verify_against(&other_ct),
            &share,
            &[1u8],
            &ct,
            &seeds,
            &mut rng2,
        );
        assert!(
            matches!(refused, Err(EncProofError::ProofRejected)),
            "a composed proof that does not verify for this ciphertext must be refused by the gate"
        );
    }

    /// A second `t0` that differs from [`test_t0`] — used to check pk-binding.
    fn other_t0() -> Vec<Rq> {
        (0..MU)
            .map(|r| {
                let mut c = [0i64; N];
                for (i, ci) in c.iter_mut().enumerate() {
                    *ci = (i as i64 * 37 + r as i64 * 13 + 5) % lib_q_dkg::lattice::ring::Q;
                }
                Rq::from_coeffs(c)
            })
            .collect()
    }

    /// Regression for card `t_fe2722bf`, carried into the κ-fold design (card `t_a73aaed2`): every
    /// tier must challenge on the statement `(pk_digest ‖ ct)`, not on `ct` alone.
    ///
    /// The old form of this test compared the folds' ζ public values. Folds no longer carry public
    /// values at all — the challenge is a vector that reaches the proof through each fold's
    /// preprocessed `ψ` and the relation's `(a, c)` — so this checks the derivation directly AND its
    /// observable consequence: the SAME ciphertext under a DIFFERENT public key must produce a
    /// different verifier assembly.
    #[test]
    fn all_tiers_absorb_pk_digest_into_the_challenge() {
        let t0 = test_t0();
        let t0b = other_t0();
        let mu = [0x6Bu8; 32];
        let ct = encapsulate_derand(&t0, &mu);
        let ct_bytes = ct.to_bytes();
        let pkd = lib_q_threshold_kem_lattice::kem::pk_digest_of(&t0);
        let pkd_b = lib_q_threshold_kem_lattice::kem::pk_digest_of(&t0b);
        assert_ne!(
            pkd, pkd_b,
            "sanity: the two keys must have distinct digests"
        );

        // The derivation itself is pk-sensitive, and κ / ρ are domain-separated.
        assert_ne!(
            statement_kappas(&pkd, &ct_bytes, 1, N),
            statement_kappas(&pkd_b, &ct_bytes, 1, N),
            "κ must absorb pk_digest, not the ciphertext alone"
        );
        assert_ne!(
            statement_kappas(&pkd, &ct_bytes, 1, KAPPA),
            statement_rhos(&pkd, &ct_bytes, 1, KAPPA),
            "κ and ρ must be drawn under separated domain tags"
        );

        // Observable consequence, per tier: swap only the public key and the verifier assembly moves.
        let (ct_p, shape, _prover) =
            assemble_e_provenance_prover(&t0, &mu).expect("e-provenance prover assembly");
        assert_ne!(
            assemble_e_provenance_verifier(&t0, &ct_p, shape).public_values,
            assemble_e_provenance_verifier(&t0b, &ct_p, shape).public_values,
            "e-provenance: the proof must be bound to this pk"
        );

        let (ct_r, rshape, _rprover) =
            assemble_r3a_f_provenance_prover(&t0, &mu, &[0]).expect("R3a+f prover assembly");
        assert_ne!(
            assemble_r3a_f_provenance_verifier(&t0, &ct_r, &rshape).public_values,
            assemble_r3a_f_provenance_verifier(&t0b, &ct_r, &rshape).public_values,
            "R3a+f: the proof must be bound to this pk"
        );
    }

    // ══════════════════════════════════════════════════════════════════════════════════════════
    // Card t_a73aaed2 regressions — the confirmed soundness break must stay closed.
    //
    // The break: the R3 relations were checked by evaluating a polynomial identity at a scalar
    // Fiat–Shamir point ζ, with the reduction mod X^N+1 witnessed by a QUOTIENT fold. That fold's
    // coefficient column was free and committed after ζ was fixed by the statement, and its public
    // coefficient −(ζ^N+1) was a nonzero constant, so `hb(ζ) := D(ζ)/(ζ^N+1)` solved the relation for
    // ANY ciphertext. A malformed ciphertext verified at tier 1 (test params) and at tier 3 with
    // m = 1 AND m = 3 at PRODUCTION FRI params.
    //
    // The κ-fold design removes the quotient, so the historical exploit cannot even be expressed —
    // there is no free term to solve for. The tests below therefore attack the property directly:
    // every fold operand must be pinned, and a malformed ciphertext must be unprovable.
    // ══════════════════════════════════════════════════════════════════════════════════════════

    /// **The structural invariant whose violation WAS the bug.** Every fold instance in every tier
    /// must have its coefficient column pinned — either by a `Receive` on a COEFF bus (`e`, `f`, `g`)
    /// or by being the `EncodeMuFold`, whose coefficients are the boolean-constrained `⌊q/2⌋·μ_i`.
    ///
    /// A fold that only Sends its result proves "this is the functional of the column I committed"
    /// and constrains that column not at all. The superseded design had one such fold per relation
    /// per challenge (the quotient), plus a free `g` in two tiers.
    #[test]
    fn no_fold_instance_is_left_unbound() {
        use lib_q_plonky_lookup::Kind;

        let t0 = test_t0();
        let mu = [0x6Bu8; 32];

        // (assembly label, AIRs, per-instance lookups)
        let (ct1, shape1, p1) = assemble_e_provenance_prover(&t0, &mu).expect("tier 1");
        let v1 = assemble_e_provenance_verifier(&t0, &ct1, shape1);
        let (ct2, shape2, p2) = assemble_r3a_f_provenance_prover(&t0, &mu, &[0]).expect("tier 2");
        let v2 = assemble_r3a_f_provenance_verifier(&t0, &ct2, &shape2);
        let (ct3, shape3, p3) = assemble_full_provenance_prover(&t0, &mu, 2).expect("tier 3");
        let v3 = assemble_full_provenance_verifier(&t0, &ct3, &shape3);

        type Case<'a> = (&'a str, &'a [EncProofAir], &'a [Vec<Lookup<ConfigVal>>]);
        let cases: [Case<'_>; 6] = [
            ("tier1 prover", &p1.airs, &p1.lookups),
            ("tier1 verifier", &v1.airs, &v1.lookups),
            ("tier2 prover", &p2.airs, &p2.lookups),
            ("tier2 verifier", &v2.airs, &v2.lookups),
            ("tier3 prover", &p3.airs, &p3.lookups),
            ("tier3 verifier", &v3.airs, &v3.lookups),
        ];

        let mut dot_folds_checked = 0usize;
        for (label, airs, lookups) in cases {
            assert_eq!(
                airs.len(),
                lookups.len(),
                "{label}: AIR/lookup lists desync"
            );
            for (i, air) in airs.iter().enumerate() {
                // NO EXEMPTIONS. An earlier version of this test skipped `EncodeMuFold` on the
                // reasoning that its coefficients are the "boolean-constrained ⌊q/2⌋·μ_i" — which is
                // wrong, and the exemption hid a live break: 256 free bits against ONE linear
                // equation over Z_q is wildly underdetermined, so a prover could subset-sum its way
                // to any value and make an arbitrary malformed `v` verify. Boolean-constrained is
                // not bound. If a future fold variant is added here, it must be given a required
                // binding bus, not a `continue`.
                let required: &[&str] = match air {
                    EncProofAir::DotFold(_) => &[COEFF_E_BUS, COEFF_F_BUS, COEFF_G_BUS],
                    EncProofAir::EncodeMuFold(_) => &[MU_BIT_BUS],
                    _ => continue,
                };
                // `Direction` is not retained on the assembled `Lookup` (it is folded into the sign
                // of the multiplicity expression), so bind-ness is read off the BUS. In this crate
                // only the samplers and the μ bridge SEND on these buses and neither is a fold, so
                // a fold touching one is necessarily the receiving side.
                let bound = lookups[i].iter().any(
                    |lk| matches!(&lk.kind, Kind::Global(bus) if required.contains(&bus.as_str())),
                );
                assert!(
                    bound,
                    "{label}: fold instance {i} touches none of {required:?} — its coefficient \
                     column is FREE, which is exactly the t_a73aaed2 defect"
                );
                dot_folds_checked += 1;
            }
        }
        // Control: the sweep must actually have inspected folds, or it passes vacuously.
        //   tier 1: MU e-folds + g                                    (encode is not a DotFold)
        //   tier 2: MU e-folds + 1 f-fold (one column selected)
        //   tier 3: per challenge, R3b's (MU e-folds + g) and R3a's (MU e-folds + KAPPA f-folds),
        //           over the 2 challenges requested above
        // counted once for the prover assembly and once for the verifier assembly.
        let tier1 = (MU + 1) + 1; // MU e-folds + g, plus the encode fold
        let tier2 = MU + 1; // MU e-folds + one f-fold; R3a has no encode term
        let tier3 = 2 * ((MU + 1) + 1 + (MU + KAPPA)); // per challenge: R3b (+encode) and R3a
        let expected = 2 * (tier1 + tier2 + tier3);
        assert_eq!(
            dot_folds_checked, expected,
            "the sweep must inspect every dot-fold instance"
        );
    }

    /// **The exploit, re-run against the fix.** Build a malformed ciphertext (`ct.v.coeffs[0] += 1`,
    /// the exact perturbation the confirmed PoC used), assemble tier 1 with every trace honest at the
    /// malformed statement's κ, and confirm the prover CANNOT produce a satisfying relation. Under the
    /// superseded design this same construction verified `Ok(())`, because the free quotient fold
    /// absorbed the discrepancy.
    ///
    /// Control: the identical construction on the untampered ciphertext must succeed — otherwise this
    /// test would pass for a reason unrelated to the tamper.
    #[test]
    fn malformed_ciphertext_has_no_satisfying_relation() {
        let t0 = test_t0();
        let mu = [0x6Bu8; 32];
        let w = fo_expand_witness(&t0, &mu);
        let honest_ct = encapsulate_derand(&t0, &mu);

        let build = |ct: &Ciphertext| -> Result<(), EncProofError> {
            let t0_cols_owned: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();
            let t0_cols: Vec<&[u64]> = t0_cols_owned.iter().map(|v| v.as_slice()).collect();
            let v_z = rq_coeffs_zq(&ct.v);
            let pd = r3b_public(&t0_cols, &v_z, one_kappa(&w.pk_digest, ct));

            // Every witness fold honest — e/g are the genuine XOF outputs, encode is the genuine μ.
            let mut w_terms = Vec::with_capacity(MU + 2);
            for (e, psi_r) in w.e.iter().map(rq_coeffs_zq).zip(pd.psi.iter()) {
                w_terms.push(generate_dot_trace(&e, psi_r)?.1);
            }
            w_terms.push(generate_dot_trace(&rq_coeffs_zq(&w.g), &pd.kappa)?.1);
            w_terms.push(generate_encode_mu_trace(&mu, &pd.kappa[..MSG_BITS])?.1);
            generate_relation_trace(&pd.a, &w_terms, pd.c).map(|_| ())
        };

        build(&honest_ct).expect("control: the honest ciphertext must satisfy the relation");

        let mut bad = honest_ct.clone();
        bad.v.coeffs[0] = (bad.v.coeffs[0] + 1) % lib_q_dkg::lattice::ring::Q;
        assert!(
            matches!(build(&bad), Err(EncProofError::TraceGeneration(_))),
            "a malformed ciphertext must leave the relation unsatisfiable — there is no free term \
             left to solve for (card t_a73aaed2)"
        );
    }

    /// **R3a coverage.** The quotient defect was not confined to R3b: every R3a column had its own
    /// free `hk_k` fold too, so tier 3 carried `KAPPA + 1 = 10` free folds per challenge. This is the
    /// R3a half of the previous test — tamper a `p_k` coefficient (leaving `v` alone) and the
    /// ρ-batched R3a relation must become unsatisfiable, at every challenge.
    ///
    /// It also exercises the ρ-batching itself: `ψ_r = corr(Σ_k ρ_k·B0_{r,k}, κ)` is only correct
    /// because `corr_negacyclic` is linear in its public argument, so a bug there would show up here
    /// as the honest control failing.
    #[test]
    fn malformed_p_k_has_no_satisfying_r3a_relation() {
        let t0 = test_t0();
        let mu = [0x6Bu8; 32];
        let w = fo_expand_witness(&t0, &mu);
        let b0 = key().b0();
        let honest_ct = encapsulate_derand(&t0, &mu);
        let all_columns: Vec<usize> = (0..KAPPA).collect();
        let t0_cols: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();

        let build = |ct: &Ciphertext| -> Result<(), EncProofError> {
            let (b0_cols_all, p_all) = r3a_public_columns(b0, ct, &all_columns);
            let v_z = rq_coeffs_zq(&ct.v);
            let (kappas, rhos) = statement_challenges(&w.pk_digest, ct, 1, KAPPA);
            let pd = full_public(
                &t0_cols,
                &b0_cols_all,
                &p_all,
                &v_z,
                kappas[0].clone(),
                &rhos[0],
            );
            let mut w_a = Vec::with_capacity(R3A_TERMS);
            for (e, psi_r) in w.e.iter().map(rq_coeffs_zq).zip(pd.psi_a.iter()) {
                w_a.push(generate_dot_trace(&e, psi_r)?.1);
            }
            for k in 0..KAPPA {
                w_a.push(generate_dot_trace(&rq_coeffs_zq(&w.f[k]), &pd.kappa)?.1);
            }
            generate_relation_trace(&pd.a_a, &w_a, pd.c_a).map(|_| ())
        };

        build(&honest_ct).expect("control: the honest ciphertext must satisfy the R3a relation");

        // Tamper a column OTHER than 0, so this also proves the ρ-batching reaches every column
        // rather than just the first.
        let mut bad = honest_ct.clone();
        bad.p[KAPPA - 1].coeffs[3] = (bad.p[KAPPA - 1].coeffs[3] + 1) % lib_q_dkg::lattice::ring::Q;
        assert!(
            matches!(build(&bad), Err(EncProofError::TraceGeneration(_))),
            "a tampered p_k must leave the ρ-batched R3a relation unsatisfiable (card t_a73aaed2)"
        );
    }

    /// **GAP 2 regression — the μ binding (card `t_a73aaed2`).** Before the μ bridge landed, the
    /// encode fold's 256 μ-bits were a free witness column: nothing tied them to the sponge preimage's
    /// μ. That was not merely a message-binding gap. `⟨encode(μ), κ⟩ = ⌊q/2⌋·Σ_i μ_i·κ_i` is linear
    /// with PUBLIC coefficients and `κ` is a public function of the statement, so a prover could
    /// compute `κ` first and subset-sum over the 256 free bits to hit any target — making an
    /// ARBITRARY malformed `v` verify.
    ///
    /// This builds the cleanest instance of that attack: derive `(e, f, g)` honestly from `μ₁`, but
    /// encode a DIFFERENT message `μ₂` into `v`, so that `v' = Σ_r t0_r·e_r + g + encode(μ₂)`. The R3b
    /// residual is then EXACTLY zero and the relation holds — every arithmetic check passes. The only
    /// thing that can reject it is MU_BIT_BUS failing to balance, because the bridge Sends μ₁'s bits
    /// while the encode fold Receives μ₂'s.
    ///
    /// Controls: (a) `μ₂ == μ₁` is the honest case and must ACCEPT — otherwise this test would be
    /// passing because the assembly is broken rather than because the binding works; (b) the relation
    /// is asserted to be satisfiable for the mismatched case before proving, so the rejection is
    /// demonstrably the bus and not an arithmetic failure.
    #[test]
    fn mu_mismatch_between_sponge_and_encode_fold_is_rejected() {
        let t0 = test_t0();
        let mu1 = [0x6Bu8; 32];
        let config = test_batch_config();

        // `mu2 == mu1` is the honest control; `mu2 != mu1` is the attack.
        let run = |mu2: [u8; 32]| -> bool {
            let w = fo_expand_witness(&t0, &mu1);
            let input = encap_preimage(&w.pk_digest, &mu1);
            let honest = encapsulate_derand(&t0, &mu1);

            // v' = v − encode(μ₁) + encode(μ₂): a ciphertext that is an exact encryption of μ₂ under
            // the μ₁-derived randomness. Under the FO transform this is malformed.
            let (enc1, enc2) = (encode_msg(&mu1), encode_msg(&mu2));
            let mut ct = honest.clone();
            for i in 0..N {
                let q = lib_q_dkg::lattice::ring::Q;
                ct.v.coeffs[i] = (ct.v.coeffs[i] - enc1.coeffs[i] + enc2.coeffs[i]).rem_euclid(q);
            }

            let num_e = MU * N;
            let num_f = KAPPA * N;
            let num_g = N;
            let e_budget = E_TERNARY_ATTEMPTS;
            let f_budget = bounded_attempts(num_f) * 8;
            let g_budget = bounded_attempts(num_g) * 8;
            let bytes = shake256_xof(&input, e_budget + f_budget + g_budget);
            let e_sampler = generate_ternary_trace(&bytes[..e_budget], num_e).expect("e sampler");
            let e_bytes = active_rows(&e_sampler, SAMPLER_WIDTH);
            let f_sampler = generate_bounded_trace(&bytes[e_budget..e_budget + f_budget], num_f)
                .expect("f sampler");
            let f_bytes = active_rows(&f_sampler, BOUNDED_WIDTH) * 8;
            let g_sampler = generate_bounded_trace(
                &bytes[e_budget + f_budget..e_budget + f_budget + g_budget],
                num_g,
            )
            .expect("g sampler");
            let g_bytes = active_rows(&g_sampler, BOUNDED_WIDTH) * 8;
            let consumed = e_bytes + f_bytes + g_bytes;
            let sponge = generate_provable_sponge_trace(&input, consumed + RATE_BYTES);
            let height = sponge.values.len() / NUM_KECCAK_COLS;
            let full_limbs = sponge_squeeze_blocks(height) * (RATE_BYTES / 2);
            let squeeze = generate_squeeze_byte_trace_partial(&input, full_limbs, consumed);

            let t0_cols_owned: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();
            let t0_cols: Vec<&[u64]> = t0_cols_owned.iter().map(|v| v.as_slice()).collect();
            let v_z = rq_coeffs_zq(&ct.v);
            let pd = r3b_public(&t0_cols, &v_z, one_kappa(&w.pk_digest, &ct));

            let mut fold_traces = Vec::with_capacity(MU);
            let mut w_terms = Vec::with_capacity(MU + 2);
            for (e, psi_r) in w.e.iter().map(rq_coeffs_zq).zip(pd.psi.iter()) {
                let (t, ev) = generate_dot_trace(&e, psi_r).expect("e fold");
                fold_traces.push(t);
                w_terms.push(ev);
            }
            let (g_trace, g_ev) =
                generate_dot_trace(&rq_coeffs_zq(&w.g), &pd.kappa).expect("g fold");
            // The encode fold carries μ₂'s bits; the bridge below carries the sponge's μ₁.
            let (enc_trace, enc_ev) =
                generate_encode_mu_trace(&mu2, &pd.kappa[..MSG_BITS]).expect("encode fold");
            w_terms.push(g_ev);
            w_terms.push(enc_ev);

            let rc = RelationCheckAir { num_terms: MU + 2 };
            // Control (b): the arithmetic genuinely holds, so any rejection below is the μ bus.
            let (rm, rel_pubs) = generate_relation_trace(&pd.a, &w_terms, pd.c)
                .expect("R3b must hold: v' is an exact encryption of μ₂ under μ₁'s randomness");

            let mut traces: Vec<RowMajorMatrix<ConfigVal>> = Vec::from([
                sponge,
                squeeze,
                e_sampler,
                f_sampler,
                g_sampler,
                generate_mu_bits_trace(&mu1),
            ]);
            traces.extend(fold_traces);
            traces.push(g_trace);
            traces.push(enc_trace);
            traces.push(pad_relation(&rm));

            let prover = EncProvenanceProver {
                airs: e_provenance_airs(height, num_e, num_f, num_g, &pd, &rc),
                traces,
                public_values: e_provenance_public_values(
                    &w.pk_digest,
                    num_e,
                    num_f,
                    num_g,
                    &rel_pubs,
                ),
                lookups: e_provenance_lookups(e_bytes as u64, (e_bytes + f_bytes) as u64, &rc),
            };
            let shape = EncProofShape {
                sponge_height: height,
                num_e_coeffs: num_e,
                num_f_coeffs: num_f,
                num_g_coeffs: num_g,
                sponge_full_limbs: full_limbs,
                consumed_bytes: consumed,
                f_offset: e_bytes,
                g_offset: e_bytes + f_bytes,
            };

            let (global, prover_only) = build_preprocessed(&config, &prover.airs);
            let prover_data = ProverData {
                common: CommonData::new(global, prover.lookups.clone()),
                prover_only,
            };
            let instances = prover_instances(&prover);
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let Ok(proof) = prove_batch(&config, &instances, &prover_data) else {
                    return false;
                };
                let verifier = assemble_e_provenance_verifier(&t0, &ct, shape);
                let (vglobal, _) = build_preprocessed(&config, &verifier.airs);
                let vcommon = CommonData::new(vglobal, verifier.lookups.clone());
                verify_batch(
                    &config,
                    &verifier.airs,
                    &proof,
                    &verifier.public_values,
                    &vcommon,
                )
                .is_ok()
            }))
            .unwrap_or(false)
        };

        assert!(
            run(mu1),
            "control: μ₂ = μ₁ is the honest case and must verify — otherwise the rejection below \
             proves nothing about the μ binding"
        );
        let mut mu2 = mu1;
        mu2[0] ^= 1;
        assert!(
            !run(mu2),
            "SOUNDNESS REGRESSION (card t_a73aaed2 GAP 2): a ciphertext encoding μ₂ while its \
             witness came from XOF(pk‖μ₁) VERIFIED — the μ bridge is not binding"
        );
    }

    /// **The exploit's last resort, end to end.** A prover that ignores the failure above and simply
    /// writes the *satisfying* value into the relation's `w` term — the moral equivalent of the old
    /// forged quotient — must be rejected by `verify_batch`, because the `g` fold Sends its real
    /// functional value on FOLD_E_BUS and the doctored relation Receives a different one, so the bus
    /// no longer balances.
    ///
    /// This is the closest expressible analogue of the confirmed PoC: malformed ciphertext, every
    /// other trace honest, one scalar chosen by the adversary.
    #[test]
    fn forged_relation_term_for_a_malformed_ciphertext_is_rejected() {
        let t0 = test_t0();
        let mu = [0x6Bu8; 32];
        let config = test_batch_config();

        let w = fo_expand_witness(&t0, &mu);
        let input = encap_preimage(&w.pk_digest, &mu);
        let mut ct = encapsulate_derand(&t0, &mu);
        ct.v.coeffs[0] = (ct.v.coeffs[0] + 1) % lib_q_dkg::lattice::ring::Q;

        // Byte-provenance layer: honest (it depends only on `input`, never on `ct`).
        let num_e = MU * N;
        let num_f = KAPPA * N;
        let num_g = N;
        let e_budget = E_TERNARY_ATTEMPTS;
        let f_budget = bounded_attempts(num_f) * 8;
        let g_budget = bounded_attempts(num_g) * 8;
        let bytes = shake256_xof(&input, e_budget + f_budget + g_budget);
        let e_sampler = generate_ternary_trace(&bytes[..e_budget], num_e).expect("e sampler");
        let e_bytes = active_rows(&e_sampler, SAMPLER_WIDTH);
        let f_sampler = generate_bounded_trace(&bytes[e_budget..e_budget + f_budget], num_f)
            .expect("f sampler");
        let f_bytes = active_rows(&f_sampler, BOUNDED_WIDTH) * 8;
        let g_sampler = generate_bounded_trace(
            &bytes[e_budget + f_budget..e_budget + f_budget + g_budget],
            num_g,
        )
        .expect("g sampler");
        let g_bytes = active_rows(&g_sampler, BOUNDED_WIDTH) * 8;
        let consumed = e_bytes + f_bytes + g_bytes;
        let sponge = generate_provable_sponge_trace(&input, consumed + RATE_BYTES);
        let height = sponge.values.len() / NUM_KECCAK_COLS;
        let full_limbs = sponge_squeeze_blocks(height) * (RATE_BYTES / 2);
        let squeeze = generate_squeeze_byte_trace_partial(&input, full_limbs, consumed);

        let t0_cols_owned: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();
        let t0_cols: Vec<&[u64]> = t0_cols_owned.iter().map(|v| v.as_slice()).collect();
        let v_z = rq_coeffs_zq(&ct.v);
        let pd = r3b_public(&t0_cols, &v_z, one_kappa(&w.pk_digest, &ct));

        // Honest folds.
        let mut fold_traces = Vec::with_capacity(MU + 2);
        let mut w_terms = Vec::with_capacity(MU + 2);
        for (e, psi_r) in w.e.iter().map(rq_coeffs_zq).zip(pd.psi.iter()) {
            let (t, ev) = generate_dot_trace(&e, psi_r).expect("e fold");
            fold_traces.push(t);
            w_terms.push(ev);
        }
        let (g_trace, _g_ev) = generate_dot_trace(&rq_coeffs_zq(&w.g), &pd.kappa).expect("g fold");
        let (enc_trace, enc_ev) =
            generate_encode_mu_trace(&mu, &pd.kappa[..MSG_BITS]).expect("encode fold");

        // THE FORGERY: solve the relation for the `g` term instead of using g's real value. Every
        // coefficient in `a` is 1, so the satisfying value is `−c − Σ(other terms)`.
        let qq = u128::from(Q);
        let mut partial = u128::from(pd.c) + u128::from(enc_ev);
        for t in &w_terms {
            partial += u128::from(*t);
        }
        let forged_g = ((qq - partial % qq) % qq) as u64;
        w_terms.push(forged_g);
        w_terms.push(enc_ev);

        let rc = RelationCheckAir { num_terms: MU + 2 };
        let (rm, rel_pubs) = generate_relation_trace(&pd.a, &w_terms, pd.c)
            .expect("the forged w satisfies the relation by construction");

        let mut traces: Vec<RowMajorMatrix<ConfigVal>> =
            Vec::from([sponge, squeeze, e_sampler, f_sampler, g_sampler]);
        traces.extend(fold_traces);
        traces.push(g_trace);
        traces.push(enc_trace);
        traces.push(pad_relation(&rm));

        let airs = e_provenance_airs(height, num_e, num_f, num_g, &pd, &rc);
        let lookups = e_provenance_lookups(e_bytes as u64, (e_bytes + f_bytes) as u64, &rc);
        let public_values =
            e_provenance_public_values(&w.pk_digest, num_e, num_f, num_g, &rel_pubs);
        let prover = EncProvenanceProver {
            airs,
            traces,
            public_values,
            lookups,
        };
        let shape = EncProofShape {
            sponge_height: height,
            num_e_coeffs: num_e,
            num_f_coeffs: num_f,
            num_g_coeffs: num_g,
            sponge_full_limbs: full_limbs,
            consumed_bytes: consumed,
            f_offset: e_bytes,
            g_offset: e_bytes + f_bytes,
        };

        let (global, prover_only) = build_preprocessed(&config, &prover.airs);
        let common = CommonData::new(global, prover.lookups.clone());
        let prover_data = ProverData {
            common,
            prover_only,
        };
        let instances = prover_instances(&prover);

        // The forgery must die at prove time (debug `check_constraints` / an unbalanced bus) or at
        // verify time. Both count; silently producing a verifying proof does not.
        let accepted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let Ok(proof) = prove_batch(&config, &instances, &prover_data) else {
                return false;
            };
            let verifier = assemble_e_provenance_verifier(&t0, &ct, shape);
            let (vglobal, _) = build_preprocessed(&config, &verifier.airs);
            let vcommon = CommonData::new(vglobal, verifier.lookups.clone());
            verify_batch(
                &config,
                &verifier.airs,
                &proof,
                &verifier.public_values,
                &vcommon,
            )
            .is_ok()
        }))
        .unwrap_or(false); // a debug `check_constraints` panic is a rejection
        assert!(
            !accepted,
            "SOUNDNESS REGRESSION (card t_a73aaed2): a malformed ciphertext with one forged \
             relation term VERIFIED"
        );
    }
}
