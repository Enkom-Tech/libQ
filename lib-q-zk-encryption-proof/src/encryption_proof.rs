//! Production entry-point assembly for the **byte-provenance** encryption proof (task #26): the
//! composition that binds the ciphertext's witness `e` to the deterministic FO expansion
//! `e = XOF(DOM_FO_SEED ‖ pk_digest ‖ μ)` AND proves `e` ternary, then feeds those *bound* `e_r`
//! folds into the R3b relation `v = Σ_r t0_r·e_r + g + encode(μ)`. This is the layer that makes the
//! partial-decap gate ([`crate::gate`]) non-vacuous for the `e`-probe class: a witness `e` that is not
//! the genuine SHAKE output (or not ternary) cannot produce a verifying proof, because the join
//! balances / sampler range constraints reject it.
//!
//! ## Relationship to [`crate::prove`]
//! [`crate::prove::prove_relation_layer`] proves ONLY the R3 linear relations over **free**
//! `(e, f, g)` — it has no sponge/sampler/joins, so it is vacuous as a malformed-ciphertext closure
//! (see the `# WARNING` in [`crate::gate`]). This module adds the sponge (`ShakeSpongeAir`), the
//! squeeze-byte bridge (`SqueezeByteAir`), and the ternary sampler (`TernarySamplerAir`), wired by the
//! three LogUp joins (SQUEEZE_LIMB → XOF_STREAM → COEFF_E → FOLD_E), so the `e_r` folds the R3b
//! relation consumes are provably the XOF-derived, ternary `e`. It is the `#[cfg(test)]` vertical slice
//! `compose::tests::compose_r3b_e_provenance_real_ciphertext` promoted to real, callable API.
//!
//! ## Config-agnostic, like [`crate::prove`]
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
//! * The byte-provenance joins are exact multiset (LogUp) checks whose soundness is the config's FRI
//!   soundness (~128 bits at production params). The ternary/bounded sampler AIRs pin `e ∈ {-1,0,1}`
//!   and `f,g ∈ [-B,B]`; the sponge pins the XOF preimage to `DOM ‖ pk_digest ‖ μ` (pk-bound public
//!   values, verifier-built from `ct`).
//! * Each lattice relation is a polynomial identity checked at `ζ`; a malformed ciphertext fails it
//!   with probability ≤ deg/|F| ≈ 2^-52 per challenge over `Complex<Mersenne31>`. Since the prover
//!   picks `ct` (grinding `ζ = H(pk_digest‖ct)`), `num_challenges = m` raises this to ≈ `2^-52m`
//!   (`m = 3` ⇒ ~156 bits). The `m` per-challenge fold sets each Receive the (shared) sampler
//!   coefficients once via the samplers' `m×`-repeated coefficient Sends, so every COEFF bus balances.
//! * **Zero-knowledge (task #32):** the same assembly runs unchanged under a **hiding-FRI** config
//!   (`is_zk() == 1`), which blinds every committed matrix and randomizes the quotient, so the proof
//!   reveals nothing about `μ` beyond the statement — sound AND zero-knowledge. Demonstrated by
//!   `tests::e_provenance_zero_knowledge_round_trip`. (Under the hiding PCS the *preprocessed* sponge
//!   column is committed with blinding, so the verifier reuses the prover's preprocessed `CommonData`
//!   — sound because preprocessed is public/deterministic in the AIRs; a deployment may instead commit
//!   preprocessed under a non-hiding sub-commitment, as it needs no blinding.)

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
    encapsulate_derand,
    encode_msg,
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
use crate::relation_assembly::{
    derive_zetas,
    r3a_public_coeffs,
    r3a_quotient_poly,
    r3b_public_coeffs,
    r3b_quotient_poly,
    rq_coeffs_zq,
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
    sponge_public_values,
};
use crate::squeeze_byte::{
    SqueezeByteAir,
    generate_squeeze_byte_trace_partial,
    squeeze_byte_limb_receive_lookup,
    squeeze_byte_send_lookup,
};
use crate::zq::{
    EncodeMuFoldAir,
    HornerFoldAir,
    RelationCheckAir,
    encode_mu_public_values,
    generate_encode_mu_trace,
    generate_horner_trace,
    generate_relation_trace,
    horner_coeff_receive_lookups_at,
    horner_e_send_lookups_at,
    horner_public_values,
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
    /// Row count of the sponge trace (a power of two ≥ the squeeze coverage of `e`'s bytes).
    pub sponge_height: usize,
    /// Ternary sampler coefficient count (`MU · N`).
    pub num_e_coeffs: usize,
    /// The number of 16-bit limbs the squeeze-byte table covers (the sponge's full squeeze).
    pub sponge_full_limbs: usize,
    /// The number of XOF bytes the `e`-sampler consumed (the byte prefix forwarded to it).
    pub consumed_bytes: usize,
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
            for v in &mut t.values {
                *v = ConfigVal::ZERO;
            }
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
/// layout as [`crate::prove`]'s private helper; kept local so the two entry points stay independent.)
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

/// **Prover** assembly of the `e`-byte-provenance ⇒ R3b layer for `(t0, μ)`.
///
/// Derives the ciphertext + witness (`encapsulate_derand` / `fo_expand_witness`), builds the SHAKE
/// sponge over the real FO preimage covering `e`'s consumed bytes, the squeeze-byte bridge, the ternary
/// `e`-sampler (`MU·N` coeffs), the `MU` `e_r` folds (byte-bound via join 2 at per-ring-element bases),
/// the `g`/`encode(μ)`/quotient folds (fed directly), and the R3b relation receiving all `MU+3` folds
/// (join 3). Returns the ciphertext, the [`EncProofShape`] the verifier needs, and the assembled
/// instances. The Fiat–Shamir challenge is `ζ = derive_zetas(ct)[0]` — verifier-recomputable, never
/// prover-supplied.
///
/// # Errors
/// [`EncProofError::TraceGeneration`] if a trace generator rejects its inputs (e.g. the R3b numerator
/// is not divisible by `X^N+1` — impossible for a well-formed witness).
pub fn assemble_e_provenance_prover(
    t0: &[Rq],
    mu: &[u8; 32],
) -> Result<(Ciphertext, EncProofShape, EncProvenanceProver), EncProofError> {
    let ct = encapsulate_derand(t0, mu);
    let w = fo_expand_witness(t0, mu);
    let input = encap_preimage(&w.pk_digest, mu);

    // e-sampler over the real XOF (MU·N ternary coeffs); sponge covers e's consumed bytes.
    let num_e = MU * N;
    let bytes = shake256_xof(&input, num_e * 2 + 4096);
    let e_sampler = generate_ternary_trace(&bytes, num_e)?;
    let consumed = active_rows(&e_sampler, SAMPLER_WIDTH);
    let sponge = generate_provable_sponge_trace(&input, consumed + RATE_BYTES);
    let height = sponge.values.len() / NUM_KECCAK_COLS;
    let blocks = sponge_squeeze_blocks(height);
    let full_limbs = blocks * (RATE_BYTES / 2);
    let squeeze = generate_squeeze_byte_trace_partial(&input, full_limbs, consumed);

    let zeta = derive_zetas(&ct.to_bytes(), 1)[0];

    // R3b public coefficients + quotient (over the real witness).
    let t0_cols_owned: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();
    let t0_cols: Vec<&[u64]> = t0_cols_owned.iter().map(|v| v.as_slice()).collect();
    let e_lifts: Zeroizing<Vec<Vec<u64>>> =
        Zeroizing::new(w.e.iter().map(rq_coeffs_zq).collect());
    let e_ref: Vec<&[u64]> = e_lifts.iter().map(|v| v.as_slice()).collect();
    let v_z = rq_coeffs_zq(&ct.v);
    let g_z: Zeroizing<Vec<u64>> = Zeroizing::new(rq_coeffs_zq(&w.g));
    let encode_z: Zeroizing<Vec<u64>> = Zeroizing::new(rq_coeffs_zq(&encode_msg(mu)));
    let (a, c) = r3b_public_coeffs(&t0_cols, &v_z, zeta, N);
    let hb = r3b_quotient_poly(&t0_cols, &e_ref, &g_z, &encode_z, &v_z, N)
        .ok_or(EncProofError::TraceGeneration("R3b numerator not divisible"))?;

    // Folds: MU byte-bound e_r folds, then g / encode / hb fed directly.
    let mut e_fold_traces = Vec::with_capacity(MU);
    let mut w_terms = Vec::with_capacity(MU + 3);
    for e in e_lifts.iter() {
        let (t, ev) = generate_horner_trace(e, zeta)?;
        e_fold_traces.push(t);
        w_terms.push(ev);
    }
    let (g_trace, g_ev) = generate_horner_trace(&g_z, zeta)?;
    let (enc_trace, enc_ev) = generate_encode_mu_trace(mu, zeta)?;
    let (hb_trace, hb_ev) = generate_horner_trace(&hb, zeta)?;
    w_terms.push(g_ev);
    w_terms.push(enc_ev);
    w_terms.push(hb_ev);
    let l = MU + 3;

    let rc = RelationCheckAir { num_terms: l };
    let (rm, rel_pubs) = generate_relation_trace(&a, &w_terms, c)?;
    let relation = pad_relation(&rm);

    // AIRs.
    let mut airs = Vec::from([
        EncProofAir::Sponge(ShakeSpongeAir { height }),
        EncProofAir::SqueezeByte(SqueezeByteAir),
        EncProofAir::Ternary(TernarySamplerAir { num_coeffs: num_e }),
    ]);
    for _ in 0..MU {
        airs.push(EncProofAir::HornerFold(HornerFoldAir));
    }
    airs.push(EncProofAir::HornerFold(HornerFoldAir)); // g
    airs.push(EncProofAir::EncodeMuFold(EncodeMuFoldAir)); // encode
    airs.push(EncProofAir::HornerFold(HornerFoldAir)); // hb
    airs.push(EncProofAir::RelationCheck(rc.clone()));

    // Lookups (identical construction on the verifier side — no witness).
    let lookups = e_provenance_lookups(&rc);

    // Traces.
    let mut traces: Vec<RowMajorMatrix<ConfigVal>> = Vec::from([sponge, squeeze, e_sampler]);
    traces.extend(e_fold_traces);
    traces.push(g_trace);
    traces.push(enc_trace);
    traces.push(hb_trace);
    traces.push(relation);

    // Public values.
    let public_values = e_provenance_public_values(&w.pk_digest, num_e, zeta, &a, c, &rel_pubs);

    let shape = EncProofShape {
        sponge_height: height,
        num_e_coeffs: num_e,
        sponge_full_limbs: full_limbs,
        consumed_bytes: consumed,
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

/// **Verifier** assembly for `(t0, ct, shape)`: recomputes `ζ = derive_zetas(ct)[0]`, rebuilds every
/// AIR from the public [`EncProofShape`], the sponge public values from `ct.pk_digest` (the
/// load-bearing pk binding — NEVER prover-supplied), and the relation public coefficients from
/// `(t0, ct, ζ)`. Rebuilds the lookups (deterministic, witness-free) in the SAME order as
/// [`assemble_e_provenance_prover`]. Feed to `verify_batch`.
pub fn assemble_e_provenance_verifier(
    t0: &[Rq],
    ct: &Ciphertext,
    shape: EncProofShape,
) -> EncProvenanceVerifier {
    let zeta = derive_zetas(&ct.to_bytes(), 1)[0];
    let t0_cols_owned: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();
    let t0_cols: Vec<&[u64]> = t0_cols_owned.iter().map(|v| v.as_slice()).collect();
    let v_z = rq_coeffs_zq(&ct.v);
    let (a, c) = r3b_public_coeffs(&t0_cols, &v_z, zeta, N);
    let l = MU + 3;
    let rc = RelationCheckAir { num_terms: l };

    let mut airs = Vec::from([
        EncProofAir::Sponge(ShakeSpongeAir {
            height: shape.sponge_height,
        }),
        EncProofAir::SqueezeByte(SqueezeByteAir),
        EncProofAir::Ternary(TernarySamplerAir {
            num_coeffs: shape.num_e_coeffs,
        }),
    ]);
    for _ in 0..MU {
        airs.push(EncProofAir::HornerFold(HornerFoldAir));
    }
    airs.push(EncProofAir::HornerFold(HornerFoldAir)); // g
    airs.push(EncProofAir::EncodeMuFold(EncodeMuFoldAir)); // encode
    airs.push(EncProofAir::HornerFold(HornerFoldAir)); // hb
    airs.push(EncProofAir::RelationCheck(rc.clone()));

    let lookups = e_provenance_lookups(&rc);
    // pk_digest is rebuilt from `t0` — the verifier does NOT trust a prover-supplied value
    // (adversarial-review 2026-07-11: the single most important obligation). `ct` is bound because ζ,
    // v_z and the relation coefficients are all recomputed from it above.
    let pk_digest = lib_q_threshold_kem_lattice::kem::pk_digest_of(t0);
    let rel_pubs = relation_public_values(&a, c);
    let public_values =
        e_provenance_public_values(&pk_digest, shape.num_e_coeffs, zeta, &a, c, &rel_pubs);

    EncProvenanceVerifier {
        airs,
        public_values,
        lookups,
    }
}

/// The per-instance lookup lists (identical for prover and verifier — no witness data). Order matches
/// the AIR order: sponge (limb Sends), squeeze (limb Receive + byte Send), e-sampler (byte Receive +
/// coeff Send), `MU` e_r folds (coeff Receive at base `r·N·4` + `E`-Send to R3b term `r`), g/encode/hb
/// folds (`E`-Send to terms `MU`/`MU+1`/`MU+2`), R3b relation (`w`-Receive of all terms).
fn e_provenance_lookups(rc: &RelationCheckAir) -> Vec<Vec<Lookup<ConfigVal>>> {
    let mut lookups: Vec<Vec<Lookup<ConfigVal>>> = Vec::new();
    lookups.push(sponge_limb_send_lookups());
    lookups.push(Vec::from([
        squeeze_byte_send_lookup(),
        squeeze_byte_limb_receive_lookup(),
    ]));
    let mut e_samp = Vec::from([ternary_receive_lookup()]); // byte Receive (aux col 0)
    e_samp.extend(ternary_coeff_send_lookups_at(0, 1)); // coeff Send (aux cols 1..5)
    lookups.push(e_samp);
    for r in 0..MU {
        // e_r fold: join-2 receive at base r·N·4 (cols 0..4) + join-3 send to R3b term r (cols 4..8).
        let mut fl = horner_coeff_receive_lookups_at(COEFF_E_BUS, (r as u64) * (N as u64) * 4);
        fl.extend(horner_e_send_lookups_at(FOLD_E_BUS, 0, r, 4));
        lookups.push(fl);
    }
    lookups.push(horner_e_send_lookups_at(FOLD_E_BUS, 0, MU, 0)); // g → term MU
    lookups.push(horner_e_send_lookups_at(FOLD_E_BUS, 0, MU + 1, 0)); // encode → term MU+1
    lookups.push(horner_e_send_lookups_at(FOLD_E_BUS, 0, MU + 2, 0)); // hb → term MU+2
    lookups.push(rc.relation_w_receive_lookups_at(FOLD_E_BUS, 0));
    lookups
}

/// The per-instance public values, in AIR order. `pk_digest` pins the sponge (ciphertext binding);
/// `zeta` pins every fold; `(a, c)`/`rel_pubs` pin the relation.
fn e_provenance_public_values(
    pk_digest: &[u8; 32],
    num_e: usize,
    zeta: u64,
    _a: &[u64],
    _c: u64,
    rel_pubs: &[ConfigVal],
) -> Vec<Vec<ConfigVal>> {
    let zeta_pubs = horner_public_values(zeta);
    let mut pubs: Vec<Vec<ConfigVal>> = Vec::from([
        sponge_public_values(pk_digest),
        Vec::new(),
        ternary_public_values(num_e),
    ]);
    for _ in 0..MU {
        pubs.push(zeta_pubs.clone());
    }
    pubs.push(zeta_pubs.clone()); // g
    pubs.push(encode_mu_public_values(zeta)); // encode
    pubs.push(zeta_pubs); // hb
    pubs.push(rel_pubs.to_vec()); // relation
    pubs
}

// ══════════════════════════════════════════════════════════════════════════════════════════════════
// R3a + f byte-provenance — binds BOTH e (ternary) AND f (bounded) to the XOF, proving the R3a
// `p_k = Σ_r B0_{r,k}·e_r + f_k` equations. This is what closes the classic `f = δ·unitₖ` insider
// spike: f_k is pinned to the bounded rejection-sampling of the XOF bytes drawn AFTER e (absolute
// offset `e_bytes`), so a spike f (out of range, or ≠ the XOF output) cannot produce a verifying proof.
// ══════════════════════════════════════════════════════════════════════════════════════════════════

/// FOLD_E_BUS base spacing per R3a relation instance: `(MU + 3)·4` ≥ `4·(MU + 2)` (the term count of an
/// R3a relation: `MU` e-folds + `F_k` + quotient). Distinct relations use `[i·SPAN, i·SPAN + 4·(MU+2))`.
const R3A_BASE_SPAN: u64 = ((MU + 3) as u64) * 4;

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

/// **Prover** assembly of the R3a+f byte-provenance layer for `(t0, μ, columns)`. Binds `e` (all
/// `MU·N` ternary coeffs) AND `f` (the bounded coeffs of `f_0..=f_max`, drawn at absolute offset
/// `e_bytes`) to the genuine SHAKE output, and proves `p_k = Σ_r B0_{r,k}·e_r + f_k` for each `k` in
/// `columns`. The `MU` `e_r` folds are SHARED across all selected relations (fan-out on FOLD_E_BUS);
/// each `f_k` fold is byte-bound via COEFF_F_BUS; the quotient `HK_k` folds are fed directly.
///
/// `columns` must be a prefix `0..=max` (the `f` sampler draws `f_0, f_1, …` in order, so covering
/// `f_max` requires covering all earlier `f_j`). Returns the ciphertext, the [`R3aProofShape`], and the
/// assembled instances.
///
/// # Errors
/// [`EncProofError::TraceGeneration`] on a rejected trace (e.g. the R3a numerator is not divisible —
/// impossible for a well-formed witness) or an exhausted XOF.
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

    // Samplers over the real XOF: e first (offset 0), then f (offset e_bytes).
    let e_num = MU * N;
    let bytes = shake256_xof(&input, e_num * 2 + f_num * 8 + 8192);
    let e_sampler = generate_ternary_trace(&bytes, e_num)?;
    let e_bytes = active_rows(&e_sampler, SAMPLER_WIDTH);
    let f_sampler = generate_bounded_trace(&bytes[e_bytes..], f_num)?;
    let f_bytes = active_rows(&f_sampler, BOUNDED_WIDTH) * 8;
    let total_consumed = e_bytes + f_bytes;

    let sponge = generate_provable_sponge_trace(&input, total_consumed + RATE_BYTES);
    let height = sponge.values.len() / NUM_KECCAK_COLS;
    let blocks = sponge_squeeze_blocks(height);
    let full_limbs = blocks * (RATE_BYTES / 2);
    let squeeze = generate_squeeze_byte_trace_partial(&input, full_limbs, total_consumed);

    let zeta = derive_zetas(&ct.to_bytes(), 1)[0];

    // Shared e_r folds (byte-bound to the ternary sampler).
    let e_lifts: Zeroizing<Vec<Vec<u64>>> =
        Zeroizing::new(w.e.iter().map(rq_coeffs_zq).collect());
    let e_ref: Vec<&[u64]> = e_lifts.iter().map(|v| v.as_slice()).collect();
    let mut e_fold_traces = Vec::with_capacity(MU);
    let mut e_evs = Vec::with_capacity(MU);
    for e in e_lifts.iter() {
        let (t, ev) = generate_horner_trace(e, zeta)?;
        e_fold_traces.push(t);
        e_evs.push(ev);
    }

    // Per-column: f_k fold (byte-bound), quotient HK_k fold (direct), R3a relation.
    let rc = RelationCheckAir { num_terms: MU + 2 };
    let mut f_fold_traces = Vec::new();
    let mut hk_fold_traces = Vec::new();
    let mut relation_traces = Vec::new();
    let mut rel_pubs_all = Vec::new();
    for &k in columns {
        let b0_cols_owned: Vec<Vec<u64>> =
            (0..MU).map(|r| rq_coeffs_zq(&b0[r * KAPPA + k])).collect();
        let b0_cols: Vec<&[u64]> = b0_cols_owned.iter().map(|v| v.as_slice()).collect();
        let p_k = rq_coeffs_zq(&ct.p[k]);
        let f_k: Zeroizing<Vec<u64>> = Zeroizing::new(rq_coeffs_zq(&w.f[k]));
        let (a, c) = r3a_public_coeffs(&b0_cols, &p_k, zeta, N);
        let hk: Zeroizing<Vec<u64>> = Zeroizing::new(
            r3a_quotient_poly(&b0_cols, &e_ref, &f_k, &p_k, N)
                .ok_or(EncProofError::TraceGeneration("R3a numerator not divisible"))?,
        );

        let (f_trace, f_ev) = generate_horner_trace(&f_k, zeta)?;
        let (hk_trace, hk_ev) = generate_horner_trace(&hk, zeta)?;
        let mut w_terms = e_evs.clone();
        w_terms.push(f_ev);
        w_terms.push(hk_ev);
        let (rm, rel_pubs) = generate_relation_trace(&a, &w_terms, c)?;

        f_fold_traces.push(f_trace);
        hk_fold_traces.push(hk_trace);
        relation_traces.push(pad_relation(&rm));
        rel_pubs_all.push(rel_pubs);
    }

    // AIRs, in the canonical order.
    let mut airs = Vec::from([
        EncProofAir::Sponge(ShakeSpongeAir { height }),
        EncProofAir::SqueezeByte(SqueezeByteAir),
        EncProofAir::Ternary(TernarySamplerAir { num_coeffs: e_num }),
        EncProofAir::Bounded(BoundedSamplerAir { num_coeffs: f_num }),
    ]);
    for _ in 0..MU {
        airs.push(EncProofAir::HornerFold(HornerFoldAir));
    }
    for _ in columns {
        airs.push(EncProofAir::HornerFold(HornerFoldAir)); // f_k
        airs.push(EncProofAir::HornerFold(HornerFoldAir)); // HK_k
        airs.push(EncProofAir::RelationCheck(rc.clone())); // R3a_k
    }

    let lookups = r3a_f_lookups(columns, e_bytes as u64, &rc);

    // Traces.
    let mut traces: Vec<RowMajorMatrix<ConfigVal>> = Vec::from([sponge, squeeze, e_sampler, f_sampler]);
    traces.extend(e_fold_traces);
    for i in 0..columns.len() {
        traces.push(f_fold_traces[i].clone());
        traces.push(hk_fold_traces[i].clone());
        traces.push(relation_traces[i].clone());
    }

    // Public values.
    let public_values = r3a_f_public_values(&w.pk_digest, e_num, f_num, zeta, &rel_pubs_all);

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

/// **Verifier** assembly for the R3a+f layer: rebuilds every AIR from the public [`R3aProofShape`], the
/// sponge pk-binding public values from `pk_digest_of(t0)`, and each R3a relation's public coefficients
/// from `(B0, t0, ct, ζ)` — never prover-supplied. Lookups rebuilt identically. Feed to `verify_batch`.
pub fn assemble_r3a_f_provenance_verifier(
    t0: &[Rq],
    ct: &Ciphertext,
    shape: &R3aProofShape,
) -> EncProvenanceVerifier {
    let zeta = derive_zetas(&ct.to_bytes(), 1)[0];
    let b0 = key().b0();
    let rc = RelationCheckAir { num_terms: MU + 2 };

    let mut airs = Vec::from([
        EncProofAir::Sponge(ShakeSpongeAir {
            height: shape.sponge_height,
        }),
        EncProofAir::SqueezeByte(SqueezeByteAir),
        EncProofAir::Ternary(TernarySamplerAir {
            num_coeffs: shape.e_num_coeffs,
        }),
        EncProofAir::Bounded(BoundedSamplerAir {
            num_coeffs: shape.f_num_coeffs,
        }),
    ]);
    for _ in 0..MU {
        airs.push(EncProofAir::HornerFold(HornerFoldAir));
    }
    let mut rel_pubs_all = Vec::new();
    for &k in &shape.columns {
        airs.push(EncProofAir::HornerFold(HornerFoldAir)); // f_k
        airs.push(EncProofAir::HornerFold(HornerFoldAir)); // HK_k
        airs.push(EncProofAir::RelationCheck(rc.clone())); // R3a_k

        let b0_cols_owned: Vec<Vec<u64>> =
            (0..MU).map(|r| rq_coeffs_zq(&b0[r * KAPPA + k])).collect();
        let b0_cols: Vec<&[u64]> = b0_cols_owned.iter().map(|v| v.as_slice()).collect();
        let p_k = rq_coeffs_zq(&ct.p[k]);
        let (a, c) = r3a_public_coeffs(&b0_cols, &p_k, zeta, N);
        rel_pubs_all.push(relation_public_values(&a, c));
    }

    let lookups = r3a_f_lookups(&shape.columns, shape.f_offset as u64, &rc);
    let pk_digest = lib_q_threshold_kem_lattice::kem::pk_digest_of(t0);
    let public_values = r3a_f_public_values(
        &pk_digest,
        shape.e_num_coeffs,
        shape.f_num_coeffs,
        zeta,
        &rel_pubs_all,
    );

    EncProvenanceVerifier {
        airs,
        public_values,
        lookups,
    }
}

/// The per-instance lookup lists for the R3a+f layer (identical prover/verifier — no witness). Order:
/// sponge, squeeze, e-sampler, f-sampler, `MU` shared e_r folds (each fanning out to every selected
/// relation), then per column `(f_k fold, HK_k fold, relation)`.
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
    // Shared e_r folds: coeff-Receive (cols 0..4) + one E-Send per selected relation.
    for r in 0..MU {
        let mut fl = horner_coeff_receive_lookups_at(COEFF_E_BUS, (r as u64) * (N as u64) * 4);
        for (i, _) in columns.iter().enumerate() {
            let base = (i as u64) * R3A_BASE_SPAN;
            fl.extend(horner_e_send_lookups_at(FOLD_E_BUS, base, r, 4 * (1 + i)));
        }
        lookups.push(fl);
    }
    // Per column: f_k fold, HK_k fold, relation.
    for (i, &k) in columns.iter().enumerate() {
        let base = (i as u64) * R3A_BASE_SPAN;
        // f_k fold: coeff-Receive from COEFF_F at base k·N·4 (cols 0..4) + E-Send to term MU (col_base 4).
        let mut fl = horner_coeff_receive_lookups_at(COEFF_F_BUS, (k as u64) * (N as u64) * 4);
        fl.extend(horner_e_send_lookups_at(FOLD_E_BUS, base, MU, 4));
        lookups.push(fl);
        // HK_k quotient fold (fed directly): E-Send to term MU+1 (col_base 0).
        lookups.push(horner_e_send_lookups_at(FOLD_E_BUS, base, MU + 1, 0));
        // Relation: receive all MU+2 terms at its base.
        lookups.push(rc.relation_w_receive_lookups_at(FOLD_E_BUS, base));
    }
    lookups
}

/// Per-instance public values for the R3a+f layer, in AIR order.
fn r3a_f_public_values(
    pk_digest: &[u8; 32],
    e_num: usize,
    f_num: usize,
    zeta: u64,
    rel_pubs_all: &[Vec<ConfigVal>],
) -> Vec<Vec<ConfigVal>> {
    let zeta_pubs = horner_public_values(zeta);
    let mut pubs: Vec<Vec<ConfigVal>> = Vec::from([
        sponge_public_values(pk_digest),
        Vec::new(),
        ternary_public_values(e_num),
        bounded_public_values(f_num),
    ]);
    for _ in 0..MU {
        pubs.push(zeta_pubs.clone()); // e_r folds
    }
    for rel_pubs in rel_pubs_all {
        pubs.push(zeta_pubs.clone()); // f_k fold
        pubs.push(zeta_pubs.clone()); // HK_k fold
        pubs.push(rel_pubs.clone()); // relation
    }
    pubs
}


// ══════════════════════════════════════════════════════════════════════════════════════════════════
// FULL byte-provenance — the COMPLETE malformed-ciphertext closure, with m-challenge soundness.
//
// Binds e (ternary) + ALL f_k (bounded) + g (bounded) to the single XOF stream, and proves ALL KAPPA
// R3a `p_k` equations AND the R3b `v` equation, in ONE batch, over `m` independent Fiat–Shamir
// challenges ζ_0..ζ_{m-1}. One verifying proof certifies the WHOLE ciphertext is a genuine
// `(e,f,g) = XOF(pk‖μ)` encryption with e ternary and f,g bounded — no component left free to spike.
//
// ## Why `m` challenges (closes H4)
// Each relation is a polynomial identity mod (X^N+1) checked at the challenge ζ = H(pk_digest‖ct).
// For a *malformed* ciphertext the identity fails as a polynomial, so it vanishes at ζ only with
// probability ≤ deg/|F| ≈ 2^-52 over the `Complex<Mersenne31>` field. Since the prover picks `ct`
// (hence can grind ζ = H(pk‖ct)), a single challenge gives only ~52-bit relation soundness. Checking
// the SAME witness at `m` independent challenges multiplies the miss probability to ≤ (deg/|F|)^m, so
// `m = 3` already exceeds ~150 bits. ζ absorbs `pk_digest` (multi-target FS separation) in addition
// to `ct`; the byte-provenance joins themselves are exact multiset checks whose soundness is the FRI
// soundness of the config (the production config's ~128 bits), independent of `m`.
//
// Sampler coefficient Sends are repeated `m×` (distinct aux columns), so the `m` per-challenge fold
// sets each Receive the (shared) coefficients once and every COEFF bus balances.
//
// Heavy: the sponge covers ~90 KB of XOF (e+f+g). The per-component tests validate the same machinery
// at tractable size; this is the full production-shaped proof.
// ══════════════════════════════════════════════════════════════════════════════════════════════════

/// FOLD_E_BUS span reserved per Fiat–Shamir challenge block: `(KAPPA + 1)` relations
/// (`KAPPA` R3a + 1 R3b), each `R3A_BASE_SPAN` wide. Challenge `i`'s relations live in
/// `[i·CHALLENGE_SPAN, (i+1)·CHALLENGE_SPAN)`, disjoint across challenges.
const CHALLENGE_SPAN: u64 = ((KAPPA + 1) as u64) * R3A_BASE_SPAN;

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

/// The `m` Fiat–Shamir challenges of the statement `(pk_digest ‖ ct)` — absorbing `pk_digest` gives
/// multi-target separation (closes the H4 transcript half); the prover cannot supply these (the
/// verifier recomputes them identically from `(t0, ct)`).
fn statement_zetas(pk_digest: &[u8; 32], ct: &Ciphertext, m: usize) -> Vec<u64> {
    let ct_bytes = ct.to_bytes();
    let mut stmt = Vec::with_capacity(32 + ct_bytes.len());
    stmt.extend_from_slice(pk_digest);
    stmt.extend_from_slice(&ct_bytes);
    derive_zetas(&stmt, m)
}

/// **Prover** assembly of the FULL `m`-challenge byte-provenance proof for `(t0, μ)`. Binds `e`, all
/// `KAPPA` `f_k`, and `g` to the single SHAKE stream (offsets `0`, `e_bytes`, `e_bytes+f_bytes`), and
/// proves every R3a `p_k` AND R3b at each of `num_challenges` independent challenges. Returns the
/// ciphertext, the [`FullProofShape`], and the instances.
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

    let e_num = MU * N;
    let f_num = KAPPA * N;
    let g_num = N;
    let bytes = shake256_xof(&input, (e_num + f_num + g_num) * 8 + 16384);
    let e_sampler = generate_ternary_trace(&bytes, e_num)?;
    let e_bytes = active_rows(&e_sampler, SAMPLER_WIDTH);
    let f_sampler = generate_bounded_trace(&bytes[e_bytes..], f_num)?;
    let f_bytes = active_rows(&f_sampler, BOUNDED_WIDTH) * 8;
    let g_sampler = generate_bounded_trace(&bytes[e_bytes + f_bytes..], g_num)?;
    let g_bytes = active_rows(&g_sampler, BOUNDED_WIDTH) * 8;
    let total_consumed = e_bytes + f_bytes + g_bytes;

    let sponge = generate_provable_sponge_trace(&input, total_consumed + RATE_BYTES);
    let height = sponge.values.len() / NUM_KECCAK_COLS;
    let blocks = sponge_squeeze_blocks(height);
    let full_limbs = blocks * (RATE_BYTES / 2);
    let squeeze = generate_squeeze_byte_trace_partial(&input, full_limbs, total_consumed);

    let zetas = statement_zetas(&w.pk_digest, &ct, m);

    // Shared witness polynomials (computed once; folded per challenge).
    let e_lifts: Zeroizing<Vec<Vec<u64>>> =
        Zeroizing::new(w.e.iter().map(rq_coeffs_zq).collect());
    let e_ref: Vec<&[u64]> = e_lifts.iter().map(|v| v.as_slice()).collect();
    let t0_cols_owned: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();
    let t0_cols: Vec<&[u64]> = t0_cols_owned.iter().map(|v| v.as_slice()).collect();
    let v_z = rq_coeffs_zq(&ct.v);
    let g_z: Zeroizing<Vec<u64>> = Zeroizing::new(rq_coeffs_zq(&w.g));
    let encode_z: Zeroizing<Vec<u64>> = Zeroizing::new(rq_coeffs_zq(&encode_msg(mu)));
    // Per-column B0 columns, p_k, f_k lift, and the (ζ-independent) R3a quotient polynomial.
    let mut b0_cols_all: Vec<Vec<Vec<u64>>> = Vec::with_capacity(KAPPA);
    let mut p_all: Vec<Vec<u64>> = Vec::with_capacity(KAPPA);
    let mut f_lifts: Vec<Zeroizing<Vec<u64>>> = Vec::with_capacity(KAPPA);
    let mut hk_polys: Vec<Zeroizing<Vec<u64>>> = Vec::with_capacity(KAPPA);
    for k in 0..KAPPA {
        let cols: Vec<Vec<u64>> = (0..MU).map(|r| rq_coeffs_zq(&b0[r * KAPPA + k])).collect();
        let col_refs: Vec<&[u64]> = cols.iter().map(|v| v.as_slice()).collect();
        let p_k = rq_coeffs_zq(&ct.p[k]);
        let f_k: Zeroizing<Vec<u64>> = Zeroizing::new(rq_coeffs_zq(&w.f[k]));
        let hk = r3a_quotient_poly(&col_refs, &e_ref, &f_k, &p_k, N)
            .ok_or(EncProofError::TraceGeneration("R3a numerator not divisible"))?;
        b0_cols_all.push(cols);
        p_all.push(p_k);
        f_lifts.push(f_k);
        hk_polys.push(Zeroizing::new(hk));
    }
    let hb: Zeroizing<Vec<u64>> = Zeroizing::new(
        r3b_quotient_poly(&t0_cols, &e_ref, &g_z, &encode_z, &v_z, N)
            .ok_or(EncProofError::TraceGeneration("R3b numerator not divisible"))?,
    );

    let rc_a = RelationCheckAir { num_terms: MU + 2 };
    let rc_b = RelationCheckAir { num_terms: MU + 3 };

    // Per-challenge fold + relation traces (in the canonical order used by the AIR list below).
    let mut per_challenge_traces: Vec<Vec<RowMajorMatrix<ConfigVal>>> = Vec::with_capacity(m);
    let mut per_challenge_relpubs: Vec<(Vec<Vec<ConfigVal>>, Vec<ConfigVal>)> = Vec::with_capacity(m);
    for &zeta in &zetas {
        let mut traces_i: Vec<RowMajorMatrix<ConfigVal>> = Vec::new();
        // MU e-folds.
        let mut e_evs = Vec::with_capacity(MU);
        for e in e_lifts.iter() {
            let (t, ev) = generate_horner_trace(e, zeta)?;
            traces_i.push(t);
            e_evs.push(ev);
        }
        // Per column: f_k fold, HK_k fold, R3a relation.
        let mut r3a_pubs_i = Vec::with_capacity(KAPPA);
        for k in 0..KAPPA {
            let col_refs: Vec<&[u64]> = b0_cols_all[k].iter().map(|v| v.as_slice()).collect();
            let (a, c) = r3a_public_coeffs(&col_refs, &p_all[k], zeta, N);
            let (f_trace, f_ev) = generate_horner_trace(&f_lifts[k], zeta)?;
            let (hk_trace, hk_ev) = generate_horner_trace(&hk_polys[k], zeta)?;
            let mut w_terms = e_evs.clone();
            w_terms.push(f_ev);
            w_terms.push(hk_ev);
            let (rm, rel_pubs) = generate_relation_trace(&a, &w_terms, c)?;
            traces_i.push(f_trace);
            traces_i.push(hk_trace);
            traces_i.push(pad_relation(&rm));
            r3a_pubs_i.push(rel_pubs);
        }
        // R3b: g fold, encode fold, hb fold, relation.
        let (a_b, c_b) = r3b_public_coeffs(&t0_cols, &v_z, zeta, N);
        let (g_trace, g_ev) = generate_horner_trace(&g_z, zeta)?;
        let (enc_trace, enc_ev) = generate_encode_mu_trace(mu, zeta)?;
        let (hb_trace, hb_ev) = generate_horner_trace(&hb, zeta)?;
        let mut w_terms_b = e_evs.clone();
        w_terms_b.push(g_ev);
        w_terms_b.push(enc_ev);
        w_terms_b.push(hb_ev);
        let (rm_b, r3b_pubs) = generate_relation_trace(&a_b, &w_terms_b, c_b)?;
        traces_i.push(g_trace);
        traces_i.push(enc_trace);
        traces_i.push(hb_trace);
        traces_i.push(pad_relation(&rm_b));

        per_challenge_traces.push(traces_i);
        per_challenge_relpubs.push((r3a_pubs_i, r3b_pubs));
    }

    // AIRs.
    let mut airs = Vec::from([
        EncProofAir::Sponge(ShakeSpongeAir { height }),
        EncProofAir::SqueezeByte(SqueezeByteAir),
        EncProofAir::Ternary(TernarySamplerAir { num_coeffs: e_num }),
        EncProofAir::Bounded(BoundedSamplerAir { num_coeffs: f_num }),
        EncProofAir::Bounded(BoundedSamplerAir { num_coeffs: g_num }),
    ]);
    for _ in 0..m {
        for _ in 0..MU {
            airs.push(EncProofAir::HornerFold(HornerFoldAir));
        }
        for _ in 0..KAPPA {
            airs.push(EncProofAir::HornerFold(HornerFoldAir)); // f_k
            airs.push(EncProofAir::HornerFold(HornerFoldAir)); // HK_k
            airs.push(EncProofAir::RelationCheck(rc_a.clone())); // R3a_k
        }
        airs.push(EncProofAir::HornerFold(HornerFoldAir)); // g
        airs.push(EncProofAir::EncodeMuFold(EncodeMuFoldAir)); // encode
        airs.push(EncProofAir::HornerFold(HornerFoldAir)); // hb
        airs.push(EncProofAir::RelationCheck(rc_b.clone())); // R3b
    }

    let lookups = full_lookups(m, e_bytes as u64, (e_bytes + f_bytes) as u64, &rc_a, &rc_b);

    // Traces.
    let mut traces: Vec<RowMajorMatrix<ConfigVal>> =
        Vec::from([sponge, squeeze, e_sampler, f_sampler, g_sampler]);
    for ti in per_challenge_traces {
        traces.extend(ti);
    }

    // Public values.
    let public_values =
        full_public_values(&w.pk_digest, e_num, f_num, g_num, &zetas, &per_challenge_relpubs);

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

/// **Verifier** assembly of the full `m`-challenge proof: rebuilds every AIR from [`FullProofShape`],
/// the sponge pk-binding pubs from `pk_digest_of(t0)`, and every relation's coefficients from
/// `(B0, t0, ct, ζ_i)`. Feed to `verify_batch`.
pub fn assemble_full_provenance_verifier(
    t0: &[Rq],
    ct: &Ciphertext,
    shape: &FullProofShape,
) -> EncProvenanceVerifier {
    let m = shape.num_challenges;
    let pk_digest = lib_q_threshold_kem_lattice::kem::pk_digest_of(t0);
    let zetas = statement_zetas(&pk_digest, ct, m);
    let b0 = key().b0();
    let rc_a = RelationCheckAir { num_terms: MU + 2 };
    let rc_b = RelationCheckAir { num_terms: MU + 3 };

    let t0_cols_owned: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();
    let t0_cols: Vec<&[u64]> = t0_cols_owned.iter().map(|v| v.as_slice()).collect();
    let v_z = rq_coeffs_zq(&ct.v);
    let b0_cols_all: Vec<Vec<Vec<u64>>> = (0..KAPPA)
        .map(|k| (0..MU).map(|r| rq_coeffs_zq(&b0[r * KAPPA + k])).collect())
        .collect();
    let p_all: Vec<Vec<u64>> = (0..KAPPA).map(|k| rq_coeffs_zq(&ct.p[k])).collect();

    let mut airs = Vec::from([
        EncProofAir::Sponge(ShakeSpongeAir {
            height: shape.sponge_height,
        }),
        EncProofAir::SqueezeByte(SqueezeByteAir),
        EncProofAir::Ternary(TernarySamplerAir {
            num_coeffs: shape.e_num_coeffs,
        }),
        EncProofAir::Bounded(BoundedSamplerAir {
            num_coeffs: shape.f_num_coeffs,
        }),
        EncProofAir::Bounded(BoundedSamplerAir {
            num_coeffs: shape.g_num_coeffs,
        }),
    ]);
    let mut per_challenge_relpubs: Vec<(Vec<Vec<ConfigVal>>, Vec<ConfigVal>)> = Vec::with_capacity(m);
    for &zeta in &zetas {
        for _ in 0..MU {
            airs.push(EncProofAir::HornerFold(HornerFoldAir));
        }
        let mut r3a_pubs_i = Vec::with_capacity(KAPPA);
        for k in 0..KAPPA {
            airs.push(EncProofAir::HornerFold(HornerFoldAir));
            airs.push(EncProofAir::HornerFold(HornerFoldAir));
            airs.push(EncProofAir::RelationCheck(rc_a.clone()));
            let col_refs: Vec<&[u64]> = b0_cols_all[k].iter().map(|v| v.as_slice()).collect();
            let (a, c) = r3a_public_coeffs(&col_refs, &p_all[k], zeta, N);
            r3a_pubs_i.push(relation_public_values(&a, c));
        }
        airs.push(EncProofAir::HornerFold(HornerFoldAir)); // g
        airs.push(EncProofAir::EncodeMuFold(EncodeMuFoldAir)); // encode
        airs.push(EncProofAir::HornerFold(HornerFoldAir)); // hb
        airs.push(EncProofAir::RelationCheck(rc_b.clone())); // R3b
        let (a_b, c_b) = r3b_public_coeffs(&t0_cols, &v_z, zeta, N);
        per_challenge_relpubs.push((r3a_pubs_i, relation_public_values(&a_b, c_b)));
    }

    let lookups = full_lookups(m, shape.f_offset as u64, shape.g_offset as u64, &rc_a, &rc_b);
    let public_values = full_public_values(
        &pk_digest,
        shape.e_num_coeffs,
        shape.f_num_coeffs,
        shape.g_num_coeffs,
        &zetas,
        &per_challenge_relpubs,
    );

    EncProvenanceVerifier {
        airs,
        public_values,
        lookups,
    }
}

/// Per-instance lookups for the full `m`-challenge proof (identical prover/verifier). The three
/// samplers Send each coefficient `m×` (one aux-column block per challenge) so the `m` per-challenge
/// fold sets each Receive once and every COEFF bus balances. Challenge `i`'s e_r folds fan out to that
/// challenge's `KAPPA` R3a relations + R3b.
fn full_lookups(
    m: usize,
    f_offset: u64,
    g_offset: u64,
    rc_a: &RelationCheckAir,
    rc_b: &RelationCheckAir,
) -> Vec<Vec<Lookup<ConfigVal>>> {
    let mut lookups: Vec<Vec<Lookup<ConfigVal>>> = Vec::new();
    lookups.push(sponge_limb_send_lookups());
    lookups.push(Vec::from([
        squeeze_byte_send_lookup(),
        squeeze_byte_limb_receive_lookup(),
    ]));
    // e-sampler: byte-Receive (col 0) + m× coeff-Send on COEFF_E (aux cols 1.., one block of 4 per ζ).
    let mut e_samp = Vec::from([ternary_receive_lookup()]);
    for i in 0..m {
        e_samp.extend(ternary_coeff_send_lookups_at(0, 1 + 4 * i));
    }
    lookups.push(e_samp);
    // f-sampler: 8 byte-Receives (cols 0..8) + m× coeff-Send on COEFF_F (aux cols 8..).
    let mut f_samp = bounded_receive_lookup_at(f_offset);
    for i in 0..m {
        f_samp.extend(bounded_coeff_send_lookups_col(COEFF_F_BUS, 0, 8 + 4 * i));
    }
    lookups.push(f_samp);
    // g-sampler: 8 byte-Receives + m× coeff-Send on COEFF_G.
    let mut g_samp = bounded_receive_lookup_at(g_offset);
    for i in 0..m {
        g_samp.extend(bounded_coeff_send_lookups_col(COEFF_G_BUS, 0, 8 + 4 * i));
    }
    lookups.push(g_samp);
    // Per challenge: the fold + relation instances.
    for i in 0..m {
        let cbase = (i as u64) * CHALLENGE_SPAN;
        let r3b_base = cbase + (KAPPA as u64) * R3A_BASE_SPAN;
        // Shared-within-challenge e_r folds: coeff-Receive + fan-out to this challenge's KAPPA R3a + R3b.
        for r in 0..MU {
            let mut fl = horner_coeff_receive_lookups_at(COEFF_E_BUS, (r as u64) * (N as u64) * 4);
            for k in 0..KAPPA {
                let base = cbase + (k as u64) * R3A_BASE_SPAN;
                fl.extend(horner_e_send_lookups_at(FOLD_E_BUS, base, r, 4 * (1 + k)));
            }
            fl.extend(horner_e_send_lookups_at(FOLD_E_BUS, r3b_base, r, 4 * (1 + KAPPA)));
            lookups.push(fl);
        }
        // R3a per column.
        for k in 0..KAPPA {
            let base = cbase + (k as u64) * R3A_BASE_SPAN;
            let mut fl = horner_coeff_receive_lookups_at(COEFF_F_BUS, (k as u64) * (N as u64) * 4);
            fl.extend(horner_e_send_lookups_at(FOLD_E_BUS, base, MU, 4));
            lookups.push(fl);
            lookups.push(horner_e_send_lookups_at(FOLD_E_BUS, base, MU + 1, 0));
            lookups.push(rc_a.relation_w_receive_lookups_at(FOLD_E_BUS, base));
        }
        // R3b.
        let mut gl = horner_coeff_receive_lookups_at(COEFF_G_BUS, 0);
        gl.extend(horner_e_send_lookups_at(FOLD_E_BUS, r3b_base, MU, 4));
        lookups.push(gl);
        lookups.push(horner_e_send_lookups_at(FOLD_E_BUS, r3b_base, MU + 1, 0)); // encode
        lookups.push(horner_e_send_lookups_at(FOLD_E_BUS, r3b_base, MU + 2, 0)); // hb
        lookups.push(rc_b.relation_w_receive_lookups_at(FOLD_E_BUS, r3b_base));
    }
    lookups
}

/// Per-instance public values for the full `m`-challenge proof, in AIR order.
fn full_public_values(
    pk_digest: &[u8; 32],
    e_num: usize,
    f_num: usize,
    g_num: usize,
    zetas: &[u64],
    per_challenge_relpubs: &[(Vec<Vec<ConfigVal>>, Vec<ConfigVal>)],
) -> Vec<Vec<ConfigVal>> {
    let mut pubs: Vec<Vec<ConfigVal>> = Vec::from([
        sponge_public_values(pk_digest),
        Vec::new(),
        ternary_public_values(e_num),
        bounded_public_values(f_num),
        bounded_public_values(g_num),
    ]);
    for (zeta, (r3a_pubs, r3b_pubs)) in zetas.iter().zip(per_challenge_relpubs.iter()) {
        let zeta_pubs = horner_public_values(*zeta);
        for _ in 0..MU {
            pubs.push(zeta_pubs.clone()); // e_r folds
        }
        for rel_pubs in r3a_pubs {
            pubs.push(zeta_pubs.clone()); // f_k
            pubs.push(zeta_pubs.clone()); // HK_k
            pubs.push(rel_pubs.clone()); // R3a_k relation
        }
        pubs.push(zeta_pubs.clone()); // g
        pubs.push(encode_mu_public_values(*zeta)); // encode
        pubs.push(zeta_pubs.clone()); // hb
        pubs.push(r3b_pubs.clone()); // R3b relation
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
    (0..height).filter(|r| r % NUM_ROUNDS == NUM_ROUNDS - 1).count()
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
    use lib_q_zkp::stark::{
        ConfigDft,
        DefaultChallengeMmcs,
        DefaultPcs,
        DefaultValMmcs,
    };

    use super::*;

    type TestChallenger = ComplexFieldChallenger<Shake256Challenger32<Mersenne31>>;
    type Cfg = StarkConfig<DefaultPcs, ConfigVal, TestChallenger>;

    /// Assemble a `StarkConfig` from a set of FRI parameters (shared plumbing for the test and
    /// production configs).
    fn config_from_fri(
        fri_params: FriParameters<DefaultChallengeMmcs>,
        val_mmcs: DefaultValMmcs,
    ) -> Cfg {
        let dft = ConfigDft::default();
        let pcs = DefaultPcs::new(dft, val_mmcs, fri_params);
        let base = Shake256Challenger32::<Mersenne31>::from_hasher(Vec::new(), Shake256Hash);
        StarkConfig::new(pcs, ComplexFieldChallenger::new(base))
    }

    fn mmcs_pair() -> (DefaultValMmcs, DefaultChallengeMmcs) {
        let shake = Shake256Hash {};
        let hash = lib_q_stark_symmetric::SerializingHasher::<Shake256Hash>::new(shake);
        let compress =
            lib_q_stark_symmetric::CompressionFunctionFromHasher::<Shake256Hash, 2, 32>::new(shake);
        let val_mmcs = DefaultValMmcs::new(hash, compress);
        let challenge_mmcs = DefaultChallengeMmcs::new(val_mmcs.clone());
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
        let (ct, shape, prover) =
            assemble_e_provenance_prover(t0, mu).expect("prover assembly for a well-formed witness");
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
    type ZkChallengeMmcs = lib_q_stark_commit::ExtensionMmcs<ConfigVal, ConfigVal, ZkValMmcs>;
    type ZkPcs = lib_q_stark_fri::HidingFriPcs<
        ConfigVal,
        ConfigDft,
        ZkValMmcs,
        ZkChallengeMmcs,
        lib_q_random::DeterministicRng,
    >;
    type ZkCfg = StarkConfig<ZkPcs, ConfigVal, TestChallenger>;

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
        let pcs = ZkPcs::new(dft, val_mmcs, fri_params, 4, DeterministicRng::seed_from_u64(1));
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
        let (ct, shape, prover) =
            assemble_e_provenance_prover(&t0, &mu).expect("prover assembly");
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
        // Under the hiding PCS the preprocessed commitment is randomized, so the verifier must use the
        // prover's committed preprocessed (it is public / verifier-trusted — a deterministic function of
        // the AIRs); it still recomputes ζ + all public values independently from `(t0, ct)`.
        let verifier = assemble_e_provenance_verifier(&t0, &ct, shape);
        assert!(
            verify_batch(
                &config,
                &verifier.airs,
                &proof,
                &verifier.public_values,
                &prover_data.common
            )
            .is_ok(),
            "the e-provenance proof must verify under the hiding-FRI (zero-knowledge) config"
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
    /// `verify_batch` rejects. Contrast with [`crate::prove::prove_relation_layer`], over which the same
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
        use lib_q_threshold_kem_lattice::threshold::ZeroShareSeeds;
        use lib_q_threshold_kem_lattice::SecretShare;
        use zeroize::Zeroizing;

        use crate::gate::gated_partial_decap_masked;

        let t0 = test_t0();
        let mu = [0x6Bu8; 32];
        let config = test_batch_config();

        let (ct, shape, prover) =
            assemble_e_provenance_prover(&t0, &mu).expect("prover assembly");
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
}
