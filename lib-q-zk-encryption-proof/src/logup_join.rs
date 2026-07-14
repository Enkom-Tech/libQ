//! LogUp **squeeze join** (design join 1) — binds the sampler's consumed XOF bytes to the sponge's
//! squeezed output, positionally, over a shared cross-table bus.
//!
//! ## What this join proves
//! The FO seed expansion is a single SHAKE-256 XOF stream `z = SHAKE256(DOM_FO_SEED ‖ pk_digest ‖ μ)`.
//! The samplers ([`crate::sampler`]) consume `z` byte-by-byte (`e` via the ternary sampler, `f`/`g` via
//! the bounded sampler) and each row records the *absolute byte position* it consumed and the *byte
//! value*. The sponge ([`crate::sponge_air`]) produces `z`. Join 1 is the LogUp argument that every
//! `(position, byte)` a sampler **receives** was **sent** by the byte-stream source at the same
//! position — a *positional* multiset equality (the tuple carries the index, so byte values at
//! different positions are distinguished; see design §5.1).
//!
//! ## Direction / bus convention
//! The byte-stream **source** (the sponge output, modelled in this milestone by [`XofStreamTableAir`])
//! is the **Send** side (contributes `−multiplicity`); each **sampler** is the **Receive** side
//! (`+multiplicity`). The batch verifier checks that the per-bus cumulated sum is zero
//! ([`lib_q_plonky_lookup`]'s `verify_global_final_value`), i.e. every received byte was sent exactly
//! once at its position. Both sides name the same bus [`XOF_STREAM_BUS`].
//!
//! ## Status (RED) — what this module lands
//! This module lands the **join mechanism** and the **Receive side against the real samplers**:
//! [`XofStreamTableAir`] (a positional byte-stream table that Sends `(pos, byte)`), and the samplers'
//! `*_receive_lookup()` constructors ([`crate::sampler::ternary_receive_lookup`],
//! [`crate::sampler::bounded_receive_lookup`]). The join is validated by
//! [`lib_q_plonky_lookup::debug_util::check_lookups`] (the multiset-balance analogue of
//! `check_constraints`): a matched producer/consumer pair balances; any tampered byte, shifted
//! position, or missing byte unbalances and is rejected.
//!
//! **Remaining for the full join (documented, not yet built):** (1) the **sponge Send side** — the
//! Keccak squeeze output is 16-bit *limbs* on `export` rows (136 bytes/permutation), so realising the
//! sponge as the byte-stream source needs a limb→byte decomposition and a squeeze-block index to form
//! the `(pos, byte)` tuples; [`XofStreamTableAir`] stands in for that source until it is built. (2)
//! **Global offsets** — the single XOF feeds several sampler instances in sequence (`e`, then each
//! `f`, then `g`); each sampler's local `stream_pos` must be shifted by the byte offset at which its
//! sub-draw begins so all instances share one absolute position axis. (3) the **`prove_batch`
//! integration** (the enum-wrapper over the heterogeneous AIRs + the full multi-table proof) that
//! *cryptographically* enforces the balance `check_lookups` checks here.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use lib_q_plonky_lookup::{
    Direction,
    Kind,
    Lookup,
    LookupAir,
};
use lib_q_stark_air::symbolic::{
    BaseEntry,
    SymbolicExpression,
    SymbolicVariable,
};
use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_field::{
    BasedVectorSpace,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_zkp::stark::ConfigVal;

/// The shared cross-table bus name for join 1 (the XOF byte stream). Both the byte-stream source
/// (Send) and every sampler (Receive) must name this exact string, or their `Kind::Global` lookups
/// land on different buses and never balance. Versioned (`.v0`) as a wire-relevant identifier.
pub const XOF_STREAM_BUS: &str = "libq.enc.xof-stream.v0";

/// Shared cross-table buses for **join 2** (design §5, coefficient binding): each sampler *Sends* the
/// mod-q lift of every coefficient it emits — as four 12-bit limbs at position `4·global_coeff_idx +
/// limb` — and the corresponding per-ring-element Horner fold ([`crate::zq::HornerFoldAir`]) *Receives*
/// them into its `w` limbs at position `4·(r·N) + 4·idx + limb` (`r` = which ring element, `idx` =
/// ζ-power). One bus per component keeps the `e` / `f` / `g` coefficient axes disjoint without base
/// bookkeeping; the fold's own canonicity + `w < q` checks back-propagate through the multiset
/// equality to pin each sampler limb. Versioned (`.v0`) as wire-relevant identifiers.
pub const COEFF_E_BUS: &str = "libq.enc.coeff-e.v0";
/// Join-2 bus for the bounded `f` coefficients (see [`COEFF_E_BUS`]).
pub const COEFF_F_BUS: &str = "libq.enc.coeff-f.v0";
/// Join-2 bus for the bounded `g` coefficients (see [`COEFF_E_BUS`]).
pub const COEFF_G_BUS: &str = "libq.enc.coeff-g.v0";

/// Shared cross-table bus for **join 3** (design §4.1, the boundary opening): each Horner fold
/// ([`crate::zq::HornerFoldAir`] / [`crate::zq::EncodeMuFoldAir`]) *Sends* its result `E` (the last
/// row's `r`, four limbs) gated by its last-row indicator, at position `base + 4·term + limb`; the
/// [`crate::zq::RelationCheckAir`] *Receives* it into its witness term `w_term` (gated by the first-row
/// indicator). `term` is the fold's index among the relation's witness terms; `base` distinguishes
/// relation instances (R3a per `p_k`, R3b for `v`) on the one bus. This is the "expose the result"
/// obligation the standalone fold cannot self-supply. Versioned (`.v0`).
///
/// **Composition obligation (disjoint bases — adversarial review 2026-07-11):** distinct
/// `RelationCheckAir` instances sharing this bus MUST use non-overlapping position ranges
/// `[base, base + 4·L)` (`L` = the instance's term count), and each fold's `term` argument to
/// [`crate::zq::horner_e_send_lookups_at`] must equal the `j` its target relation Receives at. This is
/// NOT enforced in code; a caller that aliases two instances' ranges could let one instance's Send
/// match another's Receive. Assign bases as a running offset `Σ 4·L_prev` per relation instance.
pub const FOLD_E_BUS: &str = "libq.enc.fold-e.v0";

/// The shared cross-table bus for the **sponge → squeeze-byte** join (design join 1, limb half):
/// the sponge Sends each squeezed 16-bit rate limb `(byte_position, limb_value)`; the squeeze-byte
/// table Receives `(bytepos, lo + 256·hi)` and matches, binding its byte decomposition to the true
/// sponge output. Distinct from [`XOF_STREAM_BUS`] (which carries individual bytes to the samplers).
/// Versioned (`.v0`) as a wire-relevant identifier.
pub const SQUEEZE_LIMB_BUS: &str = "libq.enc.squeeze-limb.v0";

/// A main-trace column reference (current row) as a lookup-tuple `SymbolicExpression`.
pub(crate) fn mcol(col: usize) -> SymbolicExpression<ConfigVal> {
    SymbolicExpression::from(SymbolicVariable::<ConfigVal>::new(
        BaseEntry::Main { offset: 0 },
        col,
    ))
}

/// A **preprocessed**-trace column reference (current row) as a lookup-tuple `SymbolicExpression`.
/// Used for deterministic, verifier-committed position offsets (e.g. the sponge's squeeze-block
/// byte offset `136·perm`), which the prover cannot forge.
pub(crate) fn pcol(col: usize) -> SymbolicExpression<ConfigVal> {
    SymbolicExpression::from(SymbolicVariable::<ConfigVal>::new(
        BaseEntry::Preprocessed { offset: 0 },
        col,
    ))
}

/// A small non-negative integer as a `ConfigVal` constant (real part only), for tuple-position
/// offsets and trace cells.
pub(crate) fn fc(x: u64) -> ConfigVal {
    ConfigVal::from_basis_coefficients_fn(|i| {
        if i == 0 {
            Mersenne31::new((x % ((1u64 << 31) - 1)) as u32)
        } else {
            Mersenne31::ZERO
        }
    })
}

/// A small integer as a constant lookup-tuple `SymbolicExpression` (for positional offsets like
/// `stream_pos + k`).
pub(crate) fn sconst(x: u64) -> SymbolicExpression<ConfigVal> {
    SymbolicExpression::from(fc(x))
}

// ── The byte-stream source table (Send side) ──────────────────────────────────────────────────────
//
// A minimal positional byte table: row i (while active) carries absolute position `pos` and one byte
// value. It Sends `(pos, byte)` on [`XOF_STREAM_BUS`] with multiplicity `active`. This models the
// sponge's squeezed output as a clean byte-indexed stream; the real sponge Send side (limb→byte
// decomposition over the Keccak squeeze rows) will replace it and use the *same* bus + tuple shape.

const XT_POS: usize = 0;
const XT_BYTE: usize = 1;
const XT_ACTIVE: usize = 2;

/// Trace width of [`XofStreamTableAir`].
pub const XOF_STREAM_TABLE_WIDTH: usize = 3;

/// Positional byte-stream source AIR: proves a contiguous `pos = 0, 1, 2, …` byte stream (active rows
/// first, then padding) and Sends each `(pos, byte)` on [`XOF_STREAM_BUS`]. Byte values are free here
/// (their binding to the true sponge output is the sponge Send side's job); this AIR only fixes the
/// position axis and the send multiplicity.
#[derive(Debug, Clone, Copy, Default)]
pub struct XofStreamTableAir;

impl<F> BaseAir<F> for XofStreamTableAir {
    fn width(&self) -> usize {
        XOF_STREAM_TABLE_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for XofStreamTableAir {
    fn eval(&self, builder: &mut AB) {
        let (active, pos, n_active, n_pos): (AB::Expr, AB::Expr, AB::Expr, AB::Expr) = {
            let main = builder.main();
            let local = main.current_slice();
            let next = main.next_slice();
            (
                local[XT_ACTIVE].into(),
                local[XT_POS].into(),
                next[XT_ACTIVE].into(),
                next[XT_POS].into(),
            )
        };
        builder.assert_bool(active.clone());
        // Positions start at 0 and advance by one per active row (padding freezes the counter).
        builder.when_first_row().assert_zero(pos.clone());
        builder
            .when_transition()
            .assert_zero(n_active * (AB::Expr::ONE - active.clone()));
        builder.when_transition().assert_zero(n_pos - pos - active);
    }
}

impl LookupAir<ConfigVal> for XofStreamTableAir {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        Vec::from([0])
    }

    fn get_lookups(&mut self) -> Vec<Lookup<ConfigVal>> {
        Vec::from([xof_stream_send_lookup()])
    }
}

/// The `(pos, byte)` **Send** lookup [`XofStreamTableAir`] contributes on [`XOF_STREAM_BUS`], gated by
/// `active` (so padding rows send nothing).
pub fn xof_stream_send_lookup() -> Lookup<ConfigVal> {
    let pos = mcol(XT_POS);
    let byte = mcol(XT_BYTE);
    let active = mcol(XT_ACTIVE);
    Lookup::new(
        Kind::Global(XOF_STREAM_BUS.into()),
        Vec::from([Vec::from([pos, byte])]),
        Vec::from([Direction::Send.multiplicity(active)]),
        Vec::from([0]),
    )
}

/// Build an [`XofStreamTableAir`] trace that Sends bytes `bytes[0..]` at positions `0..bytes.len()`,
/// padded to a power-of-two height (`active = 0`, position frozen). This is the byte-stream a set of
/// samplers consuming exactly `bytes` (in order, from absolute position 0) must balance against.
pub fn generate_xof_stream_table(bytes: &[u8]) -> RowMajorMatrix<ConfigVal> {
    let k = bytes.len();
    let height = k.next_power_of_two().max(2);
    let mut values = Vec::new();
    values.resize(height * XOF_STREAM_TABLE_WIDTH, ConfigVal::ZERO);
    for (i, &b) in bytes.iter().enumerate() {
        values[i * XOF_STREAM_TABLE_WIDTH + XT_POS] = fc(i as u64);
        values[i * XOF_STREAM_TABLE_WIDTH + XT_BYTE] = fc(u64::from(b));
        values[i * XOF_STREAM_TABLE_WIDTH + XT_ACTIVE] = ConfigVal::ONE;
    }
    // Padding rows: position stays at `k` (n_pos = pos + active with active = 0), byte 0, active 0.
    for i in k..height {
        values[i * XOF_STREAM_TABLE_WIDTH + XT_POS] = fc(k as u64);
    }
    RowMajorMatrix::new(values, XOF_STREAM_TABLE_WIDTH)
}

#[cfg(test)]
mod tests {
    use lib_q_plonky_lookup::debug_util::{
        LookupDebugInstance,
        check_lookups,
    };
    use lib_q_sha3::{
        ExtendableOutput,
        Update,
        XofReader,
    };

    use super::*;
    use crate::sampler::{
        BOUNDED_WIDTH,
        SAMPLER_WIDTH,
        bounded_receive_lookup,
        generate_bounded_trace,
        generate_ternary_trace,
        ternary_receive_lookup,
    };

    fn xof_bytes(seed: &[u8], n: usize) -> Vec<u8> {
        let mut h = lib_q_sha3::Shake256::default();
        h.update(seed);
        let mut rd = h.finalize_xof();
        let mut out = vec![0u8; n];
        rd.read(&mut out);
        out
    }

    /// Count active rows (= bytes consumed for the ternary sampler; ×8 for the bounded sampler).
    fn active_rows(trace: &RowMajorMatrix<ConfigVal>, width: usize, active_col: usize) -> usize {
        (0..trace.values.len() / width)
            .filter(|&r| trace.values[r * width + active_col] == ConfigVal::ONE)
            .count()
    }

    /// Run `check_lookups` on a producer/consumer instance pair and return whether it *rejected*
    /// (panicked with a multiset mismatch), under a silenced panic hook.
    fn join_rejects(
        producer: &RowMajorMatrix<ConfigVal>,
        producer_lookup: &Lookup<ConfigVal>,
        consumer: &RowMajorMatrix<ConfigVal>,
        consumer_lookup: &Lookup<ConfigVal>,
    ) -> bool {
        let none: Option<RowMajorMatrix<ConfigVal>> = None;
        let prod_l = core::slice::from_ref(producer_lookup);
        let cons_l = core::slice::from_ref(consumer_lookup);
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let p = LookupDebugInstance {
                main_trace: producer,
                preprocessed_trace: &none,
                public_values: &[],
                lookups: prod_l,
                permutation_challenges: &[],
            };
            let c = LookupDebugInstance {
                main_trace: consumer,
                preprocessed_trace: &none,
                public_values: &[],
                lookups: cons_l,
                permutation_challenges: &[],
            };
            check_lookups(&[p, c]);
        }));
        std::panic::set_hook(prev);
        r.is_err()
    }

    /// The ternary sampler's consumed byte stream balances the byte-stream source, positionally.
    #[test]
    fn join_binds_ternary_sampler_bytes() {
        let bytes = xof_bytes(b"libq/join/ternary", 4096);
        let num = 1024usize;
        let sampler = generate_ternary_trace(&bytes, num).expect("ternary trace");
        let k = active_rows(&sampler, SAMPLER_WIDTH, 0); // C_ACTIVE = 0
        let producer = generate_xof_stream_table(&bytes[..k]);

        // Balanced: every consumed (pos, byte) was produced at that pos → check_lookups accepts.
        assert!(
            !join_rejects(
                &producer,
                &xof_stream_send_lookup(),
                &sampler,
                &ternary_receive_lookup(),
            ),
            "an honest ternary byte stream must balance the source"
        );
    }

    /// Tampering one produced byte value unbalances the ternary join.
    #[test]
    fn join_rejects_tampered_source_byte_ternary() {
        let bytes = xof_bytes(b"libq/join/ternary-tamper", 2048);
        let num = 256usize;
        let sampler = generate_ternary_trace(&bytes, num).expect("ternary trace");
        let k = active_rows(&sampler, SAMPLER_WIDTH, 0);
        let mut producer = generate_xof_stream_table(&bytes[..k]);
        // Flip the byte at source row 0 (position 0) — no longer equals the consumed byte at pos 0.
        producer.values[XT_BYTE] += ConfigVal::ONE;
        assert!(
            join_rejects(
                &producer,
                &xof_stream_send_lookup(),
                &sampler,
                &ternary_receive_lookup(),
            ),
            "a tampered source byte must unbalance the positional join"
        );
    }

    /// Dropping a produced byte (source one byte short) unbalances the ternary join: the consumer
    /// receives a `(pos, byte)` at the final position that the source never sends.
    #[test]
    fn join_rejects_missing_source_byte_ternary() {
        let bytes = xof_bytes(b"libq/join/ternary-missing", 2048);
        let num = 256usize;
        let sampler = generate_ternary_trace(&bytes, num).expect("ternary trace");
        let k = active_rows(&sampler, SAMPLER_WIDTH, 0);
        let producer = generate_xof_stream_table(&bytes[..k - 1]); // one byte short
        assert!(
            join_rejects(
                &producer,
                &xof_stream_send_lookup(),
                &sampler,
                &ternary_receive_lookup(),
            ),
            "a source missing the last consumed byte must unbalance the join"
        );
    }

    /// The bounded sampler consumes 8 bytes per row at consecutive positions; the join binds all of
    /// them to the source positionally.
    #[test]
    fn join_binds_bounded_sampler_bytes() {
        let num = 128usize;
        let bytes = xof_bytes(b"libq/join/bounded", num * 8 + 1024);
        let sampler = generate_bounded_trace(&bytes, num).expect("bounded trace");
        let rows = active_rows(&sampler, BOUNDED_WIDTH, 0); // W_ACTIVE = 0
        let producer = generate_xof_stream_table(&bytes[..rows * 8]); // 8 bytes per active row
        assert!(
            join2_balances(
                &producer,
                &[xof_stream_send_lookup()],
                &sampler,
                &bounded_receive_lookup(),
            ),
            "an honest bounded byte stream must balance the source"
        );
    }

    /// Tampering one produced byte unbalances the bounded join (which reads 8 distinct positions/row).
    #[test]
    fn join_rejects_tampered_source_byte_bounded() {
        let num = 64usize;
        let bytes = xof_bytes(b"libq/join/bounded-tamper", num * 8 + 1024);
        let sampler = generate_bounded_trace(&bytes, num).expect("bounded trace");
        let rows = active_rows(&sampler, BOUNDED_WIDTH, 0);
        let mut producer = generate_xof_stream_table(&bytes[..rows * 8]);
        // Flip a byte in the middle of the stream (position 40).
        producer.values[40 * XOF_STREAM_TABLE_WIDTH + XT_BYTE] += ConfigVal::ONE;
        assert!(
            !join2_balances(
                &producer,
                &[xof_stream_send_lookup()],
                &sampler,
                &bounded_receive_lookup(),
            ),
            "a tampered source byte must unbalance the bounded positional join"
        );
    }

    /// **Global XOF offsets (design §5.1, one absolute axis).** Two samplers drawn in sequence from
    /// ONE XOF — `e` (ternary) starting at byte 0, then `f` (bounded) starting at `e`'s byte count —
    /// both Receive against a single byte-stream source on the *shared absolute* position axis (via
    /// `*_receive_lookup_at(offset)`). The union of their consumed positions tiles `[0, total)`
    /// exactly, so all three instances balance. A wrong offset for `f` unbalances the join.
    #[test]
    fn join_binds_two_samplers_on_shared_absolute_axis() {
        use crate::sampler::{
            bounded_receive_lookup_at,
            ternary_receive_lookup_at,
        };

        // The samplers now consume a *fixed budget* (they process the whole slice they are given,
        // emitting the first `num` accepts and draining the rest), so slice `e` and `f` at explicit
        // budget boundaries: 512 ternary attempts (≈ 384 accepts ≫ 128) then 24 + slack bounded draws.
        let e_budget = 512usize;
        let f_budget = (24 + 128) * 8; // kem::bounded_attempts(24) · 8
        let bytes = xof_bytes(b"libq/join/global-offsets", e_budget + f_budget);
        let e = generate_ternary_trace(&bytes[..e_budget], 128).expect("ternary trace");
        let e_bytes = active_rows(&e, SAMPLER_WIDTH, 0); // = e_budget (all rows active)
        let f = generate_bounded_trace(&bytes[e_budget..e_budget + f_budget], 24)
            .expect("bounded trace");
        let f_bytes = active_rows(&f, BOUNDED_WIDTH, 0) * 8; // = f_budget (all rows active)
        let total = e_bytes + f_bytes;
        let source = generate_xof_stream_table(&bytes[..total]);

        let none: Option<RowMajorMatrix<ConfigVal>> = None;
        let src_l = [xof_stream_send_lookup()];
        let e_l = [ternary_receive_lookup_at(0)];

        let run = |f_lookup: Vec<Lookup<ConfigVal>>| {
            let prev = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_| {}));
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                check_lookups(&[
                    LookupDebugInstance {
                        main_trace: &source,
                        preprocessed_trace: &none,
                        public_values: &[],
                        lookups: &src_l,
                        permutation_challenges: &[],
                    },
                    LookupDebugInstance {
                        main_trace: &e,
                        preprocessed_trace: &none,
                        public_values: &[],
                        lookups: &e_l,
                        permutation_challenges: &[],
                    },
                    LookupDebugInstance {
                        main_trace: &f,
                        preprocessed_trace: &none,
                        public_values: &[],
                        lookups: &f_lookup,
                        permutation_challenges: &[],
                    },
                ]);
            }));
            std::panic::set_hook(prev);
            r.is_err()
        };

        assert!(
            !run(bounded_receive_lookup_at(e_bytes as u64)),
            "e@0 + f@e_bytes must balance the shared source on one absolute axis"
        );
        assert!(
            run(bounded_receive_lookup_at(e_bytes as u64 + 1)),
            "a wrong global offset for f must unbalance the join"
        );
    }

    /// Run `check_lookups` over a two-instance pair and return whether it **balanced** (no panic).
    fn join2_balances(
        a_trace: &RowMajorMatrix<ConfigVal>,
        a_lu: &[Lookup<ConfigVal>],
        b_trace: &RowMajorMatrix<ConfigVal>,
        b_lu: &[Lookup<ConfigVal>],
    ) -> bool {
        let none: Option<RowMajorMatrix<ConfigVal>> = None;
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_lookups(&[
                LookupDebugInstance {
                    main_trace: a_trace,
                    preprocessed_trace: &none,
                    public_values: &[],
                    lookups: a_lu,
                    permutation_challenges: &[],
                },
                LookupDebugInstance {
                    main_trace: b_trace,
                    preprocessed_trace: &none,
                    public_values: &[],
                    lookups: b_lu,
                    permutation_challenges: &[],
                },
            ]);
        }));
        std::panic::set_hook(prev);
        r.is_ok()
    }

    /// **Join 2 (design §5, coefficient binding).** A ternary sampler emits `n` coefficients; a Horner
    /// fold evaluates the SAME coefficients (mod-q lifted) at ζ. The sampler Sends each coefficient's
    /// lift limbs on [`COEFF_E_BUS`] at `4·coeff_idx + j`; the fold Receives them into its `w` limbs at
    /// `4·idx + j`. Honest binding balances; a fold built over a *different* coefficient unbalances
    /// (the fold's `w` no longer matches the sampler's Sent lift at that position).
    #[test]
    fn join2_binds_ternary_coeffs_to_fold() {
        use crate::sampler::{
            generate_ternary_trace,
            ternary_coeff_send_lookups_at,
        };
        use crate::zq::{
            Q,
            generate_horner_trace,
            horner_coeff_receive_lookups_at,
        };

        let bytes = xof_bytes(b"libq/join2/ternary", 4096);
        let n = 16usize; // power of two ⇒ fold height = n, no front padding

        let sampler = generate_ternary_trace(&bytes, n).expect("ternary trace");

        // The signed coefficients the sampler emitted (reference rejection sampling), mod-q lifted and
        // fed to the fold low-order-first (coeff of degree i = the i-th emitted coefficient).
        let mut signed: Vec<i64> = Vec::new();
        let mut i = 0usize;
        while signed.len() < n {
            let two = bytes[i] & 0b11;
            i += 1;
            if two < 3 {
                signed.push(i64::from(two) - 1);
            }
        }
        let lifts: Vec<u64> = signed
            .iter()
            .map(|&c| c.rem_euclid(Q as i64) as u64)
            .collect();

        let zeta = 123_456_789u64;
        let (fold, _e) = generate_horner_trace(&lifts, zeta).expect("horner trace");

        let send = ternary_coeff_send_lookups_at(0, 0);
        let recv = horner_coeff_receive_lookups_at(COEFF_E_BUS, 0);

        assert!(
            join2_balances(&sampler, &send, &fold, &recv),
            "honest coefficient binding must balance the coeff bus"
        );

        // Fold a *different* coefficient at degree 0: its `w` limb no longer matches the sampler's Send.
        let mut bad = lifts.clone();
        bad[0] = if lifts[0] == 1 { 0 } else { 1 };
        let (bad_fold, _) = generate_horner_trace(&bad, zeta).expect("horner trace");
        assert!(
            !join2_balances(&sampler, &send, &bad_fold, &recv),
            "a fold over a tampered coefficient must unbalance the coeff bus"
        );
    }

    /// **Join 2, bounded half.** The bounded sampler derives each coefficient's canonical mod-q lift
    /// (`lift + BOUND = R + neg·Q`) into its `W_LIFT` limbs and Sends them; the fold Receives them. The
    /// non-trivial part (vs. ternary) is the 4-limb lift derivation with the negative-branch `neg`.
    /// Honest binding balances; a fold over a different coefficient unbalances.
    #[test]
    fn join2_binds_bounded_coeffs_to_fold() {
        use crate::sampler::{
            bounded_coeff_send_lookups_at,
            generate_bounded_trace,
        };
        use crate::zq::{
            Q,
            generate_horner_trace,
            horner_coeff_receive_lookups_at,
        };

        const BND: u64 = 1 << 20;
        const SPN: u64 = 2 * BND + 1;
        const ZN: u64 = u64::MAX - (u64::MAX % SPN);

        let bytes = xof_bytes(b"libq/join2/bounded", 8 * 64 + 2048);
        let n = 8usize; // power of two ⇒ fold height = n

        let sampler = generate_bounded_trace(&bytes, n).expect("bounded trace");

        // lifts of the emitted coefficients (replicating the reference bounded sampler), low-order first.
        let mut lifts: Vec<u64> = Vec::new();
        let mut i = 0usize;
        while lifts.len() < n {
            let mut b8 = [0u8; 8];
            b8.copy_from_slice(&bytes[i..i + 8]);
            i += 8;
            let r = u64::from_le_bytes(b8);
            if r < ZN {
                let coeff = (r % SPN) as i64 - BND as i64;
                lifts.push(coeff.rem_euclid(Q as i64) as u64);
            }
        }

        let zeta = 987_654_321u64;
        let (fold, _e) = generate_horner_trace(&lifts, zeta).expect("horner trace");

        let send = bounded_coeff_send_lookups_at(COEFF_F_BUS, 0);
        let recv = horner_coeff_receive_lookups_at(COEFF_F_BUS, 0);

        assert!(
            join2_balances(&sampler, &send, &fold, &recv),
            "honest bounded coefficient binding must balance the coeff bus"
        );

        let mut bad = lifts.clone();
        bad[0] = (bad[0] + 1) % Q; // a different (still valid) coefficient at degree 0
        let (bad_fold, _) = generate_horner_trace(&bad, zeta).expect("horner trace");
        assert!(
            !join2_balances(&sampler, &send, &bad_fold, &recv),
            "a fold over a tampered bounded coefficient must unbalance the coeff bus"
        );
    }

    /// **Join 3 (design §4.1, the boundary opening).** A Horner fold computes `E = Σ cᵢ·ζⁱ (mod q)`;
    /// the relation check `Σ_j a_j·w_j + c ≡ 0 (mod q)` binds `w_0` to that `E` over [`FOLD_E_BUS`]. The
    /// fold Sends its last-row `r` (= `E`); the relation Receives it into `w_0` on its first row. Honest
    /// binding balances; a relation over a *different* `w_0` (still internally valid) unbalances — so the
    /// relation cannot be proven over a fold value other than the one the fold actually computed.
    #[test]
    fn join3_binds_fold_result_to_relation() {
        use crate::zq::{
            Q,
            RelationCheckAir,
            generate_horner_trace,
            generate_relation_trace,
            horner_e_send_lookups_at,
        };

        // A fold computing E = Σ cᵢ·ζⁱ (mod q) (height 4).
        let coeffs = [3u64, 5, 7, 11];
        let zeta = 424_242u64;
        let (fold, e) = generate_horner_trace(&coeffs, zeta).expect("horner trace");

        // A relation with one witness term w_0 = E: a_0 = 1, c = (Q − E) mod Q ⇒ 1·E + (Q−E) ≡ 0 (mod Q).
        let air = RelationCheckAir { num_terms: 1 };
        let (relation, _pubs) =
            generate_relation_trace(&[1], &[e], (Q - e) % Q).expect("relation trace");

        let send = horner_e_send_lookups_at(FOLD_E_BUS, 0, 0, 0); // term 0
        let recv = air.relation_w_receive_lookups_at(FOLD_E_BUS, 0);

        assert!(
            join2_balances(&fold, &send, &relation, &recv),
            "the fold result E must bind to the relation's w_0"
        );

        // A relation over a DIFFERENT w_0 = E+1 (still internally valid) is no longer bound to the fold.
        let e2 = (e + 1) % Q;
        let (relation2, _) =
            generate_relation_trace(&[1], &[e2], (Q - e2) % Q).expect("relation trace");
        assert!(
            !join2_balances(&fold, &send, &relation2, &recv),
            "a relation over a fold value other than E must unbalance the fold-E bus"
        );
    }

    /// The two samplers name the same bus, and the positional tuple prevents cross-matching a byte at
    /// the wrong position: shifting the source by one position (so values land at pos+1) unbalances.
    #[test]
    fn join_rejects_position_shift_ternary() {
        let bytes = xof_bytes(b"libq/join/ternary-shift", 2048);
        let num = 128usize;
        let sampler = generate_ternary_trace(&bytes, num).expect("ternary trace");
        let k = active_rows(&sampler, SAMPLER_WIDTH, 0);
        // Build the source over bytes shifted right by one: value at pos i is bytes[i-1] (pos 0 = 0),
        // so no position carries the byte the consumer expects there.
        let mut shifted = Vec::with_capacity(k);
        shifted.push(0u8);
        shifted.extend_from_slice(&bytes[..k - 1]);
        let producer = generate_xof_stream_table(&shifted);
        assert!(
            join_rejects(
                &producer,
                &xof_stream_send_lookup(),
                &sampler,
                &ternary_receive_lookup(),
            ),
            "a position-shifted source must unbalance the positional join"
        );
    }
}
