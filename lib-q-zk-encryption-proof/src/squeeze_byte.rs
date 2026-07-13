//! `SqueezeByteAir` — the sponge **Send side** of join 1 (design join 1, the byte-provenance half).
//!
//! [`crate::logup_join::XofStreamTableAir`] validated the join *mechanism* with a free-byte source.
//! This table upgrades that source to a **canonical byte decomposition of the sponge's 16-bit squeeze
//! limbs**, which is the load-bearing half: the SHAKE squeeze output is produced as 16-bit limbs (4 per
//! rate lane, 17 lanes = 68 limbs = 136 bytes per squeeze permutation), but the samplers consume
//! *bytes*. Each row of this table holds one rate limb as a low/high byte pair and:
//!   * range-checks each byte to `[0, 256)` by 8-bit decomposition — **load-bearing**: the bounded
//!     sampler does not range-check its `r` bytes locally (design §5.2), it delegates that to this join;
//!   * Sends `(bytepos, lo)` and `(bytepos + 1, hi)` on [`crate::logup_join::XOF_STREAM_BUS`] so the
//!     samplers' Receive side balances against the true squeeze bytes.
//!
//! ## Position axis
//! `bytepos` is the absolute byte position of the low byte, a monotone counter `0, 2, 4, …` (`+2` per
//! active row). Global limb index `g` (counted across all squeeze permutations) sits at `bytepos = 2g`,
//! and since `2g = perm·136 + 2·limb_in_perm`, this single counter equals `perm·136 + 2·limb_in_perm` —
//! exactly the key the sponge's future limb-Send will use (so no separate `perm`/`limb` columns are
//! needed). Byte order matches `sponge::read_output_rate` / the reference SHAKE (lane-major,
//! little-endian per lane: byte `8L+2m` = limb `m`'s low byte).
//!
//! ## Two buses, two gates (design §5.1d)
//! This table sits between the sponge and the samplers and bridges two Global LogUp buses:
//!   * **limb bus** ([`SQUEEZE_LIMB_BUS`]): it *Receives* each 16-bit limb `lo + 256·hi` from the
//!     sponge ([`crate::sponge_air::sponge_limb_send_lookups`]) at position `bytepos`, so its byte
//!     values are the sponge's genuine SHAKE output — not prover-chosen (closes byte provenance);
//!   * **byte bus** ([`XOF_STREAM_BUS`]): it *Sends* the consumed bytes to the samplers.
//!
//! Two independent gate flags decouple them. `active` marks a real squeezed limb and gates the limb
//! Receive — the table must cover the **whole** squeeze the sponge Sends (all 68 limbs/block). The
//! per-byte `send_lo`/`send_hi` flags gate the byte Sends and mark only the bytes actually
//! *consumed* downstream (a contiguous stream prefix). When the samplers consume fewer bytes than
//! the full squeeze produces, `send_* = 0 < active = 1` on the unconsumed tail: the limb is still
//! received and range-checked, but its bytes are not forwarded, so **both buses balance at once**.
//! (Conflating the two gates — the earlier single-`active` design — could not balance both buses
//! under partial consumption; see the adversarial-review Q6 finding.)
//!
//! ## Status (RED) — what this lands, what remains
//! Landed + validated by `check_lookups`: the byte decomposition + range, the positional byte Send
//! to the samplers, the positional limb Receive from the sponge (KAT vs reference SHAKE-256; tampered
//! limb/byte rejected), and the **simultaneous two-bus balance** (sponge full squeeze ⇒ this table ⇒
//! ternary sampler, under partial consumption). **Remaining:** the `prove_batch` composition that
//! *cryptographically* enforces these balances (not just the debug `check_lookups`), the global
//! byte-offset shifts for multiple samplers drawn from one XOF, and the verifier-side obligation that
//! the sponge instance is built with the true committed `height` (a `height = 0` sponge silently
//! disables the limb Send).

#[cfg(not(feature = "std"))]
use alloc::{
    vec,
    vec::Vec,
};

use lib_q_plonky_lookup::{
    Direction,
    Kind,
    Lookup,
    LookupAir,
};
use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_field::PrimeCharacteristicRing;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_zkp::stark::ConfigVal;

use crate::logup_join::{
    SQUEEZE_LIMB_BUS,
    XOF_STREAM_BUS,
    fc,
    mcol,
    sconst,
};

// Column layout.
//
// Two independent gate flags decouple the two buses (design §5.1d, closing the adversarial-review
// Q6 gap): `active` marks a real squeezed limb and gates the **limb-Receive** (the row must cover
// the *whole* squeeze the sponge Sends), while `send_lo`/`send_hi` mark which bytes are actually
// *consumed* downstream and gate the **byte-Send** to the samplers. When the samplers consume fewer
// bytes than the full squeeze, `send_* < active` on the unconsumed tail: the limb is still received
// (and range-checked) but its bytes are not forwarded, so both buses balance.
const S_ACTIVE: usize = 0; // 1 = real squeezed limb row (full-squeeze coverage), 0 = padding
const S_BYTEPOS: usize = 1; // absolute position of the low byte (even; +2 per active row)
const S_LO: usize = 2; // low byte of the limb
const S_HI: usize = 3; // high byte of the limb
const S_SEND_HI: usize = 4; // 1 = the hi byte is consumed downstream (Send it on the byte bus)
const S_LO_BITS: usize = 5; // low byte's 8 bits: columns 5..13
const S_HI_BITS: usize = 13; // high byte's 8 bits: columns 13..21
const S_SEND_LO: usize = 21; // 1 = the lo byte is consumed downstream (Send it on the byte bus)

/// Trace width of [`SqueezeByteAir`].
pub const SQUEEZE_BYTE_WIDTH: usize = 22;

/// The squeeze byte-decomposition table AIR (design join 1, sponge Send side). One row per 16-bit rate
/// limb: decomposes it into two range-checked bytes and Sends them positionally on
/// [`XOF_STREAM_BUS`]. See the module docs for the position axis and odd-tail handling.
#[derive(Debug, Clone, Copy, Default)]
pub struct SqueezeByteAir;

impl<F> BaseAir<F> for SqueezeByteAir {
    fn width(&self) -> usize {
        SQUEEZE_BYTE_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for SqueezeByteAir {
    fn eval(&self, builder: &mut AB) {
        #[allow(clippy::type_complexity)]
        let (
            active,
            bytepos,
            lo,
            hi,
            send_lo,
            send_hi,
            lo_bits,
            hi_bits,
            n_active,
            n_bytepos,
            n_send_lo,
            n_send_hi,
        ): (
            AB::Expr,
            AB::Expr,
            AB::Expr,
            AB::Expr,
            AB::Expr,
            AB::Expr,
            [AB::Expr; 8],
            [AB::Expr; 8],
            AB::Expr,
            AB::Expr,
            AB::Expr,
            AB::Expr,
        ) = {
            let main = builder.main();
            let local = main.current_slice();
            let next = main.next_slice();
            (
                local[S_ACTIVE].into(),
                local[S_BYTEPOS].into(),
                local[S_LO].into(),
                local[S_HI].into(),
                local[S_SEND_LO].into(),
                local[S_SEND_HI].into(),
                core::array::from_fn(|i| local[S_LO_BITS + i].into()),
                core::array::from_fn(|i| local[S_HI_BITS + i].into()),
                next[S_ACTIVE].into(),
                next[S_BYTEPOS].into(),
                next[S_SEND_LO].into(),
                next[S_SEND_HI].into(),
            )
        };

        // Booleans.
        builder.assert_bool(active.clone());
        builder.assert_bool(send_lo.clone());
        builder.assert_bool(send_hi.clone());
        for b in lo_bits.iter().chain(hi_bits.iter()) {
            builder.assert_bool(b.clone());
        }
        // Consumption structure (the byte-Send gates):
        //   • a byte can only be sent from a real squeezed limb:  send_lo ≤ active;
        //   • the hi byte of a limb is consumed only if its lo byte was:  send_hi ≤ send_lo
        //     (bytes are consumed in stream order, lo before hi of the same limb).
        builder.assert_zero(send_lo.clone() * (AB::Expr::ONE - active.clone()));
        builder.assert_zero(send_hi.clone() * (AB::Expr::ONE - send_lo.clone()));

        // Byte range + value: lo = Σ lo_bit_i·2^i, hi likewise (each ∈ [0,256)); MSB-first Horner.
        let lo_horner = (0..8)
            .rev()
            .fold(AB::Expr::ZERO, |acc, i| acc.double() + lo_bits[i].clone());
        let hi_horner = (0..8)
            .rev()
            .fold(AB::Expr::ZERO, |acc, i| acc.double() + hi_bits[i].clone());
        builder.assert_zero(lo.clone() - lo_horner);
        builder.assert_zero(hi.clone() - hi_horner);

        // Position axis: starts at 0, advances by 2 per active row (padding freezes it).
        builder.when_first_row().assert_zero(bytepos.clone());
        builder
            .when_transition()
            .assert_zero(n_active * (AB::Expr::ONE - active.clone()));
        builder
            .when_transition()
            .assert_zero(n_bytepos - bytepos - active.double());
        // Consumed bytes form a contiguous prefix of the stream: the send gates are non-increasing
        // (once forwarding stops it never resumes). This pins `send_lo`/`send_hi` to a prefix pattern
        // structurally (the byte-bus balance also forces it, but the constraint catches it locally).
        builder
            .when_transition()
            .assert_zero(n_send_lo * (AB::Expr::ONE - send_lo.clone()));
        builder
            .when_transition()
            .assert_zero(n_send_hi * (AB::Expr::ONE - send_hi.clone()));
    }
}

impl LookupAir<ConfigVal> for SqueezeByteAir {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        Vec::from([0])
    }

    fn get_lookups(&mut self) -> Vec<Lookup<ConfigVal>> {
        Vec::from([squeeze_byte_send_lookup()])
    }
}

/// The two `(pos, byte)` **Send** tuples [`SqueezeByteAir`] contributes per row on [`XOF_STREAM_BUS`]:
/// `(bytepos, lo)` gated by `send_lo`, and `(bytepos + 1, hi)` gated by `send_hi`. Only *consumed*
/// bytes are forwarded (unconsumed tail bytes of a fully-covered squeeze are received on the limb
/// bus but not sent here), so this bus balances the samplers even when they consume fewer bytes than
/// the full squeeze.
pub fn squeeze_byte_send_lookup() -> Lookup<ConfigVal> {
    let bytepos = mcol(S_BYTEPOS);
    Lookup::new(
        Kind::Global(XOF_STREAM_BUS.into()),
        Vec::from([
            Vec::from([bytepos.clone(), mcol(S_LO)]),
            Vec::from([bytepos + sconst(1), mcol(S_HI)]),
        ]),
        Vec::from([
            Direction::Send.multiplicity(mcol(S_SEND_LO)),
            Direction::Send.multiplicity(mcol(S_SEND_HI)),
        ]),
        Vec::from([0]),
    )
}

/// The **Receive** lookup that closes byte provenance (limb half of design join 1): binds each
/// squeeze-byte row's reconstructed 16-bit limb `lo + 256·hi` to the sponge's true squeezed output
/// at the same byte position, on [`SQUEEZE_LIMB_BUS`]. Receives `(bytepos, lo + 256·hi)` gated by
/// `active`. Balances against [`crate::sponge_air::sponge_limb_send_lookups`] iff every row's byte
/// pair equals the sponge's `a‴` limb at that position — so `lo`/`hi` are no longer prover-chosen.
///
/// Uses aux column **1** (running sum), leaving column 0 for [`squeeze_byte_send_lookup`], so a
/// `SqueezeByteAir` instance can carry both lookups at once without an aux-column collision.
pub fn squeeze_byte_limb_receive_lookup() -> Lookup<ConfigVal> {
    let limb_value = mcol(S_LO) + sconst(256) * mcol(S_HI);
    Lookup::new(
        Kind::Global(SQUEEZE_LIMB_BUS.into()),
        Vec::from([Vec::from([mcol(S_BYTEPOS), limb_value])]),
        Vec::from([Direction::Receive.multiplicity(mcol(S_ACTIVE))]),
        Vec::from([1]),
    )
}

/// Build a [`SqueezeByteAir`] trace for the SHAKE-256 XOF of `input`, covering the first `num_bytes`
/// output bytes (the count the samplers consume). One row per 16-bit limb (`⌈num_bytes/2⌉` real rows),
/// padded to a power-of-two height. Byte values are the reference SHAKE-256 stream (what the KEM's
/// `xof_*` draws consume); the `has_hi` flag is cleared on an odd-length tail so the table Sends
/// exactly `num_bytes` bytes.
pub fn generate_squeeze_byte_trace(input: &[u8], num_bytes: usize) -> RowMajorMatrix<ConfigVal> {
    generate_squeeze_byte_trace_partial(input, num_bytes.div_ceil(2), num_bytes)
}

/// Build a [`SqueezeByteAir`] trace covering `total_limbs` squeezed 16-bit limbs — the **full**
/// squeeze the sponge Sends on the limb bus — while forwarding only the first `consumed_bytes` bytes
/// on the byte bus. All `total_limbs` rows are `active` (received on the limb bus and range-checked);
/// `send_lo`/`send_hi` are set exactly for byte positions `< consumed_bytes` (the contiguous prefix
/// the samplers consume). This is the general shape that balances *both* buses when the samplers
/// consume fewer bytes than a whole number of squeeze blocks produce (design §5.1d).
/// Requires `consumed_bytes ≤ 2·total_limbs`.
pub fn generate_squeeze_byte_trace_partial(
    input: &[u8],
    total_limbs: usize,
    consumed_bytes: usize,
) -> RowMajorMatrix<ConfigVal> {
    debug_assert!(
        consumed_bytes <= 2 * total_limbs,
        "consumed bytes exceed squeeze coverage"
    );
    let byte_span = total_limbs * 2;
    let bytes = shake256_xof(input, byte_span);

    let height = total_limbs.next_power_of_two().max(2);
    let mut values = vec![ConfigVal::ZERO; height * SQUEEZE_BYTE_WIDTH];

    for i in 0..total_limbs {
        let base = i * SQUEEZE_BYTE_WIDTH;
        let lo = bytes[2 * i];
        let hi = bytes[2 * i + 1];
        values[base + S_ACTIVE] = ConfigVal::ONE;
        values[base + S_BYTEPOS] = fc(2 * i as u64);
        values[base + S_LO] = fc(u64::from(lo));
        values[base + S_HI] = fc(u64::from(hi));
        values[base + S_SEND_LO] = if 2 * i < consumed_bytes {
            ConfigVal::ONE
        } else {
            ConfigVal::ZERO
        };
        values[base + S_SEND_HI] = if 2 * i + 1 < consumed_bytes {
            ConfigVal::ONE
        } else {
            ConfigVal::ZERO
        };
        for j in 0..8 {
            values[base + S_LO_BITS + j] = bit(u64::from(lo) >> j & 1);
            values[base + S_HI_BITS + j] = bit(u64::from(hi) >> j & 1);
        }
    }
    // Padding rows: position frozen at 2·total_limbs (n_bytepos = bytepos + 2·active with active = 0).
    for i in total_limbs..height {
        values[i * SQUEEZE_BYTE_WIDTH + S_BYTEPOS] = fc(2 * total_limbs as u64);
    }
    RowMajorMatrix::new(values, SQUEEZE_BYTE_WIDTH)
}

/// Reference SHAKE-256 XOF of `input` (`n` bytes) — the ground-truth squeeze stream.
fn shake256_xof(input: &[u8], n: usize) -> Vec<u8> {
    use lib_q_sha3::{
        ExtendableOutput,
        Update,
        XofReader,
    };
    let mut h = lib_q_sha3::Shake256::default();
    h.update(input);
    let mut rd = h.finalize_xof();
    let mut out = vec![0u8; n];
    rd.read(&mut out);
    out
}

/// A single bit (`0`/`1`) as a field element.
fn bit(b: u64) -> ConfigVal {
    if b == 1 {
        ConfigVal::ONE
    } else {
        ConfigVal::ZERO
    }
}

#[cfg(test)]
mod tests {
    use lib_q_plonky_lookup::debug_util::{
        LookupDebugInstance,
        check_lookups,
    };
    use lib_q_stark::check_constraints;

    use super::*;
    use crate::sampler::{
        BOUNDED_WIDTH,
        SAMPLER_WIDTH,
        bounded_receive_lookup,
        generate_bounded_trace,
        generate_ternary_trace,
        ternary_receive_lookup,
    };

    fn active_rows(trace: &RowMajorMatrix<ConfigVal>, width: usize, active_col: usize) -> usize {
        (0..trace.values.len() / width)
            .filter(|&r| trace.values[r * width + active_col] == ConfigVal::ONE)
            .count()
    }

    /// Reconstruct the byte stream the table Sends (lo, then hi if `has_hi`) and compare to reference
    /// SHAKE-256 — the KAT that the limb→byte decomposition and ordering are correct.
    #[test]
    fn squeeze_byte_trace_matches_reference_shake() {
        let input = b"libq/squeeze-byte/kat";
        let num_bytes = 273usize; // odd, spans >2 rate blocks, exercises the tail
        let trace = generate_squeeze_byte_trace(input, num_bytes);

        // Reconstruct the bytes actually forwarded on the byte bus (gated by the send flags).
        let mut got = Vec::new();
        let h = trace.values.len() / SQUEEZE_BYTE_WIDTH;
        for r in 0..h {
            let base = r * SQUEEZE_BYTE_WIDTH;
            if trace.values[base + S_SEND_LO] == ConfigVal::ONE {
                got.push(byte_of(&trace, base + S_LO));
            }
            if trace.values[base + S_SEND_HI] == ConfigVal::ONE {
                got.push(byte_of(&trace, base + S_HI));
            }
        }
        let want = shake256_xof(input, num_bytes);
        assert_eq!(got, want, "forwarded bytes must equal reference SHAKE-256");
    }

    /// The AIR's own constraints (byte range, value, position counter) are satisfied by an honest trace.
    #[test]
    fn squeeze_byte_air_accepts_honest_trace() {
        let trace = generate_squeeze_byte_trace(b"libq/squeeze-byte/air", 256);
        check_constraints(&SqueezeByteAir, &trace, &[]);
    }

    /// The squeeze byte table balances the ternary sampler's Receive side (byte provenance for `e`).
    #[test]
    fn squeeze_byte_source_binds_ternary_sampler() {
        let seed = b"libq/squeeze-byte/ternary";
        let bytes = shake256_xof(seed, 4096);
        let num = 1024usize;
        let sampler = generate_ternary_trace(&bytes, num).expect("ternary trace");
        let consumed = active_rows(&sampler, SAMPLER_WIDTH, 0); // 1 byte per active row
        let source = generate_squeeze_byte_trace(seed, consumed);
        assert!(
            !join_rejects(&source, &sampler, &[ternary_receive_lookup()]),
            "the squeeze byte source must balance the ternary sampler"
        );
    }

    /// The squeeze byte table balances the bounded sampler's Receive side (byte provenance for `f`/`g`).
    #[test]
    fn squeeze_byte_source_binds_bounded_sampler() {
        let seed = b"libq/squeeze-byte/bounded";
        let num = 128usize;
        let bytes = shake256_xof(seed, num * 8 + 1024);
        let sampler = generate_bounded_trace(&bytes, num).expect("bounded trace");
        let consumed = active_rows(&sampler, BOUNDED_WIDTH, 0) * 8; // 8 bytes per active row
        let source = generate_squeeze_byte_trace(seed, consumed);
        assert!(
            !join_rejects(&source, &sampler, &bounded_receive_lookup()),
            "the squeeze byte source must balance the bounded sampler"
        );
    }

    /// A tampered source byte (with its bits re-coded so the AIR range check still passes) unbalances
    /// the join — the value no longer matches what the sampler consumed at that position.
    #[test]
    fn squeeze_byte_tampered_byte_rejected() {
        let seed = b"libq/squeeze-byte/tamper";
        let bytes = shake256_xof(seed, 2048);
        let num = 128usize;
        let sampler = generate_ternary_trace(&bytes, num).expect("ternary trace");
        let consumed = active_rows(&sampler, SAMPLER_WIDTH, 0);
        let mut source = generate_squeeze_byte_trace(seed, consumed);
        // Flip bit 0 of the low byte on row 0 and its S_LO column to keep the AIR range check happy,
        // so only the JOIN (positional value match) fails, not the AIR.
        let base = S_LO_BITS;
        let cur = source.values[base];
        source.values[base] = if cur == ConfigVal::ONE {
            ConfigVal::ZERO
        } else {
            ConfigVal::ONE
        };
        source.values[S_LO] += if cur == ConfigVal::ONE {
            ConfigVal::ZERO - ConfigVal::ONE
        } else {
            ConfigVal::ONE
        };
        // The AIR still accepts (canonical decomposition preserved)…
        check_constraints(&SqueezeByteAir, &source, &[]);
        // …but the join no longer balances (byte at pos 0 changed).
        assert!(
            join_rejects(&source, &sampler, &[ternary_receive_lookup()]),
            "a tampered source byte must unbalance the join"
        );
    }

    /// **Byte provenance closed (limb bus).** The sponge's 68-per-block limb Sends — positioned by
    /// the preprocessed squeeze-offset column — balance the squeeze-byte table's limb Receives. The
    /// table's reconstructed `lo + 256·hi` for each row must equal the sponge's true `a‴` limb at
    /// that byte position, so the byte values are bound to the genuine SHAKE-256 output rather than
    /// chosen by the prover. A tampered squeeze limb unbalances the join.
    #[test]
    fn sponge_limb_send_binds_squeeze_byte_table() {
        use lib_q_plonky_keccak_air::{
            NUM_KECCAK_COLS,
            NUM_ROUNDS,
        };
        use lib_q_stark_air::BaseAir;

        use crate::sponge::RATE_BYTES;
        use crate::sponge_air::{
            ShakeSpongeAir,
            encap_preimage,
            generate_provable_sponge_trace,
        };

        let pk = [0xA1u8; 32];
        let mu = [0x33u8; 32];
        let input = encap_preimage(&pk, &mu);
        let sponge = generate_provable_sponge_trace(&input, 200);
        let height = sponge.values.len() / NUM_KECCAK_COLS;
        let air = ShakeSpongeAir { height };
        let pre = BaseAir::<ConfigVal>::preprocessed_trace(&air);
        assert!(
            pre.is_some(),
            "sponge must expose the preprocessed position column"
        );

        // The sponge Sends limbs on every final-step row (one squeeze block each).
        let blocks = (0..height)
            .filter(|r| r % NUM_ROUNDS == NUM_ROUNDS - 1)
            .count();
        let num_bytes = blocks * RATE_BYTES;
        let squeeze = generate_squeeze_byte_trace(&input, num_bytes);

        assert!(
            !limb_join_rejects(&sponge, &pre, &squeeze),
            "sponge limb-Sends must balance the squeeze-byte limb-Receives"
        );

        // Negative: corrupt one received limb value (row 0's low byte) — the limb bus must unbalance.
        let mut bad = generate_squeeze_byte_trace(&input, num_bytes);
        bad.values[S_LO] += ConfigVal::ONE;
        assert!(
            limb_join_rejects(&sponge, &pre, &bad),
            "a tampered squeeze limb must unbalance the sponge join"
        );
    }

    /// `check_lookups` over the limb bus: sponge (Send, with its preprocessed position column) +
    /// squeeze-byte table (Receive). Returns whether it rejected (unbalanced).
    fn limb_join_rejects(
        sponge: &RowMajorMatrix<ConfigVal>,
        sponge_pre: &Option<RowMajorMatrix<ConfigVal>>,
        squeeze: &RowMajorMatrix<ConfigVal>,
    ) -> bool {
        let none: Option<RowMajorMatrix<ConfigVal>> = None;
        let sends = crate::sponge_air::sponge_limb_send_lookups();
        let recv = [squeeze_byte_limb_receive_lookup()];
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let s = LookupDebugInstance {
                main_trace: sponge,
                preprocessed_trace: sponge_pre,
                public_values: &[],
                lookups: &sends,
                permutation_challenges: &[],
            };
            let c = LookupDebugInstance {
                main_trace: squeeze,
                preprocessed_trace: &none,
                public_values: &[],
                lookups: &recv,
                permutation_challenges: &[],
            };
            check_lookups(&[s, c]);
        }));
        std::panic::set_hook(prev);
        r.is_err()
    }

    /// **Both buses balance simultaneously under partial consumption (design §5.1d, Q6 closure).**
    /// The sponge Sends its *full* squeeze on the limb bus; the squeeze-byte table Receives all of it
    /// (full coverage) yet Sends only the byte prefix a ternary sampler actually consumes; the
    /// sampler Receives that prefix. All three instances on two shared buses net to zero at once —
    /// the case that the single-`active`-gate design could not handle.
    #[test]
    fn two_bus_balance_full_squeeze_partial_consumption() {
        use lib_q_plonky_keccak_air::{
            NUM_KECCAK_COLS,
            NUM_ROUNDS,
        };
        use lib_q_stark_air::BaseAir;

        use crate::sampler::{
            SAMPLER_WIDTH,
            generate_ternary_trace,
            ternary_receive_lookup,
        };
        use crate::sponge::RATE_BYTES;
        use crate::sponge_air::{
            ShakeSpongeAir,
            encap_preimage,
            generate_provable_sponge_trace,
            sponge_limb_send_lookups,
        };

        let pk = [0x2Cu8; 32];
        let mu = [0x71u8; 32];
        let input = encap_preimage(&pk, &mu);

        // A ternary sampler consuming a byte prefix of SHAKE-256(input).
        let bytes = shake256_xof(&input, 8192);
        let ternary = generate_ternary_trace(&bytes, 256).expect("ternary trace");
        let consumed = (0..ternary.values.len() / SAMPLER_WIDTH)
            .filter(|&r| ternary.values[r * SAMPLER_WIDTH] == ConfigVal::ONE) // C_ACTIVE = 0
            .count();

        // Sponge squeezing at least `consumed` bytes; cover the FULL squeeze it produces.
        let sponge = generate_provable_sponge_trace(&input, consumed + RATE_BYTES);
        let height = sponge.values.len() / NUM_KECCAK_COLS;
        let sponge_air = ShakeSpongeAir { height };
        let pre = BaseAir::<ConfigVal>::preprocessed_trace(&sponge_air);
        let blocks = (0..height)
            .filter(|r| r % NUM_ROUNDS == NUM_ROUNDS - 1)
            .count();
        let full_limbs = blocks * (RATE_BYTES / 2); // 68 rate limbs per squeeze block
        assert!(
            full_limbs * 2 >= consumed,
            "coverage must include the consumed prefix"
        );

        let squeeze = generate_squeeze_byte_trace_partial(&input, full_limbs, consumed);

        let none: Option<RowMajorMatrix<ConfigVal>> = None;
        let sends = sponge_limb_send_lookups();
        let sq_lookups = [
            squeeze_byte_limb_receive_lookup(),
            squeeze_byte_send_lookup(),
        ];
        let tern_lookups = [ternary_receive_lookup()];
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_lookups(&[
                LookupDebugInstance {
                    main_trace: &sponge,
                    preprocessed_trace: &pre,
                    public_values: &[],
                    lookups: &sends,
                    permutation_challenges: &[],
                },
                LookupDebugInstance {
                    main_trace: &squeeze,
                    preprocessed_trace: &none,
                    public_values: &[],
                    lookups: &sq_lookups,
                    permutation_challenges: &[],
                },
                LookupDebugInstance {
                    main_trace: &ternary,
                    preprocessed_trace: &none,
                    public_values: &[],
                    lookups: &tern_lookups,
                    permutation_challenges: &[],
                },
            ]);
        }));
        std::panic::set_hook(prev);
        assert!(
            r.is_ok(),
            "limb bus + byte bus must both balance under full-squeeze coverage + partial consumption"
        );
    }

    fn byte_of(trace: &RowMajorMatrix<ConfigVal>, idx: usize) -> u8 {
        // Recover a small integer from the real part via equality search over [0,256).
        for b in 0u16..256 {
            if trace.values[idx] == fc(u64::from(b)) {
                return b as u8;
            }
        }
        panic!("cell {idx} is not a byte value");
    }

    /// Run `check_lookups` on the (source Send, sampler Receive) pair; return whether it rejected.
    fn join_rejects(
        source: &RowMajorMatrix<ConfigVal>,
        sampler: &RowMajorMatrix<ConfigVal>,
        sampler_lookup: &[Lookup<ConfigVal>],
    ) -> bool {
        let none: Option<RowMajorMatrix<ConfigVal>> = None;
        let send = [squeeze_byte_send_lookup()];
        let recv = sampler_lookup;
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let s = LookupDebugInstance {
                main_trace: source,
                preprocessed_trace: &none,
                public_values: &[],
                lookups: &send,
                permutation_challenges: &[],
            };
            let c = LookupDebugInstance {
                main_trace: sampler,
                preprocessed_trace: &none,
                public_values: &[],
                lookups: recv,
                permutation_challenges: &[],
            };
            check_lookups(&[s, c]);
        }));
        std::panic::set_hook(prev);
        r.is_err()
    }
}
