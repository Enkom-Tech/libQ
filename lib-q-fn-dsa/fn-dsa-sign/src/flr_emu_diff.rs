//! Differential test: emulated float backend vs. native float backend.
//!
//! `flr.rs` picks the floating-point backend by `target_arch` only:
//! `flr_native.rs` on x86_64/aarch64/arm64ec/riscv64, `flr_emu.rs`
//! (software binary64) on everything else -- wasm32, armv7, 32-bit x86.
//! That means the emulated backend, which is what ships to wasm and to
//! 32-bit ARM, is never compiled on an ordinary x86_64 CI runner, and no
//! Cargo feature can bring it in (`no_avx2` selects the portable *vector*
//! path, not the float backend).
//!
//! This module closes that hole without touching production dispatch:
//! `flr.rs` compiles `flr_emu.rs` a second time under `#[cfg(test)]` as
//! `emu_ref`, and the tests below check that, for identical inputs, the
//! emulated backend produces bit-identical results to the native one for
//! every operation on the `Flr` surface. `Flr` values are compared through
//! `encode()`, i.e. as raw IEEE-754 binary64 bit patterns, so `+0.0` and
//! `-0.0` are distinguished.
//!
//! Scope limits, stated so nobody over-reads a green run:
//!   * Compiled here on a native-backend host, `flr_emu.rs` selects the
//!     *native* variants of its own four arch-gated helpers (`lzcnt_nz`,
//!     `ursh`, `ulsh`, `irsh`). The generic fallbacks that wasm32/armv7
//!     actually use are exercised by running this crate's suite on
//!     wasm32-wasip1 (the `fn-dsa-emulated-float` CI job), not here.
//!   * Inputs stay inside the domain the `Flr` abstraction defines: no
//!     denormals, infinites or NaNs, and each operation's documented
//!     precondition is respected. Divergence outside that domain would not
//!     be a defect.
//!   * Functional equality only. Nothing here measures constant-timeness.
//!
//! No Cargo feature changes which backend is *selected* -- but two of them,
//! `div_emu` and `sqrt_emu`, change how the native one *behaves*: they
//! replace flr_native's hardware divide/square-root with integer routines
//! ported from flr_emu.rs itself. So "the native backend" is not a single
//! fixed answer here, and any pinned native value has to name the features
//! it holds under. The tests below therefore run under every feature
//! combination, with the two feature-sensitive expectations selected by
//! `cfg`; do not add an unconditional assertion about `Nat::sqrt` or
//! `Nat::set_div` without checking it under `--all-features` too.
//!
//! The two backends are *not* equal everywhere: four operations disagree
//! when handed a negative zero (two of the four only in the default build --
//! `div_emu`/`sqrt_emu` make the native side agree). Those are pinned, with
//! their exact current results on both sides and their provenance, in
//! `flr_emu_negative_zero_divergences_are_pinned` below -- read that test
//! before concluding "the backends agree".
//!
//! All randomness is SHAKE256-derived from hardcoded seeds, so a failure
//! reproduces exactly.

#![allow(clippy::unwrap_used)]

use super::Flr as Nat;
use super::emu_ref::Flr as Emu;
use crate::tests::SHAKE256x4;

// `flr_emu.rs`'s `square()` is written as `self * self`, i.e. it depends on
// a `Mul` impl that lives in flr.rs and is declared for the *production*
// backend type only. The test-only second copy of the backend therefore
// needs its own, and this body must stay character-identical to the one
// flr.rs gives the production type -- otherwise `square()` would be
// measuring something the shipped build does not do.
impl core::ops::Mul<Emu> for Emu {
    type Output = Emu;

    #[inline(always)]
    fn mul(self, other: Emu) -> Emu {
        let mut r = self;
        r.set_mul(other);
        r
    }
}

// Fixed seeds: never seed from the clock or from system entropy, a failing
// input must be reproducible from the test name alone.
const SEED_RANDOM_OPS: &[u8] = b"lib-q/flr_emu_diff/random-ops/v1";
const SEED_EXPM: &[u8] = b"lib-q/flr_emu_diff/expm_p63/v1";

// Encoded-exponent band used for randomized operands.
//
// FN-DSA is proven to keep every non-zero intermediate value in
// [2^-476, 2^27*(2^52 + 605182448294568)] (eprint 2024/321, quoted in
// flr.rs), i.e. an encoded exponent in [547, 1102]. Staying inside that
// band means every operation below is closed over normal binary64 values:
// the widest excursion is a product, whose encoded exponent lands in
// [71, 1181] -- no overflow to infinity, no underflow to denormals, both of
// which are outside what `Flr` promises to support.
const EMIN: u64 = 547;
const ESPAN: u64 = 1102 - 547 + 1;

fn bits_emu(x: Emu) -> u64 {
    u64::from_le_bytes(x.encode())
}

fn bits_nat(x: Nat) -> u64 {
    u64::from_le_bytes(x.encode())
}

#[track_caller]
fn same(op: &str, e: Emu, n: Nat) {
    let (x, y) = (bits_emu(e), bits_nat(n));
    assert!(
        x == y,
        "flr_emu != flr_native in {op}: emu=0x{x:016X} native=0x{y:016X}"
    );
}

#[track_caller]
fn same_i64(op: &str, x: i64, y: i64) {
    assert!(x == y, "flr_emu != flr_native in {op}: emu={x} native={y}");
}

#[track_caller]
fn same_u64(op: &str, x: u64, y: u64) {
    assert!(
        x == y,
        "flr_emu != flr_native in {op}: emu=0x{x:016X} native=0x{y:016X}"
    );
}

// Decode the same 64-bit pattern into both backends. `decode()` is itself
// part of the compared surface, so the pair is checked before being used.
#[track_caller]
fn decode_both(bits: u64) -> (Emu, Nat) {
    let b = bits.to_le_bytes();
    let e = Emu::decode(&b).unwrap();
    let n = Nat::decode(&b).unwrap();
    same("decode", e, n);
    // encode() must round-trip the pattern it was given.
    assert!(bits_emu(e) == bits, "emu encode/decode round-trip");
    (e, n)
}

// A random binary64 bit pattern with a random sign, a random 52-bit
// mantissa and an encoded exponent drawn from [EMIN, EMIN + ESPAN - 1].
fn rand_bits(rng: &mut SHAKE256x4) -> u64 {
    let m = rng.next_u64();
    let e = ((m >> 52) & 0x7FF) % ESPAN + EMIN;
    (m & 0x800F_FFFF_FFFF_FFFF) | (e << 52)
}

// Every unary operation of the `Flr` surface, on one operand.
#[track_caller]
fn diff_unary(e: Emu, n: Nat) {
    same("encode", e, n);

    let mut ee = e;
    let mut nn = n;
    ee.set_neg();
    nn.set_neg();
    same("set_neg", ee, nn);

    // abs() and sqrt() agree on every operand except a negative zero; see
    // `flr_emu_negative_zero_divergences_are_pinned`. Callers here never
    // pass one.
    same("abs", e.abs(), n.abs());
    same("half", e.half(), n.half());
    same("double", e.double(), n.double());
    same("mul2p63", e.mul2p63(), n.mul2p63());
    same("square", e.square(), n.square());
    // sqrt() is only defined for a non-negative operand.
    same("sqrt", e.abs().sqrt(), n.abs().sqrt());
}

// Every binary operation of the `Flr` surface, on one operand pair.
#[track_caller]
fn diff_binary(ea: Emu, na: Nat, eb: Emu, nb: Nat) {
    let (mut e, mut n) = (ea, na);
    e.set_add(eb);
    n.set_add(nb);
    same("set_add", e, n);

    let (mut e, mut n) = (ea, na);
    e.set_sub(eb);
    n.set_sub(nb);
    same("set_sub", e, n);

    let (mut e, mut n) = (ea, na);
    e.set_mul(eb);
    n.set_mul(nb);
    same("set_mul", e, n);

    // set_div() assumes a non-zero divisor; callers below guarantee it.
    let (mut e, mut n) = (ea, na);
    e.set_div(eb);
    n.set_div(nb);
    same("set_div", e, n);

    // slice_div2e() is documented for e in [1, 9] and is the one operation
    // whose two implementations are structurally different (exponent
    // subtraction vs. multiplication by a table constant).
    for k in 1..=9u32 {
        let mut fe = [ea, eb, Emu::ZERO, Emu::NZERO, Emu::ONE];
        let mut fnat = [na, nb, Nat::ZERO, Nat::NZERO, Nat::ONE];
        Emu::slice_div2e(&mut fe, k);
        Nat::slice_div2e(&mut fnat, k);
        for i in 0..fe.len() {
            same("slice_div2e", fe[i], fnat[i]);
        }
    }
}

/// The named constants and the integer-conversion entry points.
#[test]
fn flr_emu_matches_native_constants_and_conversions() {
    same("ZERO", Emu::ZERO, Nat::ZERO);
    same("NZERO", Emu::NZERO, Nat::NZERO);
    same("ONE", Emu::ONE, Nat::ONE);

    // from_i32() is exact over the whole i32 range.
    for j in [
        0i32,
        1,
        -1,
        2,
        -2,
        1023,
        -1023,
        0x00FF_FFFF,
        -0x00FF_FFFF,
        0x7FFF_FFFF,
        -0x7FFF_FFFF,
        i32::MIN,
    ] {
        same("from_i32", Emu::from_i32(j), Nat::from_i32(j));
    }

    // from_i64()/scaled() forbid j = -2^63. Values around 2^53 are where
    // integer->binary64 conversion stops being exact, hence the sweep there.
    // scaled() is defined for the full [-128, 127] range of `sc` (that is
    // the size of flr_native's INV_POW2 table), so both ends are hit.
    let check = |j: i64| {
        same("from_i64", Emu::from_i64(j), Nat::from_i64(j));
        for sc in [-128i32, -127, -64, -53, -52, -8, -1, 0, 1, 52, 63, 126, 127] {
            same("scaled", Emu::scaled(j, sc), Nat::scaled(j, sc));
        }
    };
    check(0);
    check(i64::MAX);
    check(-i64::MAX);
    for k in 0..63 {
        check(1i64 << k);
        check(-(1i64 << k));
    }
    for d in -5..=5i64 {
        check((1i64 << 53) + d);
        check(-((1i64 << 53) + d));
        check((1i64 << 54) + d);
        check(-((1i64 << 54) + d));
        check((1i64 << 62) + d);
    }
}

/// Rounding to integers: `rint` (ties to even), `floor`, `trunc`.
///
/// These three take the only genuinely divergent implementation route in
/// the whole surface: `flr_native` uses an SSE2/NEON/RISC-V opcode, while
/// `flr_emu` does it with shifts and a hand-rolled sticky/guard rounding.
#[test]
fn flr_emu_matches_native_rounding_to_integer() {
    // Fixed patterns first: exact halves, values just below/above a half,
    // and both signed zeros. `scaled(j, -1)` is exactly j/2.
    for j in -600i64..=600 {
        let (e, n) = (Emu::scaled(j, -1), Nat::scaled(j, -1));
        same("scaled", e, n);
        same_i64("rint(half-integers)", e.rint(), n.rint());
        same_i64("floor(half-integers)", e.floor(), n.floor());
        same_i64("trunc(half-integers)", e.trunc(), n.trunc());
    }
    for j in -300i64..=300 {
        // Quarters: exercises the sticky bit (xxx != 0) branch of rint().
        let (e, n) = (Emu::scaled(j, -2), Nat::scaled(j, -2));
        same_i64("rint(quarters)", e.rint(), n.rint());
        same_i64("floor(quarters)", e.floor(), n.floor());
        same_i64("trunc(quarters)", e.trunc(), n.trunc());
    }
    same_i64("rint(+0)", Emu::ZERO.rint(), Nat::ZERO.rint());
    same_i64("rint(-0)", Emu::NZERO.rint(), Nat::NZERO.rint());
    same_i64("trunc(+0)", Emu::ZERO.trunc(), Nat::ZERO.trunc());
    same_i64("trunc(-0)", Emu::NZERO.trunc(), Nat::NZERO.trunc());
    same_i64("floor(+0)", Emu::ZERO.floor(), Nat::ZERO.floor());
    // floor(-0.0) is the one input on which the two backends disagree; it
    // is pinned in `flr_emu_negative_zero_divergences_are_pinned`.

    // Randomized, over the domain the three functions document: the value
    // must fit in [-(2^63-1), +(2^63-1)].
    let mut rng = SHAKE256x4::new(b"lib-q/flr_emu_diff/rounding/v1");
    for _ in 0..16384 {
        let j = rng.next_u64() as i64;
        if j == i64::MIN {
            continue;
        }
        for sc in [-1i32, -2, -3, -8, -20, -52, -60, -63] {
            let (e, n) = (Emu::scaled(j, sc), Nat::scaled(j, sc));
            same("scaled", e, n);
            same_i64("rint", e.rint(), n.rint());
            same_i64("floor", e.floor(), n.floor());
            same_i64("trunc", e.trunc(), n.trunc());
        }
    }
}

/// The upstream edge sweep, in differential form.
///
/// `flr::tests::test_spec` runs this same sweep against a golden SHAKE256
/// digest; here the two backends are compared to each other directly, which
/// is what turns a digest mismatch into a named operation and a printable
/// operand pair. Operands sit at 2^53 +/- small, i.e. exactly on the
/// boundary where binary64 stops being able to represent consecutive
/// integers, which is where round-half-to-even decides the result.
#[test]
fn flr_emu_matches_native_rounding_ties() {
    let zero = (Emu::ZERO, Nat::ZERO);
    let nzero = (Emu::NZERO, Nat::NZERO);
    for &(ea, na) in [zero, nzero].iter() {
        for &(eb, nb) in [zero, nzero].iter() {
            let (mut e, mut n) = (ea, na);
            e.set_add(eb);
            n.set_add(nb);
            same("set_add(signed zeros)", e, n);
            let (mut e, mut n) = (ea, na);
            e.set_sub(eb);
            n.set_sub(nb);
            same("set_sub(signed zeros)", e, n);
            let (mut e, mut n) = (ea, na);
            e.set_mul(eb);
            n.set_mul(nb);
            same("set_mul(signed zeros)", e, n);
        }
        same("half(zero)", ea.half(), na.half());
        same("double(zero)", ea.double(), na.double());
        same("mul2p63(zero)", ea.mul2p63(), na.mul2p63());
        same("square(zero)", ea.square(), na.square());
    }
    same("sqrt(+0)", Emu::ZERO.sqrt(), Nat::ZERO.sqrt());

    for e in -60..=60i32 {
        for i in -5..=5i64 {
            let (ea, na) = (
                Emu::from_i64((1i64 << 53) + i),
                Nat::from_i64((1i64 << 53) + i),
            );
            same("from_i64", ea, na);
            for j in -5..=5i64 {
                let (eb, nb) = (
                    Emu::scaled((1i64 << 53) + j, e),
                    Nat::scaled((1i64 << 53) + j, e),
                );
                same("scaled", eb, nb);

                // All four sign combinations, as upstream's test does: the
                // interesting cases are the cancellations.
                let mut sea = ea;
                let mut sna = na;
                let mut seb = eb;
                let mut snb = nb;
                for _ in 0..2 {
                    for _ in 0..2 {
                        let (mut xe, mut xn) = (sea, sna);
                        xe.set_add(seb);
                        xn.set_add(snb);
                        same("set_add(ties)", xe, xn);

                        let (mut xe, mut xn) = (sea, sna);
                        xe.set_sub(seb);
                        xn.set_sub(snb);
                        same("set_sub(ties)", xe, xn);

                        let (mut xe, mut xn) = (sea, sna);
                        xe.set_mul(seb);
                        xn.set_mul(snb);
                        same("set_mul(ties)", xe, xn);

                        let (mut xe, mut xn) = (sea, sna);
                        xe.set_div(seb);
                        xn.set_div(snb);
                        same("set_div(ties)", xe, xn);

                        seb.set_neg();
                        snb.set_neg();
                    }
                    sea.set_neg();
                    sna.set_neg();
                }
            }
        }
    }
}

/// Randomized differential over the whole `Flr` surface.
#[test]
fn flr_emu_matches_native_random_ops() {
    let mut rng = SHAKE256x4::new(SEED_RANDOM_OPS);
    for _ in 0..8192 {
        let (ea, na) = decode_both(rand_bits(&mut rng));
        let (eb, nb) = decode_both(rand_bits(&mut rng));

        diff_unary(ea, na);
        diff_unary(eb, nb);
        diff_binary(ea, na, eb, nb);
        diff_binary(eb, nb, ea, na);

        // Mixed with the zeros, which take the corrective branches in
        // flr_emu's set_add/set_mul/set_div.
        let (mut e, mut n) = (ea, na);
        e.set_add(Emu::ZERO);
        n.set_add(Nat::ZERO);
        same("set_add(+0)", e, n);
        let (mut e, mut n) = (ea, na);
        e.set_add(Emu::NZERO);
        n.set_add(Nat::NZERO);
        same("set_add(-0)", e, n);
        let (mut e, mut n) = (ea, na);
        e.set_sub(ea);
        n.set_sub(na);
        same("set_sub(self)", e, n);
        // NOTE: `(+/-0) / x` is deliberately NOT checked here -- flr_emu
        // forces the quotient's sign bit to 0 whenever the dividend is
        // zero, so it disagrees with the native backend on the sign of the
        // resulting zero. Pinned below; unreachable in this crate, whose
        // only divisions are `Flr::ONE / x`.
        let (mut e, mut n) = (Emu::ZERO, Nat::ZERO);
        e.set_mul(ea);
        n.set_mul(na);
        same("set_mul(0*x)", e, n);
        let (mut e, mut n) = (Emu::NZERO, Nat::NZERO);
        e.set_mul(ea);
        n.set_mul(na);
        same("set_mul(-0*x)", e, n);
    }
}

/// `expm_p63`, the Gaussian sampler's `2^63*ccs*exp(-x)` kernel.
///
/// Not reached by `flr::tests::test_spec` at all; on a native-backend host
/// its only coverage is via `sampler.rs`, which uses the native backend.
/// Domain (from flr_emu.rs): `0 <= self < log(2)` and `0 <= ccs <= 1`.
///
/// `ccs == 1` exactly is excluded: it makes the implementation evaluate
/// `Flr::ONE.mul2p63().trunc()`, i.e. `trunc()` on 2^63, which is outside
/// `trunc()`'s own documented range of `[-(2^63-1), +(2^63-1)]`. The two
/// backends saturate that differently. Pinned below rather than asserted
/// equal, because agreeing there was never promised.
#[test]
fn flr_emu_matches_native_expm_p63() {
    // log(2) rounded down, as a 53-bit fixed-point value: staying strictly
    // below log(2) is part of the precondition.
    const LOG2_M53: i64 = 6_243_314_768_165_358;
    // The largest ccs strictly below 1 that binary64 can represent.
    const CCS_MAX_J: i64 = (1i64 << 53) - 1;

    let fixed: [(i64, i32, i64, i32); 6] = [
        (0, 0, 0, 0),                               // x = 0, ccs = 0
        (0, 0, CCS_MAX_J, -53),                     // x = 0, ccs -> 1
        (LOG2_M53, -53, CCS_MAX_J, -53),            // x -> log(2), ccs -> 1
        (LOG2_M53, -53, 0, 0),                      // x -> log(2), ccs = 0
        (1, -53, 1, -1),                            // tiny x, ccs = 0.5
        (LOG2_M53 / 2, -53, (1i64 << 52) - 1, -52), // mid x, ccs just under 1
    ];
    for &(xj, xs, cj, cs) in fixed.iter() {
        let (xe, xn) = (Emu::scaled(xj, xs), Nat::scaled(xj, xs));
        let (ce, cn) = (Emu::scaled(cj, cs), Nat::scaled(cj, cs));
        same("scaled(expm operand)", xe, xn);
        same("scaled(expm ccs)", ce, cn);
        same_u64("expm_p63(fixed)", xe.expm_p63(ce), xn.expm_p63(cn));
    }

    let mut rng = SHAKE256x4::new(SEED_EXPM);
    for _ in 0..4096 {
        // x in [0, log(2)): draw a 53-bit fraction and rescale it.
        let xj = ((rng.next_u64() >> 11) as i64) % (LOG2_M53 + 1);
        // ccs in [0, 1): see the note above on why 1 itself is excluded.
        let cj = ((rng.next_u64() >> 11) as i64) % (1i64 << 53);
        let (xe, xn) = (Emu::scaled(xj, -53), Nat::scaled(xj, -53));
        let (ce, cn) = (Emu::scaled(cj, -53), Nat::scaled(cj, -53));
        same("scaled(expm operand)", xe, xn);
        same("scaled(expm ccs)", ce, cn);
        same_u64("expm_p63", xe.expm_p63(ce), xn.expm_p63(cn));
    }
}

/// `expm_p63`'s exact output is a **pinned, behaviour-defining** value, not an
/// implementation detail — replacing the approximation changes signatures.
///
/// `flr_native.rs` already says the two backends must "always return the same values ... for
/// full reproducibility of test vectors", and `fn-dsa/tests/kats/` pins whole signatures. What
/// neither states is the consequence for anyone optimising this kernel: `expm_p63` feeds the
/// Bernoulli accept/reject in `sampler.rs`, so a single differing bit changes which candidates
/// are accepted, and therefore changes the signature for a given (key, message, seed).
///
/// That matters because the FACCT polynomial is **not** the correctly rounded value of
/// `2^63*ccs*exp(-x)`. Over 200 000 sampled `(x, ccs)` pairs in the documented domain, its result
/// differs from the correctly rounded one on 99.86% of them, by up to 3556 ulp. So a *more
/// accurate* approximation — the segmented-Remez scheme of ePrint 2026/1610, say — necessarily
/// disagrees with this one almost everywhere. "Faster and more accurate" and "bit-compatible with
/// the shipped KATs" are mutually exclusive here; adopting such a change means consciously
/// re-pinning the oracle vectors, which is a decision, not a refactor. See card `t_3986efb2`.
///
/// These pins exist so that fact is discovered by a failing test on the first attempt, rather
/// than downstream in the signature KATs where the cause is much harder to see. They are the
/// current implementation's own output, not an external oracle.
#[test]
fn expm_p63_output_is_pinned_because_it_defines_signatures() {
    const LOG2_M53: i64 = 6_243_314_768_165_358;
    const CCS_MAX_J: i64 = (1i64 << 53) - 1;

    let cases: [(i64, i32, i64, i32, u64); 6] = [
        (0, 0, 0, 0, 0x0000000000000000),
        (0, 0, CCS_MAX_J, -53, 0x7FFFFFFFFFFFFC00),
        (LOG2_M53, -53, CCS_MAX_J, -53, 0x40000000000006C8),
        (LOG2_M53, -53, 0, 0, 0x0000000000000000),
        (1, -53, 1, -1, 0x3FFFFFFFFFFFFE00),
        (LOG2_M53 / 2, -53, (1i64 << 52) - 1, -52, 0x5A827999FCEF2E64),
    ];

    for &(xj, xs, cj, cs, expected) in cases.iter() {
        let (xe, xn) = (Emu::scaled(xj, xs), Nat::scaled(xj, xs));
        let (ce, cn) = (Emu::scaled(cj, cs), Nat::scaled(cj, cs));
        assert_eq!(
            xe.expm_p63(ce),
            expected,
            "emulated expm_p63 moved: x = {xj} * 2^{xs}, ccs = {cj} * 2^{cs}. \
             If this was deliberate, every fn-dsa signature KAT changes too."
        );
        assert_eq!(
            xn.expm_p63(cn),
            expected,
            "native expm_p63 moved: x = {xj} * 2^{xs}, ccs = {cj} * 2^{cs}. \
             If this was deliberate, every fn-dsa signature KAT changes too."
        );
    }
}

/// The complete set of inputs on which the two backends do NOT agree.
///
/// Every one of them involves a negative zero, and every one of them is
/// inherited verbatim from upstream fn-dsa v0.3.0 -- neither backend was
/// modified here, and `flr_emu.rs` is a byte-faithful port of upstream's.
/// They are pinned rather than fixed: "fixing" either side would change
/// signature bytes on some target, which is not something a test may decide.
///
/// Pinning both sides means this test fires if *either* backend's handling
/// of a negative zero changes, and the exhaustive sweep below means it also
/// fires if a *new* divergence appears anywhere in the signed-zero domain.
///
/// TWO OF THESE DEPEND ON CARGO FEATURES. `flr_native` is not one
/// implementation of `sqrt()`/`set_div()` but two: `--features sqrt_emu`
/// swaps the SSE2/NEON/RISC-V sqrt opcode for the integer `Flr::sqrt_emu()`,
/// and `--features div_emu` swaps `self.0 /= other.0` for the integer
/// `Flr::div_emu()` (both for targets whose FPU divide/sqrt is not
/// constant-time). Those two routines are line-for-line ports of
/// `flr_emu.rs`'s own `sqrt`/`set_div` -- `sqrt_emu` ends in the same
/// `make_z(0, ..)` that cannot produce a sign bit, `div_emu` carries the
/// same `s &= dm` zero-dividend clamp -- so under those features the native
/// side adopts flr_emu's answer and the divergence DISAPPEARS.
///
/// That is asserted, not skipped: the expected *native* value moves with the
/// feature (`NAT_SQRT_NZERO`, `NAT_ZERO_DIV` below) while every assertion
/// still runs under every feature combination. `cfg`-ing the assertions away
/// instead would leave `--features div_emu,sqrt_emu` -- the configuration a
/// constant-time-conscious integrator actually ships -- with the signed-zero
/// contract unchecked. CI's workspace-root `--all-features` clippy pass
/// does compile-check that configuration, but no CI row runs tests under
/// it, so a regression there would go untested.
///
/// Provenance of each, and why it is not (currently) a signing hazard:
///
///   * `abs(-0.0)`  emu -> +0.0, native -> -0.0.
///     `flr_native::abs` is `if self.0 < 0.0 { -self.0 } else { self }`,
///     and `-0.0 < 0.0` is false, so it returns the operand unchanged.
///     IEEE-754 says +0.0, i.e. here it is the *emulated* one that is
///     right. `abs()` is `#[allow(dead_code)]` in both backends and is
///     called only from tests in this crate.
///
///   * `sqrt(-0.0)` emu -> +0.0, native -> -0.0 (native -> +0.0, i.e. no
///     divergence at all, when built `--features sqrt_emu`).
///     IEEE-754 defines sqrt(-0.0) = -0.0, so the hardware-opcode native one
///     is right; `flr_emu::sqrt` ends in `Self::make_z(0, e, q)` with the
///     sign hardcoded to 0, and so does `flr_native::sqrt_emu`. In this
///     crate `sqrt()` is only ever applied to a value taken from
///     `g00_re`/`d11_re`-style FFT magnitudes.
///
///   * `floor(-0.0)` emu -> -1, native -> 0.
///     Deliberate upstream behaviour: flr_emu.rs's own comment says "If
///     the value is 'minus zero' then we round it to -1 (arguably, this is
///     the correct behaviour)". This is the ONLY one of the four that
///     reaches production code: `sampler.rs` computes `let s = mu.floor()`.
///     Whether `mu` can ever be exactly -0.0 is NOT established here.
///
///   * `(+/-0.0) / x`  emu -> +0.0, native -> IEEE sign (native -> +0.0,
///     i.e. no divergence at all, when built `--features div_emu`).
///     `flr_emu::set_div`'s zero-dividend correction clamps the sign bit to
///     0 ("and s to zero"), and `flr_native::div_emu` carries that same
///     clamp. Every division in this crate is `Flr::ONE / x`, so the
///     dividend is never zero.
///
///   * `expm_p63(x, ccs)` with `ccs == 1` exactly: emu -> 0, native -> the
///     ordinary result. Root cause is `Flr::ONE.mul2p63().trunc()`, i.e.
///     `trunc()` applied to 2^63, one past the top of its documented input
///     range: emu's shift-based code yields 0, the native `self.0 as i64`
///     saturates to `i64::MAX`. A precondition violation, not a defect.
#[test]
fn flr_emu_negative_zero_divergences_are_pinned() {
    const PZ: u64 = 0x0000_0000_0000_0000;
    const NZ: u64 = 0x8000_0000_0000_0000;

    // What flr_native returns for sqrt(-0.0) depends on which sqrt it was
    // compiled with. See the feature note in this test's doc comment.
    #[cfg(not(feature = "sqrt_emu"))]
    const NAT_SQRT_NZERO: u64 = NZ; // hardware opcode: IEEE, keeps the sign
    #[cfg(feature = "sqrt_emu")]
    const NAT_SQRT_NZERO: u64 = PZ; // sqrt_emu(): make_z(0, ..), no sign bit

    // abs(-0.0). Not feature-dependent: `flr_native::abs` is the same
    // `if self.0 < 0.0` under every feature combination.
    assert!(bits_emu(Emu::NZERO.abs()) == PZ, "emu abs(-0.0) != +0.0");
    assert!(bits_nat(Nat::NZERO.abs()) == NZ, "native abs(-0.0) != -0.0");
    // ... and both agree on +0.0.
    assert!(bits_emu(Emu::ZERO.abs()) == PZ);
    assert!(bits_nat(Nat::ZERO.abs()) == PZ);

    // sqrt(-0.0)
    assert!(bits_emu(Emu::NZERO.sqrt()) == PZ, "emu sqrt(-0.0) != +0.0");
    assert!(
        bits_nat(Nat::NZERO.sqrt()) == NAT_SQRT_NZERO,
        "native sqrt(-0.0) = 0x{:016X}, pinned 0x{NAT_SQRT_NZERO:016X} \
         (sqrt_emu = {})",
        bits_nat(Nat::NZERO.sqrt()),
        cfg!(feature = "sqrt_emu")
    );
    assert!(bits_emu(Emu::ZERO.sqrt()) == PZ);
    assert!(bits_nat(Nat::ZERO.sqrt()) == PZ);

    // floor(-0.0)
    assert!(Emu::NZERO.floor() == -1);
    assert!(Nat::NZERO.floor() == 0);
    assert!(Emu::ZERO.floor() == 0);
    assert!(Nat::ZERO.floor() == 0);

    // Zero dividend: emu clamps the quotient sign to +, native follows
    // IEEE (sign = XOR of operand signs) -- unless it was built with
    // `div_emu`, which is flr_emu's algorithm and clamps identically, in
    // which case the divergence is gone and all four are +0.0.
    #[cfg(not(feature = "div_emu"))]
    const NAT_ZERO_DIV: [u64; 4] = [PZ, NZ, NZ, PZ]; // IEEE: sign = XOR
    #[cfg(feature = "div_emu")]
    const NAT_ZERO_DIV: [u64; 4] = [PZ, PZ, PZ, PZ]; // div_emu: `s &= dm`

    let mone_e = {
        let mut v = Emu::ONE;
        v.set_neg();
        v
    };
    let mone_n = {
        let mut v = Nat::ONE;
        v.set_neg();
        v
    };
    // Order must match NAT_ZERO_DIV: (+0)/(+1), (+0)/(-1), (-0)/(+1),
    // (-0)/(-1). The emulated side is +0.0 for all four regardless.
    for (i, (num_e, num_n, den_e, den_n)) in [
        (Emu::ZERO, Nat::ZERO, Emu::ONE, Nat::ONE),
        (Emu::ZERO, Nat::ZERO, mone_e, mone_n),
        (Emu::NZERO, Nat::NZERO, Emu::ONE, Nat::ONE),
        (Emu::NZERO, Nat::NZERO, mone_e, mone_n),
    ]
    .into_iter()
    .enumerate()
    {
        let mut e = num_e;
        let mut n = num_n;
        e.set_div(den_e);
        n.set_div(den_n);
        assert!(
            bits_emu(e) == PZ,
            "emu zero-dividend div #{i} = 0x{:016X}, pinned 0x{PZ:016X}",
            bits_emu(e)
        );
        assert!(
            bits_nat(n) == NAT_ZERO_DIV[i],
            "native zero-dividend div #{i} = 0x{:016X}, pinned 0x{:016X} \
             (div_emu = {})",
            bits_nat(n),
            NAT_ZERO_DIV[i],
            cfg!(feature = "div_emu")
        );
    }

    // expm_p63 at the excluded ccs == 1 boundary, and its root cause.
    assert!(Emu::ONE.mul2p63().trunc() == 0);
    assert!(Nat::ONE.mul2p63().trunc() == i64::MAX);
    assert!(Emu::ZERO.expm_p63(Emu::ONE) == 0);
    assert!(Nat::ZERO.expm_p63(Nat::ONE) == 0x7FFF_FFFF_FFFF_FFFF);

    // Exhaustive sweep over the signed-zero domain: {+0, -0, +1, -1} under
    // every operation. Anything that diverges and is not named above is a
    // NEW divergence and must be triaged, not silenced.
    let vals = [
        (Emu::ZERO, Nat::ZERO),
        (Emu::NZERO, Nat::NZERO),
        (Emu::ONE, Nat::ONE),
        (mone_e, mone_n),
    ];
    for (i, &(e, n)) in vals.iter().enumerate() {
        let is_nzero = i == 1;
        same("half(zero-domain)", e.half(), n.half());
        same("double(zero-domain)", e.double(), n.double());
        same("mul2p63(zero-domain)", e.mul2p63(), n.mul2p63());
        same("square(zero-domain)", e.square(), n.square());
        let (mut xe, mut xn) = (e, n);
        xe.set_neg();
        xn.set_neg();
        same("set_neg(zero-domain)", xe, xn);
        same_i64("rint(zero-domain)", e.rint(), n.rint());
        same_i64("trunc(zero-domain)", e.trunc(), n.trunc());
        if !is_nzero {
            same("abs(zero-domain)", e.abs(), n.abs());
            same("sqrt(zero-domain)", e.abs().sqrt(), n.abs().sqrt());
            same_i64("floor(zero-domain)", e.floor(), n.floor());
        }
        for k in 1..=9u32 {
            let mut fe = [e];
            let mut fnat = [n];
            Emu::slice_div2e(&mut fe, k);
            Nat::slice_div2e(&mut fnat, k);
            same("slice_div2e(zero-domain)", fe[0], fnat[0]);
        }
        for (j, &(e2, n2)) in vals.iter().enumerate() {
            let (mut a, mut b) = (e, n);
            a.set_add(e2);
            b.set_add(n2);
            same("set_add(zero-domain)", a, b);
            let (mut a, mut b) = (e, n);
            a.set_sub(e2);
            b.set_sub(n2);
            same("set_sub(zero-domain)", a, b);
            let (mut a, mut b) = (e, n);
            a.set_mul(e2);
            b.set_mul(n2);
            same("set_mul(zero-domain)", a, b);
            // Divisor must be non-zero (j >= 2), dividend must be non-zero
            // (i >= 2) -- the zero-dividend cases are pinned above.
            if i >= 2 && j >= 2 {
                let (mut a, mut b) = (e, n);
                a.set_div(e2);
                b.set_div(n2);
                same("set_div(zero-domain)", a, b);
            }
        }
    }
}

/// Exact rounding ties in multiplication.
///
/// This test exists because of a measured coverage hole, not on principle.
/// `flr_emu`'s rounding decision is the table lookup `(0xC8 >> (m & 7)) & 1`
/// over `(result-lsb, round-bit, sticky-bit)`; bit 6 of that constant is the
/// exact-tie-rounds-up-to-even case, `(1, 1, 0)`. It is reachable only
/// through `Flr::make()`, which in turn is reached only from `set_mul` and
/// `set_div` -- and a division can never produce it: writing `a = a0*2^u`
/// and `b = b0*2^v` with `a0`, `b0` odd, the quotient `(a0/b0)*2^(u-v)` has
/// an odd denominator in lowest terms, so its binary expansion either
/// terminates (then `a0/b0 <= a0 < 2^53`, i.e. the quotient is exact and no
/// rounding happens at all) or never terminates (then the sticky bit is 1
/// and it is not a tie). Multiplication is the only route.
///
/// Without the vectors below, flipping that one bit of `0xC8` inside
/// `make()` left every other test in this crate green.
///
/// Operands are 53-bit integers, hence exactly representable, and each pair
/// was chosen so that the 106-bit exact product ends in `1` followed by
/// only zeros. Half of them truncate to an odd mantissa (ties-to-even must
/// round up), half to an even one (must round down); the expected results
/// were cross-checked against an independent arbitrary-precision model
/// before being written down.
#[test]
fn flr_emu_matches_native_multiplication_ties() {
    // (a, b) with a*b an exact tie; truncated mantissa ODD -> round up.
    const TIES_ROUND_UP: [(i64, i64); 8] = [
        (7098447068921856, 5780808304767488),
        (4548404726202368, 8755843063455744),
        (5810310390510336, 6658642417811456),
        (5198617677660160, 7122740902363136),
        (6579477580611584, 7983041405885056),
        (8689794284171520, 5963751069057024),
        (8072684908969984, 8004135412563968),
        (5644203091236732, 5066549580791808),
    ];
    // (a, b) with a*b an exact tie; truncated mantissa EVEN -> round down.
    const TIES_ROUND_DOWN: [(i64, i64); 8] = [
        (8832564101251072, 4622449962385408),
        (8349860808887212, 7881299347898368),
        (5066549580791808, 5402886207729716),
        (8233143068786688, 7364246097225792),
        (4679690694557696, 7401104824336384),
        (4884030650580992, 8276459550655488),
        (5740882011063136, 6403555720167424),
        (7931237028610048, 5304318970298368),
    ];

    for (label, vectors) in [("tie-up", &TIES_ROUND_UP), ("tie-down", &TIES_ROUND_DOWN)] {
        for &(a, b) in vectors.iter() {
            // Both operands are exact, so the only rounding in sight is the
            // product's.
            same("from_i64(tie operand)", Emu::from_i64(a), Nat::from_i64(a));
            same("from_i64(tie operand)", Emu::from_i64(b), Nat::from_i64(b));

            // All four sign combinations, and both operand orders: rounding
            // is on the magnitude, but a sign-dependent slip would show up
            // here.
            for (sa, sb) in [(1i64, 1i64), (-1, 1), (1, -1), (-1, -1)] {
                for (x, y) in [(a * sa, b * sb), (b * sb, a * sa)] {
                    let (mut e, mut n) = (Emu::from_i64(x), Nat::from_i64(x));
                    e.set_mul(Emu::from_i64(y));
                    n.set_mul(Nat::from_i64(y));
                    same(label, e, n);

                    // Same product, shifted around the exponent range: the
                    // tie pattern is exponent-independent, so this must
                    // hold everywhere, including where `make()` has to
                    // renormalize.
                    for sc in [-128i32, -60, -1, 0, 1, 60, 127] {
                        let (mut e, mut n) = (Emu::scaled(x, sc), Nat::scaled(x, sc));
                        e.set_mul(Emu::from_i64(y));
                        n.set_mul(Nat::from_i64(y));
                        same(label, e, n);
                    }
                }
            }

            // square() routes through the same rounding, so feed it a
            // self-tie where one exists.
            same(
                "square(tie operand)",
                Emu::from_i64(a).square(),
                Nat::from_i64(a).square(),
            );
        }
    }
}
