//! Global paramaters for the different Classic McEliece variants
//!
//! # Variant selection is a first-wins cascade, and the whole crate must follow it
//!
//! Exactly one variant is meant to be enabled. Cargo cannot enforce that: features are additive,
//! and `--all-features` (which CI's `cargo clippy --all-targets --all-features` and docs.rs both
//! use) turns all ten on at once. A `compile_error!` guard is therefore not available — the crate
//! has to *compile and behave coherently* under a multi-variant feature set.
//!
//! The rule this file establishes, and which every variant-gated `#[cfg]` in the crate follows:
//!
//! 1. **Lower parameter set wins**: `348864` > `460896` > `6688128` > `6960119` > `8192128`.
//! 2. **A plain variant outranks its `f` flavour**, so a multi-variant build resolves to the
//!    semi-systematic-free algorithm.
//!
//! Concretely, a block that should be active only when variant `X` is the *effective* one is
//! gated `all(not(any(<every variant above X>)), any(feature = "X", feature = "Xf"))`, and its
//! `else` counterpart is the negation of that, **not** the negation of `any(X, Xf)`. Getting that
//! second part wrong is what makes the difference invisible in a single-variant build and only
//! shows up under `--all-features`.
//!
//! This was not always true. Before 2026-08-10 (card `t_580dc5fd`) only this file cascaded; the
//! rest of the crate gated on the bare feature. Under `--all-features` that meant `params.rs`
//! resolved to `348864` while, for example, `gf::gf_mul_inplace` executed *all four* variants'
//! reduction steps in sequence — silently wrong field arithmetic, and 14 failing tests that read
//! as "cb-kem is broken" rather than "this configuration is incoherent".
//!
//! If you add a variant, add it to the ordering above and give every one of its `#[cfg]` sites the
//! exclusion prefix. The check that this still holds is `cargo test -p lib-q-cb-kem
//! --all-features`, which must stay green, together with the per-variant runs — a variant whose
//! test count *drops* has been compiled away rather than fixed.

#[cfg(any(feature = "cbkem348864", feature = "cbkem348864f"))]
pub const GFBITS: usize = 12;
#[cfg(any(feature = "cbkem348864", feature = "cbkem348864f"))]
pub const SYS_N: usize = 3488;
#[cfg(any(feature = "cbkem348864", feature = "cbkem348864f"))]
pub const SYS_T: usize = 64;

#[cfg(all(
    not(any(feature = "cbkem348864", feature = "cbkem348864f")),
    any(feature = "cbkem460896", feature = "cbkem460896f")
))]
pub const GFBITS: usize = 13;
#[cfg(all(
    not(any(feature = "cbkem348864", feature = "cbkem348864f")),
    any(feature = "cbkem460896", feature = "cbkem460896f")
))]
pub const SYS_N: usize = 4608;
#[cfg(all(
    not(any(feature = "cbkem348864", feature = "cbkem348864f")),
    any(feature = "cbkem460896", feature = "cbkem460896f")
))]
pub const SYS_T: usize = 96;

#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f"
    )),
    any(feature = "cbkem6688128", feature = "cbkem6688128f")
))]
pub const GFBITS: usize = 13;
#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f"
    )),
    any(feature = "cbkem6688128", feature = "cbkem6688128f")
))]
pub const SYS_N: usize = 6688;
#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f"
    )),
    any(feature = "cbkem6688128", feature = "cbkem6688128f")
))]
pub const SYS_T: usize = 128;

#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f",
        feature = "cbkem6688128",
        feature = "cbkem6688128f"
    )),
    any(feature = "cbkem6960119", feature = "cbkem6960119f")
))]
pub const GFBITS: usize = 13;
#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f",
        feature = "cbkem6688128",
        feature = "cbkem6688128f"
    )),
    any(feature = "cbkem6960119", feature = "cbkem6960119f")
))]
pub const SYS_N: usize = 6960;
#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f",
        feature = "cbkem6688128",
        feature = "cbkem6688128f"
    )),
    any(feature = "cbkem6960119", feature = "cbkem6960119f")
))]
pub const SYS_T: usize = 119;

#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f",
        feature = "cbkem6688128",
        feature = "cbkem6688128f",
        feature = "cbkem6960119",
        feature = "cbkem6960119f"
    )),
    any(feature = "cbkem8192128", feature = "cbkem8192128f")
))]
pub const GFBITS: usize = 13;
#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f",
        feature = "cbkem6688128",
        feature = "cbkem6688128f",
        feature = "cbkem6960119",
        feature = "cbkem6960119f"
    )),
    any(feature = "cbkem8192128", feature = "cbkem8192128f")
))]
pub const SYS_N: usize = 8192;
#[cfg(all(
    not(any(
        feature = "cbkem348864",
        feature = "cbkem348864f",
        feature = "cbkem460896",
        feature = "cbkem460896f",
        feature = "cbkem6688128",
        feature = "cbkem6688128f",
        feature = "cbkem6960119",
        feature = "cbkem6960119f"
    )),
    any(feature = "cbkem8192128", feature = "cbkem8192128f")
))]
pub const SYS_T: usize = 128;

pub const COND_BYTES: usize = (1 << (GFBITS - 4)) * (2 * GFBITS - 1);
pub const IRR_BYTES: usize = SYS_T * 2;
pub const PK_NROWS: usize = SYS_T * GFBITS;
pub const PK_NCOLS: usize = SYS_N - PK_NROWS;
pub const PK_ROW_BYTES: usize = PK_NCOLS.div_ceil(8);
pub const SYND_BYTES: usize = PK_NROWS.div_ceil(8);
pub const GFMASK: usize = (1 << GFBITS) - 1;
