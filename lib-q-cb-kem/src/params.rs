//! Global paramaters for the different Classic McEliece variants

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
