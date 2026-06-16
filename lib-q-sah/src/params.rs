//! S-A-H-256 constants, mirroring `sah-256.profile.json` (spec_version 0.3.0).
//!
//! The `spec_pin` integration test parses the vendored JSON and asserts every
//! value here matches it, so a transcription error fails CI rather than
//! shipping. The runtime artifact itself never parses JSON.

/// Spec version this build implements.
pub const SPEC_VERSION: &str = "0.3.0";

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
pub const BLOCK_LEN: usize = 32;
/// Number of 64-bit state words (512-bit state).
#[allow(dead_code)]
pub const STATE_WORDS: usize = 8;

/// Max AAD / message length in bytes: 2^61 - 1 (bit-length fits in the u64
/// length words injected at finalization).
pub const MAX_LEN: u64 = (1 << 61) - 1;

pub const ROUNDS_INIT: u8 = 12;
pub const ROUNDS_AAD: u8 = 2;
pub const ROUNDS_MSG: u8 = 2;
pub const ROUNDS_FINAL: u8 = 12;

/// ARX G-function right-rotation amounts (r0..r3).
pub const ROTATIONS: [u32; 4] = [32, 24, 16, 63];

/// ARX G-function index tuples (a, b, c, d).
pub const ARX_TUPLES: [[usize; 4]; 4] = [[0, 2, 4, 6], [1, 3, 5, 7], [0, 5, 2, 7], [4, 1, 6, 3]];

/// Linear layer: S'[i] = rotate_left(S[PI[i]], RHO[i]); PI[i] = (5i + 1) mod 8.
pub const PI: [usize; 8] = [1, 6, 3, 0, 5, 2, 7, 4];
pub const RHO: [u32; 8] = [0, 8, 16, 24, 32, 40, 48, 56];

/// Per-round constants (SplitMix64, seed LE("SAH256RC")); table is normative.
pub const ROUND_CONSTANTS: [u64; 16] = [
    0x7a42dc8d91f64384,
    0xdb17103257001d0f,
    0xaaa2a8dd76039fdb,
    0x42bf9f79cdbfe7e6,
    0xef0f661538c6cf77,
    0xd86c6b0005fc86b0,
    0xb3bccd709ac8db75,
    0xfb493434e56fb0e2,
    0x21520faeea33a0ea,
    0xc9c47c713351d049,
    0x38ae6a71051ff097,
    0x81896f2b3866ea11,
    0x9596f3632c311b6c,
    0xe854df155db92d31,
    0x5b209c555536eb89,
    0x48fffa3f03f93802,
];

/// Initial value of S[7] (SplitMix64, seed LE("SAH256IV")).
pub const IV: u64 = 0x7f078b526feaa5cb;

/// Parameter word loaded into S[6]:
/// (version 1 << 48) | (nonce_bits 128 << 32) | (tag_bits 128 << 16) | key_bits 256.
pub const PARAM: u64 = 0x0001008000800100;

/// Domain separation bytes, XORed into the top byte of S[7] before each phase.
pub const DOMAIN_INIT: u8 = 0x01;
pub const DOMAIN_AAD: u8 = 0x02;
pub const DOMAIN_MSG: u8 = 0x04;
pub const DOMAIN_FINAL: u8 = 0x08;
