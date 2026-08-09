//! Concrete Maul parameter sets, transcribed from ePrint 2025/1755 Table 5 (§5.3, p20).
//!
//! Verbatim from the paper (`reference/DAKE/DAKE Bandwidth-Efficient (U)AKE from Double-KEM.pdf`,
//! Table 5):
//!
//! ```text
//!           bikz  n    k  q     B    D     (du,dv)  delta     nu   |pk|  |ct|
//! Maul512    337  256  2  7681  B_4  D_64  (10,4)   2^-150    384   826   896
//! Maul768    557  256  3  7681  B_4  D_64  (11,6)   2^-196    512  1240  1440
//! Maul1024   766  256  4  9473  B_4  D_64  (12,5)   2^-257    640  1691  1856
//! ```
//!
//! `nu` is the bit length of the CK-FO implicit-rejection seed (Fig. 6 `dKeygen^FO`).
//!
//! See [`ParamSet::CIPHERTEXT_SIZE_NOTE`] and the crate `SECURITY.md` for the one place our
//! encoding does not reproduce the table (`|pk|`, which the paper quotes as an
//! information-theoretic bound rather than a byte-aligned encoding).

/// Ring dimension. Every Maul parameter set in Table 5 uses `n = 256`.
pub const N: usize = 256;

/// A polynomial of `R_q = Z_q[X]/(X^n + 1)`, coefficients held in `[0, q)`.
pub type Poly = [i32; N];

/// One concrete Maul parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParamSet {
    /// Human-readable name, also absorbed into every transcript for cross-parameter separation.
    pub name: &'static str,
    /// Module rank `k`.
    pub k: usize,
    /// Modulus `q` (NTT-friendly in the paper; this implementation does not require it).
    pub q: i32,
    /// Centered-binomial parameter for `B` (Table 5 lists `B_4` for all three sets).
    pub eta: u32,
    /// Compression parameter for the shared vector component `c_C`.
    pub du: u32,
    /// Compression parameter for the two scalar components `c_L`, `c_R`.
    pub dv: u32,
    /// Bit length of the CK-FO implicit-rejection seed (Table 5 column `nu`).
    pub nu_bits: usize,
    /// NIST PQC category this set targets (Table 5 §5.3: "levels 1, 3, 5").
    pub nist_category: u8,
    /// Table 6 `PrimalLWE_SigmaHints` estimate, the residual BKZ blocksize WITH the Hint-MLWE hint.
    pub bikz_hints: u32,
    /// Table 6 `PrimalLWE_(sigma1/sqrt2)`, the paper's own conservative lower bound.
    pub bikz_lower_bound: u32,
    /// Bits per coefficient used to byte-align a public-key polynomial: `ceil(log2 q)`.
    pub pk_bits: u32,
    /// Barrett magic: `floor(2^45 / q)`. See [`crate::arith::Modulus`].
    pub barrett_v: i64,
    /// Barrett magic for `2q`: `floor(2^45 / (2q))`, used by rounding division in compression.
    pub barrett_v2: i64,
}

const fn barrett(d: i64) -> i64 {
    (1i64 << 45) / d
}

/// Maul512 — NIST category 1.
pub const MAUL512: ParamSet = ParamSet {
    name: "Maul512",
    k: 2,
    q: 7681,
    eta: 4,
    du: 10,
    dv: 4,
    nu_bits: 384,
    nist_category: 1,
    bikz_hints: 353,
    bikz_lower_bound: 338,
    pk_bits: 13,
    barrett_v: barrett(7681),
    barrett_v2: barrett(2 * 7681),
};

/// Maul768 — NIST category 3. The set the DAKE handshake numbers (Table 3) are quoted at.
pub const MAUL768: ParamSet = ParamSet {
    name: "Maul768",
    k: 3,
    q: 7681,
    eta: 4,
    du: 11,
    dv: 6,
    nu_bits: 512,
    nist_category: 3,
    bikz_hints: 589,
    bikz_lower_bound: 560,
    pk_bits: 13,
    barrett_v: barrett(7681),
    barrett_v2: barrett(2 * 7681),
};

/// Maul1024 — NIST category 5.
pub const MAUL1024: ParamSet = ParamSet {
    name: "Maul1024",
    k: 4,
    q: 9473,
    eta: 4,
    du: 12,
    dv: 5,
    nu_bits: 640,
    nist_category: 5,
    bikz_hints: 811,
    bikz_lower_bound: 772,
    pk_bits: 14,
    barrett_v: barrett(9473),
    barrett_v2: barrett(2 * 9473),
};

/// All parameter sets, in ascending security order.
pub const ALL: [&ParamSet; 3] = [&MAUL512, &MAUL768, &MAUL1024];

impl ParamSet {
    /// Why `ciphertext_size` reproduces Table 5 exactly but `public_key_size` does not.
    ///
    /// `|ct|` in Table 5 is `k*n*du/8 + 2*n*dv/8`, which is byte-aligned for every listed
    /// `(k, du, dv)` and matches 896 / 1440 / 1856 exactly.
    ///
    /// `|pk|` in Table 5 is `n*k*log2(q)/8` — the information-theoretic bound, with the
    /// `A`-seed excluded: `512*log2(7681)/8 = 826.0`, `768*log2(7681)/8 = 1239.1` (quoted 1240),
    /// `1024*log2(9473)/8 = 1690.8` (quoted 1691). A real byte-aligned encoding cannot hit those
    /// numbers. [`ParamSet::public_key_size`] reports what this crate actually emits:
    /// `ceil(log2 q)` bits per coefficient plus the 32-byte `A`-seed.
    pub const CIPHERTEXT_SIZE_NOTE: &'static str = "|ct| matches Table 5 exactly; |pk| in Table 5 is an information-theoretic bound, not an \
         encoding";

    /// Encoded size in bytes of the shared vector component `c_C`.
    #[must_use]
    pub const fn c_c_size(&self) -> usize {
        self.k * N * (self.du as usize) / 8
    }

    /// Encoded size in bytes of one scalar component (`c_L` or the masked `c_R`).
    #[must_use]
    pub const fn c_scal_size(&self) -> usize {
        N * (self.dv as usize) / 8
    }

    /// Encoded ciphertext size in bytes: `c_C || c_L || c_R^OTP`.
    ///
    /// Equals Table 5's `|ct|` column exactly for all three parameter sets.
    #[must_use]
    pub const fn ciphertext_size(&self) -> usize {
        self.c_c_size() + 2 * self.c_scal_size()
    }

    /// Encoded public-key size in bytes as THIS crate emits it: 32-byte `A`-seed plus `t` packed
    /// at `ceil(log2 q)` bits per coefficient. See [`Self::CIPHERTEXT_SIZE_NOTE`].
    #[must_use]
    pub const fn public_key_size(&self) -> usize {
        32 + self.k * N * (self.pk_bits as usize) / 8
    }

    /// Byte length of the CK-FO implicit-rejection seed.
    #[must_use]
    pub const fn nu_bytes(&self) -> usize {
        self.nu_bits / 8
    }

    /// Core-SVP **quantum** cost of the residual Hint-MLWE instance, in bits.
    ///
    /// Basis: §5.4 states the analysis is "grounded in the assumed hardness of the MLWE problem,
    /// assessed via the core-SVP cost model [1]" and derives security by "applying the complexity
    /// of the best known sieving algorithms -- both classical and quantum [6,14] -- to this block
    /// size, deliberately omitting polynomial factors". The standard core-SVP quantum sieve
    /// exponent for BKZ blocksize `beta` is `0.265 * beta` (Laarhoven; the figure NIST's PQC
    /// submissions, including Kyber/ML-KEM, quote as "quantum core-SVP").
    ///
    /// Applied to Table 6's `PrimalLWE_SigmaHints` column.
    #[must_use]
    pub const fn quantum_core_svp_bits(&self) -> u32 {
        (self.bikz_hints * 265) / 1000
    }

    /// Core-SVP quantum cost of the paper's own conservative LOWER bound
    /// (Table 6 `PrimalLWE_(sigma1/sqrt2)`), i.e. the floor under Heuristics 2-3.
    #[must_use]
    pub const fn quantum_core_svp_bits_lower_bound(&self) -> u32 {
        (self.bikz_lower_bound * 265) / 1000
    }

    /// Core-SVP **classical** cost in bits: `0.292 * beta` (Becker-Ducas-Gama-Laarhoven).
    #[must_use]
    pub const fn classical_core_svp_bits(&self) -> u32 {
        (self.bikz_hints * 292) / 1000
    }

    /// Whether this set clears 128 bits of security under the **quantum** core-SVP model, taken
    /// against Table 6's hint-adjusted blocksize.
    ///
    /// `MAUL512` does **not** (93 bits). That is not a defect in the paper — it is the same
    /// well-known property of ML-KEM-512, whose quantum core-SVP figure is ~107 — but it means
    /// `MAUL512` cannot be used to satisfy a literal ">= 128-bit post-quantum" requirement, and
    /// this crate says so in the type rather than in prose only.
    #[must_use]
    pub const fn meets_128_bit_quantum_core_svp(&self) -> bool {
        self.quantum_core_svp_bits() >= 128
    }
}
