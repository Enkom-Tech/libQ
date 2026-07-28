//! Profile identifier and anonymity-set semantics for the blind token.
//!
//! `issuer_key_id` selects the issuer parameterization and, together with `epoch`, forms the
//! anonymity-set label `(issuer_key_id, epoch)`: redemptions are unlinkable to issuances *within*
//! one such set. Concrete lattice parameters (dimensions, Gaussian widths, challenge weight) are
//! frozen in [`crate::lattice::scheme`]; byte lengths stay changeable pre-freeze via the profile id.

/// Supported profile identifier (wire header byte).
///
/// Bumped `1 → 2` with the 128-bit-quantum parameter raise: `q ≈ 2^48` (6 bytes/coeff, ≈119-bit
/// quantum) → `q ≈ 2^51` (7 bytes/coeff, ≈130-bit quantum, `GADGET_LEN = 51`). Profile 2 tokens are
/// wire-incompatible with profile 1, which is the intended downgrade guard: a decoder pinned to one
/// profile rejects the other on the `[ver][profile]` header.
pub const PROFILE_ID_V1: u8 = 2;
