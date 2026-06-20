//! Profile identifier and anonymity-set semantics for the blind token.
//!
//! `issuer_key_id` selects the issuer parameterization and, together with `epoch`, forms the
//! anonymity-set label `(issuer_key_id, epoch)`: redemptions are unlinkable to issuances *within*
//! one such set. Concrete lattice parameters (dimensions, Gaussian widths, challenge weight) are
//! frozen in [`crate::lattice::scheme`]; byte lengths stay changeable pre-freeze via the profile id.

/// Supported profile identifier (wire header byte).
pub const PROFILE_ID_V1: u8 = 1;
