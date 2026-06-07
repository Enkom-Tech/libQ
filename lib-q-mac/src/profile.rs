//! Profile constants for qCW-MAC v1.

/// Tag length in bytes (256-bit quantum PRF output).
pub const QCW_MAC_TAG_BYTES: usize = 32;

/// Secret key length in bytes.
pub const QCW_MAC_KEY_BYTES: usize = 32;

/// KAT schema identifier exported to conformance consumers.
pub const QCW_MAC_KAT_SCHEMA: &str = "qcw-mac-kat-v1";
