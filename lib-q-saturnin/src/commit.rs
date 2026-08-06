//! CTX committing-AEAD transform, shared by `SaturninQcb` and `SaturninAeadCtx`.
//!
//! `ctx_tag` (`pub(crate)`) is generic over the label and the base mode; it is instantiated twice in this
//! crate, once per base AEAD, each with its own label so the two instantiations' hash inputs can
//! never collide (see [`QCB_CTX_LABEL_V0`] / [`CASCADE_CTX_LABEL_V0`]):
//!
//! - **`SaturninQcb`** (`crate::qcb`) — the original instantiation. Its mode-specific security
//!   posture (including the open S-2 obligation, which is specific to QCB's `10*`-padded core)
//!   is documented on `crate::qcb` and below.
//! - **`SaturninAeadCtx`** (`crate::aead_ctx`) — CTX applied to CTR-Cascade (`SaturninAead`,
//!   `src/aead.rs`), the mode every real libQ consumer (GIP, uGrid, My-Grid, Bitlink) actually
//!   uses. Its mode-specific security posture, including why S-2 does **not** apply to this
//!   instantiation, is documented on `crate::aead_ctx`.
//!
//! The rest of this module's docs describe the shared construction, byte layout, and injectivity
//! argument; they use `SaturninQcb` in examples for historical reasons (this module predates the
//! cascade instantiation) but apply identically to both.
//!
//! # Construction
//!
//! **CTX** — John Chan and Phillip Rogaway, *On Committing Authenticated-Encryption*, ESORICS
//! 2022 (full version: IACR ePrint 2022/1260), Fig. 2 / Theorem 2. For a tag-based nAE scheme
//! whose encryption produces `C ‖ T` (core `C`, tag `T`), CTX replaces `T` with
//! `T' = H(K, N, A, T)` for a collision-resistant `H`, and proves
//! `Adv^{CAE-XX}_{CTX}(A) ≤ Adv^{col}_H(B)` — the CMT-4 advantage of the transformed scheme is
//! bounded by the collision resistance of `H`. Decryption recomputes `T` from the base scheme,
//! then checks `T' =? H(K, N, A, T)`.
//!
//! `H` is instantiated here with [`SaturninHash`] (LWC spec §2.4: Merkle–Damgård, MMO, IV = 0,
//! domains 7/8, 16 super-rounds, `10*` padding — unmodified). The Saturnin designers claim no
//! classical collision attack below `2^112` and no quantum collision attack below `~2^75`
//! (LWC spec §1.2/§2.4); by Theorem 2 that is the CMT-4 bound this transform inherits. The
//! best-known generic classical collision cost for a 256-bit random function is `2^128` by the
//! birthday bound (LWC spec §5.4.1); the designers claim below that bound for margin — "additional
//! constant factors that these bounds do not take into account, which is why our final security
//! claims are reduced" (§5.4.1) — **not** because of a NIST-LWC floor. (Best-known generic quantum
//! collision cost: `2^85` with unrestricted qRAM, `2^102` without; Chailloux–Naya-Plasencia–
//! Schrottenloher, 2017.) Do not round `2^112` up to `2^128` in any doc that cites it.
//!
//! `H` is Saturnin-Hash rather than a Keccak-based hash (`lib-q-sha3` / `lib-q-k12`) so that a
//! hardware implementation of Saturnin does not have to also implement Keccak-f\[1600\] solely to
//! compute a handful of compression calls at the end of every message; it also burns no Saturnin
//! domain separator (only 14/15 remain unassigned across the whole submission + QCB) and adds no
//! new crate dependency.
//!
//! # Byte layout (frozen; do not change without minting a new label)
//!
//! ```text
//! H_input  =  LABEL  ‖  K  ‖  N  ‖  T  ‖  A
//! T'       =  SaturninHash(H_input)             (32 bytes)
//! ```
//!
//! - `LABEL` is a compile-time-constant, ASCII, NUL-free byte string — a **leading message
//!   prefix**, not a customization string (Saturnin-Hash has no customization input at all, so
//!   this is the only form available; it is also the lib-Q-wide K12/hash domain-separation
//!   discipline: label as leading prefix, never as a customization argument).
//! - `K` is the 32-byte AEAD key, `N` the nonce (16 bytes for `SaturninQcb`), `T` the base mode's
//!   32-byte tag, all absorbed verbatim.
//! - `A` is the associated data, verbatim, and is the **only** variable-length field; it is
//!   placed as the suffix specifically so no length prefix is needed (see injectivity argument
//!   below). It may be empty.
//!
//! ## Injectivity, and the constraint that follows from it
//!
//! For a fixed mode, `LABEL` is a compile-time constant and `K`/`N`/`T` are fixed-width. `A` is
//! the only variable-length field and it is the suffix. Saturnin-Hash's `10*` padding makes the
//! message self-delimiting, so `H_input` determines `|H_input|`, hence
//! `|A| = |H_input| - |LABEL| - |K| - |N| - |T|`, hence the tuple `(K, N, T, A)`. The map
//! `(K, N, T, A) ↦ H_input` is therefore injective and **no explicit length prefix is required**.
//!
//! **If a future version adds a second variable-length field, or moves `A` off the end, the
//! encoding stops being injective and explicit length prefixes become mandatory.** Any such
//! change must mint a new label (e.g. `libq.saturnin.qcb.ctx.v1`) rather than reuse this one.
//!
//! # Security posture — RED
//!
//! This transform is a proven construction ([Theorem
//! 2](https://eprint.iacr.org/2022/1260)) instantiated with a primitive that only carries a
//! designer *claim*, not a proof, of collision resistance, and it has not had a human
//! cryptographer's sign-off. Three obligations are open (see `lib-q-saturnin/README.md` and
//! `CHANGELOG.md`, card `t_16ddf21c`):
//!
//! - **H-1** — is 2^112 classical / ~2^75 quantum (Saturnin-Hash's own claim) the right number to
//!   publish, or is there room to argue tighter?
//! - **S-2** — Chan–Rogaway's Theorem 2 assumes the base scheme's core `C` is the same length as
//!   the message `M` (so its "encrypt" half is bijective for fixed `K,N,A`); Saturnin-QCB's `10*`
//!   padding makes `|C| ≠ |M|` in general. The argument that mere *injectivity* (not
//!   length-preserving bijectivity) suffices for QCB specifically — including the
//!   `unpad_len -> None` branch — has not been reviewed by a cryptographer.
//! - **Q-1** — CTX's own nAE-preservation proof (Theorem 3) is in the *classical* random-oracle
//!   model. Saturnin-QCB exists specifically for resistance to *superposition-query* (Q2)
//!   adversaries (see the Deutsch-algorithm warning quoted in `qcb.rs`). Whether composing CTX
//!   with QCB preserves that Q2 property is, as far as this lane could determine, not covered by
//!   any published analysis.
//!
//! Do not describe `SaturninQcb` as "committing" or "CMT-4 secure" without these qualifiers.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use lib_q_core::Result;
use zeroize::{
    Zeroize,
    Zeroizing,
};

use crate::hash::SaturninHash;

/// CTX label for Saturnin-QCB (§ module docs). 24 ASCII bytes, leading message prefix, empty
/// customization (Saturnin-Hash has no customization input).
pub const QCB_CTX_LABEL_V0: &[u8] = b"libq.saturnin.qcb.ctx.v0";

/// CTX label for Saturnin CTR-Cascade (`SaturninAeadCtx`, `crate::aead_ctx`). 28 ASCII bytes,
/// leading message prefix, empty customization (Saturnin-Hash has no customization input).
///
/// Shares the 14-byte prefix `libq.saturnin.` with [`QCB_CTX_LABEL_V0`] and then diverges at byte
/// offset 14 (`'c'` = 0x63 vs `'q'` = 0x71). Because the two labels are the *leading* bytes of
/// `H_input = LABEL ‖ K ‖ N ‖ T ‖ A`, every QCB-mode `H_input` differs from every cascade-mode
/// `H_input` at that fixed absolute byte offset regardless of what `K, N, T, A` follow — a
/// cross-mode tag collision is therefore a genuine Saturnin-Hash collision (covered by the H-1
/// bound below), not a domain-separation gap.
pub const CASCADE_CTX_LABEL_V0: &[u8] = b"libq.saturnin.cascade.ctx.v0";

/// Compute the CTX commitment tag `T' = SaturninHash(label ‖ key ‖ nonce ‖ base_tag ‖ ad)`.
///
/// `key` and `base_tag` are exactly 32 bytes; `nonce` and `ad` are the caller-supplied
/// variable-length fields (`ad` may be empty). Always does the full hash computation — callers on
/// both the encrypt and decrypt paths must call this unconditionally so that encrypt/decrypt cost
/// stays symmetric and no early exit leaks whether inputs were well-formed before commitment.
///
/// Takes `hasher` by reference rather than constructing a [`SaturninHash`] internally: building
/// one clocks the round-constant LFSR for both of its domains (see `SaturninHash`'s own field
/// docs), and this function is called on *every* `encrypt`/`decrypt`, not once per process — the
/// caller (`SaturninQcb`) builds it once and holds it, exactly like its five `SaturninTbc`
/// fields. An earlier version of this function built a fresh `SaturninHash` per call; a
/// scratch-directory timing check (not part of the checked-in bench suite, which a concurrent
/// lane owns) measured ~4.6 µs per empty-message `encrypt` with that version against a
/// back-of-envelope prediction of a few hundred ns, which is what caught this.
pub(crate) fn ctx_tag(
    hasher: &SaturninHash,
    label: &[u8],
    key: &[u8; 32],
    nonce: &[u8],
    base_tag: &[u8; 32],
    ad: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut input: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(
        label.len() + key.len() + nonce.len() + base_tag.len() + ad.len(),
    ));
    input.extend_from_slice(label);
    input.extend_from_slice(key);
    input.extend_from_slice(nonce);
    input.extend_from_slice(base_tag);
    input.extend_from_slice(ad);

    let mut digest = hasher.hash(&input)?;

    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&digest);
    digest.zeroize();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctx_tag_is_deterministic_and_32_bytes() {
        let hasher = SaturninHash::new();
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 16];
        let base_tag = [0x33u8; 32];
        let a = ctx_tag(&hasher, QCB_CTX_LABEL_V0, &key, &nonce, &base_tag, b"ad").unwrap();
        let b = ctx_tag(&hasher, QCB_CTX_LABEL_V0, &key, &nonce, &base_tag, b"ad").unwrap();
        assert_eq!(a.len(), 32);
        assert_eq!(*a, *b);
    }

    #[test]
    fn ctx_tag_empty_ad_differs_from_nonempty_ad() {
        let hasher = SaturninHash::new();
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 16];
        let base_tag = [0x33u8; 32];
        let empty = ctx_tag(&hasher, QCB_CTX_LABEL_V0, &key, &nonce, &base_tag, b"").unwrap();
        let nonempty = ctx_tag(&hasher, QCB_CTX_LABEL_V0, &key, &nonce, &base_tag, b"x").unwrap();
        assert_ne!(*empty, *nonempty);
    }
}
