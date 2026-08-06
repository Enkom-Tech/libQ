//! CTX committing-AEAD transform applied to Saturnin CTR-Cascade — `SaturninAeadCtx`.
//!
//! # What this is
//!
//! **CTX** — John Chan and Phillip Rogaway, *On Committing Authenticated-Encryption*, ESORICS
//! 2022 (full version: IACR ePrint 2022/1260), Fig. 2 / Theorem 2 — applied to Saturnin
//! CTR-Cascade (`SaturninAead`, `crate::aead`), instantiated with [`SaturninHash`]
//! (`crate::hash`). Where `SaturninAead::encrypt` produces `C ‖ T` (CTR-Cascade ciphertext body,
//! 32-byte cascade tag), `SaturninAeadCtx::encrypt` replaces `T` with
//!
//! ```text
//! T' = SaturninHash(CASCADE_CTX_LABEL_V0 ‖ K ‖ N ‖ T ‖ A)      (32 bytes)
//! ```
//!
//! at the same 32-byte offset and width — see `crate::commit::ctx_tag` for the shared
//! implementation (this instantiation reuses it, with [`CASCADE_CTX_LABEL_V0`] as the label) and
//! `crate::commit` module docs for the general byte-layout/injectivity argument. Decryption
//! recomputes `T` from CTR-Cascade's own cascade construction, then checks `T' =? SaturninHash(...)`.
//!
//! This byte layout is **frozen**; any change (a second variable-length field, moving `A` off the
//! end, etc.) must mint a new label (`libq.saturnin.cascade.ctx.v1`), never reuse this one — see
//! the injectivity argument below.
//!
//! # Why a distinct type, not a flag on `SaturninAead`
//!
//! `SaturninAead` ciphertexts are already stored in shipped products: the My-Grid vault (VMK
//! wraps, `mygrid_vault_v1`), My-Grid recovery (mnemonic-derived), and GIP's wrapkey
//! (Argon2id-sealed secret key, `bitlink-wrapkey-argon2id-v1`). Changing `SaturninAead`'s tag
//! construction in place would make every one of those blobs permanently undecryptable — that is
//! data loss in shipped products, not a version bump.
//!
//! `SaturninAeadCtx` is therefore a **separate, opt-in type** with its own, incompatible wire
//! format:
//!
//! - `SaturninAead`'s existing wire output is byte-for-byte **unchanged** — pinned by
//!   `tests/aead_kat_pin.rs`.
//! - `SaturninAeadCtx` ciphertext **never** decrypts under `SaturninAead`, and vice versa — see
//!   `tests/cascade_ctx_spec.rs::cross_mode_ciphertexts_rejected`.
//! - Making the incompatible wire format a compile-time-distinct type (rather than a runtime
//!   constructor flag such as `SaturninAead::new_committing()`) means a call site's choice of
//!   format is visible in its type, not a config value one misrouted call away from writing one
//!   format and reading it back as the other.
//!
//! **Migration guidance:** existing stored formats (`mygrid_vault_v1`, My-Grid recovery,
//! `bitlink-wrapkey-argon2id-v1`) MUST keep decrypting via `SaturninAead`. Adopting
//! `SaturninAeadCtx` for one of them means minting a **new** format tag and re-encrypting / dual
//! reading during a migration window — never switching the AEAD under an existing tag. New
//! designs that want key-commitment-shaped properties should start from `SaturninAeadCtx`
//! directly (with the RED qualifier below).
//!
//! # The two types share a keystream — a migration re-encrypt MUST use a fresh nonce
//!
//! The types are wire-incompatible, but they are **not** cryptographically independent. Only the
//! tag differs: the ciphertext *body* is CTR-Cascade's in both cases, and CTR-Cascade's keystream
//! is a function of `(K, N)` **alone** — the associated data does not enter it. So encrypting
//! under `SaturninAead` and under `SaturninAeadCtx` with the same key and the same nonce produces
//! the *same* keystream, and if the two plaintexts differ, that is a classic two-time pad:
//! `C_plain ⊕ C_ctx == M_plain ⊕ M_ctx`, and either plaintext reveals the other. Changing the AD
//! between the two calls does not help.
//!
//! This matters precisely during the migration window recommended above. **When re-encrypting
//! stored data from `SaturninAead` to `SaturninAeadCtx`, draw a fresh nonce for the new
//! ciphertext.** Do not carry the old record's nonce over, and do not treat "different type,
//! different wire format" as if it were "different keystream" — the distinct type protects the
//! *format*, not the nonce discipline. Reusing a nonce across the two types is exactly as
//! dangerous as reusing it twice within one of them; CTR-Cascade is nonce-catastrophic for
//! confidentiality either way (the Saturnin LWC submission claims no security whatsoever under
//! nonce repetition, spec §5.1 footnote 3).
//!
//! `tests/cascade_ctx_spec.rs::cross_mode_ciphertexts_rejected` pins the underlying fact: for
//! identical inputs the two types' ciphertext bodies are byte-identical and only the last 32
//! bytes differ.
//!
//! # Injectivity (no length prefix needed)
//!
//! Re-verified against `SaturninAead`'s actual parameters (the general argument is
//! `crate::commit` module docs):
//!
//! - `K` is exactly 32 bytes and `N` is exactly 16 (`SaturninAead::key_size()` /
//!   `nonce_size()`). **Both `SaturninAeadCtx::encrypt_bytes` and `SaturninAeadCtx::decrypt_core`
//!   check both lengths themselves, before `ctx_tag` is reached** — not merely by inheriting
//!   `SaturninAead`'s own checks. That redundancy is deliberate: it keeps injectivity a local
//!   property of each entry point rather than a property of call order. A wrong-length key would
//!   at least panic at the `copy_from_slice` that stages it, but a wrong-length nonce is passed to
//!   `ctx_tag` as a plain slice and would otherwise be absorbed silently as a *second*
//!   variable-length field, breaking injectivity with no symptom. Do not remove those checks.
//! - `T` is exactly 32 bytes (`Zeroizing<[u8; 32]>`; `crate::commit::ctx_tag` takes
//!   `base_tag: &[u8; 32]`).
//! - `CASCADE_CTX_LABEL_V0` is a compile-time constant (28 bytes).
//! - `A` is the only variable-length field and it is the suffix; Saturnin-Hash's `10*` padding
//!   makes the hash input self-delimiting, so `|A|` — and hence the tuple `(K, N, T, A)` — is
//!   recovered uniquely from `H_input`'s length.
//!
//! The map `(K, N, T, A) ↦ H_input` is therefore injective and no explicit length prefix is
//! required, on the same grounds as the QCB instantiation.
//!
//! # S-2 does not apply to this instantiation
//!
//! Open obligation S-2 (`crate::commit` module docs, and see `crate::qcb` module docs) is the
//! concern that Chan–Rogaway's Theorem 2 assumes the base scheme's core `C` has the same length
//! as the message `M` (so encryption is bijective for fixed `K, N, A`), which QCB's `10*` message
//! padding violates (`|C| != |M|`).
//!
//! **CTR-Cascade is a stream mode: `|C| == |M|` exactly, natively.** `SaturninAead::ctr_encrypt`
//! XORs a keystream over exactly the bytes present in the input (`block_len = remaining.min(32)`
//! on the final partial block; see `crate::aead::SaturninAead`'s implementation) — no padding is
//! ever appended to the ciphertext body. The `0x80` padding byte used inside the cascade tag's own
//! internal block construction never appears in the ciphertext body itself. `SaturninAead`'s own
//! test suite pins `ciphertext.len() == plaintext.len() + 32` (tag only, no body padding).
//! Moreover, for fixed `(K, N)` the map `M ↦ C = M ⊕ keystream` is a length-preserving *bijection*
//! on each message length — exactly Theorem 2's "encrypt half is bijective for fixed `K, N, A`"
//! hypothesis. CTR-Cascade also fits CTX's tag-based syntax directly: encryption produces `C ‖ T`
//! and decryption *recomputes* `T` deterministically from `(K, N, A, C)` rather than inverting it.
//!
//! **Conclusion, stated both ways:** Theorem 2's length/bijectivity hypothesis is satisfied
//! **natively** by CTR-Cascade; S-2 is an artifact of QCB's message padding and does **not** apply
//! to this instantiation. On this specific axis, CTX-on-CTR-Cascade rests on *firmer* ground than
//! CTX-on-QCB. (Register note: the code facts above are OBSERVED against this crate's source; that
//! they satisfy Theorem 2's stated hypothesis is this module's reading of the theorem as
//! transcribed in `crate::commit`'s module docs — pending confirmation as part of the human
//! cryptographer sign-off below, alongside H-1 and Q-1′. There is no known structural gap of the
//! S-2 kind for this instantiation.) S-2 remains open for `SaturninQcb` — closing it there is out
//! of scope for this module.
//!
//! # Security posture — RED
//!
//! This transform is a proven construction ([Theorem 2](https://eprint.iacr.org/2022/1260))
//! instantiated with a primitive that only carries a designer *claim*, not a proof, of collision
//! resistance, and it has not had a human cryptographer's sign-off. Do not describe
//! `SaturninAeadCtx` as "committing" or "CMT-4 secure" without these qualifiers, and do not
//! describe plain `SaturninAead` as committing at all — it is not (see
//! `lib-q-saturnin/README.md`'s Key commitment section and `lib-q-aead/tests/key_commitment.rs`'s
//! rule that a null search result is not evidence of commitment).
//!
//! Open obligations:
//!
//! - **H-1** (shared with `SaturninQcb`) — is Saturnin-Hash's own claimed bound (no classical
//!   collision below `2^112`, no quantum collision below `~2^75`; `crate::hash` / `crate::commit`)
//!   the right number to publish, or is there room to argue tighter? `2^112` is *below* the
//!   best-known generic classical cost of `2^128` (birthday bound on a 256-bit digest, LWC spec
//!   §5.4.1); the designers claim under it for margin — "additional constant factors that these
//!   bounds do not take into account, which is why our final security claims are reduced"
//!   (§5.4.1) — **not** because of a NIST-LWC floor. Never publish `2^112` without that reason,
//!   never round it up to `2^128`, and never quote it against a *quantum* adversary — the quantum
//!   figure is `~2^75` claimed (generic quantum collision cost is `2^85` with unrestricted qRAM,
//!   `2^102` without; Chailloux–Naya-Plasencia–Schrottenloher, 2017).
//! - **S-2** — does **not** apply here; see above. (Stays open for `SaturninQcb` only.)
//! - **Q-1′** (adapted from QCB's Q-1) — CTX's own nAE-preservation proof (Theorem 3) is in the
//!   *classical* random-oracle model. The Saturnin LWC submission markets CTR-Cascade with
//!   quantum-adversary security claims; whether the CTX-composed scheme preserves that
//!   quantum-adversary security is, as far as this module's author could determine, not covered
//!   by any published analysis. Mitigation to keep in mind: against a *quantum* attacker the CMT
//!   bound also degrades to the quantum collision claim (`~2^75` / generic `2^85`–`2^102`), not
//!   the classical `2^112` figure.
//!
//! No new obligation is introduced beyond H-1 and Q-1′: this instantiation's inputs, layout, and
//! hash are identical in shape to the QCB instantiation; the only differences (stream core, no
//! unpadding branch) *remove* a QCB-specific hypothesis (S-2) rather than adding one.
//!
//! # Perf note
//!
//! CTX adds a fixed number of Saturnin-Hash compression calls per message, plus a second pass
//! over the associated data (once inside CTR-Cascade's own AAD cascade step, again inside the CTX
//! tag) — the same structural shape documented for the QCB instantiation in this crate's README.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use lib_q_core::{
    Aead,
    AeadDecryptSemantic,
    AeadKey,
    DecryptSemanticOutcome,
    Error,
    Nonce,
    Result,
};
use zeroize::{
    Zeroize,
    Zeroizing,
};

use crate::aead::SaturninAead;
use crate::commit::{
    CASCADE_CTX_LABEL_V0,
    ctx_tag,
};
use crate::hash::SaturninHash;

/// CTX-committed AEAD on Saturnin CTR-Cascade.
///
/// Holds a plain [`SaturninAead`] (for the pre-built cascade/CTR cores) plus a pre-built
/// [`SaturninHash`] for the CTX tag, mirroring `SaturninQcb`'s `committer: SaturninHash` field —
/// building a `SaturninHash` clocks the round-constant LFSR for both of its domains, so hoisting
/// it here keeps per-message CTX overhead down to the permutation-call cost the design predicts
/// instead of paying that setup on every `encrypt`/`decrypt` call (see `crate::commit::ctx_tag`'s
/// doc comment for the measurement that caught this the first time, on the QCB instantiation).
///
/// See the module docs for why this is a distinct type from [`SaturninAead`] rather than a
/// constructor flag, and for the frozen byte layout.
pub struct SaturninAeadCtx {
    base: SaturninAead,
    committer: SaturninHash,
}

impl SaturninAeadCtx {
    /// Create a new committed CTR-Cascade AEAD instance.
    pub fn new() -> Self {
        Self {
            base: SaturninAead::new(),
            committer: SaturninHash::new(),
        }
    }

    /// Key size in bytes (256 bits), identical to [`SaturninAead::key_size`].
    pub const fn key_size() -> usize {
        32
    }

    /// Nonce size in bytes (128 bits), identical to [`SaturninAead::nonce_size`].
    pub const fn nonce_size() -> usize {
        16
    }

    /// Tag size in bytes (256 bits), identical to [`SaturninAead::tag_size`].
    pub const fn tag_size() -> usize {
        32
    }

    /// Allocation-free encrypt: takes key/nonce as byte slices. See [`SaturninAead::encrypt_bytes`]
    /// for the allocation-free rationale; this wrapper adds the CTX tag replacement on top.
    pub fn encrypt_bytes(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // The injectivity of `LABEL ‖ K ‖ N ‖ T ‖ A` rests on `K` and `N` being fixed-width, so
        // both lengths are checked HERE, locally, before `nonce` is handed to `ctx_tag` below.
        // `base.encrypt_bytes` re-checks them (same error variants, so this is not observable for
        // any input), but relying on that alone would make injectivity a property of call order
        // rather than of this function: a wrong-length key would at least panic at
        // `key32.copy_from_slice`, whereas a wrong-length nonce would be absorbed silently as a
        // second variable-length field and break the argument with no symptom. Do not remove.
        if key.len() != Self::key_size() {
            return Err(Error::InvalidKeySize {
                expected: Self::key_size(),
                actual: key.len(),
            });
        }
        if nonce.len() != Self::nonce_size() {
            return Err(Error::InvalidNonceSize {
                expected: Self::nonce_size(),
                actual: nonce.len(),
            });
        }

        // `base.encrypt_bytes` performs ALL input validation (key/nonce length, size limit) and
        // produces `C ‖ T`, `T` the 32-byte CTR-Cascade cascade tag.
        let mut ciphertext = self
            .base
            .encrypt_bytes(key, nonce, plaintext, associated_data)?;
        let ad = associated_data.unwrap_or(&[]);

        let body_len = ciphertext.len() - Self::tag_size();
        let mut base_tag = Zeroizing::new([0u8; 32]);
        base_tag.copy_from_slice(&ciphertext[body_len..]);
        ciphertext.truncate(body_len);

        let mut key32 = Zeroizing::new([0u8; 32]);
        key32.copy_from_slice(key);

        let committed_tag = ctx_tag(
            &self.committer,
            CASCADE_CTX_LABEL_V0,
            &key32,
            nonce,
            &base_tag,
            ad,
        )?;
        ciphertext.extend_from_slice(&*committed_tag);
        Ok(ciphertext)
    }

    /// Allocation-free Layer A decrypt: byte-slice counterpart to [`Aead::decrypt`]. Returns the
    /// plaintext on success, or [`Error::VerificationFailed`] on tag mismatch.
    pub fn decrypt_bytes(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match self.decrypt_core(key, nonce, ciphertext, associated_data) {
            Ok(DecryptSemanticOutcome::Success(p)) => Ok(Vec::clone(&*p)),
            Ok(DecryptSemanticOutcome::AuthenticationFailed) => Err(Error::VerificationFailed {
                operation: "Saturnin CTR-Cascade CTX tag verification".into(),
            }),
            Err(e) => Err(e),
        }
    }

    /// Shared decrypt core for Layer A ([`Aead::decrypt`]) and Layer B
    /// ([`AeadDecryptSemantic::decrypt_semantic`]).
    ///
    /// Validation (key/nonce length, minimum ciphertext length) mirrors
    /// `SaturninAead::decrypt_core` and MUST precede the `ctx_tag` call — see the module docs'
    /// injectivity argument, which depends on the nonce never reaching `ctx_tag` at any length
    /// other than 16. The CTX tag is recomputed unconditionally, before any comparison, and CTR is
    /// always run over the full body before the authentication outcome is allowed to influence the
    /// returned plaintext — the same full-work-no-early-exit schedule as `SaturninAead`.
    fn decrypt_core(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<DecryptSemanticOutcome> {
        if key.len() != Self::key_size() {
            return Err(Error::InvalidKeySize {
                expected: Self::key_size(),
                actual: key.len(),
            });
        }
        if nonce.len() != Self::nonce_size() {
            return Err(Error::InvalidNonceSize {
                expected: Self::nonce_size(),
                actual: nonce.len(),
            });
        }
        if (ciphertext.len() >> 5) >= 0xFFFF_FFFE {
            return Err(Error::InvalidMessageSize {
                max: 0xFFFF_FFFE << 5,
                actual: ciphertext.len(),
            });
        }
        if ciphertext.len() < Self::tag_size() {
            return Err(Error::aead_ciphertext_shorter_than_tag(
                Self::tag_size(),
                ciphertext.len(),
            ));
        }

        let ad = associated_data.unwrap_or(&[]);
        let body_len = ciphertext.len() - Self::tag_size();
        let body = &ciphertext[..body_len];
        let received = &ciphertext[body_len..];

        let mut key_staged = Zeroizing::new([0u8; 32]);
        key_staged.copy_from_slice(key);
        let mut nonce_staged = Zeroizing::new([0u8; 16]);
        nonce_staged.copy_from_slice(nonce);
        let kb = key_staged.as_slice();
        let nb = nonce_staged.as_slice();

        let base_tag = self.base.base_tag_over(kb, nb, ad, body)?;
        let expected = ctx_tag(
            &self.committer,
            CASCADE_CTX_LABEL_V0,
            &key_staged,
            nb,
            &base_tag,
            ad,
        )?;

        let tag_valid = lib_q_core::Utils::constant_time_compare(&*expected, received);

        let mut plaintext = body.to_vec();
        if let Err(e) = self.base.ctr_encrypt(kb, nb, &mut plaintext) {
            plaintext.zeroize();
            return Err(e);
        }

        if tag_valid {
            Ok(DecryptSemanticOutcome::Success(Zeroizing::new(plaintext)))
        } else {
            plaintext.zeroize();
            Ok(DecryptSemanticOutcome::AuthenticationFailed)
        }
    }
}

impl Aead for SaturninAeadCtx {
    fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.encrypt_bytes(key.as_bytes(), nonce.as_bytes(), plaintext, associated_data)
    }

    fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.decrypt_bytes(
            key.as_bytes(),
            nonce.as_bytes(),
            ciphertext,
            associated_data,
        )
    }
}

impl AeadDecryptSemantic for SaturninAeadCtx {
    fn decrypt_semantic(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<DecryptSemanticOutcome> {
        self.decrypt_core(
            key.as_bytes(),
            nonce.as_bytes(),
            ciphertext,
            associated_data,
        )
    }
}

impl Default for SaturninAeadCtx {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> AeadKey {
        AeadKey::new((0u8..32).collect::<Vec<_>>())
    }

    fn nonce() -> Nonce {
        Nonce::new((0u8..16).collect::<Vec<_>>())
    }

    #[test]
    fn constants() {
        assert_eq!(SaturninAeadCtx::key_size(), 32);
        assert_eq!(SaturninAeadCtx::nonce_size(), 16);
        assert_eq!(SaturninAeadCtx::tag_size(), 32);
    }

    #[test]
    fn round_trip() -> Result<()> {
        let aead = SaturninAeadCtx::new();
        let ct = aead.encrypt(&key(), &nonce(), b"hello", Some(b"ad"))?;
        assert_eq!(ct.len(), 5 + 32);
        let pt = aead.decrypt(&key(), &nonce(), &ct, Some(b"ad"))?;
        assert_eq!(pt, b"hello");
        Ok(())
    }

    #[test]
    fn default_matches_new() -> Result<()> {
        let a = SaturninAeadCtx::default();
        let b = SaturninAeadCtx::new();
        let pt = b"compare";
        assert_eq!(
            a.encrypt(&key(), &nonce(), pt, None)?,
            b.encrypt(&key(), &nonce(), pt, None)?
        );
        Ok(())
    }
}
