//! Saturnin-SIV — deterministic, nonce-misuse-resistant AEAD at the 256-bit level.
//!
//! # What this is
//!
//! `SaturninSiv` composes two components that already exist in this repository, in the
//! SIV (Synthetic IV) arrangement of Rogaway–Shrimpton (EUROCRYPT 2006, "A Provable-Security
//! Treatment of the Key-Wrap Problem"):
//!
//! * **authentication** — KMAC256 (`lib-q-hash`, NIST SP 800-185), a 256-bit PRF/MAC;
//! * **encryption** — Saturnin in CTR mode (`lib-q-saturnin::SaturninStream`), a 256-bit
//!   block cipher whose designers target post-quantum (Grover) security.
//!
//! The tag is computed over the *plaintext* (with the associated data and the nonce), and the
//! keystream is then derived from that tag. Decryption never trusts the transmitted tag: it
//! recovers the plaintext, **recomputes** the tag over what it recovered, and compares in
//! constant time.
//!
//! # Why: the gap it closes
//!
//! Before this mode, libQ offered misuse-resistant AEAD only at 128 bits (Romulus-M, whose key
//! search costs ~2^64 under Grover) and 256-bit strength only in nonce-*respecting* modes
//! (Saturnin CTR-Cascade / Saturnin-Short). Nothing offered both. For file encryption and for
//! long-lived networking sessions, re-using a nonce across re-encryptions is a realistic
//! operator error — which is exactly what MRAE is for.
//!
//! # THE DETERMINISM IS THE POINT — and it is also a leak
//!
//! **`encrypt` is a deterministic function of `(key, nonce, associated_data, plaintext)`.**
//! Encrypting the same tuple twice yields byte-identical output. That is what makes nonce
//! reuse survivable here: repeating a nonce cannot produce a keystream collision between two
//! *different* messages, because the keystream depends on the whole message, not on the nonce.
//!
//! The unavoidable price, common to every deterministic AE scheme, is that **equality of
//! plaintexts is public**. An observer who sees two ciphertexts under the same key can tell
//! whether the underlying `(nonce, AD, plaintext)` tuples were identical, and this remains true
//! however long the messages are. Concretely:
//!
//! * *File encryption* — re-encrypting an unchanged file produces an unchanged ciphertext, so an
//!   observer of a backup store learns which files changed between snapshots.
//! * *Networking* — repeated identical frames (heartbeats, fixed control messages) are linkable
//!   on the wire.
//!
//! If that linkability matters more to you than misuse resistance does, vary the nonce (or put a
//! counter in the associated data) and the leak disappears for distinct messages; or use a
//! nonce-respecting mode. **Do not** treat this mode as a drop-in for a randomised AEAD without
//! deciding that question first.
//!
//! # Construction (normative for interoperability)
//!
//! ```text
//! K                     = 32-byte master key
//! K_mac                 = KMAC256(key=K,     custom="libq.saturnin-siv.v1.kdf.mac", msg="",  32)
//! K_enc                 = KMAC256(key=K,     custom="libq.saturnin-siv.v1.kdf.enc", msg="",  32)
//!
//! T (32-byte tag)       = KMAC256(key=K_mac, custom="libq.saturnin-siv.v1.tag", msg=E,      32)
//!     where E           = be64(|AD|) || AD || be64(|N|) || N || be64(|P|) || P
//!
//! K_msg                 = KMAC256(key=K_enc, custom="libq.saturnin-siv.v1.msgkey", msg=T,   32)
//! C                     = SaturninCTR(key=K_msg, nonce=T[0..16], P)
//! ciphertext            = T || C
//! ```
//!
//! Decryption recomputes `K_msg` from the received `T`, decrypts, recomputes `T'` over the
//! recovered plaintext, and accepts only if `T' == T` in constant time.
//!
//! # Design decisions, and the reasoning for each
//!
//! **1. Key separation.** `K_mac` and `K_enc` are two independent KMAC256 outputs of the master
//! key under two *different customization strings*. The SIV security argument treats the PRF and
//! the cipher as independently keyed; sharing one key between a MAC and a stream cipher is a
//! standing source of cross-protocol attacks. KMAC's customization string `S` is the
//! SP 800-185-specified domain separator and is absorbed as an encoded, length-prefixed field —
//! so `"…kdf.mac"` and `"…kdf.enc"` cannot collide by concatenation. (The repo's "label = leading
//! message prefix, empty customization" rule is a **K12/TurboSHAKE** rule, adopted because K12's
//! customization argument is not domain-separated the same way; KMAC is the documented exception
//! to it. See `gip-k12-label-discipline`.)
//!
//! **2. Unambiguous encoding.** The MAC input length-prefixes every variable-length field with a
//! big-endian 64-bit length: `be64(|AD|) || AD || be64(|N|) || N || be64(|P|) || P`. This makes
//! the encoding injective — no two distinct `(AD, N, P)` triples share a transcript. Plain
//! concatenation would not: `AD="ab", P="c"` and `AD="a", P="bc"` would produce identical bytes.
//! That exact defect was found and fixed in `lib-q-ring-sig` (commit 275bf59) and is not repeated
//! here. A test (`framing_shift_between_ad_and_plaintext_changes_the_tag`) pins it.
//!
//! **3. Tag length: 256 bits.** Matching the target security level. A 256-bit tag also raises the
//! *generic* commitment (CMT-1) cost to ~2^128, avoiding the ~2^64 margin that a 128-bit tag
//! forces on Romulus. Note this is the generic bound only — **no key-commitment claim is made
//! for this mode**; see "Not claimed" below.
//!
//! **4. Full-tag keystream derivation, not a truncated synthetic IV.** Canonical AES-SIV uses the
//! 128-bit tag directly as the CTR IV. Saturnin-CTR's nonce is 16 bytes, so doing the same here
//! would push the whole 256-bit tag through a 128-bit bottleneck and cap keystream separation at
//! a ~2^64 birthday bound — reintroducing precisely the weakness this mode exists to remove. So
//! the keystream is instead keyed by `K_msg = PRF(K_enc, T)` over the **entire** 256-bit tag
//! (with `T[0..16]` also used as the CTR nonce, which is harmless and costs nothing). Two
//! distinct messages therefore get independent keystreams unless their full 256-bit tags collide.
//! This is a deliberate, documented deviation from RFC 5297's wire format; Saturnin-SIV is not
//! interoperable with AES-SIV and does not claim to be.
//!
//! # Not claimed (read before quoting a security level)
//!
//! * **No cryptographer has reviewed this instantiation.** It is an assembly of analysed
//!   components in a standard arrangement, not a proof. The MRAE claim is inherited from
//!   Rogaway–Shrimpton *given* that KMAC256 is a PRF and Saturnin-CTR is a secure stream cipher;
//!   neither premise is established here.
//! * Saturnin's own designers claim **224-bit** classical single-key security, not 256 — see
//!   `lib-q-saturnin`'s crate docs. The "256-bit" in this module's name is the key and tag width.
//! * **Not key-committing.** No CMT-1 transform is applied. Do not use this mode where a
//!   ciphertext must bind to exactly one key.
//! * Two passes over the plaintext are required (MAC, then encrypt), so this mode cannot stream
//!   encryption: the whole plaintext must be in memory (or read twice). That is inherent to SIV.
//!
//! # Example
//!
//! ```
//! use lib_q_aead::{
//!     Aead,
//!     AeadKey,
//!     Nonce,
//!     SaturninSiv,
//! };
//!
//! let siv = SaturninSiv::new();
//! let key = AeadKey::new(vec![7u8; 32]);
//! let nonce = Nonce::new(vec![0u8; 16]);
//!
//! let ct = siv
//!     .encrypt(&key, &nonce, b"attack at dawn", Some(b"hdr"))
//!     .unwrap();
//! let pt = siv.decrypt(&key, &nonce, &ct, Some(b"hdr")).unwrap();
//! assert_eq!(pt, b"attack at dawn");
//!
//! // Deterministic: same inputs, same bytes.
//! assert_eq!(
//!     ct,
//!     siv.encrypt(&key, &nonce, b"attack at dawn", Some(b"hdr"))
//!         .unwrap()
//! );
//! ```

use alloc::vec::Vec;

use lib_q_core::{
    Aead,
    AeadKey,
    Error,
    Nonce,
    Result,
};
use lib_q_hash::Kmac256;
use lib_q_saturnin::SaturninStream;
use subtle::{
    Choice,
    ConstantTimeEq,
};
use zeroize::{
    Zeroize,
    Zeroizing,
};

/// The two independently-derived subkeys: `(K_mac, K_enc)`.
type SubKeys = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

/// Master key length in bytes (256-bit).
pub const KEY_BYTES: usize = 32;

/// Tag length in bytes (256-bit). See design point 3 in the module docs.
pub const TAG_BYTES: usize = 32;

/// Maximum accepted nonce length in bytes.
///
/// SIV does not *need* a nonce — the construction is deterministic and the nonce is just one more
/// authenticated input — so any length from 0 to this bound is accepted, and the length is part
/// of the authenticated encoding. The bound exists only so that a caller cannot push unbounded
/// attacker-chosen data through the nonce parameter instead of the associated-data parameter.
pub const MAX_NONCE_BYTES: usize = 64;

/// Maximum plaintext length, in bytes (64 GiB).
///
/// Saturnin-CTR's counter is a `u32` over 32-byte blocks, so the keystream itself runs out at
/// 2^37 bytes. This cap sits a factor of two below that ceiling rather than at it.
const MAX_PLAINTEXT_BYTES: u64 = 1 << 36;

// Domain separators. KMAC256's customization string is the SP 800-185 domain-separation
// mechanism and is absorbed length-encoded (see design point 1); these are therefore
// customization strings, not message prefixes.
const CUSTOM_KDF_MAC: &[u8] = b"libq.saturnin-siv.v1.kdf.mac";
const CUSTOM_KDF_ENC: &[u8] = b"libq.saturnin-siv.v1.kdf.enc";
const CUSTOM_TAG: &[u8] = b"libq.saturnin-siv.v1.tag";
const CUSTOM_MSGKEY: &[u8] = b"libq.saturnin-siv.v1.msgkey";

/// Constant-time equality over two 256-bit tags — the exact comparator [`SaturninSiv::open`]
/// authenticates with.
///
/// This is a named, public function rather than an inline `ct_eq` inside `open` so that the
/// structural constant-time test can exercise the real comparator at every byte position. That
/// matters more here than for a conventional AEAD: because the keystream is derived from the
/// *whole* tag, any tampering avalanches through the recovered plaintext and changes essentially
/// every byte of the recomputed tag — so an end-to-end tamper test would still pass against a
/// comparator that only checked a prefix. Testing the comparator directly is what gives that
/// regression a way to fail. See `tests/saturnin_siv_constant_time.rs`.
#[must_use]
pub fn ct_tag_eq(a: &[u8; TAG_BYTES], b: &[u8; TAG_BYTES]) -> Choice {
    a.ct_eq(b)
}

/// Saturnin-SIV: deterministic, nonce-misuse-resistant AEAD with a 256-bit key and tag.
///
/// See the [module documentation](self) for the construction, the design reasoning, and — in
/// particular — the deterministic-encryption leak that comes with misuse resistance.
#[derive(Debug, Default, Clone, Copy)]
pub struct SaturninSiv;

impl SaturninSiv {
    /// Create a new Saturnin-SIV instance. The type is stateless.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Key size in bytes (32).
    #[must_use]
    pub const fn key_size() -> usize {
        KEY_BYTES
    }

    /// Tag size in bytes (32).
    #[must_use]
    pub const fn tag_size() -> usize {
        TAG_BYTES
    }

    fn check_key(key: &[u8]) -> Result<()> {
        if key.len() != KEY_BYTES {
            return Err(Error::InvalidKeySize {
                expected: KEY_BYTES,
                actual: key.len(),
            });
        }
        Ok(())
    }

    fn check_nonce(nonce: &[u8]) -> Result<()> {
        if nonce.len() > MAX_NONCE_BYTES {
            return Err(Error::InvalidNonceSize {
                expected: MAX_NONCE_BYTES,
                actual: nonce.len(),
            });
        }
        Ok(())
    }

    fn check_len(len: usize) -> Result<()> {
        if len as u64 > MAX_PLAINTEXT_BYTES {
            return Err(Error::InvalidMessageSize {
                max: MAX_PLAINTEXT_BYTES as usize,
                actual: len,
            });
        }
        Ok(())
    }

    /// One 32-byte KMAC256 output under the given key and customization string.
    fn kmac32(key: &[u8], custom: &[u8], msg: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let mut out = Zeroizing::new([0u8; 32]);
        let mut k = Kmac256::new(key, custom);
        k.update(msg);
        k.finalize(out.as_mut_slice())
            .ok_or_else(|| Error::EncryptionFailed {
                operation: "Saturnin-SIV: KMAC256 finalize rejected a 32-byte output length".into(),
            })?;
        Ok(out)
    }

    /// Derive `(K_mac, K_enc)` from the master key under two distinct customization strings.
    fn derive_subkeys(master: &[u8]) -> Result<SubKeys> {
        let k_mac = Self::kmac32(master, CUSTOM_KDF_MAC, b"")?;
        let k_enc = Self::kmac32(master, CUSTOM_KDF_ENC, b"")?;
        Ok((k_mac, k_enc))
    }

    /// The synthetic tag over the length-prefixed `(AD, nonce, plaintext)` encoding.
    ///
    /// The encoding is injective: every variable-length field is preceded by its own big-endian
    /// 64-bit byte length, so no two distinct triples produce the same transcript.
    fn compute_tag(
        k_mac: &[u8; 32],
        nonce: &[u8],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<[u8; TAG_BYTES]> {
        let mut m = Kmac256::new(k_mac, CUSTOM_TAG);
        m.update(&(ad.len() as u64).to_be_bytes());
        m.update(ad);
        m.update(&(nonce.len() as u64).to_be_bytes());
        m.update(nonce);
        m.update(&(plaintext.len() as u64).to_be_bytes());
        m.update(plaintext);

        let mut tag = [0u8; TAG_BYTES];
        m.finalize(&mut tag)
            .ok_or_else(|| Error::EncryptionFailed {
                operation: "Saturnin-SIV: KMAC256 finalize rejected a 32-byte tag length".into(),
            })?;
        Ok(tag)
    }

    /// CTR-transform `data` under the per-message key derived from `tag`.
    ///
    /// Symmetric: the same call encrypts and decrypts.
    fn ctr_xor(k_enc: &[u8; 32], tag: &[u8; TAG_BYTES], data: &[u8]) -> Result<Vec<u8>> {
        let k_msg = Self::kmac32(k_enc, CUSTOM_MSGKEY, tag)?;
        SaturninStream::new().encrypt(&k_msg[..], &tag[..16], data)
    }

    /// Encrypt, returning `tag || ciphertext`.
    ///
    /// Deterministic — see the [module documentation](self) for what that leaks.
    pub fn seal(&self, key: &[u8], nonce: &[u8], plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
        Self::check_key(key)?;
        Self::check_nonce(nonce)?;
        Self::check_len(plaintext.len())?;

        let (k_mac, k_enc) = Self::derive_subkeys(key)?;
        let tag = Self::compute_tag(&k_mac, nonce, ad, plaintext)?;
        let body = Self::ctr_xor(&k_enc, &tag, plaintext)?;

        let mut out = Vec::with_capacity(TAG_BYTES + body.len());
        out.extend_from_slice(&tag);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decrypt `tag || ciphertext`, recomputing the tag over the recovered plaintext.
    ///
    /// The transmitted tag is never trusted as an authenticator: it is used only to re-derive the
    /// keystream. Authentication is the constant-time comparison of the transmitted tag against
    /// the tag **recomputed from what was actually recovered**.
    pub fn open(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
        Self::check_key(key)?;
        Self::check_nonce(nonce)?;

        if ciphertext.len() < TAG_BYTES {
            return Err(Error::aead_ciphertext_shorter_than_tag(
                TAG_BYTES,
                ciphertext.len(),
            ));
        }
        Self::check_len(ciphertext.len() - TAG_BYTES)?;

        let mut tag = [0u8; TAG_BYTES];
        tag.copy_from_slice(&ciphertext[..TAG_BYTES]);
        let body = &ciphertext[TAG_BYTES..];

        let (k_mac, k_enc) = Self::derive_subkeys(key)?;
        let mut plaintext = Self::ctr_xor(&k_enc, &tag, body)?;

        let expected = Self::compute_tag(&k_mac, nonce, ad, &plaintext)?;
        if bool::from(ct_tag_eq(&expected, &tag)) {
            Ok(plaintext)
        } else {
            // Never hand back unauthenticated plaintext, and do not leave it in the heap.
            plaintext.zeroize();
            Err(Error::VerificationFailed {
                operation: "Saturnin-SIV AEAD tag verification".into(),
            })
        }
    }
}

impl Aead for SaturninSiv {
    fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.seal(
            &key.data,
            &nonce.data,
            plaintext,
            associated_data.unwrap_or(&[]),
        )
    }

    fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.open(
            &key.data,
            &nonce.data,
            ciphertext,
            associated_data.unwrap_or(&[]),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Design point 1. The MAC key and the CTR-side key must be independent of each other and of
    /// the master key. This is not observable from outside the module (both are internal), so it
    /// is pinned here, where `derive_subkeys` is reachable.
    #[test]
    fn subkeys_are_distinct_from_each_other_and_from_the_master_key() {
        let master = [0x5Au8; KEY_BYTES];
        let (k_mac, k_enc) = SaturninSiv::derive_subkeys(&master).expect("derivation");

        assert_ne!(
            k_mac[..],
            k_enc[..],
            "K_mac and K_enc are equal: the MAC and the cipher share a key"
        );
        assert_ne!(
            k_mac[..],
            master[..],
            "K_mac is the raw master key: no derivation happened"
        );
        assert_ne!(
            k_enc[..],
            master[..],
            "K_enc is the raw master key: no derivation happened"
        );
    }

    /// A one-bit change in the master key must change both subkeys.
    #[test]
    fn subkeys_depend_on_the_master_key() {
        let a = [0u8; KEY_BYTES];
        let mut b = a;
        b[31] ^= 1;

        let (a_mac, a_enc) = SaturninSiv::derive_subkeys(&a).expect("derivation");
        let (b_mac, b_enc) = SaturninSiv::derive_subkeys(&b).expect("derivation");

        assert_ne!(a_mac[..], b_mac[..], "K_mac ignored a master-key bit flip");
        assert_ne!(a_enc[..], b_enc[..], "K_enc ignored a master-key bit flip");
    }

    /// Design point 2. `be64` length prefixes make the MAC encoding injective: moving the
    /// AD/plaintext boundary must change the tag even though the concatenation is identical.
    #[test]
    fn framing_shift_between_ad_and_plaintext_changes_the_tag() {
        let k_mac = [0x11u8; 32];
        // An EMPTY nonce, deliberately: with a non-empty nonce sitting between the AD and the
        // plaintext in the transcript, the two framings differ even under plain concatenation,
        // and the test would pass against the very defect it is meant to catch. Verified: with
        // the length prefixes removed this test passed until the nonce was emptied.
        let nonce: [u8; 0] = [];

        let t1 = SaturninSiv::compute_tag(&k_mac, &nonce, b"ab", b"c").expect("tag");
        let t2 = SaturninSiv::compute_tag(&k_mac, &nonce, b"a", b"bc").expect("tag");

        assert_ne!(
            t1, t2,
            "(AD=\"ab\", P=\"c\") and (AD=\"a\", P=\"bc\") produced the same tag: the MAC \
             encoding is not injective (this is the lib-q-ring-sig 275bf59 defect)"
        );
    }

    /// The same shift, applied at the nonce/plaintext boundary.
    #[test]
    fn framing_shift_between_nonce_and_plaintext_changes_the_tag() {
        let k_mac = [0x11u8; 32];

        let t1 = SaturninSiv::compute_tag(&k_mac, b"xy", b"", b"z").expect("tag");
        let t2 = SaturninSiv::compute_tag(&k_mac, b"x", b"", b"yz").expect("tag");

        assert_ne!(t1, t2, "nonce/plaintext boundary is not authenticated");
    }
}
