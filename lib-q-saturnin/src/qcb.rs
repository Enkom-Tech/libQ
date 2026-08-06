//! Saturnin-QCB authenticated encryption
//!
//! Saturnin-QCB is the one-pass, parallelizable AEAD proposed in "An Update on Saturnin". It is
//! a `ΘCB`/`TAE`-style mode built on the Saturnin [tweakable block cipher](crate::tbc): each
//! block of plaintext is encrypted by one TBC call whose tweak binds a domain separator, the
//! nonce, and the block number; the tag is produced by encrypting a checksum of the (padded)
//! message under a distinct domain. Because nonce + block-number give every TBC call a unique
//! tweak (when nonces are not reused), the mode achieves rate-one encryption with a tighter
//! quantum-security proof than Saturnin-CTR-Cascade, and every block can be processed
//! independently (parallelized).
//!
//! # Domain separators and tweak encoding — normative source
//!
//! The "Update on Saturnin" note describes Saturnin-QCB only at a high level (Section 5 and a
//! Figure 1 that is captioned "Saturnin-QCB, **encryption**" and covers only the message path);
//! it does not give the tag or associated-data equations. The full mode is Algorithm 1 of the
//! separate QCB paper — Bhaumik, Bonnetain, Chailloux, Leurent, Naya-Plasencia, Schrottenloher and
//! Seurin, *QCB: Efficient Quantum-secure Authenticated Encryption*, ASIACRYPT 2021 (full version:
//! IACR ePrint 2020/1304) — together with that paper's *Instantiation with Saturnin* paragraph,
//! which is the source this module now follows:
//!
//! - **TBC** (unambiguous, and the one part the note alone fixes):
//!   `TBC_d(K,T)(M) = Saturnin16^d_{K⊕T}(M)`. See [`crate::tbc`].
//! - **Domains** (QCB paper, *Instantiation with Saturnin*: "The other modes of operation of the
//!   Saturnin submission use values from 0 to 8 included, so we use `D = 9, 10, 11, 12 and 13` in
//!   Algorithm 1"), mapped onto Algorithm 1's `d = 0..4`:
//!   - **9** — full message block `M_i` (Algorithm 1 line 5)
//!   - **10** — final, padded message block `pad(M_*)` (line 7)
//!   - **11** — full associated-data block `A_i` (line 10)
//!   - **12** — final, padded associated-data block `pad(A_*)` (line 12)
//!   - **13** — tag / message checksum (line 13)
//! - **Tweak encoding** (QCB paper: `E~_{k,(D,IV,i)}(x) = Saturnin^D_16(k XOR (IV||i), x)`; "The
//!   IV and the block number are simply concatenated"): `T = N (16 bytes) ‖ 0x00·8 ‖
//!   block_index_be_u64 (8 bytes)`, a 256-bit value, used **identically for message and
//!   associated-data tweaks** — the nonce is never zeroed. The QCB paper is explicit that omitting
//!   it from the AD tweak breaks the mode (Section 5, *Avoiding Quantum Attacks*: "It is important
//!   to include the IV in the tweak when processing the AD. Otherwise, there is a quantum forgery
//!   attack based on Deutsch's algorithm.").
//! - **Padding** (QCB paper: "We define the padding scheme `pad(M_*)` as appending `10*`"; "the
//!   ciphertext `C` is always longer than the plaintext (by `n` bits at most)"): `10*` padding
//!   (`0x80` then zeros) is **always** applied to the final block of both the message and the
//!   associated data, adding a whole extra block when the input is already a block multiple
//!   (including when it is empty) — this is faithful, not this module's invention.
//! - **Checksum / AD folding** (Algorithm 1 lines 8-13, verbatim):
//!   `tag = TBC_13(K, tweak(N, l)) (checksum) ⊕ ⊕_i TBC_11(K, tweak(N, i)) (A_i) ⊕
//!   TBC_12(K, tweak(N, j)) (pad(A_*))`, where `checksum` is the XOR of every (padded) message
//!   block, `l` is the index of the last full message block (or `0` if there is none), and `j` is
//!   the index of the last full AD block (or `0` if there is none). The final AD block is
//!   absorbed **unconditionally**, including when the associated data is empty.
//!
//! This module is verified against an independent transcription of Algorithm 1 in
//! `tests/qcb_spec.rs`, in addition to round-trip, tamper-detection, and parallel-equivalence
//! tests. There are still no designer-published Saturnin-QCB known-answer vectors, so the pinned
//! vectors below remain **self-consistency** vectors derived from this implementation, not
//! third-party KATs.
//!
//! # Key commitment — CTX transform (default-on)
//!
//! The tag emitted by [`Aead::encrypt`] and checked by [`Aead::decrypt`] / [`AeadDecryptSemantic`]
//! is **not** Algorithm 1's raw tag `T`. It is `T' = SaturninHash(label ‖ K ‖ N ‖ T ‖ A)` — the
//! **CTX** committing-AEAD transform (Chan and Rogaway, *On Committing Authenticated-Encryption*,
//! ESORICS 2022; IACR ePrint 2022/1260, Fig. 2 / Theorem 2), instantiated with [`SaturninHash`
//! ](crate::hash::SaturninHash). See `crate::commit` for the exact byte layout, the injectivity
//! argument for why no length prefix is needed, and the three open cryptographer-sign-off
//! obligations (H-1, S-2, Q-1) that keep this **RED** — claimed, not proven, CMT-4.
//!
//! This closes the CMT-1 break demonstrated in `tests/key_commitment.rs`: that test file retains
//! the full attack (padding search + closed-form associated-data solve) as a regression test that
//! now asserts the attack **fails**, and would go red again if this transform were removed.
//! `T'` occupies the same 32-byte offset as the old `T`, so ciphertext length and the raw-body
//! layout are unchanged; only the last 32 bytes carry a different value, and old ciphertexts
//! (pre-CTX, and pre-`bae2717`) do not decrypt under this code.
//!
//! ## Note on the IV/index split inside the 256-bit tweak
//!
//! The paper says only that "the IV and the block number are simply concatenated", and its stated
//! limits ("IVs of at most 160 bits", "up to `2^95` blocks of data") are simultaneously tight only
//! under a 160/96 split, whereas this module splits 128/128. That difference is **not observable
//! here**: with the 16-byte nonce this mode fixes, right-zero-padding the IV to 160 bits (Algorithm
//! 1 line 1, "Pad the initialization vector if necessary") and writing a big-endian index into the
//! low 96 bits gives `N ‖ 0x00·4 ‖ be96(i)`, which for every `i < 2^64` is byte-for-byte the
//! `N ‖ 0x00·8 ‖ be64(i)` built below. The two readings only diverge if an implementation
//! *left*-pads the IV or orders the index little-endian. Absent designer KATs this cannot be
//! settled, but the layout used here is the one both readings agree on.
//!
//! ## Usage Example
//!
//! ```rust
//! # #[cfg(feature = "qcb")]
//! # {
//! use lib_q_saturnin::{
//!     Aead,
//!     AeadKey,
//!     Nonce,
//!     SaturninQcb,
//! };
//!
//! let aead = SaturninQcb::new();
//! let key = AeadKey::new(vec![0u8; 32]);
//! let nonce = Nonce::new(vec![0u8; 16]);
//!
//! let ciphertext = aead
//!     .encrypt(&key, &nonce, b"Secret message", Some(b"metadata"))
//!     .unwrap();
//! let decrypted = aead
//!     .decrypt(&key, &nonce, &ciphertext, Some(b"metadata"))
//!     .unwrap();
//! assert_eq!(decrypted, b"Secret message");
//! # }
//! ```

#[cfg(feature = "alloc")]
use alloc::{
    string::ToString,
    vec::Vec,
};

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

use crate::commit::{
    QCB_CTX_LABEL_V0,
    ctx_tag,
};
use crate::hash::SaturninHash;
use crate::tbc::{
    SaturninTbc,
    TBC_BLOCK_BYTES,
};

/// Domain separator for full message blocks (QCB paper Algorithm 1 line 5, `d=0`).
const DOMAIN_MESSAGE: u8 = 9;
/// Domain separator for the final, padded message block (Algorithm 1 line 7, `d=1`).
const DOMAIN_MESSAGE_FINAL: u8 = 10;
/// Domain separator for full associated-data blocks (Algorithm 1 line 10, `d=2`).
const DOMAIN_AD: u8 = 11;
/// Domain separator for the final, padded associated-data block (Algorithm 1 line 12, `d=3`).
const DOMAIN_AD_FINAL: u8 = 12;
/// Domain separator for the tag / message checksum (Algorithm 1 line 13, `d=4`).
const DOMAIN_TAG: u8 = 13;

/// Block size in bytes (256-bit Saturnin block).
const BLOCK: usize = TBC_BLOCK_BYTES;

/// Result of [`SaturninQcb::open_core`]: `(padded plaintext, raw Algorithm-1 tag T, received
/// tag bytes)`. Named to satisfy `clippy::type_complexity`; see `open_core`'s own doc comment
/// for what each field means and who is responsible for comparing the tags.
type OpenCoreResult = (Zeroizing<Vec<u8>>, Zeroizing<[u8; BLOCK]>, [u8; BLOCK]);

/// Saturnin-QCB AEAD.
///
/// Holds pre-built tweakable block ciphers for the five domains used by the mode, plus a
/// pre-built [`SaturninHash`] for the CTX commitment tag (`crate::commit`), so that per-message
/// work allocates no round constants. Building a `SaturninHash` clocks the round-constant LFSR
/// for both of its domains (see its own field docs) — hoisting it here, rather than inside
/// `commit::ctx_tag`, is what keeps CTX's per-message overhead down to the permutation-call cost
/// the design predicts instead of paying that setup on every `encrypt`/`decrypt` call.
pub struct SaturninQcb {
    msg: SaturninTbc,
    msg_final: SaturninTbc,
    ad: SaturninTbc,
    ad_final: SaturninTbc,
    tag: SaturninTbc,
    committer: SaturninHash,
}

impl SaturninQcb {
    /// Create a new Saturnin-QCB instance.
    pub fn new() -> Self {
        Self {
            msg: SaturninTbc::new(DOMAIN_MESSAGE).expect("domain 9 is valid"),
            msg_final: SaturninTbc::new(DOMAIN_MESSAGE_FINAL).expect("domain 10 is valid"),
            ad: SaturninTbc::new(DOMAIN_AD).expect("domain 11 is valid"),
            ad_final: SaturninTbc::new(DOMAIN_AD_FINAL).expect("domain 12 is valid"),
            committer: SaturninHash::new(),
            tag: SaturninTbc::new(DOMAIN_TAG).expect("domain 13 is valid"),
        }
    }

    /// Key size in bytes (256 bits).
    pub const fn key_size() -> usize {
        32
    }

    /// Nonce size in bytes (128 bits).
    pub const fn nonce_size() -> usize {
        16
    }

    /// Tag size in bytes (256 bits).
    pub const fn tag_size() -> usize {
        BLOCK
    }

    /// Build the 256-bit tweak `N ‖ 0·8 ‖ block_index_be` (QCB paper: "The IV and the block
    /// number are simply concatenated"). Used identically for message and associated-data
    /// tweaks — the nonce must never be zeroed (Section 5, *Avoiding Quantum Attacks*).
    fn tweak(nonce16: &[u8; 16], block_index: u64) -> [u8; BLOCK] {
        let mut t = [0u8; BLOCK];
        t[0..16].copy_from_slice(nonce16);
        t[24..32].copy_from_slice(&block_index.to_be_bytes());
        t
    }

    /// The index of the last full block among `count` full blocks, or `0` if there are none
    /// (Algorithm 1 leaves `l`/`j` undefined in that case; no tweak collision results — see the
    /// module doc).
    fn last_full_index(count: usize) -> u64 {
        count.saturating_sub(1) as u64
    }

    /// `10*`-pad a partial (possibly empty) tail of length `< BLOCK` into exactly one block.
    fn pad_tail(tail: &[u8]) -> [u8; BLOCK] {
        debug_assert!(tail.len() < BLOCK);
        let mut out = [0u8; BLOCK];
        out[..tail.len()].copy_from_slice(tail);
        out[tail.len()] = 0x80;
        out
    }

    /// Authenticate associated data into a 256-bit accumulator.
    ///
    /// Algorithm 1 line 12 absorbs `pad(A_*)` unconditionally, so this always performs at least
    /// one TBC call (domain 12) even when `ad` is empty.
    fn absorb_ad(
        &self,
        key: &[u8; 32],
        nonce16: &[u8; 16],
        ad: &[u8],
    ) -> Result<Zeroizing<[u8; BLOCK]>> {
        let mut auth = Zeroizing::new([0u8; BLOCK]);
        let (full_blocks, tail) = ad.as_chunks::<BLOCK>();
        for (i, chunk) in full_blocks.iter().enumerate() {
            let tweak = Self::tweak(nonce16, i as u64);
            let mut block = *chunk;
            self.ad.encrypt_block(key, &tweak, &mut block)?;
            for k in 0..BLOCK {
                auth[k] ^= block[k];
            }
            block.zeroize();
        }
        let j = Self::last_full_index(full_blocks.len());
        let mut final_block = Self::pad_tail(tail);
        self.ad_final
            .encrypt_block(key, &Self::tweak(nonce16, j), &mut final_block)?;
        for k in 0..BLOCK {
            auth[k] ^= final_block[k];
        }
        final_block.zeroize();
        Ok(auth)
    }

    /// Compute the 256-bit tag over the padded-message checksum and the AD accumulator.
    fn compute_tag(
        &self,
        key: &[u8; 32],
        nonce16: &[u8; 16],
        checksum: &[u8; BLOCK],
        last_index: u64,
        ad_auth: &[u8; BLOCK],
    ) -> Result<Zeroizing<[u8; BLOCK]>> {
        let mut tag = Zeroizing::new(*checksum);
        let tweak = Self::tweak(nonce16, last_index);
        self.tag.encrypt_block(key, &tweak, &mut tag)?;
        for i in 0..BLOCK {
            tag[i] ^= ad_auth[i];
        }
        Ok(tag)
    }

    fn validate_lengths(key: &AeadKey, nonce: &Nonce) -> Result<()> {
        if key.as_bytes().len() != Self::key_size() {
            return Err(Error::InvalidKeySize {
                expected: Self::key_size(),
                actual: key.as_bytes().len(),
            });
        }
        if nonce.as_bytes().len() != Self::nonce_size() {
            return Err(Error::InvalidNonceSize {
                expected: Self::nonce_size(),
                actual: nonce.as_bytes().len(),
            });
        }
        Ok(())
    }

    /// Core message-decryption path, shared by [`decrypt_core`](Self::decrypt_core) and the
    /// bench-only `__bench_only_decrypt_uncommitted` affordance below: validates ciphertext
    /// shape, decrypts every block (full work, no early exit), and recomputes the raw
    /// Algorithm-1 tag `T` — but does **not** check it against anything. Callers own the
    /// comparison: production decrypt checks the received bytes against a freshly recomputed
    /// CTX tag `T'`; the bench-only path checks them directly against `T`.
    ///
    /// This extraction changes no production bytes — `pinned_kat_vectors` below is the guard.
    fn open_core(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<OpenCoreResult> {
        Self::validate_lengths(key, nonce)?;

        // Need at least one message block plus the tag.
        if ciphertext.len() < 2 * BLOCK {
            return Err(Error::aead_ciphertext_shorter_than_tag(
                2 * BLOCK,
                ciphertext.len(),
            ));
        }
        // The body (ciphertext minus tag) must be block-aligned.
        if !ciphertext.len().is_multiple_of(BLOCK) {
            return Err(Error::InvalidCiphertextSize {
                expected: (ciphertext.len() / BLOCK + 1) * BLOCK,
                actual: ciphertext.len(),
            });
        }

        let body_len = ciphertext.len() - BLOCK;
        let body = &ciphertext[..body_len];
        let mut received_tag = [0u8; BLOCK];
        received_tag.copy_from_slice(&ciphertext[body_len..]);
        let m = body_len / BLOCK;
        // The body is `mf` full message blocks (domain 9) plus exactly one final padded block
        // (domain 10); `mf` is `m - 1` since the final block is always present.
        let mf = m - 1;
        let l = Self::last_full_index(mf);

        let mut key_staged = Zeroizing::new([0u8; 32]);
        key_staged.copy_from_slice(key.as_bytes());
        let mut nonce16 = Zeroizing::new([0u8; 16]);
        nonce16.copy_from_slice(nonce.as_bytes());

        // Decrypt every block and accumulate the checksum (full work, no early exit).
        let mut plain = Zeroizing::new(Vec::with_capacity(body_len));
        let mut checksum = Zeroizing::new([0u8; BLOCK]);
        let (body_blocks, _rem) = body.as_chunks::<BLOCK>();
        for (i, chunk) in body_blocks[..mf].iter().enumerate() {
            let tweak = Self::tweak(&nonce16, i as u64);
            let mut block = *chunk;
            self.msg.decrypt_block(&key_staged, &tweak, &mut block)?;
            for k in 0..BLOCK {
                checksum[k] ^= block[k];
            }
            plain.extend_from_slice(&block);
            block.zeroize();
        }
        let mut final_block = body_blocks[mf];
        self.msg_final
            .decrypt_block(&key_staged, &Self::tweak(&nonce16, l), &mut final_block)?;
        for k in 0..BLOCK {
            checksum[k] ^= final_block[k];
        }
        plain.extend_from_slice(&final_block);
        final_block.zeroize();

        let ad_auth = self.absorb_ad(&key_staged, &nonce16, ad)?;
        let base_tag = self.compute_tag(&key_staged, &nonce16, &checksum, l, &ad_auth)?;

        Ok((plain, base_tag, received_tag))
    }

    /// Shared decrypt core for Layer A ([`Aead::decrypt`]) and Layer B
    /// ([`AeadDecryptSemantic::decrypt_semantic`]). Always decrypts the full ciphertext body
    /// before the authentication outcome is allowed to influence the returned plaintext.
    fn decrypt_core(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<DecryptSemanticOutcome> {
        let ad = associated_data.unwrap_or(&[]);
        let (plain, base_tag, received_tag) = self.open_core(key, nonce, ciphertext, ad)?;

        let mut key_staged = Zeroizing::new([0u8; 32]);
        key_staged.copy_from_slice(key.as_bytes());
        let mut nonce16 = Zeroizing::new([0u8; 16]);
        nonce16.copy_from_slice(nonce.as_bytes());

        // CTX verification: recompute T' from the base tag and compare against what was
        // received. Computed unconditionally (before any comparison) so encrypt/decrypt cost
        // stays symmetric and no early exit leaks well-formedness ahead of the tag check.
        let expected_tag = ctx_tag(
            &self.committer,
            QCB_CTX_LABEL_V0,
            &key_staged,
            &nonce16[..],
            &base_tag,
            ad,
        )?;

        let tag_valid = lib_q_core::Utils::constant_time_compare(&*expected_tag, &received_tag);

        if !tag_valid {
            return Ok(DecryptSemanticOutcome::AuthenticationFailed);
        }

        // Authenticated: strip 10* padding (the final block always carries the 0x80 marker).
        let plaintext_len = match unpad_len(&plain) {
            Some(len) => len,
            // Authentic ciphertext we produced always has well-formed padding; treat a malformed
            // (e.g. truncated/forged-yet-matching) layout as an authentication failure.
            None => return Ok(DecryptSemanticOutcome::AuthenticationFailed),
        };
        let mut out = Vec::with_capacity(plaintext_len);
        out.extend_from_slice(&plain[..plaintext_len]);
        Ok(DecryptSemanticOutcome::Success(Zeroizing::new(out)))
    }
}

/// Locate the `10*` padding marker; returns the unpadded length, or `None` if malformed.
fn unpad_len(padded: &[u8]) -> Option<usize> {
    let mut idx = padded.len();
    while idx > 0 && padded[idx - 1] == 0 {
        idx -= 1;
    }
    if idx == 0 || padded[idx - 1] != 0x80 {
        return None;
    }
    Some(idx - 1)
}

impl SaturninQcb {
    /// Core message-encryption path (QCB Algorithm 1 message/AD lines), producing the
    /// ciphertext body and the raw Algorithm-1 tag `T` — *before* CTX replaces it with `T'`.
    /// Shared by [`Aead::encrypt`] and the bench-only `__bench_only_encrypt_uncommitted`
    /// affordance below. This extraction changes no production bytes — `pinned_kat_vectors`
    /// below is the guard.
    fn seal_core(
        &self,
        key_staged: &[u8; 32],
        nonce16: &[u8; 16],
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(Vec<u8>, Zeroizing<[u8; BLOCK]>)> {
        let (full_blocks, tail) = plaintext.as_chunks::<BLOCK>();
        let output_len = (full_blocks.len() + 2) * BLOCK;

        let mut output = Vec::with_capacity(output_len);
        let mut checksum = Zeroizing::new([0u8; BLOCK]);
        for (i, chunk) in full_blocks.iter().enumerate() {
            for k in 0..BLOCK {
                checksum[k] ^= chunk[k];
            }
            let tweak = Self::tweak(nonce16, i as u64);
            let mut block = *chunk;
            self.msg.encrypt_block(key_staged, &tweak, &mut block)?;
            output.extend_from_slice(&block);
            block.zeroize();
        }
        let l = Self::last_full_index(full_blocks.len());
        let mut final_block = Self::pad_tail(tail);
        for k in 0..BLOCK {
            checksum[k] ^= final_block[k];
        }
        self.msg_final
            .encrypt_block(key_staged, &Self::tweak(nonce16, l), &mut final_block)?;
        output.extend_from_slice(&final_block);
        final_block.zeroize();

        let ad_auth = self.absorb_ad(key_staged, nonce16, ad)?;
        let base_tag = self.compute_tag(key_staged, nonce16, &checksum, l, &ad_auth)?;
        Ok((output, base_tag))
    }

    /// **Bench-only measurement affordance — not part of the public security API.**
    ///
    /// Produces a ciphertext with the raw QCB Algorithm-1 tag `T` in place of the CTX-committed
    /// tag `T'`. It exists solely so the `qcb_ctx_overhead` criterion bench can measure the CTX
    /// transform's cost by comparing this path against [`Aead::encrypt`] in the same process.
    ///
    /// This is deliberately **not** a Cargo feature: any feature is public, enumerable, and
    /// enableable by any downstream `Cargo.toml` — exactly the "ship with the security property
    /// switched off" footgun a published crate must not offer. It is also not `cfg(test)`,
    /// which is invisible to external bench targets (they compile against the public API, not
    /// the crate's own test cfg). `#[doc(hidden)]` plus the `__bench_only_` name is the
    /// minimal-exposure alternative that still links from `benches/`, and it is safe to leave
    /// reachable because [`Aead::decrypt`] **rejects** the ciphertext this produces — see
    /// `production_decrypt_rejects_uncommitted_ciphertext` below — so the raw-tag output cannot
    /// be silently shipped as an interoperable peer of the committed AEAD. No semver guarantee.
    #[doc(hidden)]
    pub fn __bench_only_encrypt_uncommitted(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        Self::validate_lengths(key, nonce)?;
        let mut key_staged = Zeroizing::new([0u8; 32]);
        key_staged.copy_from_slice(key.as_bytes());
        let mut nonce16 = Zeroizing::new([0u8; 16]);
        nonce16.copy_from_slice(nonce.as_bytes());
        let ad = associated_data.unwrap_or(&[]);

        let (mut output, base_tag) = self.seal_core(&key_staged, &nonce16, plaintext, ad)?;
        output.extend_from_slice(&*base_tag);
        Ok(output)
    }

    /// **Bench-only measurement affordance — not part of the public security API.**
    ///
    /// Counterpart to [`Self::__bench_only_encrypt_uncommitted`]: verifies the raw tag `T`
    /// directly instead of recomputing and checking `T'`. Needed because decrypt-side CTX cost
    /// is otherwise unmeasured anywhere in this repo. Same non-guarantees as the encrypt-side
    /// affordance above — `#[doc(hidden)]`, no semver guarantee, bench-only.
    #[doc(hidden)]
    pub fn __bench_only_decrypt_uncommitted(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let ad = associated_data.unwrap_or(&[]);
        let (plain, base_tag, received_tag) = self.open_core(key, nonce, ciphertext, ad)?;
        let tag_valid = lib_q_core::Utils::constant_time_compare(&*base_tag, &received_tag);
        if !tag_valid {
            return Err(Error::VerificationFailed {
                operation: "Saturnin-QCB bench-only tag verification".to_string(),
            });
        }
        let plaintext_len = unpad_len(&plain).ok_or_else(|| Error::VerificationFailed {
            operation: "Saturnin-QCB bench-only tag verification".to_string(),
        })?;
        let mut out = Vec::with_capacity(plaintext_len);
        out.extend_from_slice(&plain[..plaintext_len]);
        Ok(out)
    }
}

impl Aead for SaturninQcb {
    fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        Self::validate_lengths(key, nonce)?;

        let mut key_staged = Zeroizing::new([0u8; 32]);
        key_staged.copy_from_slice(key.as_bytes());
        let mut nonce16 = Zeroizing::new([0u8; 16]);
        nonce16.copy_from_slice(nonce.as_bytes());
        let ad = associated_data.unwrap_or(&[]);

        let (mut output, base_tag) = self.seal_core(&key_staged, &nonce16, plaintext, ad)?;
        // CTX (Chan-Rogaway, ESORICS 2022): replace the base tag with
        // T' = SaturninHash(label || K || N || T || A) at the same offset and width. See
        // `crate::commit` for the byte layout and the open sign-off obligations.
        let committed_tag = ctx_tag(
            &self.committer,
            QCB_CTX_LABEL_V0,
            &key_staged,
            &nonce16[..],
            &base_tag,
            ad,
        )?;
        output.extend_from_slice(&*committed_tag);
        Ok(output)
    }

    fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match self.decrypt_core(key, nonce, ciphertext, associated_data)? {
            DecryptSemanticOutcome::Success(p) => Ok(Vec::clone(&*p)),
            DecryptSemanticOutcome::AuthenticationFailed => Err(Error::VerificationFailed {
                operation: "Saturnin-QCB tag verification".to_string(),
            }),
        }
    }
}

impl AeadDecryptSemantic for SaturninQcb {
    fn decrypt_semantic(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<DecryptSemanticOutcome> {
        self.decrypt_core(key, nonce, ciphertext, associated_data)
    }
}

impl Default for SaturninQcb {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn key() -> AeadKey {
        AeadKey::new((0..32u8).collect::<Vec<_>>())
    }

    fn nonce() -> Nonce {
        Nonce::new((0..16u8).collect::<Vec<_>>())
    }

    #[test]
    fn constants() {
        assert_eq!(SaturninQcb::key_size(), 32);
        assert_eq!(SaturninQcb::nonce_size(), 16);
        assert_eq!(SaturninQcb::tag_size(), 32);
    }

    #[test]
    fn round_trip_various_lengths() -> Result<()> {
        let aead = SaturninQcb::new();
        for len in [0usize, 1, 15, 31, 32, 33, 64, 100, 256] {
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let ct = aead.encrypt(&key(), &nonce(), &pt, Some(b"hdr"))?;
            // Always-pad: body is padded message (multiple of 32) plus a 32-byte tag.
            let expected_body = (len / 32 + 1) * 32;
            assert_eq!(ct.len(), expected_body + 32, "len={len}");
            let dec = aead.decrypt(&key(), &nonce(), &ct, Some(b"hdr"))?;
            assert_eq!(dec, pt, "len={len}");
        }
        Ok(())
    }

    #[test]
    fn empty_message_and_ad() -> Result<()> {
        let aead = SaturninQcb::new();
        let ct = aead.encrypt(&key(), &nonce(), b"", None)?;
        assert_eq!(ct.len(), 64); // one padding block + tag
        assert_eq!(aead.decrypt(&key(), &nonce(), &ct, None)?, b"");
        Ok(())
    }

    #[test]
    fn tampered_tag_fails() -> Result<()> {
        let aead = SaturninQcb::new();
        let ct = aead.encrypt(&key(), &nonce(), b"hello world", Some(b"ad"))?;
        let mut bad = ct.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(matches!(
            aead.decrypt(&key(), &nonce(), &bad, Some(b"ad")),
            Err(Error::VerificationFailed { .. })
        ));
        assert_eq!(
            aead.decrypt_semantic(&key(), &nonce(), &bad, Some(b"ad"))?,
            DecryptSemanticOutcome::AuthenticationFailed
        );
        Ok(())
    }

    #[test]
    fn tampered_body_fails() -> Result<()> {
        let aead = SaturninQcb::new();
        let ct = aead.encrypt(&key(), &nonce(), b"hello world", None)?;
        let mut bad = ct.clone();
        bad[0] ^= 0x80;
        assert!(aead.decrypt(&key(), &nonce(), &bad, None).is_err());
        Ok(())
    }

    #[test]
    fn ad_is_authenticated() -> Result<()> {
        let aead = SaturninQcb::new();
        let ct = aead.encrypt(&key(), &nonce(), b"msg", Some(b"header-A"))?;
        // Wrong AD must fail.
        assert!(
            aead.decrypt(&key(), &nonce(), &ct, Some(b"header-B"))
                .is_err()
        );
        // Missing AD must fail.
        assert!(aead.decrypt(&key(), &nonce(), &ct, None).is_err());
        Ok(())
    }

    #[test]
    fn nonce_binding() -> Result<()> {
        let aead = SaturninQcb::new();
        let ct = aead.encrypt(&key(), &nonce(), b"msg", None)?;
        let other = Nonce::new(vec![0xFFu8; 16]);
        assert!(aead.decrypt(&key(), &other, &ct, None).is_err());
        Ok(())
    }

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Pinned self-consistency vectors for this instantiation (key = 00..1f, nonce = 00..0f).
    ///
    /// These are **derived** from the construction in this module (Saturnin TBC + the documented
    /// QCB instantiation + the CTX committing transform, `crate::commit`), not official designer
    /// KATs — see the module-level instantiation note. They lock the byte-level behavior so any
    /// accidental change to padding, tweak encoding, domains, AD folding, or the CTX tag is
    /// caught. **Regenerated for CTX** (card `t_16ddf21c`): the first `body_len` bytes of each
    /// ciphertext are unchanged from the pre-CTX vectors (the message/padding path is untouched);
    /// only the last 32 bytes (the tag) differ, because they now carry `T'` instead of `T`.
    #[test]
    fn pinned_kat_vectors() -> Result<()> {
        let aead = SaturninQcb::new();
        let cases: &[(&str, &str, &str)] = &[
            (
                "",
                "",
                "718cd938614ad4c64e971ae1df9a657e290f3d862e5429088a7066642b07b29a43ead5af07dd8584bf26c66f6108d158a405ce09ffc2ae90dd90acddb026cfb5",
            ),
            (
                "",
                "6173736f636961746564",
                "718cd938614ad4c64e971ae1df9a657e290f3d862e5429088a7066642b07b29a4cb54a56eb5210bf60d35e3b7d4f318b0e4a767347d6eb2fcbaf86c297fe4ff1",
            ),
            (
                "616263",
                "",
                "f4620482177e4946c61ae01ff424a467ab76d31a63e75d045d3daaad64909edf7c8b3d483bfa34f0a7bff18c1dcb8655f13076de2718c3f2eeef9e9cb51de4cb",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "686472",
                "16e51991ae3cb7cb92f3847c326188cb007267ece8153d03aeb98d4f161c84a7718cd938614ad4c64e971ae1df9a657e290f3d862e5429088a7066642b07b29afbb45d2adaed3857a7fb65416c2255f9de2e5ecfb0f77561c4de67fce9d08010",
            ),
            (
                "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672121",
                "61642d31",
                "fe81caa8f1ee16e54fd7b3df31247e7ccd4295382cff4f9f7efefb5e970c68809248800e70f51a3ba933d3332dbe0d0b4f49c2eab471f2bf9370c582289efeb0ec1107ab2a8caa1b6afdbfeb2cca665a197ee3cd1a98de6cde368d6c318d04c2",
            ),
        ];
        for (pt_hex, ad_hex, ct_hex) in cases {
            let pt = from_hex(pt_hex);
            let ad = from_hex(ad_hex);
            let ad_opt = if ad.is_empty() {
                None
            } else {
                Some(ad.as_slice())
            };
            let ct = aead.encrypt(&key(), &nonce(), &pt, ad_opt)?;
            assert_eq!(
                ct,
                from_hex(ct_hex),
                "encrypt mismatch for pt={pt_hex} ad={ad_hex}"
            );
            let dec = aead.decrypt(&key(), &nonce(), &ct, ad_opt)?;
            assert_eq!(dec, pt, "decrypt mismatch for pt={pt_hex} ad={ad_hex}");
        }
        Ok(())
    }

    #[test]
    fn parallel_block_independence() -> Result<()> {
        // QCB is rate-one and embarrassingly parallel: each ciphertext block depends only on its
        // own plaintext block, the key, the nonce, and its index. Changing one plaintext block
        // must change only that ciphertext block (the tag aside).
        let aead = SaturninQcb::new();
        let mut a = vec![0u8; 96]; // 3 blocks
        let mut b = a.clone();
        b[40] ^= 0xFF; // flip a byte in block 1
        let ca = aead.encrypt(&key(), &nonce(), &a, None)?;
        let cb = aead.encrypt(&key(), &nonce(), &b, None)?;
        // Block 0 (bytes 0..32) identical; block 1 (32..64) differs.
        assert_eq!(ca[0..32], cb[0..32]);
        assert_ne!(ca[32..64], cb[32..64]);
        assert_eq!(ca[64..96], cb[64..96]); // block 2 unchanged
        a.zeroize();
        b.zeroize();
        Ok(())
    }

    #[test]
    fn unpad_len_handles_valid_and_malformed() {
        // Valid 10* padding: marker then zeros.
        assert_eq!(unpad_len(&[1, 2, 3, 0x80, 0, 0]), Some(3));
        assert_eq!(unpad_len(&[0x80]), Some(0));
        // Malformed: no marker (all zeros, or trailing non-zero that isn't 0x80).
        assert_eq!(unpad_len(&[0, 0, 0]), None);
        assert_eq!(unpad_len(&[]), None);
        assert_eq!(unpad_len(&[1, 2, 3]), None);
    }

    #[test]
    fn default_matches_new() -> Result<()> {
        let a = SaturninQcb::default();
        let b = SaturninQcb::new();
        let pt = b"compare";
        assert_eq!(
            a.encrypt(&key(), &nonce(), pt, None)?,
            b.encrypt(&key(), &nonce(), pt, None)?
        );
        Ok(())
    }

    #[test]
    fn wrong_size_inputs_rejected() {
        let aead = SaturninQcb::new();
        assert!(
            aead.encrypt(&AeadKey::new(vec![0u8; 16]), &nonce(), b"x", None)
                .is_err()
        );
        assert!(
            aead.encrypt(&key(), &Nonce::new(vec![0u8; 8]), b"x", None)
                .is_err()
        );
        // Ciphertext shorter than one block + tag.
        assert!(aead.decrypt(&key(), &nonce(), &[0u8; 40], None).is_err());
        // Non block-aligned body.
        assert!(aead.decrypt(&key(), &nonce(), &[0u8; 65], None).is_err());
    }

    // --- Bench-only affordance tests (measurement lane) -----------------------------------
    //
    // These pin the property the `qcb_ctx_overhead` bench and the safety argument in the doc
    // comments above both depend on: the bench-only path takes a genuinely different tag route
    // (RED phase below proves that, not just that the two names happen to alias one code path),
    // and production `decrypt` refuses to accept what it produces.

    #[test]
    fn uncommitted_shares_body_but_not_tag() -> Result<()> {
        let aead = SaturninQcb::new();
        let committed = aead.encrypt(&key(), &nonce(), b"hello world", Some(b"ad"))?;
        let uncommitted =
            aead.__bench_only_encrypt_uncommitted(&key(), &nonce(), b"hello world", Some(b"ad"))?;
        assert_eq!(committed.len(), uncommitted.len());
        let body_len = committed.len() - 32;
        // Same message/AD path (seal_core) produces the same body bytes...
        assert_eq!(committed[..body_len], uncommitted[..body_len]);
        // ...but the last 32 bytes (the tag) differ: committed carries T', uncommitted carries
        // the raw Algorithm-1 tag T. (RED phase: asserting these EQUAL fails — see progress
        // file r3-measurement-impl.md for the verbatim failure — proving this is a genuinely
        // different tag path, not an alias of the committed one.)
        assert_ne!(committed[body_len..], uncommitted[body_len..]);
        Ok(())
    }

    #[test]
    fn production_decrypt_rejects_uncommitted_ciphertext() -> Result<()> {
        let aead = SaturninQcb::new();
        let uncommitted =
            aead.__bench_only_encrypt_uncommitted(&key(), &nonce(), b"hello world", Some(b"ad"))?;
        // The production decryptor recomputes CTX's T' and compares against the received bytes;
        // a raw-tag ciphertext must be rejected, not silently accepted as if it were committed.
        // (RED phase: asserting `.is_ok()` here fails — see progress file
        // r3-measurement-impl.md for the verbatim failure.)
        assert!(matches!(
            aead.decrypt(&key(), &nonce(), &uncommitted, Some(b"ad")),
            Err(Error::VerificationFailed { .. })
        ));
        assert_eq!(
            aead.decrypt_semantic(&key(), &nonce(), &uncommitted, Some(b"ad"))?,
            DecryptSemanticOutcome::AuthenticationFailed
        );
        Ok(())
    }

    #[test]
    fn uncommitted_round_trip() -> Result<()> {
        let aead = SaturninQcb::new();
        for len in [0usize, 1, 31, 32, 100] {
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let ct = aead.__bench_only_encrypt_uncommitted(&key(), &nonce(), &pt, Some(b"hdr"))?;
            let dec = aead.__bench_only_decrypt_uncommitted(&key(), &nonce(), &ct, Some(b"hdr"))?;
            assert_eq!(dec, pt, "len={len}");
        }
        // A flipped tag bit must be rejected.
        let mut bad = aead.__bench_only_encrypt_uncommitted(&key(), &nonce(), b"msg", None)?;
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(
            aead.__bench_only_decrypt_uncommitted(&key(), &nonce(), &bad, None)
                .is_err()
        );
        Ok(())
    }
}
