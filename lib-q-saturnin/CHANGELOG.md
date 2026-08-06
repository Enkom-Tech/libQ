# Changelog

Crate-local changelog for `lib-q-saturnin`. The workspace-wide `CHANGELOG.md` at the repo root is
authoritative for cross-crate and release-level entries; this file tracks changes scoped to this
crate in more detail than the root file carries.

## Unreleased

### Added

- **`SaturninAeadCtx`: CTX committing-AEAD transform on `SaturninAead` (CTR-Cascade).** A
  2026-08-06 consumer survey found `SaturninQcb` (the only mode CTX had been wired to) has zero
  real consumers, while every product (GIP, uGrid, My-Grid, Bitlink) reaches Saturnin through
  `SaturninAead`. This adds the same CTX transform (Chan-Rogaway, ESORICS 2022; IACR ePrint
  2022/1260) to CTR-Cascade, instantiated with `SaturninHash`, as a **new, separate, opt-in type**
  — not a change to `SaturninAead`. `SaturninAead`'s wire output is byte-for-byte **unchanged**
  (pinned by the new `tests/aead_kat_pin.rs`, generated from the pre-change tree); it is data
  loss to change that format in place, since it already encrypts stored data (My-Grid vault,
  My-Grid recovery, GIP's `bitlink-wrapkey-argon2id-v1`). `SaturninAeadCtx` ciphertext is a
  wire-incompatible new format at the same layout offsets (`C ‖ T'`, `T'` at the same 32-byte tag
  position `T` occupied) — never interchangeable with plain `SaturninAead`'s output (see
  `tests/cascade_ctx_spec.rs::cross_mode_ciphertexts_rejected`).

  **The two types are wire-incompatible but not keystream-independent.** CTX replaces only the
  tag, so the ciphertext body is CTR-Cascade's in both cases, and CTR-Cascade's keystream is a
  function of `(K, N)` alone (the AD does not enter it). Encrypting different plaintexts under the
  same key and nonce with `SaturninAead` and `SaturninAeadCtx` is therefore a two-time pad —
  `C_plain ⊕ C_ctx == M_plain ⊕ M_ctx` — and either plaintext reveals the other. **A migration
  re-encrypt must draw a fresh nonce**; a distinct type protects the wire format, not the nonce
  discipline. Documented in `src/aead_ctx.rs`, the README row, and on `create_saturnin`.

  New label `CASCADE_CTX_LABEL_V0 = b"libq.saturnin.cascade.ctx.v0"` in `src/commit.rs`, alongside
  the existing `QCB_CTX_LABEL_V0`; the two share a 14-byte prefix and diverge at a fixed byte
  offset, so no cross-mode `H_input` can coincide without a genuine Saturnin-Hash collision. The
  shared `commit::ctx_tag` function is reused, not forked. `src/aead.rs` gained two additive,
  `pub(crate)`-only changes (no production-byte impact, guarded by the KAT pin): `ctr_encrypt`
  widened from private, and a new `base_tag_over` helper that is a pure extraction of the tag
  computation already present in `decrypt_core`/`encrypt_bytes`.

  **S-2 does not apply to this instantiation** (unlike QCB, where it remains open): CTR-Cascade is
  a stream mode with `|C| == |M|` exactly and no message padding, which satisfies Chan-Rogaway
  Theorem 2's length/bijectivity hypothesis natively. **H-1** (is Saturnin-Hash's designer-claimed
  collision bound the right number to publish) carries over verbatim, shared with `SaturninQcb`.
  A new obligation, **Q-1′**, is opened: CTX's own nAE-preservation proof is classical-ROM only,
  and whether it preserves CTR-Cascade's own quantum-adversary security claims is, as far as this
  change's author could determine, not covered by published analysis. **The mode is marked RED**
  — a claimed, not proven, CMT-4 construction — pending human cryptographer sign-off, same as
  `SaturninQcb`. Full argument in `src/aead_ctx.rs` module docs.

  Two new test files: `tests/aead_kat_pin.rs` (the `SaturninAead` wire-format freeze guard) and
  `tests/cascade_ctx_spec.rs` (independent transcription gate + label/key/nonce/AD/base-tag
  binding tests + cross-mode rejection + a pinned `SaturninAeadCtx` KAT), both landed red-first /
  with built-in falsification. No fabricated CMT-1 attack test was added: no cheap CMT-1 break is
  known for CTR-Cascade (a 256-bit tag over a 256-bit cascade state with no GHASH-like algebraic
  structure), so — as with the existing `lib-q-aead/tests/key_commitment.rs` bounded searches — a
  clean result would not be evidence of commitment; the new tests cover the transform's properties
  instead.

  No new Cargo feature: gated on `all(feature = "aead", feature = "hash")`, both already default
  features, so the type is available with zero migration friction and no new string for CI/docs.rs
  to forget. `src/lib.rs`'s `commit` module gate widened from `qcb` to
  `any(qcb, all(aead, hash))` — the stale comment's stated plan, `any(qcb, aead)`, would not have
  compiled (`aead` does not imply `hash`, and `commit.rs` needs `SaturninHash`).

### Changed — BREAKING (wire format)

- **`SaturninQcb` now applies the CTX committing-AEAD transform.** The last 32 bytes of every
  ciphertext change: `SaturninQcb::encrypt` used to emit Algorithm 1's raw tag `T` there; it now
  emits `T' = SaturninHash(label ‖ K ‖ N ‖ T ‖ A)` — the **CTX** transform (Chan and Rogaway, *On
  Committing Authenticated-Encryption*, ESORICS 2022; IACR ePrint 2022/1260, Fig. 2 / Theorem 2).
  Ciphertext **length** is unchanged (CTX's expansion is zero: `T'` occupies exactly the 32 bytes
  `T` occupied); only the tag's **value** changes. Nothing produced by this crate before this
  change decrypts under this code, and there is no compatibility flag (see the root
  `CHANGELOG.md`'s equivalent note on the `bae2717` QCB Algorithm-1 fix for the precedent — this is
  the second QCB wire break in the same unreleased 0.0.10 cycle, so it costs nothing that has not
  already been spent).

  This closes card `t_16ddf21c`'s demonstrated CMT-1 break: `tests/key_commitment.rs` retains the
  full attack (a `~2^8`-try padding search plus a closed-form solve for the second side's
  associated data) verbatim as a regression test, which now asserts the attack **fails** — the
  previously-successful `qcb_is_not_key_committing_ad_is_solvable_in_closed_form` test is replaced
  by `qcb_ctx_defeats_the_closed_form_ad_solve`, asserting the search still finds a candidate, side
  1 still decrypts, and side 2 now fails tag verification.

  New module `src/commit.rs` holds the transform (`QCB_CTX_LABEL_V0`, `ctx_tag`) and its byte
  layout, injectivity argument, and the three open cryptographer-sign-off obligations (H-1: is
  Saturnin-Hash's designer-claimed 2^112-classical / ~2^75-quantum collision bound the right number
  to publish; S-2: does QCB's `10*`-padded `E1` satisfy Chan-Rogaway's structural hypothesis via
  mere injectivity rather than length-preserving bijectivity; Q-1: does CTX preserve QCB's
  superposition-query (Q2) unforgeability, given CTX's own nAE-preservation proof is only in the
  *classical* ROM). **The mode is marked RED** — a claimed, not proven, CMT-4 construction —
  pending human cryptographer sign-off on those three obligations.

  `Cargo.toml`'s `qcb` feature now implies `hash` (`qcb = ["dep:zeroize", "hash"]`), since the CTX
  tag is computed with `SaturninHash`. `SaturninQcb` gained a `committer: SaturninHash` field (built
  once in `new()`, mirroring the existing pre-built-`SaturninTbc` pattern) so the per-message cost
  is the hash's compression-call cost, not its one-time round-constant setup — an earlier draft
  that built a fresh `SaturninHash` per call measured roughly 2x the overhead this shipped version
  measures, entirely in per-call LFSR setup that had nothing to do with the transform itself.

  Five pinned self-consistency vectors in `qcb::tests::pinned_kat_vectors` were regenerated (never
  hand-written — computed by running the implementation and capturing its own output). The
  independent Algorithm-1 conformance oracle in `tests/qcb_spec.rs` was extended to also
  reconstruct the CTX layer from scratch (via the public `SaturninHash` API, not by importing
  `commit::ctx_tag`), so its existing full-ciphertext comparisons keep covering both layers. A new
  `tests/qcb_ctx_spec.rs` independently re-derives `T'` from the documented byte layout and checks
  it against `SaturninQcb::encrypt`'s actual output, plus dedicated label/key/nonce/AD binding
  tests, each with a built-in falsification control.

  `SaturninAead` (CTR-Cascade) was **not** given a committing transform by this change — it remains
  non-committing (open follow-up, see card `t_16ddf21c`). `SaturninShortAead` was evaluated and is
  **not committing and will not be made committing**: it is not tag-based (no CTX-shaped transform
  applies), and any transform that adds bytes is strictly size-dominated by `SaturninQcb` at the
  same ciphertext length with more function (see `src/aead_short.rs`'s `key_commitment_tests`
  module docs for the full argument).

### Performance

- `SaturninQcb::encrypt`/`decrypt` cost more, and the added cost is front-loaded onto small
  messages (a fixed number of extra Saturnin permutation calls) rather than scaling with message
  size. A scratch (non-criterion) timing check, not part of the checked-in `benches/` suite,
  measured roughly **+75% to +130%** at message sizes at or below 64 bytes, falling to **within
  ~10% (often indistinguishable from run-to-run noise)** at 1 KiB and above with no/small
  associated data, and growing again with associated-data size (roughly **+10%** at 0-64 B AD on a
  1 KiB message up to **+85-90%** at 4 KiB AD) — CTX hashes the associated data a second time, on
  top of QCB's own AD pass. See `lib-q-saturnin/README.md` for the numbers and the reproduction
  caveat (this crate's `benches/` suite does not yet have a QCB benchmark group; adding one is a
  separate open item, not owned by this change).

### Fixed — documentation

- **Corrected the rationale given for Saturnin-Hash's `2^112` classical / `~2^75` quantum
  collision-resistance claim, repo-wide.** The numbers were always right and are unchanged; six
  docs (`lib-q-aead/README.md`, `lib-q-duplex-aead/README.md`, `lib-q-rocca-s/README.md`,
  `lib-q-romulus/SECURITY.md`, `lib-q-saturnin/README.md`, `lib-q-tweak-aead/README.md`) and
  `src/commit.rs` glossed them as "not the naive `256/2 = 128` bits", implying `2^128` was never a
  real generic bound. The Saturnin designers' own spec §5.4.1 gives `2^128` as the best-known
  generic classical collision cost (birthday bound on a 256-bit random function) and states the
  claim is held below it for margin — "additional constant factors that these bounds do not take
  into account, which is why our final security claims are reduced" — not because of a NIST-LWC
  floor. Replaced the gloss with that rationale plus the best-known generic quantum figures
  everywhere it appeared. (Those figures were themselves miscited at the time and were corrected
  later: `2^85.3 = 2^(n/3)` with qRAM is **Brassard–Høyer–Tapp**, LATIN '98, not CNS; CNS 2017 is
  the `2^102.4 = 2^(2n/5)` figure, and it is qRAM-free rather than memory-free, needing `2^51.2`
  classical memory. The memoryless generic is `2^128`.) Also corrected `src/block_cipher.rs`, `src/hash.rs`, `src/stream.rs` and
  this crate's `README.md` "Security" section, which each claimed a flat "256-bit post-quantum
  security" — a level the Saturnin submission never claims, and one contradicted by its own
  block-cipher claim box (spec §2.1: no quantum attack in the single-key setting with
  `T/p < 2^112`); replaced with the actual per-primitive claim boxes from LWC spec §2.1–§2.4. No
  code, wire format or security decision changed.
- **`docs/HARDWARE.md`: corrected the domain-separator accounting.** It previously said "fourteen
  of sixteen domain values are spoken for" while listing QCB as domains 9–11; QCB in fact uses
  9–13 (`qcb.rs`), and with the submission's own Table 2 (spec §2.5, domains 0–8) that leaves
  exactly two values — 14 and 15 — unassigned. The same section now also records that the block
  cipher and stream cipher run at domain 1 rather than claiming domains of their own.
