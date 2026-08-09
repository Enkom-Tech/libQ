# Changelog

Crate-local changelog for `lib-q-saturnin`. The workspace-wide `CHANGELOG.md` at the repo root is
authoritative for cross-crate and release-level entries; this file tracks changes scoped to this
crate in more detail than the root file carries.

## Unreleased

### BREAKING — `qcb` is no longer a default feature (fe64036, 2026-08-06)

`qcb` (and therefore `SaturninQcb`, `lib_q_saturnin::commit`, and `QCB_CTX_LABEL_V0`) has been
removed from this crate's `default` feature set. **Reason:** a single repeated nonce under
`SaturninQcb` is a universal forgery — catastrophic integrity loss, not merely a keystream leak
(see `src/qcb.rs` module docs and `lib-q-romulus/SECURITY.md`'s nonce-reuse table) — and as of
this change it has zero call sites in any consumer crate (GIP, uGrid, My-Grid, Bitlink all reach
Saturnin through `SaturninAead`/CTR-Cascade, which degrades to a keystream leak on nonce reuse
instead). A default-on mode with that failure mode and no callers was assessed as a liability, so
it is now opt-in. The mode itself is unchanged and not deprecated — it remains the rate-1,
per-block-parallel candidate for the Saturnin hardware programme.

**Migration:** any downstream `Cargo.toml` that depended on `SaturninQcb`/`commit`/
`QCB_CTX_LABEL_V0` being reachable without listing a feature must add `features = ["qcb"]`
explicitly:

```toml
lib-q-saturnin = { version = "...", features = ["qcb"] }
```

No workspace crate in this repo enables `qcb`, so nothing in-tree needed this migration. This
change landed on `main` after the `0.0.10` release (`0.0.10` still ships `qcb` as default); it
will ship as a breaking change in the next release that includes it.

### Changed — security documentation only (2026-08-07 primary-source review; **no code change**)

- **Adversarial review of the review (same day, same sources re-opened).** Four corrections to
  the entries below, plus four overclaims elsewhere in the crate that the review pass had listed
  but not fixed. No RED marker was lifted at any point; none was reinstated because none had been
  removed. Corrections: (1) Saturnin-Hash attack depths are **super-rounds of 16**, not rounds of
  32 — see the CORRECTION under the `~2^75` entry below, and the newly-recorded 10/16 free-start
  line; (2) Theorem 3's privacy term is `qH / 2^(δ+τ)` with `δ` a free integer and `τ` the base
  scheme's expansion — the first draft wrote `qH/2^(κ+λ)` with an invented "`κ+λ = 512`"; (3) the
  constant-`τ` hypothesis is immaterial to Theorem 2 but **not** to Theorem 3, whose bound and
  App. B reduction (`C*` "of the length `δ + τ`") both presuppose one `τ`, so `SaturninQcb`'s
  33..=64-byte range needs a worst-case reading (`SaturninAeadCtx` is unaffected, its expansion
  really is constant); (4) 2025/387's replacement chain is **Thm 3** + Thm 4 + Cor 1 — Thm 4 and
  Cor 1 only equate the three compositions and are vacuous without Thm 3's positive result.
  Also fixed: `src/tbc.rs` called Saturnin16 "the related-key-secure variant" as fact and stated
  no security model; `src/aead.rs` — the module for the **frozen** mode Q-2 actually lands on —
  carried no Q-2 note at all; `src/lib.rs`'s crate-root bullets advertised "Provable security" and
  a "256-bit security level" against a designer claim of 224-bit; `tests/qcb_spec.rs` still read
  as if Q-1 were narrow.

- **The CTX sign-off register went from three obligations to five, and nothing closed.** The
  papers behind H-1, S-2 and Q-1 were unobtainable when those obligations were written; they are
  now on file and were read. Outcome: **S-2 narrowed**, **Q-1 widened**, and **L-1**, **RK-1** and
  **Q-2** opened. `SaturninQcb` and `SaturninAeadCtx` both stay **RED**. Every claim below is a
  quote from a named paper; the full text lives in `src/commit.rs`, `src/aead_ctx.rs` and
  `src/qcb.rs`.

  - **S-2 — narrowed to a confirmation, not closed.** Chan and Rogaway's §4 setup does say "The
    core `C` is the same length as `M`. As such, `E1` is bijective when `K, N, A` are fixed" (IACR
    ePrint 2022/1260 p.9), and Saturnin-QCB violates it: `pad_tail` always writes `0x80`, so
    `|core| − |M| ∈ 1..=32` always. But `|C| = |M|` is **not load-bearing in Theorem 2** — it is
    the premise of an inference *to* bijectivity, and the proof uses only the injective half
    ("there exists only one `M` such that `E1(Ki, N, A, M) = C`", p.10). The authors restate the
    operative property as injectivity twice themselves (p.2–3, p.4), and Bellare–Hoang reach it
    independently for this transform family ("the pair `(M, N)` will be committed via the
    decryption correctness requirement of `SE`", IACR ePrint 2024/875 p.11). **It is still not a
    citation closure**: no published theorem states CTX's committing security under the weaker
    hypothesis. Bellare–Hoang's Theorem 3.3 is about **CTY**, not CTX — they explicitly "omit a
    statement and proof about the security of our general form of CTX because we are going to
    improve it to CTY" (2024/875 p.12) — and IACR ePrint 2022/268 contains zero occurrences of
    "CTX" and zero of "tag-based". Also newly documented: a **second** Chan–Rogaway syntactic
    requirement QCB violates, "its expansion, which is a constant `τ` such that
    `|E(K,N,A,M)| = |M| + τ`" (2022/1260 p.4) — our total expansion ranges over 33–64 bytes.
    Theorem 2's proof never mentions `τ`, but a reviewer must say so rather than us assuming it.

  - **Q-1 — widened; the gap is structural, not notational.** Theorem 3 is not merely *stated*
    classically: its authenticity reduction `B3` recovers the base tag only by inverting a
    recorded table of the adversary's own hash queries — "Now `B3` selects particular entries in
    its table `HT` … It then iterates through all such entries" (2022/1260, App. B) — which
    no-cloning forbids under superposition queries. Second, QCB supplies exactly the hypothesis
    pair a published counterexample defeats: it proves IND-qCPA and BZ / plus-one unforgeability,
    while Lang, Leuther and Lucks (IACR ePrint 2025/387, Thm 1) construct an IND-qCPA scheme plus
    a plus-one unforgeable MAC whose EtM composition is IND-qCCA **insecure**; their positive
    results all need the MAC to be a **qPRF**, which QCB does not claim. *Scope:* CTX is a
    tag-replacement transform, not EtM, so that counterexample does not apply directly — what it
    destroys is the intuition that classical composition results carry to Q2. Third, blind
    unforgeability does not rescue it: QCB is blindly unforgeable (Leuther and Lucks, IACR ePrint
    2023/1653, Thm 1), but that paper's revised front-matter **withdraws** the BU ⇒ PO
    implication, so BU and PO are incomparable — which also makes the QCB paper's own "Theorem 6
    ([1], Theorem 1). Any BU-unforgeable MAC is BZ-unforgeable" a retracted claim; do not cite it.
    Sharpest residual: BZ is a *counting* notion and Theorem 3's `B3` makes `qe + 1` queries, so a
    BZ win at the CTX layer hands `B3` one forgery too few to win BZ against QCB. Negative
    evidence recorded so nobody re-runs the search: the committing-AE papers on file (2022/1260,
    2022/268, 2024/875, 2025/320, 2026/1222) contain **zero** occurrences of "quantum", "QROM" or
    "superposition".

  - **L-1 (new; both instantiations)** — CTX's nAE-preservation proof is **single-user and
    single-verification-query**: "Chan and Rogaway [16] only consider a restricted setting where
    the adversary attacks just a single user, and it can only make a single verification query.
    Translating this result to the general setting via a hybrid argument will lead to a very poor
    bound" (2024/875 p.12), corroborated by Theorem 3's own proof, where `A2` "terminates with a
    forgery `(N2, A2, C2 ‖ T2)`" (2022/1260 App. B, p.26). Orthogonal to both S-2 (Theorem 2 has
    no oracles) and Q-1 (query counts, not oracle model). Bellare–Hoang's good multi-user bound,
    Theorem 3.4, is for **CTY**.

  - **RK-1 (new; `SaturninQcb` only, about the base mode)** — the designers claim Saturnin16
    related-key security only "against related-key attacks involving a small number of keys",
    footnoted "with related-key deriving functions satisfying the conditions of [BK03]" (LWC spec
    §1.2), while QCB's key-tweak insertion uses `Φ_⊕` over a 95-bit index, i.e. up to `2^95`
    related keys per key. Nobody has said whether `2^95` is inside that scope.

  - **Q-2 (new; the *base* mode, so it lands on the frozen `SaturninAead` too — not on
    `SaturninQcb`)** — the Saturnin spec's IND-qCCA claim for CTR-Cascade rests on a citation
    that has since been disproved. §4.3.1: "Soukharev, Jao and Seshadri have revisited these
    results [SJS16], and proved that the encrypt-then-MAC composition offers IND-qCCA security,
    assuming that the encryption scheme is IND-qCPA, and the MAC is SUF-qCMA." IACR ePrint
    2025/387 disproves exactly that ("we disprove a claim made by Soukharev et al. at PQCrypto
    2016"; "[SJS16, Theorem 3.6] … is inconclusive"). The conclusion looks **repairable** —
    2025/387's Theorem 3 (with Theorem 4 / Corollary 1 carrying it from EatM to EtM — Thm 4 and
    Cor 1 alone are vacuous, they only equate the three compositions) needs the MAC to be a
    *qPRF*, and the spec argues precisely
    that for Cascade via "Theorem 5.1 in [SY17]" (§4.3.3), the stronger hypothesis — but the
    citation swap is unratified, with the spec's own caveats (constant block count; "This proof
    seems not tight") and 2025/387's caution that "we are not aware of any practical MAC, which
    has been proven to be a qPRF".

- **Saturnin-QCB's security model is now named everywhere it is claimed: ideal cipher, classical
  tweaks. It was previously stated nowhere, which reads as the standard model.** `src/qcb.rs`
  gained a *Security model* section and `SECURITY.md` a matching block. Sources: the Saturnin
  update note §5, "*In the ideal-cipher model*, we can prove the indistinguishability and
  unforgeability of QCB under quantum chosen-plaintext attacks … The proof assumes that nonces are
  not controlled by the adversary and not reused"; the QCB paper §6.3, "the first statement holds
  in the standard model, the second in the ideal cipher model" — the *second* is the one covering
  a block-cipher instantiation like ours. QCB's standard-model statements are about an abstract
  (S)TPRP-secure TBC and do not reach `E(K ⊕ T, ·)`; Mennink (CRYPTO 2017; IACR ePrint 2017/474,
  Theorem 4 / Corollary 1) argues, heuristically and under his Assumption 1, that *optimal*
  standard-model security is out of reach for tweak-rekeyable TBCs of exactly this shape. This is
  a **doc bug fixed by citation**, not a new gate. `src/qcb.rs`'s opening claim of "a tighter
  quantum-security proof than Saturnin-CTR-Cascade" was rewritten: it named no model and compared
  a proof against CTR-Cascade's *claim*.

  The same sections now state **where the Q2 claim stops**: the proof lets the adversary put the
  *message* in superposition and fixes classical, pre-declared tweaks (QCB §4.1). Superposition
  *tweak* queries are a total break, because here the tweak is the key offset — QCB §4.2: "It
  admits a simple distinguisher based on Simon's algorithm if the tweaks are queried in
  superposition: this is the quantum related-key attack of [31]. Indeed, the function
  `f(δ) = E_K(0) ⊕ E_{K⊕δ}(0)` admits `K` as a period" (Rötteler–Steinwandt, IACR ePrint
  2013/378). Generic to every block cipher, but it is the boundary of what this crate may claim.

- **The `~2^75` quantum collision figure is a corner of a time–memory claim, not a flat number.**
  Corrected in `src/commit.rs` and `README.md`. Verbatim (LWC spec §2.4): "There exists no quantum
  collision attack verifying `T^5 × M_q < 2^448`", with `M_q` the quantum memory in 256-qubit
  registers; `2^75` is the designers' own worst corner ("because we necessarily have `M_q < T`"),
  while a memoryless attacker (`M_q = 1`) gets `2^89.6` from the same inequality. H-1's write-up
  also now records why the cryptanalysis settles nothing in either direction: no attack exists on
  full Saturnin-Hash, the best in-model classical result is a chosen-prefix collision on **6 of
  the 16 super-rounds** (12 of 32 rounds) *at* the claimed floor (Chen, Dong, Guo and Zhang, ToSC
  2024(4) / IACR ePrint 2024/1888 §6.1: "the overall time complexity of this 6-round CPC attack on
  Saturnin-hash is `2^112 + 2^96 ≈ 2^112`"), and the best in-model quantum result is **7 of 16
  super-rounds** at `2^113.5` — `2^38.5` *above* the `2^75` corner. Out-of-model free-start
  collisions on the compression function reach **10 of 16 super-rounds** at `2^127.2` (Chen et
  al., IACR ePrint 2022/731 §5.2); they do not apply because Saturnin-Hash is MMO with a fixed
  `IV = 0`, but they are recorded so the margin is not read as larger than it is.

  **CORRECTION 2026-08-07 (post-review):** the first version of this entry and of H-1 in
  `src/commit.rs` wrote these depths as "6 of 32 rounds" / "7 of 32 rounds" and omitted the
  free-start line. That was wrong — the Saturnin-Hash cryptanalysis literature counts in
  **super-rounds of 16** (Dong et al., IACR ePrint 2021/1119, tabulate "5/16", "7/16", "8/16";
  Chen et al., 2022/731 §5, "Saturnin-Hash is built on 16-super-round Saturnin block cipher"; Bao
  et al., 2021/427 App. E, round function over "16-bit `supernibbles`" via "the 16-bit
  Super-Sbox"). The error halved the attacked depth and made the primitive the CMT-4 claim rests
  on look safer than the literature shows. Corrected in `src/commit.rs`, `src/qcb.rs` and
  `SECURITY.md`.

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

  **SUPERSEDED 2026-08-07 (obligation list only):** this instantiation now also carries **L-1**
  (Chan–Rogaway's Theorem 3 is single-user and single-verification-query) and **Q-2** (CTR-Cascade's
  own IND-qCCA claim rests on the disproved [SJS16] composition theorem, so Q-2 lands on the frozen
  `SaturninAead` as well). Q-1′ was *widened*. See the *Changed — security documentation only*
  section at the top of Unreleased.

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

  **SUPERSEDED 2026-08-07 (count only; the entry above is otherwise accurate):** the register is
  now **five** obligations, H-1, S-2, Q-1, L-1 and RK-1, with S-2 narrowed and Q-1 widened. See
  the *Changed — security documentation only* section at the top of Unreleased.

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
