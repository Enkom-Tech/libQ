//! CTX committing-AEAD transform, shared by `SaturninQcb` and `SaturninAeadCtx`.
//!
//! `ctx_tag` (`pub(crate)`) is generic over the label and the base mode; it is instantiated twice in this
//! crate, once per base AEAD, each with its own label so the two instantiations' hash inputs can
//! never collide (see [`QCB_CTX_LABEL_V0`] / [`CASCADE_CTX_LABEL_V0`]):
//!
//! - **`SaturninQcb`** (`crate::qcb`) — the original instantiation. Its mode-specific security
//!   posture (including the open S-2 obligation, which is specific to QCB's `10*`-padded core,
//!   and RK-1, which is specific to QCB's key-tweak-insertion TBC) is documented on `crate::qcb`
//!   and below.
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
//! classical collision attack below `2^112`. Their quantum collision claim is a *time–memory*
//! claim, verbatim "There exists no quantum collision attack verifying `T^5 × M_q < 2^448`"
//! (`M_q` = quantum memory in 256-qubit registers); its worst corner, which the designers state
//! themselves, is `T < 2^75` "because we necessarily have `M_q < T`", while a memoryless attacker
//! (`M_q = 1`) gets `2^89.6` out of the same inequality. Every `~2^75` in this crate is that worst
//! corner, not the whole claim (LWC spec §1.2/§2.4); by Theorem 2 it is the CMT-4 bound this
//! transform inherits. The
//! best-known generic classical collision cost for a 256-bit random function is `2^128` by the
//! birthday bound (LWC spec §5.4.1); the designers claim below that bound for margin — "additional
//! constant factors that these bounds do not take into account, which is why our final security
//! claims are reduced" (§5.4.1) — **not** because of a NIST-LWC floor. Best-known generic quantum
//! collision costs at `n = 256`, all three of which the `2^75` claim sits below:
//! `2^85.3 = 2^(n/3)` with `2^85.3` qRAM (Brassard–Høyer–Tapp, LATIN '98); `2^102.4 = 2^(2n/5)`
//! with no qRAM but `2^51.2 = 2^(n/5)` classical memory (Chailloux–Naya-Plasencia–Schrottenloher,
//! 2017); and `2^128` memoryless. An earlier version of this note credited BOTH the first two
//! figures to CNS and described the second as needing no memory at all; the first is BHT's, and
//! CNS is qRAM-free rather than memory-free. Do not round `2^112` up to `2^128` in any doc that
//! cites it.
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
//! cryptographer's sign-off. **Five** obligations are open (see `lib-q-saturnin/README.md` and
//! `CHANGELOG.md`, card `t_16ddf21c`) — three named at the 2026-08-06 review, plus **L-1** and
//! **RK-1**, added on 2026-08-07 when the primary sources were read. That review **narrowed S-2**
//! and **widened Q-1**; nothing was closed:
//!
//! - **H-1** — is 2^112 classical / ~2^75 quantum (Saturnin-Hash's own claim) the right number to
//!   publish? The cryptanalysis does **not** settle it in either direction and it cannot be
//!   closed by citation. Nothing argues the claim *down*: there is no attack on full
//!   Saturnin-Hash. **Read the round counts in this literature carefully — they are in
//!   *super-rounds*, and an earlier draft of this bullet halved the attacked depth by reading
//!   them as rounds.** Saturnin-Hash is Saturnin16, i.e. 16 super-rounds = 32 rounds, and the
//!   papers write their results as fractions of 16: Dong et al. (ASIACRYPT 2021 / IACR ePrint
//!   2021/1119) tabulate "Collision 5/16", "7/16 … Quantum", "Free-start 8/16"; Chen et al.
//!   (IACR ePrint 2022/731 §5) restate the target as "Saturnin-Hash is built on 16-super-round
//!   Saturnin block cipher with the MMO hashing mode"; and Bao et al. (IACR ePrint 2021/427
//!   App. E) describe their round function as acting on "16-bit `supernibbles`" via "the 16-bit
//!   Super-Sbox", which is the super-round representation. In those units:
//!   - Best **in-model classical** result: a chosen-prefix collision on **6 of 16 super-rounds**
//!     (12 of 32 rounds) *at* — not below — the claimed floor (Chen, Dong, Guo and Zhang,
//!     ToSC 2024(4) / IACR ePrint 2024/1888 §6.1: "the overall time complexity of this 6-round
//!     CPC attack on Saturnin-hash is `2^112 + 2^96 ≈ 2^112`", whose `2^112` term is itself a
//!     generic birthday search; that paper improves the collision line "from 5 to 6 rounds",
//!     the 5 being Dong et al.'s tabulated 5/16).
//!   - Best **in-model quantum** result: **7 of 16 super-rounds** (14 of 32) at `2^113.5`
//!     (Dong et al., tabulated "7/16 … 2^113.5 … Quantum"), i.e. `2^38.5` *above* the `2^75`
//!     corner.
//!   - **Out-of-model** free-start results go deeper still and must not be omitted just because
//!     they do not apply: Dong et al. reach 8/16 at `2^122.5` and Chen et al. (2022/731 §5.1–5.2)
//!     improve that to `2^89.65` and then give "the first 10-round free-start quantum collision
//!     attack … with two more rounds than Dong et al.'s result", at `2^127.2` for **10 of 16
//!     super-rounds** (20 of 32). These are outside the claimed model — Saturnin-Hash is MMO with
//!     a fixed `IV = 0`, so the adversary does not get to choose the chaining value — but 10/16 is
//!     the same depth the designers' own related-key attack reaches on the block cipher, so the
//!     "free-start is out of scope" line in item 3 below is doing real work and is not a formality.
//!
//!   Arguing the claim *up* (say to BHT's `2^85.33` generic floor) is possible on
//!   paper but is a security-visible change to a designer's published number, which is precisely
//!   what this obligation gates. Three things a cryptographer must actually sign:
//!   1. Theorem 2 bounds an *advantage* — `Adv^{CMT-4}_{CTX}(A) ≤ Adv^{col}_H(B)` — whereas the
//!      Saturnin claim is about attack *cost* `T` (quantumly `T^5 × M_q`). The cost-to-advantage
//!      conversion we publish is a modelling step the designers did not make.
//!   2. Which corner of `T^5 × M_q < 2^448` belongs in a CMT-4 statement: `2^75` (`M_q → T`), or
//!      a named larger figure for a qRAM-bounded adversary.
//!   3. That CTX's use of `H` — `K` absorbed as a message *prefix* of an unkeyed MMO hash —
//!      requires only plain collision resistance, so the free-start line of results stays out of
//!      scope.
//! - **S-2 — narrowed 2026-08-07; resolved on the merits, residual is a confirmation, not a
//!   research question.** Chan–Rogaway's §4 setup says "The core `C` is the same length as `M`.
//!   As such, `E1` is bijective when `K, N, A` are fixed" (2022/1260 p.9), and Saturnin-QCB
//!   violates that literal hypothesis: `pad_tail` always writes a `0x80` marker, so
//!   `|core| = 32·(⌊|M|/32⌋ + 1)` and `|core| − |M| ∈ 1..=32` always. **But `|C| = |M|` is not
//!   load-bearing in Theorem 2.** It appears only as the premise of an inference *to*
//!   bijectivity, and the proof never uses the surjective half. What the proof consumes is one
//!   sentence — "there exists only one `M` such that `E1(Ki, N, A, M) = C`" (p.10) — i.e. that
//!   `M` is a *function* of `(K, N, A, C)`. Chan–Rogaway say this themselves twice: CTX commits
//!   to `M` "from the injectivity of the map from the ciphertext core `C` to the plaintext `M`
//!   when `K, N`, and `A` are all fixed" (p.2–3), and "a notable property of correct schemes is
//!   how encryption is injective from `M` to `C` when `K, N, A` are fixed" (p.4) — so decryption
//!   correctness alone yields the property. Bellare–Hoang reach the same conclusion
//!   independently for this transform family: "the pair `(M, N)` will be committed via the
//!   decryption correctness requirement of `SE`" (2024/875 p.11), in a framework whose tidiness
//!   definition carries **no** length relation and whose expansion is a *function* `SE.ce(m)`,
//!   not a constant (p.9, p.12). Working the CAE game's four cases (each winning tuple comes
//!   from an ENC or a DEC query) closes every one using only "`D1` is deterministic and
//!   `D1 ∘ E1 = id`"; the `unpad_len -> None` branch is irrelevant to all four, because it only
//!   rejects cores outside `E1`'s image and both winning messages are valid by definition.
//!   `SaturninQcb` satisfies the operative hypothesis: `decrypt` is deterministic and correct,
//!   `10*` padding is injective, and each block is a TBC permutation under a tweak that depends
//!   only on `(nonce, index)` and not on message content — so `E1(K, N, A, ·)` is injective. It
//!   is also *tidy* in Bellare–Hoang's sense, so it additionally satisfies their stronger
//!   hypothesis. **Residual for a reviewer:** confirm (i) the proof-inspection reading above,
//!   (ii) the injectivity/tidiness argument for our `E1`, and (iii) that Chan–Rogaway's *other*
//!   violated syntactic requirement — "its expansion, which is a constant `τ` such that
//!   `|E(K,N,A,M)| = |M| + τ`" (p.4), which our padding also breaks, total expansion ranging
//!   over 33..=64 bytes — is immaterial to Theorem 2, whose proof never mentions `τ`, as it is
//!   to Bellare–Hoang's `SE.ce(m)` framework. That third point was not previously documented.
//!   **Scope that third point to Theorem 2 and nothing else.** Non-constant `τ` is *not*
//!   immaterial to Theorem 3: `τ` appears in Theorem 3's privacy bound as the exponent term
//!   `qH / 2^(δ+τ)`, and its App. B reduction has `B2` query its own oracle and get "back a
//!   response `C*` of the length `δ + τ`" — a step that presupposes a single `τ` for the scheme.
//!   For `SaturninQcb`, `τ` is a *range* (33..=64 bytes), so that leg of Theorem 3 needs a
//!   worst-case reading before it can be quoted. This is an nAE-preservation problem, not a
//!   committing-security problem, so it belongs with Q-1/L-1 rather than with S-2 — but it is
//!   listed here because it is the same `τ` hypothesis. `SaturninAeadCtx` is unaffected: its
//!   expansion really is the constant 32 bytes.
//!   **No published theorem states CTX's committing security under the weaker hypothesis.**
//!   Bellare–Hoang's Theorem 3.3 (2024/875 p.12) is about **CTY**, not CTX, and they explicitly
//!   "omit a statement and proof about the security of our general form of CTX because we are
//!   going to improve it to CTY" (p.12). Do not cite Theorem 3.3 as a CTX result. ePrint
//!   2022/268 is not relevant at all: it contains zero occurrences of "CTX" and zero of
//!   "tag-based", and does not cite Chan–Rogaway.
//! - **Q-1** — CTX's own nAE-preservation proof (Theorem 3, ePrint 2022/1260) is in the
//!   *classical* random-oracle model. Saturnin-QCB exists specifically for resistance to
//!   superposition-query (Q2) adversaries — precisely: adversaries that query the *message* in
//!   superposition, with nonces and tweaks classical and pre-declared (QCB §4.1), which is the
//!   strongest model QCB can have, since superposition tweaks recover the key outright (see
//!   `crate::qcb`, *Security model*). On the 2026-08-07 review of the primary sources this
//!   obligation got **wider, not narrower**, and the gap is **structural rather than
//!   notational**:
//!   1. **Theorem 3's authenticity reduction is classical transcript replay.** Its adversary `B3`
//!      recovers the base tag `T` from the CTX tag `T'` only by inverting a recorded table of the
//!      adversary's own hash queries — "Now `B3` selects particular entries in its table `HT` …
//!      It then iterates through all such entries" (2022/1260, App. B). Under superposition hash
//!      queries no such table can exist (no-cloning), so the argument would have to be rebuilt on
//!      Zhandry compressed oracles. The privacy legs are lazily-sampled-RO game hops with the
//!      same defect ("two tables keeping track of random oracle entries, `HT` and `ET`").
//!   2. **QCB supplies exactly the hypothesis pair a published counterexample defeats.** QCB
//!      proves IND-qCPA (its Thm 4) and BZ / plus-one unforgeability (its Thm 5: "Let A succeed
//!      if it outputs q + 1 valid quadruples"). Lang, Leuther and Lucks (IACR ePrint 2025/387,
//!      Thm 1) prove: "If IND-qCPA\[LoR\] secure encryption schemes and qPRFs exist, then there
//!      exists an IND-qCPA\[LoR\] secure encryption scheme SE and a plus-one unforgeable MAC F,
//!      such that the Encrypt-then-MAC composition of SE and F is IND-qCCA\[LoR\] insecure."
//!      Their positive results all require the MAC to be a **qPRF**, which QCB does not claim.
//!      *Scope, exactly:* CTX is a tag-replacement transform, **not** the EtM composition of a
//!      separate cipher and MAC, so this counterexample does **not** apply to CTX-of-QCB
//!      directly. What it destroys is the informal "classical composition results carry over to
//!      Q2" intuition that made this obligation look like a formality. It is not one.
//!   3. **Blind unforgeability does not rescue it.** QCB *is* blindly unforgeable (Leuther and
//!      Lucks, IACR ePrint 2023/1653, Thm 1), which does kill 2025/387's specific counterexample
//!      MAC. But 2023/1653's revised front-matter withdraws the implication that would have made
//!      this a strengthening: "a claim from \[2\] was repeated, that blind unforgeability (BU)
//!      implies plus-one unforgeability (PO) … has been withdrawn in an updated version of
//!      \[2\]". BU and PO are therefore **incomparable** — note this makes the QCB paper's own
//!      "Theorem 6 (\[1\], Theorem 1). Any BU-unforgeable MAC is BZ-unforgeable" a *retracted*
//!      claim; do not cite it. 2025/387 adds "In this work, we do not provide any results about
//!      blind unforgeability", and lists BU-based composition as open Future Work. Ruling out one
//!      counterexample is not a composition theorem.
//!
//!   **What a cryptographer would still have to sign**, precisely: (a) a QROM / compressed-oracle
//!   restatement of Theorem 3's `B1`, `B2` and `B3`; and (b) a base-notion match, since Theorem 3
//!   reduces to *classical* `Adv^priv` / `Adv^auth` while QCB provides IND-qCPA and BZ. The
//!   `auth` leg is the sharp one: BZ is a **counting** notion (`q` queries ⇒ `q+1` forgeries) and
//!   Theorem 3 states "If `A2` makes `qe` encryption oracle queries, then `B3` makes `qe + 1`
//!   queries to its own oracle" — so a BZ win at the CTX layer hands `B3` one forgery too few to
//!   win BZ against QCB. That off-by-one is invisible under classical single-forgery `auth` and
//!   fatal under BZ. Until both are signed, **claim no Q2 property for `T'`**: the Q2 results
//!   quoted in `crate::qcb` are QCB's own and cover the raw tag `T`, not the CTX tag. The privacy
//!   bound's residual term is the *smaller* worry, but state it correctly: Theorem 3 writes it
//!   `qH / 2^(δ+τ)`, where `δ ≥ 0` is the free integer the analyst fixes in the theorem statement
//!   and `τ` is the base scheme's expansion — **not** a key length. (An earlier draft of this
//!   bullet wrote it `qH/2^(κ+λ)` with "`κ+λ = 512`"; those symbols are not in the paper and the
//!   instantiation was invented. Corrected 2026-08-07.) Its semantics are a "did the adversary
//!   query `H` at the secret key" union bound (game `G3`, App. B), and its QROM analogue would be
//!   expected to degrade roughly quadratically, which at any sane `δ` is not where this
//!   obligation bites. What `τ` *does* cost us is recorded in S-2's residual (iii): our `τ` is a
//!   range, not a constant. Negative evidence, so nobody re-runs the search: the committing-AE
//!   literature
//!   on file (2022/1260, 2022/268, 2024/875, 2025/320, and the 2026/1222 universal-transform
//!   paper) contains **zero** occurrences of "quantum", "QROM" or "superposition".
//! - **L-1 — CTX's nAE-preservation proof is single-user and single-verification-query.** New
//!   2026-08-07; previously undocumented; applies to **both** instantiations, since both inherit
//!   Theorem 3. Bellare–Hoang, 2024/875 p.12: "Chan and Rogaway \[16\] only consider a restricted
//!   setting where the adversary attacks just a single user, and it can only make a single
//!   verification query. Translating this result to the general setting via a hybrid argument
//!   will lead to a very poor bound." Corroborated by Theorem 3's own proof, in which `A2`
//!   "terminates with a forgery `(N2, A2, C2 ‖ T2)`" (2022/1260 App. B, p.26) — one forgery, one
//!   key. This is **orthogonal to S-2**: Theorem 2, the committing bound, has no oracles at all
//!   and is unaffected. It is also **orthogonal to Q-1**, which is about the classical-vs-Q2
//!   oracle model rather than query counts. Consequence: any multi-user or multi-verification
//!   deployment claim for these types rests on a hybrid argument we have not performed and which
//!   Bellare–Hoang expect to be lossy. Their Theorem 3.4 does give a good multi-user bound — but
//!   for **CTY**, not CTX.
//! - **RK-1** (new 2026-08-07, `SaturninQcb` only; about the *base mode*, not the CTX transform)
//!   — the Saturnin designers claim Saturnin16 related-key security only "against related-key
//!   attacks involving a small number of keys", footnoted "with related-key deriving functions
//!   satisfying the conditions of \[BK03\]" (LWC spec §1.2). QCB's key-tweak insertion uses
//!   `Φ_⊕` over the whole tweak space; with `crate::qcb`'s 95-bit block index that is up to
//!   `2^95` related keys per key. Nobody has stated whether `2^95` is inside the claimed scope. A
//!   cryptographer must sign either that it is, or a lower per-key block cap that keeps us inside
//!   it. This obligation is **not** about the ideal-cipher model itself — that question is closed
//!   by citation (see `crate::qcb`, *Security model*): both the QCB authors and the Saturnin
//!   designers state the ideal-cipher model in print, so naming it is a documentation duty, not
//!   an open problem.
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
