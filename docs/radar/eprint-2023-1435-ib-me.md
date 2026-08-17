# IB-ME with enhanced CCA privacy (ePrint 2023/1435) — radar disposition

Status: **radar / out of scope — not adopted.** This note dispositions IACR ePrint
2023/1435 for the `iacr-radar` import (board card `ENK-459`). It is a triage record, not a
finding against any shipped primitive: the paper describes constructions that `lib-q` does
**not** implement and, for its concrete scheme, cannot implement without contradicting the
workspace threat model.

- **Paper:** "Identity-Based Matchmaking Encryption with Enhanced Privacy Against
  Chosen-Ciphertext Attacks." <https://eprint.iacr.org/2023/1435>
- **Authors:** Sohto Chiku, Keitaro Hashimoto, Keisuke Hara, Junji Shikata.
- **Category:** public-key cryptography (identity-based matchmaking encryption, IB-ME).
- **Radar classifier verdict:** `high (conf 0.95) — identity-based encryption`.

## Disposition: not applicable to a post-quantum workspace

The radar classifier flagged this "high relevance" on the keyword *identity-based
encryption*. That is a **false positive** against `lib-q`'s actual scope, for two
independent reasons:

1. **`lib-q` ships no identity-based (or matchmaking) encryption at all.** There is no
   IBE, no IB-ME, and no elliptic-curve pairing / bilinear-group arithmetic anywhere in the
   workspace. There is nothing here for this paper to improve, attack, or interoperate with.
2. **The paper's concrete scheme is not post-quantum.** Its first (and only fully specified)
   construction is proven under the **Bilinear Diffie–Hellman (BDH)** assumption in the
   random oracle model. BDH is a pairing/discrete-log–type assumption, which a
   quantum adversary breaks with Shor's algorithm. That directly contradicts
   [`docs/security.md`](../security.md) threat-model item 1 — *"quantum-capable adversaries
   can break classical public-key schemes (RSA, ECC, and similar)"* — so adopting it would
   regress, not extend, the library's stated guarantee.

Either reason alone is dispositive. Recorded here so the card is closed on a documented
rationale rather than silently dropped, matching how the other `iacr-radar` cards
(`ENK-457`, `ENK-458`, `ENK-541`, `ENK-542`) were folded into the tree.

## What the paper actually contains (from the abstract)

The paper proposes **two** IB-ME schemes that simultaneously achieve enhanced privacy
against chosen-ciphertext attacks (CCA) — the first schemes to do so, per the authors:

- **Scheme 1 — concrete, pairing-based.** Built on the **bilinear Diffie–Hellman**
  assumption in the **random oracle model**. Inspired by the original Ateniese et al. IB-ME
  (CRYPTO 2019 / J. Cryptology 2021); the authors report *more compact decryption keys and
  ciphertexts* than that scheme while attaining stronger security. **Not post-quantum**
  (see above).
- **Scheme 2 — generic / primitive-agnostic.** A generic construction from **anonymous IBE
  + digital signatures + NIZK proof systems + reusable extractors**, generalizing the
  concrete Francati et al. scheme (INDOCRYPT 2021) with techniques to resolve the CCA
  issues. Claimed to be the first IB-ME reaching the stronger notions in the **standard
  model** (no random oracle).
- **Taxonomy contribution.** Classifies IB-ME *authenticity* notions into four categories —
  **no-message attacks (NMA)** and **chosen-message attacks (CMA)**, each against
  **insiders** and **outsiders** — enabling precise comparison across IB-ME schemes.

## Why even the generic (Scheme 2) construction is not buildable from `lib-q` today

Scheme 2 is primitive-agnostic, so in principle a *post-quantum* IB-ME could be assembled by
instantiating its building blocks with PQ-secure components. That is **out of scope and not
currently possible from this workspace**, because the required blocks are only partly
present:

| Scheme 2 building block | Present in `lib-q`? |
|-------------------------|---------------------|
| Anonymous identity-based encryption | **No** — no IBE of any kind (PQ IBE exists from lattices in the literature, but is not implemented here). |
| Digital signatures | Yes — ML-DSA, SLH-DSA, FN-DSA (`lib-q-ml-dsa`, `lib-q-slh-dsa`, `lib-q-fn-dsa`). |
| NIZK proof system | Partial — a transparent STARK stack (`lib-q-zkp`), not a general-purpose NIZK targeted at this construction's relations. |
| Reusable extractor | **No** — not provided as a reusable primitive. |

The two missing blocks (anonymous IBE, reusable extractor) are the load-bearing ones, and
adding an IBE subsystem is a major new cryptographic surface, not a radar follow-up. No work
is proposed here.

## Recommendation

- **No code, wire-format, dependency, or test change.**
- Keep IB-ME / matchmaking encryption **off** the roadmap: it is neither a NIST PQC track
  primitive nor buildable from current `lib-q` components, and its concrete instantiation is
  pre-quantum.
- Should IB-ME ever be revisited, the paper's **NMA/CMA × insider/outsider authenticity
  taxonomy** is the useful transferable artifact for specifying security goals; its concrete
  BDH scheme is not.

## Verification — verified vs inferred

**Verified (by running / reading in-repo):**

- `lib-q` declares no pairing/IBE/IB-ME crate: no such entry in root `Cargo.toml`
  `[workspace].members`; a workspace grep for `pairing|bilinear|IBE|identity-based` returns
  only lattice/STARK math and unrelated hits, no elliptic-curve pairing code.
- [`docs/security.md`](../security.md) threat model states quantum adversaries break classical
  public-key schemes (item 1 / "Adversary Capabilities").
- The paper's title, authors, category, and abstract are quoted from the `ENK-459` card
  (which reproduces the ePrint 2023/1435 abstract verbatim).

**Inferred (reasoned, not machine-checked):**

- BDH is a pairing/discrete-log–type assumption and is therefore broken by a quantum
  adversary (Shor). This is standard cryptographic background, not a claim re-derived here.
- A PQ instantiation of Scheme 2 is *conceivable* but not buildable from `lib-q` today; the
  building-block table reflects current crate coverage, not an exhaustive audit of every
  construction the STARK stack could be coerced into.

**Could not verify (environment):** the microVM has no outbound network (git proxy only), so
the full PDF of 2023/1435 was not fetched; all paper-specific claims above rest on the
abstract as reproduced on the card. Nothing in this note depends on details beyond the
abstract.
