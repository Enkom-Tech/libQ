# Radar triage: ePrint 2026/1003 — Blockchain Access Control with Hidden Attributes and Policies

Board card `ENK-477` (project `iacr-radar`). Paper: *A Blockchain-Based Access Control
Scheme with Hidden Attributes and Policies Using Commitments and Zero-Knowledge Proofs*,
Yuanshao Liang, Hui Li, Wenhui Hu, Wu Zhou, Baocheng Yan, Kedan Li, Naixing Wu, Kaili Shao,
IACR ePrint 2026/1003 (<https://eprint.iacr.org/2026/1003>). Radar relevance tag:
"zero-knowledge & credentials" (medium, conf 0.75).

Status: **evaluated — out of scope, not adopted.** This is a **triage note**, not a security
claim against any shipped primitive. Everything below is either read out of the paper / this
tree (marked **VERIFIED**) or a fit judgement (marked **INFERRED**). Nothing here was reviewed
by a cryptographer. No `lib-q` runtime code changed on this branch.

## 1. What the paper is (VERIFIED — read end-to-end via the IACR reader)

A blockchain access-control protocol `Π_AC = {Setup, AttrAuth, PolicyUpload, ProveAccess,
VerifyAccess, DecryptData}` that lets a smart contract verify "requester attributes satisfy the
data provider's policy" while learning only the accept/reject bit — hiding both the attribute
vector and the policy vector.

- **Vectorized predicate (§III-B).** Each attribute domain's accepted values become roots of a
  fixed-degree polynomial `f_i`; the policy vector `y` packs the weighted coefficients
  `ρ_i · a_{i,k}`, and the requester's attribute vector `x` packs the monomial evaluations
  `(1, L_i, …, L_i^{n_i})`. Then `⟨x, y⟩ = Σ_i ρ_i f_i(L_i)`, which is `0` iff every clause is
  satisfied. A false accept happens with probability `≤ 1/(q−1)`. So **policy matching is
  reduced to a hidden inner-product-equals-zero relation.**
- **Commitments (§III-A).** Multi-generator **Pedersen** commitments in a prime-order group `G`
  where DL is hard: `C = B^r · Π_j G_j^{v_j}`. Perfectly hiding, computationally binding under
  **discrete log**. Each attribute authority `AA_i` commits to its local block on a disjoint
  generator interval; the global attribute commitment is the public product `C_x = Π_i C_i`.
- **Authority certification (§III-D, §V).** Each `AA_i` **Schnorr-signs** `(ID_DR, pk_DR, i, C_i)`.
  The contract checks the signatures and the aggregation `C_x = Π_i C_i` *in the clear* — these
  are public predicates, deliberately outside the ZK proof.
- **Access proof (§V-B).** One linked commit-and-prove NIZK `π_match` for the relation
  `R_cip = {(C_x, C_y; x, y, r_x, r_y) | C_x, C_y open correctly ∧ ⟨x,y⟩ = 0}`, built from the
  Bootle-et-al. discrete-log inner-product argument [EUROCRYPT'16] compressed with the
  **Bulletproofs** [S&P'18] recursive IPA to `O(log m)` size, made non-interactive by
  **Fiat–Shamir in the ROM**. Openings are proved with a multi-base **Schnorr–Okamoto**
  representation protocol. `π_AC = π_match` (no separate opening transcript).
- **Data path.** `AES-GCM` for the payload; the symmetric key is released off-chain over an
  authenticated channel after the contract accepts; an on-chain digest `h` binds the ciphertext.
- **Security (VERIFIED as stated, NOT independently checked).** Three theorems:
  *policy hiding* and *attribute hiding* reduce to **perfect Pedersen hiding + NIZK zero
  knowledge**; *authenticated attribute integrity* reduces to **Schnorr EUF-CMA + Pedersen
  computational binding**. All are classical (PPT-adversary) reductions.

### Concrete numbers (VERIFIED — paper §VII, Tables I–IV; NOT reproduced here)

| Quantity | Value | Source |
|---|---|---|
| Group | Ristretto255 (`curve25519-dalek`), `\|G\| = \|Z_q\| = 32 B` | §VII, Table I |
| Signatures / hash / AEAD | `ed25519-dalek`, SHA-2, AES-GCM, `rand`/`rand_chacha` | §VII, Table I |
| Access proof `π_AC` size | `(64·log₂ m + 192)` B | Table II, §VIII |
| Access-verification record | `(64·log₂ m + 353)` B — **< 1 KB at m = 512** | Table III, §VIII |
| Final decryption | **0.103 ms**, independent of `m` | Table IV (m=512), §VIII |
| Setup / attr-auth cost | **linear** in `m` (`64m+64` B, `41m` B) | Table III |
| Eval dimensions | `m ∈ {16, 32, 64, 128, 256, 512}`, block size 4 (`m = 4N`) | §VII |

**Reproducibility caveat (VERIFIED — paper §VII).** The public Rust prototype
(<https://github.com/liangyuanshao/zk_vector_commitment_access_control>) implements commitment,
signature, encryption, ledger, and the end-to-end workflow, **but the access-proof component
"uses a protocol-level simulator and the logarithmic proof-size model."** The Bulletproof IPA
is therefore **modeled, not executed**: the sub-1 KB / `O(log m)` proof figures are analytic,
and the Proof-Gen / Proof-Verify columns of Table IV time the surrounding protocol, not a real
recursive IPA over Ristretto255.

## 2. Where libQ actually sits (VERIFIED — read out of the tree)

The topical home is `lib-q-lattice-zkp` (BLNS-style module-lattice anonymous credentials) and
the STARK credential stack in `lib-q-zkp`.

- **libQ is a post-quantum library and bans exactly this stack.**
  [`docs/security.md`](../../docs/security.md) states the threat model assumes quantum
  adversaries and lists ECC / DH / ECDH / RSA as "Broken by Shor's algorithm."
  [`scripts/security_check_classical_crypto.py`](../../scripts/security_check_classical_crypto.py)
  is a CI gate whose `CLASSICAL` ban set includes **`curve25519-dalek`, `ed25519-dalek`,
  `aes-gcm`, `sha2`, and `bulletproofs`** — i.e. every asymmetric/ZK dependency the paper's
  prototype uses. Grepping the workspace `Cargo.toml`s for `dalek|bulletproof|curve25519`
  returns **nothing**.
- **`lib-q-zkp` excludes DL/Bulletproof ZK by design.**
  [`lib-q-zkp/src/lib.rs`](../../lib-q-zkp/src/lib.rs) (`ProofType`) documents that "Classical
  pairing/discrete-log-based schemes (SNARKs, Bulletproofs) are intentionally excluded because
  those assumptions are broken by a quantum computer"; the only variant is transparent
  `Stark`. `docs/security.md` argues ZKP soundness from SHAKE256 + FRI, "**not** from a
  classical discrete-log or pairing assumption."
- **libQ already has the post-quantum analog of the paper's core gadget.**
  `lib-q-lattice-zkp` proves the *same class of relation* — committed-vector openings and
  **inner-product / linear maps over committed vectors** ([`src/sigma/linear.rs`](../src/sigma/linear.rs),
  [`DESIGN.md`](../DESIGN.md) §"Linear relations in NTT domain") — but over **Ajtai
  commitments** (Module-SIS binding, Module-LWE hiding, `n=256`, `q=8380417`) with
  **QROM** committed-first-message Fiat–Shamir, not Pedersen + ROM. Issuer-keyed blind issuance,
  tokens, nullifiers, and PVTN membership already ship on frozen wire v0.

## 3. Fit assessment (INFERRED — reasoned judgement)

Topically the paper lands on-radar: hidden requester attributes + hidden policy + a publicly
verifiable inner-product satisfaction proof is precisely the anonymous-credential / hidden-
predicate domain `lib-q-lattice-zkp` targets, and reducing predicate matching to
`⟨x,y⟩ = 0` is an idea directly comparable to `sigma/linear.rs`. It is **not an adopt /
implement candidate**, for three independent reasons:

1. **Threat-model mismatch (dispositive).** The construction's *only* asymmetric hardness
   assumptions are **discrete log** (Pedersen binding, Schnorr EUF-CMA, the Bulletproof IPA).
   A quantum adversary breaks all of them with Shor, which contradicts libQ's stated post-
   quantum threat model. Adopting it would *regress* the library's core guarantee, and its
   dependencies (`curve25519-dalek`, `ed25519-dalek`, `bulletproofs`) are hard-blocked by the
   `security_check_classical_crypto.py` CI gate. This alone closes the card.
2. **Nothing to interoperate with, and libQ is already ahead on its own axis.** libQ ships no
   Pedersen/Ristretto commitments, no Schnorr/Ed25519 signatures in-tree, and no Bulletproof
   IPA — there is no shipped primitive for this paper to attack, extend, or interoperate with.
   Its post-quantum analog (`lib-q-lattice-zkp` Ajtai + `sigma/linear.rs`, QROM FS) already
   proves committed-vector linear/inner-product relations without a discrete-log assumption.
3. **Maturity / method.** The headline efficiency claims rest on a **modeled** IPA, not a real
   proof implementation (§1 caveat), so even the classical performance story is not fully
   demonstrated. Security is ROM + PPT reductions, not QROM.

What *is* genuinely reusable is only confirmatory design vocabulary, not code: the
polynomial-root attribute/policy vectorization (`⟨x,y⟩ = 0` ⇔ conjunctive-clause satisfaction,
false-accept `≤ 1/(q−1)`) and the "public signature/aggregation checks outside the ZK proof,
hidden opening + inner-product inside it" split are a clean pattern that a future *lattice*
hidden-policy credential relation could borrow — implemented over Ajtai commitments, not
Pedersen.

## 4. Recommendation (INFERRED)

**Track, do not action.** Close the radar item as *evaluated — not adopted*. It does not
change any `lib-q-lattice-zkp` or `lib-q-zkp` direction: a discrete-log Pedersen/Bulletproof
scheme is the wrong hardness base for a post-quantum library and is CI-banned outright.

Revisit **only** as *design inspiration* if libQ later specs a lattice hidden-attribute /
hidden-policy access-control credential: the vector-encoding-of-conjunctive-policy trick and
the certify-outside / prove-inside split would port to the existing Ajtai + `sigma/linear.rs`
machinery, gated on a QROM soundness argument and independent review. The concrete Pedersen +
Ristretto + Bulletproof construction itself must **not** be imported.

## 5. Provenance — VERIFIED vs INFERRED

- **VERIFIED (read):** full text of ePrint 2026/1003 (abstract, §I–§VIII, Algorithms 1–6,
  Theorems 1–3, Tables I–IV) via the IACR reader; in this tree —
  `scripts/security_check_classical_crypto.py` `CLASSICAL` ban set (incl. `curve25519-dalek`,
  `ed25519-dalek`, `bulletproofs`); `lib-q-zkp/src/lib.rs` `ProofType` exclusion docstring;
  `docs/security.md` threat model / "Broken by Shor" list; `lib-q-lattice-zkp/DESIGN.md` +
  `README.md` (Ajtai, `sigma/linear.rs`, QROM FS); and the empty
  `dalek|bulletproof|curve25519` grep over all workspace `Cargo.toml`s.
- **INFERRED (judgement):** §3 fit assessment, §4 recommendation, and the "already ahead /
  reusable only as design vocabulary" conclusions.
- **NOT done / out of scope:** I did **not** clone, build, or benchmark the external Rust
  prototype — the 32 B / `64·log₂ m` / 0.103 ms figures are quoted from the paper (and, per §1,
  are themselves partly modeled rather than measured). No security proofs were re-derived. No
  `lib-q` runtime code changed, so no crate tests were run for this triage.
