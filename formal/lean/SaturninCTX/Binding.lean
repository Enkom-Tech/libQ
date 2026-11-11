import SaturninCTX.Encoding

/-!
# Gate D binding: the direct CMTD argument

The formal-verification programme's Gate D task (item 1, first part) asks for: "two successful openings of the same `core || T'` under distinct
`(K,N,A)` imply an H-collision (the direct CMTD argument, with no tidiness assumption)."

Models `lib-q-saturnin/src/commit.rs`'s CTX transform:

```
H_input  =  LABEL ‖ K ‖ N ‖ T ‖ A
T'       =  SaturninHash(H_input)
```

Decryption recomputes the base scheme's tag `T` from `(K, N, A, core)` (`commit.rs`: "Decryption
recomputes `T` from the base scheme, then checks `T' =? H(K, N, A, T)`") and checks the received
tag against `H(LABEL, K, N, T, A)`. We keep the base scheme (`SaturninQcb`'s or
`SaturninAeadCtx`'s tag/checksum machinery) entirely abstract, as `baseTagOf`, since binding here
does not depend on anything about it beyond producing a fixed-width tag — this is what
`commit.rs`'s S-2 discussion means by the argument holding regardless of the base scheme's
length relation.
-/

namespace SaturninCTX.Binding

open SaturninCTX

variable {Digest : Type}

/-- `H` has a collision between `x` and `y`: distinct inputs, equal outputs. -/
def Collision (H : Bytes → Digest) (x y : Bytes) : Prop := x ≠ y ∧ H x = H y

/-- The CTX commitment tag, matching `commit.rs::ctx_tag`:
`T' = H(label ‖ key ‖ nonce ‖ baseTag ‖ ad)`. -/
def ctxTag (H : Bytes → Digest) (label key nonce baseTag ad : Bytes) : Digest :=
  H (encode label key nonce baseTag ad)

/-- Ciphertext `(core, tag')` **opens** under `(key, nonce, ad)`: the base scheme's deterministic
tag recomputation from `(key, nonce, ad, core)` — `baseTagOf` — feeds the CTX check, and it passes.
This is exactly `SaturninQcb::decrypt`/`SaturninAeadCtx`'s decrypt path: recompute the base tag,
then recompute and compare `T'`. -/
def Opens (baseTagOf : Bytes → Bytes → Bytes → Bytes → Bytes) (H : Bytes → Digest)
    (label core : Bytes) (tag' : Digest) (key nonce ad : Bytes) : Prop :=
  ctxTag H label key nonce (baseTagOf key nonce ad core) ad = tag'

/-- **Gate D, direct binding argument.** If `(core, tag')` opens under two key/nonce/AD triples
that are not identical, and the base scheme always produces a fixed-width tag (`hBaseTagLen`,
true of both `SaturninQcb` and `SaturninAeadCtx`: the base tag is always exactly 32 bytes,
independent of the key/nonce/AD/core it was computed from) — and keys and nonces are compared at
matching fixed widths (`hKeyLen`/`hNonceLen`, again always true per-mode) — then `H` has a
collision between the two `H_input` transcripts.

No tidiness assumption, no appeal to the Bellare-Hoang hierarchy (`SaturninCTX.Hierarchy`): this
is the "four-case argument" `commit.rs`'s S-2 obligation describes as needing only "`D1` is
deterministic and `D1 ∘ E1 = id`" — here, only that `baseTagOf` is a (total, deterministic) Lean
function, which every Lean function already is. -/
theorem binding_direct (baseTagOf : Bytes → Bytes → Bytes → Bytes → Bytes) (H : Bytes → Digest)
    (label core : Bytes) (tag' : Digest)
    {key₁ nonce₁ ad₁ key₂ nonce₂ ad₂ : Bytes}
    (hKeyLen : key₁.length = key₂.length)
    (hNonceLen : nonce₁.length = nonce₂.length)
    (hBaseTagLen : (baseTagOf key₁ nonce₁ ad₁ core).length
                 = (baseTagOf key₂ nonce₂ ad₂ core).length)
    (hOpens₁ : Opens baseTagOf H label core tag' key₁ nonce₁ ad₁)
    (hOpens₂ : Opens baseTagOf H label core tag' key₂ nonce₂ ad₂)
    (hDistinct : (key₁, nonce₁, ad₁) ≠ (key₂, nonce₂, ad₂)) :
    Collision H (encode label key₁ nonce₁ (baseTagOf key₁ nonce₁ ad₁ core) ad₁)
                (encode label key₂ nonce₂ (baseTagOf key₂ nonce₂ ad₂ core) ad₂) := by
  refine ⟨fun heq => hDistinct ?_, hOpens₁.trans hOpens₂.symm⟩
  obtain ⟨hk, hn, _ht, ha⟩ := encode_injective label hKeyLen hNonceLen hBaseTagLen heq
  simp only [Prod.mk.injEq]
  exact ⟨hk, hn, ha⟩

end SaturninCTX.Binding
