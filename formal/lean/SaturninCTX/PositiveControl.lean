import SaturninCTX.Binding

/-!
# Positive control: dropping `K` from the hash input breaks Gate D

The formal-verification programme's acceptance criterion for Gate D: "a mutated construction (for example, dropping `K` from the hash
input) makes the Gate D proof fail."

`Binding.binding_direct` needs `encode_injective`, whose proof peels `key`/`nonce`/`baseTag` off
the front of `H_input` in turn. If `key` is not part of `H_input` at all, that peeling step is
gone and the encoding stops depending on `key` — so two *different* keys produce the exact same
`H_input`, hence the exact same `T'`, with **no collision on `H` at all** (`H` is applied to the
literal same argument, not merely to two inputs that happen to collide). This is not "the proof is
harder to complete"; it is a live break: two distinct keys open the same ciphertext. -/

namespace SaturninCTX.PositiveControl

open SaturninCTX

variable {Digest : Type}

/-- The mutated `H_input`: `label ‖ nonce ‖ baseTag ‖ ad`, with `key` dropped entirely. -/
def mutatedEncode (label nonce baseTag ad : Bytes) : Bytes :=
  label ++ nonce ++ baseTag ++ ad

/-- The mutated CTX tag: same shape as `Binding.ctxTag`, but the hash never sees `key`. -/
def mutatedCtxTag (H : Bytes → Digest) (label _key nonce baseTag ad : Bytes) : Digest :=
  H (mutatedEncode label nonce baseTag ad)

/-- The mutated tag literally does not depend on `key` — by `rfl`, not by any collision-resistance
argument. Contrast with the real `SaturninCTX.Encoding.encode_injective`, which is a genuine
theorem (about `List.append`, needing the length hypotheses) precisely because the real encoding
*does* depend on `key`. -/
theorem mutatedCtxTag_independent_of_key (H : Bytes → Digest) (label nonce baseTag ad : Bytes)
    (key₁ key₂ : Bytes) :
    mutatedCtxTag H label key₁ nonce baseTag ad = mutatedCtxTag H label key₂ nonce baseTag ad :=
  rfl

/-- "Opens" for the mutated construction, matching `Binding.Opens`. -/
def MutatedOpens (baseTagOf : Bytes → Bytes → Bytes → Bytes → Bytes) (H : Bytes → Digest)
    (label core : Bytes) (tag' : Digest) (key nonce ad : Bytes) : Prop :=
  mutatedCtxTag H label key nonce (baseTagOf key nonce ad core) ad = tag'

/-- **The break.** Suppose an attacker finds a `core` at which the base scheme's tag
recomputation happens to coincide across two distinct keys at a shared `(nonce, ad)` — exactly the
kind of coincidence `tests/key_commitment.rs`'s pre-CTX attack (padding search + closed-form AD
solve) demonstrates is findable for `SaturninQcb`'s base mode. Real Gate D (`Binding.binding_direct`)
turns any such coincidence into a required `H`-collision, which is exactly what blocks the attack
once `K` is in the hash input. Here, with `K` removed, the SAME `core`/tag' pair opens under
*both* keys — a live CMT-1 break — and critically, it needs no `H`-collision to reach: the tag
identity below is `mutatedCtxTag_independent_of_key` applied after `hCoincide`, not a use of any
property of `H`. This is "the proof fails" made concrete: the step `Binding.binding_direct` relies
on (`encode_injective`) is false for this mutated encoding, and here is the resulting break. -/
theorem mutated_binding_breaks (baseTagOf : Bytes → Bytes → Bytes → Bytes → Bytes)
    (H : Bytes → Digest) (label core nonce ad : Bytes) {key₁ key₂ : Bytes} (_hKeyNe : key₁ ≠ key₂)
    (hCoincide : baseTagOf key₁ nonce ad core = baseTagOf key₂ nonce ad core) :
    ∃ tag', MutatedOpens baseTagOf H label core tag' key₁ nonce ad
          ∧ MutatedOpens baseTagOf H label core tag' key₂ nonce ad :=
  ⟨mutatedCtxTag H label key₁ nonce (baseTagOf key₁ nonce ad core) ad, rfl, by
    unfold MutatedOpens
    rw [hCoincide]
    exact (mutatedCtxTag_independent_of_key H label nonce (baseTagOf key₂ nonce ad core) ad
      key₁ key₂).symm ▸ rfl⟩

end SaturninCTX.PositiveControl
