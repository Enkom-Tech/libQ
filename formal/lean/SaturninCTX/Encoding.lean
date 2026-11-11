import SaturninCTX.Bytes

/-!
# Injectivity of the CTX byte encoding

The formal-verification programme's Gate D task (item 1, third part) asks to "prove that the tuple encoding in `commit.rs` is injective, since
`A` is the only variable-length suffix."

`lib-q-saturnin/src/commit.rs` ("Byte layout") fixes

```
H_input  =  LABEL ‖ K ‖ N ‖ T ‖ A
```

where `LABEL` is a compile-time constant, `K`/`N`/`T` have a fixed width for a given mode (32,
16 or 32 bytes respectively for `SaturninQcb`), and `A` is the only variable-length field, placed
last specifically so that no length prefix is needed. The crate's own argument for this
(`commit.rs` "Injectivity, and the constraint that follows from it") is: since `H` pads its input
canonically (`10*`), `H_input` determines `|H_input|`, hence `|A|` is determined, hence the split
point of the whole string into `(LABEL, K, N, T, A)` is determined.

We prove the *combinatorial* half of that argument directly at the list level: appending a
variable-length suffix onto a run of fixed-width fields is injective, given only that the
fixed-width fields on both sides have matching lengths (which they always do, since `K`, `N`, `T`
have one fixed width per mode) — this does not need to talk about `H`'s padding at all, since the
split point is fixed by the *known* lengths of `LABEL`/`K`/`N`/`T`, not recovered from `H_input`'s
total length. (The crate's own argument recovers the split a different way — from the hash's
padding recovering `|H_input|` and subtracting fixed offsets — but the two arguments prove the
same fact: `A` is the only place two encodings can differ freely.)
-/

namespace SaturninCTX

/-- Two lists of equal length that, once each is extended by a suffix, produce equal
concatenations, must already have been equal, and so must the (arbitrary) suffixes.

This is the general "peel a fixed-width field off the front" fact used repeatedly below: `K`, `N`
and `T` all have a fixed width per mode, so each can be peeled off in turn, leaving only `A` (the
variable-length suffix) free. -/
theorem append_left_cancel_of_length_eq {α : Type _} :
    ∀ (l₁ l₂ r₁ r₂ : List α), l₁.length = l₂.length → l₁ ++ r₁ = l₂ ++ r₂ →
      l₁ = l₂ ∧ r₁ = r₂
  | [], [], _, _, _, happ => ⟨rfl, happ⟩
  | [], _ :: _, _, _, hlen, _ => by simp at hlen
  | _ :: _, [], _, _, hlen, _ => by simp at hlen
  | a :: l₁, b :: l₂, r₁, r₂, hlen, happ => by
      have hlen' : l₁.length = l₂.length := by
        have h := hlen
        simp only [List.length_cons] at h
        omega
      have happ2 : (a :: (l₁ ++ r₁) : List α) = b :: (l₂ ++ r₂) := happ
      injection happ2 with hab htail
      obtain ⟨hl, hr⟩ := append_left_cancel_of_length_eq l₁ l₂ r₁ r₂ hlen' htail
      exact ⟨by rw [hab, hl], hr⟩

/-- The `H_input` transcript CTX hashes (`commit.rs`, "Byte layout"):
`label ‖ key ‖ nonce ‖ base_tag ‖ ad`. `ad` is the only variable-length field. -/
def encode (label key nonce baseTag ad : Bytes) : Bytes :=
  label ++ key ++ nonce ++ baseTag ++ ad

/-- **Injectivity of the CTX byte encoding.** For a fixed `label`, and keys/nonces/base-tags of
matching length on the two sides (always true: they are the mode's fixed widths, e.g. 32/16/32
bytes for `SaturninQcb`), equal `H_input`s force equal `(key, nonce, baseTag, ad)` tuples.

This is the fact `commit.rs`'s "Injectivity, and the constraint that follows from it" states in
prose ("The map `(K, N, T, A) ↦ H_input` is therefore injective"); [`SaturninCTX.Binding.binding_direct`]
is where it is actually used, chained with a hash-collision conclusion. -/
theorem encode_injective (label : Bytes)
    {key₁ key₂ nonce₁ nonce₂ baseTag₁ baseTag₂ ad₁ ad₂ : Bytes}
    (hkey : key₁.length = key₂.length)
    (hnonce : nonce₁.length = nonce₂.length)
    (htag : baseTag₁.length = baseTag₂.length)
    (heq : encode label key₁ nonce₁ baseTag₁ ad₁ = encode label key₂ nonce₂ baseTag₂ ad₂) :
    key₁ = key₂ ∧ nonce₁ = nonce₂ ∧ baseTag₁ = baseTag₂ ∧ ad₁ = ad₂ := by
  unfold encode at heq
  -- Normalize `label ++ key ++ nonce ++ baseTag ++ ad` to `label ++ (key ++ (nonce ++ (baseTag ++ ad)))`
  -- so each fixed-width field can be peeled off the front in turn.
  simp only [List.append_assoc] at heq
  obtain ⟨-, heq⟩ :=
    append_left_cancel_of_length_eq label label _ _ rfl heq
  obtain ⟨hkeyEq, heq⟩ :=
    append_left_cancel_of_length_eq key₁ key₂ _ _ hkey heq
  obtain ⟨hnonceEq, heq⟩ :=
    append_left_cancel_of_length_eq nonce₁ nonce₂ _ _ hnonce heq
  obtain ⟨htagEq, hadEq⟩ :=
    append_left_cancel_of_length_eq baseTag₁ baseTag₂ _ _ htag heq
  exact ⟨hkeyEq, hnonceEq, htagEq, hadEq⟩

end SaturninCTX
