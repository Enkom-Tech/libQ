import SaturninCTX.Bytes

/-!
# QCB tidiness counterexample

The formal-verification programme's Gate D task (item 2) asks for "The QCB tidiness counterexample, as a checked, concrete non-tidiness witness,
so the false premise can never quietly return."

`lib-q-saturnin/src/commit.rs`'s S-2 obligation currently claims `SaturninQcb` "is also *tidy* in
Bellare–Hoang's sense" (Bellare-Hoang, ePrint 2022/268 §2: `SE` is tidy if
`M ← SE.Dec(K,N,A,C)` implies `SE.Enc(K,N,A,M) = C`). That claim is **false**, and this file is
the checked witness.

The bug is in `qcb.rs::unpad_len`:

```rust
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
```

`open_core` calls this on the *whole* decrypted plaintext (every message block concatenated),
not on the final padding block alone. Nothing stops the trailing-zero scan from crossing a block
boundary. `pad_tail` always writes a `0x80` marker, so every *honest* encryption unpads correctly
(`unpadLen_genuine` below) — but a ciphertext whose second block decrypts to an all-zero string
(never producible by `pad_tail`, which always contains a `0x80`, but a perfectly good 32-byte
string all the same) makes the scan run straight through it and misread an earlier block's own
`0x80` as the marker (`unpadLen_forged` below). That ciphertext still carries an honestly-computed,
verifying tag (the checksum is unaffected by *which* domain produced which plaintext bytes), so
`Dec` accepts it — reporting a message the honest `Enc` never produces at this ciphertext shape.

This is a syntactic (tidiness) fact, not a cryptographic attack: constructing the witness needs
the encryption key, exactly as constructing *any* chosen ciphertext under a known key does. It has
no bearing on `SaturninQcb`'s confidentiality or authenticity, and in particular it does not
undermine `SaturninCTX.Binding.binding_direct`, which needs no tidiness assumption. What it *does*
rule out is ever invoking Bellare-Hoang's tidy-only `CMT-ℓ ⇔ CMTD-ℓ` equivalence
(`SaturninCTX.Hierarchy.cmt_wins_of_cmtd_wins` et al.) for `SaturninQcb` specifically.

`unpadLen_genuine`/`unpadLen_forged` were additionally cross-checked empirically against a
verbatim copy of the real `unpad_len` Rust function (not committed — a throwaway `rustc` script
run during development).
-/

namespace SaturninCTX.QcbTidiness

open SaturninCTX

/-- Block size in bytes, matching `qcb.rs::BLOCK` (`TBC_BLOCK_BYTES`, 32). -/
def BLOCK : Nat := 32

/-- Verbatim port of `qcb.rs::unpad_len`: locate the `10*` padding marker by scanning from the
end. Ported via the reversed list: peeling zero bytes off the *front* of `padded.reverse` is
exactly peeling zero bytes off the *end* of `padded`. Nothing here confines the scan to the final
padding block — it runs across as many trailing zero bytes as there are, wherever they came from.
That is the bug this file exploits. -/
def unpadLen (padded : Bytes) : Option Nat :=
  match padded.reverse.dropWhile (· == (0 : Byte)) with
  | [] => none
  | b :: rest => if b = (0x80 : Byte) then some rest.length else none

/-- `pad_tail([])`: the padding block for an empty tail, `0x80 ‖ 0^31` (`qcb.rs::pad_tail`). Also
the plaintext of `seal_core`'s "final block" whenever the message is empty *or* exactly one full
block — both cases appear below. -/
def x0 : Bytes := (0x80 : Byte) :: List.replicate (BLOCK - 1) (0 : Byte)

/-- An all-zero block. `pad_tail` can **never** produce this (it always writes a `0x80` marker
somewhere), so this plaintext is reachable only by directly choosing a ciphertext block, not by
any honest call to `seal_core`. -/
def x1 : Bytes := List.replicate BLOCK (0 : Byte)

theorem x0_length : x0.length = BLOCK := by decide
theorem x1_length : x1.length = BLOCK := by decide

/-- **Checked fact 1.** The honest two-block plaintext for a one-full-block message (`x0`, the
message itself, followed by `pad_tail([]) = x0`) unpads correctly, to length 32. -/
theorem unpadLen_genuine : unpadLen (x0 ++ x0) = some BLOCK := by decide

/-- **Checked fact 2 — the bug.** Replace the second block with an all-zero block: the scan runs
straight through it and into the *first* block's own trailing zeros, misreading the message as
empty. -/
theorem unpadLen_forged : unpadLen (x0 ++ x1) = some 0 := by decide

/-- Byte-wise XOR, matching the crate's `checksum[k] ^= chunk[k]` accumulation. -/
def xorBytes (a b : Bytes) : Bytes := List.zipWith (· ^^^ ·) a b

theorem xorBytes_x0_x1 : xorBytes x0 x1 = x0 := by decide

/-- "Decrypt undoes encrypt" for one TBC domain at a fixed `(key, nonce, tweak)` — true of any
block cipher, and in particular of `SaturninTbc::decrypt_block`/`encrypt_block` (documented as
inverse to each other). -/
def LeftInverse (dec enc : Bytes → Bytes) : Prop := ∀ p, dec (enc p) = p

/-- The ciphertext shape this development needs: the (already block-chunked) body, plus the tag.
Chunking into blocks, rather than a flat byte string, sidesteps `open_core`'s length arithmetic —
uninteresting here, and already covered by the crate's own `open_core` tests — and lets `dec`
below dispatch on list *shape* instead. -/
abbrev Ciphertext := List Bytes × Bytes

section
variable (encMsg decMsg encMsgFinal decMsgFinal tagOf : Bytes → Bytes) (adAuth : Bytes)

/-- Honest raw-Algorithm-1 decrypt (pre-CTX), restricted to the one- and two-body-block shapes
this file needs, at a *fixed* `(key, nonce, ad)` (so `adAuth` is a constant, not recomputed).
Mirrors `open_core`: recompute the checksum, recompute and compare the tag, then `unpad_len`. -/
def dec (c : Ciphertext) : Option Bytes :=
  match c.1 with
  | [bFinal] =>
      let checksum := decMsgFinal bFinal
      if xorBytes (tagOf checksum) adAuth = c.2 then
        (unpadLen checksum).map checksum.take
      else none
  | [b0, b1] =>
      let checksum := xorBytes (decMsg b0) (decMsgFinal b1)
      if xorBytes (tagOf checksum) adAuth = c.2 then
        (unpadLen (decMsg b0 ++ decMsgFinal b1)).map (decMsg b0 ++ decMsgFinal b1).take
      else none
  | _ => none

/-- The honest encryption of the empty message: `seal_core`'s only block is
`pad_tail([]) = x0`, encrypted under the `msg_final` domain. Always exactly **one** body block. -/
def encEmpty : Ciphertext := ([encMsgFinal x0], xorBytes (tagOf x0) adAuth)

/-- The forged witness: two body blocks, decrypting (under the *same* `(key, nonce, ad)`, via
`hMsg`/`hMsgFinal` below) to `x0` and `x1` respectively — a genuine one-full-block message
plaintext (`x0`) followed by an all-zero block `pad_tail` could never have produced. Its tag is
computed *honestly* from that checksum: not a guess or a replay, exactly what an honest
`compute_tag` call returns for this checksum, so it verifies. -/
def forged : Ciphertext := ([encMsg x0, encMsgFinal x1], xorBytes (tagOf x0) adAuth)

/-- **`SaturninQcb`'s raw Algorithm 1 (pre-CTX `E1`) is not tidy.**

`forged` decrypts successfully — the tag verifies, and `unpad_len` reports the empty message, by
`unpadLen_forged` — yet the honest encryption of the empty message, `encEmpty`, is a *different*
ciphertext: it has one body block where `forged` has two, unconditionally (`List.length`, no byte
content involved). Formally: `Dec(K,N,A, forged) = some []` but `Enc(K,N,A, []) = encEmpty ≠
forged`. -/
theorem qcb_not_tidy
    (hMsg : LeftInverse decMsg encMsg) (hMsgFinal : LeftInverse decMsgFinal encMsgFinal) :
    dec decMsg decMsgFinal tagOf adAuth (forged encMsg encMsgFinal tagOf adAuth) = some []
      ∧ encEmpty encMsgFinal tagOf adAuth ≠ forged encMsg encMsgFinal tagOf adAuth := by
  constructor
  · unfold dec forged
    dsimp only
    rw [hMsg, hMsgFinal, xorBytes_x0_x1]
    simp [unpadLen_forged]
  · intro heq
    have hlen := congrArg (fun c : Ciphertext => c.1.length) heq
    unfold encEmpty forged at hlen
    simp at hlen

end

end SaturninCTX.QcbTidiness
