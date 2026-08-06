# Saturnin in hardware — implementation notes

Notes for anyone implementing Saturnin in RTL, derived from building it in software twice and
getting it wrong both times in instructive ways.

Everything marked **VERIFIED** below was checked against the designers' own NIST LWC submission
package (reference C, specification, and their generated KAT files). Everything marked
**UNVERIFIED** is exactly that, and is called out so it does not get frozen into a mask set.

Provenance for the verified claims: a C harness built from the designers' `ref/saturnin.c`
regenerates all three submitted LWC KAT files byte-for-byte, and was used as an oracle over a
960-vector grid (rounds × domain × key/block). The relevant defects and their evidence are on
board card `t_ae63f1ec`.

---

## 1. There is one core, one datapath — this is measured, not assumed

**VERIFIED.** Saturnin is a single permutation. `(R, D)` — super-round count and domain — are
*configuration*, not variants:

- **R** is a loop bound.
- **D** is a 4-bit seed input to the round-constant generator, and nothing else.

The designers' 16-bit reference implementation and their bit-sliced implementation agree
byte-for-byte. A single datapath, parameterised by a 5-bit round count and a 4-bit domain, serves
every mode this crate exposes: CTR-Cascade AEAD, Saturnin-Short, QCB's tweakable block cipher, the
stream cipher, the block cipher, and the hash.

This is the property that makes Saturnin attractive for silicon: **AEAD, hash and the TBC all come
off one core.** If a committing transform is added later and is instantiated with Saturnin-Hash,
the commitment stack lands on the same core too.

> This crate briefly appeared to contradict that — it contained two implementations computing
> different functions. They did not disagree about Saturnin; one of them had a transposed constant
> table. See §5.

**Domains currently in use.** 1–5 CTR-Cascade, 6 Short, 7–8 Hash, 9–11 QCB (this crate's own
choice; see §6). Fourteen of sixteen domain values are spoken for under the current profile. If the
domain input is hard-wired to 4 bits, there is little headroom for a version bump, a KDF domain, or
a second mode. Worth deciding deliberately rather than discovering late.

---

## 2. Generate the round constants. Do not ROM them.

**VERIFIED against `ref/saturnin.c` `make_round_constants`.**

Both software failures in this crate were *table* failures, and a hardware ROM has the identical
failure mode with no `diff` to catch it:

- `core.rs` shipped a hand-copied table that was transposed (§5).
- `bs32_core.rs` shipped a *correct* table that masked a *broken* generator — so the generator bug
  never surfaced at the two configurations anyone looked at, and stayed live everywhere else.

The generator is small enough that ROMing it is a false economy — two 16-bit LFSRs:

```text
seed:   x0 = x1 = D + (R << 4) + 0xFE00        (16-bit)
per super-round n in 0..R:
    repeat 16 times:
        x0 = (x0 << 1) ^ (0x2D & -(x0 >> 15))   -- arithmetic: mask is all-ones iff MSB set
        x1 = (x1 << 1) ^ (0x53 & -(x1 >> 15))
    RC0[n] = x0
    RC1[n] = x1
```

Two 16-bit shift registers, two XOR taps, a 16-cycle inner count. Smaller than the 2×31×16 bits of
ROM it replaces, and — the real argument — **checkable against the specification text rather than
against a hand-transcribed table.**

Note the `-(x >> 15)` idiom: it is a *negation* producing an all-ones mask, not a logical NOT. In
software this crate got that wrong too — `!(x0 >> 15).wrapping_add(1)` parses as `!((x0>>15)+1)`
and yields `0x2C` instead of `0` whenever the MSB is clear. In HDL write it as a replication of the
MSB (`{16{x0[15]}}`), which cannot be misread.

The registers are **16-bit and must truncate**. The same software bug ran them in a 32-bit word
where `x0 << 1` never wrapped, silently producing a different sequence.

---

## 3. Pin the RC packing convention in normative prose

**VERIFIED.** This is precisely what this crate got backwards, and a table cannot express it
unambiguously. State it as a sentence:

> `RC0[n]` XORs into state word **0**. `RC1[n]` XORs into state word **8**.
> In the bit-sliced packing `(RC1 << 16) | RC0`, the **low** half is `RC0` (word 0) and the **high**
> half is `RC1` (word 8).

Reference: `ref/saturnin.c` emits `RC0[n] = x0; RC1[n] = x1;` and the round applies
`state[0] ^= RC0[n]; state[8] ^= RC1[n];`.

The failure mode this guards against is not a typo. It is that a bit-sliced implementation stores
one packed 32-bit word per super-round while a 16-bit implementation stores two, and transcribing
between the two forms is where the ordering gets inverted. Both representations are correct; the
translation is what is fragile.

---

## 4. The inverse datapath is required, and the S-box and MDS are NOT involutions

**VERIFIED.** This is the most expensive thing to get wrong late, so budget it up front.

Three shipped modes need the inverse permutation: Saturnin-Short decryption, QCB decryption
(via the TBC), and the block cipher. Only CTR-Cascade is inverse-free — it uses the permutation in
counter mode, so decryption is another forward pass.

The designers' reference C defines **distinct inverse operations**, not reuses of the forward ones:

| forward | inverse | in `ref/saturnin.c` |
|---|---|---|
| `sigma_0`, `sigma_1` | `inv_sigma_0`, `inv_sigma_1` | separate S-box tables |
| `MDS` | `MDS_inv` | separate function |
| `SR_slice` / `SR_sheet` | `SR_slice_inv` / `SR_sheet_inv` | separate |

So an inverse datapath costs real area: separate S-box tables and a separate MDS network, plus an
asymmetric shift-row pairing around the inverse MDS (`SR_sheet`, `MDS_inv`, `SR_sheet_inv`).

Do not take the involution shortcut. `bs32_core.rs` did, with the comments *"S-box is its own
inverse in Saturnin"* and *"MDS is its own inverse in Saturnin"* — both false — and its
`decrypt_block` consequently does not invert its own `encrypt_block`.

---

## 5. The trap catalogue — what went wrong in software, so it does not recur in HDL

Each of these was live in a shipped crate. None is hypothetical.

1. **Transposed constant table.** `core.rs` special-cased `(R=16, D=7|8)` with tables copied from
   the bit-sliced code, stored as `RC1[0], RC0[0], RC1[1], RC0[1], …` while the round function read
   `rc[2i]` as `RC0`. Those two configurations computed a permutation that is not Saturnin. Fixed
   by deleting the table (the LFSR reproduces the designers' values exactly).
2. **Non-truncating LFSR register**, plus the `-(x>>15)` mask misread. See §2.
3. **Assumed involutions.** See §4. Four independent bugs in one `decrypt_block`, including a
   round-pairing error from iterating `(0..n).rev().step_by(2)`.
4. **A constant ROM that is right where you test and wrong where you don't.** The generator bug in
   (2) was invisible because a correct ROM shadowed it at exactly the two configurations under
   test.

**The meta-lesson, which is the one worth carrying into verification planning:** every one of these
survived a green test suite. The tests asserted `len() == 32`, or "not the identity", or — in one
case — computed the correct constants, printed them next to the wrong table, and asserted only that
they were non-zero. **A hardware verification plan for this core must compare against the
designers' KAT vectors and against an independent model, not against itself.** Self-consistency
between an RTL model and its own testbench reproduces exactly this class of failure.

Concretely, the checks that would have caught all four:

- Every `(R, D)` the design supports, against the designers' generated KATs.
- `decrypt(encrypt(x)) == x` across the full `(R, D)` grid, not just the configurations in use.
- The constant generator against an independent derivation of the LFSR, not a copy of a table.

---

## 6. Not verified — do not freeze these

- **The AVX2 and NEON kernels in `src/simd/`** have never been compared against the reference
  oracle. Their constant code was read; their round functions were not. NEON has never been built
  or executed at all. Do not treat them as a second opinion on the round function.
- **QCB's mode-level correctness.** The submission package contains no QCB KAT. This crate's QCB
  additionally deviates from the QCB paper in two known ways — it zeroes the nonce in the
  associated-data tweak (which the paper explicitly warns forfeits the mode's quantum-forgery
  resistance) and it uses three domain separators where the specification fixes five. Neither is
  settled in this tree yet.
- **Cryptographic strength of the RC-transposed permutation** at `(16,7)`/`(16,8)`: unknown. It was
  established only that it is not the standard. Relevant only if something reached it through the
  public API before the fix.
- **Behaviour outside the reference KAT ranges** — hash messages over 1024 B, AEAD payloads over
  32 B, multi-block counter rollover. "Matches the reference" is scoped to what the reference
  covers plus the 960-vector permutation grid.
- **Side-channel posture.** No masked or threshold implementation of Saturnin is published, and
  none exists here. A 256-bit state makes masking proportionally more expensive than a
  128-bit-state competitor. If DPA or fault resistance is in scope, that work has no prior art to
  draw on and should be costed separately.

---

## 7. Physical-design notes

- **Datapath width.** The state is 256 bits (a 4×4×4 cube of nibbles). Against a 128-bit-block
  competitor that is 2× the datapath for 1× the block — but also no 2^64 birthday cliff, which for
  long-lived unrekeyed silicon is the reason to pick Saturnin in the first place. If the deployment
  rekeys, that advantage is smaller than it looks; check the per-key data volume before paying for
  it.
- **Parallelism depends on the mode, not the core.** CTR-Cascade's MAC is a sequential cascade
  (each block's output feeds the next block's key input), so it does not benefit from replicated
  cores on the authentication pass. QCB's blocks carry independent tweaks and do parallelise. A
  multi-core design is worth much more to QCB than to CTR-Cascade.
- **Round-count parameterisation.** Modes in this crate use R = 10 (CTR-Cascade, Short, stream) and
  R = 16 (hash, QCB's TBC). Supporting both is a loop bound, not a second design.
