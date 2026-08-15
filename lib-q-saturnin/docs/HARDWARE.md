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

**Domains currently in use.** 1–5 CTR-Cascade, 6 Short, 7–8 Hash, 9–13 QCB (five domains, one per
Algorithm 1 sub-step: message, final message, AD, final AD, tag — see §6). That is **thirteen**
values (1–13) spoken for under this crate's profile; the block cipher and the stream cipher both
run at domain 1 (`block_cipher.rs` and `stream.rs` each construct `SaturninCore::new(10, 1)`)
rather than burning one of their own. The submission's own domain table (spec §2.5, Table 2)
additionally assigns domain 0 to the raw block cipher, so — counting the whole submission plus QCB
together, not just this crate's thirteen — **14 of the 16 values are spoken for and only 14 and 15
are left**, which is what `lib-q-saturnin/src/commit.rs` records. With the domain input hard-wired
to 4 bits, that is almost no headroom for a version bump, a KDF domain, or a second mode. Worth
deciding deliberately rather than discovering late.

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

> **Open question, not a decision: is the inverse datapath currently justified by any shipped
> caller?** The claim above ("three shipped modes need the inverse permutation") is still true of
> the mode inventory, but re-examined against what is actually *reachable* today: Saturnin-Short is
> opt-in (not in `default`) and its key commitment is broken and will not be fixed (see this
> crate's README); `SaturninQcb` has zero call sites outside `lib-q-saturnin` itself (no `.rs` or
> `.toml` reference anywhere else in the workspace); and the HPKE default AEAD, in all four
> `HpkeContext` constructors, is `SaturninAead` (CTR-Cascade), which is inverse-free by
> construction. So the only default-reachable caller of Saturnin decryption today is the bare block
> cipher's own `decrypt_block`. This does not mean the inverse datapath — the single largest area
> commitment this document describes — is unjustified; it means the justification should be
> re-examined against actual shipped callers before area is committed, not assumed from the mode
> inventory alone. This document takes no position on the outcome.

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
- **QCB's mode-level correctness.** The submission package contains no QCB KAT — that gap remains.
  This crate's QCB previously deviated from the QCB paper in two known ways — it zeroed the nonce
  in the associated-data tweak (which the paper explicitly warns forfeits the mode's
  quantum-forgery resistance) and it used three domain separators where the specification fixes
  five. **Both are fixed as of commit `bae2717`:** the nonce is now included in every
  message/AD tweak and is never zeroed (see `qcb.rs`'s tweak-construction doc comment, "the nonce
  must never be zeroed"), and the crate now uses the full five domain separators Algorithm 1 calls
  for (9–13; see §1). The absence of a QCB KAT is still an open gap, independent of those two
  fixes.
- **QCB tweak layout is libQ-specific, not paper-conformant — OPEN, undecided.** `qcb.rs` builds
  the tweak as a 128-bit nonce, 64 zero bits, then a 64-bit big-endian block counter. The QCB
  paper's Saturnin instantiation budgets IVs of at most 160 bits and up to 2^95 blocks, which places
  the block counter at a different byte offset. The two layouts produce different ciphertexts for
  identical inputs, so a paper-faithful third-party implementation of QCB-over-Saturnin will **not**
  interoperate with this crate's `SaturninQcb`. Neither layout is a security choice — 2^64 blocks
  per nonce is 512 EiB, far beyond any realistic message size either way — so this is a pure
  interop/roadmap question with no default answer here. It has not been decided, and nothing in
  this document should be read as deciding it.
- **Cryptographic strength of the RC-transposed permutation** at `(16,7)`/`(16,8)`: unknown. It was
  established only that it is not the standard. Relevant only if something reached it through the
  public API before the fix.
- **Behaviour outside the reference KAT ranges** — hash messages over 1024 B, AEAD payloads over
  32 B, multi-block counter rollover. "Matches the reference" is scoped to what the reference
  covers plus the 960-vector permutation grid.
- **Side-channel posture.** No masked or threshold implementation of Saturnin is published, and
  none exists here. That is now a documented obstacle rather than an absence of effort: the one
  group that built threshold implementations across the NIST lightweight field built one for
  every candidate *except* Saturnin, and gave two independent reasons — the cascade's key
  structure defeats datapath-only sharing, and both S-boxes sit in a cubic class that needs
  three quadratic factors where its peers need two. **See §8.1, which supersedes this bullet's
  earlier reasoning:** the 256-bit state is real but is not the dominant term, and §8.2's
  flip-flop table shows Saturnin is not even the sequentially heaviest core in its field. If DPA
  resistance is in scope, cost it from §8.1. Fault *resistance* still has no prior art at all —
  but fault *analysis* does, as of 2023: two ciphertext-only attacks recover the full 256-bit key
  (656 faults on the block cipher, 1 097 on Saturnin-Short), both simulation-only, neither
  proposing a countermeasure. If fault resistance is in scope it must cover the last four *single*
  rounds, not the last one or two, and detection/redundancy alone is not enough because one of the
  two attacks is a SIFA. See §8.6 and `SECURITY.md` (*Fault injection*).

---

## 7. Physical-design notes

- **Datapath width.** The state is 256 bits (a 4×4×4 cube of nibbles). Against a 128-bit-block
  competitor that is 2× the datapath for 1× the block — but also no 2^64 birthday cliff, which for
  long-lived unrekeyed silicon is the reason to pick Saturnin in the first place. If the deployment
  rekeys, that advantage is smaller than it looks; check the per-key data volume before paying for
  it. Note also that "2× the datapath" overstates the total sequential cost — Saturnin-BC carries
  no block-cipher-level key register, so its 288 flip-flops sit below SKINNY's 518 and
  ForkSkinny's 647. See §8.2.
- **Parallelism depends on the mode, not the core.** CTR-Cascade's MAC is a sequential cascade
  (each block's output feeds the next block's key input), so it does not benefit from replicated
  cores on the authentication pass. QCB's blocks carry independent tweaks and *could* parallelise.
  A multi-core design would be worth much more to QCB than to CTR-Cascade — **if** that parallelism
  were implemented. **It is not, in this crate.** `src/parallel.rs` is gated on a non-default
  `parallel` Cargo feature (absent from `default`) and has no callers anywhere in this workspace —
  it is dead code in every build this repo ships. So today, QCB's parallelism is a property of the
  mode's tweak structure, not something a multi-core silicon design would actually exercise against
  this codebase as it stands.
- **Round-count parameterisation.** Modes in this crate use R = 10 (CTR-Cascade, Short, stream) and
  R = 16 (hash, QCB's TBC). Supporting both is a loop bound, not a second design.
- **The unrolling factor is not free of the round structure.** Saturnin's rounds alternate
  `R0, R1, R0, R3, …`, so a 2-round or 4-round unroll aligns with that pattern while a 1-round or
  3-round one pays for mux filtering. Third-party synthesis puts the unmasked energy optimum at
  4-round unrolled and publishes no 3-round configuration at all. See §8.2 — and note that
  §8.1's masking constraint pulls the other way, towards round-based.

---

## 8. Third-party hardware data, and what masking will actually cost

Everything in this section is **VERIFIED against published papers**, quoted rather than
paraphrased, with the measurement configuration attached to every number. It is separated from
§§1–7 because those were verified against the designers' code and this is verified against other
people's measurements — a different kind of evidence with different failure modes.

The short version: there are exactly **two** third-party hardware studies that report a Saturnin
number, one ASIC and one FPGA, and both measure CTR-Cascade and Saturnin-Hash. Nobody has
published a masked Saturnin, nobody has published QCB hardware, and there is a specific,
documented reason why the one group that built threshold implementations of the whole NIST
lightweight field built one for every candidate except this one.

### 8.1 The masking constraint — two independent obstacles, and only one is about the S-box

**This is the item to settle before PCB layout, because it decides how much silicon a
side-channel-resistant Saturnin needs, and the answer is "more than the usual rule of thumb".**

#### Obstacle one: the mode, not the cipher

Caforio, Balli and Banik synthesised first-order threshold implementations of ten NIST LWC AEAD
candidates and built one for every scheme except Saturnin. Their stated reason, in full
("Energy Analysis of Lightweight AEAD Circuits", IACR ePrint 2020/607 = CANS 2020, §5, item 2 of
the TI characteristics list, printed pages 29–30):

> We implement TI profiles in which only the state path of the underlying encryption primitive
> is shared, but not the keypath. Many previous papers have taken this approach [PMK+11,
> BJK+16], as it is adequate for first order security and for simplicity we follow the suit. If
> the keypaths were also shared, we estimate that it would increase the power consumption of the
> AEAD schemes by a similar factor, and energy consumption comparisons would probably lead to
> similar results. In short, we implement threshold circuits for all the AEAD schemes except
> SATURNIN. The mode SATURNIN was designed in an unusual way that the output of block cipher is
> used as the key in the subsequent block cipher call. And so a TI which only considers shares
> in the datapath is not possible for this mode. We believe it would be unfair to compare its
> energy profile with the remaining schemes, as it could not guarantee the same level of
> security.

Read that as a design constraint rather than a benchmarking footnote: **the cheap masking
profile — share the state, leave the key register in the clear — is not available.** The
keypath has to be shared too, and the authors' own estimate of that cost is a power increase
"by a similar factor" to the state-path sharing they did do.

**Scope it precisely, because it does not apply to every mode this crate ships.** What defeats
datapath-only sharing is the *cascade*, where each block cipher call is keyed by the previous
call's output. The specification's authentication pass is `t ← A_i ⊕ Saturnin2(t, A_i)`
(spec v1.1 §2.2; Figure 7's caption notes "A thick line represents the input of the key"). The
CTR pass is not affected — it is `Saturnin1(K, N‖i+1)` under the fixed master key throughout.

| mode / pass | key input during a message | datapath-only TI |
|---|---|---|
| CTR-Cascade, confidentiality pass | master key, static | no obstacle of this kind |
| CTR-Cascade, authentication pass | chaining value `t` — secret, changes per block | **blocked** — this is what 2020/607 is describing |
| QCB | master key static, tweak varies | no obstacle of this kind |
| Saturnin-Short | master key, static, one call | no obstacle of this kind |

**UNVERIFIED for every row except the second.** 2020/607 discusses only CTR-Cascade; the other
three rows are read off the specification's own key inputs, not measured or asserted by anyone.
They are stated here because if they hold they are load-bearing: a masked design has a reason to
prefer QCB over CTR-Cascade that has nothing to do with the security proofs, and that is worth
checking properly rather than discovering after layout.

#### Obstacle two: the S-box class

From the same paragraph of 2020/607, and independent of the mode:

> In any case, both the s-boxes used in SATURNIN belong to the cubic class C270 listed in
> [BNN+12]. This class of s-box cannot be decomposed into 2 quadratic functions F ∘ G, so we
> need at least 3 quadratic functions to decompose this class of s-boxes. This of course means
> that in a 3-share TI, the s-box layer needs 3 cycles for evaluation and so more energy is
> spent doing so.

The general rule they are applying, from §5 of the same paper: "the minimum number of input
shares required to implement the TI of a function of algebraic degree w is w + 1 [NRS11]. This
means that quadratic s-boxes need at least 3 shares and cubic s-boxes need at least 4 shares
even for first order TI." A 3-share TI of a *cubic* S-box is only possible by decomposing it
into quadratics and separating the pieces with a register bank (or an equivalent demux-and-
feedback arrangement) — and Saturnin needs three pieces where its peers need two.

Both σ0 and σ1 are in C270. There is no "pick the cheaper S-box" escape: they are equally bad.

| candidate | S-box class | quadratic factors | cycles per S-box, 3-share TI |
|---|---|---|---|
| GIFT | C172 | 2 | 2 |
| Pyjamask-BC | C223 (same as PICCOLO) | 2 | 2 |
| SKINNY S8 (8-bit, degree 6) | — | 4 (`I∘H∘G∘F`) | 4 |
| **Saturnin σ0 and σ1** | **C270** | **3** | **3** |

Source for the GIFT, Pyjamask and SKINNY rows: 2020/607 §5.1.

#### What that costs, concretely

Two choices, both worse than the field:

- **4 shares, one cycle per S-box layer.** The straightforward route for a cubic S-box.
- **3 shares, three cycles per S-box layer.** Cheaper in registers-per-bit, three times the
  latency in the non-linear layer, and 2020/607's own measurements are a warning against
  assuming this wins: "it is surprising to see that 4-share TI circuits have similar energy-
  efficiency when compared to the corresponding 3-share circuits", because the intermediate
  register writes a 3-share design needs "consume almost as much energy as the shared s-box
  circuit in the 4-share TI" (§5.2). That measurement was taken with **two** quadratic factors.
  Saturnin needs three, so it pays that penalty one more time.

Whichever you pick, size it against the non-linear gate count, which is the quantity masking
multiplies. Per the designers' own hardware operation count (spec v1.1 §3.3): "64 × 12 gates for
the S-Box layer (6 AND/OR, and 6 XOR)" — so **384 AND/OR gates per round** across the 256-bit
state, 7680 over the 20 rounds of a `R = 10` call.

- **Round-based only.** 2020/607 rules out unrolling under TI: "We implemented first order TI of
  only round based circuits. This is necessary because r-round unrolled circuits must
  necessarily have higher algebraic degree, and as per the observation in [NRS11], it will
  require more shares to construct a TI. For example a 2-round unrolled TI of a block cipher
  with a cubic s-box has algebraic degree 6, if properly designed and then 7 shares are
  required." Saturnin's S-boxes are cubic, so it falls under exactly that example. **This
  collides directly with §8.2 below**, where the *unmasked* energy optimum is the 4-round
  configuration and the round-based configuration is the worst of the three. Masking and energy
  pull in opposite directions here and the design cannot have both.

- **A better S-box circuit does not help.** ePrint 2024/1996 found a shorter circuit for the
  Saturnin Super-Sbox, but explicitly holds the AND count fixed: "the effects of our framework
  occur while maintaining the AND gate count and AND depth without any increase." See §8.4. It
  buys latency, not masking cost.

**A floor, not an estimate.** There is no masked Saturnin to cost, but 2020/607 measured both
the unmasked and the TI versions of the same nine other schemes, so the multiplier is at least
observable elsewhere. Pyjamask is the nearest structural comparator — dedicated block cipher,
low round count, similar unmasked area — and it goes from 15 667 GE unmasked (Table 7, 1-Round)
to **42 001 GE at 3 shares and 64 577 GE at 4 shares** (Table 8, `CG-RB`), with energy per
128 bits rising 0.487 → 1.825 / 1.628 nJ. That is roughly **2.7× to 4.1× area and 3.3× to 3.7×
energy**. Saturnin's unmasked round-based figure is 14 540 GE (§8.2), so those multipliers are
the right order of magnitude to start from — but they are a **lower bound**, because Pyjamask's
S-box splits into two quadratics where Saturnin's needs three, and because Pyjamask's TI leaves
the keypath unshared where Saturnin's cannot. Do not present the scaled number as a budget.

**Adjacent, weaker evidence.** Li et al., "Transparency order versus confusion coefficient: a
case study of NIST lightweight cryptography S-Boxes" (Cybersecurity 4:35, 2021) computes leakage
metrics for nine round-2 4-bit S-boxes; σ0 and σ1 score identically (VTO0 3.0000, CCV 0.3602,
MCC 0.2500) and rank 6th–7th of nine by VTO0 and CCV, ahead of only SKINNY-64 and Spook. Treat
that as a hint, not a finding: the paper's own conclusion is that "there exist contradictions
between the three metrics", and it is not a measurement of a Saturnin implementation.

### 8.2 The only published ASIC figures — 2020/607, TSMC 90 nm

**Configuration.** TSMC 90 nm; Synopsys Design Vision v2019.03 / Design Compiler / Power
Compiler; ModelSim for functional verification. 10 MHz for the partially-unrolled versions,
5 MHz for the fully-unrolled ones. Workload is fixed: "the number of clock cycles it takes to
process the baseline AEAD input, which consists of one authenticated data and eight message
blocks, where each block contains 128 bits" (§4.3). `CG` is clock-gated, `IG` is inverse-gated.
The mode is CTR-Cascade. **These are unmasked.**

Table 7, p.27:

| implementation | latency (cycles) | area (GE) | TPmax (Mbps) | power (µW) | energy (nJ/128-bit) |
|---|---|---|---|---|---|
| 1-Round | 273 | 15 214 | 638.78 | 413.8 | 1.255 |
| 1-Round-CG | 273 | 14 540 | 622.96 | 382.6 | 1.161 |
| 2-Round | 143 | 20 530 | 2226.89 | 564.8 | 0.897 |
| 2-Round-CG | 143 | 19 184 | 2226.89 | 531.3 | 0.844 |
| 4-Round | 78 | 22 895 | 2062.23 | 858.1 | 0.744 |
| 4-Round-CG | 78 | 22 160 | 2092.87 | 823.3 | 0.714 |
| Unrolled | 13 | 70 348 | 3322.58 | 37 791.1 | 5.459 |
| Unrolled-IG | 13 | 87 854 | 2491.91 | 4790.6 | 0.623 |

Three things to take from this rather than the headline numbers.

**Unroll by 2 or by 4. Never by 3, and think hard before 1.** There is no 3-round row in that
table and that is deliberate (§3.3.6):

> The block cipher SATURNIN-BC employs 3 types of round functions: even R0, two types of odd
> rounds with indices congruent to 1 and 3 mod 4, call them R1 and R3, invoked in the following
> order
>
>     R0, R1, R0, R3, R0, R1, R0, R3 …
>
> As a result, round-based implementations are very inefficient for this cipher, requiring
> multiple muxes to filter signals. On the other hand, a 2-round implementation which implements
> R0, R1 and R0, R3 together requires only a single level of filtering between the outputs of
> R1, R3, and is probably the best with respect to speed and energy consumption. For similar
> reasons, a 3-round implementation would be terribly inefficient, whereas a 4-round
> implementation which implements the double super-round R0, R1, R0, R3 requires no additional
> filtering, but requires a larger power and area footprint.

The super-round structure this document has been treating as a loop bound (§1, §7) is also a
*mux* structure, and the unrolling factor either aligns with it or pays for filtering. That is
the same fact as this crate's `(R, D)` parameterisation, seen from the other side.

**Do not buffer the ciphertext.** The naive schedule needs the whole ciphertext resident before
the cascade can run over it (§3.4.8): "It is necessary to store each ciphertext block in
hardware after the counter mode so that they can be used during the cascade mode later to
produce the tag. This requires a lot of memory and energy to store ciphertext bits, and
especially infeasible on constrained environments that can not support high storage space."
Their fix is to interleave — process the AD cascade first into a `t` register, then per plaintext
block compute `CT_i` in counter mode and immediately fold it into `t`. "The above process
obviates the need for employing large storage elements to implement SATURNIN, and implies that
the mode can easily be employed on constrained environments. This design supports clock-gating
(i.e. t-register), but is not compatible with register-borrowing technique."

**The flip-flop budget is better than the 256-bit state suggests.** Figure 3's bottom table:

| | GIFT | TWE-GIFT | SKINNY | ForkSkinny | Pyjamask | SATURNIN |
|---|---|---|---|---|---|---|
| key | 128 | 128 | 384 | 384 | 128 | – |
| state | 128 | 64 | 128 | 128 | 128 | 256 |
| round cst. | 6 | 6 | 6 | 7 | 4 | 32 |
| **total FFs** | **262** | **198** | **518** | **647** | **260** | **288** |

Saturnin-BC is not the flip-flop-heaviest core in the set — SKINNY and ForkSkinny are, by a
wide margin. This qualifies §7's "2× the datapath for 1× the block": true of the state register
in isolation, not true of the total sequential cost, because Saturnin has no separate key
schedule register at the block-cipher level. (The dash in the key row is a consequence of the
cascade: the AEAD-level KEY register holds it. That is the same structural fact as §8.1's
obstacle one, showing up as an area saving in the unmasked case and as an area cost in the
masked one.)

**Overall placement.** §4.6: "On the trailing end are the more involved schemes, such as ForkAE,
SKINNY-AEAD and SATURNIN." Also: "The situation is different for the fully-unrolled
implementation where inverse-gating equalizes most of the measured values" — which is visible
above, where `Unrolled-IG` is the best energy figure in the table.

### 8.3 The only published FPGA figures — 2020/1207

Mohajerani, Haeussler, Nagpal, Farahmand, Abdulgadir, Kaps and Gaj, "FPGA Benchmarking of Round
2 Candidates in the NIST Lightweight Cryptography Standardization Process", ePrint 2020/1207.
The implementation is GMU/CERG's, in VHDL. Its reference software is given as
`saturninctrcascadev2` and `saturninhashv2` — **CTR-Cascade plus Saturnin-Hash, exactly the
crate's default `SaturninAead` plus the hash, and not QCB or Short.** Two variants:
`Saturnin-v1` is a *folded* architecture, `Saturnin-v2` an *unrolled SuperRound* architecture.
Maximum input length for both is 2^16 − 1 bytes.

Resource usage (Table 22, Xilinx Artix-7 `xc7a12tcsg325-3`):

| variant | LUTs | FFs | slices | freq. (MHz) |
|---|---|---|---|---|
| Saturnin-v1 (folded) | 1725 | 1329 | 518 | 215 |
| Saturnin-v2 (unrolled super-round) | 2321 | 768 | 622 | 167 |
| *AESGCM-v2, for scale* | *2520* | *1611* | *810* | *143* |

Throughput on Artix-7, long messages (Tables 25–28; the rank column is the candidate ranking
within the study):

| metric | Saturnin-v2 | rank | Saturnin-v1 | cycles/block, v2 / v1 |
|---|---|---|---|---|
| encryption, PT | 791.7 Mbit/s | 14 | 139.7 Mbit/s | 54 / 394 |
| encryption, AD | 1583.4 Mbit/s | 9 | 279.4 Mbit/s | 27 / 197 |
| encryption, AD+PT | 1055.6 Mbit/s | 12 | 186.3 Mbit/s | 81 / 591 |
| hashing | 1295.5 Mbit/s | 6 | 180.5 Mbit/s | 33 / 305 |

Other devices, for portability rather than for a decision: Cyclone 10 LP gives v2 3892 LEs at
104.6 MHz (495.7 Mbit/s PT), ECP5 gives v2 3648 LUTs at 79.0 MHz (374.5 Mbit/s PT).

Estimated power and energy at 75 MHz on Artix-7 (Tables 20 and 21; columns are PT,AD byte
counts):

| variant | Enc 1536,0 | Enc 0,1536 | Enc 16,0 | Hash 1536 | Hash 16 |
|---|---|---|---|---|---|
| power (mW) v1 | 91 | 68 | 68 | 115 | 114 |
| power (mW) v2 | 784 | 90 | 88 | 158 | 160 |
| energy (pJ/bit) v1 | 1934 | 988 | 7868 | not recovered | not recovered |
| energy (pJ/bit) v2 | 2348 | 1201 | 10 237 | not recovered | not recovered |

> **CORRECTION 2026-08-07.** The power row as first written here was wrong in 4 of its 5
> columns per variant, and the energy row's two hash columns were wrong. The figures were not
> approximations, they were **other submissions' numbers**: `764` and `551` are SCHWAEMM-v1's
> `Enc 0,1536` and `Enc 16,0`, and `801`/`425` are Pyjamask-v1's hash power. The energy hash
> pair `1463`/`3066` is likewise Pyjamask-v1's. Cause: Table 20 and Table 21 extract with the
> label column offset from the number column, so a row read positionally picks up its
> neighbours. Saturnin's own rows carry a full complement of 8 numbers matching the 8 headed
> columns (`91 68 68 68 88 88 115 114` and `784 90 91 88 476 590 158 160`), which is what the
> corrected table above uses; the *broken* rows in that table are the short ones, such as
> Pyjamask-v1 with only 5. The Saturnin rows in **Table 21 carry only 6 numbers and no hash
> pair at all**, so those two cells are marked not recovered rather than guessed. Do not fill
> them from the orphan `1,435 2,935` line floating between the Pyjamask rows: it is unassigned
> in the extraction, and an energy-equals-power-times-time estimate from the corrected
> `115 mW` and 305 cycles/block gives roughly 1830 pJ/bit for v1, which matches neither
> candidate closely enough to identify one. Read them from the PDF or leave them empty.
>
> The three conclusions drawn below this table are unaffected, because each rests on the
> `Enc 1536,0` column, which was correct: 791.7/139.7 = 5.7x throughput, 2321/1725 = 1.35x
> LUTs, 784/91 = 8.6x power.

**Read the area and power columns with this caveat attached, every time:**

> Power and energy estimations of two-pass submissions (Saturnin, ISAP) do not include the power
> required for writing to and reading from the two-pass FIFO. The two-pass FIFO is not
> synthesized. It is also not included in the resource utilization of the design. Cycle
> measurements, on the other hand, cover the entire operation of the core, including the
> read/write operations from/to the two-pass FIFO.

So the LUT, FF and power numbers above exclude the message buffer, and the cycle counts do not.
Either add the buffer back before budgeting from these, or adopt 2020/607 §3.4.8's interleaved
schedule and remove the need for it. Do not do neither.

Two shape findings worth more than the absolute numbers:

- **AD and hashing are Saturnin's strong axis; short plaintexts are its weak one.** "The ratio
  of the hashing throughput to the plaintext processing throughput is the highest for Saturnin
  and the smallest for KNOT and Subterranean 2.0" (§4). "Saturnin approaches the speed of
  AES-GCM and, at the same time, uses about 200 less LUTs." "Very close behind SHA-2 are
  DryGASCON and Saturnin, with the throughputs between 1.4 and 1.6 Gbits/s." Against that:
  "A candidate particularly fast in hashing but not so good for processing small plaintexts is
  Saturnin"; "For 16-byte ADs, Elephant drops to position 14 and Saturnin to position 19"; and
  for hashing, "The ranking of Saturnin gets significantly worse … for 16-byte inputs." The
  rate-1/2 mode plus a 256-bit block means a short message pays for a whole block either way.
  **The corrected power table now says the same thing independently, and the erroneous one hid
  it:** on v2, associated data costs `90 mW` against plaintext's `784 mW`, and hashing `158 mW`,
  so the AD and hash paths are roughly an order of magnitude cheaper in power, not merely faster.
  The original row gave AD as `764 mW` (SCHWAEMM's number), which made the two paths look
  comparable and destroyed the corroboration.
- **Folded versus unrolled is a real fork, not a tuning knob.** v2 is 5.7× v1's plaintext
  throughput for 35% more LUTs — but at roughly 8× the power.

### 8.4 S-box circuits — 2024/1996 improves depth, and nothing else

"A Framework for Generating S-Box Circuits with Boyar–Peralta Algorithm-Based Heuristics, and
Its Applications to AES, SNOW3G, and Saturnin", ePrint 2024/1996, optimises the **16-bit
Super-Sbox** S16 — defined in spec v1.1 §4.1 as "the permutation of F2^16, composed of the
succession of an Sbox layer, the linear function σ, and a second Sbox layer" — not the 4-bit
σ0/σ1. Its Table 2 (p.16; `D` depth, `AD` AND depth, `#NL` non-linear gates, `#L` linear gates):

| circuit | D | AD | #NL | #L | total | source |
|---|---|---|---|---|---|---|
| Saturnin Super-Sbox, submission's own | 28 | 12 | 48 | 86 | 134 | ad-hoc, [CDL+20] |
| Saturnin Super-Sbox, new | 25 | 12 | 48 | 143 | 191 | eBPD, Listing 22 |

So: **depth 28 → 25 (−11%), AND depth unchanged, AND count unchanged, XOR count 86 → 143 (+66%),
total gates 134 → 191 (+43%).** It is a latency-for-area trade. Take it for a
high-frequency core; do not take it for a minimum-area one; and note that because `#NL` is
invariant by construction, **it does not reduce the cost of masking Saturnin by a single gate.**

The `#NL = 48` figure independently corroborates the designers' own count: one column is four
nibbles, the specification's "6 AND/OR" per nibble gives 24 non-linear gates per S-box layer,
and S16 contains two S-box layers.

### 8.5 RISC-V — 2020/836, for the firmware side of the same board

Campos, Jellema, Lemmen, Müller, Sprenkels and Viguier, "Assembly or Optimized C for Lightweight
Cryptography on RISC-V?", ePrint 2020/836, benchmarked the designers' reference C and both
32-bit bitsliced C implementations on a SiFive HiFive1 (FE310-G000, E31, "320+ MHz",
"16KB, 2-way instruction cache"), a VexRiscv core under Verilator, and riscvOVPsim.

Three results that change decisions:

- **Bitslice inside a block, not across blocks.** "The 'bs32' and 'bs32x' implementations both
  implement Saturnin in a 32×bitsliced fashion. Their difference is that 'bs32' bitslices inside
  of blocks, whereas 'bs32x' bitslices across blocks. When comparing the two bitsliced
  implementations, 'bs32' showed a consistently better performance than the other, albeit
  sometimes with a small margin. We decided that 'bs32' would be the preferred implementation to
  use on our platforms." Bitslicing is worth roughly 2× over the reference: Saturnin-Hash over
  128 bytes goes 49 433 → 28 199 cycles on the board (Clang-10 -O3), and Saturnin-Cipher over
  128 AD + 128 message bytes goes 121 651 → 59 368.
- **Do not let the compiler fully unroll it.** The worst cell in their Table 5 is bs32x under
  GCC -O3 on the physical board: 5 210 541 cycles, ×34 the same build's reference column, against
  75 646 for the same code on the simulator. Their explanation: "greedy unrolling and inlining by
  GCC with -O3 results in major speed-up on simulators. However once tested on a physical device
  such as the SiFive development board, this results in a code too large for the 16KB cache,
  inducing in a slowdown by a factor of 5." Any Saturnin firmware on a cached core needs an
  I-cache-resident-size check, not just a cycle count from a simulator.
- **Budget nothing for a bit-manipulation ISA extension.** Their Table 16, RISC-V Bitmanip
  on/off: Saturnin-Hash C-ref 83 516 → 80 866 (−3%), bs32 33 087 → 30 943 (−6%). In the same
  table AES LUT goes 3647 → 1578 (−57%), Esch256 unrolled 17 585 → 11 586 (−34%), Keccak-f[1600]
  14 633 → 12 402 (−15%). Saturnin's round function is AND/OR/XOR plus nibble permutations that
  the bitsliced form already turns into free re-indexing, so rotate/pack instructions have
  almost nothing to buy. (The comparison is ours, computed from their table; the paper does not
  comment on Saturnin's result.)

One footnote so nobody cites it: their Table 17 lists `saturnin_short_aead_encrypt` at 42/55
cycles. Saturnin-Short takes messages "of length strictly less than 128 bits" with no associated
data (spec v1.1 §2.3), and that harness feeds 128 bytes of each — the call almost certainly
returned an error without doing any work. **UNVERIFIED**, but do not quote the row.

### 8.6 What is *not* known — do not fill these in from the tables above

- **There is no published masked or threshold implementation of Saturnin, of any order, in any
  technology.** §8.1 establishes what such a design would have to do; nobody has built one, so
  there is no area, power or latency figure to scale from, and no design to review. Cost it as
  new work.
- **There is no published hardware implementation of QCB, over Saturnin or over anything else.**
  Every third-party number in this section is CTR-Cascade or Saturnin-Hash. QCB's tweak
  injection, its five domain separators, and its inverse datapath (§4) have never been
  synthesised by anyone. This compounds the QCB gaps already recorded in §6 — no KAT, and a
  tweak layout that is this crate's rather than the paper's.
- **2021/049 has no Saturnin data.** Aagaard and Zidaric's "ASIC Benchmarking of Round 2
  Candidates in the NIST Lightweight Cryptography Standardization Process" is the obvious second
  ASIC source and it does not contain the string "Saturnin" anywhere in its 49 pages; the cipher
  legend in Figure 1.1 lists all 23 included ciphers and Saturnin is not among them. Their
  intake was "110 instances, 38 hardware packages, and 27 ciphers collected by the FPGA
  benchmarking group", of which they kept what "synthesized and simulated correctly", and §2.6
  notes that "cipher instances that were unsynthesizable or that generated netlists whose
  behaviour differed from the original source code are not included in the analysis". The paper
  never names which ciphers were dropped, so **why** Saturnin is absent is not established and
  must not be asserted. Recorded here so the search is not repeated.
- **No fault-*resistance* work exists for Saturnin**, masked or otherwise — no published
  countermeasure, so there is no area, power or latency figure to scale from. **Fault *analysis*
  does exist, and until 2026-08-15 this bullet denied it.** Two ciphertext-only attacks recover the
  full 256-bit key: Li et al., IEEE TIFS **18** (2023) 1487–1496, using 656 faults at the
  fourth-to-last single round on the block cipher ("It is recommended that the fault injection
  position is in the (2R−3)-th single round with R ∈ [10, 31]", p.1491); and Li et al., *Journal on
  Communications* **44**(4) (2023) 167–175, using 1 097 ineffective faults on Saturnin-Short. Both
  are simulation-only and neither proposes a countermeasure. They **size** the requirement — a
  protected datapath must cover the last four single rounds, and SIFA specifically defeats
  detection/redundancy — they do not supply one. Full scope and caveats, including that both papers
  model Saturnin with half its S-box layers: `SECURITY.md` (*Fault injection*).
- **No third party has measured the configuration this crate actually ships.** The ASIC and FPGA
  numbers are for the specification's CTR-Cascade. This crate's QCB tweak layout differs from the
  QCB paper (§6), and no published measurement covers Saturnin-Short in hardware at all.
- **The FPGA area and power figures exclude the two-pass buffer** (§8.3). They are not a
  complete AEAD core.
- **The masked-versus-energy conflict in §8.1 is unresolved.** The unmasked energy optimum is a
  4-round unrolled datapath; TI requires a round-based one. Nobody has published the cost of
  that trade for Saturnin, and this document does not estimate it.
