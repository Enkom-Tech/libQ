# Radar triage — ePrint 2026/1410: "A Memory-Efficient and Assembly-Optimized Implementation of NTRU+"

- **Card:** ENK-479 (Hive `iacr-radar`, Akira id `t_14fe0106`)
- **Paper:** <https://eprint.iacr.org/2026/1410>
- **Authors:** SuBeen Cho, Jiwon Bang, Minjoo Sim, Hwajeong Seo
- **Keywords (from ePrint):** Memory Optimization, KpqC, NTRU+, Lattice-based KEM, Assembly Optimization, Cortex-M4
- **Relevance call on import:** medium (conf 0.75), "Post-quantum KEMs"
- **Triage verdict:** **No code action. Low direct applicability to libQ / GIP today.** Keep as
  a reference for a future embedded / `no_std` KEM effort.

Status legend: **[V]** verified by running/grepping this checkout, **[I]** inferred / from the
paper text (not independently reproduced here).

## What the paper does

**[I, from abstract]** It is an *implementation* paper (no new scheme, no new cryptanalysis). It
takes the KpqC KEM **NTRU+** and, targeting an ARM **Cortex-M4** microcontroller:

1. Reduces **peak stack** by a liveness analysis of the polynomial buffers, restructuring the
   algorithm so only a *single* polynomial buffer is resident at a time (trading recomputation for
   memory).
2. Rewrites the **NTT** for NTRU+'s *mixed-radix* ring structure in hand-written Cortex-M4
   assembly, whose speed-up is claimed to pay back the recomputation cost of (1).

**[I]** Reported result vs the `KpqClean_ver2` reference: peak stack **-83..84 %**, all three
operations (keygen/encaps/decaps) up to **1.8x** faster. These numbers are the paper's; not
reproduced here (no Cortex-M4 target, toolchain, or NTRU+ code in this repo).

## Why it does not map onto this codebase

### 1. NTRU+ is not present anywhere

**[V]** Grep across both `libQ` and `GIP` (`ntru`, `ntru+`, `ntruplus`, `kpqc`, case-insensitive):

- No NTRU+ / KpqC KEM implementation, registry entry, wire suite, or roadmap item.
- libQ KEM set (`lib-q-core/src/algorithm_registry.rs`): **ML-KEM** {512, 768, 1024},
  **CB-KEM / Classic McEliece** {348864, 460896, 6688128, 6960119, 8192128}, **HQC** {128, 192,
  256}. See `ROADMAP.md` §"Key encapsulation mechanisms (KEMs)".
- GIP cipher suites (`sdk/gip-core/src/suite.rs`): only ML-KEM (512/768/1024), HQC (128/192/256),
  and Classic McEliece 6960119 appear as KEMs.
- The only `NTRU` token in either tree is the **NTRU-lattice basis inside FN-DSA / Falcon**
  signatures (`lib-q-fn-dsa/fn-dsa-kgen/src/ntru*.rs`) — a *different* object from the NTRU+ KEM —
  plus substring false positives (`unTRUsted`, `senTRUx`).

So there is no existing NTRU+ code to which the paper's optimizations could be applied.

### 2. The optimizations are platform-specific to a target libQ does not build

**[V]** libQ is portable Rust. It builds for host and **WASM**; `ROADMAP.md` §"Cross-platform"
lists *ARM optimization (NEON)*, *Embedded systems*, and *Mobile* as **unchecked**. There is no
Cortex-M4 / `thumbv7em` target, no ARM assembly, and no bare-metal firmware target in the tree.

The paper's headline contribution — **hand-written Cortex-M4 assembly for a mixed-radix NTT** — is
inherently non-portable and would not compile or run in libQ's targets. libQ's own NTT
(`lib-q-ring`) is for a *different* ring: negacyclic `R_q = Z_q[X]/(X^256+1)` with
`q = 8 380 417` (the FIPS-204 ML-DSA field), not NTRU+'s mixed-radix ring. The assembly is not
transferable even as a template.

### 3. The stack numbers are against an embedded baseline libQ does not share

**[I]** "Peak stack -83..84 %" is meaningful on a Cortex-M4 with a few KiB of RAM against
`KpqClean_ver2`'s buffer usage. libQ crates are `no_std`-capable (`lib-q-ml-kem`, `lib-q-kem`,
`lib-q-ring` declare `no_std`), but the library is not deployed to a microcontroller today, and its
buffer sizing/liveness is a property of its own (unrelated) implementations. The paper gives no
change that could be lifted into libQ's ML-KEM/HQC/McEliece code.

## The one transferable *idea* (not code)

**[I]** The generic technique in (1) — **buffer-liveness analysis + single-resident-buffer
restructuring, trading recomputation for peak stack** — is scheme-agnostic and is the part worth
remembering. If/when libQ pursues the currently-unchecked `ROADMAP.md` "Embedded systems" line, that
methodology (not this paper's NTRU+-specific assembly) is the reusable lesson, and would apply to
libQ's *own* KEMs (ML-KEM in particular), not to NTRU+.

## Recommendation

- **Do not** implement NTRU+ on the strength of this paper. It is not on the KpqC-vs-NIST path libQ
  has taken (NIST ML-KEM / HQC / Classic McEliece), and adding a KpqC-only KEM is a product decision
  independent of an implementation-optimization paper.
- **Close the radar card as triaged / no-action**, retaining this note as the reference.
- **If** an embedded KEM track is later opened, revisit for the memory-liveness methodology only,
  applied to libQ's existing lattice KEM code.

## Commands run (evidence)

```
grep -riE 'ntru\+|ntruplus|ntru_plus|kpqc'  libQ GIP      # -> none
grep -riE 'cortex-m4|thumbv7'               libQ          # -> none (only doc/false hits)
# libQ KEM registry: lib-q-core/src/algorithm_registry.rs  -> ML-KEM, CB-KEM, HQC
# GIP suites:        sdk/gip-core/src/suite.rs             -> ML-KEM, HQC, Classic McEliece
# ROADMAP.md: KEMs = ML-KEM/CB-KEM/HQC; Embedded systems = unchecked
```
