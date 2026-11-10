# Fault-detection coverage assessment: CMALU (ePrint 2026/1423)

This document assesses whether libQ's modular-arithmetic paths (ML-KEM, ML-DSA)
carry software fault-detection coverage comparable to the technique described
in [CMALU: Compact Fault-Tolerant Modular Arithmetic Logic Unit for
Post-Quantum Cryptography](https://eprint.iacr.org/2026/1423) (Kim, Imran, Ul
Abideen, Rafferty, Khalid, O'Neill, Seo; ePrint 2026/1423).

## What CMALU is

CMALU is a **hardware** reconfigurable-datapath modular ALU for
resource-constrained IoT/FPGA/ASIC targets. It supports six modular
operations behind a 2-bit mode selector:

- **Mode-0** — un-protected baseline datapath.
- **Mode-1** — on-the-fly **parity and invariant checking** wired into the
  datapath, with a formal single-bit fault-detection guarantee, at zero
  latency overhead.
- **Mode-2** — Mode-1 plus **hardware-reuse recomputation** (reusing idle
  datapath cycles/slices to recompute, without duplicating the datapath) for
  deterministic silent-data-corruption (SDC) elimination.

The paper's own evaluation is register-level fault injection into an NTT
accelerator and an Ibex RISC-V core running ML-KEM-512, with post-P&R FPGA
synthesis (65 nm CMOS) and ASIC synthesis (Nangate45 45 nm). The countermeasure
is realized as **extra gates/registers on a physical datapath** (parity
predictors on the ALU's carry/reduction stages, and control logic that steals
otherwise-idle cycles to recompute); none of that has a Rust-source
equivalent — libQ is a pure-software, portable-Rust workspace with no HDL,
FPGA bitstream, or microcontroller-target datapath to instrument.

## libQ's current fault-injection posture

libQ ships the lattice schemes whose modular-reduction arithmetic CMALU's
datapath protects: ML-KEM (`lib-q-ml-kem`) and ML-DSA (`lib-q-ml-dsa`).
Re-verified against `3ee0d90d` (v0.0.12, current `main` tip at re-cut time):

- **libQ does not resist fault injection, and says so.**
  [`lib-q-aead/src/security/mod.rs`](../lib-q-aead/src/security/mod.rs#L10-L17)
  states plainly that fault injection is not in its list of security
  enhancements: `fault_injection_protection` is an advisory `bool` that
  callers set and read back, and **no call site anywhere in the workspace
  consumes it** — there is no redundancy, recomputation, infective
  countermeasure, or detection behind it. It is caller-declared policy
  plumbing, not a control. The same note points at a concrete consequence for
  Saturnin (the crate's default AEAD): a published ciphertext-only attack
  recovers its full 256-bit key from 656 nibble faults (Li et al., IEEE TIFS
  18 (2023) 1487–1496); see `lib-q-saturnin/SECURITY.md`.
- **The `hardened` feature is side-channel masking, not fault detection.**
  [`lib-q-ml-dsa/src/hardened.rs`](../lib-q-ml-dsa/src/hardened.rs) opens with
  `//! Side-channel hardening helpers (Cargo feature \`hardened\`)`; it adds
  additive NTT-domain secret sharing against DPA. It contains no parity,
  recomputation, or redundancy logic. `lib-q-ml-kem` has no `hardened.rs`
  module at all (its `hardened` feature lives in `masking.rs` and covers the
  same side-channel-masking ground, e.g. `polynomial_ct_eq` /
  `ciphertexts_equal_ct` used in constant-time re-encryption comparison —
  again a timing control, not a fault check).
- **The reduction paths CMALU's datapath protects have no runtime fault
  check in libQ.** ML-KEM: `barrett_reduce` (`lib-q-ml-kem/src/algebra.rs:47`),
  `montgomery_reduce` (`:433`), `barrett_reduce_i16` (`:450`). ML-DSA:
  `reduce` (`lib-q-ml-dsa/src/ntt.rs:21`). None of these recompute, check
  parity, or compare against an invariant at runtime.
- **libQ's `hax_lib::loop_invariant!` annotations are proof-time, not
  runtime.** `lib-q-ml-dsa/src/arithmetic.rs` carries nine
  `hax_lib::loop_invariant!` calls. These are formal-verification annotations
  consumed by the hax/F* toolchain at proof-extraction time; they assert
  functional-correctness invariants to a theorem prover and compile to
  nothing (or to debug assertions at most) in the shipped binary. They do not
  detect a bit-flip or stuck-at fault that occurs during actual execution —
  which is exactly the class of fault CMALU's Mode-1/Mode-2 target.
- **The one relevant existing mechanism is incidental, not a fault
  countermeasure, and this is already documented for a related paper.**
  ML-KEM decapsulation (`lib-q-ml-kem/src/kem.rs:152-192`) re-encrypts the
  decrypted message and compares the result against the input ciphertext —
  the standard Fujisaki–Okamoto implicit-rejection check. This
  [`hardened-attestation.md`](hardened-attestation.md#residual-risks-ml-kem)'s
  "Fault injection on decryption" row already states this plainly: "Fault
  resistance rests solely on the FO re-encryption equality check ... No
  CRT/RNR redundancy or recomputation is implemented", citing Pessl & Prokop
  (ePrint 2025/181 §2.4.3) showing a single skipped instruction during
  decryption can bypass the FO transform's protection. That row does not
  cover ML-DSA at all, and the FO check gives no diagnostic signal beyond
  "shared secret is now attacker-unpredictable" — it is not comparable to
  CMALU's formal single-bit detection guarantee or its 0% SDC elimination.
- **libQ's SCA test battery has no fault-injection target.**
  `lib-q-sca-test` (`git grep -ni fault lib-q-sca-test/`) only matches
  `default`/`DEFAULT_TVLA_ABS_T`-style identifiers; the crate's entire scope
  is Welch's-*t* / TVLA / dudect timing screening (documented in
  [`sca-self-certification.md`](sca-self-certification.md) and
  [`hardened-attestation.md`](hardened-attestation.md)). It has no glitch,
  stuck-at, or bit-flip injection harness, simulated or otherwise.

## Verdict

CMALU's actual contribution — parity-predictor logic wired into a physical
ALU datapath, plus a hardware-reuse recomputation scheduler that steals idle
datapath cycles — is a **circuit-level** technique for an FPGA/ASIC/RISC-V
accelerator target. It has no meaningful translation to a portable-Rust
source tree: there is no datapath to instrument, no idle hardware cycles to
reuse, and "recomputation" in software would mean re-running the whole
reduction in the same execution context using the same (potentially already
corrupted) inputs and registers, which does not carry CMALU's stuck-at/SDC
guarantees. libQ's genuine, standing gap — no software fault-injection
countermeasure anywhere in the workspace, `lib-q-aead/src/security/mod.rs:10-17`
— is real and already documented, but it predates and is broader than this
one paper; it is not something CMALU's specific hardware technique closes or
extends for a software target.

Verdict: OUT-OF-MODEL

## Not checked

- The paper PDF's full body beyond its ePrint abstract page (only the
  abstract page rendered; the FPGA/ASIC area, latency, and fault-injection
  count tables were not extracted).
- Whether `lib-q-hqc`, `lib-q-fn-dsa`, `lib-q-mayo`, or `lib-q-slh-dsa` carry
  any runtime fault check — only the ML-KEM/ML-DSA reduction paths this
  paper's arithmetic bears on were read.
- Whether downstream consumers' pinned revisions track this same working
  tree revision for these crates.

## Out of scope

Implementing a software fault-detection countermeasure (this assessment
returned OUT-OF-MODEL, not GAP, so none is proposed here); porting CMALU's
FPGA/ASIC datapath, parity-prediction logic, or hardware-reuse recomputation
scheduler (needs a hardware or microcontroller-firmware target, not a Rust
source tree); reproducing the paper's area/latency/throughput synthesis
numbers; fault coverage of any libQ scheme this paper's arithmetic does not
bear on.
