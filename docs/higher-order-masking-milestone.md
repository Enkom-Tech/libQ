# Higher-order masking milestone

## Status

Planned research milestone. Not started. This document scopes the work that the
current `hardened` feature on [`lib-q-lattice-zkp`](../lib-q-lattice-zkp)
deliberately omits and that
[hardened-attestation.md](hardened-attestation.md) lists as out of scope.

## Current baseline

The `hardened` feature provides **first-order** countermeasures only:

- [`MaskedWitness`](../lib-q-lattice-zkp/src/sigma/secrets.rs) splits the witness
  into two additive shares so that `c·wit = c·share_a + c·share_b`, with shares
  derived from SHAKE256.
- Branch-free norm, normalization, and scalar-multiply primitives in
  [`lib-q-ring`](../lib-q-ring/src/poly.rs).
- Fixed-iteration rejection loops with constant-time first-accept selection.

First-order masking resists first-order differential power/EM analysis. It does
**not** resist higher-order analysis that combines leakage from multiple points,
and the masking is applied only to the `c·wit` step rather than to every
secret-dependent gadget in the prover.

## Goal

Achieve and **prove** masking security at order `d ≥ 2` for the secret-dependent
gadgets of the hardened lattice-ZKP prover, under a defined leakage model, using a
composition notion that lets independently verified gadgets be combined without
re-proving the whole circuit.

"Prove" is load-bearing: adding more shares is not the deliverable. The deliverable
is a masked implementation whose gadgets are individually verified and whose
composition carries a security argument.

## Scope

### Gadgets to mask and verify

| Gadget | Current state | Required for order `d` |
|--------|---------------|------------------------|
| `c·wit` accumulation | First-order additive shares | `d`-order masked multiply with refresh |
| NTT / inverse-NTT | Unmasked (shared with ML-DSA via `lib-q-ring`) | Masked linear transform over shares |
| Barrett / Montgomery reduction | Branch-free, unmasked | Masked modular reduction gadget |
| Infinity-norm / rejection screen | Branch-free, unmasked | Masked comparison / bound check |
| Mask refresh | Implicit (two shares) | Explicit refresh gadgets between composed gadgets |

Masking the NTT and the rejection-sampling decision are the hard parts and are
where the lattice-signature masking literature is still maturing; the milestone
must treat them as research, not as a port.

### Leakage model and order

- Fix the security order `d` (initial target `d = 2`).
- Fix the leakage model (probing model; specify whether glitch-extended /
  region-probing is in scope, since that materially changes gadget requirements).
- Fix the composition notion (SNI or PINI) and require every gadget to meet it so
  composition is sound.

### Tooling

Gadget-level and composition proofs must be machine-checked, not argued by hand.
Candidate tools: `maskVerif`, `IronMask`, `SILVER`, `scVerif`. Selection is part of
the milestone; the choice constrains the gadget representation and the leakage
model that can be expressed.

## Non-goals

- Microarchitectural channels (cache, SMT, transient execution). These are
  platform-dependent and remain out of scope; see
  [hardened-attestation.md](hardened-attestation.md).
- Independent laboratory certification. The milestone produces a masked
  implementation and machine-checked proofs; accredited evaluation is a separate,
  external process tracked in [sca-self-certification.md](sca-self-certification.md).
- Masking order beyond the fixed target `d` in the first iteration.

## Acceptance criteria

1. A documented gadget decomposition of every secret-dependent prover path with a
   stated leakage model and order `d`.
2. Machine-checked SNI/PINI proofs for each gadget and a composition argument for
   the assembled prover, with the tool, version, and inputs archived.
3. A masked prover implementation behind a feature flag, with KATs unchanged
   against the unmasked reference and the existing hardened tests still passing.
4. A measured performance envelope (the masked path is expected to cost on the
   order of `d²` per masked gadget on top of the fixed `max_attempts` loop), recorded
   as a regression anchor in [hardened-attestation.md](hardened-attestation.md).
5. An order-`d` (≥ 2) leakage assessment fed through the
   [self-certification](sca-self-certification.md) ingestion path; first-order TVLA
   does not exercise higher-order leakage and is insufficient here.

## Sequencing

This is a research milestone, not an incremental hardening of the existing feature.
It should be scheduled as a dedicated effort: tool selection and leakage-model fixing
first, then gadget decomposition and per-gadget proofs, then the composed prover and
its evaluation. It does not block the wire v0 integration candidate, which is
analysed in the ROM and ships first-order memory and timing hardening today.
