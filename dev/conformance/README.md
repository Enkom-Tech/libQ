# Conformance & integration assurance artifacts

Development-time assurance material for the RED-zone advanced primitives. **Not part of the
built library** — nothing here is a crate, a dependency, or referenced by the build or CI. It
exists for human review and for keeping security claims reproducible-from-artifact.

## `integration/<crate>/LIBQ_API.md`

Consumer-protocol-agnostic API contracts — the normative description of what each crate
guarantees, carrying no consumer-protocol references: `lib-q-dkg`, `lib-q-blind-token`,
`lib-q-threshold-raccoon`.

## `integration/lib-q-threshold-raccoon/`

- `SECURITY_ANALYSIS.md` — binding / soundness / hiding analysis for the DKG + Threshold-Raccoon
  parameter set.
- `security_estimate.py`, `sweep_qs_preserving.py` — live cross-checks against malb's
  [lattice-estimator](https://github.com/malb/lattice-estimator).
- `archive_estimator_run.py` + `estimator_run_kappa9.txt` — the archived full per-attack
  estimator run, so the headline hiding figure in `SECURITY_ANALYSIS.md` is
  reproducible-from-artifact rather than a transcribed constant.
