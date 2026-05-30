# Side-channel self-certification

This document defines the libQ **side-channel self-certification** process: a
repeatable, auditable internal evaluation of the `hardened` builds of
[`lib-q-ml-kem`](../lib-q-ml-kem), [`lib-q-ml-dsa`](../lib-q-ml-dsa),
[`lib-q-lattice-zkp`](../lib-q-lattice-zkp), and (via `hqc-hardened`)
[`lib-q-hqc`](../lib-q-hqc) KEM paths (built with the `hardened` feature when using
`hqc-hardened`). Its purpose is to surface
implementation leakage **before** an accredited laboratory engagement, so that
defects are found and fixed while they are cheap to address.

Self-certification is a precondition for, not a replacement for, independent
certification. See [Boundary of self-certification](#boundary-of-self-certification).

## Standards alignment

The methodology follows the leakage-assessment approach used in ISO/IEC 17825 and
the FIPS 140-3 non-invasive attack testing track (which references ISO/IEC 17825
and the ISO/IEC 19790 security requirements), specialized to the channels libQ can
measure in software and to the channels an external rig must supply.

| Concept | ISO/IEC 17825 framing | libQ self-certification |
|---------|-----------------------|-------------------------|
| Leakage assessment | Test Vector Leakage Assessment (TVLA), non-specific fixed-vs-random | Welch *t*-test, fixed-vs-random classes ([`lib-q-sca-test`](../lib-q-sca-test)) |
| Decision statistic | \|t\| threshold (commonly 4.5) | [`DEFAULT_TVLA_ABS_T = 4.5`](../lib-q-sca-test/src/evaluation.rs) |
| Trace budget | On the order of 10⁶ traces per class for confidence | Configurable; software-timing batteries report their actual count and are labelled pre-laboratory |
| Channels | Timing, power, electromagnetic | Timing measured in-harness; power/EM acquired externally and ingested |
| Device under test | Frozen artifact on defined hardware | Frozen `hardened` build; environment captured per run |

## Targets

| Target id | Crate | Path under test | Property |
|-----------|-------|-----------------|----------|
| `lib-q-ml-kem:decapsulate` | `lib-q-ml-kem` (`hardened`) | `MlKem768` decapsulation | Decapsulation time independent of secret key / ciphertext |
| `lib-q-ml-dsa:sign` | `lib-q-ml-dsa` (`hardened`) | ML-DSA-44 signing | Signing time independent of signing key |
| `lib-q-lattice-zkp:prove_opening` | `lib-q-lattice-zkp` (`hardened`) | Opening prover (fixed-iteration rejection loop) | Prover time independent of witness / token header |
| `lib-q-hqc:hqc128_keygen` | `lib-q-hqc` (`hqc-hardened`) | HQC-128 KEM key generation | Keygen time independent of 48-byte KEM seed |
| `lib-q-hqc:hqc192_keygen` | `lib-q-hqc` (`hqc-hardened`) | HQC-192 KEM key generation | Keygen time independent of 48-byte KEM seed |
| `lib-q-hqc:hqc256_keygen` | `lib-q-hqc` (`hqc-hardened`) | HQC-256 KEM key generation | Keygen time independent of 48-byte KEM seed |
| `lib-q-hqc:hqc128_encapsulate` | `lib-q-hqc` (`hqc-hardened`) | HQC-128 KEM encapsulation | Encapsulation time independent of pk / encapsulation PRNG |
| `lib-q-hqc:hqc192_encapsulate` | `lib-q-hqc` (`hqc-hardened`) | HQC-192 KEM encapsulation | Encapsulation time independent of pk / encapsulation PRNG |
| `lib-q-hqc:hqc256_encapsulate` | `lib-q-hqc` (`hqc-hardened`) | HQC-256 KEM encapsulation | Encapsulation time independent of pk / encapsulation PRNG |
| `lib-q-hqc:hqc128_decapsulate` | `lib-q-hqc` (`hqc-hardened`) | HQC-128 KEM decapsulation | Decapsulation time independent of secret key / ciphertext |
| `lib-q-hqc:hqc192_decapsulate` | `lib-q-hqc` (`hqc-hardened`) | HQC-192 KEM decapsulation | Decapsulation time independent of secret key / ciphertext |
| `lib-q-hqc:hqc256_decapsulate` | `lib-q-hqc` (`hqc-hardened`) | HQC-256 KEM decapsulation | Decapsulation time independent of secret key / ciphertext |

CI smoke (`BatteryConfig::smoke`, `self_cert_smoke`) collects **HQC-128 only** with four
samples per class; HQC-192/256 are included in the default full battery
(`BatteryConfig::default`, ignored `self_cert_full_report`).

Verifier paths and pure hash derivations (nullifiers, federation digests) are
covered as additional timing screens through
[`privacy_workloads`](../lib-q-sca-test/src/privacy_workloads.rs). Prover paths that
are data-dependent **by construction** and are not hardened (e.g. non-hardened
rejection sampling in blind issuance) are excluded; their timing is not a
meaningful TVLA target and is documented as such.

## Method

### Fixed-vs-random classes

Each target defines two measurement classes:

- **Fixed:** one fixed secret input, repeated.
- **Random:** the secret input rotates per sample.

A Welch two-sample *t*-statistic is computed on the per-class measurement
populations. The class construction for each target is recorded in the evidence
report's `notes` field.

### Decision rule

For per-target statistic *t* and threshold *T* (default 4.5):

- `pass` — *t* is finite and `|t| < T`.
- `fail` — *t* is finite and `|t| >= T`.
- `inconclusive` — *t* could not be computed (insufficient samples, zero variance,
  or non-finite). An inconclusive result is **not** a pass: the property has not
  been demonstrated.

A self-certification run is **clean** only when every target returns `pass`
([`SelfCertReport::all_pass`](../lib-q-sca-test/src/report.rs)).

### Measurement channels

| Channel | Source | Use |
|---------|--------|-----|
| `wall_clock_timing` | `std::time::Instant` inside [`lib-q-sca-test`](../lib-q-sca-test) | Unattended timing screening; subject to OS scheduler noise |
| `ingested_trace` | External acquisition (oscilloscope / EM probe / cycle counter) | Power, EM, or cycle-accurate evidence fed through the same TVLA gate |

Wall-clock timing is the only channel the harness can produce without external
hardware. It is sensitive to coarse, secret-independent effects (allocation,
branch mispredict on public data) and cannot characterise power or EM leakage.
Higher-fidelity channels are acquired on an instrumented rig and ingested.

### External trace ingestion

The acquisition rig writes one numeric measurement per token (whitespace- or
newline-separated; `#` comment lines ignored), one file per class. The measurement
may be a leakage point of interest, a point-wise *t* maximum, or a cycle count.
[`lib_q_sca_test::ingest::screen_trace_files`](../lib-q-sca-test/src/ingest.rs)
parses the two class files and emits an `ingested_trace` report through the same
Welch gate, so power/EM evidence and software-timing evidence share one decision
rule and one report schema.

## Running

### CI smoke (every build)

```bash
cargo test -p lib-q-sca-test --features lattice-zkp-hardened \
    --test self_cert_report self_cert_smoke
```

Validates the battery and evidence-package plumbing at reduced sample counts. It
does not assert a leakage bound — wall-clock TVLA under CI scheduling is too noisy
to gate on a single verdict.

### Full timing battery (archival evidence)

```bash
cargo test -p lib-q-sca-test --features lattice-zkp-hardened \
    --test self_cert_report self_cert_full_report -- --ignored --nocapture
```

Runs the default-sized battery (10 000 timings per class per target) and writes a
dated evidence package to `target/sca-self-cert/<unix-ts>/`:

- `report.json` — machine-readable evidence, schema `libq.sca.self-cert.v1`.
- `report.md` — human-readable summary table.

For instrumented runs, raise `BatteryConfig::samples_per_class` toward the ISO/IEC
17825 trace budget and pin the environment (fixed CPU, SMT disabled, governor
fixed) so the timing channel is not dominated by scheduler noise.

### Power / EM evidence

After acquiring per-class measurements on the rig:

```rust
use std::path::Path;
use lib_q_sca_test::ingest::screen_trace_files;

let report = screen_trace_files(
    "lib-q-ml-dsa:sign:em-poi",
    Path::new("traces/fixed.txt"),
    Path::new("traces/random.txt"),
    4.5,
)?;
println!("{}", report.to_json()); // archive alongside the timing battery
```

## Evidence package

| Artifact | Schema / format | Contents |
|----------|-----------------|----------|
| `report.json` | `libq.sca.self-cert.v1` | Environment (OS, arch, pointer width, harness version, timestamp) and one entry per target (channel, samples/class, *t*-statistic, threshold, verdict, notes) |
| `report.md` | Markdown | Same data as a review table with a pass/fail/inconclusive summary |

Archive both artifacts with the release they describe. The
[release attestation string](hardened-attestation.md#release-attestation-string-template)
references the build versions the package covers.

## Boundary of self-certification

Self-certification provides repeatable internal evidence. It does **not** provide:

- **Power/EM coverage from software alone.** Those channels require an instrumented
  rig; the harness only ingests externally acquired traces.
- **Microarchitectural coverage.** Cache, SMT, and transient-execution channels are
  platform-dependent and out of scope (see
  [hardened-attestation.md](hardened-attestation.md)).
- **Higher-order leakage coverage.** First-order TVLA does not detect higher-order
  leakage; higher-order masking and its evaluation are tracked in
  [higher-order-masking-milestone.md](higher-order-masking-milestone.md).
- **Accredited certification.** Only an accredited laboratory can issue an ISO/IEC
  17825 or FIPS 140-3 result. No libQ crate has completed independent side-channel
  certification unless stated in a signed release note.

A clean self-certification run is the entry criterion for engaging a laboratory: it
demonstrates the team has exercised the channels it can measure and resolved the
defects those channels expose.
