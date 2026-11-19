# lib-q-ct-kat (`cargo ct-kat`)

A screening tool in the style of CT-KAT (ePrint 2026/1418, Lee/Kim/Jeong/Seo): it checks C
entry points for constant-time risks and folds the evidence into one verdict. A passing verdict is
a screening result, **not** proof of constant-time behaviour.

Standalone crate (own `[workspace]`, own lockfile), like `benches/`: it shells out to C
toolchains and must not change the dependency resolution of the shipped crates.

```
cargo build --release --manifest-path lib-q-ct-kat/Cargo.toml     # produces cargo-ct-kat
cargo ct-kat -c config.yaml [--ci | --interactive] [--report out.json] [--keep] [--verbose] [--only <target>]
cargo ct-kat gc                                                  # reap dirs of interrupted runs
```
Exit codes: `0` gate passed, `1` gate blocked, `2` usage / config / I/O error.

## Layers

| layer | what it does | needs |
|---|---|---|
| `build_kat` | builds the generated harness, runs it twice (determinism), compares `expected_out_hex` if given | C compiler |
| `memcheck` | marks `secret` buffers undefined via Valgrind client requests, runs under Memcheck; uninitialised-value use in a branch / address => finding | valgrind + `valgrind/memcheck.h` |
| `ct_matrix` | rebuilds under every compiler x `-O` level, compares KAT output and memcheck results across cells; any difference => `build-sensitive` | compilers, valgrind |
| `asm_scan` | `-S` per cell, scans for division instructions and runtime division helpers (x86, aarch64, arm, riscv) | compilers |
| `dudect` (opt-in) | fixed-vs-random secret timing, Welch t over percentile crops | compiler |

## Verdicts and the default-deny rule

`robust`, `varlat-secret-risk`, `accepted-variable-time`, `needs-analysis` are named in the paper's
abstract. The paper's full nine-class list could not be fetched (eprint.iacr.org served a bot
challenge), so `secret-branch-risk`, `secret-index-risk`, `timing-leak-suspected`,
`build-sensitive`, `invalid-target` are this tool's own labels and may not match the paper's.

* An analysis layer that cannot run (tool missing, timeout, target crash, ...) is `ERROR`, and the
  target becomes `needs-analysis`. A missing check never reads as constant-time.
* `robust` needs `build_kat`, `memcheck`, `ct_matrix`, `asm_scan` all to pass. A disabled
  required layer also yields `needs-analysis`.
* A failing layer can be accepted only by a written `triage:` justification in the config; that
  gives `accepted-variable-time`. An `ERROR` can never be triaged away.
* Only `robust` and `accepted-variable-time` pass the gate.

## Config

See `examples/libq-e2e.yaml` and `tests/ct-kat_synthetic.rs`. Per target: `sources`,
`include_dirs`, `link_args`, `function`, `args` (`secret|public|out|len`), `return`,
`expected_out_hex`, `triage`. Global: `compilers`, `opt_levels`, `timeout_secs`, `layers`, `dudect`.

## Run isolation, CI mode

Each run uses `target/ct-kat/run-<random id>/` (created with `create_dir`, retried on collision,
removed afterwards unless `--keep`); stale ones from interrupted runs are reaped by pid liveness
(Linux) / age. The JSON report goes to `target/ct-kat/report-<id>.json` unless `--report`.
`--ci` (or `CI` set, or stdout not a TTY) prints JSON only; `--interactive` prints a table. Both
render the same in-memory report.

## Known limits

* `asm_scan` sees only the **C** sources it is given. For Rust code behind a C-ABI shim
  (`shim/`) it scans the C wrapper, not the Rust, so its PASS there says nothing about the Rust.
* The division scan does not know which divisors are secret: every hit is a candidate.
* dudect is wall-clock and noisy on shared hosts; thresholds are configurable.
* Harness prototypes use `unsigned char *` / `size_t`; targets with other parameter types need a wrapper.
