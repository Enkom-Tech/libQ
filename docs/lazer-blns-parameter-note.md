# LaZer BLNS anonymous-credential parameters: L0 reproduction and L1 estimator checks

- Scope: research, steps L0 (reproduction) and L1 (estimator checks) of an internal plan.
- Date: 2026-11-03. Status: research note, no code change, no security claim about libQ code.
- Artefacts: the scripts are in `docs/lazer-blns-l1/`. **The raw logs are NOT committed** (the repository
  ignores `*.log`, and they were not force-added). Wherever this note says "VERIFIED" it means "run by
  the author in a scratch environment, output read from the console", not "checkable from this
  repository". Re-run the scripts to check any figure; the log names below name the output of each run.
- Register: **VERIFIED** = run by the author as described, **log not committed**. **INHERITED** = read from
  another document, not re-run. **INFERRED** = reasoning, not measured.

## 1. Result in one paragraph

ev: (logs not committed, see Artefacts) every bit-count below comes from `grep 'min log2 rop' docs/lazer-blns-l1/*.log` (L1, `l1.py`) and
`cat docs/lazer-blns-l1/sens.log` (cost-model sweep, `l1_sens.py`); every size and time in section 2 comes
from `cat docs/lazer-blns-l1/l0_runs.log` (11 runs of `l0_runs.sh`, median computed from that file).
ev: doctest counts in section 5 are from running `doctest.testmod` on `estimator.{reduction,sis_lattice,lwe_primal,lwe_dual}`
in the same environment (`TestResults(failed=0, attempted=85)`, `failed=2, attempted=11`, `failed=4, attempted=25`, `failed=0, attempted=26`).

L0: the LaZer anonymous-credential demo at the paper's pinned commit builds and runs on AVX2 only
(no AVX-512) and reproduces the **size** (29.1 KB show) but not the 0.2 s show time inside the plan's
10 % band; it is faster in the median and very noisy. L1: both sides of the LaZer parameter set
come out at **129.2 bits (MLWE) and 129.4 bits (MSIS)** under the estimator's default MATZOV cost
model, with weak-instance controls at 39.7 and 41.2 bits. **The headline depends on the reduction
cost model**: the same two instances are 101 bits under ADPS16 classical and 122 bits under
LaaMosPol14, and only 89 bits under ChaLoy21. The margin over 128 is about 1.2 bits on the default
model and negative on three of the six models tried. The plan's L2 requirement (at least 138 bits on
both sides) is **not met** on any model tried; the best case, GJ21, gives 135.5 (MLWE) and 135.8 (MSIS).

## 2. L0: reproduction (VERIFIED)

| item | value |
|---|---|
| LaZer commit | `10eafeca4cd53ff4fc54193dce904dbd0026fefd` (the commit the README names for the CCS 2024 paper) |
| labrador submodule | `8b6626b26afd4c0162ddd089759d21d3d51bfbdf`, fetched from `github.com/lattice-dogs/labrador` over https (the `.gitmodules` ssh URL could not be used in the environment; `lazer-crypto/labrador` does not contain that commit) |
| parameter header | `python/anon_cred/anon_cred_params.h` as committed, not regenerated (no Sage). Byte-identical to the header at LaZer HEAD `b958e247` (`cmp`) |
| host | AMD EPYC, 2 vCPU, flags include `avx2`, **no `avx512f`**; gcc 14.3.0; shared VM, so timings are noisy |
| runs | 11 separate processes of `python/anon_cred/anon_cred.py` (`docs/lazer-blns-l1/l0_runs.sh`, output `l0_runs.log`) |

| quantity | this run (11 runs) | plan / paper | within 10 %? |
|---|---|---|---|
| show proof P2 | 29 083 to 29 143 B (about 29.1 KB) | 29.1 KB | yes |
| blinded credential | 1 300 to 1 312 B | 1.3 KB | yes |
| masked credentials P1 (issue request) | 20 409 to 20 434 B | not in the plan | n/a |
| show time, median | 0.152 s (min 0.111, max 0.227) | about 0.2 s (0.198 s paper) | median is 23 % below; **outside the band** |
| issue time, median | 0.077 s | 0.117 s paper | 34 % below |

How to read the time rows: the demo times only the Python-level user and verifier calls, on a
different CPU from the paper's, so a faster result is plausible but is **not** a confirmation of
0.2 s. The spread across runs (0.111 to 0.227 s) is larger than the band, so a 10 % check on a
single number is not meaningful on this host. The earlier libQ run (INHERITED, 0.202 s show, Ryzen 9
5900X) sits inside that spread. Strictly by the plan's wording, L0 "reproduces 29.1 KB" and does
not reproduce "about 0.2 s within 10 %" on this host; a quiet bare-metal host is needed for that.
The LaBRADOR backend was not run (it needs AVX-512).

## 3. L1: lattice-estimator on both sides (VERIFIED)

Tool: `malb/lattice-estimator` at `ee46985f` (2026-11-02), run on passagemath 10.5.49 wheels because
the scratch environment had no SageMath (see section 5). Scripts: `l1.py`, `l1_sens.py`.

### 3.1 Instances

LaZer's header (INHERITED from the generated `anon_cred_params.h`, same bytes at both commits):

```
protocol is simulatable under MLWE(26,29,[-1,1])
protocol is knowledge-sound with knowledge error <= 2^(-127.0) under MSIS(17,79,2^(33.599457))
ring degree d = 64, modulus q = 2199023255717 (log q ~ 41.0)
MSIS root hermite factor 1.0043951, MLWE root hermite factor 1.0043734
```

Encoding used here (INFERRED from the header, not from reading LaZer's source):

- MLWE: module rank 26, 29 samples, ternary `[-1,1]` secret and error, flattened to plain LWE with
  n = 26*64 = 1664, m = 29*64 = 1856. The estimator's own `m` in the best dual-hybrid line is 1664.
- MSIS: module rank 17, 79 columns, Euclidean bound 2^33.599457, flattened to SIS with n = 17*64 =
  1088, m = 79*64 = 5056, norm 2. This ignores the module/ring structure (the conservative choice,
  since the estimator has no ring-structure speed-up for these).
- The pair `(26,29)` is read as (rank, samples). The check that supports it: the root Hermite factor
  the estimator reports for the SIS instance, 1.004391, is close to the header's MSIS value 1.0043951
  (not identical; the estimator and LaZer compute it differently), so the dimensions are at least consistent.

### 3.2 Real instances and controls, default cost model (MATZOV)

| run | best attack | bits (log2 rop) | log |
|---|---|---|---|
| MLWE(26,29,[-1,1]) | bdd / dual_hybrid | **129.17** | `mlwe_real.log` |
| MLWE control: rank 2, 3 samples, same q, d | | 39.75 | `mlwe_ctrl.log` |
| MSIS(17,79,2^33.6) | lattice (beta 347, d 2655) | **129.36** | `sis_real.log` |
| MSIS control: rank 2, 5 samples, same q, d, bound | lattice (beta 40) | 41.18 | `sis_ctrl.log` |

Controls are below 128 (the plan's requirement), so the harness does report low numbers when it
should. The MLWE figure agrees with the earlier libQ run of 129.2 (INHERITED, different estimator
checkout), and attacks `bkw` and `arora-gb` were denied on the MLWE run as in that run (they hang at
these parameters). Per-attack MLWE numbers: usvp 130.5, bdd 129.2, bdd_hybrid 129.2, dual 132.7,
dual_hybrid 129.2, bdd_mitm_hybrid 183.7.

### 3.3 Sensitivity to the reduction cost model (VERIFIED, `sens.log`)

Best-of (usvp, bdd, dual_hybrid) for LWE and the lattice attack for SIS, same instances:

| cost model | MSIS bits | MLWE bits |
|---|---|---|
| ADPS16 (classical, 0.292 beta) | 101.3 | 101.0 |
| ChaLoy21 | 89.2 | 89.2 |
| LaaMosPol14 | 122.7 | 122.0 |
| MATZOV (estimator default) | 129.4 | 129.2 |
| BDGL16 | 132.1 | 130.9 |
| GJ21 | 135.8 | 135.5 |
| Kyber (sieve) | 135.8 | error: `Kyber.short_vectors() got an unexpected keyword argument 'sieve_dim'` |

The SIS block size is 347 on every model (the attack shape does not change, only the cost per
block size). 0.292 * 347 = 101.3 is the plain classical core-SVP exponent, so the "128-bit"
reading of the header (root Hermite factor 1.0044) holds only under a cost model that adds
substantial overhead on top of core-SVP. This matters because an earlier verdict has already
moved once on the ADPS16-versus-MATZOV spread. State the cost model whenever a bit-count for these
parameters is quoted.

## 4. What this means for the plan

1. L1 is complete as written: both sides reported, control below 128 on both.
2. The 128-bit claim for the LaZer parameters is supported only on the MATZOV-class cost models
   (about 1.2 bits of margin on MLWE, 1.4 on MSIS) and not on the ADPS16 classical model.
   INFERRED consequence: L2's 138-bit target should name its cost model explicitly; on GJ21 the
   current parameters give 135.5 to 135.8 and are within 3 bits of it.
3. The MSIS side is now estimated, which the earlier libQ note listed as missing. It is no weaker
   than the MLWE side on any model tried.
4. The plan's "expect the 29 KB figure to grow" still stands; this note does not measure by how much.

## 5. Not checked, and environment deviations (read before trusting section 3)

- **No SageMath in the scratch environment.** The estimator was run on passagemath 10.5.49 wheels (modules, flint,
  symbolics) with `sage/all.py` replaced by a pure re-export of the split `all__*` modules plus a
  `line` stub (`sage_all_shim.py`; `line` is plotting-only, used by `simulator.py`). No numeric
  patches. A first shim that rerouted `sqrt`/`log` was discarded: it changed behaviour (it hit an RDF
  overflow in a sanity check) and was replaced by the symbolics install.
- Smoke check of the setup: Kyber-512 primal-uSVP gave beta 406 at 2^118.6 (ADPS16) and 2^143.8
  (MATZOV) in the runs above. I did not compare these against the estimator's published tables.
- Estimator doctests: `reduction` 85/85, `lwe_dual` 26/26, `sis_lattice` 9/11, `lwe_primal` 21/25 pass.
  All 6 failures are the `cn11` shape-simulator branch, which needs `fpylll` (not installed);
  my runs use the default `gsa` shape model. Other estimator modules were not doctested.
- The scratch environment also lacked `m4`, `gmp.h` and `mpfr.h`; GMP 6.3.0, MPFR 4.2.2 and m4 1.4.19 were built
  from source into a scratch directory (`build_deps.sh`) and linked statically. cmake 4.x needed
  `CMAKE_POLICY_VERSION_MINIMUM=3.5` for HEXL's bundled cpu_features. Not a security concern, but
  the L0 binaries are not from a pristine toolchain.
- The L0 numbers are from the Python demo only; the C demos, the LaBRADOR backend and the
  paper's own benchmark harness were not run. No aarch64 or phone measurement (L5).
- I did not read LaZer's `lin-codegen.sage` to confirm the encoding in 3.1 beyond the root Hermite
  factor cross-check. An MSIS/MLWE encoding that differs from mine would move the numbers.
- The estimator models module instances as plain LWE/SIS. Ring-structure attacks are not modelled.
- Not a substitute for cryptographer review; every construction here remains RED.

## 6. Reproduce

Environment: Python 3.13 venv with `passagemath-modules/flint/categories/symbolics==10.5.49`, scipy,
cffi, setuptools; copy `sage_all_shim.py` over `site-packages/sage/all.py`. Then
`python -I l1.py {mlwe_ctrl|mlwe_real|sis_ctrl|sis_real}` and `python -I l1_sens.py` with the
estimator checkout on the path (hard-coded in the scripts, edit it). L0: `build_deps.sh`, then
`make lib` and the CFFI builds in LaZer at the commit above, then `l0_runs.sh`.
