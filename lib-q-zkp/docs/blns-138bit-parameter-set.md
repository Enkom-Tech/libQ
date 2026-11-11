# BLNS / LNP22 anonymous-credential parameters with a 10-bit margin (L2)

Status: **PARTIAL.** The security-estimate half is measured. The proof-size and timing half is **not**
re-measured (no LaZer build was possible in the environment used; see "Not done").

Target: 128 bits plus a 10-bit margin, i.e. **>= 138 bits on both the MLWE and the MSIS side.**

Every figure below is from the estimator's **default cost model only**, which is a MATZOV-class
model. Other models give lower numbers on the same baseline: the sibling LaZer L1 note reports about
101 bits (ADPS16) and about 89 bits (ChaLoy21), so ">= 138" must not be read as model-independent.

**Raw estimator output is not committed.** The tables were copied from console output of the scripts
in `docs/estimator/` and no log was saved, so the numbers are unlogged and can only be checked by
re-running. They were also computed at q = 2^41 (2199023255552), an approximation of LaZer's
q = 2199023255717; the two differ by 165 and the effect on the estimates was not measured.

## 1. Baseline, re-run with the real estimator (this also supplies the missing L1 MSIS number)

Tool: malb/lattice-estimator at commit `ee46985`, run under `passagemath-modules/-flint/-repl/-symbolics`
and `fpylll` installed with `uv` (the full `passagemath-standard` does not fit in a 3 GB tmpfs), with a
small `sage.all` shim (`docs/estimator/sage_all_shim.py`). Default cost model; `arora-gb` and `bkw`
denied on the LWE side, as in `anon-cred-wire-fork-recommendation.md` section 4.

LaZer baseline (`anon_cred_params.h`): d = 64, q = 2199023255717 (about 2^41; the scripts use 2^41,
see above),
MLWE(26,29,[-1,1]), MSIS(17,79,B = 2^33.599457), treated as plain LWE / SIS over Z_q
(n = 64 x rank).

| instance | control (must be < 128) | real |
|---|---|---|
| MLWE, n=1664, m=1856, ternary | 41.1 bits (n=256) | **129.2 bits** |
| MSIS, n=1088, m=5056, l2 bound 2^33.599457 | 40.9 bits (ad hoc: n=64, B=2^20) | **129.4 bits** |

The MLWE row reproduces section 4 of the research note exactly (129.2 / 41.1). The MSIS row is new.
The MSIS control is my own ad hoc weak instance, not a LaZer parameter. Both sides sit about 1 bit
over 128, so neither has the 10-bit margin.

## 2. Rank sweep (q, d, B and the declared noise held fixed)

MLWE rank k with m = 64(k+3) samples; MSIS rank k with m = 64(k+62) columns; everything else as above.
Minimum over all attacks the estimator ran.

| MLWE rank | bits | | MSIS rank | bits |
|---|---|---|---|---|
| 26 (baseline) | 129.2 | | 17 (baseline) | 129.4 |
| 27 | 134.5 | | 18 | 137.8 |
| **28** | **139.4** | | **19** | **146.4** |
| 29 | 144.4 | | 20 | 155.1 |
| 30 | 150.0 | | 21 | 163.8 |

Smallest set meeting >= 138 on both sides under these assumptions: **MLWE(28, 31, [-1,1]) and
MSIS(19, 81, B)**. MSIS rank 18 gives 137.8 bits and misses by 0.2, so it does not count.

## 3. Caveats (these matter)

- **B is held fixed. It will not stay fixed.** In LaZer the extractable norm bound B is derived by the
  parameter generator from the ranks and the challenge set. Larger ranks change B, and a larger B
  lowers MSIS security. The MSIS figures above are therefore an upper bound on what a regenerated set
  achieves at the same ranks. The real answer needs `lin-codegen.sage` re-run with the new ranks, then
  this estimate re-run on the generated header.
- The estimate treats the module problems as unstructured LWE/SIS (same as the research note); it
  ignores any ring-structure speedup.
- Both rows use the estimator's default cost model; the spread between models is not explored here.
- The claim "meets 138" is for the estimator's minimum over the attacks it ran, not a proof.

## 4. Size and timing: NOT re-measured

Baseline L0 (INHERITED from the research note, not re-run): 29.1 KB proof, about 0.2 s.
ESTIMATE only: ranks rise by about 8% (26 to 28) on the MLWE side and about 12% (17 to 19) on the MSIS
side, so I would expect a proof a bit larger than 29.1 KB, plausibly on the order of 10% more. This is a
guess from the rank ratios, not a measurement. Nothing here has been built or timed.

## 5. Not done

- Regenerate LaZer parameters (`lin-codegen.sage`) at the new ranks, read the new B, and re-run the
  MSIS estimate on it.
- Build LaZer, run `python/anon_cred/anon_cred.py`, record proof size and prover/verifier time.
  Blocked in the environment used: no `gmp.h` or `mpfr.h` headers, no cffi or jinja2, and the disk
  was nearly full.
- Map the chosen ranks onto `lib-q-lattice-zkp` parameters (this note does not touch any crate code).

## Reproduce

```
uv venv venv --python "$(command -v python3)"
VIRTUAL_ENV=$PWD/venv uv pip install --no-cache passagemath-modules passagemath-flint passagemath-repl fpylll passagemath-symbolics
git clone https://github.com/malb/lattice-estimator          # commit ee46985
export LATTICE_ESTIMATOR=$PWD/lattice-estimator
export ESTIMATOR_PYTHON=$PWD/venv/bin/python
export LD_LIBRARY_PATH=<dir holding libstdc++.so.6>           # only if the venv cannot find it
cd lib-q-zkp/docs/estimator
$ESTIMATOR_PYTHON estimate_base.py lwe ; $ESTIMATOR_PYTHON estimate_base.py sis   # section 1
$ESTIMATOR_PYTHON drive_ranks.py                                                   # section 2
```

`sage_all_shim.py` is imported from the directory of the scripts; the estimator is found through
`LATTICE_ESTIMATOR`. Set `Q=2199023255717` to re-run with LaZer's exact modulus.
