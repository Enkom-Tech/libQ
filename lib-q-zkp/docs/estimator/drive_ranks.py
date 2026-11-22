import os
import subprocess
import sys

# Python interpreter that has passagemath and fpylll installed (defaults to the current one).
PY = os.environ.get("ESTIMATOR_PYTHON", sys.executable)
jobs = [("lwe", k) for k in (27, 28, 29, 30)] + [("sis", k) for k in (18, 19, 20, 21)]
procs = [(w, k, subprocess.Popen([PY, "-I", __import__("os").path.join(__import__("os").path.dirname(__import__("os").path.abspath(__file__)), "estimate_ranks.py"), w, str(k)],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True))
         for w, k in jobs]
for w, k, p in procs:
    try:
        out, _ = p.communicate(timeout=800)
    except subprocess.TimeoutExpired:
        p.kill()
        out = "TIMEOUT"
    print(w, k, "->", out.strip().splitlines()[-1] if out.strip() else "no output", flush=True)
