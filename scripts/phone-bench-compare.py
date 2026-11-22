#!/usr/bin/env python3
"""Compare phone-bench JSON files from several hosts and apply the L5 / S3 pass rules.

Thresholds are copied from the credential-track research note, section 7:
  L5 (lattice): phone show <= 1.0 s, verify <= 100 ms, peak RSS <= 64 MB, show size <= 64 KB
  S3 (STARK)  : phone prove <= 3 s,  verify <= 50 ms,  peak RSS <= 256 MB, proof <= 200 KB

A verdict is only given for a track when
  * a result file with host class "phone" exists for that track, and
  * the workload is not a stand-in (see `phone-bench list`).
Otherwise the verdict is INCONCLUSIVE and says why. A stand-in can never pass or fail a track.

Usage: phone-bench-compare.py result.json [result.json ...]
"""
import json
import sys

KIB = 1024
TRACKS = {
    "lattice": {"step": "L5", "prove_ms": 1000, "verify_ms": 100, "rss_kib": 64 * 1024, "bytes": 64 * KIB},
    "stark": {"step": "S3", "prove_ms": 3000, "verify_ms": 50, "rss_kib": 256 * 1024, "bytes": 200 * KIB},
}


def load(paths):
    rows = []
    for p in paths:
        with open(p, encoding="utf-8") as f:
            doc = json.load(f)
        if doc.get("schema") != 1:
            sys.exit(f"{p}: unsupported schema {doc.get('schema')!r}")
        for r in doc["results"]:
            res = r["result"]
            rows.append({
                "file": p, "commit": doc["commit"], "host": doc["host"], "iters": doc["iters"],
                "workload": r["workload"], "track": r["track"], "standin": r["standin"],
                "ok": res.get("ok", False), "res": res,
            })
    return rows


def main(paths):
    rows = load(paths)
    if not rows:
        sys.exit("no results")
    commits = {r["commit"] for r in rows}
    warn = "   WARNING: results from different commits" if len(commits) > 1 else ""
    print(f"commits: {', '.join(sorted(commits))}{warn}")
    print()
    hdr = f"{'workload':32} {'host class':16} {'iters':>5} {'prove ms':>10} {'verify ms':>10} {'bytes':>10} {'RSS MiB':>8}  note"
    print(hdr)
    print("-" * len(hdr))
    for r in sorted(rows, key=lambda r: (r["track"], r["workload"], r["host"]["class"])):
        res = r["res"]
        if not r["ok"]:
            print(f"{r['workload']:32} {r['host']['class']:16} {r['iters']:>5} FAILED: {res.get('error')}")
            continue
        rss = res.get("peak_rss_kib")
        rss_s = "-" if rss is None else f"{rss / 1024:.1f}"
        print(f"{r['workload']:32} {r['host']['class']:16} {r['iters']:>5} {res['prove_ms_median']:>10.1f} "
              f"{res['verify_ms_median']:>10.1f} {res['wire_bytes']:>10} {rss_s:>8}"
              f"  {'stand-in' if r['standin'] else ''}")
    print()
    exit_code = 0
    for track, th in TRACKS.items():
        cand = [r for r in rows if r["track"] == track]
        phone = [r for r in cand if r["host"]["class"] == "phone"]
        real = [r for r in phone if not r["standin"]]
        label = f"{th['step']} ({track})"
        if not real:
            if not cand:
                why = "no results for this track"
            elif not phone:
                why = "no phone result"
            else:
                why = "only stand-in workloads were measured on the phone"
            print(f"{label}: INCONCLUSIVE - {why}; no pass/fail verdict is given.")
            continue
        for r in real:
            res = r["res"]
            if not r["ok"]:
                print(f"{label} {r['workload']}: FAIL - workload errored: {res.get('error')}")
                exit_code = 1
                continue
            rss = res.get("peak_rss_kib")
            if rss is None:
                print(f"{label} {r['workload']}: INCONCLUSIVE - peak RSS not available on this host")
                continue
            checks = [
                ("prove", res["prove_ms_median"], th["prove_ms"], "ms"),
                ("verify", res["verify_ms_median"], th["verify_ms"], "ms"),
                ("size", res["wire_bytes"], th["bytes"], "B"),
                ("peak RSS", rss, th["rss_kib"], "KiB"),
            ]
            bad = [f"{n} {v} {u} > {lim} {u}" for n, v, lim, u in checks if v > lim]
            if bad:
                print(f"{label} {r['workload']}: FAIL - " + "; ".join(bad))
                exit_code = 1
            else:
                print(f"{label} {r['workload']}: PASS")
    print()
    print("Decision rule (note section 7): L5 pass -> BLNS is the E4 option; L5 fail and S3 pass -> STARK AIR is E3;")
    print("both pass -> lattice for attribute presentations, STARK for membership-only; neither -> v1 pairwise credentials.")
    return exit_code


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1:]))
