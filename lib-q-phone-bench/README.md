# lib-q-phone-bench

One harness that measures both credential tracks on the same hosts, so lattice vs STARK is compared
on the same numbers. Implements the measurement side of steps **L5** and **S3** in the
credential-track research note, section 7. Tooling only (`publish = false`).

## What it records

Per workload, per host: median prove ("show") time, median verify time, proof size as serialised
on the wire, and **peak RSS**. Each workload runs in its own child process, so peak RSS is that
workload's, not the running maximum of the whole run. The JSON also records commit, OS, arch, CPU
model and flags, iteration count and thread count (always 1: no `parallel` features are enabled).

| workload | track | what it is |
|---|---|---|
| `lattice.private_membership` | lattice | `lib-q-lattice-zkp` private membership proof, PVTN profile |
| `lattice.opening` | lattice | `lib-q-lattice-zkp` Ajtai opening proof, token-spend profile |
| `stark.membership_bb_zk` | stark | Arm B (BabyBear/Poseidon2), hiding. The arm the note's 0.95-1.21 MB refers to |
| `stark.membership_zk` | stark | Arm A (Complex Mersenne31), hiding, verified from the frozen wire envelope. About 17 MB |

**Every workload is currently a stand-in** (`phone-bench list` shows `standin=true`). The BLNS
presentation for the L3 attribute profile (L4) and the narrow-trace attribute AIR (S1/S2) do not
exist yet. The lattice stand-ins use all-zero witnesses and are far smaller than a BLNS show, so
**their timings must not be read as the L5 answer**. When the real workloads land, add them to
`ALL` in `src/workloads.rs` with `standin: false`; nothing else changes.

## Running

```sh
# x86 or aarch64 desktop
cargo build --release -p lib-q-phone-bench
target/release/phone-bench run --class desktop-x86 --label "ryzen 5900X" --out x86.json
target/release/phone-bench run --class desktop-aarch64 --label "mac mini M-series" --out a64.json

# Android arm64 over adb (needs ANDROID_NDK_HOME, rustup target add aarch64-linux-android)
scripts/phone-bench-android.sh -o phone.json -l "pixel 7a"

# compare, and apply the L5 / S3 pass rules
python3 scripts/phone-bench-compare.py x86.json a64.json phone.json
```

Options: `--iters N` (default 11, the note's median of 11), `--depth D` (default 20; Arm B rounds
up to a power of two, min 8), `--workload NAME` (repeatable).

`phone-bench-compare.py` only gives PASS/FAIL for a track when a `--class phone` file contains a
non-stand-in workload for it. Otherwise it prints INCONCLUSIVE and says why.

## Verified vs not (state at the time of writing)

Verified by running it on a 2-core x86_64 VM (AMD EPYC, not the Ryzen 5900X from the note):
the harness builds, all four workloads run and verify, JSON is produced, the compare script
reads it, and the stand-in refusal and the PASS/FAIL branches behave as described. Arm B at
depth 32 gave 1 211 470 B, matching the 1 211 498 B in `lib-q-zkp/docs/membership-arm-b-measurement.md`.

`cargo check --target aarch64-unknown-linux-gnu` passes.

**Not verified:** anything on a real aarch64 desktop or Android phone. `scripts/phone-bench-android.sh`
has only been syntax-checked (`bash -n`); there was no NDK or device. The macOS peak-RSS path
(`nix::sys::resource::getrusage`, a safe wrapper over `getrusage(2)`; macOS reports bytes, converted
to KiB) was not compiled. On a Linux-kernel Android the `/proc/self/status` `VmHWM` path is used,
which was exercised on Linux only. Timings from the VM are not phone numbers.

## Notes for whoever runs it on the phone

- Run with the device cool and on mains power; thermal throttling dominates a phone run. Note the
  governor and whether the device was idle in `--label`.
- Release builds use the workspace profile, no `target-cpu=native`, so the numbers reflect what the
  library ships.
- Arm A's verify (~0.5 s on x86) alone exceeds S3's 50 ms bound, and its size exceeds 200 KB by
  about 85x. That is a property of the existing Arm A parameters, not of the harness.
