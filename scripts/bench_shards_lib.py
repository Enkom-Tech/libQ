#!/usr/bin/env python3
"""Load benchmark shard manifest for CI and local scripts."""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / ".github" / "benchmark-shards.toml"
DEFAULT_TIMEOUT_MINUTES = 20


def package_manifest_path(package: str) -> Path:
    """Resolve a workspace package name to its Cargo.toml path."""
    import subprocess

    proc = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    data = json.loads(proc.stdout)
    for pkg in data["packages"]:
        if pkg["name"] == package:
            return Path(pkg["manifest_path"])
    raise SystemExit(f"package not found in workspace metadata: {package}")


def _load_package_manifest(package: str, manifest_path: Path | None = None) -> tuple[Path, dict[str, Any]]:
    path = manifest_path or package_manifest_path(package)
    with path.open("rb") as f:
        return path, tomllib.load(f)


def lib_bench_enabled(package: str, manifest_path: Path | None = None) -> bool:
    """True when `cargo bench -p package` builds a libtest bench for src/lib.rs."""
    _, data = _load_package_manifest(package, manifest_path)
    lib = data.get("lib")
    if lib is None:
        # Implicit library target uses the package default (bench = true).
        return True
    return lib.get("bench", True) is not False


def expand_enabled_features(data: dict[str, Any], features: str) -> set[str]:
    """Resolve feature names implied by [features] (e.g. std -> alloc)."""
    enabled = {f.strip() for f in features.split(",") if f.strip()}
    if not enabled:
        enabled = set(data.get("features", {}).get("default", []))

    feature_defs: dict[str, list[str]] = data.get("features", {})
    changed = True
    while changed:
        changed = False
        for name in list(enabled):
            for dep in feature_defs.get(name, []):
                dep_name = dep.split("/", 1)[0]
                if dep_name.startswith("dep:"):
                    continue
                if dep_name not in enabled and dep_name in feature_defs:
                    enabled.add(dep_name)
                    changed = True
    return enabled


def autobenches_enabled(package: str, manifest_path: Path | None = None) -> bool:
    _, data = _load_package_manifest(package, manifest_path)
    pkg_table = data.get("package", {})
    value = data.get("autobenches", pkg_table.get("autobenches", True))
    return value is not False


def orphan_autobench_files(package: str, manifest_path: Path | None = None) -> list[str]:
    """benches/*.rs files that would become libtest autobenches (not in [[bench]])."""
    path, data = _load_package_manifest(package, manifest_path)
    bench_dir = path.parent / "benches"
    if not bench_dir.is_dir():
        return []
    declared = {row.get("path", f"benches/{row['name']}.rs") for row in data.get("bench", []) if row.get("name")}
    declared_names = {Path(p).name for p in declared}
    orphans: list[str] = []
    for rs in sorted(bench_dir.glob("*.rs")):
        if rs.name not in declared_names:
            orphans.append(rs.name)
    return orphans


def audit_shard(shard: dict[str, Any]) -> list[str]:
    """Return human-readable issues for a manifest shard row."""
    package = shard["package"]
    features = shard.get("features", "")
    pinned = shard.get("bench", "")
    issues: list[str] = []

    try:
        path, _ = _load_package_manifest(package)
    except SystemExit as exc:
        return [str(exc)]

    names = criterion_bench_names(package, features=features, manifest_path=path)
    if not names:
        issues.append(f"{package}: no Criterion benches (harness=false) for features={features!r}")

    if pinned and pinned not in names:
        issues.append(
            f"{package}: manifest bench={pinned!r} is not a Criterion target "
            f"(available: {', '.join(names) or 'none'})"
        )

    if lib_bench_enabled(package, path):
        issues.append(
            f"{package}: [lib] bench is enabled; bare `cargo bench` runs libtest before Criterion "
            f"(set `bench = false` under [lib])"
        )

    if autobenches_enabled(package, path):
        orphans = orphan_autobench_files(package, path)
        if orphans:
            issues.append(
                f"{package}: autobenches=true with undeclared benches/*.rs: {', '.join(orphans)} "
                f"(set autobenches=false or add [[bench]] entries)"
            )

    return issues


def audit_all_shards(shards: list[dict[str, Any]] | None = None) -> list[str]:
    issues: list[str] = []
    for shard in shards or load_shards():
        issues.extend(audit_shard(shard))
    # Manifest may list the same package twice (e.g. HQC portable/simd).
    return list(dict.fromkeys(issues))


def criterion_bench_names(
    package: str,
    *,
    features: str = "",
    manifest_path: Path | None = None,
) -> list[str]:
    """Return [[bench]] target names with harness=false (Criterion) for a package."""
    import subprocess

    path, data = _load_package_manifest(package, manifest_path)

    names: list[str] = []
    for row in data.get("bench", []):
        if row.get("harness", True) is not False:
            continue
        name = row.get("name")
        if not name:
            continue
        required = row.get("required-features", [])
        if required:
            enabled = expand_enabled_features(data, features)
            if not all(req in enabled for req in required):
                continue
        names.append(name)

    if names:
        return names

    # Compile-check which bench binaries exist for this feature set.
    cmd = ["cargo", "bench", "-p", package, "--no-run"]
    if features:
        cmd.extend(["--features", features])
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"cargo bench --no-run failed for {package}: {proc.stderr or proc.stdout}"
        )
    discovered: list[str] = []
    # Cargo prints bench executable lines to stderr on some platforms.
    combined_output = f"{proc.stdout}\n{proc.stderr}"
    for line in combined_output.splitlines():
        marker = "Executable benches"
        if marker not in line:
            continue
        # e.g. "  Executable benches\foo.rs (target\release\deps\sha3_benchmarks-....exe)"
        stem = line.split(marker, 1)[1].strip().split("(", 1)[0].strip()
        if stem.replace("\\", "/").endswith("src/lib.rs"):
            continue
        name = Path(stem).stem
        if name not in discovered:
            discovered.append(name)
    return discovered


def load_shards(manifest: Path | None = None) -> list[dict[str, Any]]:
    path = manifest or MANIFEST_PATH
    with path.open("rb") as f:
        data = tomllib.load(f)

    shards: list[dict[str, Any]] = []
    for row in data.get("shard", []):
        if row.get("enabled", True) is False:
            continue
        shards.append(
            {
                "id": row["id"],
                "package": row["package"],
                "features": row.get("features", ""),
                "bench": row.get("bench", ""),
                "timeout_minutes": row.get("timeout_minutes", DEFAULT_TIMEOUT_MINUTES),
            }
        )
    return shards


def matrix_json(shards: list[dict[str, Any]]) -> str:
    return json.dumps({"include": shards}, separators=(",", ":"))


REQUIRED_MATRIX_ROW_KEYS = frozenset(
    {"id", "package", "features", "bench", "timeout_minutes"}
)


def verify_matrix_payload(raw: str, *, expected_shards: list[dict[str, Any]] | None = None) -> None:
    """Ensure JSON is valid for GitHub Actions strategy.matrix fromJson."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"matrix JSON parse error: {exc}") from exc

    if not isinstance(data, dict) or set(data.keys()) != {"include"}:
        raise SystemExit('matrix JSON must be a single object with key "include"')

    include = data["include"]
    if not isinstance(include, list) or not include:
        raise SystemExit('matrix JSON "include" must be a non-empty list')

    ids: list[str] = []
    for index, row in enumerate(include):
        if not isinstance(row, dict):
            raise SystemExit(f"matrix row {index} is not an object")
        missing = REQUIRED_MATRIX_ROW_KEYS - row.keys()
        if missing:
            raise SystemExit(f"matrix row {index} missing keys: {sorted(missing)}")

        for key in ("id", "package", "features", "bench"):
            value = row[key]
            if not isinstance(value, str):
                raise SystemExit(f"matrix row {index}: {key} must be a string")

        if not row["id"].strip() or not row["package"].strip():
            raise SystemExit(f"matrix row {index}: id and package must be non-empty")

        timeout = row["timeout_minutes"]
        if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1:
            raise SystemExit(f"matrix row {index}: timeout_minutes must be a positive integer")

        ids.append(row["id"])

    if len(ids) != len(set(ids)):
        raise SystemExit("matrix JSON contains duplicate shard id values")

    if expected_shards is not None and len(include) != len(expected_shards):
        raise SystemExit(
            f"matrix row count {len(include)} does not match manifest ({len(expected_shards)})"
        )


def main() -> int:
    if len(sys.argv) < 2:
        print(
            "Usage: bench_shards_lib.py matrix|list|criterion-benches|audit|verify-matrix",
            file=sys.stderr,
        )
        return 2

    shards = load_shards()
    command = sys.argv[1]

    if command == "matrix":
        print(matrix_json(shards))
        return 0

    if command == "list":
        for shard in shards:
            print(shard["id"])
        return 0

    if command == "criterion-benches":
        if len(sys.argv) < 3:
            print("Usage: bench_shards_lib.py criterion-benches PACKAGE [FEATURES]", file=sys.stderr)
            return 2
        package = sys.argv[2]
        features = sys.argv[3] if len(sys.argv) > 3 else ""
        for name in criterion_bench_names(package, features=features):
            print(name)
        return 0

    if command == "audit":
        issues = audit_all_shards(shards)
        if issues:
            for issue in issues:
                print(f"ERROR: {issue}", file=sys.stderr)
            return 1
        print(f"audit: OK ({len(shards)} shards)")
        return 0

    if command == "verify-matrix":
        raw = Path(sys.argv[2]).read_text(encoding="utf-8") if len(sys.argv) > 2 else sys.stdin.read()
        verify_matrix_payload(raw, expected_shards=shards)
        print(f"verify-matrix: OK ({len(shards)} shards)")
        return 0

    print(f"Unknown command: {command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
