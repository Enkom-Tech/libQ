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
        print("Usage: bench_shards_lib.py matrix|list|verify-matrix", file=sys.stderr)
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

    if command == "verify-matrix":
        raw = Path(sys.argv[2]).read_text(encoding="utf-8") if len(sys.argv) > 2 else sys.stdin.read()
        verify_matrix_payload(raw, expected_shards=shards)
        print(f"verify-matrix: OK ({len(shards)} shards)")
        return 0

    print(f"Unknown command: {command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
