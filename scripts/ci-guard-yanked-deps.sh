#!/usr/bin/env bash
# Guard: a published (non-yanked) lib-q-* crate must not depend on a crate version that is
# YANKED on crates.io.
#
# WHY THIS EXISTS
# ----------------
# lib-q-zk-encryption-proof@0.0.10 shipped depending on lib-q-threshold-kem-lattice ^0.0.10.
# lib-q-threshold-kem-lattice was later fully yanked (every version) -- AFTER zk-encryption-proof
# had already been published against it -- and only then was zk-encryption-proof itself yanked to
# match, a manual, after-the-fact catch. Verified against the real registry 2026-08-11: at that
# point BOTH crates were fully yanked (every version, no live release) and zero other published
# lib-q-* crate depended on either -- a fact about that day, not a standing guarantee.
#
# TWO DISTINCT QUESTIONS, TWO MODES
# -----------------------------------
# 1. "Is the tree I am about to BUILD/PUBLISH consuming a yanked registry artifact right now?"
#    -> the default (lockfile) mode. Reads Cargo.lock. Fast, no rate-limit concern, belongs in
#    core-validation, runs on every PR.
#
#    THE TRAP THIS MODE MUST NOT FALL INTO: in this workspace, lib-q-* -> lib-q-* edges in
#    Cargo.lock are almost always PATH dependencies on workspace members (Cargo resolves the
#    local source tree, not crates.io), and the workspace happens to be at version 0.0.10 -- the
#    exact version that is yanked for both crates above. A guard that checks "(name, version) in
#    Cargo.lock is yanked?" without checking WHERE that entry is sourced from fires on our own
#    local source tree, which consumes nothing from the registry and is not a defect. That is a
#    false positive that happens to name the real incident's pair, which is exactly what makes it
#    look like a catch instead of a bug. A Cargo.lock package entry only names an artifact
#    actually pulled from crates.io when it carries a `source = "registry+..."` line; a
#    workspace-member path dependency has NO `source` line at all. This mode only queries
#    crates.io for entries that carry that line.
#
#    HONEST LIMITATION, so nobody reads mode 1's green as more than it is: because EVERY
#    lib-q-* -> lib-q-* edge in this workspace is currently a path dependency (368 of them, all
#    skipped), mode 1 has no reachable failure in this repo as it stands today. It would fire only
#    if a lib-q-* crate were ever consumed from the registry rather than the local tree. It is
#    cheap insurance against that day, NOT the control that catches the incident described above
#    -- `--published` is. Mode 1's detection mechanism is still re-proved on every invocation by
#    the self-test (the mutation battery runs inline before any real verdict), so a green here
#    means "the check works and found nothing", not "the check ran and could never have spoken".
#
# 2. "Did a crate we already published end up, after the fact, depending on something that got
#    yanked later?" -> `--published` mode. This is the actual shape of the real incident: a LIVE,
#    non-yanked published version pointing at a dependency that is now fully yanked. Cargo.lock
#    (mode 1) can never see this -- it only reflects the tree checked out right now, not what
#    crates.io shipped in the past. This mode re-derives the workspace's published crate list,
#    and for each one that is still live (non-yanked) at the current workspace version, fetches
#    its REGISTRY dependency list (not Cargo.lock) and fails if any lib-q-* dependency is a fully
#    yanked crate (no non-yanked version exists at all). This is what Part 1's manual audit did
#    by hand; this mode automates it. It makes ~1 + 2*N sequential rate-limited API calls (N =
#    published crate count), so it does NOT belong on every PR -- wire it to the release/publish
#    path or a schedule, not core-validation.
#
# NETWORK FAILURE POLICY (both modes)
# --------------------------------------
# A curl error, non-200, or unparsable/empty JSON response FAILS the guard -- it is never treated
# as "no yanked dependency found". A guard that goes quiet on network trouble is a guard that
# passes the exact incident it exists to catch, silently, whenever the runner has a bad network
# day.
#
# FIXTURE / OFFLINE MODE (self-test and offline runs use this; real runs do not set it)
#   YANK_GUARD_FIXTURE_DIR=<dir>
#     Mode 1 reads <dir>/<crate-name>.json instead of GET /crates/<crate-name>.
#     Mode 2 additionally reads <dir>/<crate-name>-<version>-deps.json instead of
#     GET /crates/<crate-name>/<version>/dependencies.
#     A missing or empty fixture file is treated exactly like a network failure: FAIL.
#   YANK_GUARD_PUBLISHED_CRATES="name1 name2 ..." (mode 2 only) overrides crate-list discovery.
#   YANK_GUARD_WS_VERSION=X.Y.Z (mode 2 only) overrides workspace-version discovery.
#
# Usage:
#   bash scripts/ci-guard-yanked-deps.sh [REPO_ROOT]              # mode 1: Cargo.lock, every PR
#   bash scripts/ci-guard-yanked-deps.sh --published [REPO_ROOT]  # mode 2: registry drift, release/schedule
#   bash scripts/ci-guard-yanked-deps.sh --self-test

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UA="lib-q-ci-yank-guard/1.0 (+https://github.com/enkom-tech/libQ; accounts@enkom.tech)"
API_BASE="https://crates.io/api/v1/crates"

# fetch_crate_json <crate-name>
# Prints the crate's crates.io JSON on stdout. Returns 0 on a usable response, 2 on ANY failure
# (network error, non-200, empty body, unparsable JSON, missing/empty fixture file). Never
# returns 0 with output the caller can't parse -- the caller must not have to guess.
fetch_crate_json() {
  local crate="$1" json rc

  if [[ -n "${YANK_GUARD_FIXTURE_DIR:-}" ]]; then
    local f="$YANK_GUARD_FIXTURE_DIR/$crate.json"
    if [[ ! -s "$f" ]]; then
      echo "  ERROR: no fixture data for '$crate' at $f" >&2
      return 2
    fi
    json="$(cat "$f" 2>/dev/null)"
  else
    # -sf: silent, but -f makes curl exit nonzero on HTTP >=400 instead of printing the error
    # body and exiting 0. Capture output and exit code separately -- never through a pipe, so
    # $? is curl's own status, not some downstream command's (the classic `cmd | tail; echo $?`
    # trap this repo has been bitten by before).
    json="$(curl -s -f -A "$UA" "$API_BASE/$crate" 2>/dev/null)"
    rc=$?
    if [[ $rc -ne 0 ]]; then
      echo "  ERROR: curl failed fetching '$crate' (exit $rc)" >&2
      return 2
    fi
  fi

  if [[ -z "$json" ]]; then
    echo "  ERROR: empty response body for '$crate'" >&2
    return 2
  fi
  if ! printf '%s' "$json" | jq -e '.versions | type == "array"' >/dev/null 2>&1; then
    echo "  ERROR: malformed/unparsable JSON for '$crate' (no .versions array)" >&2
    return 2
  fi

  printf '%s' "$json"
  return 0
}

# fetch_deps_json <crate-name> <version>
# Same contract as fetch_crate_json, against the /dependencies endpoint (mode 2 only).
fetch_deps_json() {
  local crate="$1" ver="$2" json rc

  if [[ -n "${YANK_GUARD_FIXTURE_DIR:-}" ]]; then
    local f="$YANK_GUARD_FIXTURE_DIR/$crate-$ver-deps.json"
    if [[ ! -s "$f" ]]; then
      echo "  ERROR: no deps fixture data for '$crate@$ver' at $f" >&2
      return 2
    fi
    json="$(cat "$f" 2>/dev/null)"
  else
    json="$(curl -s -f -A "$UA" "$API_BASE/$crate/$ver/dependencies" 2>/dev/null)"
    rc=$?
    if [[ $rc -ne 0 ]]; then
      echo "  ERROR: curl failed fetching deps for '$crate@$ver' (exit $rc)" >&2
      return 2
    fi
  fi

  if [[ -z "$json" ]]; then
    echo "  ERROR: empty deps response body for '$crate@$ver'" >&2
    return 2
  fi
  if ! printf '%s' "$json" | jq -e '.dependencies | type == "array"' >/dev/null 2>&1; then
    echo "  ERROR: malformed/unparsable deps JSON for '$crate@$ver' (no .dependencies array)" >&2
    return 2
  fi

  printf '%s' "$json"
  return 0
}

# check_dependency <depender-label> <dep-name> <dep-version>
# Used by mode 1 only (mode 2's "fully yanked?" check is simpler and inlined in published_mode).
check_dependency() {
  local depender="$1" dep="$2" ver="$3"
  local json yanked
  json="$(fetch_crate_json "$dep")" || { PROBLEMS=$((PROBLEMS + 1)); FAILS+=("$depender -> $dep@$ver: could not verify (network/data error) -- treated as FAIL, not pass"); return; }

  yanked="$(printf '%s' "$json" | jq -r --arg v "$ver" '[.versions[] | select(.num == $v) | .yanked] | if length == 0 then "no-such-version" else (.[0] | tostring) end')"

  case "$yanked" in
    true)
      PROBLEMS=$((PROBLEMS + 1))
      FAILS+=("$depender -> $dep@$ver: YANKED on crates.io")
      ;;
    false)
      : # fine
      ;;
    no-such-version)
      local any_live
      any_live="$(printf '%s' "$json" | jq -r '[.versions[] | select(.yanked == false)] | length')"
      if [[ "$any_live" == "0" ]]; then
        PROBLEMS=$((PROBLEMS + 1))
        FAILS+=("$depender -> $dep@$ver: dependency crate has NO non-yanked version at all (fully yanked)")
      fi
      ;;
    *)
      PROBLEMS=$((PROBLEMS + 1))
      FAILS+=("$depender -> $dep@$ver: could not determine yanked status (got '$yanked') -- treated as FAIL, not pass")
      ;;
  esac
}

# ---------------------------------------------------------------------------------------------
# MODE 1: Cargo.lock scan
# ---------------------------------------------------------------------------------------------

# scan_lockfile <path-to-Cargo.lock>
# Populates PROBLEMS and FAILS[]. Three-pass parse of [[package]] blocks:
#   pass 1: name -> first-seen version (for bare dependency entries with no explicit version)
#   pass 1 also: "name@version" -> registry? (does that exact block carry a `source = "registry+`
#     line). A block with NO source line is a workspace-member path dependency: nothing was
#     pulled from crates.io, so its yanked status is irrelevant and it MUST NOT be queried.
#   pass 2: for each lib-q-* package block, walk its dependencies = [ ... ] list; for each lib-q-*
#     entry, resolve (name, version), and only call check_dependency if that (name, version) was
#     marked as a registry source in pass 1.
scan_lockfile() {
  local lockfile="$1"
  PROBLEMS=0
  FAILS=()
  SKIPPED_PATH=0

  if [[ ! -f "$lockfile" ]]; then
    echo "ci-guard-yanked-deps: no Cargo.lock at $lockfile" >&2
    PROBLEMS=$((PROBLEMS + 1))
    FAILS+=("(setup) missing Cargo.lock -- cannot verify anything, treated as FAIL")
    return
  fi

  # Pass 1: name -> version map, and "name@version" -> is-registry-sourced map.
  local -A NAME_TO_VERSION=()
  local -A IS_REGISTRY=()
  local cur_name="" cur_version=""
  while IFS= read -r line; do
    if [[ "$line" == "[[package]]" ]]; then
      cur_name=""; cur_version=""
    elif [[ "$line" =~ ^name\ =\ \"(.*)\"$ ]]; then
      cur_name="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^version\ =\ \"(.*)\"$ ]]; then
      cur_version="${BASH_REMATCH[1]}"
      if [[ -n "$cur_name" && -z "${NAME_TO_VERSION[$cur_name]:-}" ]]; then
        NAME_TO_VERSION["$cur_name"]="$cur_version"
      fi
    elif [[ "$line" == source\ =\ \"registry+* && -n "$cur_name" && -n "$cur_version" ]]; then
      IS_REGISTRY["$cur_name@$cur_version"]=1
    fi
  done < "$lockfile"

  # Pass 2: for each lib-q-* package block, walk its dependencies = [ ... ] list.
  local in_deps=0 dep_line dep_name dep_ver
  cur_name=""; cur_version=""
  while IFS= read -r line; do
    if [[ "$line" == "[[package]]" ]]; then
      cur_name=""; cur_version=""; in_deps=0
      continue
    fi
    if [[ "$line" =~ ^name\ =\ \"(.*)\"$ ]]; then
      cur_name="${BASH_REMATCH[1]}"
      continue
    fi
    if [[ "$line" =~ ^version\ =\ \"(.*)\"$ ]]; then
      cur_version="${BASH_REMATCH[1]}"
      continue
    fi
    if [[ "$line" == "dependencies = ["* ]]; then
      in_deps=1
      continue
    fi
    if [[ $in_deps -eq 1 ]]; then
      if [[ "$line" == "]" ]]; then
        in_deps=0
        continue
      fi
      # entries look like:  "lib-q-core",   or   "lib-q-core 0.0.9",
      dep_line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*"//' -e 's/",\?[[:space:]]*$//')"
      [[ "$dep_line" == lib-q-* ]] || continue
      if [[ "$dep_line" == *" "* ]]; then
        dep_name="${dep_line%% *}"
        dep_ver="${dep_line#* }"
      else
        dep_name="$dep_line"
        dep_ver="${NAME_TO_VERSION[$dep_name]:-}"
      fi
      [[ -z "$cur_name" || "$cur_name" != lib-q-* ]] && continue
      if [[ -z "$dep_ver" ]]; then
        PROBLEMS=$((PROBLEMS + 1))
        FAILS+=("$cur_name -> $dep_name: could not resolve dependency version from lock file -- treated as FAIL, not pass")
        continue
      fi
      # THE FIX: a workspace-member path dependency has no `source = "registry+..."` line in its
      # own [[package]] block. Only query crates.io -- and only fire -- for entries that DO carry
      # one, i.e. artifacts actually consumed from the registry.
      if [[ -z "${IS_REGISTRY[$dep_name@$dep_ver]:-}" ]]; then
        SKIPPED_PATH=$((SKIPPED_PATH + 1))
        continue
      fi
      check_dependency "$cur_name@$cur_version" "$dep_name" "$dep_ver"
    fi
  done < "$lockfile"
}

# ---------------------------------------------------------------------------------------------
# MODE 2: --published (post-publish registry drift)
# ---------------------------------------------------------------------------------------------

# list_published_crates <root> -> prints one lib-q-* crate name per line.
# A crate is "published" if some Cargo.toml under root names it `lib-q-*` and that manifest does
# not carry an ACTIVE `publish = false` line (a commented-out one, `# publish = false`, does not
# count -- that is how lib-q-hpke's manifest deliberately re-enables publishing).
list_published_crates() {
  local root="$1"
  if [[ -n "${YANK_GUARD_PUBLISHED_CRATES:-}" ]]; then
    printf '%s\n' $YANK_GUARD_PUBLISHED_CRATES
    return
  fi
  local f name has_disable
  while IFS= read -r f; do
    name="$(grep -m1 '^name = "lib-q-' "$f" 2>/dev/null | sed -E 's/name = "(.*)"/\1/')"
    [[ -z "$name" ]] && continue
    has_disable="$(grep -E '^[[:space:]]*publish[[:space:]]*=[[:space:]]*false' "$f" 2>/dev/null)"
    [[ -n "$has_disable" ]] && continue
    echo "$name"
  done < <(find "$root" \
    -path "$root/target" -prune -o \
    -path "$root/scratchpad" -prune -o \
    -path "$root/reference" -prune -o \
    -path "*/node_modules" -prune -o \
    -path "*/.git" -prune -o \
    -name "Cargo.toml" -print 2>/dev/null)
}

# get_workspace_version <root>
get_workspace_version() {
  local root="$1"
  if [[ -n "${YANK_GUARD_WS_VERSION:-}" ]]; then
    printf '%s' "$YANK_GUARD_WS_VERSION"
    return
  fi
  awk '
    /^\[workspace\.package\]/ { in_block=1; next }
    /^\[/ { in_block=0 }
    in_block && /^version[[:space:]]*=/ { print; exit }
  ' "$root/Cargo.toml" 2>/dev/null | sed -E 's/.*"([^"]*)".*/\1/'
}

# published_mode <root>
# Populates PROBLEMS and FAILS[]. For every published crate that is currently LIVE (non-yanked)
# at the workspace version, fetch its registry dependency list and fail on any lib-q-* dependency
# that is fully yanked (no non-yanked version exists anywhere for it).
published_mode() {
  local root="$1"
  PROBLEMS=0
  FAILS=()
  local wsver crates name json ver_status deps_json dep any_live depjson

  wsver="$(get_workspace_version "$root")"
  if [[ -z "$wsver" ]]; then
    echo "ci-guard-yanked-deps --published: could not determine workspace version" >&2
    PROBLEMS=$((PROBLEMS + 1))
    FAILS+=("(setup) could not determine workspace version -- treated as FAIL")
    return
  fi

  crates="$(list_published_crates "$root")"
  if [[ -z "$crates" ]]; then
    echo "ci-guard-yanked-deps --published: no published crates discovered" >&2
    PROBLEMS=$((PROBLEMS + 1))
    FAILS+=("(setup) discovered zero published crates -- almost certainly a discovery bug, treated as FAIL")
    return
  fi

  while IFS= read -r name; do
    name="${name%$'\r'}"
    [[ -z "$name" ]] && continue
    json="$(fetch_crate_json "$name")" || { PROBLEMS=$((PROBLEMS + 1)); FAILS+=("$name: could not verify (network/data error)"); continue; }

    ver_status="$(printf '%s' "$json" | jq -r --arg v "$wsver" '[.versions[] | select(.num == $v) | .yanked] | if length == 0 then "missing" else (.[0] | tostring) end')"
    # Not live at the workspace version (not yet published under it, or yanked) -> nothing to
    # audit for THIS crate; its own yanked-ness is not what this guard checks.
    [[ "$ver_status" != "false" ]] && continue

    deps_json="$(fetch_deps_json "$name" "$wsver")" || { PROBLEMS=$((PROBLEMS + 1)); FAILS+=("$name@$wsver: could not verify dependency list (network/data error)"); continue; }

    while IFS= read -r dep; do
      # `read` splits on \n only; jq on this platform emits trailing \r before its \n even for
      # a single-field -r filter, which command substitution ($()) strips but a `read` loop over
      # a process-substituted stream does not -- strip it explicitly or the crate-id lookup below
      # silently misses its fixture/registry entry.
      dep="${dep%$'\r'}"
      [[ -z "$dep" ]] && continue
      depjson="$(fetch_crate_json "$dep")" || { PROBLEMS=$((PROBLEMS + 1)); FAILS+=("$name@$wsver -> $dep: could not verify (network/data error)"); continue; }
      any_live="$(printf '%s' "$depjson" | jq -r '[.versions[] | select(.yanked == false)] | length')"
      if [[ "$any_live" == "0" ]]; then
        PROBLEMS=$((PROBLEMS + 1))
        FAILS+=("$name@$wsver -> $dep: dependency crate is FULLY YANKED (no live version anywhere) while $name@$wsver is still live -- registry drift")
      fi
    done < <(printf '%s' "$deps_json" | jq -r '.dependencies[]? | select(.crate_id | startswith("lib-q-")) | .crate_id' | sort -u)
  done <<< "$crates"
}

# ---------------------------------------------------------------------------------------------
# self-test / mutation battery
# ---------------------------------------------------------------------------------------------

self_test() {
  local tmp; tmp="$(mktemp -d)"
  local fixtures="$tmp/fixtures"
  mkdir -p "$fixtures"
  local problems=0
  local cases=0

  # --- shared fixture crates.io JSON: one clean crate, one fully-yanked crate ---
  cat > "$fixtures/lib-q-clean-dep.json" <<'JSON'
{"versions":[{"num":"0.0.10","yanked":false},{"num":"0.0.9","yanked":true}]}
JSON
  cat > "$fixtures/lib-q-bad-dep.json" <<'JSON'
{"versions":[{"num":"0.0.10","yanked":true},{"num":"0.0.9","yanked":true}]}
JSON

  # === Case A: clean lock file (registry-sourced clean dep) -> must NOT fire ===
  cases=$((cases + 1))
  cat > "$tmp/clean.lock" <<'LOCK'
[[package]]
name = "lib-q-clean-dep"
version = "0.0.10"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "lib-q-consumer"
version = "0.0.10"
dependencies = [
 "lib-q-clean-dep",
]
LOCK
  YANK_GUARD_FIXTURE_DIR="$fixtures" scan_lockfile "$tmp/clean.lock"
  if [[ $PROBLEMS -ne 0 ]]; then
    echo "  MUTATION-CHECK FAIL (A): clean registry-sourced dep must not fire (got $PROBLEMS: ${FAILS[*]:-})"
    problems=1
  fi

  # === Case B: THE REAL INCIDENT SHAPE -- registry-sourced dependency yanked -> MUST fire ===
  cases=$((cases + 1))
  cat > "$tmp/bad.lock" <<'LOCK'
[[package]]
name = "lib-q-bad-dep"
version = "0.0.10"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "lib-q-zk-encryption-proof"
version = "0.0.10"
dependencies = [
 "lib-q-bad-dep",
]
LOCK
  YANK_GUARD_FIXTURE_DIR="$fixtures" scan_lockfile "$tmp/bad.lock"
  if [[ $PROBLEMS -eq 0 ]]; then
    echo "  MUTATION-CHECK FAIL (B): a registry-sourced yanked dependency must fire (got 0 problems)"
    problems=1
  fi

  # === Case C: fully-yanked, registry-sourced dep referenced by disambiguated "name version" ===
  cases=$((cases + 1))
  cat > "$tmp/bad2.lock" <<'LOCK'
[[package]]
name = "lib-q-bad-dep"
version = "0.0.10"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "lib-q-bad-dep"
version = "0.0.9"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "lib-q-consumer2"
version = "0.0.10"
dependencies = [
 "lib-q-bad-dep 0.0.10",
]
LOCK
  YANK_GUARD_FIXTURE_DIR="$fixtures" scan_lockfile "$tmp/bad2.lock"
  if [[ $PROBLEMS -eq 0 ]]; then
    echo "  MUTATION-CHECK FAIL (C): disambiguated 'name version' dependency form must also fire"
    problems=1
  fi

  # === Case D (network-failure discipline): fixture dir missing entirely -> MUST fail, not pass ===
  cases=$((cases + 1))
  YANK_GUARD_FIXTURE_DIR="$tmp/this-fixture-dir-does-not-exist" scan_lockfile "$tmp/clean.lock"
  if [[ $PROBLEMS -eq 0 ]]; then
    echo "  MUTATION-CHECK FAIL (D): an unreachable data source (simulated network failure) must FAIL, not silently pass"
    problems=1
  fi

  # === Case E (network-failure discipline): empty fixture file (simulated empty HTTP body) -> MUST fail ===
  cases=$((cases + 1))
  local emptydir="$tmp/emptyfixtures"; mkdir -p "$emptydir"
  : > "$emptydir/lib-q-clean-dep.json"
  YANK_GUARD_FIXTURE_DIR="$emptydir" scan_lockfile "$tmp/clean.lock"
  if [[ $PROBLEMS -eq 0 ]]; then
    echo "  MUTATION-CHECK FAIL (E): an empty response body must FAIL, not be read as 'no yanked deps'"
    problems=1
  fi

  # === Case F (network-failure discipline): malformed JSON (no .versions) -> MUST fail ===
  cases=$((cases + 1))
  local baddir="$tmp/malformedfixtures"; mkdir -p "$baddir"
  echo 'not json at all {{{' > "$baddir/lib-q-clean-dep.json"
  YANK_GUARD_FIXTURE_DIR="$baddir" scan_lockfile "$tmp/clean.lock"
  if [[ $PROBLEMS -eq 0 ]]; then
    echo "  MUTATION-CHECK FAIL (F): malformed JSON must FAIL, not be read as clean"
    problems=1
  fi

  # === Case G: empty lock file (no packages) -> nothing to report, must not fire ===
  cases=$((cases + 1))
  : > "$tmp/empty.lock"
  YANK_GUARD_FIXTURE_DIR="$fixtures" scan_lockfile "$tmp/empty.lock"
  if [[ $PROBLEMS -ne 0 ]]; then
    echo "  MUTATION-CHECK FAIL (G): an empty lock file (no packages) has nothing to report and must not fire"
    problems=1
  fi

  # === Case H (THE FIX under test): a workspace-member PATH dependency (no `source` line) whose
  # name+version happens to match a version the registry reports as YANKED must NOT fire. This is
  # the exact false positive this guard shipped with: lib-q-zk-encryption-proof (path member,
  # workspace version 0.0.10) depending on lib-q-threshold-kem-lattice (path member, 0.0.10) --
  # and crates.io's real lib-q-threshold-kem-lattice 0.0.10 IS yanked, but nothing here is being
  # consumed from the registry, so it must not fire. ===
  cases=$((cases + 1))
  cat > "$tmp/pathmember.lock" <<'LOCK'
[[package]]
name = "lib-q-threshold-kem-lattice"
version = "0.0.10"
dependencies = [
]

[[package]]
name = "lib-q-zk-encryption-proof"
version = "0.0.10"
dependencies = [
 "lib-q-threshold-kem-lattice",
]
LOCK
  # deliberately reuse the "bad-dep"-shaped fixture under the REAL crate names, both marked
  # yanked==true for 0.0.10, to prove the registry data alone is not what stops the fire --
  # the absence of a `source` line in the lock file is what must stop it.
  cat > "$fixtures/lib-q-threshold-kem-lattice.json" <<'JSON'
{"versions":[{"num":"0.0.10","yanked":true},{"num":"0.0.9","yanked":true}]}
JSON
  cat > "$fixtures/lib-q-zk-encryption-proof.json" <<'JSON'
{"versions":[{"num":"0.0.10","yanked":true},{"num":"0.0.9","yanked":true}]}
JSON
  YANK_GUARD_FIXTURE_DIR="$fixtures" scan_lockfile "$tmp/pathmember.lock"
  if [[ $PROBLEMS -ne 0 ]]; then
    echo "  MUTATION-CHECK FAIL (H): a workspace-member path dependency (no 'source' line) must NEVER be queried against the registry, even when the registry would report it yanked (got $PROBLEMS: ${FAILS[*]:-})"
    problems=1
  fi
  if [[ $SKIPPED_PATH -lt 1 ]]; then
    echo "  MUTATION-CHECK FAIL (H): expected the path-dependency edge to be recorded as skipped (SKIPPED_PATH=$SKIPPED_PATH)"
    problems=1
  fi

  # === Case I (--published mode, clean): live crate depends on a live registry dep -> no fire ===
  cases=$((cases + 1))
  cat > "$fixtures/lib-q-live-consumer.json" <<'JSON'
{"versions":[{"num":"0.0.10","yanked":false}]}
JSON
  cat > "$fixtures/lib-q-live-consumer-0.0.10-deps.json" <<'JSON'
{"dependencies":[{"crate_id":"lib-q-clean-dep","req":"^0.0.10"}]}
JSON
  YANK_GUARD_PUBLISHED_CRATES="lib-q-live-consumer" YANK_GUARD_WS_VERSION="0.0.10" \
    YANK_GUARD_FIXTURE_DIR="$fixtures" published_mode "$tmp"
  if [[ $PROBLEMS -ne 0 ]]; then
    echo "  MUTATION-CHECK FAIL (I): --published mode, live crate + live dep must not fire (got $PROBLEMS: ${FAILS[*]:-})"
    problems=1
  fi

  # === Case J (--published mode, THE REAL RECURRENCE SHAPE): live crate depends on a crate that
  # is NOW fully yanked (post-publish drift, exactly what a Cargo.lock scan structurally cannot
  # see) -> MUST fire ===
  cases=$((cases + 1))
  cat > "$fixtures/lib-q-live-consumer-0.0.10-deps.json" <<'JSON'
{"dependencies":[{"crate_id":"lib-q-bad-dep","req":"^0.0.10"}]}
JSON
  YANK_GUARD_PUBLISHED_CRATES="lib-q-live-consumer" YANK_GUARD_WS_VERSION="0.0.10" \
    YANK_GUARD_FIXTURE_DIR="$fixtures" published_mode "$tmp"
  if [[ $PROBLEMS -eq 0 ]]; then
    echo "  MUTATION-CHECK FAIL (J): --published mode must fire when a live crate depends on a fully-yanked crate"
    problems=1
  fi

  # === Case K (--published mode, network-failure discipline): unreachable fixture dir -> MUST fail ===
  cases=$((cases + 1))
  YANK_GUARD_PUBLISHED_CRATES="lib-q-live-consumer" YANK_GUARD_WS_VERSION="0.0.10" \
    YANK_GUARD_FIXTURE_DIR="$tmp/this-fixture-dir-does-not-exist" published_mode "$tmp"
  if [[ $PROBLEMS -eq 0 ]]; then
    echo "  MUTATION-CHECK FAIL (K): --published mode network failure must FAIL, not silently pass"
    problems=1
  fi

  rm -rf "$tmp"
  if [[ $problems -ne 0 ]]; then
    echo "SELF-TEST FAILED -- the yanked-dependency guard is not detecting what it claims."
    return 1
  fi
  SELFTEST_CASES=$cases
  return 0
}

if [[ "${1:-}" == "--self-test" ]]; then
  if self_test; then echo "ci-guard-yanked-deps: self-test OK ($SELFTEST_CASES mutation cases passed)"; exit 0; else exit 1; fi
fi

PUBLISHED_MODE=0
if [[ "${1:-}" == "--published" ]]; then
  PUBLISHED_MODE=1
  shift
fi

ROOT="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"

# Re-prove detection before trusting a clean result on the real tree -- a broken guard and a
# healthy repo look identical from a bare "no problems reported" output.
if ! self_test; then exit 1; fi

if [[ $PUBLISHED_MODE -eq 1 ]]; then
  published_mode "$ROOT"
  if [[ $PROBLEMS -ne 0 ]]; then
    echo "ci-guard-yanked-deps --published: $PROBLEMS problem(s) found:"
    for f in "${FAILS[@]}"; do
      echo "  FAIL: $f"
    done
    exit 1
  fi
  echo "ci-guard-yanked-deps --published: OK -- no live published lib-q-* crate depends on a fully-yanked crate"
  exit 0
fi

scan_lockfile "$ROOT/Cargo.lock"
if [[ $PROBLEMS -ne 0 ]]; then
  echo "ci-guard-yanked-deps: $PROBLEMS problem(s) found:"
  for f in "${FAILS[@]}"; do
    echo "  FAIL: $f"
  done
  exit 1
fi
echo "ci-guard-yanked-deps: OK -- no registry-sourced lib-q-* dependency in Cargo.lock is yanked ($SKIPPED_PATH workspace-path edge(s) correctly skipped)"
