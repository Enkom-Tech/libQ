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
#     (Mode 2 has no workspace-version knob: it resolves each crate's latest LIVE version from the
#     registry response. Auditing the workspace version is the bug it was rewritten to fix.)
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
# Prints the crate's crates.io JSON on stdout. Returns 0 on a usable response, 3 when crates.io
# answers HTTP 404 (the crate has never been published), and 2 on ANY other failure (network
# error, 5xx, other non-200, empty body, unparsable JSON, missing/empty fixture file). Never
# returns 0 with output the caller can't parse -- the caller must not have to guess.
#
# WHY 404 IS ITS OWN CODE: the 0.0.12 release introduced lib-q-aegis and lib-q-hiae. They cannot
# be published before the crates they depend on, so at pre-release validation crates.io rightly
# answers 404 for them. `curl -f` folded that into the same exit 22 as a 5xx, the guard called it
# INFRA-FAILURE, and the release could not start. A 404 is a definite answer (nothing of ours is
# on the registry under that name, so nothing published can sit on a yanked dependency); only
# --published mode's top-level lookup treats it as "skip". Every other caller still fails on it.
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
    #
    # Bounded retry + hard per-request timeout: a single crates.io 5xx or a stalled
    # connection must not turn the whole job red -- that is an environmental failure,
    # the exact class that made Core Validation flake, and an unbounded curl could
    # previously stall the job into its own step timeout. Still fail-closed: after the
    # last attempt the error stands and the job fails, with an INFRA-FAILURE banner
    # naming the class instead of reading as a guard defect. Fixture mode (self-test)
    # is never retried and never hits the network.
    local attempt out
    rc=0
    for attempt in 1 2 3; do
      # -w appends the HTTP status after a newline; with -f a failed response prints no body, so
      # on error `out` is just "\n<status>". Split it off rather than guessing from the exit code.
      out="$(curl -s -f --max-time 30 -A "$UA" -w $'\n%{http_code}' "$API_BASE/$crate" 2>/dev/null)"
      rc=$?
      json="${out%$'\n'*}"
      [[ $rc -eq 0 ]] && break
      # 404 is a definite answer, not a transient: do not retry, do not call it infra.
      if [[ "${out##*$'\n'}" == "404" ]]; then
        echo "  NOTICE: crates.io has no crate '$crate' (HTTP 404)" >&2
        return 3
      fi
      if [[ $attempt -lt 3 ]]; then
        echo "  WARN: curl failed fetching '$crate' (exit $rc), attempt $attempt/3; retrying" >&2
        sleep $((attempt * 5))
      fi
    done
    if [[ $rc -ne 0 ]]; then
      echo "  ERROR INFRA-FAILURE: crates.io unreachable after 3 attempt(s) fetching '$crate' (last exit $rc)" >&2
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
    # Same bounded retry + hard timeout as fetch_crate_json above: environmental
    # crates.io failures absorb themselves; real failures still fail closed, now
    # named INFRA-FAILURE instead of reading as a guard defect. Fixture mode is
    # never retried and never hits the network.
    local attempt
    rc=0
    for attempt in 1 2 3; do
      json="$(curl -s -f --max-time 30 -A "$UA" "$API_BASE/$crate/$ver/dependencies" 2>/dev/null)"
      rc=$?
      [[ $rc -eq 0 ]] && break
      if [[ $attempt -lt 3 ]]; then
        echo "  WARN: curl failed fetching deps for '$crate@$ver' (exit $rc), attempt $attempt/3; retrying" >&2
        sleep $((attempt * 5))
      fi
    done
    if [[ $rc -ne 0 ]]; then
      echo "  ERROR INFRA-FAILURE: crates.io unreachable after 3 attempt(s) fetching deps for '$crate@$ver' (last exit $rc)" >&2
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

# latest_live_version <crate-json>
# Prints the highest version of a crate that is currently NON-YANKED on crates.io, or nothing if
# the crate is fully yanked / has no versions.
#
# Prefers crates.io's own `crate.max_stable_version` (which already excludes yanked releases) and
# falls back to the first non-yanked entry in `.versions`, which the API returns newest-first. The
# fallback is what keeps the self-test fixtures (bare `{"versions":[...]}` objects) meaningful.
latest_live_version() {
  local json="$1"
  local v
  v="$(printf '%s' "$json" | jq -r '.crate.max_stable_version // empty' 2>/dev/null)"
  if [[ -n "$v" && "$v" != "null" ]]; then
    printf '%s' "$v"
    return
  fi
  printf '%s' "$json" | jq -r 'first(.versions[]? | select(.yanked == false) | .num) // empty' 2>/dev/null
}

# published_mode <root>
# Populates PROBLEMS and FAILS[]. For every published crate, fetch the registry dependency list of
# its LATEST LIVE (non-yanked) version and fail on any lib-q-* dependency that is fully yanked.
#
# WHY THE LATEST LIVE VERSION AND NOT THE WORKSPACE VERSION
# ---------------------------------------------------------
# This mode used to audit crates at `[workspace.package] version`, and was VACUOUS everywhere it
# actually ran. It is wired into cd.yml's pre-release-validation, which runs on a tag, *before*
# anything is published -- and cd.yml's own "Validate version consistency" step fails the release
# unless the tag equals the workspace version. So the version being audited was, by construction,
# the one not yet on crates.io: every crate reported `missing`, every crate was skipped by
#
#     [[ "$ver_status" != "false" ]] && continue
#
# and the guard passed without examining a single dependency, every release. OBSERVED at the
# 0.0.11 release: `curl .../crates/lib-q-core` reported `0.0.11: MISSING, 0.0.10: live`.
#
# The artifacts that can actually suffer post-publication yank drift are the ones already on the
# registry, so that is what this now audits. The version is resolved PER CRATE rather than from one
# workspace number: crates enter and leave the workspace between releases, so they are not all live
# at the same version (and after a half-shipped release like v0.0.11's first two attempts, they are
# demonstrably not).
published_mode() {
  local root="$1"
  PROBLEMS=0
  FAILS=()
  local crates name json frc auditver deps_json dep any_live depjson audited=0

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
    json="$(fetch_crate_json "$name")"; frc=$?
    if [[ $frc -eq 3 ]]; then
      # Never published (e.g. new in the release being cut): no live artifact of ours exists, so
      # nothing here can depend on a yanked crate. Not a problem, and not audited either.
      echo "  NOTICE: $name is not on crates.io yet, skipped"
      continue
    elif [[ $frc -ne 0 ]]; then
      PROBLEMS=$((PROBLEMS + 1)); FAILS+=("$name: could not verify (network/data error)"); continue
    fi

    # The crate's newest version that is still live. Empty means the crate is fully yanked or has
    # never been published -- in either case there is no live artifact of ours pointing at anything,
    # so there is nothing for THIS guard to audit. Note this is a genuine "nothing to check", unlike
    # the workspace-version skip it replaces, which fired for every crate on every release.
    auditver="$(latest_live_version "$json")"
    [[ -z "$auditver" || "$auditver" == "null" ]] && continue
    audited=$((audited + 1))

    deps_json="$(fetch_deps_json "$name" "$auditver")" || { PROBLEMS=$((PROBLEMS + 1)); FAILS+=("$name@$auditver: could not verify dependency list (network/data error)"); continue; }

    while IFS= read -r dep; do
      # `read` splits on \n only; jq on this platform emits trailing \r before its \n even for
      # a single-field -r filter, which command substitution ($()) strips but a `read` loop over
      # a process-substituted stream does not -- strip it explicitly or the crate-id lookup below
      # silently misses its fixture/registry entry.
      dep="${dep%$'\r'}"
      [[ -z "$dep" ]] && continue
      depjson="$(fetch_crate_json "$dep")"; frc=$?
      if [[ $frc -eq 3 ]]; then
        # Unlike the top-level lookup above, a 404 here is NOT a skip: a live crate of ours depends
        # on a crate the registry has never heard of, which cannot happen for a healthy release.
        PROBLEMS=$((PROBLEMS + 1)); FAILS+=("$name@$auditver -> $dep: dependency $dep not found on crates.io"); continue
      elif [[ $frc -ne 0 ]]; then
        PROBLEMS=$((PROBLEMS + 1)); FAILS+=("$name@$auditver -> $dep: could not verify (network/data error)"); continue
      fi
      any_live="$(printf '%s' "$depjson" | jq -r '[.versions[] | select(.yanked == false)] | length')"
      if [[ "$any_live" == "0" ]]; then
        PROBLEMS=$((PROBLEMS + 1))
        FAILS+=("$name@$auditver -> $dep: dependency crate is FULLY YANKED (no live version anywhere) while $name@$auditver is still live -- registry drift")
      fi
    done < <(printf '%s' "$deps_json" | jq -r '.dependencies[]? | select(.crate_id | startswith("lib-q-")) | .crate_id' | sort -u)
  done <<< "$crates"

  # A run that audited nothing is the vacuity this mode was rewritten to end. Reaching zero here
  # means either discovery or the live-version resolution is broken, and a silent pass would look
  # exactly like a clean registry. Fail instead, and say which it was.
  if [[ $audited -eq 0 ]]; then
    PROBLEMS=$((PROBLEMS + 1))
    FAILS+=("(setup) audited ZERO crates -- no discovered crate has a live version on crates.io. That is what the old workspace-version bug looked like; treated as FAIL, not pass")
  fi
  AUDITED=$audited
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
  YANK_GUARD_PUBLISHED_CRATES="lib-q-live-consumer" \
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
  YANK_GUARD_PUBLISHED_CRATES="lib-q-live-consumer" \
    YANK_GUARD_FIXTURE_DIR="$fixtures" published_mode "$tmp"
  if [[ $PROBLEMS -eq 0 ]]; then
    echo "  MUTATION-CHECK FAIL (J): --published mode must fire when a live crate depends on a fully-yanked crate"
    problems=1
  fi

  # === Case K (--published mode, network-failure discipline): unreachable fixture dir -> MUST fail ===
  cases=$((cases + 1))
  YANK_GUARD_PUBLISHED_CRATES="lib-q-live-consumer" \
    YANK_GUARD_FIXTURE_DIR="$tmp/this-fixture-dir-does-not-exist" published_mode "$tmp"
  if [[ $PROBLEMS -eq 0 ]]; then
    echo "  MUTATION-CHECK FAIL (K): --published mode network failure must FAIL, not silently pass"
    problems=1
  fi

  # === Case L (THE VACUITY REGRESSION -- the whole point of the rewrite): the RELEASE-PATH shape.
  # The workspace has been bumped to a version that is NOT yet on crates.io (which is exactly the
  # state cd.yml runs this guard in, since it fails the release unless tag == workspace version).
  # The crate's live 0.0.10 release depends on a now-fully-yanked crate. The OLD implementation
  # audited the workspace version, found it `missing`, skipped the crate, and returned 0 -- passing
  # the one incident this mode exists to catch. It MUST fire. ===
  cases=$((cases + 1))
  cat > "$fixtures/lib-q-live-consumer-0.0.10-deps.json" <<'JSON'
{"dependencies":[{"crate_id":"lib-q-bad-dep","req":"^0.0.10"}]}
JSON
  YANK_GUARD_PUBLISHED_CRATES="lib-q-live-consumer" \
    YANK_GUARD_FIXTURE_DIR="$fixtures" published_mode "$tmp"
  if [[ $PROBLEMS -eq 0 ]]; then
    echo "  MUTATION-CHECK FAIL (L): with the workspace bumped to an UNPUBLISHED version (the release-path state), the guard must still audit the crate's latest LIVE version and fire -- passing here is the vacuity bug"
    problems=1
  fi
  if [[ ${AUDITED:-0} -ne 1 ]]; then
    echo "  MUTATION-CHECK FAIL (L): expected exactly 1 crate to be audited at its live version (AUDITED=${AUDITED:-unset})"
    problems=1
  fi

  # === Case M: a crate with NO live version anywhere -> nothing to audit, and auditing nothing at
  # all must FAIL rather than report a clean registry. This is the tripwire that would have made
  # the original bug loud instead of silent. ===
  cases=$((cases + 1))
  YANK_GUARD_PUBLISHED_CRATES="lib-q-bad-dep" \
    YANK_GUARD_FIXTURE_DIR="$fixtures" published_mode "$tmp"
  if [[ $PROBLEMS -eq 0 ]]; then
    echo "  MUTATION-CHECK FAIL (M): a run that audits ZERO crates must FAIL, not read as clean"
    problems=1
  fi

  # === Case N (--published mode, 404 = never published): the crate is new in this release and
  # crates.io answers HTTP 404. That must NOT fail the guard (0.0.12 release); the other crate is
  # still audited, so the zero-audit tripwire (case M) stays satisfied by real work. The stub
  # shadows curl and sleep inside a subshell (the /dependencies endpoint is fetched without -w, so
  # its stub prints no status line), so this exercises the real fetch path offline. ===
  cases=$((cases + 1))
  (
    curl() {
      case "${*: -1}" in
        */lib-q-live-consumer) cat "$fixtures/lib-q-live-consumer.json"; printf '\n200'; return 0 ;;
        */lib-q-live-consumer/0.0.10/dependencies) cat "$fixtures/lib-q-live-consumer-0.0.10-deps.json"; return 0 ;;
        */lib-q-clean-dep) cat "$fixtures/lib-q-clean-dep.json"; printf '\n200'; return 0 ;;
        *) printf '\n404'; return 22 ;;
      esac
    }
    sleep() { :; }
    unset YANK_GUARD_FIXTURE_DIR
    cat > "$fixtures/lib-q-live-consumer-0.0.10-deps.json" <<'JSON'
{"dependencies":[{"crate_id":"lib-q-clean-dep","req":"^0.0.10"}]}
JSON
    YANK_GUARD_PUBLISHED_CRATES="lib-q-never-published lib-q-live-consumer" published_mode "$tmp" >/dev/null 2>&1
    echo "$PROBLEMS $AUDITED" > "$tmp/case-n"
  )
  if [[ "$(cat "$tmp/case-n" 2>/dev/null)" != "0 1" ]]; then
    echo "  MUTATION-CHECK FAIL (N): an HTTP 404 (crate never published) must be skipped with 0 problems and the other crate audited (got '$(cat "$tmp/case-n" 2>/dev/null)')"
    problems=1
  fi
  # === Case P: an audited crate whose DEPENDENCY lookup answers 404 must still count as a problem.
  # The 404 skip (case N) applies only to the top-level crate; a live crate depending on a crate
  # the registry does not know is not "never published, nothing to audit". ===
  cases=$((cases + 1))
  (
    curl() {
      case "${*: -1}" in
        */lib-q-live-consumer) cat "$fixtures/lib-q-live-consumer.json"; printf '\n200'; return 0 ;;
        */lib-q-live-consumer/0.0.10/dependencies) echo '{"dependencies":[{"crate_id":"lib-q-ghost-dep","req":"^0.0.10"}]}'; return 0 ;;
        *) printf '\n404'; return 22 ;;
      esac
    }
    sleep() { :; }
    unset YANK_GUARD_FIXTURE_DIR
    YANK_GUARD_PUBLISHED_CRATES="lib-q-live-consumer" published_mode "$tmp" >/dev/null 2>&1
    echo "$PROBLEMS ${FAILS[*]}" > "$tmp/case-p"
  )
  if [[ "$(cat "$tmp/case-p" 2>/dev/null)" != *"dependency lib-q-ghost-dep not found on crates.io"* || "$(cut -d' ' -f1 "$tmp/case-p")" != "1" ]]; then
    echo "  MUTATION-CHECK FAIL (P): a dependency lookup answering 404 must count as exactly 1 problem (got '$(cat "$tmp/case-p" 2>/dev/null)')"
    problems=1
  fi
  # === Case O: a 5xx (and a plain network error) must STILL fail closed -- the 404 carve-out must
  # not weaken the network failure policy. A healthy crate is audited alongside the failing one so
  # that a guard which wrongly skipped the failure would still audit something and read as clean
  # (the zero-audit tripwire alone would mask exactly that regression). ===
  local code
  for code in 503 000; do
    cases=$((cases + 1))
    (
      curl() {
        case "${*: -1}" in
          */lib-q-clean-dep) cat "$fixtures/lib-q-clean-dep.json"; printf '\n200'; return 0 ;;
          */lib-q-clean-dep/*/dependencies) echo '{"dependencies":[]}'; return 0 ;;
          *) printf '\n%s' "$code"; return 22 ;;
        esac
      }
      sleep() { :; }
      unset YANK_GUARD_FIXTURE_DIR
      YANK_GUARD_PUBLISHED_CRATES="lib-q-clean-dep lib-q-live-consumer" published_mode "$tmp" >/dev/null 2>&1
      echo "$PROBLEMS $AUDITED" > "$tmp/case-o"
    )
    if [[ "$(cat "$tmp/case-o" 2>/dev/null)" != "1 1" ]]; then
      echo "  MUTATION-CHECK FAIL (O): HTTP $code from crates.io must FAIL (infra), not be skipped like a 404 (got '$(cat "$tmp/case-o" 2>/dev/null)', want '1 1')"
      problems=1
    fi
  done
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
  # Report the count, not just "OK": this mode passed vacuously on every release while auditing
  # zero crates, and the output gave no way to tell that from a clean registry.
  echo "ci-guard-yanked-deps --published: OK -- audited ${AUDITED:-0} live crate(s); none depends on a fully-yanked crate"
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
