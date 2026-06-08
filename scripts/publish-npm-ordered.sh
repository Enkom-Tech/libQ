#!/usr/bin/env bash
# Publish @lib-q/* packages to npm in CD order (.github/workflows/cd.yml publish-wasm-packages).
# Requires: npm login (NODE_AUTH_TOKEN or ~/.npmrc), wasm-pack, wasm32-unknown-unknown, Node 20+.
# Resume: START_AT=N (0-based index). Dry-run: DRY_RUN=1.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

START_AT="${START_AT:-0}"
END_AT="${END_AT:-}"
DRY_RUN="${DRY_RUN:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"
BUILD_ONLY="${BUILD_ONLY:-0}"
PUBLISH_ONLY="${PUBLISH_ONLY:-0}"
[[ "$PUBLISH_ONLY" == "1" ]] && SKIP_BUILD=1
LOG="${LOG:-$ROOT/scripts/publish-npm-ordered.log}"

export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C panic=abort'

PYTHON="${PYTHON:-}"
if [[ -z "$PYTHON" ]]; then
  for candidate in python3 python "/c/Program Files/Python312/python.exe" "/c/Program Files/Python3101/python.exe"; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys' >/dev/null 2>&1; then
      PYTHON="$candidate"
      break
    fi
  done
  if [[ -z "$PYTHON" ]] && command -v py >/dev/null 2>&1; then
    PYTHON="py -3"
  fi
fi
if [[ -z "$PYTHON" ]] || ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "ERROR: python not found (install Python 3 or set PYTHON=...)" >&2
  exit 1
fi

log() {
  local msg="[$(date -Iseconds)] $*"
  echo "$msg"
  echo "$msg" >>"$LOG" 2>/dev/null || true
}

workspace_version() {
  sed -n '/^\[workspace\.package\]/,/^\[/p' Cargo.toml | grep '^version = ' | head -1 | cut -d'"' -f2
}

VERSION="${VERSION:-$(workspace_version)}"
if [[ -z "$VERSION" ]]; then
  echo "ERROR: could not read [workspace.package].version from Cargo.toml" >&2
  exit 1
fi

# working-directory|npm name|description|keywords|features|out-dir|skip-build(1=types only)
read -r -d '' PACKAGES <<'EOF' || true
lib-q|@lib-q/core|Post-quantum cryptography library for Node.js (complete package)|cryptography,post-quantum,security,wasm|wasm,all-algorithms,ml-kem|pkg|
lib-q-ml-kem|@lib-q/ml-kem|NIST ML-KEM (Module-Lattice-based Key Encapsulation Mechanism) for Node.js|cryptography,post-quantum,ml-kem,key-encapsulation,nist,wasm|wasm|pkg|
lib-q-kem|@lib-q/kem|Post-quantum Key Encapsulation Mechanisms for Node.js|cryptography,post-quantum,kem,key-encapsulation,wasm|wasm,ml-kem|pkg|
lib-q-sig|@lib-q/sig|Post-quantum Digital Signatures for Node.js|cryptography,post-quantum,signatures,digital-signatures,wasm|wasm,ml-dsa|pkg-sig|
lib-q-hash|@lib-q/hash|Post-quantum Hash Functions for Node.js (SHA-3, SHAKE, cSHAKE, KMAC, TupleHash, ParallelHash)|cryptography,post-quantum,hash,shake,kmac,tuplehash,parallelhash,wasm|alloc,oid|pkg-hash|
lib-q-utils|@lib-q/utils|Utility functions for post-quantum cryptography|cryptography,post-quantum,utilities,helpers,wasm||pkg-utils|
lib-q-fn-dsa|@lib-q/fn-dsa|FN-DSA (FIPS 206) post-quantum digital signatures for Node.js|cryptography,post-quantum,fn-dsa,falcon,signature,wasm,nist|wasm,std,rand|pkg|
lib-q-aead|@lib-q/aead|Post-quantum AEAD (Saturnin, Romulus, duplex-sponge) for Node.js|cryptography,post-quantum,aead,saturnin,wasm,nist|wasm,saturnin,romulus,duplex-sponge-aead|pkg|
lib-q-hpke|@lib-q/hpke|Post-quantum HPKE (RFC 9180) for Node.js|cryptography,post-quantum,hpke,ml-kem,wasm|wasm,alloc,ml-kem,saturnin,shake256|pkg|
lib-q-zkp|@lib-q/zkp|Post-quantum zero-knowledge proofs (STARK) for Node.js|cryptography,post-quantum,zkp,stark,wasm|wasm,zkp|pkg|
lib-q-random|@lib-q/random|Secure random bytes for post-quantum libQ on Node.js and WASM|cryptography,random,entropy,wasm,getrandom|wasm|pkg|
lib-q-hqc|@lib-q/hqc|HQC KEM (NIST PQC) for Node.js|cryptography,post-quantum,hqc,kem,wasm|wasm,hqc,random,serialization|pkg|
lib-q-slh-dsa|@lib-q/slh-dsa|SLH-DSA / SPHINCS+ (FIPS 205) signatures for Node.js|cryptography,post-quantum,slh-dsa,sphincs,wasm|wasm|pkg|
lib-q-cb-kem|@lib-q/cb-kem|Classical McEliece CB-KEM for Node.js (single compile-time parameter set)|cryptography,post-quantum,mceliece,cb-kem,wasm|wasm,cbkem348864,wasm_getrandom,alloc,zeroize|pkg|
lib-q-ring-sig|@lib-q/ring-sig|Federation ring-style openings / DualRing-LB pilot for Node.js|cryptography,post-quantum,ring-signature,lattice,wasm|wasm|pkg|
lib-q-prf|@lib-q/prf|Legendre / Gold PRF pilots for Node.js|cryptography,post-quantum,prf,legendre,wasm|wasm|pkg|
npm/lib-q-types|@lib-q/types|TypeScript typings for @lib-q WASM packages|typescript,lib-q,wasm,types|||1
lib-q-stark|@lib-q/stark|STARK framework (lib-q-stark); prove/verify via @lib-q/zkp for high-level flows|cryptography,post-quantum,stark,zkp,wasm|wasm|pkg|
lib-q-plonky|@lib-q/plonky|Plonky3-derived STARK components (lib-q-plonky)|cryptography,post-quantum,zkp,plonky,wasm|wasm|pkg|
lib-q-poseidon|@lib-q/poseidon|Poseidon hash for STARK fields (Complex<Mersenne31>)|cryptography,post-quantum,poseidon,zkp,wasm|wasm,alloc|pkg|
lib-q-lattice-zkp|@lib-q/lattice-zkp|Module-lattice commitments and sigma protocols (research)|cryptography,post-quantum,lattice,zkp,wasm|wasm,random|pkg|
lib-q-ring|@lib-q/ring|ML-DSA ring arithmetic R_q (shared with lattice-zkp)|cryptography,post-quantum,lattice,ml-dsa,wasm|wasm,alloc|pkg|
lib-q-mac|@lib-q/mac|Quantum Carter-Wegman MAC (qCW-MAC) for Node.js|cryptography,post-quantum,mac,wasm|wasm,random|pkg|
lib-q-blind-pcs|@lib-q/blind-pcs|Experimental blind commitment demo (EXPERIMENTAL_NON_NIST)|cryptography,post-quantum,commitment,experimental,wasm|wasm,blind-pcs|pkg|
lib-q-double-kem|@lib-q/double-kem|PROVISIONAL MAUL v1 double ML-KEM-768 for Node.js|cryptography,post-quantum,kem,ml-kem,double-kem,wasm|wasm,std,random|pkg|
lib-q-fhe|@lib-q/fhe|Experimental toy lattice FHE demo (EXPERIMENTAL_NON_NIST)|cryptography,post-quantum,fhe,experimental,wasm|wasm,fhe|pkg|
lib-q-threshold-kem|@lib-q/threshold-kem|PROVISIONAL threshold KEM (ML-KEM-768 + Shamir) for Node.js|cryptography,post-quantum,threshold,kem,wasm|wasm,std,random|pkg|
lib-q-threshold-sig|@lib-q/threshold-sig|PROVISIONAL threshold signatures (FROST-like) for Node.js|cryptography,post-quantum,threshold,signature,wasm|wasm,std,random|pkg|
EOF

mapfile -t ROWS < <(printf '%s\n' "$PACKAGES")

ensure_tools() {
  command -v node >/dev/null || { echo "ERROR: node not found" >&2; exit 1; }
  command -v npm >/dev/null || { echo "ERROR: npm not found" >&2; exit 1; }
  if [[ "$SKIP_BUILD" != "1" ]]; then
    command -v wasm-pack >/dev/null || {
      log "Installing wasm-pack..."
      cargo install wasm-pack --locked
    }
    rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true
  fi
  if [[ "$BUILD_ONLY" != "1" && "$DRY_RUN" != "1" ]]; then
    if [[ -z "${NODE_AUTH_TOKEN:-}" ]] && ! npm whoami >/dev/null 2>&1; then
      echo "ERROR: npm not authenticated. Run 'npm login' or set NODE_AUTH_TOKEN." >&2
      exit 1
    fi
  fi
}

has_wasm_artifacts() {
  local pkg_dir="$1"
  [[ -f "$pkg_dir/web/package.json" || -f "$pkg_dir/package.json" || -f "$pkg_dir/index.js" ]]
}

build_wasm() {
  local wd="$1" features="$2" out_dir="$3"
  log "Building WASM in $wd (features=${features:-default}, out=$out_dir)..."
  pushd "$ROOT/$wd" >/dev/null
  local web_out="$out_dir/web" node_out="$out_dir/nodejs"
  mkdir -p "$web_out" "$node_out"
  local rel="--release"
  local feat_args=()
  if [[ -n "$features" ]]; then
    feat_args=(-- --features "$features" --verbose)
    cargo check --target wasm32-unknown-unknown --features "$features" --lib
    wasm-pack build $rel --target web --out-dir "$web_out" "${feat_args[@]}"
    wasm-pack build $rel --target nodejs --out-dir "$node_out" "${feat_args[@]}"
  else
    wasm-pack build $rel --target web --out-dir "$web_out" --verbose
    wasm-pack build $rel --target nodejs --out-dir "$node_out" --verbose
  fi
  popd >/dev/null
}

ensure_pkg_manifest() {
  local pkg_dir="$1"
  if [[ -f "$pkg_dir/package.json" ]]; then
    return 0
  fi
  if [[ -f "$pkg_dir/web/package.json" ]]; then
    cp "$pkg_dir/web/package.json" "$pkg_dir/package.json"
    return 0
  fi
  if [[ -f "$pkg_dir/nodejs/package.json" ]]; then
    cp "$pkg_dir/nodejs/package.json" "$pkg_dir/package.json"
    return 0
  fi
  log "ERROR: no package.json under $pkg_dir (wasm-pack output missing?)"
  return 1
}

prepare_npm_package() {
  local pkg_dir="$1" npm_name="$2" description="$3" keywords="$4" crate_root="$5"
  ensure_pkg_manifest "$pkg_dir" || return 1
  # wasm-pack writes `*` in web/.gitignore and nodejs/.gitignore; npm pack honors those and omits .wasm glue.
  rm -f "$pkg_dir/web/.gitignore" "$pkg_dir/nodejs/.gitignore" 2>/dev/null || true
  pushd "$pkg_dir" >/dev/null
  local stem=""
  if [[ -n "$crate_root" && -f "$ROOT/$crate_root/Cargo.toml" ]]; then
    stem=$(CRATE_TOML="$ROOT/$crate_root/Cargo.toml" "$PYTHON" -c "import os,tomllib;d=tomllib.load(open(os.environ['CRATE_TOML'],'rb'));lib=d.get('lib')or{};print(lib.get('name')or d['package']['name'].replace('-','_'))")
  fi
  export NPM_PUBLISH_STEM="$stem"
  npm pkg set name="$npm_name"
  npm pkg set version="$VERSION"
  npm pkg set description="$description"
  npm pkg set type="module"
  KEYWORDS_JSON=$(KEYWORDS_INPUT="$keywords" node -e "const keywords = process.env.KEYWORDS_INPUT.split(',').map(k => k.trim()).filter(k => k); console.log(JSON.stringify(keywords));")
  npm pkg set keywords="$KEYWORDS_JSON"
  npm pkg set author="lib-Q Contributors"
  npm pkg set license="Apache-2.0"
  npm pkg set repository.type="git"
  npm pkg set repository.url="https://github.com/Enkom-Tech/libQ.git"
  npm pkg set homepage="https://github.com/Enkom-Tech/libQ#readme"
  npm pkg set bugs.url="https://github.com/Enkom-Tech/libQ/issues"
  local readme_dst="README.md"
  if [[ -n "$crate_root" && -f "$ROOT/$crate_root/README.md" ]]; then
    cp "$ROOT/$crate_root/README.md" "$readme_dst"
  else
    sed 's/^        //' >"$readme_dst" <<EOF
# $npm_name

$description

## Install

\`\`\`bash
npm install $npm_name@$VERSION
\`\`\`
EOF
  fi
  node "$ROOT/scripts/npm-publish-annotate.mjs"
  if [[ -f integrity-manifest.json ]]; then
    {
      echo ""
      echo "## Subresource integrity (SHA-384)"
      echo "Paths in \`integrity-manifest.json\` are relative to the package root."
    } >>"$readme_dst"
  fi
  popd >/dev/null
}

publish_one() {
  local npm_name="$1" pkg_dir="$2"
  local attempt out code otp_args=()
  if [[ -n "${NPM_OTP:-}" ]]; then
    otp_args=(--otp="$NPM_OTP")
  fi
  for attempt in $(seq 1 6); do
    set +e
    if [[ "$DRY_RUN" == "1" ]]; then
      out=$(cd "$pkg_dir" && npm publish --access public --dry-run "${otp_args[@]}" 2>&1)
      code=$?
    else
      # Do not pass --provenance with NODE_AUTH_TOKEN; npm often returns misleading E404.
      out=$(cd "$pkg_dir" && npm publish --access public "${otp_args[@]}" 2>&1)
      code=$?
    fi
    set -e
    printf '%s\n' "$out"
    printf '%s\n' "$out" >>"$LOG" 2>/dev/null || true
    if [[ "$DRY_RUN" == "1" ]]; then
      log "DRY_RUN OK: $npm_name"
      return 0
    fi
    if printf '%s' "$out" | grep -qE 'npm ERR! 403.*You cannot publish over'; then
      log "SKIP (already published): $npm_name"
      return 0
    fi
    if printf '%s' "$out" | grep -qiE 'code E403.*cannot publish|already exists|previously published'; then
      log "SKIP (already published): $npm_name"
      return 0
    fi
    if [[ "$code" -eq 0 ]]; then
      log "OK: $npm_name"
      return 0
    fi
    if printf '%s' "$out" | grep -qE '429|rate limit|too many requests'; then
      local wait=120
      log "Rate limited on $npm_name; waiting ${wait}s (attempt $attempt)..."
      sleep "$wait"
      continue
    fi
    log "FAILED: $npm_name (exit $code)"
    return "$code"
  done
  log "FAILED: $npm_name (retries exhausted)"
  return 101
}

main() {
  ensure_tools
  echo "" >>"$LOG"
  log "=== run START_AT=$START_AT END_AT=${END_AT:-*} VERSION=$VERSION DRY_RUN=$DRY_RUN SKIP_BUILD=$SKIP_BUILD BUILD_ONLY=$BUILD_ONLY PUBLISH_ONLY=$PUBLISH_ONLY ==="

  local i=0
  for row in "${ROWS[@]}"; do
    [[ -n "$row" ]] || continue
    IFS='|' read -r wd npm_name description keywords features out_dir skip_build <<<"$row"
    if (( i < START_AT )); then
      ((i++)) || true
      continue
    fi
    if [[ -n "$END_AT" ]] && (( i > END_AT )); then
      break
    fi
    local crate_root="$wd"
    local pkg_dir
    if [[ "$skip_build" == "1" ]]; then
      pkg_dir="$ROOT/$wd"
      crate_root=""
    else
      pkg_dir="$ROOT/$wd/$out_dir"
      if [[ "$SKIP_BUILD" != "1" ]] && ! has_wasm_artifacts "$pkg_dir"; then
        build_wasm "$wd" "$features" "$out_dir"
      elif [[ "$SKIP_BUILD" != "1" ]]; then
        log "SKIP build (artifacts exist): $npm_name"
      fi
    fi
    if [[ "$BUILD_ONLY" == "1" ]]; then
      log "BUILD_ONLY OK: $npm_name"
      ((i++)) || true
      continue
    fi
    log "Publishing $npm_name from $pkg_dir ..."
    prepare_npm_package "$pkg_dir" "$npm_name" "$description" "$keywords" "$crate_root"
    publish_one "$npm_name" "$pkg_dir" || exit $?
    ((i++)) || true
    sleep 5
  done
  log "All ${#ROWS[@]} npm packages processed."
}

main "$@"
