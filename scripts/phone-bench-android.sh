#!/usr/bin/env bash
# Cross-build phone-bench for Android arm64, run it on an adb-attached phone, pull the JSON back.
#
# NOT VERIFIED: the author's VM had neither an Android NDK nor a device. See lib-q-phone-bench/README.md.
#
# Usage: scripts/phone-bench-android.sh [-s SERIAL] [-o OUT.json] [-l LABEL] [-- extra phone-bench run args]
# Needs: ANDROID_NDK_HOME, `rustup target add aarch64-linux-android`, `adb`.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SERIAL=""; OUT="phone-bench-android.json"; LABEL="android-arm64"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -s) SERIAL="$2"; shift 2 ;;
    -o) OUT="$2"; shift 2 ;;
    -l) LABEL="$2"; shift 2 ;;
    --) shift; break ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to an NDK r26+ install}"
API="${ANDROID_API:-29}"
HOST_TAG="$(ls "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt" | head -n1)"
CLANG="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/bin/aarch64-linux-android${API}-clang"
[[ -x "$CLANG" ]] || { echo "linker not found: $CLANG" >&2; exit 1; }

export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CLANG"
export CC_aarch64_linux_android="$CLANG"
# Portable build: the code path the library ships. No target-cpu=native.
cargo build --release -p lib-q-phone-bench --target aarch64-linux-android

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
BIN="$TARGET_DIR/aarch64-linux-android/release/phone-bench"
ADB=(adb); [[ -n "$SERIAL" ]] && ADB=(adb -s "$SERIAL")
REMOTE=/data/local/tmp/phone-bench
"${ADB[@]}" push "$BIN" "$REMOTE" >/dev/null
"${ADB[@]}" shell chmod 755 "$REMOTE"
# Put the device model and SoC in the label so the file describes itself.
MODEL="$("${ADB[@]}" shell getprop ro.product.model | tr -d '\r')"
SOC="$("${ADB[@]}" shell getprop ro.soc.model | tr -d '\r')"
"${ADB[@]}" shell "$REMOTE run --class phone --label '${LABEL} ${MODEL} ${SOC}' --out $REMOTE.json $*"
"${ADB[@]}" pull "$REMOTE.json" "$OUT" >/dev/null
echo "wrote $OUT"
