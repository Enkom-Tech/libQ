#!/usr/bin/env bash
# Bounded retry for CI steps whose failures are environmental, not defects:
# apt-get installs, crates.io/registry fetches, toolchain downloads. A runner
# that is reclaimed mid-step, or a registry that answers one 5xx, currently
# turns the whole job red -- indistinguishable from a real regression and,
# per the dependency-audit step's own comment, this runner is "occasionally
# reclaimed mid-job".
#
# Contract:
#   - Retries ONLY the command given. Never wraps a test, a guard or anything
#     whose failure could mean a real defect -- only idempotent network/install
#     steps. Callers are reviewed with that rule in mind.
#   - Retries on ANY non-zero exit (apt has no distinct "transient" code, and
#     a network fetch can fail in any layer). The retried command must
#     therefore be safe to re-run; every current caller is.
#   - Bounded: default 3 attempts, 10 s initial delay doubling to a 60 s cap.
#   - Fail-closed: after the final attempt the exit status is the command's
#     own, prefixed by an "INFRA-FAILURE:" banner so a red log names the
#     failure class instead of looking like a code regression. The banner is
#     a classification aid, not a pass: the step still fails.
#
# Usage:
#   ci-retry.sh [--attempts N] [--delay S] [--max-delay S] -- command [args...]
#   ci-retry.sh --self-test

set -uo pipefail

usage() {
	echo "usage: ci-retry.sh [--attempts N] [--delay S] [--max-delay S] -- command [args...]" >&2
	echo "       ci-retry.sh --self-test" >&2
	exit 2
}

attempts=3
delay=10
max_delay=60

while [ $# -gt 0 ]; do
	case "$1" in
	--attempts)
		[ $# -ge 2 ] || usage
		attempts="$2"
		shift 2
		;;
	--delay)
		[ $# -ge 2 ] || usage
		delay="$2"
		shift 2
		;;
	--max-delay)
		[ $# -ge 2 ] || usage
		max_delay="$2"
		shift 2
		;;
	--self-test)
		self_test=1
		shift
		;;
	--)
		shift
		break
		;;
	*)
		usage
		;;
	esac
done

if [ "${self_test:-0}" = 1 ]; then
	[ $# -eq 0 ] || usage
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT

	# 1. A command that fails twice then succeeds is retried to success.
	cat >"$tmp/flaky" <<'EOF'
#!/bin/sh
n=$(cat "$1" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" >"$1"
[ "$n" -ge 3 ]
EOF
	chmod +x "$tmp/flaky"
	if ! bash "$0" --attempts 5 --delay 0 -- "$tmp/flaky" "$tmp/count" >"$tmp/out1" 2>&1; then
		echo "ci-retry self-test: FAIL -- did not recover a fail-twice-then-pass command" >&2
		cat "$tmp/out1" >&2
		exit 1
	fi
	[ "$(cat "$tmp/count")" = "3" ] || {
		echo "ci-retry self-test: FAIL -- ran $(cat "$tmp/count") times, expected 3" >&2
		exit 1
	}

	# 2. A command that always fails exhausts attempts and exits non-zero,
	#    with the INFRA-FAILURE banner in output.
	if bash "$0" --attempts 2 --delay 0 -- false >"$tmp/out2" 2>&1; then
		echo "ci-retry self-test: FAIL -- always-failing command reported success" >&2
		exit 1
	fi
	grep -q "INFRA-FAILURE" "$tmp/out2" || {
		echo "ci-retry self-test: FAIL -- no INFRA-FAILURE banner on exhausted retries" >&2
		cat "$tmp/out2" >&2
		exit 1
	}

	# 3. A command that succeeds first try runs exactly once.
	: >"$tmp/once"
	if ! bash "$0" --delay 0 -- echo ok >"$tmp/out3" 2>&1; then
		echo "ci-retry self-test: FAIL -- passing command reported failure" >&2
		exit 1
	fi
	echo "ci-retry self-test: OK (recover, exhaust+banner, single-pass)"
	exit 0
fi

[ $# -ge 1 ] || usage

i=1
while :; do
	if "$@"; then
		[ "$i" -gt 1 ] && echo "ci-retry: succeeded on attempt $i/$attempts"
		exit 0
	else
		status=$?
	fi
	[ "$i" -ge "$attempts" ] && break
	echo "ci-retry: attempt $i/$attempts failed (exit $status); retrying in ${delay}s" >&2
	sleep "$delay"
	delay=$((delay * 2))
	[ "$delay" -gt "$max_delay" ] && delay="$max_delay"
	i=$((i + 1))
done

echo "INFRA-FAILURE: '$*' failed $attempts attempt(s); environmental, not retried further" >&2
exit "$status"
