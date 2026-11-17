# Copyright 2026, Dario Casalinuovo.
# SPDX-License-Identifier: LGPL-2.1-or-later
# Shared by the trial scripts: result lines, a private state tree, cleanup.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
JUNO=${JUNO:-$ROOT/build/juno}
HELPER=${HELPER:-$ROOT/build/juno_helper}
JT=$(mktemp -d "${JUNO_TEST_TMP:-/tmp}/juno-trial.XXXXXX")
T=$JT/t
mkdir -p "$T" "$JT/tmp"
export TMPDIR=$JT/tmp JUNO_RUNTIME_DIR=$JT/rt JUNO_DATA_DIR=$JT/dt
mkdir -p "$JUNO_RUNTIME_DIR" "$JUNO_DATA_DIR"
chmod 700 "$JUNO_RUNTIME_DIR" "$JUNO_DATA_DIR"
pass=0
fail=0
skip=0
ok() {
	echo "PASS $1 - $2"
	pass=$((pass + 1))
}
bad() {
	echo "FAIL $1 - $2"
	fail=$((fail + 1))
}
skp() {
	echo "SKIP $1 - $2"
	skip=$((skip + 1))
}
chk() {
	if [ $r -eq 0 ]; then
		ok "$1" "$2"
	else
		bad "$1" "$2 (check failed)"
	fi
}
J()    { timeout 60 "$JUNO" run "$@"; }
psl()  { "$JUNO" ps | tail -n +2; }
named() { "$JUNO" run --name "$@"; }
# waitfor CONDITION SECONDS: poll CONDITION every 50 ms until it holds
waitfor() {
	local tries=$(( $2 * 20 ))

	while [ $tries -gt 0 ]; do
		eval "$1" && return 0
		sleep 0.05
		tries=$((tries - 1))
	done
	return 1
}
EXTRA_CLEANUP=:
cleanup() {
	eval "$EXTRA_CLEANUP"
	"$JUNO" ps 2>/dev/null | tail -n +2 | while read -r n _; do "$JUNO" stop "$n" --time 1 >/dev/null 2>&1; done
	"$JUNO" net ls 2>/dev/null | tail -n +2 | while read -r n _; do "$JUNO" net rm "$n" >/dev/null 2>&1; done
	jobs -p | xargs -r kill 2>/dev/null
	"$JUNO" rmtree "$JT" >/dev/null 2>&1
	rm -rf "$JT"
}
trap cleanup EXIT
. "$(dirname "${BASH_SOURCE[0]}")/procs.sh"
# no stage directory may survive in our private TMPDIR
leftover_tmp() {
	local leftover

	leftover=$(ls -A "$TMPDIR")
	[ -z "$leftover" ]
	r=$?
	chk no-leftover-stage-dirs "private TMPDIR is empty${leftover:+: $leftover}"
}

summary() {
	echo "SUMMARY $1: $pass passed, $fail failed, $skip skipped"
	[ $fail -eq 0 ]
}
