#!/bin/bash
# Copyright 2026, Dario Casalinuovo.
# SPDX-License-Identifier: LGPL-2.1-or-later
# Reruns the cgroup tests inside a delegated systemd user scope.
ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$(dirname "$0")/procs.sh"
JUNO=${JUNO:-$ROOT/build/juno}
HELPER=${HELPER:-$ROOT/build/juno_helper}
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
summary() {
	echo "SUMMARY cgroup.sh: $pass passed, $fail failed, $skip skipped"
	[ $fail -eq 0 ]
}

if [ -z "$JUNO_IN_SCOPE" ]; then
	if ! command -v systemd-run >/dev/null; then
		skp cgroup-all "systemd-run not installed"
		summary
		exit
	fi
	why=$(systemd-run --user --scope --quiet --expand-environment=no -p Delegate=yes true 2>&1)
	if [ $? -ne 0 ]; then
		skp cgroup-all "systemd-run --user --scope -p Delegate=yes failed: $(echo "$why" | head -1)"
		summary
		exit
	fi
	export JUNO_IN_SCOPE=1
	exec systemd-run --user --scope --quiet --expand-environment=no -p Delegate=yes -- bash "$0"
fi

# We are the first process of a delegated scope. A manager keeps itself in a
# leaf and enables the controllers on the scope, as the cgroup v2 rules require.
cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
if ! { mkdir "$cg/manager" && echo $$ > "$cg/manager/cgroup.procs" &&
       echo "+memory +pids +cpu" > "$cg/cgroup.subtree_control"; } 2>/dev/null; then
	skp cgroup-all "cannot prepare the delegated scope $cg"
	summary
	exit
fi
H="--bind-ro $HELPER:/helper"
J() { timeout 60 "$JUNO" run "$@"; }
leaves() { ls "$cg" | grep -c '^juno-'; }

probe=$("$JUNO" probe)
echo "$probe" | grep -q '^cgroup v2 delegation: usable'; r=$?; chk cgroup-probe-usable "$(echo "$probe" | grep '^cgroup')"
if [ $r -ne 0 ]; then summary; exit; fi

J $H --mem 33554432 -- /helper alloc 300 >/dev/null 2>&1; rc=$?
out=$(J $H --mem 1073741824 -- /helper alloc 64)
[ $rc -eq 137 ] && [ "$out" = "alloc ok" ]; r=$?; chk cgroup-memory-enforced "300MB under a 32MB cap: rc=$rc (137 = OOM kill); 64MB under 1GB: $out"
out=$(J $H --pids 10 -- /helper forkcount 30); ctl=$(J $H -- /helper forkcount 30)
[ "${out:-99}" -ge 1 ] && [ "${out:-99}" -le 9 ] && [ "$ctl" = 30 ]
r=$?; chk cgroup-pids-enforced "pids.max 10 allowed $out forks of 30, unlimited allowed $ctl"
"$JUNO" run --cpu-weight 50 --mem 104857600 --pids 50 -- sleep 3 & jp=$!
n=40; while [ $n -gt 0 ] && ! ls -d "$cg"/juno-*/ >/dev/null 2>&1; do sleep 0.05; n=$((n-1)); done
leaf=$(ls -d "$cg"/juno-*/ 2>/dev/null | head -1)
vals=$(cat "$leaf/cpu.weight" "$leaf/memory.max" "$leaf/pids.max" 2>/dev/null | tr '\n' ' ')
[ "$vals" = "50 104857600 50 " ]; r=$?; chk cgroup-limits-written "cpu.weight, memory.max, pids.max in the leaf: $vals"
wait $jp
[ "$(leaves)" = 0 ]; r=$?; chk cgroup-removed-after-exit "no juno-* cgroup left after the cell ended ($(leaves))"
J $H --pids 5 -- /helper forkcount 3 >/dev/null; [ "$(leaves)" = 0 ]; r=$?; chk cgroup-removed-second-run "second run leaves nothing either"

export JUNO_RUNTIME_DIR=$(mktemp -d "${JUNO_TEST_TMP:-/tmp}/juno-rt.XXXXXX") JUNO_DATA_DIR=$(mktemp -d "${JUNO_TEST_TMP:-/tmp}/juno-dt.XXXXXX")
"$JUNO" run --name cgx -d --mem 33554432 $H -- sleep 60
"$JUNO" exec cgx -- /helper alloc 300 >/dev/null 2>&1; rc=$?
out=$("$JUNO" exec cgx -- /helper alloc 8)
[ $rc -eq 137 ] && [ "$out" = "alloc ok" ]; r=$?; chk cgroup-exec-joins-cell "exec'd process is bound by the cell's memory.max: rc=$rc, small alloc: $out"
"$JUNO" stop cgx --time 1
[ "$(leaves)" = 0 ]; r=$?; chk cgroup-removed-named "named cell's cgroup removed after stop"

# agent preset memory limit, and --mem surviving a restart
T=$(mktemp -d "${JUNO_TEST_TMP:-/tmp}/juno-cgt.XXXXXX"); mkdir -p "$T/ws"
"$JUNO" run --preset agent --workspace "$T/ws" -- sleep 4 & jp=$!
n=40; while [ $n -gt 0 ] && ! ls -d "$cg"/juno-*/ >/dev/null 2>&1; do sleep 0.05; n=$((n-1)); done
leaf=$(ls -d "$cg"/juno-*/ 2>/dev/null | head -1); mv_=$(cat "$leaf/memory.max" 2>/dev/null); pm=$(cat "$leaf/pids.max" 2>/dev/null)
kill $jp 2>/dev/null; wait $jp 2>/dev/null
[ "$mv_" = 2147483648 ] && [ "$pm" = 256 ]; r=$?; chk cgroup-agent-preset-limits "agent preset sets memory.max $mv_ and pids.max $pm on a usable cgroup"
J --preset agent --mem 33554432 --workspace "$T/ws" $H --landlock-ro /helper -- /helper alloc 300 >/dev/null 2>&1; rc=$?
[ $rc -eq 137 ]; r=$?; chk cgroup-agent-mem-override "--preset agent --mem 32M overrides the preset and is enforced (rc=$rc)"
export JUNO_RUNTIME_DIR=${JUNO_RUNTIME_DIR:-$(mktemp -d "${JUNO_TEST_TMP:-/tmp}/juno-rt.XXXXXX")} JUNO_DATA_DIR=${JUNO_DATA_DIR:-$(mktemp -d "${JUNO_TEST_TMP:-/tmp}/juno-dt.XXXXXX")}
"$JUNO" run --name rmem -d --restart always --mem 33554432 $H -- sleep 120
waitfor 'ls -d "$cg"/juno-*/ >/dev/null 2>&1' 5; before=$(leaves)
"$JUNO" kill rmem KILL; waitfor '"$JUNO" status rmem | grep -q "^restarts=[1-9]"' 10; sleep 0.5
after=$(leaves); leaf=$(ls -d "$cg"/juno-*/ | head -1); mm=$(cat "$leaf/memory.max")
"$JUNO" exec rmem -- /helper alloc 300 >/dev/null 2>&1; erc=$?
"$JUNO" stop rmem --time 1
[ "$before" = 1 ] && [ "$after" = 1 ] && [ "$mm" = 33554432 ] && [ $erc -eq 137 ] && [ "$(leaves)" = 0 ]
r=$?; chk cgroup-restart-keeps-mem "one cgroup before ($before) and after ($after) a restart, memory.max $mm, exec still OOM-killed (rc=$erc), nothing left ($(leaves))"
JB="--bind-ro $JUNO:/juno"
out=$(J --nesting $JB $H --pids 14 -- /juno run --bind-ro /helper:/helper -- /helper forkcount 40)
ctl=$(J --nesting $JB $H -- /juno run --bind-ro /helper:/helper -- /helper forkcount 40)
[ "${out:-99}" -ge 1 ] && [ "${out:-99}" -le 13 ] && [ "$ctl" = 40 ]
r=$?; chk nesting-outer-pids-bounds-inner "outer pids.max 14: inner helper forked $out of 40; unlimited outer: $ctl"

# shared network together with cgroup limits
SP=$(freebase 2)
"$JUNO" run --name cgs -d --net shared:cgn --mem 33554432 --pids 40 $H -- /helper listen $SP
n=40; while [ $n -gt 0 ] && ! J --net shared:cgn $H -- /helper connect 127.0.0.1 $SP >/dev/null 2>&1; do sleep 0.1; n=$((n-1)); done
out=$(J --net shared:cgn $H -- /helper connect 127.0.0.1 $SP)
"$JUNO" exec cgs -- /helper alloc 300 >/dev/null 2>&1; rc=$?
vals=$(cat "$cg"/juno-*/memory.max "$cg"/juno-*/pids.max 2>/dev/null | tr '\n' ' ')
"$JUNO" stop cgs --time 1
[ "$out" = hello ] && [ $rc -eq 137 ] && [ "$vals" = "33554432 40 " ] && [ "$(leaves)" = 0 ]
r=$?; chk cgroup-shared-net-limits "listener reachable ($out), exec bound by memory.max (rc=$rc), leaf had $vals and was removed ($(leaves) left)"

# nesting: the inner cell gets a real cgroup below the outer one
JB="--bind-ro $JUNO:/juno"
out=$(J --nesting $JB --mem 268435456 -- /juno probe | grep '^cgroup')
echo "$out" | grep -q 'usable'; r=$?; chk nesting-delegated-subtree "inner probe inside a nesting cell: $out"
J --nesting $JB $H --mem 268435456 -- /juno run --mem 16777216 --bind-ro /helper:/helper -- /helper alloc 64 >/dev/null 2>&1; rc1=$?
out=$(J --nesting $JB $H --mem 268435456 -- /juno run --mem 1073741824 --bind-ro /helper:/helper -- /helper alloc 32)
J --nesting $JB $H --mem 268435456 -- /juno run --mem 1073741824 --bind-ro /helper:/helper -- /helper alloc 400 >/dev/null 2>&1; rc2=$?
[ $rc1 -eq 137 ] && [ "$out" = "alloc ok" ] && [ $rc2 -eq 137 ] && [ "$(leaves)" = 0 ]
r=$?; chk nesting-inner-memory-limits "inner cap 16M kills a 64M alloc by cgroup (rc=$rc1, an rlimit would give 3); 32M ok ($out); inner 1G cap still bound by the outer 256M (rc=$rc2); leftovers $(leaves)"
out=$(J --nesting $JB $H --mem 268435456 -- sh -c 'cat /sys/fs/cgroup/cgroup.controllers; cat /sys/fs/cgroup/memory.max 2>&1 | head -1; test -w /sys/fs/cgroup/cgroup.procs && echo writable')
echo "$out" | grep -q memory && echo "$out" | grep -q writable
r=$?; chk nesting-cell-sees-own-subtree "the cell sees a cgroup tree rooted at its own subtree, writable: $(echo $out | tr '\n' ' ')"

"$JUNO" ps | tail -n +2 | while read -r n _; do "$JUNO" stop "$n" --time 1 >/dev/null 2>&1; done
rm -rf "$JUNO_RUNTIME_DIR" "$JUNO_DATA_DIR" "$T"
rmdir "$cg/manager" 2>/dev/null
summary
