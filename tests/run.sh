#!/bin/bash
# Copyright 2026, Dario Casalinuovo.
# SPDX-License-Identifier: LGPL-2.1-or-later
# Drives the juno CLI. One PASS|FAIL|SKIP line per test.
ROOT=$(cd "$(dirname "$0")/.." && pwd)
JUNO=${JUNO:-$ROOT/build/juno}
HELPER=${HELPER:-$ROOT/build/juno_helper}
T=$(mktemp -d "$ROOT/build/t.XXXXXX")
TB=${JUNO_TEST_TMP:-/tmp}
export JUNO_RUNTIME_DIR=$(mktemp -d "$TB/juno-rt.XXXXXX") JUNO_DATA_DIR=$(mktemp -d "$TB/juno-dt.XXXXXX") TMPDIR=$(mktemp -d "$TB/juno-tmp.XXXXXX")
pass=0
fail=0
skip=0
cleanup() {
	"$JUNO" ps 2>/dev/null | tail -n +2 | while read -r n _; do "$JUNO" stop "$n" --time 1 >/dev/null 2>&1; done
	"$JUNO" net ls 2>/dev/null | tail -n +2 | while read -r n _; do "$JUNO" net rm "$n" >/dev/null 2>&1; done
	jobs -p | xargs -r kill 2>/dev/null
	chmod -R u+rwx "$T" "$JUNO_DATA_DIR" 2>/dev/null
	"$JUNO" rmtree "$T" "$JUNO_DATA_DIR" >/dev/null 2>&1
	rm -rf "$T" "$JUNO_RUNTIME_DIR" "$JUNO_DATA_DIR" "$TMPDIR"
}
trap cleanup EXIT

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
# chk NAME DETAIL: passes when r (status of the preceding condition) is 0
chk() {
	if [ $r -eq 0 ]; then
		ok "$1" "$2"
	else
		bad "$1" "$2 (check failed)"
	fi
}

. "$ROOT/tests/procs.sh"
H0="--bind-ro $HELPER:/helper"
J() { timeout 60 "$JUNO" run "$@"; }
tr_ifaces() { tail -n +3 | cut -d: -f1 | tr -d ' ' | tr '\n' ' '; }

probe=$("$JUNO" probe 2>&1)
if ! J -- true >/dev/null 2>"$T/pre.err"; then
	skp all "cells cannot start on this host: $(cat "$T/pre.err")"
echo "SUMMARY run.sh: $pass passed, $fail failed, $skip skipped"
	exit 0
fi

# --- exit status -----------------------------------------------------------
J -- true; rc=$?
[ $rc -eq 0 ]; r=$?; chk exit-zero "payload true gives $rc"
J -- sh -c 'exit 7'; rc=$?
[ $rc -eq 7 ]; r=$?; chk exit-code "exit 7 gives $rc (not 0)"
J -- sh -c 'kill -9 $$'; rc=$?
[ $rc -eq 137 ]; r=$?; chk exit-signal-tiny "SIGKILL payload gives $rc, want 137"
J $H0 -- /helper segv; rc=$?
J $H0 --init none -- /helper segv; rc2=$?
[ $rc -eq 139 ] && [ $rc2 -eq 139 ]; r=$?; chk exit-signal-segv "SIGSEGV payload gives $rc (tiny init) and $rc2 (init none), want 139"
s=$(date +%s); J --timeout 1 -- sleep 30; rc=$?; e=$(( $(date +%s) - s ))
[ $rc -eq 124 ] && [ $e -lt 10 ]; r=$?; chk timeout-kills "rc=$rc after ${e}s, want 124 in <10s"
J --timeout 10 -- true; rc=$?
[ $rc -eq 0 ]; r=$?; chk timeout-not-hit "fast payload under --timeout gives $rc, not 124"
J --timeout 1 --init none -- sleep 30; rc=$?
[ $rc -eq 124 ]; r=$?; chk timeout-init-none "wall-clock timeout with init none gives $rc"

# --- pid namespace ---------------------------------------------------------
out=$(J -- sh -c 'echo $$; ls /proc | grep -c "^[0-9]"' 2>&1)
mypid=$(echo "$out" | sed -n 1p); cnt=$(echo "$out" | sed -n 2p)
hostcnt=$(ls /proc | grep -c '^[0-9]')
[ "${mypid:-999}" -le 5 ] && [ "${cnt:-999}" -le 6 ] && [ "$hostcnt" -gt 20 ]
r=$?; chk pidns-low-pid "payload pid $mypid, $cnt pids in /proc, host has $hostcnt"
kill -0 $$ 2>/dev/null; hostok=$?
J -- sh -c "kill -0 $$" 2>/dev/null; rc=$?
[ $hostok -eq 0 ] && [ $rc -ne 0 ]; r=$?; chk pidns-host-invisible "host pid $$ visible on host (rc $hostok), in cell kill -0 rc=$rc"

# --- mounts ----------------------------------------------------------------
[ -e "$HOME" ] && J -- sh -c "test ! -e '$HOME' && test ! -e /home"
r=$?; chk mount-home-hidden "host $HOME exists on host but not in host-ro cell"
mkdir -p "$T/ro" "$T/rw"; echo data > "$T/ro/f"
out=$(J --bind-ro "$T/ro:/data" -- sh -c 'cat /data/f; { echo x > /data/new; } 2>/dev/null && echo WROTE || echo DENIED')
[ "$out" = "$(printf 'data\nDENIED')" ] && [ ! -e "$T/ro/new" ]
r=$?; chk mount-bind-ro "read ok, write denied, nothing on host: $(echo $out)"
out=$(J --bind "$T/rw:/data" -- sh -c 'echo hello > /data/out; test -e '"$T"'/rw && echo LEAK')
[ "$(cat "$T/rw/out" 2>/dev/null)" = hello ] && [ -z "$out" ]
r=$?; chk mount-bind-rw "write visible on host; original path $T/rw not visible in cell"
out=$(J --tmpfs /scratch -- sh -c 'echo a > /scratch/x; cat /scratch/x')
out2=$(J --tmpfs /scratch -- sh -c 'ls /scratch | wc -l')
[ "$out" = a ] && [ "$out2" = 0 ] && [ ! -e /scratch ]
r=$?; chk mount-tmpfs "writable ($out), empty in a fresh cell ($out2), absent on host"

# --- roots -----------------------------------------------------------------
RF=$T/rootfs
mkdir -p "$RF"/{bin,lib,lib64,etc,proc,dev,tmp,run,usr}
BB=$(command -v busybox)
if [ -z "$BB" ]; then
	skp root-dir "busybox not installed"; skp root-overlay "busybox not installed"
	RF=
else
	cp "$BB" "$RF/bin/busybox"
	for a in $("$BB" --list); do ln -sf busybox "$RF/bin/$a"; done
	ldd "$BB" | awk '$1 ~ /^\// {print $1} $2 == "=>" && $3 ~ /^\// {print $3}' | while read -r l; do
		mkdir -p "$RF$(dirname "$l")"; cp -L "$l" "$RF$l"
	done
	echo dirroot > "$RF/etc/juno-marker"
	out=$(J --root "dir:$RF" -- sh -c 'cat /etc/juno-marker; ls /; test -e /home && echo HOME; test -e /usr/bin/busybox && echo HOSTUSR' 2>&1)
	echo "$out" | grep -q '^dirroot$' && echo "$out" | grep -q '^bin$' &&
		! echo "$out" | grep -q -e HOME -e HOSTUSR && [ ! -e /etc/juno-marker ]
	r=$?; chk root-dir "marker from rootfs visible, no host /home or /usr/bin; host lacks marker"

	mkdir -p "$T/up"
	out=$(J --root "overlay:$T/up" --layer "$RF" -- sh -c 'echo new > /newfile; echo changed > /etc/juno-marker; cat /etc/juno-marker' 2>&1)
	[ "$out" = changed ] && [ "$(cat "$T/up/newfile" 2>/dev/null)" = new ] &&
		[ "$(cat "$T/up/etc/juno-marker" 2>/dev/null)" = changed ] &&
		[ "$(cat "$RF/etc/juno-marker")" = dirroot ] && [ ! -e "$RF/newfile" ]
	r=$?; chk root-overlay "writes in upper (newfile, copy-up), lower unchanged; out=$out"
	J --root "overlay:$T/up2" -- true 2>"$T/o.err"; rc=$?
	[ $rc -eq 125 ] && grep -q overlay "$T/o.err"
	r=$?; chk root-overlay-no-layer "overlay without layer fails with 125: $(head -c 120 "$T/o.err")"
fi

# --- uts / net / dev -------------------------------------------------------
out=$(J --hostname junocell -- hostname); hh=$(hostname)
[ "$out" = junocell ] && [ "$hh" != junocell ]; r=$?; chk uts-hostname "cell '$out', host still '$hh'"
out=$(J -- cat /proc/net/dev | tr_ifaces)
[ "$out" = "lo " ]; r=$?; chk net-none-only-lo "interfaces in cell: '$out'"
J -- busybox ifconfig lo 2>&1 | grep -q UP; r=$?; chk net-none-lo-up "loopback is UP"
out=$(J --net host -- cat /proc/net/dev | tr_ifaces); hostif=$(tr_ifaces < /proc/net/dev)
[ "$out" = "$hostif" ] && [ "$out" != "lo " ]; r=$?
chk net-host-sees-host "cell '$out' vs host '$hostif'"
out=$(J -- sh -c 'echo x > /dev/null && cat /dev/null | wc -c; head -c 4 /dev/zero | wc -c; ls /dev | tr "\n" " "')
exp=$(printf '0\n4\nfd full null ptmx pts random shm stderr stdin stdout tty urandom zero ')
hostdev=$(ls /dev | wc -l)
[ "$out" = "$exp" ] && [ "$hostdev" -gt 13 ]; r=$?; chk dev-minimal "null/zero work; /dev has 13 entries, host has $hostdev"

# --- fd hygiene, env ------------------------------------------------------
hostfds=$( (exec 9</etc/hostname; ls /proc/self/fd) | tr '\n' ' ')
cellfds=$( (exec 9</etc/hostname; J -- ls /proc/self/fd) | tr '\n' ' ')
echo " $hostfds" | grep -q ' 9 ' && ! echo " $cellfds" | grep -q ' 9 '
r=$?; chk fd-hygiene "host sees fds [$hostfds], cell sees [$cellfds]"
export JUNO_LEAK=secret
out=$(J -- env); out2=$(J --env FOO=bar -- env)
env | grep -q JUNO_LEAK && ! echo "$out" | grep -q JUNO_LEAK && ! echo "$out" | grep -q '^HOME=' &&
	! echo "$out" | grep -q JUNO_RUNTIME_DIR && echo "$out2" | grep -q '^FOO=bar$'
r=$?; chk env-clean "JUNO_LEAK/JUNO_RUNTIME_DIR absent by default, FOO=bar present with --env"

# --- privileges ------------------------------------------------------------
st() { J "$@" -- sh -c 'grep -E "^(NoNewPrivs|CapEff|CapBnd|CapInh|CapAmb):" /proc/self/status' | tr -s '\t\n' '  '; }
out=$(st)
echo "$out" | grep -q 'NoNewPrivs: 1' && grep -q 'NoNewPrivs:.0' /proc/self/status
r=$?; chk nnp-set "cell: NoNewPrivs 1; host: $(grep NoNewPrivs /proc/self/status | tr -s '\t' ' ')"
echo "$out" | grep -q 'CapEff: 0000000000000000' && echo "$out" | grep -q 'CapBnd: 0000000000000000'
r=$?; chk caps-empty "$out"
out=$(st --keep-cap net_raw)
echo "$out" | grep -q 'CapEff: 0000000000002000' && echo "$out" | grep -q 'CapBnd: 0000000000002000'
r=$?; chk keep-cap-name "net_raw kept: $out"
out=$(st --keep-cap 0)
echo "$out" | grep -q 'CapEff: 0000000000000001'; r=$?; chk keep-cap-number "cap 0 kept: $out"

# --- seccomp ---------------------------------------------------------------
H="--bind-ro $HELPER:/helper"
out=$(J $H -- /helper userns); out2=$(J $H --seccomp off -- /helper userns)
[ "$out" = "unshare-user Operation not permitted" ] && [ "$out2" = "unshare-user ok" ]
r=$?; chk seccomp-nested-userns "default: '$out'; off: '$out2'"
out=$(J $H -- /helper keyctl); out2=$(J $H --seccomp off -- /helper keyctl)
[ "$out" = "keyctl Operation not permitted" ] && [ "$out2" = "keyctl ok" ]
r=$?; chk seccomp-keyctl "default: '$out'; off: '$out2'"
out=$(J $H --keep-cap sys_admin -- /helper mount); out2=$(J $H --keep-cap sys_admin --seccomp strict -- /helper mount)
[ "$out" = "mount ok" ] && [ "$out2" = "mount Operation not permitted" ]
r=$?; chk seccomp-strict-mount "default+CAP_SYS_ADMIN: '$out'; strict: '$out2'"
out=$(J -- sh -c 'ls / | wc -l; echo fine >/dev/null; echo done')
echo "$out" | tail -1 | grep -q '^done$'; r=$?; chk seccomp-normal-work "ordinary commands run under the default filter"

# --- landlock --------------------------------------------------------------
if echo "$probe" | grep -q '^landlock: yes'; then
	mkdir -p "$T/ll"; echo secret > "$T/ll/f"
	LL="--landlock-ro /usr --landlock-ro /bin --landlock-ro /lib --landlock-ro /lib64 --landlock-ro /etc --landlock-ro /data --landlock-rw /dev --landlock-ro /proc"
	cmd='cat /data/f; { echo x > /data/new; } 2>/dev/null && echo WROTE || echo DENIED'
	out=$(J --bind "$T/ll:/data" $LL -- sh -c "$cmd"); ctl=$(J --bind "$T/ll:/data" -- sh -c "$cmd")
	[ "$out" = "$(printf 'secret\nDENIED')" ] && [ "$ctl" = "$(printf 'secret\nWROTE')" ]
	r=$?; chk landlock-ro "with landlock: $(echo $out); without (rw bind): $(echo $ctl)"
	rm -f "$T/ll/new"
else
	skp landlock-ro "Landlock unavailable: $(echo "$probe" | grep '^landlock')"
fi

# --- limits ----------------------------------------------------------------
out=$(J $H --pids 10 -- /helper forkcount 30); ctl=$(J $H -- /helper forkcount 30)
[ "${out:-99}" -ge 1 ] && [ "${out:-99}" -le 9 ] && [ "$ctl" = 30 ]
r=$?; chk limit-pids "--pids 10 allowed $out forks of 30 (init counts), unlimited allowed $ctl"
out=$(J $H --nofile 20 -- /helper openmany); ctl=$(J $H -- /helper openmany)
[ "${out:-99}" -ge 5 ] && [ "${out:-99}" -le 20 ] && [ "${ctl:-0}" -gt 100 ]
r=$?; chk limit-nofile "--nofile 20 allowed $out opens, default allowed $ctl"
if echo "$probe" | grep -q '^cgroup v2 delegation: usable'; then
	skp limit-mem-cgroup "cgroup tests run in make test-cgroup"
else
	skp limit-mem-cgroup "cgroup delegation unusable: $(echo "$probe" | grep '^cgroup' | sed 's/.*(//; s/)$//')"
	J $H --mem 100000000 --mem-fallback rlimit -- /helper alloc 300 >/dev/null 2>&1; rc=$?
	out=$(J $H --mem 1073741824 --mem-fallback rlimit -- /helper alloc 64)
	[ $rc -ne 0 ] && [ "$out" = "alloc ok" ]; r=$?; chk limit-mem-rlimit-fallback "300MB under 100MB RLIMIT_AS rc=$rc; 64MB under 1GB: $out"
fi

# --- init ------------------------------------------------------------------
out=$(J $H -- /helper zombies); ctl=$(J $H --init none -- /helper zombies)
[ "$out" = 0 ] && [ "${ctl:-0}" -ge 1 ]
r=$?; chk init-reaps "tiny init: $out zombies; without init: $ctl"
"$JUNO" run -- sleep 30 & jp=$!
sleep 1; kill -TERM $jp; wait $jp; rc=$?
[ $rc -eq 143 ]; r=$?; chk init-sigterm-forward "SIGTERM to the CLI ended the payload, rc=$rc (want 143)"

# --- start failure ---------------------------------------------------------
J --bind /nonexistent/xyz:/x -- true 2>"$T/e.err"; rc=$?
[ $rc -eq 125 ] && grep -q 'mount bind' "$T/e.err" && grep -q '/nonexistent/xyz' "$T/e.err"
r=$?; chk start-failure-step "rc=$rc: $(head -c 150 "$T/e.err")"
J --bind "$T/ro:/x" -- true; rc=$?
[ $rc -eq 0 ]; r=$?; chk start-ok-control "valid bind starts (rc=$rc)"
J -- /nonexistent/prog 2>"$T/e.err"; rc=$?
[ $rc -eq 125 ] && grep -q 'exec /nonexistent/prog' "$T/e.err"
r=$?; chk start-failure-exec "rc=$rc: $(head -c 150 "$T/e.err")"

# --- named cells -------------------------------------------------------
RT=$JUNO_RUNTIME_DIR; DT=$JUNO_DATA_DIR
psl() { "$JUNO" ps | tail -n +2; }
waitfor() { local n=$(( $2 * 20 )); while [ $n -gt 0 ]; do eval "$1" && return 0; sleep 0.05; n=$((n-1)); done; return 1; }
named() { "$JUNO" run --name "$@"; }
mkdir -p "$T/data"; : > "$T/data/count"

named c1 -d --bind-ro "$T/ro:/data" --keep-cap net_raw -- sh -c 'echo hello-log; sleep 60'; rc=$?
waitfor 'psl | grep -q "^c1 .*running"' 5
[ $rc -eq 0 ] && psl | grep -q '^c1 .*running'; r=$?; chk named-detached-ps "started detached rc=$rc; ps: $(psl | head -1 | tr -s ' ')"
named c1 -d -- sleep 5 2>"$T/dup.err"; rc=$?
[ $rc -eq 125 ] && grep -q 'already exists' "$T/dup.err" && psl | grep -q '^c1 .*running'
r=$?; chk named-duplicate-refused "second 'c1' gives $rc: $(head -c 100 "$T/dup.err"); first still running"
named c1b -d -- sleep 5; rc=$?; "$JUNO" stop c1b --time 1
[ $rc -eq 0 ]; r=$?; chk named-other-name-ok "a different name starts fine (rc=$rc)"

out=$("$JUNO" exec c1 -- sh -c 'cat /data/f; echo $$; test -e '"$HOME"' && echo HOSTHOME; { echo x > /data/new; } 2>/dev/null && echo WROTE; ls /proc | grep -c "^[0-9]"' 2>&1)
echo "$out" | head -1 | grep -q '^data$' && [ "$(echo "$out" | sed -n 2p)" -le 12 ] && ! echo "$out" | grep -q -e HOSTHOME -e WROTE &&
	[ "$(echo "$out" | tail -1)" -le 8 ]
r=$?; chk exec-sees-cell "exec reads the cell's bind, low pid, no host home, bind-ro still ro: $(echo $out)"
out=$("$JUNO" exec c1 -- sh -c 'grep -E "^(NoNewPrivs|CapEff):" /proc/self/status' | tr -s '\t\n' '  ')
echo "$out" | grep -q 'NoNewPrivs: 1' && echo "$out" | grep -q 'CapEff: 0000000000002000'
r=$?; chk exec-same-hardening "exec has no_new_privs and exactly the cell's kept cap: $out"
out=$("$JUNO" exec c1 -- sh -c 'unshare -U true 2>&1; echo rc=$?' 2>&1)
echo "$out" | grep -q 'rc=1'; r=$?; chk exec-same-seccomp "nested userns denied inside exec: $(echo $out)"
"$JUNO" exec c1 -- sh -c 'exit 5'; rc=$?
[ $rc -eq 5 ]; r=$?; chk exec-exit-status "exec exit status propagated ($rc)"
"$JUNO" exec nosuchcell -- true 2>"$T/e.err"; rc=$?
[ $rc -eq 125 ] && grep -q 'not running' "$T/e.err"; r=$?; chk exec-unknown-cell "exec on missing cell fails: rc=$rc $(head -c 80 "$T/e.err")"
"$JUNO" exec c1 -- /nonexistent 2>"$T/e.err"; rc=$?
[ $rc -eq 125 ]; r=$?; chk exec-bad-command "exec of a missing binary reports failure: rc=$rc $(head -c 100 "$T/e.err")"

out=$("$JUNO" logs c1); "$JUNO" logs nosuchcell >/dev/null 2>&1; rc=$?
[ "$out" = hello-log ] && [ $rc -ne 0 ]; r=$?; chk logs-output "payload output in log: '$out'; unknown cell rc=$rc"
mode=$(stat -c %a "$RT/c1/sock"); dmode=$(stat -c %a "$DT/c1")
[ "$mode" = 600 ]; r=$?; chk ctl-socket-mode "control socket mode $mode (data dir mode $dmode)"
"$JUNO" status c1 | grep -q '^state=running'; r=$?; chk status-running "status reports running"

s0=$(date +%s%N); "$JUNO" stop c1 --time 5; rc=$?; el=$(( ($(date +%s%N) - s0) / 1000000 ))
[ $rc -eq 0 ] && [ ! -e "$RT/c1" ] && ! psl | grep -q '^c1 ' && [ -s "$DT/c1/log" ] && [ $el -lt 4000 ]
r=$?; chk stop-clean "stop rc=$rc in ${el}ms, runtime state gone, log kept; status: $("$JUNO" status c1 | tr '\n' ' ')"
"$JUNO" stop c1 2>/dev/null; rc=$?
[ $rc -ne 0 ]; r=$?; chk stop-twice-fails "stopping a stopped cell fails (rc=$rc)"

named g1 -d -- sh -c 'trap "" TERM; while :; do sleep 1; done'
s0=$(date +%s%N); "$JUNO" stop g1 --time 1; rc=$?; el=$(( ($(date +%s%N) - s0) / 1000000 ))
[ $rc -eq 0 ] && [ $el -ge 900 ] && [ $el -lt 6000 ]; r=$?; chk stop-grace-then-kill "SIGTERM ignored, SIGKILL after grace: stop took ${el}ms"

named k1 -d -- sleep 60; "$JUNO" kill k1 KILL; rc=$?
waitfor '! psl | grep -q "^k1 "' 5; gone=$?
"$JUNO" status k1 | grep -q '^exit=137'; st=$?
[ $rc -eq 0 ] && [ $gone -eq 0 ] && [ $st -eq 0 ]; r=$?; chk kill-signal "kill KILL ends the cell (exit 137), no restart: rc=$rc gone=$gone"
"$JUNO" kill k1 TERM 2>/dev/null; rc=$?
[ $rc -ne 0 ]; r=$?; chk kill-unknown "kill of a finished cell fails (rc=$rc)"

# restart policies
: > "$T/data/count"
named r1 -d --bind "$T/data:/w" --restart on-failure --max-restarts 3 -- sh -c 'echo run >> /w/count; exit 1'
waitfor '! psl | grep -q "^r1 "' 15
n=$(wc -l < "$T/data/count"); "$JUNO" status r1 | grep -q '^restarts=3'; sr=$?
[ "$n" -eq 4 ] && [ $sr -eq 0 ]; r=$?; chk restart-on-failure "ran $n times (1 + 3 restarts), then gave up: $("$JUNO" status r1 | tr '\n' ' ')"
: > "$T/data/count"
named r2 -d --bind "$T/data:/w" --restart on-failure -- sh -c 'echo run >> /w/count; exit 0'
waitfor '! psl | grep -q "^r2 "' 5; n=$(wc -l < "$T/data/count")
[ "$n" -eq 1 ]; r=$?; chk restart-on-failure-clean-exit "exit 0 is not restarted ($n runs)"
: > "$T/data/count"
named r3 -d --bind "$T/data:/w" --restart no -- sh -c 'echo run >> /w/count; exit 1'
waitfor '! psl | grep -q "^r3 "' 5; sleep 0.5; n=$(wc -l < "$T/data/count")
[ "$n" -eq 1 ]; r=$?; chk restart-no "policy no never restarts ($n runs)"
: > "$T/data/count"
named r4 -d --bind "$T/data:/w" --restart always -- sh -c 'echo run >> /w/count; exit 0'
waitfor '[ $(wc -l < "$T/data/count") -ge 3 ]' 15; n=$(wc -l < "$T/data/count")
psl | grep -q '^r4 '; alive=$?
"$JUNO" stop r4 --time 2; rc=$?; sleep 0.8; n2=$(wc -l < "$T/data/count")
[ "$n" -ge 3 ] && [ $alive -eq 0 ] && [ $rc -eq 0 ] && [ "$n2" -le $((n+1)) ] && ! psl | grep -q '^r4 '
r=$?; chk restart-always-and-stop "restarted after exit 0 ($n runs), stop ended it (rc=$rc, $n2 runs after, listed: $(psl | grep -c '^r4 '))"

# stale state after the supervisor dies
named s1 -d -- sleep 60
sp=$("$JUNO" status s1 | sed -n 's/^supervisor=//p'); cp=$("$JUNO" status s1 | sed -n 's/^pid=//p')
kill -9 "$sp"; sleep 0.3
! psl | grep -q '^s1 '; r1=$?
waitfor '! kill -0 '"$cp"' 2>/dev/null' 3; r2=$?
[ $r1 -eq 0 ] && [ $r2 -eq 0 ] && [ ! -e "$RT/s1" ]; r=$?; chk stale-state-cleaned "supervisor $sp killed: ps drops it ($r1), cell process $cp died with it ($r2), runtime dir removed"
named s1 -d -- sleep 5; rc=$?; "$JUNO" stop s1 --time 1
[ $rc -eq 0 ]; r=$?; chk stale-name-reusable "a stale name can be started again (rc=$rc)"

# rm
named m1 -d -- sleep 60
"$JUNO" rm m1 2>/dev/null; rc1=$?
"$JUNO" rm -f m1; rc2=$?
[ $rc1 -ne 0 ] && [ $rc2 -eq 0 ] && [ ! -e "$DT/m1" ] && ! psl | grep -q '^m1 '
r=$?; chk rm-refuses-running "rm refused while running ($rc1), rm -f stopped and removed it ($rc2)"
"$JUNO" rm nosuch 2>/dev/null; rc=$?
[ $rc -ne 0 ]; r=$?; chk rm-unknown "rm of an unknown cell fails ($rc)"

# logs follow
named f1 -d -- sh -c 'for i in 1 2 3; do echo tick$i; sleep 0.3; done; sleep 60'
timeout 3 "$JUNO" logs f1 -f > "$T/follow.out" 2>&1
grep -q tick3 "$T/follow.out"; r=$?; chk logs-follow "follow streamed the live output: $(tr '\n' ' ' < "$T/follow.out")"
"$JUNO" stop f1 --time 1

# text spec
cat > "$T/ok.spec" <<EOF
# a comment
root = host-ro
bind-ro = $T/ro:/data
env = SPECVAR=fromspec
hostname = specbox
argv = sh -c 'echo \$SPECVAR \$(hostname); cat /data/f'
EOF
out=$("$JUNO" run --spec "$T/ok.spec")
[ "$out" = "$(printf 'fromspec specbox\ndata')" ]; r=$?; chk spec-file-run "spec file drives a run: $(echo $out)"
out=$("$JUNO" run --spec "$T/ok.spec" --hostname override -- sh -c 'hostname')
[ "$out" = override ]; r=$?; chk spec-cli-overrides "CLI options override the spec file: $out"
printf 'root = host-ro\nhostname = x\nbogus = 1\nargv = true\n' > "$T/bad.spec"
"$JUNO" run --spec "$T/bad.spec" 2>"$T/e.err"; rc=$?
grep -q "bad.spec:3: unknown key 'bogus'" "$T/e.err" && [ $rc -ne 0 ]; r=$?; chk spec-error-line "bad key reported with file and line: $(head -1 "$T/e.err")"
printf 'root = host-ro\nmem = lots\nargv = true\n' > "$T/bad2.spec"
"$JUNO" run --spec "$T/bad2.spec" 2>"$T/e.err"
grep -q "bad2.spec:2: bad value for 'mem'" "$T/e.err"; r=$?; chk spec-error-value "bad value reported with line: $(head -1 "$T/e.err")"
named sp1 --spec "$T/ok.spec" >/dev/null
"$JUNO" run --name sp2 --spec "$DT/sp1/spec" > "$T/sp2.out"
cmp -s "$T/sp2.out" <(printf 'fromspec specbox\ndata\n'); r=$?; chk spec-saved-by-supervisor "the saved spec of a named cell reruns identically"

# overlay with a supervisor-owned upper
if [ -d "$RF" ]; then
	named ov1 --root overlay --layer "$RF" -- sh -c 'echo persisted > /fromcell'
	[ "$(cat "$DT/ov1/upper/fromcell" 2>/dev/null)" = persisted ] && [ ! -e "$RF/fromcell" ]
	r=$?; chk overlay-default-upper "upper dir lives in the cell's data dir; lower untouched"
else skp overlay-default-upper "no busybox rootfs"; fi

# --- nesting ---------------------------------------------------------------
JB="--bind-ro $JUNO:/juno"
mkdir -p "$T/nro"; echo secret > "$T/nro/f"
out=$(J --nesting $JB -- /juno run -- sh -c 'echo inner-ok' 2>&1)
J $JB -- /juno run -- true 2>"$T/e.err"; rc=$?
[ "$out" = inner-ok ] && [ $rc -eq 125 ] && grep -q 'nested cells are not allowed here' "$T/e.err"
r=$?; chk nesting-allow-and-default-deny "with --nesting an inner cell starts ($out); without it start fails: $(head -c 80 "$T/e.err")"
out=$(J --nesting $JB -- /juno run -- sh -c 'grep -E "^(CapEff|CapBnd|NoNewPrivs):" /proc/self/status' | tr -s '\t\n' '  ')
echo "$out" | grep -q 'CapEff: 0000000000000000' && echo "$out" | grep -q 'CapBnd: 0000000000000000' && echo "$out" | grep -q 'NoNewPrivs: 1'
r=$?; chk nesting-inner-no-caps-nnp "inner cell: $out"
J --nesting $JB -- /juno run --bind "$HOME:/h" -- true 2>"$T/e.err"; rc=$?
[ $rc -eq 125 ] && grep -q 'mount bind' "$T/e.err" && [ -d "$HOME" ]
r=$?; chk nesting-hidden-path-stays-hidden "inner cannot bind $HOME the outer hid: rc=$rc $(head -c 90 "$T/e.err")"
out=$(J --nesting $JB --bind-ro "$T/nro:/data" -- /juno run --bind /data:/d -- sh -c 'cat /d/f; { echo x > /d/new; } 2>/dev/null && echo WROTE || echo DENIED' 2>&1)
[ "$out" = "$(printf 'secret\nDENIED')" ] && [ ! -e "$T/nro/new" ]
r=$?; chk nesting-ro-bind-stays-ro "inner rw bind of an outer ro bind is still ro: $(echo $out)"
out=$(J --nesting $JB --bind-ro "$HELPER:/helper" --nofile 20 -- /juno run --bind-ro /helper:/helper -- /helper openmany)
ctl=$(J --nesting $JB --bind-ro "$HELPER:/helper" -- /juno run --bind-ro /helper:/helper -- /helper openmany)
[ "${out:-99}" -ge 3 ] && [ "${out:-99}" -le 20 ] && [ "${ctl:-0}" -gt 100 ]
r=$?; chk nesting-outer-limit-bounds-inner "outer --nofile 20: inner opened $out fds; unlimited outer: $ctl"
if ! echo "$probe" | grep -q '^cgroup v2 delegation: usable'; then
	skp nesting-outer-pids-bounds-inner "needs cgroup delegation; covered by make test-cgroup"
fi

# --- networking --------------------------------------------------------
HP=$(freebase 64); P1=$((HP + 1)); P2=$((HP + 2))
named na -d --net shared:n1 $H -- /helper listen $HP
waitfor "J --net shared:n1 $H -- /helper connect 127.0.0.1 $HP >/dev/null 2>&1" 5
out=$(J --net shared:n1 $H -- /helper connect 127.0.0.1 $HP 2>&1)
outn=$(J --net none $H -- /helper connect 127.0.0.1 $HP 2>&1)
outh=$(timeout 3 "$HELPER" connect 127.0.0.1 $HP 2>&1)
outo=$(J --net shared:n2 $H -- /helper connect 127.0.0.1 $HP 2>&1)
[ "$out" = hello ] && [ "$outn" = "connect: Connection refused" ] && [ "$outh" = "connect: Connection refused" ] &&
	[ "$outo" = "connect: Connection refused" ]
r=$?; chk net-shared-reachable "same shared net: '$out'; --net none: '$outn'; host: '$outh'; other shared net: '$outo'"
J --net shared:n1 -- busybox ifconfig lo 2>&1 | grep -q UP; r=$?; chk net-shared-lo-up "loopback is up in a shared network"
"$JUNO" net ls | grep -q '^n1 '; r=$?; chk net-ls "net ls lists the holder: $("$JUNO" net ls | tail -n +2 | tr '\n' ';')"
"$JUNO" exec na -- /helper connect 127.0.0.1 $HP | grep -q hello; r=$?; chk net-shared-exec "exec joins the shared net"
"$JUNO" stop na --time 1
waitfor '! "$JUNO" net ls | grep -q "^n1 "' 8; r=$?; chk net-holder-exits "holder exits after the last cell left"
named nb -d --net shared:n3 -- sleep 30; "$JUNO" net rm n3; rc=$?
waitfor '! "$JUNO" net ls | grep -q "^n3 "' 3; r2=$?
[ $rc -eq 0 ] && [ $r2 -eq 0 ]; r=$?; chk net-rm "net rm removes a holder (rc=$rc)"; "$JUNO" stop nb --time 1

head -c 3000000 /dev/urandom > "$T/big.in"; head -c 1 "$T/big.in" > "$T/one.in"
named pe -d --publish $P1:9000 $H -- /helper echo 9000
waitfor "timeout 3 \"$HELPER\" xfer 127.0.0.1 $P1 \"$T/one.in\" \"$T/one.out\" >/dev/null 2>&1" 4
out=$("$HELPER" xfer 127.0.0.1 $P1 "$T/big.in" "$T/big.out")
cmp -s "$T/big.in" "$T/big.out"; r=$?; chk publish-roundtrip-3MB "$out; data identical both ways"
named pr -d --publish $P2:9999 -- sleep 30
out=$("$HELPER" xfer 127.0.0.1 $P2 "$T/one.in" "$T/one.out" 2>&1); rc=$?
[ $rc -ne 0 ] || [ ! -s "$T/one.out" ]; r=$?; chk publish-refused "nothing listens in the cell: client got '$out' and no data"
out=$("$HELPER" xfer 127.0.0.1 $P1 "$T/one.in" "$T/one.out"); cmp -s "$T/one.in" "$T/one.out"
r=$?; chk publish-survives-refusal "the other published port still works after a refused connection"
"$JUNO" stop pe --time 1; "$JUNO" stop pr --time 1
out=$(timeout 3 "$HELPER" connect 127.0.0.1 $P1 2>&1); out2=$(timeout 3 "$HELPER" connect 127.0.0.1 $P2 2>&1)
[ "$out" = "connect: Connection refused" ] && [ "$out2" = "connect: Connection refused" ]
r=$?; chk publish-port-closed-after-stop "ports closed once the cells stopped: '$out' '$out2'"
named pd -d --publish 127.0.0.1:$P1:9000 $H -- /helper echo 9000
named pd2 -d --publish $P1:9000 -- sleep 5 2>"$T/e.err"; rc=$?
[ $rc -eq 125 ] && grep -q 'publish: bind' "$T/e.err"; r=$?; chk publish-port-in-use "second cell on a taken port fails: $(head -c 100 "$T/e.err")"
"$JUNO" stop pd --time 1
"$JUNO" run --net host --publish $P1:9000 -- true 2>"$T/e.err"; rc=$?
[ $rc -eq 125 ] && grep -q 'network namespace' "$T/e.err"; r=$?; chk publish-needs-netns "publish with --net host refused: $(head -c 100 "$T/e.err")"
"$JUNO" run --publish $P2:9000 $H -- /helper echo 9000 & jp=$!
waitfor "timeout 3 \"$HELPER\" xfer 127.0.0.1 $P2 \"$T/one.in\" \"$T/one.out\" >/dev/null 2>&1" 4
cmp -s "$T/one.in" "$T/one.out"; r=$?; chk publish-foreground-cell "unnamed foreground cell publishes too"
kill $jp; wait $jp 2>/dev/null
waitfor 'timeout 3 "$HELPER" connect 127.0.0.1 $P2 2>&1 | grep -q refused' 3; r=$?; chk publish-foreground-closed "port closed after the foreground cell ended"

# --- hardening round: host-ro /etc, shared-net user namespaces, compat32, tty ----------
out=$(J -- sh -c 'for p in /etc/ssh /etc/shadow /etc/sudoers /etc/NetworkManager /etc/fstab /etc/os-release /opt /boot /var /root /srv /sys; do test -e $p && echo "HAS$p"; done; id -u; id -un')
leaked=$(echo "$out" | grep '^HAS' | tr '\n' ' ')
[ -e /etc/shadow ] && [ -e /etc/ssh ]; r1=$?
[ -z "$leaked" ] && echo "$out" | tail -2 | tr '\n' ' ' | grep -q '^0 root $'
r=$((r1 + $?)); chk host-ro-etc-narrow "none of ssh shadow sudoers NetworkManager fstab os-release opt var root visible (leaked: '${leaked}'); id shows root"
out=$(J -- sh -c 'ls /etc | tr "\n" " "')
[ "$out" = "alternatives ca-certificates group hostname hosts ld.so.cache ld.so.conf ld.so.conf.d localtime nsswitch.conf passwd ssl " ]
r=$?; chk host-ro-etc-contents "/etc holds exactly: $out"
out=$(J --hostname etcbox -- sh -c 'cat /etc/hostname; grep -c etcbox /etc/hosts; getent passwd root | cut -d: -f1,3; ls /usr/bin/ls >/dev/null && echo dyn-ok')
[ "$out" = "$(printf 'etcbox\n1\nroot:0\ndyn-ok')" ]; r=$?; chk host-ro-etc-generated "generated hostname, hosts, passwd work through nsswitch: $(echo $out)"
out=$(J --bind-ro /etc/os-release:/etc/os-release -- head -1 /etc/os-release)
[ "$out" = "$(head -1 /etc/os-release)" ]; r=$?; chk host-ro-bind-ro-exposes "--bind-ro brings back one host file: $out"
J -- test -e /etc/resolv.conf; a=$?
J --net host -- test -e /etc/resolv.conf; b=$?
if [ -e /etc/resolv.conf ]; then [ $a -ne 0 ] && [ $b -eq 0 ]; else [ $a -ne 0 ]; fi
r=$?; chk host-ro-resolv-conf-only-with-host-net "resolv.conf absent with --net none ($a), present with --net host ($b)"
out=$(J -- sh -c 'readlink /bin; readlink /lib; test -e /opt && echo OPT')
hl=$(readlink /bin; readlink /lib)
[ "$out" = "$hl" ]; r=$?; chk host-ro-usr-merge "bin and lib keep the host's usr-merge symlinks, nothing else (opt absent): $(echo $out)"

# shared net: separate user namespaces, no control over the interface
named su1 -d --net shared:usn $H -- /helper listen $((HP + 10))
named su2 -d --net shared:usn $H -- sleep 60
waitfor "J --net shared:usn $H -- /helper connect 127.0.0.1 $((HP + 10)) >/dev/null 2>&1" 5
u1=$("$JUNO" exec su1 -- readlink /proc/self/ns/user); u2=$("$JUNO" exec su2 -- readlink /proc/self/ns/user)
uh=$(readlink /proc/self/ns/user)
[ -n "$u1" ] && [ "$u1" != "$u2" ] && [ "$u1" != "$uh" ] && [ "$u2" != "$uh" ]
r=$?; chk net-shared-distinct-userns "cells on one shared net: $u1 vs $u2 (host $uh)"
out=$("$JUNO" exec su2 -- /helper connect 127.0.0.1 $((HP + 10)))
[ "$out" = hello ]; r=$?; chk net-shared-two-cells-reach "su2 reaches su1's listener on 127.0.0.1: $out"
out=$("$JUNO" exec su2 -- busybox ifconfig lo down 2>&1); rc=$?
up=$("$JUNO" exec su1 -- busybox ifconfig lo | grep -c UP)
[ $rc -ne 0 ] && [ "$up" -ge 1 ] && echo "$out" | grep -q 'not permitted'
r=$?; chk net-shared-cannot-change-interface "ifconfig lo down fails ($out), lo still UP for the other cell"
out=$("$JUNO" exec su2 -- grep -E '^(CapEff|NoNewPrivs):' /proc/self/status | tr -s '\t\n' '  ')
echo "$out" | grep -q 'CapEff: 0000000000000000'; r=$?; chk net-shared-no-caps "cell on shared net holds no capabilities: $out"
"$JUNO" stop su1 --time 1; "$JUNO" stop su2 --time 1

# compat32
if [ -x "$ROOT/build/juno_helper32" ] && J --compat32 --bind-ro "$ROOT/build/juno_helper32:/h32" -- /h32 p >/dev/null 2>&1; then
	H32="--bind-ro $ROOT/build/juno_helper32:/h32"
	out=$(J $H32 --compat32 -- /h32 b); out2=$(J $H32 --compat32 --seccomp off -- /h32 b)
	J $H32 -- /h32 b >/dev/null 2>&1; rc=$?
	[ "$out" = "bpf EPERM" ] && [ "$out2" = "bpf EINVAL" ] && [ $rc -eq 159 ]
	r=$?; chk compat32-i386-denylist "i386 bpf: filtered '$out', unfiltered '$out2'; native-only filter kills an i386 program (rc=$rc, SIGSYS)"
	out=$(J $H32 --compat32 -- /h32 u); out2=$(J $H32 --compat32 --seccomp off -- /h32 u)
	[ "$out" = "unshare EPERM" ] && [ "$out2" = "unshare ok" ]; r=$?; chk compat32-i386-nested-userns "i386 unshare(NEWUSER): '$out'; seccomp off: '$out2'"
	out=$(J $H32 --compat32 --keep-cap sys_admin -- /h32 m); out2=$(J $H32 --compat32 --keep-cap sys_admin --seccomp strict -- /h32 m)
	[ "$out" != "mount EPERM" ] && [ "$out2" = "mount EPERM" ]; r=$?; chk compat32-i386-strict-mount "i386 mount: default '$out', strict '$out2'"
	printf 'root = host-ro\ncompat32 = yes\nargv = /h32 b\nbind-ro = %s/build/juno_helper32:/h32\n' "$ROOT" > "$T/c32.spec"
	out=$("$JUNO" run --spec "$T/c32.spec"); [ "$out" = "bpf EPERM" ]; r=$?; chk compat32-spec-key "compat32 = yes in a spec file: $out"
else
	skp compat32-i386-denylist "no 32-bit test program: gcc -m32 -nostdlib failed or the kernel has no IA32 emulation (the filter is still checked by api-seccomp-filter-interpreted)"
fi

# terminals
if command -v script >/dev/null; then
	out=$(script -qc "stty rows 31 cols 97; $JUNO run -t -- sh -c 'tty; stty size'" /dev/null < /dev/null | tr -d '\r')
	echo "$out" | grep -q '/dev/pts/[0-9]' && echo "$out" | grep -q '31 97$'
	r=$?; chk tty-run "run -t: tty is a cell pts, stty size follows the outer terminal: $(echo $out)"
	out=$(script -qc "stty rows 31 cols 97; $JUNO run -- sh -c 'tty 2>&1'" /dev/null < /dev/null | tr -d '\r')
	echo "$out" | grep -q 'not a tty' && ! echo "$out" | grep -q '/dev/pts'
	r=$?; chk tty-run-without-t "without -t the cell has no terminal of its own (inherited fds are not a cell pts): $(echo $out)"
	named tt -d -- sleep 60
	out=$(script -qc "stty rows 20 cols 70; $JUNO exec -t tt -- sh -c 'tty; stty size; exit 3'; echo rc=\$?" /dev/null < /dev/null | tr -d '\r')
	echo "$out" | grep -q '/dev/pts/[0-9]' && echo "$out" | grep -q '20 70$' && echo "$out" | grep -q 'rc=3$'
	r=$?; chk tty-exec "exec -t: pts in the cell, size 20x70, exit status 3: $(echo $out)"
	out=$(script -qc "(sleep 1; stty -F /dev/tty rows 40 cols 120) & $JUNO run -t -- sh -c 'sleep 2; stty size'; wait" /dev/null < /dev/null | tr -d '\r')
	echo "$out" | grep -q '40 120$'; r=$?; chk tty-sigwinch "window size change forwarded to the pty: $(echo $out)"
	script -qc "stty -g > $T/stty1; $JUNO run -t -- sh -c 'echo x' > /dev/null; stty -g > $T/stty2" /dev/null < /dev/null > /dev/null
	[ -s "$T/stty1" ] && cmp -s "$T/stty1" "$T/stty2"; r=$?; chk tty-restores-terminal "terminal mode identical before and after run -t"
	"$JUNO" stop tt --time 1
else
	skp tty-run "script(1) is not installed"
fi

# --- supervisor gaps --------------------------------------------------------
out=$("$JUNO" run --name fg -- sh -c 'echo fgout; echo fgerr >&2' 2>"$T/fg.err")
grep -q fgerr "$T/fg.err" && [ "$out" = fgout ] && [ "$(sort "$DT/fg/log" | tr '\n' ' ')" = "fgerr fgout " ] && ! psl | grep -q '^fg '
r=$?; chk foreground-named-tee "stdout/stderr reach the terminal and the log; state removed afterwards"
"$JUNO" run --name fg -- true; rc=$?; [ $rc -eq 0 ]; r=$?; chk foreground-named-reusable "the name is reusable after a foreground run (rc=$rc)"
"$JUNO" run --name fg -- sh -c 'exit 9'; rc=$?; [ $rc -eq 9 ]; r=$?; chk foreground-named-exit-code "foreground named run returns the payload status ($rc)"

P3=$((HP + 20)); P4=$((HP + 21)); P5=$((HP + 22))
named rp -d --restart always --publish $P3:9000 $H -- /helper echo 9000
waitfor "timeout 3 \"$HELPER\" xfer 127.0.0.1 $P3 \"$T/one.in\" \"$T/one.out\" >/dev/null 2>&1" 4
"$JUNO" kill rp KILL
waitfor '"$JUNO" status rp | grep -q "^restarts=[1-9]"' 8
rm -f "$T/one.out"
waitfor "timeout 3 \"$HELPER\" xfer 127.0.0.1 $P3 \"$T/one.in\" \"$T/one.out\" >/dev/null 2>&1" 8
cmp -s "$T/one.in" "$T/one.out"; r=$?; chk restart-with-publish "published port works again after a restart: $("$JUNO" status rp | tr '\n' ' ')"
"$JUNO" stop rp --time 1
named rs -d --restart always --net shared:rsn $H -- /helper listen $P4
waitfor "J --net shared:rsn $H -- /helper connect 127.0.0.1 $P4 >/dev/null 2>&1" 5
"$JUNO" kill rs KILL
waitfor '"$JUNO" status rs | grep -q "^restarts=[1-9]"' 8
waitfor "J --net shared:rsn $H -- /helper connect 127.0.0.1 $P4 >/dev/null 2>&1" 8
out=$(J --net shared:rsn $H -- /helper connect 127.0.0.1 $P4)
[ "$out" = hello ]; r=$?; chk restart-with-shared-net "listener reachable on the shared net again after a restart: $out ($("$JUNO" status rs | grep restarts))"
"$JUNO" stop rs --time 1
named nn -d --nesting $JB -- sleep 60
out=$("$JUNO" exec nn -- /juno run -- echo nested-in-named 2>&1)
named nm -d $JB -- sleep 60
out2=$("$JUNO" exec nm -- /juno run -- echo should-not 2>&1)
[ "$out" = nested-in-named ] && echo "$out2" | grep -q 'nested cells are not allowed here'
r=$?; chk nesting-in-named-cell "exec into a nesting named cell can start an inner cell ($out); without nesting: $(echo $out2 | head -c 80)"
"$JUNO" stop nn --time 1; "$JUNO" stop nm --time 1
named lf2 -d -- sh -c 'echo la; sleep 1; echo lb'
s0=$(date +%s); timeout 8 "$JUNO" logs lf2 -f > "$T/lf2.out" 2>&1; rc=$?; el=$(( $(date +%s) - s0 ))
[ $rc -eq 0 ] && [ $el -lt 6 ] && [ "$(tr '\n' ' ' < "$T/lf2.out")" = "la lb " ]
r=$?; chk logs-follow-ends-with-cell "logs -f returned rc=$rc after ${el}s with: $(tr '\n' ' ' < "$T/lf2.out")"
LONGD=/tmp/$(printf 'long%.0s' {1..30})
mkdir -p "$LONGD"
JUNO_RUNTIME_DIR=$LONGD "$JUNO" run --name lp -d -- true 2>"$T/e.err"; rc=$?
[ $rc -eq 125 ] && grep -q 'path too long' "$T/e.err" && grep -q 'limit is 107' "$T/e.err"
r=$?; chk socket-path-too-long "clear error naming the limit: $(head -c 140 "$T/e.err")"
rm -rf "$LONGD"

# no fd leaks in the long-lived processes
named fl -d --publish $P5:9000 $H -- /helper echo 9000
waitfor "timeout 3 \"$HELPER\" xfer 127.0.0.1 $P5 \"$T/one.in\" \"$T/one.out\" >/dev/null 2>&1" 4
sp=$("$JUNO" status fl | sed -n 's/^supervisor=//p'); cp=$("$JUNO" status fl | sed -n 's/^pid=//p')
fp=; for k in $(pgrep -P "$sp"); do [ "$k" != "$cp" ] && [ -z "$(cat /proc/$k/stat | grep Z)" ] && fp=$k; done
cnt() { ls /proc/$1/fd 2>/dev/null | wc -l; }
sb=$(cnt $sp); fb=$(cnt $fp)
for i in $(seq 200); do timeout 3 "$HELPER" xfer 127.0.0.1 $P5 "$T/one.in" "$T/one.out" >/dev/null; done
for i in $(seq 50); do "$JUNO" exec fl -- true; done
sleep 0.5
sa=$(cnt $sp); fa=$(cnt $fp)
[ -n "$fp" ] && [ "$sb" -gt 0 ] && [ "$sb" = "$sa" ] && [ "$fb" = "$fa" ]
r=$?; chk no-fd-leaks "after 200 published connections and 50 execs: supervisor $sp fds $sb -> $sa, forwarder ${fp:-none} fds $fb -> $fa"
"$JUNO" stop fl --time 1

# --- outbound networking: net = nat -------------------------------------------
pylisten() { python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('$1', $2)); s.listen(8)
while True:
    c,_=s.accept(); c.close()" & }
LAN=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')
if ! echo "$probe" | grep -q 'pasta available'; then
	skp nat-outbound "pasta is not installed: $(echo "$probe" | grep outbound)"
elif [ -z "$LAN" ]; then
	skp nat-outbound "the host has no default route, pasta cannot attach"
else
	NP=$((HP + 40)); NQ=$((HP + 41))
	pylisten 0.0.0.0 $NP; L1=$!; pylisten 127.0.0.1 $NQ; L2=$!
	waitfor "'$HELPER' tcp 127.0.0.1 $NQ | grep -q ok" 5
	a=$(J --net nat:lan $H -- /helper tcp "$LAN" $NP); b=$(J --net none $H -- /helper tcp "$LAN" $NP)
	[ "$a" = "tcp ok" ] && echo "$b" | grep -q FAIL
	r=$?; chk nat-outbound-tcp "host listener at $LAN:$NP: nat:lan cell [$a]; none cell [$b]"
	c1=$(J --net nat $H -- /helper gwconnect $NQ); c2=$(J --net nat $H -- /helper tcp 127.0.0.1 $NQ); c3=$(J --net nat:host $H -- /helper gwconnect $NQ)
	echo "$c1" | grep -q FAIL && echo "$c2" | grep -q FAIL && [ "$c3" = "tcp ok" ]
	r=$?; chk nat-host-loopback-blocked "host 127.0.0.1:$NQ: through the gateway from nat [$c1]; own loopback [$c2]; nat:host gateway [$c3]"
	out=$(J --net nat -- cat /etc/resolv.conf); out2=$(J --net none -- sh -c 'test -e /etc/resolv.conf && echo present')
	[ "$out" = "nameserver 10.0.2.3" ] && [ -z "$out2" ]; r=$?; chk nat-resolv-conf "nat cell gets pasta's DNS forwarder: '$out'; none cell has none ('$out2')"
	if [ -d "$RF" ]; then
		out=$(J --root "dir:$RF" --net nat -- cat /etc/resolv.conf)
		[ "$out" = "nameserver 10.0.2.3" ] && [ ! -s "$RF/etc/resolv.conf" ]; r=$?; chk nat-resolv-conf-dir-root "dir root without one gets it bound in ('$out'); only an empty mountpoint file stays in the rootfs"
	fi
	out=$(J --net nat -- busybox ifconfig 2>&1 | grep -c 'inet addr:10.0.2.15')
	[ "$out" = 1 ]; r=$?; chk nat-address "cell has 10.0.2.15 on eth0 (IPv4 only: $(J --net nat -- sh -c 'ls /proc/sys/net/ipv6 >/dev/null 2>&1; busybox ifconfig eth0 | grep -c inet6'))"
	"$JUNO" run --net nat $H -- sleep 20 & JP=$!
	waitfor '[ "$(count_mine pasta)" -ge 1 ]' 5; seen=$(count_mine pasta)
	kill $JP; wait $JP 2>/dev/null
	waitfor '[ "$(count_mine pasta)" = 0 ]' 5; gone=$?
	[ "$seen" -ge 1 ] && [ $gone -eq 0 ]; r=$?; chk nat-pasta-lifetime "pasta processes while the cell ran: $seen; none after it ended"
	named nt -d --net nat:lan $H -- sleep 60
	waitfor 'psl | grep -q "^nt .*running"' 5
	o1=$("$JUNO" exec nt -- /helper tcp "$LAN" $NP)
	"$JUNO" kill nt KILL; "$JUNO" stop nt --time 1 >/dev/null 2>&1
	named nt2 -d --net nat:lan --restart always $H -- /helper listen $((NP + 5))
	waitfor 'psl | grep -q "^nt2 .*running"' 5; sleep 0.5
	p1=$(mine | grep pasta | cut -d' ' -f1 | tr '\n' ' ')
	"$JUNO" kill nt2 KILL; waitfor '"$JUNO" status nt2 | grep -q "^restarts=[1-9]"' 8; sleep 0.5
	o2=$("$JUNO" exec nt2 -- /helper tcp "$LAN" $NP); p2=$(count_mine pasta)
	"$JUNO" stop nt2 --time 1
	[ "$o1" = "tcp ok" ] && [ "$o2" = "tcp ok" ] && [ "$p2" = 1 ]
	r=$?; chk nat-named-exec-restart "exec in a named nat cell [$o1]; after a restart the cell has outbound again [$o2] with exactly $p2 pasta (was $p1)"
	named np -d --net nat --publish $((NP + 6)):9000 $H -- /helper echo 9000
	waitfor "timeout 3 '$HELPER' xfer 127.0.0.1 $((NP + 6)) '$T/one.in' '$T/one.out' >/dev/null 2>&1" 5
	cmp -s "$T/one.in" "$T/one.out"; r=$?; chk nat-with-publish "published port works with a nat cell"
	"$JUNO" stop np --time 1
	kill $L1 $L2 2>/dev/null
	env PATH=/nonexistent "$JUNO" run --net nat -- true 2>"$T/e.err"; rc=$?
	[ $rc -eq 125 ] && grep -q 'needs pasta' "$T/e.err"; r=$?; chk nat-missing-pasta "without pasta: $(head -c 120 "$T/e.err")"
	if "$HELPER" tcp 1.1.1.1 443 | grep -q ok; then
		o=$(J --net nat $H -- /helper tcp 1.1.1.1 443)
		d=$(J --net nat -- busybox nslookup example.com 2>&1 | grep -c '^Address: [0-9]')
		[ "$o" = "tcp ok" ] && [ "$d" -ge 1 ]; r=$?; chk nat-internet "TCP connect to 1.1.1.1:443 from a nat cell [$o]; DNS lookup of example.com answered ($d addresses)"
	else
		skp nat-internet "the host cannot reach 1.1.1.1:443 (offline)"
	fi
fi

# --- multi-id maps and --user ---------------------------------------------------
if ! echo "$probe" | grep -q 'idmap = full): available'; then
	skp idmap-full "$(echo "$probe" | grep 'multi-id')"
else
	SUB=$(awk -F: -v u="$(id -un)" '$1==u{print $2; exit}' /etc/subuid)
	out=$(J --idmap full -- cat /proc/self/uid_map | tr -s ' ' | tr '\n' ';'); out1=$(J -- cat /proc/self/uid_map | tr -s ' ' | tr '\n' ';')
	[ "$out" = " 0 $(id -u) 1; 1 $SUB 65536;" ] && [ "$out1" = " 0 $(id -u) 1;" ]
	r=$?; chk idmap-full-maps "full: $out; default single: $out1"
	mkdir -p "$T/u"; chmod 777 "$T/u"; echo secret > "$T/u/rootonly"; chmod 600 "$T/u/rootonly"
	cp "$HELPER" "$T/u/suid"; chmod 4755 "$T/u/suid"
	UA="--idmap full --user 100:100 --bind $T/u:/u"
	out=$(J $UA -- sh -c 'id; grep -E "^(CapEff|CapPrm|CapBnd|NoNewPrivs):" /proc/self/status | tr -s "\t\n" "  "; echo; tail -1 /etc/passwd')
	echo "$out" | grep -q '^uid=100(user) gid=100(user) groups=100(user)$' && echo "$out" | grep -q 'CapPrm: 0000000000000000 CapEff: 0000000000000000 CapBnd: 0000000000000000' && echo "$out" | grep -q 'NoNewPrivs: 1' && echo "$out" | grep -q '^user:x:100:100:'
	r=$?; chk user-id-and-caps "$(echo "$out" | tr '\n' ';')"
	out=$(J $UA -- sh -c 'cat /u/rootonly 2>&1; /u/suid caps; touch /u/made; mkdir /u/d; touch /u/d/x; chmod 700 /u/d')
	echo "$out" | grep -q 'Permission denied' && echo "$out" | grep -q 'Uid:	100	100	100	100 | CapEff:	0000000000000000'
	r=$?; chk user-cannot-read-root-file-or-gain-via-setuid "root-only file denied; the setuid-root copy still runs as uid 100 without caps: $(echo "$out" | tr '\n' ';' | head -c 200)"
	o=$(stat -c %u "$T/u/made"); od=$(stat -c %u "$T/u/d")
	[ "$o" = "$((SUB + 99))" ] && [ "$od" = "$((SUB + 99))" ] && ! rm -rf "$T/u/d" 2>/dev/null
	r=$?; chk user-files-owned-by-subuid "file created as cell uid 100 is owned by $o on the host (subuid $SUB + 99); plain rm of its 0700 dir fails"
	"$JUNO" rmtree "$T/u/d"; [ ! -e "$T/u/d" ]; r=$?; chk rmtree-removes-subuid-files "juno rmtree removes it through a mapped user namespace"
	out=$(J $UA -- sh -c 'su -c id root 2>&1; id -u')
	echo "$out" | tail -1 | grep -q '^100$' && ! echo "$out" | grep -q 'uid=0'; r=$?; chk user-cannot-su "su gives nothing: $(echo "$out" | tr '\n' ';' | head -c 120)"
	J --user 100 -- true 2>"$T/e.err"; rc=$?
	[ $rc -eq 125 ] && grep -q 'needs idmap = full' "$T/e.err"; r=$?; chk user-needs-idmap-full "--user 100 with the single map: $(head -c 100 "$T/e.err")"
	a=$(J $H --idmap full --keep-cap setuid --keep-cap setgid -- /helper dropuid 100); b=$(J $H --keep-cap setuid --keep-cap setgid -- /helper dropuid 100)
	[ "$a" = "dropped uid=100 euid=100" ] && echo "$b" | grep -q FAIL
	r=$?; chk daemon-drop-privileges "root-then-drop program: full map '$a'; single map '$b'"
	named xu -d --idmap full $H -- sleep 60
	waitfor 'psl | grep -q "^xu .*running"' 5
	a=$("$JUNO" exec --user 100 xu -- id -u); b=$("$JUNO" exec --user 0 xu -- id -u); c=$("$JUNO" exec --user 100:100 xu -- /helper caps)
	[ "$a" = 100 ] && [ "$b" = 0 ] && echo "$c" | grep -q 'CapEff:	0000000000000000'; r=$?; chk exec-user "exec --user 100 runs as 100 ($a), --user 0 as root ($b), no caps: $(echo $c | head -c 80)"
	"$JUNO" stop xu --time 1
	if [ -d "$RF" ]; then
		mkdir -p "$RF/data"; chmod 777 "$RF/data"
		named ov2 -d --root overlay --layer "$RF" --idmap full --user 100:100 -- sh -c 'mkdir /data/d; echo hi > /data/d/f; chmod 700 /data/d; sleep 60'
		waitfor "[ -e '$JUNO_DATA_DIR/ov2/upper/data/d' ]" 8
		own=$(stat -c %u "$JUNO_DATA_DIR/ov2/upper/data/d"); "$JUNO" stop ov2 --time 1 >/dev/null
		rm -rf "$JUNO_DATA_DIR/ov2" 2>/dev/null; still=$([ -e "$JUNO_DATA_DIR/ov2/upper/data/d" ] && echo yes || echo no)
		"$JUNO" rm ov2; rc=$?
		[ "$own" = "$((SUB + 99))" ] && [ "$still" = yes ] && [ $rc -eq 0 ] && [ ! -e "$JUNO_DATA_DIR/ov2" ]
		r=$?; chk rm-removes-subuid-overlay-upper "upper dir owned by $own resists plain rm ($still), juno rm removes it (rc=$rc)"
	fi
fi

# --- egress policy of nat cells ------------------------------------------------------
HADDR=$(ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -E '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)' | head -4)
if ! echo "$probe" | grep -q 'pasta available'; then
	skp nat-egress "pasta is not installed"
elif [ -z "$HADDR" ] || [ -z "$LAN" ]; then
	skp nat-egress "the host has no private IPv4 address or no default route to test against"
else
	EP=$((HP + 50))
	pylisten 0.0.0.0 $EP; L3=$!
	waitfor "'$HELPER' tcp 127.0.0.1 $EP | grep -q ok" 5
	A1=$(echo "$HADDR" | sed -n 1p); A2=$(echo "$HADDR" | sed -n 2p)
	res_nat=""; res_lan=""; okn=0
	for a in $HADDR; do
		s=$(date +%s%N); o=$(J --net nat $H -- /helper tcp "$a" $EP); ms=$(( ($(date +%s%N) - s) / 1000000 ))
		p=$(J --net nat:lan $H -- /helper tcp "$a" $EP)
		res_nat="$res_nat $a:[${o#tcp }]${ms}ms"; res_lan="$res_lan $a:[${p#tcp }]"
		{ [ "$o" = "tcp FAIL No route to host" ] && [ $ms -lt 3000 ] && [ "$p" = "tcp ok" ]; } || okn=1
	done
	r=$okn; chk nat-egress-private-blocked "host listener on each private host address: nat fails fast:$res_nat; nat:lan reaches:$res_lan"
	g=$(J --net nat $H -- /helper tcp 10.0.2.2 80); d=$(J --net nat $H -- /helper tcp 10.0.2.3 53)
	m=$(J --net nat $H -- /helper tcp 224.0.0.1 80); l=$(J --net nat:lan $H -- /helper tcp 169.254.169.254 80)
	echo "$g" | grep -q 'No route' && [ "$d" = "tcp ok" ] && echo "$m" | grep -q 'No route' && echo "$l" | grep -q 'No route'
	r=$?; chk nat-egress-special-ranges "gateway 10.0.2.2 [$g]; DNS forwarder 10.0.2.3:53 [$d]; multicast [$m]; link-local metadata address even with nat:lan [$l]"
	c=$(J --net nat:host $H -- /helper tcp "$A1" $EP)
	[ "$c" = "tcp ok" ]; r=$?; chk nat-host-implies-lan "nat:host reaches the private host address $A1 [$c]"
	o1=$(J --net nat $H --egress-allow "$A1/32" -- /helper tcp "$A1" $EP)
	if [ -n "$A2" ]; then o2=$(J --net nat $H --egress-allow "$A1/32" -- /helper tcp "$A2" $EP); else o2="tcp FAIL No route to host (single address host)"; fi
	o3=$(J --net nat $H --egress-allow "$A1/32" -- /helper tcp 10.77.77.77 $EP)
	[ "$o1" = "tcp ok" ] && echo "$o2" | grep -q 'No route' && echo "$o3" | grep -q 'No route'
	r=$?; chk nat-egress-allow-one "--egress-allow $A1/32 opens exactly that address [$o1]; ${A2:-another} stays blocked [$o2]; 10.77.77.77 blocked [$o3]"
	o=$(J --net nat:lan $H --egress-deny "$A1/32" -- /helper tcp "$A1" $EP)
	echo "$o" | grep -q 'No route'; r=$?; chk nat-egress-deny-one "--egress-deny $A1/32 closes one address inside nat:lan [$o]"
	o=$(J --net nat $H -- sh -c 'busybox ip route del 10.0.0.0/8 2>&1; busybox ip route add default via 10.0.2.2 2>&1; busybox ip route flush all 2>&1; /helper caps; /helper tcp "'"$A1"'" '$EP)
	echo "$o" | grep -qi 'not permitted' && echo "$o" | grep -q 'CapEff:	0000000000000000' && echo "$o" | tail -1 | grep -q 'No route'
	r=$?; chk nat-egress-payload-cannot-change "route changes by the payload are refused and the address is still blocked: $(echo "$o" | tr '\n' ';' | head -c 220)"
	J --net nat --keep-cap net_admin -- true 2>"$T/e.err"; rc=$?
	[ $rc -eq 125 ] && grep -q 'cannot be combined with net = nat' "$T/e.err"; r=$?; chk nat-egress-refuses-net-admin "keep-cap net_admin with nat: $(head -c 140 "$T/e.err")"
	named en -d --net nat --egress-allow "$A1/32" $H -- sleep 60
	waitfor 'psl | grep -q "^en .*running"' 5
	o=$("$JUNO" exec en -- /helper tcp "$A1" $EP); o2=$("$JUNO" exec en -- busybox ip route del 10.0.0.0/8 2>&1)
	"$JUNO" stop en --time 1
	[ "$o" = "tcp ok" ] && echo "$o2" | grep -qi 'not permitted'; r=$?; chk nat-egress-exec-same-policy "exec into the cell keeps the policy (allowed [$o]; route removal: $(echo $o2 | head -c 60))"
	if "$HELPER" tcp 1.1.1.1 443 | grep -q ok; then
		a=$(J --net nat $H -- /helper tcp 1.1.1.1 443); s=$(date +%s%N); b=$(J --net nat $H --egress-deny 1.1.1.1/32 -- /helper tcp 1.1.1.1 443); ms=$(( ($(date +%s%N) - s) / 1000000 ))
		[ "$a" = "tcp ok" ] && echo "$b" | grep -q 'No route' && [ $ms -lt 3000 ]
		r=$?; chk nat-egress-deny-public "public 1.1.1.1:443 reachable [$a]; --egress-deny 1.1.1.1/32 blocks it fast [$b] (${ms}ms)"
	else
		skp nat-egress-deny-public "the host cannot reach 1.1.1.1:443 (offline)"
	fi
	kill $L3 2>/dev/null
fi

# --- egress proxy ------------------------------------------------------------------------
PB=$(freebase 3); PA=$PB; PD=$((PB + 1))
"$HELPER" echo $PA & PE=$!
waitfor "'$HELPER' tcp 127.0.0.1 $PA | grep -q ok" 5
named px -d --egress-proxy-allow "127.0.0.1:$PA" --egress-proxy-allow "LocalHost:$PA" --egress-proxy-allow '*.Wild.Test:443' $H -- sleep 120
waitfor 'psl | grep -q "^px .*running"' 5
px() { timeout 15 "$JUNO" exec px -- /helper "$@" 2>&1 | tr '\n' ' '; }
o=$(px connectproxy "127.0.0.1:$PA")
[ "$o" = "status 200 echo ping through the proxy " ]; r=$?; chk proxy-allowed-roundtrip "CONNECT to an allowlisted host:port relays both ways incl. half-close: $o"
o=$(px connectproxy "LOCALHOST:$PA")
echo "$o" | grep -q '^status 200 '; r=$?; chk proxy-host-case-insensitive "allowlist entry LocalHost matches LOCALHOST, resolved on the host: $o"
o1=$(px connectproxy "127.0.0.1:$PD"); o2=$(px connectproxy evil.example:443); o3=$(px connectproxy "127.0.0.2:$PA")
o4=$(px connectproxy wild.test:443); o5=$(px connectproxy evilwild.test:443); o6=$(px connectproxy a.b.wild.test:443)
echo "$o1" | grep -q 'status 403' && echo "$o2" | grep -q 'status 403' && echo "$o3" | grep -q 'status 403' && echo "$o4" | grep -q 'status 403' && echo "$o5" | grep -q 'status 403' && ! echo "$o6" | grep -q 'status 403'
r=$?; chk proxy-denies-everything-else "other port [$o1], other host [$o2], unlisted IP literal [$o3], wildcard base domain [$o4], suffix lookalike [$o5]; wildcard subdomain passes the policy [$o6]"
g=$(px rawproxy get); j=$(px rawproxy junk); nb=$(px rawproxy nullbyte); bg=$(px rawproxy big); ht=$(px rawproxy hugetarget)
echo "$g" | grep -q 'status 403' && echo "$j" | grep -q 'status 400' && echo "$bg" | grep -q 'status 431' && echo "$ht" | grep -q 'status 400' && echo "$nb" | grep -qE 'status (400|closed)'
r=$?; chk proxy-rejects-bad-requests "GET http:// [$g]; junk [$j]; NUL in the request line [$nb]; 40 KB without a terminator [$bg]; 2 KB target [$ht]"
o=$(px connectproxy "127.0.0.1:$PA")
[ "$o" = "status 200 echo ping through the proxy " ]; r=$?; chk proxy-survives-garbage "still serving after the bad requests: $o"
e=$("$JUNO" exec px -- sh -c 'echo $HTTPS_PROXY $https_proxy $HTTP_PROXY'); lg=$("$JUNO" logs px)
echo "$e" | grep -q '^http://127.0.0.1:3128 http://127.0.0.1:3128 http://127.0.0.1:3128$' && echo "$lg" | grep -q "CONNECT 127.0.0.1:$PA allowed up=23 down=23 bytes" && echo "$lg" | grep -q 'CONNECT evil.example:443 denied' && echo "$lg" | grep -q 'GET denied'
r=$?; chk proxy-audit-log "HTTPS_PROXY set in the cell; the cell log has allowed (with bytes) and denied lines: $(echo "$lg" | head -3 | tr '\n' ';')"
d=$(J --net none $H -- /helper tcp 127.0.0.1 3128)
echo "$d" | grep -q FAIL; r=$?; chk proxy-no-entries-no-listener "a cell without --egress-proxy-allow has nothing on 127.0.0.1:3128 [$d]"
"$JUNO" stop px --time 1
waitfor '[ -z "$(mine | grep -v helper)" ]' 5; left=$(mine | tr '\n' ';')
[ -z "$left" ]; r=$?; chk proxy-dies-with-cell "no proxy or connection process survives the cell${left:+: $left}"
kill $PE 2>/dev/null
if command -v curl >/dev/null && curl -sS -m 6 -o /dev/null https://example.com 2>/dev/null; then
	a=$(J --egress-proxy-allow example.com:443 -- curl -sS -m 15 -o /dev/null -w '%{http_code}' https://example.com 2>&1)
	b=$(J --egress-proxy-allow example.com:443 -- curl -sS -m 15 -o /dev/null -w '%{http_code}' https://example.org 2>&1 | tail -1)
	[ "$a" = 200 ] && echo "$b" | grep -qE '000|403|CONNECT'
	r=$?; chk proxy-real-https "curl in the cell: allowlisted https://example.com gives $a; https://example.org is refused ($(echo "$b" | head -c 80))"
else
	skp proxy-real-https "no curl, or the host cannot fetch https://example.com (offline)"
fi

# --- Landlock alone, control socket peer check, hidden tools -------------------------------
mkdir -p "$T/lld"; echo keep > "$T/lld/f"
LLR="--landlock-ro / --landlock-rw /tmp"
a=$(J --seccomp off --keep-cap dac_override --keep-cap sys_admin --keep-cap fowner $H --bind "$T/lld:/data" $LLR -- sh -c '/helper writefile /data/new; /helper writefile /tmp/ok; /helper mountany /tmp')
b=$(J --seccomp off --keep-cap dac_override --keep-cap sys_admin --keep-cap fowner $H --bind "$T/lld:/data" -- sh -c '/helper writefile /data/new2; /helper writefile /tmp/ok')
echo "$a" | sed -n 1p | grep -q 'write FAIL Permission denied' && echo "$a" | sed -n 2p | grep -q 'write ok' && echo "$b" | tr '\n' ' ' | grep -q '^write ok write ok' && [ ! -e "$T/lld/new" ] && [ -e "$T/lld/new2" ]
r=$?; chk landlock-alone "no seccomp, caps kept, rw bind: with Landlock the write to /data is [$(echo "$a" | sed -n 1p)], /tmp works; without Landlock it succeeds ($(echo $b | head -c 40))"
a=$(J --preset agent --mem-fallback rlimit --seccomp off --workspace "$T/lld" --bind-ro "$HELPER:/helper" --landlock-ro /helper -- sh -c 'for p in /usr/x /etc/x /run/x /x /dev/x /bin/x; do /helper writefile $p; done; /helper writefile /tmp/t; /helper writefile /work/w')
[ "$(echo "$a" | grep -c 'write FAIL')" = 6 ] && echo "$a" | tail -2 | tr '\n' ' ' | grep -q 'write ok write ok'
r=$?; chk landlock-agent-seccomp-off "agent preset with seccomp off: six writes outside /work and /tmp fail, those two succeed: $(echo "$a" | tr '\n' ';' | head -c 200)"
named pc -d $H -- sleep 60; waitfor 'psl | grep -q "^pc .*running"' 5
chmod 755 "$JUNO_RUNTIME_DIR/pc"; chmod 666 "$JUNO_RUNTIME_DIR/pc/sock"
mine_=$("$HELPER" ctlstatus "$JUNO_RUNTIME_DIR/pc/sock")
if echo "$probe" | grep -q 'idmap = full): available'; then
	other=$(J --idmap full --user 100:100 $H --bind "$JUNO_RUNTIME_DIR/pc:/ctl" -- /helper ctlstatus /ctl/sock)
	st=$("$JUNO" status pc | head -1)
	echo "$mine_" | grep -q 'ctl reply' && echo "$other" | grep -q 'closed without a reply' && [ "$st" = "state=running" ]
	r=$?; chk ctl-socket-peer-check "socket made world-writable for the test: our uid gets a reply [$mine_], a mapped subuid (cell uid 100) is dropped by SO_PEERCRED [$other]; the supervisor keeps running"
else
	skp ctl-socket-peer-check "needs idmap = full for a second uid"
fi
"$JUNO" stop pc --time 1
o1=$(env PATH=/nonexistent "$JUNO" run --idmap full -- true 2>&1); o2=$(JUNO_SUBUID_FILE=/dev/null "$JUNO" run --idmap full -- true 2>&1); o3=$(JUNO_SUBGID_FILE=/dev/null "$JUNO" run --idmap full -- true 2>&1)
o4=$(env PATH=/nonexistent "$JUNO" run --net nat -- true 2>&1); o5=$("$JUNO" run -t --name tt9 -- true 2>&1)
echo "$o1" | grep -q 'newuidmap/newgidmap are not installed' && echo "$o2" | grep -q 'no subuid range for uid .* in /dev/null' && echo "$o3" | grep -q 'no subgid range for uid .* in /dev/null' && echo "$o4" | grep -q 'needs pasta' && echo "$o5" | grep -q -- '-t does not combine with --name'
r=$?; chk missing-tools-clear-errors "hidden newuidmap: [$o1]; no subuid: [$o2]; no subgid: [$o3]; hidden pasta: [$o4]; run -t --name: [$o5]"

# --- small fixes ---------------------------------------------------------------------------
v=$("$JUNO" version); [ "$v" = "juno 0.1.0" ]; r=$?; chk version "juno version: $v"
pl=$("$JUNO" probe | grep '^outbound')
echo "$pl" | grep -qE 'pasta (available \(.+\)|unavailable)' || echo "$pl" | grep -q 'unavailable'; r=$?; chk probe-pasta-version "$pl"
if [ -d "$RF" ] && echo "$probe" | grep -q 'pasta available'; then
	rm -f "$RF/etc/resolv.conf"
	J --root "dir:$RF" --net nat -- cat /etc/resolv.conf >/dev/null
	[ ! -e "$RF/etc/resolv.conf" ]; r=$?; chk nat-dir-root-leaves-no-resolv-conf "the empty mountpoint file is removed again after the cell exits"
	echo mine > "$RF/etc/resolv.conf"; J --root "dir:$RF" --net nat -- true; [ "$(cat "$RF/etc/resolv.conf")" = mine ]; r=$?; chk nat-dir-root-keeps-own-resolv-conf "an existing resolv.conf in the rootfs is neither replaced nor removed"; rm -f "$RF/etc/resolv.conf"
fi

# --- review round: limits that fail closed, tmpfs caps, log cap, validation --------------
if echo "$probe" | grep -q '^cgroup v2 delegation: usable'; then
	skp mem-fails-closed "cgroups are usable here; the cgroup tests cover the limit itself"
else
	o1=$("$JUNO" run --mem 100000000 -- true 2>&1); rc1=$?
	o2=$("$JUNO" run --preset agent -- true 2>&1); rc2=$?
	o3=$("$JUNO" run --mem 100000000 --mem-fallback rlimit -- true 2>&1); rc3=$?
	[ $rc1 -eq 125 ] && [ $rc2 -eq 125 ] && [ $rc3 -eq 0 ] && echo "$o1" | grep -q 'systemd-run --user --scope -p Delegate=yes' && echo "$o2" | grep -q 'delegated cgroup'
	r=$?; chk mem-fails-closed "--mem and the agent preset refuse to start without a delegated cgroup (rc $rc1/$rc2) and name the systemd-run scope; --mem-fallback rlimit opts in (rc $rc3)"
fi
o=$(J -- df -m /tmp /run /dev/shm | awk 'NR>1 {print $2}' | tr '\n' ' ')
o2=$(J --tmp-size 32M --run-size 8M --shm-size 4M --tmpfs-size 16M --tmpfs /scratch -- df -m /tmp /run /dev/shm /scratch | awk 'NR>1 {print $2}' | tr '\n' ' ')
[ "$o" = "256 64 64 " ] && [ "$o2" = "32 8 4 16 " ]; r=$?; chk tmpfs-size-caps "default /tmp /run /dev/shm = $o MB; configured = $o2 MB"
named lg -d --log-max 100k -- sh -c 'yes | head -c 3000000; : > /proc/self/fd/1; echo after; sleep 30'
waitfor 'psl | grep -q "^lg .*running"' 5; sleep 1.5
sz=$(stat -c %s "$DT/lg/log"); sz1=$(stat -c %s "$DT/lg/log.1" 2>/dev/null || echo 0)
"$JUNO" status lg | grep -q '^state=running'; st=$?
[ "$sz" -le 110000 ] && [ "$sz1" -gt 90000 ] && [ $st -eq 0 ] && grep -q after "$DT/lg/log"
r=$?; chk log-capped-and-rotated "3 MB of output with --log-max 100k: log $sz bytes, log.1 $sz1 bytes, the payload's truncation attempt did not touch the file"
"$JUNO" stop lg --time 1
if echo "$probe" | grep -q 'idmap = full): available'; then
	named eu -d --idmap full --user 100:100 -- sleep 60
	waitfor 'psl | grep -q "^eu .*running"' 5
	o=$("$JUNO" exec eu -- id -u 2>&1)
	[ "$o" = 100 ]; r=$?; chk exec-into-user-cell "exec into a cell started with --user: $o"
	"$JUNO" stop eu --time 1
else skp exec-into-user-cell "needs idmap = full"; fi
"$JUNO" run --name -x -d -- true 2>"$T/e.err"; rc1=$?
named lf9 -d -- sh -c 'echo logline; sleep 20'; sleep 0.5
o=$(timeout 2 "$JUNO" logs -f lf9 2>&1 | head -1); "$JUNO" stop lf9 --time 1
[ $rc1 -ne 0 ] && grep -q 'invalid cell name' "$T/e.err" && [ "$o" = logline ]
r=$?; chk cell-name-and-logs-f-parsing "name -x refused ($(head -c 60 "$T/e.err")); 'logs -f NAME' parses: $o"
b=0
for t in nan inf -1 1e30 abc; do "$JUNO" run --timeout $t -- true >/dev/null 2>&1 && b=1; done
"$JUNO" run --max-restarts 4294967296 -- true >/dev/null 2>&1 && b=1
"$JUNO" run --timeout 2.5 --max-restarts 3 -- true >/dev/null 2>&1 || b=1
r=$b; chk numeric-ranges "timeout nan/inf/-1/1e30/abc and max-restarts 2^32 are rejected; sane values pass"
mkdir -p "$T/loose"; chmod 755 "$T/loose"
o=$(JUNO_RUNTIME_DIR="$T/loose" "$JUNO" run --name sd -d -- true 2>&1); rc=$?
[ $rc -ne 0 ] && echo "$o" | grep -q 'mode 0700'; r=$?; chk state-dir-mode-checked "a pre-existing state dir with mode 0755 is refused: $(echo "$o" | head -c 150)"
o=$("$JUNO" run --keep-cap sys_admin -- true 2>&1 >/dev/null)
echo "$o" | grep -q 'warning: --keep-cap sys_admin'; r=$?; chk keepcap-sysadmin-warning "$o"

# --- presets and juno up ---------------------------------------------------------
named pr1 -d --preset agent --mem-fallback rlimit --workspace "$T/u" -- sleep 30
sp=$(cat "$JUNO_DATA_DIR/pr1/spec")
echo "$sp" | grep -q '^net = none' && echo "$sp" | grep -q '^seccomp = strict' && echo "$sp" | grep -q "^bind = $T/u:/work" && echo "$sp" | grep -q '^cwd = /work' &&
	echo "$sp" | grep -q '^landlock-rw = /work' && echo "$sp" | grep -q '^pids = 256' && echo "$sp" | grep -q '^env = HOME=/work'
r=$?; chk preset-agent-expands "agent preset in the saved spec: $(echo "$sp" | grep -E '^(net|seccomp|pids|nofile|cwd|env)' | tr '\n' ';')"
"$JUNO" stop pr1 --time 1
named pr2 -d --preset agent --mem-fallback rlimit --net host --pids 10 --workspace "$T/u" -- sleep 30
sp=$(cat "$JUNO_DATA_DIR/pr2/spec"); "$JUNO" stop pr2 --time 1
echo "$sp" | grep -q '^net = host' && echo "$sp" | grep -q '^pids = 10' && echo "$sp" | grep -q '^seccomp = strict'; r=$?; chk preset-later-options-override "net host and pids 10 override the preset, the rest stays"
named pr3 -d --preset service -- sleep 30
sp=$(cat "$JUNO_DATA_DIR/pr3/spec"); "$JUNO" stop pr3 --time 1
echo "$sp" | grep -q '^restart = on-failure' && echo "$sp" | grep -q '^seccomp = default' && echo "$sp" | grep -q '^idmap = ' && echo "$sp" | grep -q '^net = '; r=$?; chk preset-service-expands "$(echo "$sp" | grep -E '^(restart|idmap|net|seccomp)' | tr '\n' ';')"
"$JUNO" run --preset bogus -- true 2>"$T/e.err"; rc=$?
grep -q "unknown preset 'bogus'" "$T/e.err"; r=$?; chk preset-unknown "$(head -c 100 "$T/e.err")"
mkdir -p "$T/upd"; printf 'root = host-ro\nargv = sleep 30\n' > "$T/upd/a.cell"; printf 'root = host-ro\nbogus = 1\nargv = true\n' > "$T/upd/b.cell"
out=$("$JUNO" up "$T/upd"); rc=$?
echo "$out" | grep -q '^a: started' && echo "$out" | grep -q '^b: failed: .*b.cell:2: unknown key' && [ $rc -ne 0 ]
r=$?; chk up-reports-per-cell "one cell starts, a bad spec fails with its line, rc=$rc: $(echo "$out" | tr '\n' ';' | head -c 200)"
"$JUNO" down "$T/upd" >/dev/null

# --- no leftovers ------------------------------------------------------------
"$JUNO" ps | tail -n +2 | while read -r n _; do "$JUNO" stop "$n" --time 1 >/dev/null 2>&1; done
"$JUNO" net ls | tail -n +2 | while read -r n _; do "$JUNO" net rm "$n" >/dev/null 2>&1; done
waitfor '[ -z "$(mine)" ]' 8
left=$(mine | tr "\n" ";")
[ -z "$left" ] && [ -z "$(psl)" ]; r=$?; chk no-leftover-processes "no juno supervisors, holders, forwarders or payloads remain${left:+: $left}"

l=$(ls -A "$TMPDIR"); [ -z "$l" ]; r=$?; chk no-leftover-stage-dirs "private TMPDIR holds no stage directory${l:+: $l}"
echo "SUMMARY run.sh: $pass passed, $fail failed, $skip skipped"
[ $fail -eq 0 ]
