#!/bin/bash
# Copyright 2026, Dario Casalinuovo.
# SPDX-License-Identifier: LGPL-2.1-or-later
# Trial 1: an "agent" (here a shell script) confined with --preset agent. Normal work must
# succeed; every escape attempt must fail, each reported on its own line with the error seen.
. "$(dirname "$0")/lib.sh"

if ! J -- true >/dev/null 2>"$T/pre.err"; then
	skp agent-all "cells cannot start on this host: $(cat "$T/pre.err")"; summary trial_agent.sh; exit 0
fi
W=$T/work; mkdir -p "$W"
BR=$T/broker.sock
python3 "$ROOT/tests/broker.py" "$BR" & BP=$!
waitfor "[ -S '$BR' ]" 5
A="--preset agent --mem-fallback rlimit --workspace $W --broker $BR --bind-ro $HELPER:/helper --landlock-ro /helper"
ag() { J $A -- "$@" 2>&1; }
# denied OUT: every FAIL line, no success line
denied() { echo "$1" | grep -q 'FAIL' && ! echo "$1" | grep -qE ' ok$| ok '; }
one() { echo "$1" | tr '\n' ';' | sed 's/;$//'; }

# --- normal work -------------------------------------------------------------
out=$(ag sh -c 'cd /work && echo data > out.txt && cat out.txt && pwd && echo "$HOME" && ls /work | wc -l')
[ "$out" = "$(printf 'data\n/work\n/work\n1')" ] && [ "$(cat "$W/out.txt")" = data ]
r=$?; chk agent-workspace-files "reads and writes /work (cwd and HOME), the file is on the host: $(one "$out")"
out=$(ag sh -c 'sort /work/out.txt | wc -l; grep -c data /work/out.txt; cp /work/out.txt /tmp/c && echo copied; sed s/data/DATA/ /tmp/c; find /work -name out.txt; printf "%s\n" a b | wc -l')
[ "$out" = "$(printf '1\n1\ncopied\nDATA\n/work/out.txt\n2')" ]; r=$?; chk agent-ordinary-tools "sort grep cp sed find wc run: $(one "$out")"
out=$(ag /helper unixreq /run/broker.sock hello-broker)
[ "$out" = "pong:hello-broker" ]; r=$?; chk agent-broker-roundtrip "request over /run/broker.sock gets its reply: $out"
out=$(J --preset agent --mem-fallback rlimit --bind-ro "$HELPER:/helper" --landlock-ro /helper -- /helper unix /run/broker.sock 2>&1)
denied "$out"; r=$?; chk agent-no-broker-no-channel "without --broker there is no socket to talk to: $(one "$out")"
out=$(ag env | sort | tr '\n' ' ')
[ "$out" = "HOME=/work PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin " ]; r=$?; chk agent-clean-env "environment is only HOME and PATH: $out"
out=$(ag /helper caps)
echo "$out" | grep -q 'CapEff:	0000000000000000' && echo "$out" | grep -q 'NoNewPrivs:	1'
r=$?; chk agent-no-caps-nnp "no capabilities, no_new_privs: $(one "$out")"

# --- escape attempts ---------------------------------------------------------
fails=""; all=0
for p in "$HOME/.ssh/id_ed25519" "$HOME/.ssh/id_rsa" "$HOME/.ssh/authorized_keys" "$HOME/.bashrc" "$HOME/.gnupg/pubring.kbx" /root/.ssh/id_rsa /etc/shadow /home; do
	o=$(ag /helper readfile "$p"); all=$((all+1))
	denied "$o" || fails="$fails $p"
	seen="$seen [$(echo "$o" | sed 's/^read //')]"
done
[ -z "$fails" ]; r=$?; chk escape-read-home-and-keys "host home, ssh keys, /etc/shadow unreadable ($all paths): $seen${fails:+; SUCCEEDED:$fails}"

pid=$BP
kill -0 "$pid" 2>/dev/null; hostok=$?
out=$(ag sh -c "/helper kill $pid; ls /proc | grep -c '^[0-9]'")
n=$(echo "$out" | tail -1)
[ $hostok -eq 0 ] && echo "$out" | head -1 | grep -q 'kill FAIL' && [ "$n" -le 6 ]
r=$?; chk escape-host-processes "host pid $pid exists but is not signalable from the cell; the cell's /proc has $n pids: $(one "$out" | head -c 120)"

# TCP: a loopback listener, a listener on the host's LAN address, an external address
LP=$(freebase 2)
python3 -c "
import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('0.0.0.0', $LP)); s.listen(8)
while True:
    c,_=s.accept(); c.close()" & LPID=$!
waitfor "timeout 1 '$HELPER' tcp 127.0.0.1 $LP | grep -q ok" 5
host_ok=$("$HELPER" tcp 127.0.0.1 $LP)
LAN=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')
o1=$(ag /helper tcp 127.0.0.1 $LP)
o2=$(ag /helper tcp "${LAN:-10.0.2.15}" $LP)
o3=$(ag /helper tcp 1.1.1.1 443)
o4=$(ag /helper tcp 10.0.2.2 $LP)
denied "$o1" && denied "$o2" && denied "$o3" && denied "$o4" && [ "$host_ok" = "tcp ok" ]
r=$?; chk escape-tcp "host listener reachable from the host ($host_ok); from the cell: loopback [$o1], LAN address ${LAN:-?} [$o2], external [$o3], 10.0.2.2 [$o4]"
kill $LPID 2>/dev/null

o=$(ag /helper userns); echo "$o" | grep -q "not permitted"; r=$?; chk escape-new-userns "$o"
o=$(ag /helper mountany /work); denied "$o"; r=$?; chk escape-mount "$o"
o=$(ag /helper ptrace); denied "$o"; r=$?; chk escape-ptrace "$o"
fails=""; seen=""
for p in /usr/x /etc/x /run/x /x /proc/x /bin/x /dev/x /work/../x; do
	o=$(ag /helper writefile "$p"); denied "$o" || fails="$fails $p"; seen="$seen $p:[$(echo "$o" | sed 's/^write //')]"
done
o1=$(ag /helper writefile /tmp/x); o2=$(ag /helper writefile /work/y)
[ -z "$fails" ] && [ "$o1" = "write ok" ] && [ "$o2" = "write ok" ] && [ ! -e "$W/../x" ]
r=$?; chk escape-write-outside-work "writes outside /work and /tmp fail:$seen; /tmp and /work work${fails:+; SUCCEEDED:$fails}"
o=$(ag sh -c '/helper mknod /tmp/n; /helper mknod /work/n; /helper mknod /dev/n'); denied "$o"; r=$?; chk escape-device-node "$(one "$o")"
o=$(ag /helper kmod); denied "$o"; r=$?; chk escape-kernel-module "$o"
o=$(ag /helper bpf); denied "$o"; r=$?; chk escape-bpf "$o"
o=$(ag /helper raiselimit); denied "$o"; r=$?; chk escape-raise-limits "$o"
o=$(ag /helper forkcount 2000)
[ "$o" -le 256 ] && [ "$o" -ge 50 ]; r=$?; chk escape-fork-bomb "fork loop got $o children (pids limit 256 incl. the cell init)"
o=$(ag /helper openmany)
[ "$o" -le 1024 ] && [ "$o" -ge 100 ]; r=$?; chk escape-fd-exhaustion "open loop stopped at $o descriptors (nofile 1024)"
o=$(ag sh -c 'cp /helper /work/suid && chmod 4755 /work/suid && /work/suid caps')
echo "$o" | grep -q 'CapEff:	0000000000000000' && echo "$o" | grep -q 'NoNewPrivs:	1'
r=$?; chk escape-setuid-binary "a setuid binary in the workspace gains nothing: $(one "$o")"
o=$(ag sh -c 'echo 1 > /proc/sysrq-trigger; echo 1 > /proc/sys/kernel/hostname; echo 0 > /proc/sys/vm/swappiness' 2>&1)
[ "$(echo "$o" | grep -c 'cannot create\|Permission denied\|Read-only')" -ge 3 ]; r=$?; chk escape-proc-sys-writes "$(one "$o")"
o1=$(ag /helper readfile /proc/kcore); o2=$(ag /helper kallsyms)
denied "$o1" && echo "$o2" | grep -q ' 0 with a non-zero address'
r=$?; chk escape-kernel-memory "kcore: [$o1]; $o2"

# other cells and sockets
named other -d -- sleep 120
waitfor 'psl | grep -q "^other "' 5
o1=$(ag /helper readfile "$JUNO_DATA_DIR/other/spec"); o2=$(ag /helper unix "$JUNO_RUNTIME_DIR/other/sock"); o3=$(ag sh -c 'ls /proc | grep -c "^[0-9]"')
[ -S "$JUNO_RUNTIME_DIR/other/sock" ] && denied "$o1" && denied "$o2"
r=$?; chk escape-other-cell "its control socket exists on the host; data file [$o1]; socket [$o2]"
python3 -c "
import socket,os
p='$T/other.sock'
s=socket.socket(socket.AF_UNIX); s.bind(p); s.listen(4)
a=socket.socket(socket.AF_UNIX); a.bind('\0juno-trial-abs'); a.listen(4)
import time
time.sleep(600)" & SPID=$!
waitfor "[ -S '$T/other.sock' ]" 5
ho=$("$HELPER" abstract juno-trial-abs); hp=$("$HELPER" unix "$T/other.sock")
o1=$(ag /helper unix "$T/other.sock"); o2=$(ag /helper abstract juno-trial-abs)
ab=$(grep -o '@[^ ]*' /proc/net/unix | sort -u | head -3 | tr '\n' ' ')
o3=$(ag /helper abstract "${ab%% *}" 2>&1 | sed 's/^abstract/real-host-abstract/')
[ "$ho" = "abstract ok" ] && [ "$hp" = "unix ok" ] && denied "$o1" && denied "$o2"
r=$?; chk escape-other-unix-sockets "host connects to both ($hp, $ho); cell: path socket [$o1], host abstract socket [$o2] (the cell's own network namespace has its own abstract namespace); real host abstract names seen: ${ab:-none}"
kill $SPID 2>/dev/null
fails=""; seen=""
for p in "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/wayland-0" "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/bus" "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/pulse/native" /tmp/.X11-unix/X0 /var/run/dbus/system_bus_socket /run/dbus/system_bus_socket "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/at-spi/bus_0"; do
	o=$(ag /helper unix "$p"); denied "$o" || fails="$fails $p"
	e=no; [ -S "$p" ] && e=yes
	seen="$seen $(basename "$p")(host:$e):$(echo "$o" | sed 's/^unix FAIL //')"
done
[ -z "$fails" ]; r=$?; chk escape-desktop-sockets "X11/Wayland/DBus/pulse/AT-SPI sockets unreachable:$seen${fails:+; SUCCEEDED:$fails}"

# --- the agent reaches its API endpoint and nothing else -----------------------------------
API=$(freebase 3); APIDENY=$((API + 1))
"$HELPER" echo $API & APID=$!
waitfor "'$HELPER' tcp 127.0.0.1 $API | grep -q ok" 5
"$JUNO" run --name agp -d $A --egress-proxy-allow "127.0.0.1:$API" -- sleep 180
waitfor 'psl | grep -q "^agp .*running"' 8
ap() { timeout 15 "$JUNO" exec agp -- /helper "$@" 2>&1 | tr '\n' ' '; }
o1=$(ap connectproxy "127.0.0.1:$API"); o2=$(ap connectproxy "127.0.0.1:$APIDENY"); o3=$(ap connectproxy example.com:443)
o4=$(ap tcp 127.0.0.1 $API); o5=$(ap tcp 1.1.1.1 443); o6=$(ap rawproxy get)
echo "$o1" | grep -q 'status 200 echo ping' && echo "$o2" | grep -q 'status 403' && echo "$o3" | grep -q 'status 403' && echo "$o4" | grep -q FAIL && echo "$o5" | grep -q FAIL && echo "$o6" | grep -q 'status 403'
r=$?; chk agent-reaches-only-its-api "allowlisted endpoint through the proxy [$o1]; other port [$o2]; other host [$o3]; direct TCP to the same endpoint [$o4]; direct external [$o5]; plain GET [$o6]"
lg=$("$JUNO" logs agp)
echo "$lg" | grep -q "CONNECT 127.0.0.1:$API allowed" && echo "$lg" | grep -q "CONNECT 127.0.0.1:$APIDENY denied" && echo "$lg" | grep -q 'CONNECT example.com:443 denied'
r=$?; chk agent-proxy-audit-trail "cell log records each decision: $(echo "$lg" | tr '\n' ';' | head -c 240)"
"$JUNO" stop agp --time 1; kill $APID 2>/dev/null
kill $BP 2>/dev/null
leftover_tmp
summary trial_agent.sh
