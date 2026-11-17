#!/bin/bash
# Copyright 2026, Dario Casalinuovo.
# SPDX-License-Identifier: LGPL-2.1-or-later
# Trial 2: a small mail service (SMTP receiver) deployed with `juno up`.
. "$(dirname "$0")/lib.sh"

if ! J -- true >/dev/null 2>"$T/pre.err"; then
	skp mail-all "cells cannot start on this host: $(cat "$T/pre.err")"; summary trial_mail.sh; exit 0
fi
probe=$("$JUNO" probe)
if ! echo "$probe" | grep -q 'multi-id maps (idmap = full): available' || ! echo "$probe" | grep -q 'pasta available'; then
	skp mail-all "needs idmap = full and pasta: $(echo "$probe" | grep -E 'multi-id|outbound')"; summary trial_mail.sh; exit 0
fi
DIR=$T/deploy; SPOOL=$T/spool; mkdir -p "$DIR" "$SPOOL"
HP=$(freebase 4)
LAN=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')
OTHER=$(ip -4 -o addr show | awk '{print $4}' | cut -d/ -f1 | grep -v "^127\.\|^$LAN\$" | head -1)
SUB=$(awk -F: -v u="$(id -un)" '$1==u{print $2; exit}' /etc/subuid)
WANT_OWNER=$((SUB + 99))
cat > "$DIR/mail.cell" <<EOF
# a small SMTP receiver: starts as cell root, binds, drops to uid 100
preset = service
idmap = full
keep-cap = setuid
keep-cap = setgid
keep-cap = chown
bind = $SPOOL:/spool
bind-ro = $ROOT/tests/smtpd.py:/srv/smtpd.py
bind-ro = $HELPER:/helper
publish = 127.0.0.1:$HP:2525
${LAN:+egress-allow = $LAN/32}
restart = on-failure
max-restarts = 5
mem = 536870912
mem-fallback = rlimit
pids = 64
argv = python3 /srv/smtpd.py 2525 /spool 100
EOF
cat > "$DIR/client.cell" <<EOF
# submits one message through the nat gateway to the host's published port
preset = service
net = nat:host
restart = no
bind-ro = $ROOT/tests/smtpclient.py:/srv/smtpclient.py
argv = python3 /srv/smtpclient.py $HP 'hello from the client cell'
EOF
spool_files() { ls "$SPOOL" 2>/dev/null | grep -c '\.eml$'; }
smtp_pid() { "$JUNO" exec mail -- sh -c 'for d in /proc/[0-9]*; do case "$(tr "\0" " " < $d/cmdline)" in "python3 /srv/smtpd.py"*) echo ${d#/proc/};; esac; done'; }

out=$("$JUNO" up "$DIR")
echo "$out" | grep -q '^client: started' && echo "$out" | grep -q '^mail: started'
r=$?; chk up-starts-cells "juno up: $(echo "$out" | tr '\n' ';')"
out2=$("$JUNO" up "$DIR")
echo "$out2" | grep -q '^mail: already running'; r=$?; chk up-is-idempotent "second juno up: $(echo "$out2" | tr '\n' ';')"
waitfor "psl | grep -q '^mail .*running'" 10; r=$?; chk mail-running "$(psl | grep '^mail')"

waitfor "python3 '$ROOT/tests/smtpsend.py' 127.0.0.1 $HP 'ping' '$T/exp0' >/dev/null 2>&1" 15
ls "$SPOOL" > "$T/before.lst"
python3 "$ROOT/tests/smtpsend.py" 127.0.0.1 $HP $'line one\nline two\n.dot-led line' "$T/exp1" >/dev/null 2>"$T/send.err"; rc=$?
f=$(ls "$SPOOL" | grep "\.eml$" | grep -vxFf "$T/before.lst" | head -1); f=${f:+$SPOOL/$f}
[ $rc -eq 0 ] && [ -n "$f" ] && cmp -s "$f" "$T/exp1"
r=$?; chk mail-delivered-intact "host submitted through 127.0.0.1:$HP; spool file $(basename "$f") has the exact bytes (incl. a dot-stuffed line) $(head -c 100 "$T/send.err")"
owner=$(stat -c %u "$f"); sown=$(stat -c %u "$SPOOL")
[ "$owner" = "$WANT_OWNER" ] && [ "$sown" = "$WANT_OWNER" ]
r=$?; chk mail-owned-by-subuid "message owned by $owner, spool dir by $sown (cell uid 100 = subuid $SUB + 99 = $WANT_OWNER)"
pid=$(smtp_pid | head -1)
st=$("$JUNO" exec mail -- grep -E '^(Uid|CapEff|CapPrm|NoNewPrivs):' /proc/$pid/status | tr -s '\t\n' '  ')
echo "$st" | grep -q 'Uid: 100 100 100 100' && echo "$st" | grep -q 'CapEff: 0000000000000000' && echo "$st" | grep -q 'CapPrm: 0000000000000000'
r=$?; chk mail-service-not-root "server process $pid inside the cell: $st"
waitfor 'grep -l "hello from the client cell" "$SPOOL"/*.eml >/dev/null 2>&1' 25
grep -l 'hello from the client cell' "$SPOOL"/*.eml >/dev/null 2>&1
r=$?; chk mail-client-cell-delivered "the client cell (nat:host) delivered through the gateway: $("$JUNO" logs client | tr '\n' ' ')"
"$JUNO" logs mail | grep -q 'listening on 2525, running as uid 100' && "$JUNO" logs mail | grep -q 'stored msg-'
r=$?; chk mail-logs "juno logs mail: $("$JUNO" logs mail | head -2 | tr '\n' ';')"

before=$(spool_files)
pid=$(smtp_pid | head -1)
"$JUNO" exec --user 100 mail -- kill -9 "$pid"; krc=$?
waitfor '"$JUNO" status mail | grep -q "^restarts=[1-9]"' 15; rr=$?
waitfor "python3 '$ROOT/tests/smtpsend.py' 127.0.0.1 $HP 'after the restart' '$T/exp2' >/dev/null 2>&1" 15; sr=$?
after=$(spool_files)
pid2=$(smtp_pid | head -1)
[ $krc -eq 0 ] && [ $rr -eq 0 ] && [ $sr -eq 0 ] && [ "$after" -gt "$before" ] && [ -n "$pid2" ] && cmp -s "$f" "$T/exp1"
r=$?; chk mail-restart-keeps-spool "killed server $pid (exec --user 100 rc=$krc), supervisor restarted it ($("$JUNO" status mail | grep restarts)), new pid $pid2; delivery works again; spool $before -> $after, first message intact"

OP=$((HP + 1)); LP=$((HP + 2))
python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('0.0.0.0', $OP)); s.listen(8)
while True:
    c,_=s.accept(); c.close()" & OPID=$!
python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('127.0.0.1', $LP)); s.listen(8)
while True:
    c,_=s.accept(); c.close()" & LPID=$!
waitfor "'$HELPER' tcp 127.0.0.1 $OP | grep -q ok" 5
LAN=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')
o1=$("$JUNO" exec mail -- /helper tcp "$LAN" $OP); o2=$("$JUNO" exec mail -- /helper gwconnect $LP)
o3=$([ -n "$OTHER" ] && "$JUNO" exec mail -- /helper tcp "$OTHER" $OP || echo "tcp FAIL No route to host (no second address)")
[ "$o1" = "tcp ok" ] && echo "$o2" | grep -q FAIL && echo "$o3" | grep -q "No route"
r=$?; chk mail-outbound-nat "host listener at $LAN:$OP reachable from the mail cell [$o1]; host loopback listener through the gateway is not [$o2]; a second host address ${OTHER:-none} stays blocked by the egress policy [$o3]"
kill $OPID $LPID 2>/dev/null
if "$HELPER" tcp 1.1.1.1 443 | grep -q ok; then
	o=$("$JUNO" exec mail -- /helper tcp 1.1.1.1 443); [ "$o" = "tcp ok" ]; r=$?; chk mail-outbound-internet "TCP connect to 1.1.1.1:443 from the mail cell: $o"
else
	skp mail-outbound-internet "the host itself cannot reach 1.1.1.1:443 (offline)"
fi

out=$("$JUNO" down "$DIR"); rc=$?
sleep 0.5
left=$(mine)
holder=$("$JUNO" net ls | tail -n +2)
port=$("$HELPER" tcp 127.0.0.1 $HP)
[ $rc -eq 0 ] && [ -z "$(psl)" ] && [ -z "$left" ] && [ -z "$holder" ] && echo "$port" | grep -q FAIL && [ ! -e "$JUNO_DATA_DIR/mail" ]
r=$?; chk down-leaves-nothing "down: $(echo "$out" | tr '\n' ';') ps empty, no juno/pasta/helper/smtpd process${left:+ ($left)}, no holder, port $HP: $port"
"$JUNO" rmtree "$SPOOL"
leftover_tmp
summary trial_mail.sh
