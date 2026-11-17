#!/bin/bash
# Copyright 2026, Dario Casalinuovo.
# SPDX-License-Identifier: LGPL-2.1-or-later
# Attacks from inside cells and against the supervisor. One PASS|FAIL|SKIP line
# per attack; FAIL means the attack got through. Run from the tree root.
ROOT=$(cd "$(dirname "$0")/.." && pwd)
JUNO=${JUNO:-$ROOT/build/juno}
JT=$(mktemp -d "${JUNO_TEST_TMP:-/tmp}/jadv.XXXXXX")
export TMPDIR=$JT/tmp JUNO_RUNTIME_DIR=$JT/rt JUNO_DATA_DIR=$JT/dt
mkdir -p "$TMPDIR" "$JUNO_RUNTIME_DIR" "$JUNO_DATA_DIR" "$JT/w"
chmod 700 "$JUNO_RUNTIME_DIR" "$JUNO_DATA_DIR"
unset XDG_RUNTIME_DIR
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
# chk NAME DETAIL: r is 0 when the cell held
chk() {
	if [ "$r" -eq 0 ]; then
		ok "$1" "$2"
	else
		bad "$1" "$2"
	fi
}
J() { timeout 60 "$JUNO" run "$@"; }
supkill() { local p; p=$(grep '^supervisor=' "$JUNO_RUNTIME_DIR/$1/status" 2>/dev/null | cut -d= -f2); [ -n "$p" ] && kill -9 "$p" 2>/dev/null; }
cleanup() {
	"$JUNO" ps 2>/dev/null | tail -n +2 | while read -r n _; do "$JUNO" stop "$n" --time 1 >/dev/null 2>&1; done
	"$JUNO" net ls 2>/dev/null | tail -n +2 | while read -r n _; do "$JUNO" net rm "$n" >/dev/null 2>&1; done
	jobs -p | xargs -r kill 2>/dev/null
	chmod -R u+rwx "$JT" 2>/dev/null
	"$JUNO" rmtree "$JT" >/dev/null 2>&1
	rm -rf "${JT:?}"
}
trap cleanup EXIT
pickport() { python3 -c "
import socket,random
while True:
    p=random.randint(39000,39999); s=socket.socket()
    try: s.bind(('127.0.0.1',p)); s.close(); print(p); break
    except OSError: pass"; }

if ! J -- true >/dev/null 2>"$JT/pre.err"; then
	skp all "cells cannot start on this host: $(head -c 150 "$JT/pre.err")"
	echo "SUMMARY adversarial.sh: $pass passed, $fail failed, $skip skipped"; exit 0
fi
if ! command -v gcc >/dev/null; then skp all "no C compiler for the attack helpers"; echo "SUMMARY adversarial.sh: $pass passed, $fail failed, $skip skipped"; exit 0; fi
ADV=$JT/adv; gcc -std=gnu11 -O1 -static "$ROOT/tests/adv/adv.c" -o "$ADV" 2>/dev/null || { skp all "cannot build tests/adv/adv.c"; echo "SUMMARY adversarial.sh: $pass passed, $fail failed, $skip skipped"; exit 0; }
ADV32=$JT/adv32; gcc -m32 -nostdlib -static -ffreestanding -fno-pic -no-pie -fno-stack-protector -O1 -o "$ADV32" "$ROOT/tests/adv/adv32.c" 2>/dev/null || ADV32=
A="--bind-ro $ADV:/adv"
denied() { [ "$(J $A -- /adv $1 2>&1 | head -1 | cut -d' ' -f1)" = DENIED ]; }

# --- information leaks from the cell init ----------------------------------
export JADV_SECRET=sk-adv-0123456789
out=$(J -- sh -c 'tr "\0" "\n" < /proc/1/environ | grep -c JADV_SECRET')
[ "$out" = 0 ]; r=$?; chk init-environ-hides-host-env "host variable visible in the cell's /proc/1/environ: $out hit(s)"
out=$(J -- sh -c 'tr "\0" " " < /proc/1/cmdline | grep -c "^/"')
[ "$out" = 0 ]; r=$?; chk init-cmdline-hides-host-path "host path of the juno binary visible in /proc/1/cmdline: $out"
cat > "$JT/memread.py" <<'PY'
import sys
n = 0
mem = open("/proc/1/mem", "rb")
for l in open("/proc/1/maps").read().splitlines():
    p = l.split()
    if "r" not in p[1] or "[vvar" in l or "vsyscall" in l: continue
    s, e = [int(x, 16) for x in p[0].split("-")]
    try: mem.seek(s); n += mem.read(e - s).count(b"JADV_SECRET")
    except Exception: pass
print(n)
PY
out=$(J --bind-ro "$JT/memread.py:/m.py" -- python3 /m.py 2>&1 | tail -1)
[ "$out" = 0 ]; r=$?; chk init-memory-unreadable "payload read the init's memory (a copy of the launcher): host secret found $out time(s)"
unset JADV_SECRET
out=$(J --init none -- sh -c 'grep -c . /proc/1/environ >/dev/null; cat /proc/1/environ | wc -c')
[ "$out" -lt 200 ]; r=$?; chk init-none-environ-clean "--init none: payload's own environ only ($out bytes)"

# --- tty ---------------------------------------------------------------------
out=$(python3 "$ROOT/tests/adv/runpty.py" /bin/sh -c "$JUNO run -- sh -c 'echo HOSTTTY-REACHED > /dev/tty' >/dev/null 2>&1")
echo "$out" | grep -q HOSTTTY-REACHED; r=$(( $? == 0 )); chk tty-host-terminal-unreachable "payload wrote to the launcher's controlling terminal through /dev/tty: '$(echo $out)'"
$JUNO run --name tt -d -- sleep 30; sleep 1
out=$(python3 "$ROOT/tests/adv/runpty.py" /bin/sh -c "$JUNO exec tt -- sh -c 'echo EXECTTY > /dev/tty' 2>&1")
echo "$out" | grep -q EXECTTY; r=$(( $? == 0 )); chk tty-exec-no-controlling-terminal "exec'd payload reached the caller's terminal: '$(echo $out)'"
$JUNO stop tt --time 1 >/dev/null 2>&1

# --- seccomp, namespaces, caps -------------------------------------------------
for s in "userns unshare" "userns clone" "userns clone-hi" "userns clone3"; do
	denied "$s"; r=$?; chk "seccomp-${s// /-}" "nested user namespace via ${s#userns } is refused with nesting off"
done
for s in userfaultfd setns-net unshare-mnt unshare-net fsopen open_tree mount_setattr move_mount bpf perf keyctl kexec init_module reboot settime chroot pivot_root sethostname mknod swapon ioperm; do
	denied "sys $s"; r=$?; chk "syscall-$s" "refused for a cell without capabilities"
done
for s in io_uring personality; do
	denied "sys $s"; r=$?; chk "seccomp-deny-$s" "$s is on the default deny list (kernel attack surface)"
done
caps=$(J $A -- /adv caps | grep -E 'CapEff|CapBnd|CapAmb' | awk '{print $2}' | sort -u | tr -d '\n')
[ "$caps" = 0000000000000000 ]; r=$?; chk caps-default-empty "CapEff/CapBnd/CapAmb all zero: $caps"
for flags in "--init none" "--seccomp strict" "--preset agent --mem-fallback rlimit"; do
	o=$(J $A $flags -- /adv caps | grep -E 'NoNewPrivs|Seccomp:' | tr -s '\t ' ' ' | tr '\n' ' ')
	[ "$o" = "NoNewPrivs: 1 Seccomp: 2 " ]; r=$?; chk "hardened-path-${flags//[ -]/_}" "no_new_privs and a seccomp filter on this path: $o"
done
if "$JUNO" probe | grep -q 'multi-id maps.*available'; then
	o=$(J $A --idmap full --user 1000 -- /adv caps | grep -E 'Uid|CapEff|Seccomp:' | tr -s '\t ' ' ' | tr '\n' ' ')
	[ "$o" = "Uid: 1000 1000 1000 1000 CapEff: 0000000000000000 Seccomp: 2 " ]; r=$?; chk hardened-path-user "--user drops ids and caps: $o"
else skp hardened-path-user "idmap full unavailable"; fi
$JUNO run --name ex -d $A -- sleep 60; sleep 1
o=$("$JUNO" exec ex -- sh -c '/adv caps | grep -E "CapEff|CapBnd|CapAmb|NoNew|Seccomp:" | tr -s "\t " " " | tr "\n" " "')
[ "$o" = "CapEff: 0000000000000000 CapBnd: 0000000000000000 CapAmb: 0000000000000000 NoNewPrivs: 1 Seccomp: 2 " ]; r=$?; chk hardened-path-exec "exec'd process has the cell's hardening: $o"
$JUNO stop ex --time 1 >/dev/null 2>&1
if [ -n "$ADV32" ]; then
	o=$(J --compat32 --bind-ro "$ADV32:/a32" -- /a32 m)
	case "$o" in "clone3-newuser-mount EPERM"|"clone3-newuser-mount ENOSYS") r=0;; *) r=1;; esac; chk compat32-clone3-userns "i386 clone3(CLONE_NEWUSER) then mount with nesting off: $o"
	o=$(J --compat32 --bind-ro "$ADV32:/a32" -- /a32 i)
	[ "$o" = "io_uring EPERM" ]; r=$?; chk compat32-io_uring "i386 io_uring_setup: $o"
else skp compat32-clone3-userns "cannot build a 32-bit program"; fi

# --- mounts under CAP_SYS_ADMIN ---------------------------------------------------
mkdir -p "$JT/ro"; echo data > "$JT/ro/f"
w=$(J --keep-cap sys_admin --bind-ro "$JT/ro:/data" -- sh -c 'mount -o remount,rw,bind /data && echo x > /data/new' 2>&1 >/dev/null | grep -c 'warning: --keep-cap sys_admin')
# the remount itself is documented behaviour of CAP_SYS_ADMIN; what is required is that the CLI says so
[ "$w" = 1 ]; r=$?; chk keepcap-sysadmin-keeps-ro-bind "--keep-cap sys_admin can remount a --bind-ro mount rw (documented); the CLI printed the warning $w time(s)"
o=$(J --keep-cap sys_admin -- sh -c 'ls /home /root 2>&1 | grep -vc "No such"')
[ "$o" = 0 ]; r=$?; chk keepcap-sysadmin-no-host-fs "sys_admin cell sees no host /home or /root"
o=$(J --keep-cap net_raw --keep-cap net_admin --net shared:advn $A -- sh -c '/adv raw packet; /adv raw icmp; ip addr add 10.9.9.9/24 dev lo 2>&1 | head -1' | tr '\n' ' ')
echo "$o" | grep -q 'DENIED.*DENIED.*not permitted'; r=$?; chk shared-net-caps-no-power "net_raw/net_admin in a shared-net cell give no raw socket or address change: $o"
$JUNO net rm advn >/dev/null 2>&1
o=$(J --keep-cap sys_admin --keep-cap dac_read_search $A -- /adv sys mknod 2>&1 | grep -v '^juno: warning' | head -1)
[ "${o%% *}" = DENIED ]; r=$?; chk keepcap-mknod-in-userns "device node creation refused even with sys_admin: $o"

# --- filesystem and hostile roots ------------------------------------------------
RF=$JT/rf; mkdir -p "$RF"/{bin,lib,lib64,etc,proc,dev,tmp,run,usr,work}
if BB=$(command -v busybox); then
	cp "$BB" "$RF/bin/busybox"; for a in $("$BB" --list); do ln -sf busybox "$RF/bin/$a"; done
	ldd "$BB" | awk '$1 ~ /^\// {print $1} $2 == "=>" && $3 ~ /^\// {print $3}' | while read -r l; do mkdir -p "$RF$(dirname "$l")"; cp -L "$l" "$RF$l"; done
	cp "$ADV" "$RF/adv"
	OUT=$JT/outside
	for v in proc dev tmp run; do
		rm -rf "${OUT:?}"; mkdir -p "$OUT"; mv "$RF/$v" "$RF/$v.orig"; ln -s "$OUT" "$RF/$v"
		J --root "dir:$RF" -- true >/dev/null 2>&1; rc=$?
		[ $rc -ne 0 ] && [ -z "$(ls -A "$OUT")" ]; r=$?; chk "hostile-root-$v-symlink" "start refused (rc $rc) and nothing written outside"
		rm "$RF/$v"; mv "$RF/$v.orig" "$RF/$v"
	done
	rm -rf "${OUT:?}"; mkdir -p "$OUT" "$JT/src"; ln -s "$OUT" "$RF/work/lnk"
	J --root "dir:$RF" --bind "$JT/src:/work/lnk/x" -- true >/dev/null 2>&1
	[ -z "$(ls -A "$OUT")" ]; r=$?; chk bind-dst-through-symlink "mount destination under a symlink inside the root left the outside dir empty"
	echo ORIG > "$JT/victim"; ln -s "$JT/victim" "$RF/etc/resolv.conf"
	J --root "dir:$RF" --net nat -- true >/dev/null 2>&1
	[ "$(cat "$JT/victim")" = ORIG ]; r=$?; chk hostile-resolv-symlink "nat resolv.conf planted as a symlink did not overwrite the host file"
	rm -f "$RF/etc/resolv.conf"
	# deep tree left by a payload must not crash 'juno rm'
	$JUNO run --name deep -d --root overlay --layer "$RF" -- sh -c '/adv deep 800; sleep 1' >/dev/null 2>&1; sleep 3
	timeout 60 "$JUNO" rm -f deep >/dev/null 2>&1; rc=$?
	[ $rc -eq 0 ]; r=$?; chk rm-deep-tree "juno rm of a cell whose upper layer holds an 800-level tree: rc $rc (139 = SIGSEGV)"
	rm -rf "${JT:?}/dt/deep"
else
	skp hostile-root "busybox not installed"
fi
o=$(J -- sh -c 'echo x > /proc/sys/kernel/hostname; echo x > /proc/sysrq-trigger; echo 1 > /proc/sys/vm/drop_caches' 2>&1 | grep -c -i 'denied\|read-only\|permitted')
[ "$o" -ge 3 ]; r=$?; chk proc-sys-not-writable "writes to /proc/sys and sysrq-trigger refused"
o=$(J -- sh -c 'ls /dev | tr "\n" " "')
[ "$o" = "fd full null ptmx pts random shm stderr stdin stdout tty urandom zero " ]; r=$?; chk dev-minimal "/dev holds only the 13 expected entries"
o=$(J -- sh -c 'df -m /tmp /run /dev/shm | tail -n +2 | awk "{print \$2}" | sort -n | tail -1')
ram=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
[ "$o" -lt $((ram / 4)) ]; r=$?; chk tmpfs-size-limited "largest of /tmp /run /dev/shm is ${o} MB, host RAM ${ram} MB"
if "$JUNO" probe | grep -q 'cgroup v2 delegation: usable'; then
	o=$(J --mem 67108864 $A --env FILL=/tmp/big -- /adv flood tmpfs 200)
	case $o in *"wrote 200 MB"*) r=1;; *) r=0;; esac; chk tmpfs-counted-in-mem-limit "--mem 64M cell wrote: $o"
else skp tmpfs-counted-in-mem-limit "needs a delegated cgroup (tmpfs pages are charged to the cgroup memory limit, not to RLIMIT_AS)"; fi
if "$JUNO" probe | grep -q 'cgroup v2 delegation: usable'; then :; fi
o=$(J --preset agent $A -- /adv flood mem 1200 2>&1 | tail -1)
case $o in *"allocated 1200"*) mem_ok=1;; *) mem_ok=0;; esac
if "$JUNO" probe | grep -q 'cgroup v2 delegation: not usable'; then
	[ $mem_ok -eq 0 ]; r=$?; chk agent-memory-limit-without-cgroup "agent preset on a host without cgroup delegation: $o"
else skp agent-memory-limit-without-cgroup "cgroup delegation usable here, the preset limit applies"; fi
o=$(J --pids 40 $A -- /adv flood fork 200 | tail -1)
n=${o#forked }; [ "$n" -lt 60 ]; r=$?; chk pids-limit "--pids 40 fork bomb stopped at $n"
o=$(J --nofile 64 $A -- /adv flood open 0 | tail -1)
n=${o#opened }; [ "$n" -le 64 ]; r=$?; chk nofile-limit "--nofile 64 open loop stopped at $n"

# --- process and ipc ---------------------------------------------------------------
o=$(J $A -- /adv sys kill-ppid | head -1); [ "${o%% *}" = DENIED ] || [ "$o" = "OK kill-ppid" ]; r=$?; chk host-pid-invisible "payload cannot see a host parent: $o"
kill -0 $$ 2>/dev/null; hk=$?
J -- sh -c "kill -0 $$" >/dev/null 2>&1; rc=$?
[ $hk -eq 0 ] && [ $rc -ne 0 ]; r=$?; chk host-pid-unreachable "kill -0 on a host pid from the cell: rc $rc"
python3 - "$JT" <<'PY' &
import socket, sys, time
s = socket.socket(socket.AF_UNIX); s.bind('\0jadv-host-abstract'); s.listen(5); s.settimeout(40)
try:
    while True: s.accept()[0].close()
except Exception: pass
PY
sleep 1
for m in none nat; do
	if [ $m = nat ] && ! "$JUNO" probe | grep -q 'pasta available'; then skp abstract-socket-nat "no pasta"; continue; fi
	o=$(J $A --net $m -- /adv abstract jadv-host-abstract | head -1); [ "${o%% *}" = DENIED ]; r=$?; chk "abstract-socket-$m" "host abstract unix socket from a net=$m cell: $o"
done
o=$(J $A --net host -- /adv abstract jadv-host-abstract | head -1)
if [ "${o%% *}" = OK ]; then skp abstract-socket-host "net=host cell reaches host abstract unix sockets (shared network namespace, documented in docs/security.md)"; else ok abstract-socket-host "not reachable: $o"; fi
wait

# --- network reachability ------------------------------------------------------------
PL=$(pickport)
python3 -m http.server "$PL" --bind 127.0.0.1 >/dev/null 2>&1 & L1=$!
sleep 1
o=$(J $A --net none -- /adv connect 127.0.0.1 "$PL" 1000 | head -1); [ "${o%% *}" = DENIED ]; r=$?; chk net-none-host-loopback "net=none cell to host loopback service: $o"
if "$JUNO" probe | grep -q 'pasta available'; then
	o=$(J $A --net nat -- /adv connect 10.0.2.2 "$PL" 1000 | head -1); [ "${o%% *}" = DENIED ]; r=$?; chk net-nat-gateway-no-host-loopback "nat cell to gateway address (host loopback service): $o"
	o=$(J $A --net nat -- /adv connect 127.0.0.1 "$PL" 1000 | head -1); [ "${o%% *}" = DENIED ]; r=$?; chk net-nat-own-loopback "nat cell's 127.0.0.1 is its own: $o"
	o=$(J $A --net nat:host -- /adv connect 10.0.2.2 "$PL" 1000 | head -1); [ "${o%% *}" = OK ]; r=$?; chk net-nat-host-maps-gateway "nat:host reaches the host loopback by design: $o"
else skp net-nat "pasta not installed"; fi
kill $L1 2>/dev/null
o=$(J $A --net none -- /adv raw packet | head -1); [ "${o%% *}" = DENIED ]; r=$?; chk raw-packet-no-cap "AF_PACKET without net_raw in net=none: $o"
o=$(J $A --net host -- /adv raw packet | head -1); [ "${o%% *}" = DENIED ]; r=$?; chk raw-packet-host-net "AF_PACKET in a net=host cell: $o"

# --- fds ------------------------------------------------------------------------------
for m in "" "--init none" "--net nat" "--net shared:fdn"; do
	case $m in *nat*) "$JUNO" probe | grep -q 'pasta available' || { skp "fds-${m:-default}" "no pasta"; continue; };; esac
	n=$(J $A $m -- /adv fds < /dev/null 2>&1 | grep -vc '^fd [012] ')
	[ "$n" = 0 ]; r=$?; chk "fds-${m:-default}" "fds above 2 in the payload: $n"
done
$JUNO net rm fdn >/dev/null 2>&1
$JUNO run --name fd1 -d $A -- sh -c '/adv fds; sleep 20' >/dev/null; sleep 1.5
n=$(grep -c '^fd' "$JUNO_DATA_DIR/fd1/log"); n3=$(grep '^fd' "$JUNO_DATA_DIR/fd1/log" | grep -vc '^fd [012] ')
[ "$n3" = 0 ]; r=$?; chk fds-named-detached "detached payload holds only stdio ($n entries)"
o=$("$JUNO" exec fd1 -- /adv fds < /dev/null 2>&1 | grep -vc '^fd [012] '); [ "$o" = 0 ]; r=$?; chk fds-exec "exec'd payload holds only stdio ($o extra)"
$JUNO run --name lg1 -d -- sh -c ': > /proc/self/fd/1; echo after' >/dev/null; sleep 1.5
o=$(cat "$JUNO_DATA_DIR/lg1/log" 2>/dev/null | tr -d '\n')
$JUNO stop fd1 --time 1 >/dev/null 2>&1

# --- supervisor, control socket, state dirs ------------------------------------------
$JUNO run --name sv -d -- sleep 120 >/dev/null; sleep 1
SUP=$(grep '^supervisor=' "$JUNO_RUNTIME_DIR/sv/status" | cut -d= -f2)
fd0=$(ls /proc/$SUP/fd | wc -l)
python3 - "$JUNO_RUNTIME_DIR/sv/sock" <<'PY' >/dev/null 2>&1
import socket, struct, sys, time
def send(raw):
    s = socket.socket(socket.AF_UNIX); s.settimeout(2); s.connect(sys.argv[1])
    try: s.sendall(raw); time.sleep(0.2); s.recv(100)
    except Exception: pass
    s.close()
for raw in [b'', struct.pack('<I',0)+b'\x01', b'\x01\x00', struct.pack('<I',0x7fffffff)+b'\x01', struct.pack('<i',-1)+b'\x01'*8,
            struct.pack('<I',65536)+b'\x01'+b'a'*65535, struct.pack('<I',1)+b'\xff', struct.pack('<I',5)+b'\x03'+struct.pack('<i',100000)]:
    send(raw)
PY
kill -0 "$SUP" 2>/dev/null && "$JUNO" status sv >/dev/null 2>&1; r=$?; chk ctl-fuzz-survives "malformed, truncated and oversized frames: supervisor alive and answering"
fd1n=$(ls /proc/$SUP/fd | wc -l); [ "$fd1n" -le "$fd0" ]; r=$?; chk ctl-fuzz-no-fd-leak "supervisor fds $fd0 -> $fd1n"
python3 - "$JUNO_RUNTIME_DIR/sv/sock" <<'PY' >"$JT/wrap.out" 2>&1
import socket, struct, sys, time
s = socket.socket(socket.AF_UNIX); s.settimeout(2); s.connect(sys.argv[1])
s.sendall(struct.pack('<i', -1) + b'\x01' + b'\x00' * 8)
try: d = s.recv(200)
except Exception: d = b''
print('ACCEPTED' if d else 'REJECTED')
PY
grep -q REJECTED "$JT/wrap.out"; r=$?; chk ctl-length-wraparound "frame length 0xffffffff is rejected (len + 4 must not wrap): $(cat "$JT/wrap.out")"
python3 - "$JUNO_RUNTIME_DIR/sv/sock" "$JUNO" <<'PY' >"$JT/idle.out" 2>&1
import socket, subprocess, sys, time
socks = []
for i in range(6):
    s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); socks.append(s)
t = time.time()
subprocess.run([sys.argv[2], 'status', 'sv'], capture_output=True, timeout=60)
print('%.1f' % (time.time() - t))
PY
t=$(cat "$JT/idle.out"); awk -v t="$t" 'BEGIN { exit !(t < 3) }'; r=$?; chk ctl-idle-clients-dont-stall "status with 6 idle connected clients took ${t}s"
python3 - "$JUNO_RUNTIME_DIR/sv/sock" <<'PY' >/dev/null 2>&1
import socket, struct, sys, time
socks = []
for i in range(36):
    s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(struct.pack('<I',2)+b'\x05\x01'); socks.append(s); time.sleep(0.03)
for s in socks: s.close()
PY
sleep 2
timeout 8 "$JUNO" status sv >/dev/null 2>&1; rc=$?
[ $rc -eq 0 ]; r=$?; chk ctl-log-followers-bounded "supervisor answers after 36 'logs -f' clients came and went (rc $rc, 124 = hung)"
[ $rc -ne 0 ] && supkill sv
$JUNO stop sv --time 1 >/dev/null 2>&1
for n in '../x' 'a/b' '.hid' '..' "$(printf 'a%.0s' $(seq 1 65))" "$(printf 'a\nb')"; do
	"$JUNO" run --name "$n" -d -- true >/dev/null 2>&1; rc=$?
	[ $rc -ne 0 ] && [ ! -e "$JT/dt/x" ] && [ ! -e "$JT/x" ]; r=$?; chk "name-reject-$(printf '%s' "$n" | tr -c 'a-zA-Z0-9' _ | cut -c1-12)" "invalid cell name refused (rc $rc)"
done
mkdir -p "$JT/rt/sym1" "$JT/dt/sym1"; echo IMPORTANT > "$JT/victim1"; echo LOG > "$JT/victim2"; echo SPEC > "$JT/victim3"
ln -s "$JT/victim1" "$JT/rt/sym1/status.tmp"; ln -s "$JT/victim2" "$JT/dt/sym1/log"; ln -s "$JT/victim3" "$JT/dt/sym1/spec"
$JUNO run --name sym1 -d -- sh -c 'echo hi; sleep 2' >/dev/null 2>&1; sleep 1.5
[ "$(cat "$JT/victim1")" = IMPORTANT ] && [ "$(cat "$JT/victim3")" = SPEC ] && [ "$(cat "$JT/victim2")" = LOG ]; r=$?
chk state-dir-symlinks "planted status.tmp/spec/log symlinks in a pre-created state dir were followed (victim1: $(head -c 12 "$JT/victim1" | head -1), victim3: $(head -c 12 "$JT/victim3" | head -1))"
$JUNO stop sym1 --time 1 >/dev/null 2>&1
o=$(stat -c %a "$JT/dt/sv" "$JT/rt/sv/sock" 2>/dev/null | tr '\n' ' ')
$JUNO run --name pm -d -- sleep 20 >/dev/null; sleep 1
o=$(stat -c %a "$JUNO_RUNTIME_DIR/pm" "$JUNO_RUNTIME_DIR/pm/sock" "$JUNO_DATA_DIR/pm" "$JUNO_DATA_DIR/pm/log" | tr '\n' ' ')
[ "$o" = "700 600 700 600 " ]; r=$?; chk state-permissions "runtime dir, socket, data dir, log modes: $o"
$JUNO stop pm --time 1 >/dev/null 2>&1
o=$($JUNO run --name inj -d $A --env $'A=1\nbind = /home:/h\nkeep-cap = sys_admin' -- sh -c 'ls /h 2>&1 | head -1; grep CapEff /proc/self/status' 2>&1; sleep 1.5; cat "$JUNO_DATA_DIR/inj/log" 2>/dev/null | tr '\n' ' ')
echo "$o" | grep -q 'CapEff:[[:space:]]*0000000000000000'; r=$?; chk spec-newline-injection "env value with a newline cannot add spec keys (named cell): $o"
V=$(head -c 9000 /dev/zero | tr '\0' x)
$JUNO run --name bigenv -d --env "A=$V" -- true >/dev/null 2>&1; rc=$?
[ $rc -eq 0 ]; r=$?; chk spec-long-line "a 9000-byte env value starts as a named cell (rc $rc)"
$JUNO run --name del -d -- sleep 25 >/dev/null; sleep 1
dsp=$(grep '^supervisor=' "$JUNO_RUNTIME_DIR/del/status" | cut -d= -f2); dcp=$(grep '^pid=' "$JUNO_RUNTIME_DIR/del/status" | cut -d= -f2)
rm -rf "${JUNO_RUNTIME_DIR:?}/del"
for i in $(seq 60); do kill -0 "$dsp" 2>/dev/null || break; sleep 0.1; done
kill -0 "$dsp" 2>/dev/null; sa=$?; kill -0 "$dcp" 2>/dev/null; ca=$?
[ $sa -ne 0 ] && [ $ca -ne 0 ]; r=$?; chk state-dir-deleted-cell-controllable "runtime dir deleted under a running cell: the supervisor stopped the cell and exited (supervisor alive=$((1-sa)), cell alive=$((1-ca)))"
$JUNO run --name lgr -d -- sh -c 'yes | head -c 300000000' >/dev/null; sleep 2
sz=$(stat -c %s "$JUNO_DATA_DIR/lgr/log" 2>/dev/null || echo 0)
[ "$sz" -lt 100000000 ]; r=$?; chk log-growth-bounded "log of a flooding payload reached $((sz/1000000)) MB in 2 s"
"$JUNO" rm -f lgr >/dev/null 2>&1

# --- published ports ---------------------------------------------------------------------
P1=$(pickport); P2=$(pickport)
cat > "$JT/two.py" <<'PY'
import socket, http.server
a = socket.socket(); a.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); a.bind(('127.0.0.1', 9001)); a.listen(0)
http.server.HTTPServer(('127.0.0.1', 9002), http.server.SimpleHTTPRequestHandler).serve_forever()
PY
$JUNO run --name pub -d --bind-ro "$JT/two.py:/two.py" --publish "$P1:9001" --publish "$P2:9002" -- python3 /two.py >/dev/null 2>&1; sleep 1.5
curl -s -m 3 -o /dev/null "http://127.0.0.1:$P2/"; [ $? -eq 0 ]; r=$?; chk publish-works "published port answers"
python3 - "$P1" <<'PY'
import socket, sys
k = []
for i in range(6):
    s = socket.socket(); s.settimeout(1)
    try: s.connect(('127.0.0.1', int(sys.argv[1]))); k.append(s)
    except Exception: pass
PY
t0=$(date +%s.%N); curl -s -m 20 -o /dev/null "http://127.0.0.1:$P2/"; t1=$(date +%s.%N)
d=$(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.1f", b - a }')
awk -v t="$d" 'BEGIN { exit !(t < 2) }'; r=$?; chk publish-no-head-of-line-blocking "second published port answered in ${d}s while the first listener was wedged"
$JUNO stop pub --time 1 >/dev/null 2>&1
P3=$(pickport)
( ulimit -n 256; exec "$JUNO" run --name pub2 -d --publish "$P3:8080" -- python3 -m http.server 8080 --bind 127.0.0.1 >/dev/null 2>&1 ); sleep 1.5
SP=$(grep '^supervisor=' "$JUNO_RUNTIME_DIR/pub2/status" 2>/dev/null | cut -d= -f2); CP=$(grep '^pid=' "$JUNO_RUNTIME_DIR/pub2/status" 2>/dev/null | cut -d= -f2)
FW=$(ps --no-headers -o pid --ppid "${SP:-0}" 2>/dev/null | tr -d ' ' | grep -vx "${CP:-0}" | head -1)
if [ -n "$FW" ]; then
	python3 - "$P3" "$FW" <<'PY' >"$JT/cpu.out" 2>&1
import socket, sys, time, os
port, fw = int(sys.argv[1]), sys.argv[2]
socks = []
try:
    for i in range(400):
        socks.append(socket.create_connection(('127.0.0.1', port), timeout=2))
except Exception: pass
def ticks():
    t = open('/proc/%s/stat' % fw).read().split(); return int(t[13]) + int(t[14])
time.sleep(1); c0 = ticks(); time.sleep(2)
print(len(socks), len(os.listdir('/proc/%s/fd' % fw)), ticks() - c0)
PY
	set -- $(cat "$JT/cpu.out"); conns=$1; fds=$2; ticks=${3:-0}
	[ "${ticks:-0}" -lt 50 ]; r=$?; chk publish-fd-exhaustion "forwarder with nofile 256 after $conns idle connections ($fds fds): ${ticks} cpu ticks in 2 s (200 = a spinning core)"
else skp publish-fd-exhaustion "forwarder not found"; fi
$JUNO stop pub2 --time 1 >/dev/null 2>&1

# --- nesting ----------------------------------------------------------------------------------
IN="env JUNO_RUNTIME_DIR=/tmp/rt JUNO_DATA_DIR=/tmp/dt TMPDIR=/tmp /juno run"
o=$(J --bind-ro "$JUNO:/juno" -- /juno run -- true 2>&1 | head -1)
case $o in *"not allowed"*) r=0;; *) r=1;; esac; chk nesting-off-refuses-inner "inner cell without nesting: $o"
o=$(J --nesting --bind-ro "$JUNO:/juno" $A -- sh -c "$IN --bind-ro /adv:/adv --seccomp off -- sh -c '/adv caps | grep -E \"CapEff|Seccomp:|NoNew\" | tr -s \"\\t \" \" \" | tr \"\\n\" \" \"'" 2>&1)
[ "$o" = "CapEff: 0000000000000000 NoNewPrivs: 1 Seccomp: 2 " ]; r=$?; chk nesting-inner-cannot-shed "inner cell with --seccomp off still filtered, no caps: $o"
mkdir -p "$JT/ro2"; echo d > "$JT/ro2/f"
J --nesting --bind-ro "$JT/ro2:/data" --bind-ro "$JUNO:/juno" -- sh -c "$IN --bind /data:/d --keep-cap sys_admin -- sh -c 'mount -o remount,rw,bind /d; echo x > /d/new'" >/dev/null 2>&1
[ ! -e "$JT/ro2/new" ]; r=$?; chk nesting-ro-bind-locked "inner sys_admin cell could not make the outer read-only bind writable"

# --- agent preset ---------------------------------------------------------------------------------
mkdir -p "$JT/ws"
o=$(J --preset agent --mem-fallback rlimit --workspace "$JT/ws" $A -- sh -c 'for p in /etc/n /usr/n /run/n /dev/shm/n /n /proc/self/comm; do /adv write $p x | cut -d" " -f1; done | sort -u | tr "\n" " "')
[ "$o" = "DENIED " ]; r=$?; chk agent-writes-confined "agent preset writes outside /work and /tmp: $o"
o=$(J --preset agent --mem-fallback rlimit --workspace "$JT/ws" $A -- /adv write /work/ok x | cut -d' ' -f1)
[ "$o" = OK ]; r=$?; chk agent-workspace-writable "agent can write its workspace: $o"
o=$(J --preset agent --mem-fallback rlimit $A -- sh -c 'ls /home /root 2>&1 | grep -vc "No such"')
[ "$o" = 0 ]; r=$?; chk agent-no-host-home "agent sees no /home or /root"

echo "SUMMARY adversarial.sh: $pass passed, $fail failed, $skip skipped"
[ $fail -eq 0 ]
