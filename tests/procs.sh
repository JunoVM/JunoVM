# Copyright 2026, Dario Casalinuovo.
# SPDX-License-Identifier: LGPL-2.1-or-later
# Helpers shared by every test script. Other juno users may run on the same host, so a
# process counts as ours only when our private JUNO_RUNTIME_DIR is in its environment
# (supervisors, holders, forwarders, proxies and pasta inherit it; nothing else does).
mine() {
	local proc_dir pid comm parent seen=""

	for proc_dir in /proc/[0-9]*; do
		pid=${proc_dir#/proc/}
		[ "$pid" = "$$" ] && continue
		[ -r "$proc_dir/environ" ] 2>/dev/null || continue
		tr '\0' '\n' < "$proc_dir/environ" 2>/dev/null | grep -qxF "JUNO_RUNTIME_DIR=$JUNO_RUNTIME_DIR" || continue
		comm=$(cat "$proc_dir/comm" 2>/dev/null)
		case "$comm" in bash|sh|tr|grep|cat|timeout|sleep|ls|python3|juno_helper|"") continue;; esac
		echo "$pid $comm"
		seen="$seen $pid "
	done

	# pasta keeps its environment private (not dumpable): find it as a child of one of ours
	for proc_dir in /proc/[0-9]*; do
		pid=${proc_dir#/proc/}
		case "$seen" in *" $pid "*) continue;; esac
		[ "$(cat "$proc_dir/comm" 2>/dev/null | cut -c1-5)" = pasta ] || continue
		parent=$(awk '{print $4}' "$proc_dir/stat" 2>/dev/null)
		case "$seen" in *" $parent "*) echo "$pid pasta";; esac
	done
}
count_mine() { mine | grep -c "$1"; }
# a base port such that base..base+N-1 are all free right now
freebase() {
	python3 - "$1" <<'PY'
import random, socket, sys

count = int(sys.argv[1])
while True:
    base = random.randint(20000, 60000 - count)
    sockets = []
    try:
        for offset in range(count):
            sock = socket.socket()
            sock.bind(("0.0.0.0", base + offset))
            sockets.append(sock)
        print(base)
        break
    except OSError:
        pass
    finally:
        for sock in sockets:
            sock.close()
PY
}
