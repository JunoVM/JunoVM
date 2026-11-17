# juno command line

`juno` is a thin wrapper over libjuno. Exit status of `run` is the payload's (`128+N` for a signal), 124 on timeout, 125 when the cell could not start, 2 for usage errors.

## Commands

| Command | Meaning |
|---|---|
| `juno probe` | Print what the host supports (userns, overlay, Landlock ABI, seccomp, cgroup v2 delegation, pasta, subuid range). |
| `juno run [options] -- cmd [args]` | Start a cell and wait for it. With `--name` it is supervised and can be managed; with `-d` it detaches. |
| `juno ps` | List named cells: name, state, pid, uptime in seconds, restarts. Stale entries are removed. |
| `juno status NAME` | Print the supervisor's status (`state`, `pid`, `supervisor`, `started`, `restarts`, `exit`); for a finished cell the last exit. |
| `juno exec [-t] [--user U[:G]] NAME -- cmd [args]` | Run a command inside a named cell, using your stdio. `-t` allocates a pty. `--user` needs a cell started with `--idmap full`; a cell started with `--user` can be entered. |
| `juno stop NAME [--time S]` | SIGTERM, then SIGKILL after S seconds (default 10), wait for the supervisor to finish. |
| `juno kill NAME [SIG]` | Signal the cell's init (default TERM). Names: HUP INT QUIT KILL USR1 USR2 TERM CONT STOP, or a number. |
| `juno logs [-f] NAME` | Print the cell's log (`NAME -f` also works); `-f` follows while it runs. The log is capped (see `--log-max`) with one rotation to `log.1`. |
| `juno rm [-f] NAME` | Remove state and data of a stopped cell; `-f` stops a running one first. |
| `juno net ls` / `juno net rm NAME` | List or remove shared networks (columns: name, holder pid, member cells). |
| `juno up DIR` / `juno down DIR` | Start every `DIR/*.cell` file as a named detached cell (sorted order); `down` stops and removes them in reverse order. |
| `juno rmtree PATH...` | Remove trees that contain files owned by your subuids. |

## `run` options

Options take their value as the next argument or as `--opt=value`. Later options override earlier ones; a preset is applied first.

| Option | Meaning | Default |
|---|---|---|
| `--name NAME` | Supervise as a named cell. Letters, digits, `.`, `_`, `-`, up to 64 characters, not starting with `.` or `-`. | unnamed |
| `-d`, `--detach` | Run the supervisor in the background (needs `--name`). | foreground |
| `-t`, `--tty` | Give the payload a pty (not with `--name`). | off |
| `--spec FILE` | Load a spec file first (see spec.md). | none |
| `--preset agent\|service` | Apply a preset. | none |
| `--workspace DIR` | Agent preset: bind DIR at `/work`, cwd `/work`, Landlock rw there. | none |
| `--broker SOCKET` | Agent preset: bind a host socket at `/run/broker.sock`. | none |
| `--root host-ro\|dir:PATH\|overlay[:UPPER]` | Root kind. `overlay` needs `--layer`; without UPPER a named cell uses its data dir. | `host-ro` |
| `--layer PATH` | Lower layer of an overlay root (repeatable). | none |
| `--bind SRC:DST` / `--bind-ro SRC:DST` | Bind a host path read-write / read-only. DST is absolute. | none |
| `--tmpfs DST` | A tmpfs at DST. | none |
| `--net none\|host\|shared:NAME\|nat\|nat:lan\|nat:host` | Network mode (see networking.md). | `none` |
| `--egress-deny CIDR` / `--egress-allow CIDR` | nat egress policy, repeatable (longest prefix wins). | none |
| `--egress-proxy-allow HOST:PORT` | Allow the in-cell CONNECT proxy to reach this endpoint (repeatable; works with `--net none`). | none |
| `--publish [ADDR:]HOSTPORT:CELLPORT` | Forward a host TCP port into the cell. Not with `--net host`. | none |
| `--hostname N` | UTS name, up to 64 characters. | `juno` |
| `--env K=V` | Set a variable. The environment is otherwise empty except `PATH`. | none |
| `--cwd P` | Working directory (absolute). | `/` |
| `--mem BYTES` | Memory limit through cgroup `memory.max`. Without a usable delegated cgroup the start is refused. | none |
| `--mem-fallback rlimit` | Accept `RLIMIT_AS` (per process, tmpfs not counted) when no cgroup is usable. | off |
| `--tmp-size`, `--run-size`, `--shm-size`, `--tmpfs-size` | Size caps (bytes, K/M/G) of `/tmp`, `/run`, `/dev/shm` and `--tmpfs` mounts. | 256M, 64M, 64M, 256M |
| `--log-max BYTES` | Log size before the single rotation. | 10M |
| `--pids N` | Task limit: cgroup `pids.max`, else `RLIMIT_NPROC`. | none |
| `--nofile N` | `RLIMIT_NOFILE`. | inherited |
| `--cpu-weight N` | cgroup `cpu.weight` (needs cgroups; start fails without). | none |
| `--timeout SECONDS` | Wall-clock limit (fractions allowed); exit 124. | none |
| `--seccomp default\|strict\|off` | Syscall filter. `strict` also denies mount family, ptrace, process_vm, setns. | `default` |
| `--keep-cap CAP` | Keep a capability (name like `sys_admin`, or number). Repeatable. `sys_admin` prints a warning: it lets the cell remount `--bind-ro` mounts read-write. `net_admin` is refused with `net = nat`. | none kept |
| `--landlock-ro PATH` / `--landlock-rw PATH` | Landlock rule (read-only / read-write below PATH). Once any rule exists everything else is denied. | none |
| `--init tiny\|none` | `tiny` reaps and forwards signals; `none` execs the payload as pid 1. | `tiny` |
| `--nesting` | Allow the payload to start cells (user namespaces, setfcap kept, delegated cgroup if available). | off |
| `--restart no\|on-failure\|always`, `--max-restarts N` | Supervisor restart policy (backoff 100 ms doubling to 5 s). | `no`, 10 |
| `--compat32` | x86_64: also filter 32-bit syscalls instead of killing 32-bit programs. | off |
| `--idmap full\|single` | `full` maps cell ids 1.. onto your subuid range via newuidmap. | `single` |
| `--user UID[:GID]` | Drop to this id before the payload (needs `--idmap full`; no keep-cap or nesting). | root |

`landlock-ro-opt` and `landlock-rw-opt` (skip a missing path) exist as spec keys only.

## Examples that were run

```
$ juno run -- echo hello
hello
$ juno run --name web -d --publish 39777:8080 -- python3 -m http.server 8080 --bind 127.0.0.1
$ juno ps
NAME                 STATE       PID      UPTIME   RESTARTS
web                  running     92361    1        0
$ juno exec web -- hostname
juno
$ juno stop web
$ juno run --timeout 1 -- sleep 5; echo rc=$?
rc=124
$ juno kill nosuch
juno: kill: cell 'nosuch' is not running (No such file or directory)
```

Environment: `JUNO_RUNTIME_DIR` (default `$XDG_RUNTIME_DIR/juno`, else `/tmp/juno-UID`) holds lock, socket and status of running cells; `JUNO_DATA_DIR` (default `$XDG_DATA_HOME/juno`, else `~/.local/share/juno`) holds `spec`, `log`, `last`, and the overlay upper. `TMPDIR` holds the short-lived stage directory.
