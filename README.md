# junovm

junovm runs a process tree in a *cell*: Linux namespaces, a private root, limits and a security policy, started by an ordinary user.
It is one C library (`libjuno`) plus a `juno` command and a small static init (`juno-init`); there is no daemon, no image registry and no dependency beyond libc.
Named cells get a small supervisor with a control socket (status, stop, exec, logs, restart policy).
It supports published TCP ports, shared networks, outbound `nat` through `pasta` with an egress policy, an HTTP CONNECT egress proxy for cells without a network, uid maps through `newuidmap`, and the presets `agent` and `service`.
The backend is namespaces only (`ns`).

## Requirements
Linux 5.15 or later with unprivileged user namespaces (developed on 6.12); Landlock and seccomp are used when present. Optional: `pasta` (package `passt`) for `--net nat`, `newuidmap`/`newgidmap` (package `uidmap`) and a subuid range for `--idmap full`, a delegated cgroup v2 subtree for memory/pid/cpu limits (`systemd-run --user --scope -p Delegate=yes juno ...`).

## Build and install
```
make                 # build/libjuno.a, build/juno, build/juno-init and the test helpers
make test            # functional suites, trials, install test and the adversarial suite
make test-asan       # the same under AddressSanitizer and UBSan
make test-adversarial
make install PREFIX=/usr/local DESTDIR=   # juno, libjuno.a, juno.h, juno.pc and libexec/juno/juno-init
```
`juno-init` is the program that runs as pid 1 of every cell with the default `--init tiny`. It is found through `$JUNO_INIT`, the path compiled into the library, `../libexec/juno/juno-init` next to the running binary, the usual prefixes, or (inside a nesting cell) `/dev/.juno-init`. A start fails if it cannot be found.

## Five-minute tour
```
$ build/juno run -- echo hello
hello

$ build/juno run --name web -d --publish 39777:8080 -- python3 -m http.server 8080 --bind 127.0.0.1
$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:39777/
200
$ build/juno ps
NAME                 STATE       PID      UPTIME   RESTARTS
web                  running     92361    1        0
$ build/juno exec web -- hostname
juno
$ build/juno stop web

$ examples/agent/run.sh /tmp/ws sh -c 'echo ok > /work/out; echo no > /etc/x'
sh: 1: cannot create /etc/x: Permission denied

$ build/juno up examples/web          # starts every examples/web/*.cell
files: started
web: started
$ build/juno down examples/web
web: stopped and removed
files: stopped and removed
```
Embedding: `make -C examples && examples/embed` (see docs/api.md).

## Documentation
- `docs/cli.md` every command and option
- `docs/spec.md` spec file keys, presets, root kinds
- `docs/api.md` the C API and an embedding example
- `docs/networking.md` network modes, egress policy, egress proxy, published ports
- `docs/security.md` isolation layers and honest limits

## Known limits
It shares the host kernel: a deny-list seccomp filter is not a sandbox for hostile code, use a VM for that. Memory limits need a delegated cgroup and are refused without one unless you opt in to the weaker per-process `RLIMIT_AS` (`--mem-fallback rlimit`). `--keep-cap sys_admin` defeats `--bind-ro`. The control socket and state directories are protected by uid and mode only. See `docs/security.md`.

## Licence
LGPL-2.1-or-later. See `LICENSE`.
