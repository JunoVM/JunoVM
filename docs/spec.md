# Spec files

A spec is a text file of `key = value` lines. Blank lines and lines starting with `#` are ignored; whitespace around key and value is trimmed. Lines may be up to 8 MiB and values up to 1 MiB. In values a backslash starts an escape: `\\`, `\n`, `\r`, `\xHH` (anything else keeps its backslash); `juno_spec_save` writes values this way, so a value can never add or change another key. Every key is also a `juno run` option of the same name (`--key value`), and `juno run --spec FILE` loads one. `juno up DIR` reads `DIR/*.cell` files in this format; the cell name is the file name without `.cell`. Later lines override earlier ones for single-valued keys and add for repeatable ones.

## Keys

| Key | Value | Default | Repeatable |
|---|---|---|---|
| `root` | `host-ro`, `dir:PATH`, `overlay`, `overlay:UPPER` | `host-ro` | no |
| `layer` | lower directory of an overlay root (no `,` or `:` in the path) | none | yes |
| `bind` / `bind-ro` | `SRC:DST` (DST absolute) | none | yes |
| `tmpfs` | `DST` | none | yes |
| `net` | `none`, `host`, `shared:NAME`, `nat`, `nat:lan`, `nat:host` | `none` | no |
| `egress-deny`, `egress-allow` | `ADDR[/N]` (nat egress policy) | none | yes |
| `egress-proxy-allow` | `HOST:PORT`, host may start with `*.` | none | yes |
| `mem-fallback` | `rlimit` (accept `RLIMIT_AS` when no cgroup is usable), `none` | `none` | no |
| `tmp-size`, `run-size`, `shm-size`, `tmpfs-size` | bytes, optional K/M/G suffix: `/tmp`, `/run`, `/dev/shm`, user `tmpfs` mounts | 256M, 64M, 64M, 256M | no |
| `log-max` | bytes; the log is rotated once when it passes this | 10M | no |
| `publish` | `[A.B.C.D:]HOSTPORT:CELLPORT`, ports 1-65535; address default `127.0.0.1` | none | yes |
| `hostname` | up to 64 characters | `juno` | no |
| `env` | `NAME=VALUE` | none (only `PATH` is added) | yes |
| `cwd` | absolute path | `/` | no |
| `mem`, `pids`, `nofile`, `cpu-weight` | unsigned integer (decimal, `0x`, or octal with leading 0) | unset | no |
| `timeout` | seconds, finite, 0 to 3e8 | unset | no |
| `seccomp` | `default`, `strict`, `off` | `default` | no |
| `keep-cap` | capability name (`sys_admin`) or number 0-63 | none | yes |
| `landlock-ro`, `landlock-rw` | path | none | yes |
| `landlock-ro-opt`, `landlock-rw-opt` | same, ignored when the path does not exist | none | yes |
| `init` | `tiny`, `none` | `tiny` | no |
| `nesting` | `allow`, `deny` | `deny` | no |
| `compat32` | `yes`, `no` (x86_64 only) | `no` | no |
| `idmap` | `full`, `single` | `single` | no |
| `user` | `UID[:GID]` (0-65535) | unset (root) | no |
| `restart` | `no`, `on-failure`, `always` | `no` | no |
| `max-restarts` | 0 to 1000000 | 10 | no |
| `preset` | `agent`, `service` | none | no |
| `workspace`, `broker` | agent preset parameters (see below) | none | no |
| `argv` | the command, shell-style words (`'single'`, `"double"`, backslash) | required | no |

Unknown keys are an error with the line number (`FILE:LINE: unknown key 'x'`).

## Presets

Presets are ordinary option lists applied first; anything after them overrides.

`agent` sets:
```
root = host-ro        net = none          seccomp = strict     nesting = deny
pids = 256            nofile = 1024       env = HOME=/work
landlock-ro = /
landlock-rw-opt = /tmp, /dev/null, /dev/zero, /dev/full, /dev/random, /dev/urandom
mem = 2147483648      (the start is refused when no delegated cgroup is usable, unless mem-fallback = rlimit)
```
`workspace = DIR` adds `bind = DIR:/work`, `cwd = /work`, `landlock-rw = /work`. `broker = SOCK` adds `bind = SOCK:/run/broker.sock`.

`service` sets `restart = on-failure`, `seccomp = default`, `idmap = full` if newuidmap and a subuid range exist (else `single`), `net = nat` if `pasta` is in PATH (else `none`).

## Root kinds

- `host-ro`: a 4 MB tmpfs with the host's `/usr`, `/bin`, `/sbin`, `/lib*` bound read-only, a generated `/etc` (passwd, group, hosts, hostname, nsswitch.conf, plus read-only `ld.so.cache`, `ld.so.conf(.d)`, `alternatives`, `ssl/certs`, `ca-certificates`, `localtime`, and the host `resolv.conf` with `net = host`), fresh `/proc`, `/dev`, `/tmp`, `/run`.
- `dir:PATH`: PATH is bind-mounted as the root, writable. `/proc`, `/dev`, `/tmp`, `/run` are mounted over it; they must be directories or absent, symlinks make the start fail.
- `overlay`: read-only `layer`s plus a writable upper directory (named cells: `$JUNO_DATA_DIR/NAME/upper`).

Example spec (run and verified):
```
hostname = specdemo
argv = hostname
```
```
$ juno run --spec a.spec
specdemo
```

## Default seccomp deny list
kexec_load/kexec_file_load, init_module/finit_module/delete_module, bpf, perf_event_open, add_key/request_key/keyctl, userfaultfd, open_by_handle_at, name_to_handle_at, swapon/swapoff, reboot, settimeofday, clock_settime, clock_adjtime, adjtimex, iopl, ioperm, acct, quotactl, lookup_dcookie, io_uring_setup/enter/register, kcmp, pidfd_getfd, process_madvise, move_pages, mbind, migrate_pages, set_mempolicy, vhangup, syslog, nfsservctl, uselib, ustat, sysfs, _sysctl, fanotify_init; `personality` except 0 and 0xffffffff; `clone`/`unshare` with CLONE_NEWUSER and `clone3` (answered ENOSYS so libc falls back) unless `nesting` is on. `strict` adds the mount family, ptrace, process_vm_*, setns, sethostname, chroot, pivot_root, `unshare`, and `clone` with any CLONE_NEW* flag. With `compat32` the same lists apply to i386 syscall numbers (including i386 `clone3`).
