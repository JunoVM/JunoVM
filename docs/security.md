# Security model

junovm gives a payload a different view of the system and takes away what it does not need, using only unprivileged kernel features. It is not a virtual machine: the payload shares the host kernel. `tests/adversarial.sh` is the attack suite (a FAIL line means the attack got through).

## Layers, outermost first
1. **User namespace.** The cell's root (uid 0) is your own uid on the host (`idmap single`), or with `--idmap full` ids 1.. map to your subuid range. Root in the cell owns nothing outside it.
2. **Mount namespace and pivot_root.** The old root is detached before the payload runs. The payload sees only what the root kind and the binds provide.
3. **PID, IPC, UTS, cgroup namespaces.** Host processes and SysV/POSIX IPC are invisible; signals to host pids fail.
4. **Network namespace** (except `net host`; see networking.md).
5. **Capabilities.** The bounding, ambient, effective, permitted and inheritable sets are cleared, except `--keep-cap`. The same code path runs for `run`, `--init none`, `--user` and `exec` (tested).
6. **no_new_privs.** Set on every path.
7. **Landlock** when rules are given (the agent preset does).
8. **seccomp** deny-list: kexec, module loading, bpf, perf_event_open, keyrings, userfaultfd, open_by_handle_at, swap, reboot, clock setting, ioperm/iopl, acct, quotactl, and nested user namespaces (`clone`/`unshare` with CLONE_NEWUSER, `clone3` answered with ENOSYS) unless `--nesting`. `strict` adds mount-family, ptrace, process_vm, setns, chroot, hostname calls. 32-bit programs are killed unless `--compat32`.
9. **Limits:** rlimits always; cgroup v2 `memory`/`pids`/`cpu` only with a delegated cgroup (`juno probe`).
Fds: only 0-2 and explicitly passed fds survive into the payload (tested for run, exec, detached, nat, shared).

## Hardening order and seccomp details
The payload's restrictions are applied in this order: rlimits, descriptor hygiene (`close_range` on everything except stdio and passed fds; `O_CLOEXEC` is not relied on), `no_new_privs`, Landlock, capabilities, then seccomp last, so the filter covers the payload and nothing before it needs an exemption.
- The filter checks the architecture first and kills on a mismatch; x32 system calls are killed. Denied calls return `EPERM`; only a wrong architecture kills.
- `clone3` passes its flags in memory, which a filter cannot inspect, so every `clone3` returns `ENOSYS` and the C library falls back to `clone`. A program calling `clone3` directly with no fallback fails.
- `--compat32` adds a second branch for 32-bit programs with its own deny list.
- Landlock rules only ever tighten, so they stay in force in nested cells.
- Without a delegated cgroup, `RLIMIT_NPROC` and `RLIMIT_AS` are the only limits; `juno probe` reports which is in effect. A CPU weight without cgroups fails the start.

## Nesting
Nesting is off by default because user-namespace creation exposes more kernel code. With `--nesting` the filter permits it, the cell keeps `CAP_SETFCAP`, and with usable cgroups it gets a delegated subtree so an inner cell is still bound by the outer limits. User namespaces, capabilities, seccomp, Landlock, `no_new_privs` and inherited mounts only narrow in inner cells. Without cgroups an outer process limit does not bound an inner cell (`RLIMIT_NPROC` is counted per user namespace). An inner cell reaches only the network its parent forwards to it.

## What each root exposes
`host-ro`: the host's `/usr`, `/bin`, `/lib*` read-only and selected `/etc` files. Anything readable there by your uid is readable by the payload (including setuid binaries, which do nothing under no_new_privs). No `/home`, `/root`, `/var`, `/sys`.
`dir:PATH`: the whole directory, writable. Treat its content as hostile if it is: mount points that are symlinks make the start fail (tested).
`overlay`: lower layers read-only; the upper lives in the data dir and is written by the payload.
Binds expose exactly their source; `--bind` is read-write for the payload (as your uid).

## What is not protected (honest limits)
- The shared kernel: seccomp is a deny-list, not an allow-list; many subsystems remain reachable (the default filter does deny io_uring, kcmp, the NUMA calls, `personality` other than 0, and the other entries listed in `docs/spec.md`). Use `--seccomp strict` and Landlock for less trusted code; use a VM for hostile code.
- `--keep-cap sys_admin` lets the payload remount `--bind-ro` mounts writable (the binds belong to the cell's own mount namespace). The CLI prints a warning; do not combine it with binds you need read-only.
- Memory: only a delegated cgroup enforces `--mem` (tmpfs pages are charged to it, the sizes of `/tmp`, `/run` and `/dev/shm` are capped by default at 256 MiB, 64 MiB and 64 MiB and configurable). Without a cgroup `--mem` and the agent preset's 2 GiB limit **refuse to start**; `--mem-fallback rlimit` opts in to `RLIMIT_AS`, which is per process and does not count tmpfs.
- `net host` shares abstract unix sockets and loopback services with the host. `nat` reaches only the public internet by default (see networking.md), but DNS can resolve any name through the forwarder.
- `/proc` is not masked: `/proc/modules`, `/proc/meminfo` (host memory), `/proc/self/mountinfo` (host device names and bind sources) are readable.
- Control socket and state dirs are protected only by user id and 0700/0600 modes (the supervisor refuses to use a state directory that is not a plain directory owned by you with mode 0700). Another process of the same user can control any cell.
- Published ports are TCP only. Cells on a shared network share one loopback and cannot bind the same port. `idmap full` cannot be combined with a shared network.
- Only x86-64 has been run; the arm64 filter branch is untested. The cgroup-enforced paths are exercised only where a delegated cgroup exists.
- Shared-net, exec and nesting cells keep `CAP_SETFCAP` only where documented in cli.md.

## What the cell init is
With `--init tiny` pid 1 of the cell is `juno-init`, a separate static program that the cell's init process `execve`s after forking the payload. The payload therefore sees an empty environment and a command line of `juno-init PID MS FD` in `/proc/1`, and none of the launcher's memory. `--init none` makes the payload pid 1. Cells call `setsid()`, so they never share the launcher's controlling terminal (`/dev/tty` only works with `-t`).

## Running untrusted code
- Start with the agent preset: `juno run --preset agent --workspace DIR --timeout N -- cmd`. Writes are limited to the workspace and `/tmp`, no network, strict seccomp, 256 tasks. Run it inside a delegated cgroup scope (the preset refuses to start without one; `--mem-fallback rlimit` accepts the weaker limit). Add `--mem` only on a host where `juno probe` says cgroup delegation is usable, and check `ps`/`status` instead of trusting it otherwise.
- The payload cannot read the launcher's environment or memory through `/proc/1` (the init is a fresh image), but still keep secrets out of the cell: bind only what it needs.
- Never mount secrets, sockets (D-Bus, X11, ssh-agent, docker) or `$HOME` into the cell.
- Prefer `net none`; if the payload needs a few HTTPS endpoints use `--egress-proxy-allow HOST:PORT`; if it needs the internet use `nat` (the LAN, link-local addresses and the gateway are unreachable by default).
- Treat anything the payload wrote (workspace, overlay upper, logs) as untrusted data: symlinks, huge files and very deep trees are possible (`juno rm` removes deep trees iteratively).
