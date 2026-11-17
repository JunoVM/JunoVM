# C API (`include/juno.h`)

Link with `build/libjuno.a` (no other library; `-pthread` only if your program uses threads). Handles are opaque: `juno_spec` describes a cell, `juno_cell` is a running one.

## Errors
Functions return 0 (or a positive value where noted) on success and a negative errno on failure. `juno_error()` returns one line of detail for the last failure on the calling thread (thread-local buffer, valid until the next juno call on that thread).

## Spec
`juno_spec_new/free`, then setters: `set_backend` (only "ns"), `set_root(kind, path)` with `JUNO_ROOT_HOST_RO|DIR|OVERLAY`, `add_layer`, `add_mount(JUNO_MOUNT_BIND|TMPFS, src, dst, JUNO_MNT_RO)`, `set_net(JUNO_NET_NONE|HOST|SHARED|NAT, name)` (name: network name for shared, `"host"` for nat:host), `set_limit(JUNO_LIMIT_MEMORY|PIDS|CPU_WEIGHT|NOFILE|TIMEOUT_MS, v)`, `set_seccomp`, `keep_cap`, `add_landlock(path, JUNO_LL_READ|WRITE|OPTIONAL)`, `set_argv` (NULL-terminated, required), `set_env`, `set_cwd`, `set_hostname`, `set_stdio(in,out,err)` (-1 inherits), `pass_fd(host_fd, cell_fd)` (cell_fd >= 3), `set_init`, `set_nesting`, `set_compat32`, `set_idmap_full`, `set_user`, `apply_preset("agent"|"service")`, `set_tty`, `add_publish("[A.B.C.D:]HP:CP")`, `set_restart`; limits that have no setter (`mem-fallback`, tmpfs sizes, `log-max`, egress rules) go through `juno_spec_set_option`. Values may not exceed 1 MiB; the text form escapes newlines and backslashes, so no value can add keys to a saved spec. `juno_spec_set_option(key, value)` takes the same keys as the CLI and spec file. `juno_spec_load/save` read and write the text form. Any string is safe to pass: values are escaped in the text form and a spec is copied as a struct, never through text.

## Lifecycle
```
juno_start(spec, &cell)      /* returns when the payload has exec'd, or the setup error */
juno_cell_fd(cell)           /* pollable; readable once the cell has exited */
juno_cell_wait(cell, &status, timeout_ms)   /* -1 blocks, 0 polls; -ETIMEDOUT; status is a wait status */
juno_cell_timed_out(cell)    /* 1 if JUNO_LIMIT_TIMEOUT_MS killed it (the timeout is enforced inside juno_cell_wait and by the init) */
juno_cell_kill(cell, sig)    /* signal the cell's init */
juno_cell_free(cell)         /* kills a running cell, waits, releases everything */
```
`juno_cell_pid` is the host pid. `juno_cell_exec(cell, argv, &status)` runs a command inside using your fds 0-2; `juno_cell_exec_tty` returns a pty master and a done-fd to pass to `juno_cell_exec_wait`; `juno_cell_set_exec_user` selects the user for later execs.

Named cells: `juno_run_named(spec, name, detach)` supervises in this process (or in a daemon when `detach` is non-zero, returning 0 once started); `juno_cell_open(name, &cell)` gives a remote handle usable with `kill`, `wait`, `exec`; `juno_list`, `juno_cell_status`, `juno_cell_stop`, `juno_cell_signal`, `juno_cell_logs(name, follow, fd)`, `juno_cell_remove`, `juno_net_list`, `juno_net_remove`, `juno_up`, `juno_down`, `juno_rmtree`. Probes: `juno_probe("ns", buf, len)`, `juno_idmap_full_available`, `juno_pasta_available`.

## Threading
Specs and cells are not internally locked: use one handle from one thread at a time. Different handles are independent. `juno_error()` is per thread. `juno_start` forks helper processes; call it from a thread of a process that tolerates `fork` (no locks held in another thread that the child would need; the child side uses only raw syscalls). The cell's init is a separate static image (`juno-init`) exec'd inside the cell, so the payload cannot read the caller's memory or environment; `juno_start` fails if that image cannot be found (`$JUNO_INIT`, see README).

## Minimal embedding (`examples/embed.c`, built with `make -C examples`)
```c
juno_spec *spec = juno_spec_new();
char *cmd[] = { "echo", "hello from a cell", NULL };
juno_spec_set_argv(spec, cmd);
juno_spec_set_limit(spec, JUNO_LIMIT_TIMEOUT_MS, 10000);
juno_cell *cell;
if (juno_start(spec, &cell)) { fprintf(stderr, "%s\n", juno_error()); return 1; }
juno_spec_free(spec);
struct pollfd pf = { juno_cell_fd(cell), POLLIN, 0 };
while (poll(&pf, 1, -1) < 0) ;
int status; juno_cell_wait(cell, &status, 0);
juno_cell_free(cell);
```
Output of the full example:
```
$ ./embed
hello from a cell
cell pid 94677 exited with status 0
$ ./embed sh -c 'exit 3'
cell pid 94679 exited with status 3
```
