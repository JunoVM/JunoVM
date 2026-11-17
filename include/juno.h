/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef JUNO_H
#define JUNO_H

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#define JUNO_VERSION "0.1.0"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct juno_spec juno_spec;
typedef struct juno_cell juno_cell;

enum { JUNO_ROOT_HOST_RO = 1, JUNO_ROOT_DIR, JUNO_ROOT_OVERLAY };
enum { JUNO_MOUNT_BIND = 1, JUNO_MOUNT_TMPFS };
#define JUNO_MNT_RO 0x1u
enum { JUNO_NET_NONE = 1, JUNO_NET_HOST, JUNO_NET_SHARED, JUNO_NET_NAT };
enum { JUNO_RESTART_NO = 0, JUNO_RESTART_ON_FAILURE, JUNO_RESTART_ALWAYS };
enum {
	JUNO_LIMIT_MEMORY = 1,	/* bytes */
	JUNO_LIMIT_PIDS,	/* tasks, including the cell init */
	JUNO_LIMIT_CPU_WEIGHT,	/* cgroup cpu.weight, 1..10000; cgroup only */
	JUNO_LIMIT_NOFILE,
	JUNO_LIMIT_TIMEOUT_MS,	/* enforced by juno_cell_wait() */
	JUNO_LIMIT_MAX
};
enum { JUNO_SECCOMP_DEFAULT = 0, JUNO_SECCOMP_STRICT, JUNO_SECCOMP_OFF };
enum { JUNO_INIT_TINY = 0, JUNO_INIT_NONE };
#define JUNO_LL_READ  0x1u
#define JUNO_LL_WRITE 0x2u
#define JUNO_LL_OPTIONAL 0x4u	/* skip the rule when the path does not exist */

juno_spec *juno_spec_new(void);
void       juno_spec_free(juno_spec *);
int        juno_spec_set_backend(juno_spec *, const char *name);
int        juno_spec_set_root(juno_spec *, int kind, const char *path);
int        juno_spec_add_layer(juno_spec *, const char *lower);
int        juno_spec_add_mount(juno_spec *, int kind, const char *src,
               const char *dst, unsigned flags);
int        juno_spec_set_net(juno_spec *, int mode, const char *name);
int        juno_spec_set_limit(juno_spec *, int which, uint64_t value);
int        juno_spec_set_seccomp(juno_spec *, int profile);
int        juno_spec_keep_cap(juno_spec *, int cap);
int        juno_spec_add_landlock(juno_spec *, const char *path, unsigned access);
int        juno_spec_set_argv(juno_spec *, char *const argv[]);
int        juno_spec_set_env(juno_spec *, const char *name, const char *value);
int        juno_spec_set_cwd(juno_spec *, const char *path);
int        juno_spec_set_hostname(juno_spec *, const char *name);
int        juno_spec_set_stdio(juno_spec *, int in, int out, int err);
int        juno_spec_pass_fd(juno_spec *, int host_fd, int cell_fd);
int        juno_spec_set_init(juno_spec *, int mode);
int        juno_spec_set_nesting(juno_spec *, int allow);
int        juno_spec_set_compat32(juno_spec *, int allow);	/* x86_64 only */
int        juno_spec_set_idmap_full(juno_spec *, int full);	/* cell ids 1.. map to the caller's subuid range */
int        juno_spec_set_user(juno_spec *, int uid, int gid);	/* gid < 0: same as uid */
int        juno_spec_apply_preset(juno_spec *, const char *name);	/* "agent", "service" */
int        juno_spec_set_tty(juno_spec *, int on);		/* give the payload a pty (run -t) */
int        juno_spec_add_publish(juno_spec *, const char *hostport_cellport);
int        juno_spec_set_restart(juno_spec *, int policy, int max_restarts);
/* Same keys as the CLI options and the text spec ("bind", "mem", "argv", ...). */
int        juno_spec_set_option(juno_spec *, const char *key, const char *value);
int        juno_spec_load(const char *path, juno_spec **out);
int        juno_spec_save(const juno_spec *, const char *path);

int        juno_start(const juno_spec *, juno_cell **out);
int        juno_cell_fd(const juno_cell *);	/* readable on exit */
int        juno_cell_pid(const juno_cell *);
int        juno_cell_wait(juno_cell *, int *status, int timeout_ms);
int        juno_cell_timed_out(const juno_cell *);
int        juno_cell_kill(juno_cell *, int sig);
void       juno_cell_free(juno_cell *);
/* Runs argv inside the cell using the caller's fds 0, 1 and 2; *status is a wait status. */
int        juno_cell_exec(juno_cell *, char *const argv[], int *status);
/* Same with a pty created inside the cell: returns its master and an fd to hand to
 * juno_cell_exec_wait() once it becomes readable. */
int        juno_cell_exec_tty(juno_cell *, char *const argv[], int *master, int *donefd);
int        juno_cell_exec_wait(juno_cell *, int donefd, int *status);
int        juno_cell_tty(const juno_cell *);	/* pty master of a spec with tty set, or -1 */
int        juno_cell_set_exec_user(juno_cell *, int uid, int gid);	/* user for later exec calls */

/* Named cells. juno_run_named supervises in this process (or a daemon when detach is set)
 * and returns the payload exit code (0 when detached and started) or a negative errno. */
int        juno_run_named(const juno_spec *, const char *name, int detach);
int        juno_cell_open(const char *name, juno_cell **out);
typedef void (*juno_list_fn)(const char *name, const char *state, int pid,
               long uptime_s, int restarts, void *ud);
int        juno_list(juno_list_fn fn, void *ud);
int        juno_cell_status(const char *name, char *buf, size_t len);
int        juno_cell_stop(const char *name, int grace_s);
int        juno_cell_signal(const char *name, int sig);
int        juno_cell_logs(const char *name, int follow, int fd);
int        juno_cell_remove(const char *name, int force);
int        juno_net_list(char *buf, size_t len);
/* juno up/down: every .cell file of DIR as a named detached cell; one report line per cell on out */
int        juno_up(const char *dir, FILE *out);
int        juno_down(const char *dir, FILE *out);
int        juno_rmtree(const char *path);	/* also removes files owned by the caller's subuids */
int        juno_idmap_full_available(char *why, size_t len);
int        juno_pasta_available(char *version, size_t len);
int        juno_net_remove(const char *name);

int        juno_probe(const char *backend, char *report, size_t len);
const char *juno_error(void);
int        juno_cap_from_name(const char *name_or_number);

#ifdef __cplusplus
}
#endif
#endif
