/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef JUNO_NS_H
#define JUNO_NS_H

#include "../internal.h"
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>

/* Everything the child needs between clone3 and exec is computed here, in the
 * parent, so the child never allocates or touches stdio. */
struct ns_ctx {
	const juno_spec *spec;
	int errfd, syncfd;
	const char *stage;
	const char *workdir;
	char **envp;
	int cg;			/* 0 none, 1 limits in a cgroup, 2 cgroup with a delegated subtree */
	int shared, userfd, netfd, ipfd;
	int tmofd;		/* init reports a timeout here (one byte) */
	int ttyfd;		/* run -t: the pty master is sent here */
	int master, slave;
	char hostname[72];
	char hosts[200];
	char netreg[600];
	char passwd[400], group[200];
	char initpath[600];		/* host path of the static init, bound into the cell */
	char tmpopt[64], runopt[64], shmopt[64], utmpopt[64];	/* tmpfs options with size caps */
	struct ns_egress_rule { uint32_t addr; unsigned char plen, action; } egress_rules[48];
	int egress_count;
	int pivoted;
};

#include <sys/syscall.h>
#include <signal.h>
#include <unistd.h>
/* libc fork() takes the malloc locks, which a clone3 child of a threaded
 * process may inherit held; the child path forks with the bare syscall. */
static inline pid_t ns_rawfork(void) { return (pid_t)syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0); }

#define NS_INIT_IN_CELL "/dev/.juno-init"
#define ERRMSG_MAX 300
struct ns_err { int err; char step[ERRMSG_MAX]; };

/* tiny formatter for the child: %s %d %u %% only */
size_t ns_fmt(char *buf, size_t n, const char *fmt, ...);
size_t ns_vfmt(char *buf, size_t n, const char *fmt, va_list ap);

void ns_die(struct ns_ctx *c, const char *fmt, ...) __attribute__((noreturn));

int ns_write_idmap(pid_t pid, uid_t uid, gid_t gid);
int ns_write_idmap_full(pid_t pid, char *err, size_t elen);
int ns_proxy_spawn(const juno_spec *s, int pidfd, juno_cell *cell);
int ns_init_find(char *out, size_t len);
int ns_egress_plan(const juno_spec *s, struct ns_ctx *c);
int ns_egress_apply(struct ns_ctx *c);
void ns_wait_gateway(void);
int ns_pasta_start(const juno_spec *s, pid_t cellpid, juno_cell *cell);

int ns_build_root(struct ns_ctx *c);
int ns_mount_dev(int rootfd, const char *shmopt);
int ns_net_up(void);
int ns_open_in(int root_fd, const char *rel, int is_file);
int ns_mount_at(int root_fd, const char *src, const char *rel, const char *type,
	unsigned long flags, const char *data, int is_file, int readonly);

int ns_fds_prepare(struct ns_ctx *c);
void ns_keep(int fd);
int ns_harden(struct ns_ctx *c);
void ns_cgroup_delegate(struct ns_ctx *c);
int ns_run(struct ns_ctx *c) __attribute__((noreturn));
void ns_exec_payload(struct ns_ctx *c) __attribute__((noreturn));
char **ns_build_env(const juno_spec *s);
int ns_exec(juno_cell *cell, char *const argv[], int *status);
int ns_exec_tty(juno_cell *cell, char *const argv[], int *master, int *donefd);
int ns_exec_done(juno_cell *cell, int donefd, int *status);
int ns_open_pty(int *master, int *slave);
void ns_pty_prelude(struct ns_ctx *c);
int ns_recv_fd(int sock);
int ns_send_fd(int sock, int fd);

int ns_net_holder(const char *name, int *userfd, int *netfd);
int ns_net_register_path(const char *name, char *out, size_t len);

/* publish: bind listeners before the cell starts, serve them afterwards */
int ns_fwd_bind(const juno_spec *spec, int *listen_fds, int *cell_ports, int max);
int ns_fwd_spawn(juno_cell *cell, int *listen_fds, int *cell_ports, int count);

#define NS_SECCOMP_MAXINS 256
int ns_seccomp_build(int profile, int nesting, int compat32, struct sock_filter *out, int *n);
int ns_seccomp_apply(const juno_spec *s);
int ns_landlock_abi(void);
int ns_landlock_apply(const juno_spec *s, char *why, size_t wlen);

int ns_cgroup_probe(char *base, size_t blen, char *why, size_t wlen);
int ns_cgroup_attach(const juno_spec *s, pid_t pid, juno_cell *cell);
void ns_cgroup_remove(const char *path);

#endif
