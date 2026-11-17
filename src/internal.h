/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef JUNO_INTERNAL_H
#define JUNO_INTERNAL_H

#include "juno.h"
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <linux/filter.h>

struct juno_mount { int kind; char *src, *dst; unsigned flags; };
struct juno_ll { char *path; unsigned access; };
struct juno_fdmap { int src, dst; };

struct juno_spec {
	char backend[16];
	int root_kind;
	char *root_path;
	char **layers; int nlayers;
	struct juno_mount *mounts; int nmounts;
	int net;
	uint64_t limit[JUNO_LIMIT_MAX];
	bool limit_set[JUNO_LIMIT_MAX];
	int seccomp;
	uint64_t keepcaps;
	struct juno_ll *ll; int nll;
	char **argv;
	char **env; int nenv;		/* "K=V" strings */
	char *cwd, *hostname;
	int stdio[3];
	struct juno_fdmap *fds; int nfds;
	int init;
	char *netname;
	int nesting, restart, max_restarts, compat32;
	bool nat_host, nat_lan, idmap_full, user_set;
	char **egress_deny, **egress_allow; int n_deny, n_allow;
	char **proxy_allow; int nproxy;
	int uid, gid;
	bool tty;			/* not saved */
	char **pubs; int npubs;
	bool die_with_parent;		/* not saved */
	bool mem_fallback;		/* RLIMIT_AS instead of a cgroup when none is usable */
	uint64_t tmp_size, run_size, shm_size, tmpfs_size, log_max;	/* 0 = default */
};

struct juno_backend;
struct juno_cell {
	const struct juno_backend *be;
	int pidfd, pid;
	bool done, timed_out;
	int status;
	uint64_t deadline_ms;		/* 0 = none */
	char *workdir, *cgroup;		/* removed on release */
	char *cgprocs;			/* cgroup.procs that exec'd processes join */
	char *rm_resolv;		/* resolv.conf mountpoint we created in a dir/overlay root */
	int tmofd, ttyfd;		/* init timeout report; pty master of run -t */
	int ipidfd;			/* the cell init (pidfd), may differ from pidfd */
	pid_t fwdpid;			/* publish forwarder */
	juno_spec *spec;		/* private copy, used by exec */
	char *name;			/* remote cell handle: control socket owner */
	pid_t pastapid, proxypid;			/* pasta attached to a nat cell */
	bool exec_user_set;
	int exec_uid, exec_gid;
};

struct juno_backend {
	const char *name;
	int (*probe)(char *report, size_t len);
	int (*start)(const juno_spec *, juno_cell *);
	int (*kill)(juno_cell *, int sig);
	int (*wait)(juno_cell *, int *status, int timeout_ms);
	int (*exec)(juno_cell *, char *const argv[], int *status);
	int (*exec_tty)(juno_cell *, char *const argv[], int *master, int *donefd);
	int (*exec_done)(juno_cell *, int donefd, int *status);
	void (*release)(juno_cell *);
};

extern const struct juno_backend juno_ns_backend;
const struct juno_backend *juno_backend_find(const char *name);
int juno_backend_need(const struct juno_backend *be, const char *name);

void juno_seterr(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
uint64_t juno_now_ms(void);
int juno_append(char ***arr, int *n, char *item);
int juno_spec_write(const juno_spec *s, FILE *f);
int juno_spec_read(FILE *f, const char *label, juno_spec **out);
juno_spec *juno_spec_dup(const juno_spec *s);
#define JUNO_MAX_VALUE (1u << 20)	/* longest accepted value; keeps every spec line far below the reader limit */
int juno_parse_cidr(const char *t, uint32_t *addr, int *plen);
int juno_spec_add_egress(juno_spec *s, int allow, const char *cidr);
int juno_spec_add_proxy_allow(juno_spec *s, const char *hp);
int juno_preset_param(juno_spec *s, const char *key, const char *value);
int juno_cgroups_usable(void);
int juno_put_file_at(int dfd, const char *name, const char *data, size_t n);
int juno_mkdir_secure(const char *path, int nverify);
int juno_spec_save_at(const juno_spec *s, int dfd, const char *name);
int juno_dirs(const char *name, char *rdir, char *ddir, size_t len);
int juno_valid_name(const char *name);
int juno_rm_tree(const char *path);
extern const struct juno_backend juno_remote_backend;
int juno_ctl_connect(const char *name);
int juno_ctl_call(int fd, int op, const void *p, size_t n, int *fds, int nfds, char **resp, size_t *rn, int *rfd);
enum { CTL_STATUS = 1, CTL_STOP, CTL_KILL, CTL_EXEC, CTL_LOGS };
int juno_serve_forwarder(const juno_spec *s, juno_cell *c, int *lfds, int nl, int *cports);

#endif
