/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "ns.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/sched.h>
#include <sched.h>
#include <sys/mount.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef P_PIDFD
#define P_PIDFD 3
#endif
#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x1000
#endif

/* sync byte the supervisor sends once the parent side is ready */
#define SYNC_NO_CGROUP 'n'
#define SYNC_CGROUP 'c'
#define SYNC_CGROUP_DELEGATED 'd'

#define MAX_PUBLISHED 16
#define DEFAULT_TMP_SIZE (256ull << 20)
#define DEFAULT_RUN_SIZE (64ull << 20)
#define DEFAULT_SHM_SIZE (64ull << 20)
#define DEFAULT_TMPFS_SIZE (256ull << 20)
#define OVERFLOW_ID 65534
#define PROXY_URL "http://127.0.0.1:3128"
#define CELL_NS (CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS)

/* the init exited, was reaped or the supervisor vanished before the sync byte arrived */
static void wait_for_sync(struct ns_ctx *ctx, char *sync)
{
	if (read(ctx->syncfd, sync, 1) != 1) {
		if (ctx->stage)
			rmdir(ctx->stage);
		_exit(126);
	}
	close(ctx->syncfd);
}

static void child_main(struct ns_ctx *ctx)
{
	const juno_spec *spec = ctx->spec;
	const char *cwd = spec->cwd ? spec->cwd : "/";
	char sync;

	if (spec->die_with_parent || ctx->shared)
		prctl(PR_SET_PDEATHSIG, SIGKILL);
	wait_for_sync(ctx, &sync);

	ctx->cg = sync == SYNC_CGROUP ? 1 : sync == SYNC_CGROUP_DELEGATED ? 2 : 0;
	ctx->master = ctx->slave = -1;
	setsid();	/* the cell must not share the launcher's controlling terminal */

	if (ns_fds_prepare(ctx) < 0)
		ns_die(ctx, "fd setup");
	if (unshare(CLONE_NEWCGROUP) < 0)
		ns_die(ctx, "unshare cgroup namespace");
	if (sethostname(ctx->hostname, strlen(ctx->hostname)) < 0)
		ns_die(ctx, "set hostname");
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
		ns_die(ctx, "make mounts private");
	if ((spec->net == JUNO_NET_NONE || spec->net == JUNO_NET_NAT) && ns_net_up() < 0)
		ns_die(ctx, "bring up loopback");
	if (spec->net == JUNO_NET_NAT)
		ns_wait_gateway();
	if (ns_egress_apply(ctx) < 0)
		ns_die(ctx, "install the egress routes");

	ns_build_root(ctx);

	if (ctx->ttyfd >= 0) {
		if (ns_open_pty(&ctx->master, &ctx->slave) < 0)
			ns_die(ctx, "open pty");
		if (ns_send_fd(ctx->ttyfd, ctx->master) < 0)
			ns_die(ctx, "send pty master");
		ns_keep(ctx->master);
		ns_keep(ctx->slave);
		close(ctx->ttyfd);
		ctx->ttyfd = -1;
	}

	ns_cgroup_delegate(ctx);
	if (chdir(cwd) < 0)
		ns_die(ctx, "chdir %s", cwd);
	ns_harden(ctx);
	ns_run(ctx);
}

static long clone3(unsigned long long flags, int *pidfd)
{
	struct clone_args args = {
		.flags = flags | CLONE_PIDFD, .pidfd = (uintptr_t)pidfd, .exit_signal = SIGCHLD,
	};

	return syscall(SYS_clone3, &args, sizeof args);
}

/* Shared network: join the holder's user and net namespaces, then give the
 * cell a user namespace of its own (a child of the holder's) plus the other
 * namespaces. The cell keeps the shared network namespace but holds no
 * capabilities over it. Stays as the cell init's parent and mirrors its exit. */
static void launcher_main(struct ns_ctx *ctx)
{
	char sync, member_path[700];
	int init_sync[2], init_pidfd = -1;
	int member_fd, init_pid, status;
	long clone_rc;

	if (ctx->spec->die_with_parent)
		prctl(PR_SET_PDEATHSIG, SIGKILL);
	wait_for_sync(ctx, &sync);

	if (setns(ctx->userfd, CLONE_NEWUSER) < 0)
		ns_die(ctx, "join shared user namespace");
	if (setns(ctx->netfd, CLONE_NEWNET) < 0)
		ns_die(ctx, "join shared network namespace");
	close(ctx->userfd);
	close(ctx->netfd);

	ns_fmt(member_path, sizeof member_path, "%s/m.%d", ctx->netreg, (int)getpid());
	member_fd = open(member_path, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
	if (member_fd < 0)
		ns_die(ctx, "register in shared network");
	close(member_fd);

	if (pipe2(init_sync, O_CLOEXEC) < 0)
		ns_die(ctx, "pipe");
	clone_rc = clone3(CELL_NS | CLONE_NEWUSER, &init_pidfd);
	if (clone_rc < 0)
		ns_die(ctx, "clone3 (cell)");
	if (clone_rc == 0) {
		close(init_sync[1]);
		close(ctx->ipfd);
		ctx->syncfd = init_sync[0];
		child_main(ctx);
		_exit(127);
	}
	close(init_pidfd);
	close(init_sync[0]);

	/* inner 0 -> holder 0 -> the caller */
	init_pid = (int)clone_rc;
	if (ns_write_idmap(clone_rc, 0, 0) < 0) {
		errno = EPERM;
		ns_die(ctx, "map the cell's user namespace");
	}
	if (write(ctx->ipfd, &init_pid, sizeof init_pid) != sizeof init_pid ||
	    write(init_sync[1], &sync, 1) != 1)
		ns_die(ctx, "relay setup");
	close(init_sync[1]);
	close(ctx->ipfd);
	close(ctx->errfd);

	while (waitpid(clone_rc, &status, 0) < 0 && errno == EINTR)
		;
	if (WIFSIGNALED(status)) {
		signal(WTERMSIG(status), SIG_DFL);
		raise(WTERMSIG(status));
		_exit(128 + WTERMSIG(status));
	}
	_exit(WEXITSTATUS(status));
}

static void free_env_list(char **env)
{
	for (char **entry = env; env && *entry; entry++)
		free(*entry);
	free(env);
}

static int env_has(const juno_spec *spec, const char *name)
{
	size_t len = strlen(name);

	for (int i = 0; i < spec->nenv; i++) {
		if (!strncmp(spec->env[i], name, len) && spec->env[i][len] == '=')
			return 1;
	}
	return 0;
}

char **ns_build_env(const juno_spec *spec)
{
	static const char *const proxy_vars[] = { "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy" };
	char **env = NULL;
	int count = 0, have_path = 0;

	for (int i = 0; i < spec->nenv; i++) {
		char *copy;

		if (!strncmp(spec->env[i], "PATH=", 5))
			have_path = 1;
		copy = strdup(spec->env[i]);
		if (!copy || juno_append(&env, &count, copy))
			goto fail;
	}

	if (spec->nproxy) {
		for (size_t i = 0; i < sizeof proxy_vars / sizeof *proxy_vars; i++) {
			char *entry;

			if (env_has(spec, proxy_vars[i]))
				continue;
			entry = malloc(64);
			if (!entry)
				goto fail;
			snprintf(entry, 64, "%s=" PROXY_URL, proxy_vars[i]);
			if (juno_append(&env, &count, entry))
				goto fail;
		}
	}

	if (!have_path) {
		char *path = strdup("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");

		if (!path || juno_append(&env, &count, path))
			goto fail;
	}
	if (!env)
		env = calloc(1, sizeof *env);
	return env;

fail:
	free_env_list(env);
	return NULL;
}

static void report_child_error(const struct ns_err *report)
{
	juno_seterr("start failed: %s: %s", report->step, strerror(report->err));
}

/* Refuse combinations that cannot work or would weaken a guarantee, before anything is created. */
static int validate_spec(const juno_spec *spec)
{
	if (spec->root_kind != JUNO_ROOT_HOST_RO && !spec->root_path) {
		juno_seterr("spec: root kind needs a path");
		return -EINVAL;
	}
	if (spec->limit_set[JUNO_LIMIT_MEMORY] && !spec->mem_fallback && !juno_cgroups_usable()) {
		juno_seterr("a memory limit needs a delegated cgroup and none is usable here; run under "
			"`systemd-run --user --scope -p Delegate=yes juno ...`, or accept the weaker "
			"per-process RLIMIT_AS with --mem-fallback rlimit");
		return -ENOTSUP;
	}
	if (spec->npubs && spec->net == JUNO_NET_HOST) {
		juno_seterr("publish needs a network namespace for the cell (net none or shared)");
		return -EINVAL;
	}
	if (spec->net == JUNO_NET_SHARED && spec->idmap_full) {
		juno_seterr("idmap = full cannot be combined with a shared network (its user namespace has one id)");
		return -EINVAL;
	}
	if (spec->user_set && (spec->uid || spec->gid) && !spec->idmap_full) {
		juno_seterr("user %d:%d needs idmap = full (the single-id map has only id 0)", spec->uid, spec->gid);
		return -EINVAL;
	}
	if (spec->user_set && (spec->keepcaps || spec->nesting)) {
		juno_seterr("a cell with a user cannot keep capabilities or allow nesting");
		return -EINVAL;
	}
	if (spec->idmap_full) {
		char why[200];

		if (!juno_idmap_full_available(why, sizeof why)) {
			juno_seterr("idmap = full is unavailable: %s", why);
			return -ENOTSUP;
		}
	}
	if (spec->net == JUNO_NET_NAT && (spec->keepcaps >> CAP_NET_ADMIN & 1)) {
		juno_seterr("keep-cap net_admin cannot be combined with net = nat: "
			"the cell could remove the egress rules");
		return -EINVAL;
	}
	if (spec->nproxy && spec->net == JUNO_NET_SHARED) {
		juno_seterr("egress-proxy-allow is not supported with a shared network");
		return -EINVAL;
	}
	if (spec->net == JUNO_NET_NAT && !juno_pasta_available(NULL, 0)) {
		juno_seterr("net = nat needs pasta (package passt), which is not in PATH");
		return -ENOENT;
	}
	return 0;
}

static void format_tmpfs_opts(char *out, size_t len, const char *mode, uint64_t size, uint64_t fallback)
{
	snprintf(out, len, "mode=%s,size=%llu", mode, (unsigned long long)(size ? size : fallback));
}

/* Everything the child needs as text, computed in the parent so the child never allocates. */
static void fill_cell_text(struct ns_ctx *ctx, const juno_spec *spec)
{
	format_tmpfs_opts(ctx->tmpopt, sizeof ctx->tmpopt, "1777", spec->tmp_size, DEFAULT_TMP_SIZE);
	format_tmpfs_opts(ctx->runopt, sizeof ctx->runopt, "755", spec->run_size, DEFAULT_RUN_SIZE);
	format_tmpfs_opts(ctx->shmopt, sizeof ctx->shmopt, "1777", spec->shm_size, DEFAULT_SHM_SIZE);
	format_tmpfs_opts(ctx->utmpopt, sizeof ctx->utmpopt, "1777", spec->tmpfs_size, DEFAULT_TMPFS_SIZE);

	snprintf(ctx->hostname, sizeof ctx->hostname, "%s", spec->hostname ? spec->hostname : "juno");
	snprintf(ctx->hosts, sizeof ctx->hosts,
		 "127.0.0.1 localhost\n::1 localhost ip6-localhost\n127.0.1.1 %s\n", ctx->hostname);
	snprintf(ctx->passwd, sizeof ctx->passwd,
		 "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n");
	snprintf(ctx->group, sizeof ctx->group, "root:x:0:\nnogroup:x:65534:\n");

	if (spec->user_set && spec->uid && spec->uid != OVERFLOW_ID) {
		size_t passwd_len = strlen(ctx->passwd);
		size_t group_len = strlen(ctx->group);

		snprintf(ctx->passwd + passwd_len, sizeof ctx->passwd - passwd_len,
			 "user:x:%d:%d:user:/:/bin/sh\n", spec->uid, spec->gid);
		if (spec->gid && spec->gid != OVERFLOW_ID)
			snprintf(ctx->group + group_len, sizeof ctx->group - group_len, "user:x:%d:\n", spec->gid);
	}
}

/* Create the overlay upper and work directories, and record the work dir for release. */
static int prepare_overlay(struct ns_ctx *ctx, const juno_spec *spec, juno_cell *cell, char *work, size_t work_len)
{
	snprintf(work, work_len, "%s.work", spec->root_path);
	if (mkdir(spec->root_path, 0755) < 0 && errno != EEXIST) {
		juno_seterr("overlay: create upper %s: %s", spec->root_path, strerror(errno));
		return -errno;
	}
	if (mkdir(work, 0700) < 0 && errno != EEXIST) {
		juno_seterr("overlay: create work dir %s: %s", work, strerror(errno));
		return -errno;
	}
	ctx->workdir = work;
	cell->workdir = strdup(work);
	return 0;
}

/* A nat cell on a dir/overlay root may need a resolv.conf mountpoint: remember whether we create it. */
static void note_resolv_mountpoint(const juno_spec *spec, juno_cell *cell)
{
	char path[4300];

	snprintf(path, sizeof path, "%s/etc/resolv.conf", spec->root_path);
	if (access(path, F_OK) != 0)
		cell->rm_resolv = strdup(path);
}

static void kill_and_reap(pid_t *pid)
{
	if (*pid > 0) {
		kill(*pid, SIGKILL);
		waitpid(*pid, NULL, 0);
		*pid = 0;
	}
}

/* Undo a start that failed after the cell process exists. */
static void abort_start(juno_cell *cell, pid_t pid, int pidfd)
{
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	kill_and_reap(&cell->proxypid);
	kill_and_reap(&cell->pastapid);

	close(pidfd);
	if (cell->ipidfd >= 0 && cell->ipidfd != pidfd)
		close(cell->ipidfd);
	if (cell->tmofd >= 0)
		close(cell->tmofd);
	if (cell->ttyfd >= 0)
		close(cell->ttyfd);
	cell->pidfd = cell->ipidfd = cell->tmofd = cell->ttyfd = -1;
	cell->done = true;
}

/* Everything a start opens in the parent; closed again on every exit path. */
struct start_fds {
	int sync[2], err[2], ipid[2], timeout[2], tty[2];
};

static void close_start_fds(struct start_fds *fds)
{
	for (int i = 0; i < 2; i++) {
		if (fds->sync[i] >= 0)
			close(fds->sync[i]);
		if (fds->err[i] >= 0)
			close(fds->err[i]);
		if (fds->ipid[i] >= 0)
			close(fds->ipid[i]);
		if (fds->timeout[i] >= 0)
			close(fds->timeout[i]);
		if (fds->tty[i] >= 0)
			close(fds->tty[i]);
	}
}

/* In the cloned child: drop the parent's ends and run the cell (never returns). */
static void run_cloned_child(struct ns_ctx *ctx, struct start_fds *fds, int *listen_fds, int listener_count,
	int shared)
{
	close(fds->sync[1]);
	close(fds->err[0]);
	close(fds->ipid[0]);
	if (fds->timeout[0] >= 0)
		close(fds->timeout[0]);
	if (fds->tty[0] >= 0)
		close(fds->tty[0]);
	for (int i = 0; i < listener_count; i++)
		close(listen_fds[i]);
	if (shared)
		launcher_main(ctx);
	close(fds->ipid[1]);
	child_main(ctx);
	_exit(127);
}

/* Map ids, set up limits, networking and the proxy; returns the sync byte to release the child. */
static int configure_cell(const juno_spec *spec, juno_cell *cell, pid_t pid, int pidfd, int shared, char *sync)
{
	int rc;

	*sync = SYNC_NO_CGROUP;
	if (!shared && spec->idmap_full) {
		char err[200];

		rc = ns_write_idmap_full(pid, err, sizeof err);
		if (rc) {
			juno_seterr("idmap = full: %s", err[0] ? err : "newuidmap/newgidmap failed");
			return rc;
		}
	} else if (!shared) {
		rc = ns_write_idmap(pid, getuid(), getgid());
		if (rc) {
			juno_seterr("idmap: %s", strerror(-rc));
			return rc;
		}
	}

	rc = ns_cgroup_attach(spec, pid, cell);
	if (rc)
		return rc;
	if (cell->cgroup)
		*sync = spec->nesting ? SYNC_CGROUP_DELEGATED : SYNC_CGROUP;

	if (spec->net == JUNO_NET_NAT) {
		rc = ns_pasta_start(spec, pid, cell);
		if (rc)
			return rc;
	}
	rc = ns_proxy_spawn(spec, pidfd, cell);
	if (rc)
		return rc;

	if (spec->limit_set[JUNO_LIMIT_TIMEOUT_MS])
		cell->deadline_ms = juno_now_ms() + spec->limit[JUNO_LIMIT_TIMEOUT_MS];
	return 0;
}

/* Wait for the child's start report; its failure step is turned into an error. */
static int read_child_report(int err_fd)
{
	struct ns_err report;
	ssize_t got;

	do {
		got = read(err_fd, &report, sizeof report);
	} while (got < 0 && errno == EINTR);

	if (got > (ssize_t)sizeof report.err) {
		report.step[ERRMSG_MAX - 1] = 0;
		report_child_error(&report);
		return -(report.err ? report.err : EIO);
	}
	if (got < 0) {
		juno_seterr("start: error pipe: %s", strerror(errno));
		return -errno;
	}
	return 0;
}

static int ns_start(const juno_spec *spec, juno_cell *cell)
{
	struct ns_ctx ctx = { .spec = spec, .userfd = -1, .netfd = -1, .ipfd = -1, .tmofd = -1, .ttyfd = -1 };
	struct start_fds fds = { { -1, -1 }, { -1, -1 }, { -1, -1 }, { -1, -1 }, { -1, -1 } };
	char work[4200] = "";
	char stage[4200] = "";
	const char *tmpdir = getenv("TMPDIR");
	int listen_fds[MAX_PUBLISHED], cell_ports[MAX_PUBLISHED];
	int listener_count = 0;
	int pidfd = -1;
	int shared = spec->net == JUNO_NET_SHARED;
	int rc;
	long pid;
	unsigned long long clone_flags;
	char sync;

	cell->ipidfd = cell->tmofd = cell->ttyfd = -1;
	rc = validate_spec(spec);
	if (rc)
		return rc;

	if (spec->npubs) {
		listener_count = ns_fwd_bind(spec, listen_fds, cell_ports, MAX_PUBLISHED);
		if (listener_count < 0)
			return listener_count;
	}
	if (shared) {
		rc = ns_net_holder(spec->netname, &ctx.userfd, &ctx.netfd);
		if (rc < 0)
			goto out;
		ns_net_register_path(spec->netname, ctx.netreg, sizeof ctx.netreg);
	}
	if ((spec->init == JUNO_INIT_TINY || spec->nesting) &&
	    ns_init_find(ctx.initpath, sizeof ctx.initpath) < 0) {
		juno_seterr("the cell init binary juno-init was not found (looked at $JUNO_INIT, %s and "
			"libexec/juno); install it or set JUNO_INIT", "the compiled-in path");
		rc = -ENOENT;
		goto out;
	}

	fill_cell_text(&ctx, spec);

	snprintf(stage, sizeof stage, "%s/juno-XXXXXX", tmpdir && *tmpdir == '/' ? tmpdir : "/tmp");
	if (!mkdtemp(stage)) {
		juno_seterr("create stage dir %s: %s", stage, strerror(errno));
		rc = -errno;
		stage[0] = 0;
		goto out;
	}
	ctx.stage = stage;

	if (spec->root_kind == JUNO_ROOT_OVERLAY) {
		rc = prepare_overlay(&ctx, spec, cell, work, sizeof work);
		if (rc)
			goto out;
	}
	if (spec->net == JUNO_NET_NAT && spec->root_kind != JUNO_ROOT_HOST_RO)
		note_resolv_mountpoint(spec, cell);

	rc = ns_egress_plan(spec, &ctx);
	if (rc) {
		juno_seterr("egress rules: %s", strerror(-rc));
		goto out;
	}
	ctx.envp = ns_build_env(spec);
	if (!ctx.envp) {
		rc = -ENOMEM;
		goto out;
	}

	if (pipe2(fds.sync, O_CLOEXEC) < 0 || pipe2(fds.err, O_CLOEXEC) < 0 || pipe2(fds.ipid, O_CLOEXEC) < 0 ||
	    (spec->limit_set[JUNO_LIMIT_TIMEOUT_MS] && pipe2(fds.timeout, O_CLOEXEC | O_NONBLOCK) < 0) ||
	    (spec->tty && socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds.tty) < 0)) {
		juno_seterr("pipe: %s", strerror(errno));
		rc = -errno;
		goto out;
	}
	ctx.syncfd = fds.sync[0];
	ctx.errfd = fds.err[1];
	ctx.shared = shared;
	ctx.ipfd = fds.ipid[1];
	ctx.tmofd = fds.timeout[1];
	ctx.ttyfd = fds.tty[1];

	clone_flags = shared ? 0 : (CELL_NS | CLONE_NEWUSER);
	if (!shared && (spec->net == JUNO_NET_NONE || spec->net == JUNO_NET_NAT))
		clone_flags |= CLONE_NEWNET;
	fflush(NULL);
	pid = clone3(clone_flags, &pidfd);
	if (pid < 0) {
		int saved = errno;

		if ((saved == ENOSYS || saved == EPERM) && prctl(PR_GET_SECCOMP) == 2)
			juno_seterr("nested cells are not allowed here (parent cell lacks nesting)");
		else
			juno_seterr("clone3: %s", strerror(saved));
		rc = -saved;
		goto out;
	}
	if (pid == 0)
		run_cloned_child(&ctx, &fds, listen_fds, listener_count, shared);

	/* parent: keep our ends only */
	close(fds.sync[0]);
	fds.sync[0] = -1;
	close(fds.err[1]);
	fds.err[1] = -1;
	close(fds.ipid[1]);
	fds.ipid[1] = -1;
	if (fds.timeout[1] >= 0) {
		close(fds.timeout[1]);
		fds.timeout[1] = -1;
	}
	if (fds.tty[1] >= 0) {
		close(fds.tty[1]);
		fds.tty[1] = -1;
	}
	cell->pid = pid;
	cell->pidfd = pidfd;
	cell->tmofd = fds.timeout[0];
	fds.timeout[0] = -1;

	rc = configure_cell(spec, cell, pid, pidfd, shared, &sync);
	if (rc)
		goto abort;
	if (write(fds.sync[1], &sync, 1) != 1) {
		juno_seterr("sync write: %s", strerror(errno));
		rc = -errno;
		goto abort;
	}
	close(fds.sync[1]);
	fds.sync[1] = -1;

	rc = read_child_report(fds.err[0]);
	if (rc)
		goto abort;

	if (shared) {
		int init_pid = 0;

		if (read(fds.ipid[0], &init_pid, sizeof init_pid) != sizeof init_pid ||
		    (cell->ipidfd = syscall(SYS_pidfd_open, init_pid, 0)) < 0) {
			juno_seterr("start: cell init pid: %s", strerror(errno));
			rc = -EIO;
			goto abort;
		}
	} else {
		cell->ipidfd = pidfd;
	}
	if (spec->tty && (cell->ttyfd = ns_recv_fd(fds.tty[0])) < 0) {
		juno_seterr("start: pty master not received");
		rc = -EIO;
		goto abort;
	}

	cell->spec = juno_spec_dup(spec);
	if (listener_count && ns_fwd_spawn(cell, listen_fds, cell_ports, listener_count) < 0) {
		rc = -errno;
		goto abort;
	}
	listener_count = 0;	/* the forwarder owns the listeners now */
	rc = 0;
	goto out;

abort:
	abort_start(cell, pid, pidfd);
out:
	close_start_fds(&fds);
	for (int i = 0; i < listener_count; i++)
		close(listen_fds[i]);
	if (ctx.userfd >= 0)
		close(ctx.userfd);
	if (ctx.netfd >= 0)
		close(ctx.netfd);
	if (stage[0])
		rmdir(stage);
	free_env_list(ctx.envp);
	return rc;
}

static int ns_kill(juno_cell *cell, int sig)
{
	if (cell->done)
		return -ESRCH;
	if (syscall(SYS_pidfd_send_signal, cell->ipidfd >= 0 ? cell->ipidfd : cell->pidfd, sig, NULL, 0) < 0)
		return -errno;
	return 0;
}

/* Collect the exit status if the cell has exited: 1 reaped, 0 still running, <0 error. */
static int reap(juno_cell *cell)
{
	siginfo_t info;
	char byte;

	memset(&info, 0, sizeof info);
	if (waitid(P_PIDFD, cell->pidfd, &info, WEXITED | WNOHANG) < 0)
		return -errno;
	if (info.si_pid == 0)
		return 0;

	switch (info.si_code) {
	case CLD_EXITED:
		cell->status = (info.si_status & 0xff) << 8;
		break;
	case CLD_DUMPED:
		cell->status = (info.si_status & 0x7f) | 0x80;
		break;
	default:
		cell->status = info.si_status & 0x7f;
		break;
	}
	cell->done = true;
	if (cell->tmofd >= 0 && read(cell->tmofd, &byte, 1) == 1)
		cell->timed_out = true;	/* the init enforced it */
	return 1;
}

static int ns_wait(juno_cell *cell, int *status, int timeout_ms)
{
	uint64_t caller_deadline = timeout_ms < 0 ? 0 : juno_now_ms() + timeout_ms;

	while (!cell->done) {
		uint64_t now = juno_now_ms();
		uint64_t next_deadline = 0;
		struct pollfd waiting = { cell->pidfd, POLLIN, 0 };
		int wait_ms = -1;
		int ready;

		if (cell->deadline_ms && !cell->timed_out)
			next_deadline = cell->deadline_ms;
		if (caller_deadline && (!next_deadline || caller_deadline < next_deadline))
			next_deadline = caller_deadline;
		if (next_deadline)
			wait_ms = next_deadline > now ? (int)(next_deadline - now) : 0;

		ready = poll(&waiting, 1, wait_ms);
		if (ready < 0 && errno != EINTR)
			return -errno;
		if (ready > 0) {
			ready = reap(cell);
			if (ready < 0)
				return ready;
			continue;
		}

		now = juno_now_ms();
		if (cell->deadline_ms && !cell->timed_out && now >= cell->deadline_ms) {
			cell->timed_out = true;
			caller_deadline = 0;
			ns_kill(cell, SIGKILL);
		} else if (caller_deadline && now >= caller_deadline && !cell->timed_out) {
			return -ETIMEDOUT;
		}
	}
	if (status)
		*status = cell->status;
	return 0;
}

static void ns_release(juno_cell *cell)
{
	if (!cell->done && cell->pidfd >= 0) {
		ns_kill(cell, SIGKILL);
		ns_wait(cell, NULL, -1);
	}
	if (cell->fwdpid > 0) {
		kill(cell->fwdpid, SIGKILL);
		waitpid(cell->fwdpid, NULL, 0);
	}
	if (cell->pastapid > 0) {
		kill(cell->pastapid, SIGKILL);
		waitpid(cell->pastapid, NULL, 0);
	}
	if (cell->proxypid > 0) {
		kill(cell->proxypid, SIGKILL);
		waitpid(cell->proxypid, NULL, 0);
	}

	if (cell->ipidfd >= 0 && cell->ipidfd != cell->pidfd)
		close(cell->ipidfd);
	if (cell->pidfd >= 0)
		close(cell->pidfd);
	if (cell->tmofd >= 0)
		close(cell->tmofd);
	if (cell->ttyfd >= 0)
		close(cell->ttyfd);
	free(cell->cgprocs);

	if (cell->rm_resolv) {	/* the empty mountpoint file we created in the user's rootfs */
		struct stat st;

		if (lstat(cell->rm_resolv, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 0)
			unlink(cell->rm_resolv);
		free(cell->rm_resolv);
	}
	juno_spec_free(cell->spec);

	if (cell->cgroup) {
		ns_cgroup_remove(cell->cgroup);
		free(cell->cgroup);
	}
	if (cell->workdir) {
		char work_dir[4300];

		snprintf(work_dir, sizeof work_dir, "%s/work", cell->workdir);
		chmod(work_dir, 0700);
		rmdir(work_dir);
		rmdir(cell->workdir);
		free(cell->workdir);
	}
}

#define PROBE_USERNS 1
#define PROBE_OVERLAY 2
#define SECCOMP_ACTION_ERRNO 0x00050000

/* In the forked probe child: can we get a user namespace, and mount an overlay inside it? */
static void probe_child(const char *dir)
{
	static const char *const subdirs[] = { "l", "u", "w", "m" };
	char path[300], opts[1200];
	int result = 0;
	/* ids must be read before unshare: inside the new namespace they read as the overflow id */
	uid_t uid = getuid();
	gid_t gid = getgid();

	if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0)
		_exit(0);
	if (ns_write_idmap(getpid(), uid, gid))
		_exit(0);
	result |= PROBE_USERNS;

	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0) {
		for (size_t i = 0; i < sizeof subdirs / sizeof *subdirs; i++) {
			snprintf(path, sizeof path, "%s/%s", dir, subdirs[i]);
			mkdir(path, 0755);
		}
		snprintf(opts, sizeof opts, "lowerdir=%s/l,upperdir=%s/u,workdir=%s/w", dir, dir, dir);
		snprintf(path, sizeof path, "%s/m", dir);
		if (mount("overlay", path, "overlay", 0, opts) == 0) {
			result |= PROBE_OVERLAY;
		} else {
			strcat(opts, ",userxattr");
			if (mount("overlay", path, "overlay", 0, opts) == 0)
				result |= PROBE_OVERLAY;
		}
	}
	_exit(result);
}

static void probe_userns_overlay(int *userns, int *overlay)
{
	static const char *const leftovers[] = { "w/work", "w", "u", "l", "m" };
	char template[] = "/tmp/juno-probe-XXXXXX";
	char *dir = mkdtemp(template);
	char path[320];
	int status = 0;
	pid_t pid;

	*userns = *overlay = 0;
	if (!dir)
		return;
	pid = fork();
	if (pid == 0)
		probe_child(dir);
	if (pid > 0 && waitpid(pid, &status, 0) > 0 && WIFEXITED(status)) {
		*userns = WEXITSTATUS(status) & PROBE_USERNS;
		*overlay = (WEXITSTATUS(status) & PROBE_OVERLAY) != 0;
	}

	for (size_t i = 0; i < sizeof leftovers / sizeof *leftovers; i++) {
		snprintf(path, sizeof path, "%s/%s", dir, leftovers[i]);
		rmdir(path);
	}
	rmdir(dir);
}

static int ns_probe(char *report, size_t len)
{
	char why[256] = "", base[400], kernel[64] = "", landlock[64], pasta_line[160];
	char pasta_version[100], idmap_line[260], idmap_why[200];
	int userns, overlay;
	int landlock_abi, seccomp_rc, cgroup_ok;
	FILE *fp;

	probe_userns_overlay(&userns, &overlay);
	landlock_abi = ns_landlock_abi();
	seccomp_rc = syscall(SYS_seccomp, 2 /* SECCOMP_GET_ACTION_AVAIL */, 0,
			     &(unsigned){ SECCOMP_ACTION_ERRNO });
	cgroup_ok = ns_cgroup_probe(base, sizeof base, why, sizeof why);

	if (juno_pasta_available(pasta_version, sizeof pasta_version))
		snprintf(pasta_line, sizeof pasta_line, "pasta available (%s), net = nat works",
			 pasta_version[0] ? pasta_version : "version unknown");
	else
		snprintf(pasta_line, sizeof pasta_line, "unavailable (pasta not found in PATH)");
	snprintf(idmap_line, sizeof idmap_line, "%s (%s)",
		 juno_idmap_full_available(idmap_why, sizeof idmap_why) ? "available" : "unavailable", idmap_why);

	fp = fopen("/proc/sys/kernel/osrelease", "re");
	if (fp) {
		if (fgets(kernel, sizeof kernel, fp))
			kernel[strcspn(kernel, "\n")] = 0;
		fclose(fp);
	}
	if (landlock_abi > 0)
		snprintf(landlock, sizeof landlock, "yes (ABI %d)", landlock_abi);
	else
		snprintf(landlock, sizeof landlock, "no (%s)", strerror(-landlock_abi));

	snprintf(report, len,
		"backend: ns (kernel %s)\n"
		"userns: %s\n"
		"overlay in userns: %s\n"
		"landlock: %s\n"
		"seccomp filter: %s\n"
		"cgroup v2 delegation: %s (%s)\n"
		"outbound networking for rootless cells: %s\n"
		"multi-id maps (idmap = full): %s\n",
		kernel, userns ? "yes" : "no", overlay ? "yes" : "no", landlock,
		seccomp_rc == 0 ? "yes" : "no", cgroup_ok ? "usable" : "not usable", why,
		pasta_line, idmap_line);
	return userns ? 0 : -EPERM;
}

const struct juno_backend juno_ns_backend = {
	.name = "ns",
	.probe = ns_probe,
	.start = ns_start,
	.kill = ns_kill,
	.wait = ns_wait,
	.exec = ns_exec,
	.exec_tty = ns_exec_tty,
	.exec_done = ns_exec_done,
	.release = ns_release,
};
