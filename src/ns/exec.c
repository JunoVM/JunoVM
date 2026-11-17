/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "ns.h"
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef P_PIDFD
#define P_PIDFD 3
#endif
#ifndef TIOCGPTPEER
#define TIOCGPTPEER 0x5441
#endif

int ns_open_pty(int *master, int *slave)
{
	int unlock = 0;
	int master_fd = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC);
	int slave_fd;

	if (master_fd < 0)
		return -1;
	if (ioctl(master_fd, TIOCSPTLCK, &unlock) < 0) {
		close(master_fd);
		return -1;
	}

	slave_fd = ioctl(master_fd, TIOCGPTPEER, O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (slave_fd < 0) {
		int saved = errno;

		close(master_fd);
		errno = saved;
		return -1;
	}
	*master = master_fd;
	*slave = slave_fd;
	return 0;
}

/* Runs in the forked helper: join the cell, then fork the payload into its pid namespace. */
static void enter(juno_cell *cell, struct ns_ctx *ctx, int root_fd, int pty_sock)
{
	const juno_spec *spec = cell->spec;
	int flags = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS |
		    CLONE_NEWCGROUP;
	const char *cwd = spec->cwd ? spec->cwd : "/";
	pid_t payload;
	int status;

	if (spec->net != JUNO_NET_HOST)
		flags |= CLONE_NEWNET;

	if (cell->cgprocs) {
		int fd = open(cell->cgprocs, O_WRONLY | O_CLOEXEC);

		if (fd < 0 || write(fd, "0", 1) != 1)
			ns_die(ctx, "join cell cgroup");
		close(fd);
	}

	if (ctx->userfd >= 0) {
		/* shared network: its namespaces belong to the holder, not to the cell */
		if (setns(ctx->userfd, CLONE_NEWUSER) < 0)
			ns_die(ctx, "join shared user namespace");
		if (setns(ctx->netfd, CLONE_NEWNET) < 0)
			ns_die(ctx, "join shared network namespace");
		flags &= ~CLONE_NEWNET;
	}

	if (setns(cell->ipidfd, flags) < 0)
		ns_die(ctx, "join cell namespaces");
	if (fchdir(root_fd) < 0 || chroot(".") < 0)
		ns_die(ctx, "enter cell root");
	if (chdir(cwd) < 0)
		ns_die(ctx, "chdir %s", cwd);

	ctx->master = ctx->slave = -1;
	if (pty_sock >= 0) {
		if (ns_open_pty(&ctx->master, &ctx->slave) < 0)
			ns_die(ctx, "open pty in the cell");
		if (ns_send_fd(pty_sock, ctx->master) < 0)
			ns_die(ctx, "send pty master");
		close(pty_sock);
	}

	/* children of this process now live in the cell's pid namespace */
	payload = ns_rawfork();
	if (payload < 0)
		ns_die(ctx, "fork");
	if (payload == 0) {
		ctx->cg = cell->cgprocs != NULL;
		if (ns_fds_prepare(ctx) < 0)
			ns_die(ctx, "fd setup");
		if (ctx->master >= 0) {
			ns_keep(ctx->master);
			ns_keep(ctx->slave);
		}
		ns_harden(ctx);
		ns_exec_payload(ctx);
	}

	close(ctx->errfd);
	if (ctx->slave >= 0)
		close(ctx->slave);
	if (ctx->master >= 0)
		close(ctx->master);
	while (waitpid(payload, &status, 0) < 0 && errno == EINTR)
		;
	_exit(WIFSIGNALED(status) ? 128 + WTERMSIG(status) : WEXITSTATUS(status));
}

/* The exec spec is the cell's spec minus what must not be inherited (fds, timeout, privileges). */
static int make_exec_spec(juno_cell *cell, char *const argv[], juno_spec *out)
{
	*out = *cell->spec;
	out->argv = (char **)argv;
	out->nfds = 0;
	out->fds = NULL;
	out->stdio[0] = out->stdio[1] = out->stdio[2] = -1;
	out->limit_set[JUNO_LIMIT_TIMEOUT_MS] = false;

	if (cell->exec_user_set) {
		out->user_set = true;
		out->uid = cell->exec_uid;
		out->gid = cell->exec_gid;
		out->keepcaps = 0;
		out->nesting = 0;
	}
	if (out->user_set && (out->uid || out->gid) && !out->idmap_full) {
		juno_seterr("exec: user %d:%d needs a cell with idmap = full", out->uid, out->gid);
		return -EINVAL;
	}
	return 0;
}

/* The cell's init pid as the kernel reports it for our pidfd; falls back to the recorded pid. */
static int cell_init_pid(juno_cell *cell)
{
	char path[64], line[128];
	int pid = cell->pid;
	FILE *info;

	snprintf(path, sizeof path, "/proc/self/fdinfo/%d", cell->ipidfd);
	info = fopen(path, "re");
	while (info && fgets(line, sizeof line, info)) {
		if (sscanf(line, "Pid: %d", &pid) == 1)
			break;
	}
	if (info)
		fclose(info);
	return pid;
}

static void free_env(char **envp)
{
	if (!envp)
		return;
	for (char **entry = envp; *entry; entry++)
		free(*entry);
	free(envp);
}

/* Starts the process; returns the helper's pid once the payload has exec'd (or -errno). */
static int exec_common(juno_cell *cell, char *const argv[], int tty, int *master, pid_t *helper_pid)
{
	if (!cell->spec || cell->ipidfd < 0 || cell->done) {
		juno_seterr("exec: cell is not running");
		return -ESRCH;
	}

	juno_spec exec_spec;
	int rc = make_exec_spec(cell, argv, &exec_spec);

	if (rc)
		return rc;

	int err_pipe[2] = { -1, -1 };
	int pty_pair[2] = { -1, -1 };
	int user_fd = -1, net_fd = -1, root_fd = -1;
	struct ns_ctx ctx = { .spec = &exec_spec, .ipfd = -1, .userfd = -1, .netfd = -1,
			      .tmofd = -1, .ttyfd = -1 };
	struct ns_err report;
	char root_path[64];
	pid_t helper;
	ssize_t got;

	if (exec_spec.net == JUNO_NET_SHARED) {
		rc = ns_net_holder(exec_spec.netname, &user_fd, &net_fd);
		if (rc < 0)
			return rc;
	}
	ctx.userfd = user_fd;
	ctx.netfd = net_fd;
	ctx.envp = ns_build_env(&exec_spec);
	if (!ctx.envp) {
		rc = -ENOMEM;
		goto fail;
	}

	snprintf(root_path, sizeof root_path, "/proc/%d/root", cell_init_pid(cell));
	root_fd = open(root_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (root_fd < 0) {
		juno_seterr("exec: open %s: %s", root_path, strerror(errno));
		rc = -errno;
		goto fail;
	}

	if (pipe2(err_pipe, O_CLOEXEC) < 0 ||
	    (tty && socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pty_pair) < 0)) {
		rc = -errno;
		goto fail;
	}
	ctx.errfd = err_pipe[1];

	fflush(NULL);
	helper = fork();
	if (helper < 0) {
		rc = -errno;
		goto fail;
	}
	if (helper == 0) {
		close(err_pipe[0]);
		if (pty_pair[0] >= 0)
			close(pty_pair[0]);
		enter(cell, &ctx, root_fd, pty_pair[1]);
	}

	close(err_pipe[1]);
	err_pipe[1] = -1;
	if (pty_pair[1] >= 0) {
		close(pty_pair[1]);
		pty_pair[1] = -1;
	}
	close(root_fd);
	root_fd = -1;

	do {
		got = read(err_pipe[0], &report, sizeof report);
	} while (got < 0 && errno == EINTR);
	if (got > (ssize_t)sizeof report.err) {
		report.step[ERRMSG_MAX - 1] = 0;
		juno_seterr("exec failed: %s: %s", report.step, strerror(report.err));
		waitpid(helper, NULL, 0);
		rc = -(report.err ? report.err : EIO);
		goto fail;
	}

	if (tty) {
		*master = ns_recv_fd(pty_pair[0]);
		if (*master < 0) {
			juno_seterr("exec: pty master not received");
			kill(helper, SIGKILL);
			waitpid(helper, NULL, 0);
			rc = -EIO;
			goto fail;
		}
	}
	*helper_pid = helper;
	rc = 0;

fail:
	for (int i = 0; i < 2; i++) {
		if (err_pipe[i] >= 0)
			close(err_pipe[i]);
		if (pty_pair[i] >= 0)
			close(pty_pair[i]);
	}
	if (root_fd >= 0)
		close(root_fd);
	if (user_fd >= 0)
		close(user_fd);
	if (net_fd >= 0)
		close(net_fd);
	free_env(ctx.envp);
	return rc;
}

int ns_exec(juno_cell *cell, char *const argv[], int *status)
{
	pid_t helper;
	int wait_status;
	int rc = exec_common(cell, argv, 0, NULL, &helper);

	if (rc)
		return rc;
	while (waitpid(helper, &wait_status, 0) < 0 && errno == EINTR)
		;
	if (status)
		*status = wait_status;
	return 0;
}

int ns_exec_tty(juno_cell *cell, char *const argv[], int *master, int *donefd)
{
	pid_t helper;
	int rc = exec_common(cell, argv, 1, master, &helper);

	if (rc)
		return rc;
	*donefd = syscall(SYS_pidfd_open, helper, 0);
	if (*donefd < 0) {
		rc = -errno;
		kill(helper, SIGKILL);
		waitpid(helper, NULL, 0);
		close(*master);
		return rc;
	}
	return 0;
}

int ns_exec_done(juno_cell *cell, int donefd, int *status)
{
	siginfo_t info;

	(void)cell;
	memset(&info, 0, sizeof info);
	while (waitid(P_PIDFD, donefd, &info, WEXITED) < 0) {
		if (errno != EINTR) {
			int saved = errno;

			close(donefd);
			return -saved;
		}
	}
	close(donefd);
	if (status)
		*status = info.si_code == CLD_EXITED ? (info.si_status & 0xff) << 8 : info.si_status & 0x7f;
	return 0;
}
