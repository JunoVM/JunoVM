/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "ns.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEFAULT_PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

/* The payload gets the pty slave as its terminal and stdio. */
void ns_pty_prelude(struct ns_ctx *ctx)
{
	if (ctx->slave < 0)
		return;

	setsid();
	ioctl(ctx->slave, TIOCSCTTY, 0);
	dup2(ctx->slave, 0);
	dup2(ctx->slave, 1);
	dup2(ctx->slave, 2);
	if (ctx->slave > 2)
		close(ctx->slave);
	if (ctx->master >= 0)
		close(ctx->master);
}

/* PATH from the payload's environment, or the default. */
static const char *payload_path(char *const *envp)
{
	const char *path = DEFAULT_PATH;

	for (char *const *entry = envp; *entry; entry++) {
		if (!strncmp(*entry, "PATH=", 5))
			path = *entry + 5;
	}
	return path;
}

void ns_exec_payload(struct ns_ctx *ctx)
{
	char *const *argv = ctx->spec->argv;
	const char *path;
	size_t name_len;
	int err = ENOENT;

	ns_pty_prelude(ctx);
	if (strchr(argv[0], '/')) {
		execve(argv[0], argv, ctx->envp);
		ns_die(ctx, "exec %s", argv[0]);
	}

	/* no execvpe in the child: walk PATH by hand */
	path = payload_path(ctx->envp);
	name_len = strlen(argv[0]);
	for (;;) {
		size_t dir_len = strcspn(path, ":");
		char candidate[PATH_MAX];

		if (dir_len + name_len + 2 < sizeof candidate) {
			size_t off = 0;

			if (dir_len) {
				memcpy(candidate, path, dir_len);
				off = dir_len;
			} else {
				candidate[off++] = '.';
			}
			candidate[off++] = '/';
			memcpy(candidate + off, argv[0], name_len + 1);

			execve(candidate, argv, ctx->envp);
			if (errno != ENOENT && errno != ENOTDIR)
				err = errno;
		}
		if (!path[dir_len])
			break;
		path += dir_len + 1;
	}
	errno = err;
	ns_die(ctx, "exec %s", argv[0]);
}

/* The tiny init is a fresh image: after the payload is forked, this process execs the static
 * juno-init bound into the cell, so pid 1 holds nothing of the launcher. */
int ns_run(struct ns_ctx *ctx)
{
	sigset_t all_signals, old_mask;
	char pid_arg[16], timeout_arg[24], tmofd_arg[16];
	char *init_argv[] = { "juno-init", pid_arg, timeout_arg, tmofd_arg, NULL };
	char *init_envp[] = { NULL };
	long long timeout_ms = 0;
	pid_t payload;

	if (ctx->spec->init == JUNO_INIT_NONE)
		ns_exec_payload(ctx);

	sigfillset(&all_signals);
	sigprocmask(SIG_BLOCK, &all_signals, &old_mask);
	payload = ns_rawfork();
	if (payload < 0)
		ns_die(ctx, "fork payload");
	if (payload == 0) {
		sigprocmask(SIG_SETMASK, &old_mask, NULL);
		if (ctx->tmofd >= 0)
			close(ctx->tmofd);
		ns_exec_payload(ctx);
	}

	if (ctx->slave >= 0)
		close(ctx->slave);
	if (ctx->master >= 0)
		close(ctx->master);
	if (ctx->tmofd >= 0)
		fcntl(ctx->tmofd, F_SETFD, 0);	/* the init keeps it across exec */

	if (ctx->spec->limit_set[JUNO_LIMIT_TIMEOUT_MS])
		timeout_ms = ctx->spec->limit[JUNO_LIMIT_TIMEOUT_MS];
	ns_fmt(pid_arg, sizeof pid_arg, "%d", (int)payload);
	ns_fmt(timeout_arg, sizeof timeout_arg, "%d", (int)timeout_ms);
	ns_fmt(tmofd_arg, sizeof tmofd_arg, "%d", ctx->tmofd);

	execve(NS_INIT_IN_CELL, init_argv, init_envp);
	ns_die(ctx, "exec the cell init %s", NS_INIT_IN_CELL);
}

#ifndef JUNO_INIT_DEFAULT
#define JUNO_INIT_DEFAULT "/usr/local/libexec/juno/juno-init"
#endif

static int usable(const char *path)
{
	struct stat st;

	return path && *path && stat(path, &st) == 0 && S_ISREG(st.st_mode) && access(path, X_OK) == 0;
}

/* libexec/juno/juno-init next to the running binary's directory */
static int find_beside_binary(char *out, size_t len)
{
	char exe[500], candidate[600];
	ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
	char *slash;

	if (n <= 0)
		return -ENOENT;
	exe[n] = 0;
	slash = strrchr(exe, '/');
	if (!slash)
		return -ENOENT;

	*slash = 0;
	snprintf(candidate, sizeof candidate, "%s/../libexec/juno/juno-init", exe);
	if (!usable(candidate))
		return -ENOENT;
	snprintf(out, len, "%s", candidate);
	return 0;
}

/* Where the cell init image lives: JUNO_INIT (tests, odd installs), the path compiled in,
 * then libexec next to the running binary and the usual prefixes. */
int ns_init_find(char *out, size_t len)
{
	/* inside a nesting cell the outer cell's own init is the one to hand on */
	static const char *const fallbacks[] = {
		"/usr/local/libexec/juno/juno-init", "/usr/libexec/juno/juno-init", NS_INIT_IN_CELL,
	};
	const char *override = getenv("JUNO_INIT");

	if (override && *override) {
		snprintf(out, len, "%s", override);
		return usable(out) ? 0 : -ENOENT;
	}

	snprintf(out, len, "%s", JUNO_INIT_DEFAULT);
	if (usable(out))
		return 0;
	if (find_beside_binary(out, len) == 0)
		return 0;

	for (size_t i = 0; i < sizeof fallbacks / sizeof *fallbacks; i++) {
		if (usable(fallbacks[i])) {
			snprintf(out, len, "%s", fallbacks[i]);
			return 0;
		}
	}
	return -ENOENT;
}
