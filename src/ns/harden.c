/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "ns.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/close_range.h>
#include <grp.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_RAISE 2
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

#define MAX_KEEP_FDS 80
#define MAX_PASSED_FDS 64
#define NUM_CAPS 64
/* the kernel closes descriptors past this when close_range() is unavailable */
#define FALLBACK_CLOSE_LIMIT 65536
/* an inner cell maps its root, which the kernel allows only with CAP_SETFCAP in the parent */
#define NESTING_CAPS (1ull << CAP_SETFCAP)

static int keep_fds[MAX_KEEP_FDS];
static int keep_count;

void ns_keep(int fd)
{
	if (keep_count < MAX_KEEP_FDS)
		keep_fds[keep_count++] = fd;
}

/* Move one of our own fds above everything the cell asked for. */
static int park(int *fd, int above)
{
	if (*fd < 0)
		return 0;

	int moved = fcntl(*fd, F_DUPFD_CLOEXEC, above);
	if (moved < 0)
		return -1;
	close(*fd);
	*fd = moved;
	return 0;
}

/* Move passed fds and stdio into place and park our own fds above them. */
int ns_fds_prepare(struct ns_ctx *ctx)
{
	const juno_spec *spec = ctx->spec;
	struct { int src, dst; } moves[3 + MAX_PASSED_FDS];
	int staged[3 + MAX_PASSED_FDS];
	int move_count = 0;
	int highest_target = 2;

	for (int i = 0; i < 3; i++) {
		if (spec->stdio[i] >= 0 && spec->stdio[i] != i) {
			moves[move_count].src = spec->stdio[i];
			moves[move_count].dst = i;
			move_count++;
		}
	}
	if (spec->nfds > MAX_PASSED_FDS) {
		errno = E2BIG;
		return -1;
	}
	for (int i = 0; i < spec->nfds; i++) {
		moves[move_count].src = spec->fds[i].src;
		moves[move_count].dst = spec->fds[i].dst;
		move_count++;
		if (spec->fds[i].dst > highest_target)
			highest_target = spec->fds[i].dst;
	}

	if (park(&ctx->errfd, highest_target + 1) < 0 ||
	    park(&ctx->tmofd, highest_target + 1) < 0 ||
	    park(&ctx->ttyfd, highest_target + 1) < 0)
		return -1;

	int highest_own = ctx->errfd;
	if (ctx->tmofd > highest_own)
		highest_own = ctx->tmofd;
	if (ctx->ttyfd > highest_own)
		highest_own = ctx->ttyfd;

	/* two passes so a source that is another move's target is not clobbered */
	for (int i = 0; i < move_count; i++) {
		staged[i] = fcntl(moves[i].src, F_DUPFD_CLOEXEC, highest_own + 1);
		if (staged[i] < 0)
			return -1;
	}
	for (int i = 0; i < move_count; i++) {
		if (dup2(staged[i], moves[i].dst) < 0)
			return -1;
		close(staged[i]);
	}

	keep_count = 0;
	for (int i = 0; i < 3; i++)
		keep_fds[keep_count++] = i;
	for (int i = 0; i < spec->nfds; i++)
		keep_fds[keep_count++] = spec->fds[i].dst;
	keep_fds[keep_count++] = ctx->errfd;
	if (ctx->tmofd >= 0)
		keep_fds[keep_count++] = ctx->tmofd;
	if (ctx->ttyfd >= 0)
		keep_fds[keep_count++] = ctx->ttyfd;
	return 0;
}

static void sort_keep_fds(void)
{
	/* insertion sort: no qsort in the child */
	for (int i = 1; i < keep_count; i++) {
		int value = keep_fds[i];
		int j = i - 1;

		for (; j >= 0 && keep_fds[j] > value; j--)
			keep_fds[j + 1] = keep_fds[j];
		keep_fds[j + 1] = value;
	}
}

/* Close every descriptor that is not in the keep list, one gap at a time. */
static void close_others(void)
{
	unsigned gap_start = 0;

	sort_keep_fds();
	for (int i = 0; i <= keep_count; i++) {
		unsigned gap_end = i < keep_count ? (unsigned)keep_fds[i] : ~0u;

		if (gap_end > gap_start &&
		    syscall(SYS_close_range, gap_start, gap_end - 1, 0) < 0 && errno == ENOSYS) {
			for (unsigned fd = gap_start; fd < gap_end && fd < FALLBACK_CLOSE_LIMIT; fd++)
				close(fd);
		}
		if (i < keep_count)
			gap_start = keep_fds[i] + 1;
	}
}

/* Drop every bounding-set capability not in keep_mask and clear the ambient set. */
static int drop_bounding_and_ambient(uint64_t keep_mask)
{
	for (int cap = 0; cap < NUM_CAPS; cap++) {
		int present = prctl(PR_CAPBSET_READ, cap);

		if (present < 0)
			break;	/* EINVAL past the last cap */
		if (present && !(keep_mask >> cap & 1) && prctl(PR_CAPBSET_DROP, cap) < 0)
			return -1;
	}
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0 && errno != EINVAL)
		return -1;
	return 0;
}

static int drop_caps(uint64_t keep_mask)
{
	struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct data[2] = { { 0 } };

	if (drop_bounding_and_ambient(keep_mask) < 0)
		return -1;

	data[0].effective = data[0].permitted = data[0].inheritable = (uint32_t)keep_mask;
	data[1].effective = data[1].permitted = data[1].inheritable = (uint32_t)(keep_mask >> 32);
	if (syscall(SYS_capset, &header, data) < 0)
		return -1;

	for (int cap = 0; cap < NUM_CAPS; cap++) {
		if ((keep_mask >> cap & 1) && prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) < 0)
			return -1;
	}
	return 0;
}

static void set_rlimit(struct ns_ctx *ctx, int resource, uint64_t value, const char *name)
{
	struct rlimit lim = { value, value };

	if (setrlimit(resource, &lim) < 0)
		ns_die(ctx, "rlimit %s", name);
}

/* Leave root while we still can: bounding set first, then ids; the switch clears the rest. */
static void switch_user(struct ns_ctx *ctx, const juno_spec *spec)
{
	if (drop_bounding_and_ambient(0) < 0)
		ns_die(ctx, "drop capabilities");
	if (spec->idmap_full && setgroups(0, NULL) < 0)
		ns_die(ctx, "setgroups");
	if (setresgid(spec->gid, spec->gid, spec->gid) < 0)
		ns_die(ctx, "setgid %u", (unsigned)spec->gid);
	if (setresuid(spec->uid, spec->uid, spec->uid) < 0)
		ns_die(ctx, "setuid %u", (unsigned)spec->uid);
}

int ns_harden(struct ns_ctx *ctx)
{
	const juno_spec *spec = ctx->spec;
	char landlock_why[160] = "";
	int rc;

	if (spec->limit_set[JUNO_LIMIT_NOFILE])
		set_rlimit(ctx, RLIMIT_NOFILE, spec->limit[JUNO_LIMIT_NOFILE], "nofile");
	if (!ctx->cg) {
		if (spec->limit_set[JUNO_LIMIT_PIDS])
			set_rlimit(ctx, RLIMIT_NPROC, spec->limit[JUNO_LIMIT_PIDS], "pids");
		if (spec->limit_set[JUNO_LIMIT_MEMORY])
			set_rlimit(ctx, RLIMIT_AS, spec->limit[JUNO_LIMIT_MEMORY], "memory");
	}

	close_others();
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		ns_die(ctx, "no_new_privs");

	rc = ns_landlock_apply(spec, landlock_why, sizeof landlock_why);
	if (rc < 0) {
		errno = -rc;
		ns_die(ctx, "landlock%s%s", landlock_why[0] ? " " : "", landlock_why);
	}

	if (spec->user_set && (spec->uid || spec->gid))
		switch_user(ctx, spec);

	if (drop_caps(spec->keepcaps | (spec->nesting ? NESTING_CAPS : 0)) < 0)
		ns_die(ctx, "drop capabilities");

	rc = ns_seccomp_apply(spec);
	if (rc < 0) {
		errno = -rc;
		ns_die(ctx, "seccomp");
	}
	return 0;
}
