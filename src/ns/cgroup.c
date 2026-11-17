/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "ns.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CG "/sys/fs/cgroup"
#define CG_PATH_MAX 600

static int own_cgroup(char *out, size_t len)
{
	FILE *fp = fopen("/proc/self/cgroup", "re");
	char line[512];
	int found = 0;

	if (!fp)
		return -errno;
	while (fgets(line, sizeof line, fp)) {
		if (strncmp(line, "0::", 3))
			continue;
		line[strcspn(line, "\n")] = 0;
		snprintf(out, len, CG "%.380s", line + 3);
		found = 1;
		break;
	}
	fclose(fp);
	return found ? 0 : -ENOENT;
}

static int write_file(const char *dir, const char *name, const char *value)
{
	char path[CG_PATH_MAX];
	int fd;
	ssize_t written;
	int saved;

	snprintf(path, sizeof path, "%s/%s", dir, name);
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	written = write(fd, value, strlen(value));
	saved = written < 0 ? errno : 0;
	close(fd);
	return -saved;
}

static int is_writable(const char *dir, const char *name)
{
	char path[CG_PATH_MAX];

	snprintf(path, sizeof path, "%s/%s", dir, name);
	return access(path, W_OK) == 0;
}

/* Can we create a child of dir that has memory and pids controllers? Sets why when not. */
static int try_base(const char *dir, char *why, size_t why_len)
{
	char probe[480];
	int has_memory, has_pids;

	if (access(dir, W_OK) < 0) {
		snprintf(why, why_len, "%s is not writable by uid %u", dir, getuid());
		return 0;
	}
	snprintf(probe, sizeof probe, "%s/juno-probe-%d", dir, getpid());
	if (mkdir(probe, 0755) < 0) {
		snprintf(why, why_len, "cannot create a child of %s: %s", dir, strerror(errno));
		return 0;
	}
	has_memory = is_writable(probe, "memory.max");
	has_pids = is_writable(probe, "pids.max");
	rmdir(probe);

	if (!has_memory || !has_pids) {
		snprintf(why, why_len, "%s lacks %s%s%s controller in subtree_control", dir,
			has_memory ? "" : "memory", (!has_memory && !has_pids) ? "+" : "",
			has_pids ? "" : "pids");
		return 0;
	}
	return 1;
}

/* Delegation is usable when we may create a child of our own cgroup (or of its
 * parent, for a manager that keeps itself in a leaf) that gets memory and pids. */
int ns_cgroup_probe(char *base, size_t base_len, char *why, size_t why_len)
{
	char own[400], parent[400], parent_why[256];
	struct stat st;
	char *slash;

	if (stat(CG "/cgroup.controllers", &st) < 0) {
		snprintf(why, why_len, "cgroup v2 is not mounted at " CG);
		return 0;
	}
	if (own_cgroup(own, sizeof own) < 0) {
		snprintf(why, why_len, "cannot read /proc/self/cgroup");
		return 0;
	}
	if (try_base(own, why, why_len)) {
		snprintf(why, why_len, "delegated subtree %s", own);
		snprintf(base, base_len, "%s", own);
		return 1;
	}

	/* never climb above the cgroup root */
	snprintf(parent, sizeof parent, "%s", own);
	slash = strrchr(parent, '/');
	if (slash && slash >= parent + sizeof CG - 1 && strlen(own) > sizeof CG) {
		*slash = 0;
		if (try_base(parent, parent_why, sizeof parent_why)) {
			snprintf(base, base_len, "%s", parent);
			snprintf(why, why_len, "delegated subtree %s", parent);
			return 1;
		}
	}
	return 0;
}

/* Move pid into the cgroup that owns the given cgroup.procs path. */
static int attach_pid(const char *procs_path, pid_t pid)
{
	char pid_text[32], dir[CG_PATH_MAX];
	char *slash;

	snprintf(pid_text, sizeof pid_text, "%d", pid);
	snprintf(dir, sizeof dir, "%s", procs_path);
	slash = strrchr(dir, '/');
	*slash = 0;
	return write_file(dir, "cgroup.procs", pid_text);
}

static int write_limit(const char *leaf, const char *file, unsigned long long value)
{
	char text[32];

	snprintf(text, sizeof text, "%llu", value);
	return write_file(leaf, file, text);
}

static int write_limits(const char *leaf, const juno_spec *spec)
{
	int rc = 0;

	if (spec->limit_set[JUNO_LIMIT_MEMORY]) {
		rc = write_limit(leaf, "memory.max", spec->limit[JUNO_LIMIT_MEMORY]);
		write_file(leaf, "memory.swap.max", "0");
	}
	if (!rc && spec->limit_set[JUNO_LIMIT_PIDS])
		rc = write_limit(leaf, "pids.max", spec->limit[JUNO_LIMIT_PIDS]);
	if (!rc && spec->limit_set[JUNO_LIMIT_CPU_WEIGHT])
		rc = write_limit(leaf, "cpu.weight", spec->limit[JUNO_LIMIT_CPU_WEIGHT]);
	return rc;
}

/* The limits stay on leaf, out of the cell's sight; the cell owns leaf/cell. Its processes
 * start in leaf/cell/init, which cell->cgprocs points at. */
static int setup_nested_leaf(const char *leaf, pid_t pid, juno_cell *cell)
{
	char path[560];
	int rc = 0;

	write_file(leaf, "cgroup.subtree_control", "+memory");
	write_file(leaf, "cgroup.subtree_control", "+pids");
	write_file(leaf, "cgroup.subtree_control", "+cpu");

	snprintf(path, sizeof path, "%s/cell", leaf);
	if (mkdir(path, 0755) < 0)
		rc = -errno;
	snprintf(path, sizeof path, "%s/cell/init", leaf);
	if (!rc && mkdir(path, 0755) < 0)
		rc = -errno;
	snprintf(path, sizeof path, "%s/cell/cgroup.procs", leaf);
	if (!rc)
		rc = attach_pid(path, pid);

	snprintf(path, sizeof path, "%s/cell/init/cgroup.procs", leaf);
	cell->cgprocs = strdup(path);
	return rc;
}

int ns_cgroup_attach(const juno_spec *spec, pid_t pid, juno_cell *cell)
{
	char base[400], why[256], leaf[480], procs[560];
	int rc;

	if (!spec->limit_set[JUNO_LIMIT_MEMORY] && !spec->limit_set[JUNO_LIMIT_PIDS] &&
	    !spec->limit_set[JUNO_LIMIT_CPU_WEIGHT] && !spec->nesting)
		return 0;

	if (!ns_cgroup_probe(base, sizeof base, why, sizeof why)) {
		if (spec->limit_set[JUNO_LIMIT_CPU_WEIGHT]) {
			juno_seterr("cgroup: cpu weight needs cgroups: %s", why);
			return -ENOTSUP;
		}
		return 0;	/* memory and pids fall back to rlimits in the child */
	}

	snprintf(leaf, sizeof leaf, "%s/juno-%d", base, pid);
	if (mkdir(leaf, 0755) < 0) {
		juno_seterr("cgroup: mkdir %s: %s", leaf, strerror(errno));
		return -errno;
	}
	cell->cgroup = strdup(leaf);

	rc = write_limits(leaf, spec);
	if (!rc && spec->nesting) {
		rc = setup_nested_leaf(leaf, pid, cell);
	} else if (!rc) {
		snprintf(procs, sizeof procs, "%s/cgroup.procs", leaf);
		rc = attach_pid(procs, pid);
		cell->cgprocs = strdup(procs);
	}
	if (rc)
		juno_seterr("cgroup: configure %s: %s", leaf, strerror(-rc));
	return rc;
}

/* In the cell: move into leaf "init" and enable controllers for children of
 * the cgroup namespace root, so the cell can run cgroups of its own. */
void ns_cgroup_delegate(struct ns_ctx *ctx)
{
	static const char *const controllers[] = { "+memory", "+pids", "+cpu" };
	int fd;

	if (ctx->cg != 2)
		return;

	mkdir("/sys/fs/cgroup/init", 0755);
	fd = open("/sys/fs/cgroup/init/cgroup.procs", O_WRONLY | O_CLOEXEC);
	if (fd < 0 || write(fd, "0", 1) != 1)
		ns_die(ctx, "move into the delegated cgroup leaf");
	close(fd);

	for (size_t i = 0; i < sizeof controllers / sizeof *controllers; i++) {
		ssize_t written;

		fd = open("/sys/fs/cgroup/cgroup.subtree_control", O_WRONLY | O_CLOEXEC);
		if (fd < 0)
			continue;
		written = write(fd, controllers[i], strlen(controllers[i]));
		(void)written;
		close(fd);
	}
}

/* cgroup directories cannot be removed while a dying process still counts; retry briefly */
#define RMDIR_RETRIES 1000
#define RMDIR_RETRY_USEC 10000

static void rmdir_retry(const char *path)
{
	for (int i = 0; i < RMDIR_RETRIES && rmdir(path) < 0 && errno == EBUSY; i++)
		usleep(RMDIR_RETRY_USEC);
}

static void remove_children(const char *path)
{
	DIR *dir = opendir(path);
	struct dirent *entry;

	while (dir && (entry = readdir(dir))) {
		char child[1100];

		if (entry->d_type != DT_DIR || entry->d_name[0] == '.')
			continue;
		snprintf(child, sizeof child, "%s/%s", path, entry->d_name);
		remove_children(child);
		rmdir_retry(child);
	}
	if (dir)
		closedir(dir);
}

/* The cell is gone, but its processes may need a moment to finish exiting: ask the kernel to
 * kill whatever is left in the subtree and wait (bounded) until the cgroup is empty. */
void ns_cgroup_remove(const char *path)
{
	write_file(path, "cgroup.kill", "1");
	remove_children(path);
	rmdir_retry(path);
}
