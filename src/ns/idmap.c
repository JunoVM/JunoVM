/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "ns.h"
#include <errno.h>
#include <sched.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

/* uid/gid maps are written as "inner outer count" lines */
#define NEWIDMAP_ARGS 5
#define NUM_BUF 32

static int write_proc_file(pid_t pid, const char *file, const char *text)
{
	char path[64];
	int fd;
	ssize_t written;
	int saved;

	ns_fmt(path, sizeof path, "/proc/%d/%s", (int)pid, file);
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	written = write(fd, text, strlen(text));
	saved = written < 0 ? errno : 0;
	close(fd);
	return -saved;
}

/* Single-id map: inner root is the given id of the parent namespace. */
int ns_write_idmap(pid_t pid, uid_t uid, gid_t gid)
{
	char line[64];
	int rc;

	ns_fmt(line, sizeof line, "0 %u 1\n", (unsigned)uid);
	rc = write_proc_file(pid, "uid_map", line);
	if (rc)
		return rc;
	rc = write_proc_file(pid, "setgroups", "deny\n");
	if (rc)
		return rc;
	ns_fmt(line, sizeof line, "0 %u 1\n", (unsigned)gid);
	return write_proc_file(pid, "gid_map", line);
}

/* --- full maps through newuidmap/newgidmap --- */
#include <ctype.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

static int find_tool(const char *name, char *out, size_t len)
{
	const char *path = getenv("PATH");
	char *copy = strdup(path && *path ? path : "/usr/bin:/bin:/usr/sbin:/sbin");
	char *save = NULL;
	int found = -1;

	for (char *dir = strtok_r(copy, ":", &save); dir && found < 0; dir = strtok_r(NULL, ":", &save)) {
		snprintf(out, len, "%s/%s", dir, name);
		if (access(out, X_OK) == 0)
			found = 0;
	}
	free(copy);
	return found;
}

/* tests may point the range lookup elsewhere; /etc/subuid and /etc/subgid otherwise */
static const char *subid_file(int want_gid)
{
	const char *override = getenv(want_gid ? "JUNO_SUBGID_FILE" : "JUNO_SUBUID_FILE");

	return override && *override ? override : (want_gid ? "/etc/subgid" : "/etc/subuid");
}

/* first "user:start:count" or "uid:start:count" line of /etc/subuid or /etc/subgid */
static int read_subid_range(const char *file, unsigned long *start, unsigned long *count)
{
	char line[256], uid_text[24], pw_buf[1024];
	struct passwd pw, *pw_result = NULL;
	FILE *fp;
	int found = -1;

	getpwuid_r(getuid(), &pw, pw_buf, sizeof pw_buf, &pw_result);
	snprintf(uid_text, sizeof uid_text, "%u", getuid());
	fp = fopen(file, "re");
	if (!fp)
		return -1;

	while (found < 0 && fgets(line, sizeof line, fp)) {
		char *first_colon = strchr(line, ':');
		char *second_colon = first_colon ? strchr(first_colon + 1, ':') : NULL;

		if (!second_colon)
			continue;
		*first_colon = 0;
		if ((pw_result && !strcmp(line, pw_result->pw_name)) || !strcmp(line, uid_text)) {
			*start = strtoul(first_colon + 1, NULL, 10);
			*count = strtoul(second_colon + 1, NULL, 10);
			if (*count > 0)
				found = 0;
		}
	}
	fclose(fp);
	return found;
}

int juno_idmap_full_available(char *why, size_t len)
{
	char tool_path[64];
	unsigned long start, count;

	if (find_tool("newuidmap", tool_path, sizeof tool_path) ||
	    find_tool("newgidmap", tool_path, sizeof tool_path)) {
		snprintf(why, len, "newuidmap/newgidmap are not installed (package uidmap)");
		return 0;
	}
	if (read_subid_range(subid_file(0), &start, &count)) {
		snprintf(why, len, "no subuid range for uid %u in %s", getuid(), subid_file(0));
		return 0;
	}
	if (read_subid_range(subid_file(1), &start, &count)) {
		snprintf(why, len, "no subgid range for uid %u in %s", getuid(), subid_file(1));
		return 0;
	}
	snprintf(why, len, "subuid %lu+%lu", start, count);
	return 1;
}

/* Map inner 0 to the caller and inner 1.. to [start, start+count), through the setuid helper. */
static int run_idmap_tool(const char *tool, pid_t pid, unsigned long caller_id, unsigned long start,
	unsigned long count, char *err, size_t err_len)
{
	char path[64], arg[NEWIDMAP_ARGS][NUM_BUF];
	int err_pipe[2];
	pid_t child;
	ssize_t got;
	int status;

	if (find_tool(tool, path, sizeof path)) {
		snprintf(err, err_len, "%s not found", tool);
		return -ENOENT;
	}
	if (pipe2(err_pipe, O_CLOEXEC) < 0)
		return -errno;

	snprintf(arg[0], NUM_BUF, "%d", (int)pid);
	snprintf(arg[1], NUM_BUF, "%lu", caller_id);
	snprintf(arg[2], NUM_BUF, "%lu", start);
	snprintf(arg[3], NUM_BUF, "%lu", count);
	char *argv[] = { (char *)tool, arg[0], "0", arg[1], "1", "1", arg[2], arg[3], NULL };

	fflush(NULL);
	child = fork();
	if (child == 0) {
		dup2(err_pipe[1], 2);
		execv(path, argv);
		_exit(127);
	}

	close(err_pipe[1]);
	got = read(err_pipe[0], err, err_len - 1);
	err[got > 0 ? got : 0] = 0;
	err[strcspn(err, "\n")] = 0;
	close(err_pipe[0]);

	waitpid(child, &status, 0);
	return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -EPERM;
}

/* cell 0 -> the caller, cell 1.. -> the caller's subuid/subgid range */
int ns_write_idmap_full(pid_t pid, char *err, size_t err_len)
{
	unsigned long uid_start, uid_count, gid_start, gid_count;
	int rc;

	if (read_subid_range(subid_file(0), &uid_start, &uid_count) ||
	    read_subid_range(subid_file(1), &gid_start, &gid_count)) {
		snprintf(err, err_len, "no subuid/subgid range for uid %u", getuid());
		return -ENOENT;
	}
	rc = run_idmap_tool("newuidmap", pid, getuid(), uid_start, uid_count, err, err_len);
	if (rc)
		return rc;
	return run_idmap_tool("newgidmap", pid, getgid(), gid_start, gid_count, err, err_len);
}

/* Remove a tree that holds files owned by our subuids: plain unlink first, then
 * from inside a user namespace that maps them. */
int juno_rmtree(const char *path)
{
	struct stat st;
	int up[2], down[2];
	char err[200] = "";
	char token = 0;
	pid_t child;
	int rc, wait_status;

	juno_rm_tree(path);
	if (lstat(path, &st) < 0)
		return 0;

	if (pipe2(up, O_CLOEXEC) < 0 || pipe2(down, O_CLOEXEC) < 0)
		return -errno;

	fflush(NULL);
	child = fork();
	if (child == 0) {
		char byte = 0;

		if (unshare(CLONE_NEWUSER) < 0)
			_exit(2);
		if (write(up[1], &byte, 1) != 1 || read(down[0], &byte, 1) != 1)
			_exit(3);
		juno_rm_tree(path);
		_exit(lstat(path, &st) < 0 ? 0 : 1);
	}

	close(up[1]);
	close(down[0]);
	if (read(up[0], &token, 1) != 1)
		rc = -EIO;
	else
		rc = ns_write_idmap_full(child, err, sizeof err);
	if (write(down[1], &token, 1) < 0)
		rc = rc ?: -EIO;
	close(up[0]);
	close(down[1]);

	waitpid(child, &wait_status, 0);
	if (rc) {
		juno_seterr("remove %s: %s", path, err);
		return rc;
	}
	return WIFEXITED(wait_status) && WEXITSTATUS(wait_status) == 0 ? 0 : -EACCES;
}
