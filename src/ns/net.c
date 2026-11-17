/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "ns.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* A shared network is a user+net namespace pair kept alive by a holder
 * process. Cells join the holder's user namespace, so they own the net
 * namespace's capabilities without any privilege. State: <runtime>/.net/NAME */

/* the holder exits after this long without a member */
#define HOLDER_POLL_USEC 200000
#define HOLDER_IDLE_MS 3000
#define HOLDER_CLOSE_FDS 64

static int net_dir(const char *name, char *out, size_t len)
{
	char runtime_dir[512], data_dir[512];

	if (juno_dirs(".net", runtime_dir, data_dir, sizeof runtime_dir) < 0)
		return -1;
	snprintf(out, len, "%s/%s", runtime_dir, name);
	return 0;
}

/* The holder's pid if it is alive, else 0. */
static int holder_alive(const char *dir)
{
	char path[600];
	int pid = 0;
	FILE *fp;

	snprintf(path, sizeof path, "%s/pid", dir);
	fp = fopen(path, "re");
	if (!fp)
		return 0;
	if (fscanf(fp, "%d", &pid) != 1)
		pid = 0;
	fclose(fp);
	return pid > 0 && kill(pid, 0) == 0 ? pid : 0;
}

/* Count live member files (m.PID); stale ones are removed. */
static int count_members(const char *dir)
{
	DIR *dh = opendir(dir);
	struct dirent *entry;
	int alive = 0;

	if (!dh)
		return 0;
	while ((entry = readdir(dh))) {
		int pid;

		if (sscanf(entry->d_name, "m.%d", &pid) != 1)
			continue;
		if (kill(pid, 0) == 0)
			alive++;
		else
			unlinkat(dirfd(dh), entry->d_name, 0);
	}
	closedir(dh);
	return alive;
}

static void holder_main(const char *dir, int ready_fd, uid_t uid, gid_t gid)
{
	char pid_path[700];
	FILE *fp;
	int pid, nul;
	uint64_t last_member_ms;

	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0 || ns_write_idmap(getpid(), uid, gid) ||
	    ns_net_up() < 0)
		_exit(1);

	snprintf(pid_path, sizeof pid_path, "%s/pid", dir);
	fp = fopen(pid_path, "we");
	if (!fp)
		_exit(1);
	fprintf(fp, "%d\n", getpid());
	fclose(fp);

	pid = getpid();
	if (write(ready_fd, &pid, sizeof pid) != sizeof pid)
		_exit(1);
	close(ready_fd);

	nul = open("/dev/null", O_RDWR);
	dup2(nul, 0);
	dup2(nul, 1);
	dup2(nul, 2);
	for (int fd = 3; fd < HOLDER_CLOSE_FDS; fd++)
		close(fd);

	last_member_ms = juno_now_ms();
	for (;;) {
		usleep(HOLDER_POLL_USEC);
		if (count_members(dir))
			last_member_ms = juno_now_ms();
		else if (juno_now_ms() - last_member_ms > HOLDER_IDLE_MS)
			break;
	}
	unlink(pid_path);
	_exit(0);
}

/* Double-fork a holder and return its pid through ready_pipe. */
static int start_holder(const char *dir, const char *name, int lock_fd, int *pid)
{
	int ready_pipe[2];
	uid_t uid = getuid();
	gid_t gid = getgid();
	pid_t middle;

	if (pipe2(ready_pipe, O_CLOEXEC) < 0) {
		close(lock_fd);
		return -errno;
	}
	fflush(NULL);
	middle = fork();
	if (middle == 0) {
		setsid();
		if (fork() == 0)
			holder_main(dir, ready_pipe[1], uid, gid);
		_exit(0);
	}

	close(ready_pipe[1]);
	waitpid(middle, NULL, 0);
	if (read(ready_pipe[0], pid, sizeof *pid) != sizeof *pid) {
		close(ready_pipe[0]);
		close(lock_fd);
		juno_seterr("shared net %s: holder failed to start", name);
		return -EIO;
	}
	close(ready_pipe[0]);
	return 0;
}

int ns_net_holder(const char *name, int *userfd, int *netfd)
{
	char dir[600], path[700];
	int lock_fd, pid, saved;
	int rc;

	if (net_dir(name, dir, sizeof dir) < 0) {
		juno_seterr("shared net: no runtime dir");
		return -EINVAL;
	}
	rc = juno_mkdir_secure(dir, 3);
	if (rc)
		return rc;

	snprintf(path, sizeof path, "%s/lock", dir);
	lock_fd = open(path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (lock_fd < 0 || flock(lock_fd, LOCK_EX) < 0) {
		juno_seterr("shared net %s: lock: %s", name, strerror(errno));
		return -errno;
	}

	pid = holder_alive(dir);
	if (!pid) {
		rc = start_holder(dir, name, lock_fd, &pid);
		if (rc)
			return rc;
	}

	snprintf(path, sizeof path, "/proc/%d/ns/user", pid);
	*userfd = open(path, O_RDONLY | O_CLOEXEC);
	snprintf(path, sizeof path, "/proc/%d/ns/net", pid);
	*netfd = open(path, O_RDONLY | O_CLOEXEC);
	saved = errno;
	close(lock_fd);

	if (*userfd < 0 || *netfd < 0) {
		juno_seterr("shared net %s: open namespaces of holder %d: %s", name, pid, strerror(saved));
		if (*userfd >= 0)
			close(*userfd);
		if (*netfd >= 0)
			close(*netfd);
		*userfd = *netfd = -1;
		return -saved;
	}
	return 0;
}

int ns_net_register_path(const char *name, char *out, size_t len)
{
	char dir[600];

	if (net_dir(name, dir, sizeof dir) < 0)
		return -1;
	snprintf(out, len, "%s", dir);	/* the relay names its member file after its own pid */
	return 0;
}

int juno_net_list(char *buf, size_t len)
{
	char runtime_dir[512], data_dir[512], dir[512];
	size_t used = 0;
	DIR *dh;
	struct dirent *entry;

	buf[0] = 0;
	if (juno_dirs(".net", runtime_dir, data_dir, sizeof runtime_dir) < 0)
		return -EINVAL;
	snprintf(dir, sizeof dir, "%s", runtime_dir);

	dh = opendir(dir);
	if (!dh)
		return 0;
	while ((entry = readdir(dh))) {
		char sub[800];
		int pid;

		if (entry->d_name[0] == '.')
			continue;
		snprintf(sub, sizeof sub, "%s/%s", dir, entry->d_name);
		pid = holder_alive(sub);
		if (pid && used < len)
			used += snprintf(buf + used, len - used, "%s %d %d\n", entry->d_name, pid,
					 count_members(sub));
	}
	closedir(dh);
	return 0;
}

int juno_net_remove(const char *name)
{
	char dir[600];
	int pid;

	if (!juno_valid_name(name) || net_dir(name, dir, sizeof dir) < 0)
		return -EINVAL;
	pid = holder_alive(dir);
	if (!pid) {
		juno_rm_tree(dir);
		return -ENOENT;
	}
	kill(pid, SIGTERM);
	juno_rm_tree(dir);
	return 0;
}
