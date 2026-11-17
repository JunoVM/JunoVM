/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "ns.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <unistd.h>

int ns_mount_dev(int root_fd, const char *shm_opts)
{
	static const char *const nodes[] = { "null", "zero", "full", "random", "urandom", "tty" };
	/* { target, link name } inside /dev */
	static const char *const links[][2] = {
		{ "pts/ptmx", "ptmx" }, { "/proc/self/fd", "fd" }, { "/proc/self/fd/0", "stdin" },
		{ "/proc/self/fd/1", "stdout" }, { "/proc/self/fd/2", "stderr" },
	};
	char host_path[32];
	int dev_fd;

	if (ns_mount_at(root_fd, "tmpfs", "/dev", "tmpfs", MS_NOSUID | MS_NOEXEC, "mode=755,size=1m", 0, 0) < 0)
		return -1;

	/* a missing host node is skipped; any other failure aborts */
	for (size_t i = 0; i < sizeof nodes / sizeof *nodes; i++) {
		ns_fmt(host_path, sizeof host_path, "/dev/%s", nodes[i]);
		if (ns_mount_at(root_fd, host_path, host_path, NULL, MS_BIND, NULL, 1, 0) < 0 && errno != ENOENT)
			return -1;
	}

	if (ns_mount_at(root_fd, "devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC,
			"newinstance,ptmxmode=0666,mode=0620", 0, 0) < 0)
		return -1;
	if (ns_mount_at(root_fd, "tmpfs", "/dev/shm", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
			shm_opts, 0, 0) < 0)
		return -1;

	dev_fd = ns_open_in(root_fd, "/dev", 0);
	if (dev_fd < 0)
		return -1;
	for (size_t i = 0; i < sizeof links / sizeof *links; i++) {
		if (symlinkat(links[i][0], dev_fd, links[i][1]) < 0) {
			close(dev_fd);
			return -1;
		}
	}
	close(dev_fd);
	return 0;
}
