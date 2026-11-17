/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "ns.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* pasta gets this long to configure the namespace (250 * 20 ms) */
#define PASTA_POLLS 250
#define PASTA_POLL_USEC 20000

static int find_pasta(char *out, size_t len)
{
	const char *path = getenv("PATH");
	char *copy = strdup(path && *path ? path : "/usr/local/bin:/usr/bin:/bin");
	char *save = NULL;
	int found = -1;

	for (char *dir = strtok_r(copy, ":", &save); dir && found < 0; dir = strtok_r(NULL, ":", &save)) {
		snprintf(out, len, "%s/pasta", dir);
		if (access(out, X_OK) == 0)
			found = 0;
	}
	free(copy);
	return found;
}

/* First line of "pasta --version" output, or empty. */
static void read_pasta_version(const char *pasta_path, char *version, size_t len)
{
	int out_pipe[2];
	pid_t child;
	ssize_t got;

	version[0] = 0;
	if (pipe(out_pipe) != 0)
		return;
	child = fork();
	if (child == 0) {
		dup2(out_pipe[1], 1);
		dup2(out_pipe[1], 2);
		execl(pasta_path, "pasta", "--version", (char *)NULL);
		_exit(127);
	}
	close(out_pipe[1]);
	got = read(out_pipe[0], version, len - 1);
	version[got > 0 ? got : 0] = 0;
	version[strcspn(version, "\n")] = 0;
	close(out_pipe[0]);
	waitpid(child, NULL, 0);
}

/* The binary prints nothing: ask the package database. */
static void read_passt_package_version(char *version, size_t len)
{
	FILE *fp = fopen("/var/lib/dpkg/status", "re");
	char line[300];
	int in_passt = 0;

	while (fp && fgets(line, sizeof line, fp)) {
		if (!strncmp(line, "Package: passt\n", 15)) {
			in_passt = 1;
		} else if (!strncmp(line, "Package:", 8)) {
			in_passt = 0;
		} else if (in_passt && !strncmp(line, "Version: ", 9)) {
			line[strcspn(line, "\n")] = 0;
			snprintf(version, len, "passt %s", line + 9);
			break;
		}
	}
	if (fp)
		fclose(fp);
}

int juno_pasta_available(char *version, size_t len)
{
	char path[600];

	if (find_pasta(path, sizeof path))
		return 0;
	if (version && len) {
		read_pasta_version(path, version, len);
		if (!version[0])
			read_passt_package_version(version, len);
	}
	return 1;
}

static int has_default_route(pid_t pid)
{
	char path[64], line[256];
	FILE *fp;
	int found = 0;

	snprintf(path, sizeof path, "/proc/%d/net/route", (int)pid);
	fp = fopen(path, "re");
	if (!fp)
		return 0;
	while (fgets(line, sizeof line, fp)) {
		char ifname[32], dest[16];

		if (sscanf(line, "%31s %15s", ifname, dest) == 2 &&
		    !strcmp(ifname, "eth0") && !strcmp(dest, "00000000"))
			found = 1;
	}
	fclose(fp);
	return found;
}

/* Attach pasta to the cell's user+net namespaces while the cell waits for its
 * start signal. pasta runs in the foreground as our child, dies with us, and
 * exits by itself when the namespace is gone. */
int ns_pasta_start(const juno_spec *spec, pid_t cell_pid, juno_cell *cell)
{
	char path[600], pid_text[24], output[300] = "";
	int out_pipe[2];
	pid_t pasta;
	char *argv[] = { "pasta", "-4", "-f", "-q", "--config-net", "-I", "eth0", "-a", "10.0.2.15",
		"-n", "24", "-g", "10.0.2.2", "--dns-forward", "10.0.2.3", "-t", "none", "-u", "none",
		"-T", "none", "-U", "none", "--no-dhcpv6", "--no-ndp", "--no-ra", "--no-dhcp",
		"--no-map-gw", pid_text, NULL };

	if (find_pasta(path, sizeof path)) {
		juno_seterr("net = nat needs pasta (package passt), which is not in PATH");
		return -ENOENT;
	}
	snprintf(pid_text, sizeof pid_text, "%d", (int)cell_pid);

	if (spec->nat_host) {	/* the gateway address reaches the host's loopback */
		for (int i = 0; argv[i]; i++) {
			if (!strcmp(argv[i], "--no-map-gw"))
				argv[i] = "-q";
		}
	}

	if (pipe2(out_pipe, O_CLOEXEC) < 0)
		return -errno;
	fflush(NULL);
	pasta = fork();
	if (pasta < 0) {
		close(out_pipe[0]);
		close(out_pipe[1]);
		return -errno;
	}
	if (pasta == 0) {
		int nul;

		prctl(PR_SET_PDEATHSIG, SIGKILL);
		nul = open("/dev/null", O_RDWR);
		dup2(nul, 0);
		dup2(out_pipe[1], 1);
		dup2(out_pipe[1], 2);
		syscall(SYS_close_range, 3, ~0u, 0);
		execv(path, argv);
		_exit(127);
	}
	close(out_pipe[1]);
	cell->pastapid = pasta;

	for (int i = 0; i < PASTA_POLLS; i++) {
		int status;

		if (waitpid(pasta, &status, WNOHANG) == pasta) {
			ssize_t got = read(out_pipe[0], output, sizeof output - 1);

			output[got > 0 ? got : 0] = 0;
			output[strcspn(output, "\n")] = 0;
			close(out_pipe[0]);
			cell->pastapid = 0;
			juno_seterr("pasta failed to attach to the cell's network: %s",
				output[0] ? output : "no output (is there a default route on the host?)");
			return -ECONNREFUSED;
		}
		if (has_default_route(cell_pid)) {
			close(out_pipe[0]);
			return 0;
		}
		usleep(PASTA_POLL_USEC);
	}

	close(out_pipe[0]);
	kill(pasta, SIGKILL);
	waitpid(pasta, NULL, 0);
	cell->pastapid = 0;
	juno_seterr("pasta did not configure the cell's network within 5 s");
	return -ETIMEDOUT;
}
