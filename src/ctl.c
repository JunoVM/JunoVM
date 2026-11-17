/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define PATH_BUF 512
#define MAX_CTL_MESSAGE (1u << 20)
#define POLL_USEC 20000
#define CTL_MAX_FDS 4
#define MAX_REMOVE_DEPTH_START 64

/* Runtime (sockets, locks) and data (specs, logs) directories of a cell or area. */
int juno_dirs(const char *name, char *runtime_dir, char *data_dir, size_t len)
{
	const char *env;

	if ((env = getenv("JUNO_RUNTIME_DIR")) && *env)
		snprintf(runtime_dir, len, "%s/%s", env, name);
	else if ((env = getenv("XDG_RUNTIME_DIR")) && *env)
		snprintf(runtime_dir, len, "%s/juno/%s", env, name);
	else
		snprintf(runtime_dir, len, "/tmp/juno-%u/%s", getuid(), name);

	if ((env = getenv("JUNO_DATA_DIR")) && *env)
		snprintf(data_dir, len, "%s/%s", env, name);
	else if ((env = getenv("XDG_DATA_HOME")) && *env)
		snprintf(data_dir, len, "%s/juno/%s", env, name);
	else if ((env = getenv("HOME")) && *env)
		snprintf(data_dir, len, "%s/.local/share/juno/%s", env, name);
	else
		return -1;
	return 0;
}

/* Remove the entries of the current directory; returns the first subdirectory name found
 * (to descend into) or NULL when only files were left. */
static char *remove_files_find_subdir(int *err)
{
	DIR *dir = opendir(".");
	struct dirent *entry;
	char *subdir = NULL;

	if (!dir) {
		*err = -errno;
		return NULL;
	}
	while ((entry = readdir(dir))) {
		struct stat st;

		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;
		if (fstatat(dirfd(dir), entry->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
			continue;
		if (S_ISDIR(st.st_mode)) {
			if (!subdir)
				subdir = strdup(entry->d_name);
		} else {
			unlinkat(dirfd(dir), entry->d_name, 0);
		}
	}
	closedir(dir);
	return subdir;
}

/* Iterative removal in a child of its own (it changes directory, which a library must not do to
 * its caller): no recursion and no path buffers, so a payload cannot make the depth of its tree
 * crash us. */
static int remove_tree_iteratively(const char *path)
{
	struct stat st;
	char absolute[4096];
	char **stack = NULL;
	size_t depth = 0, capacity = 0;

	if (lstat(path, &st) < 0)
		return errno == ENOENT ? 0 : -errno;
	if (!S_ISDIR(st.st_mode))
		return unlink(path) < 0 ? -errno : 0;

	if (path[0] == '/') {
		snprintf(absolute, sizeof absolute, "%s", path);
	} else if (!getcwd(absolute, sizeof absolute - strlen(path) - 2)) {
		return -errno;
	} else {
		strcat(absolute, "/");
		strcat(absolute, path);
	}

	chmod(path, 0700);
	if (chdir(path) < 0)
		return -errno;

	for (;;) {
		int err = 0;
		char *subdir = remove_files_find_subdir(&err);

		if (err)
			return err;
		if (subdir) {
			chmod(subdir, 0700);
			if (chdir(subdir) < 0) {
				int saved = errno;

				free(subdir);
				return -saved;
			}
			if (depth == capacity) {
				capacity = capacity ? capacity * 2 : MAX_REMOVE_DEPTH_START;
				stack = realloc(stack, capacity * sizeof *stack);
				if (!stack)
					return -ENOMEM;
			}
			stack[depth++] = subdir;
			continue;
		}

		if (!depth)
			break;
		subdir = stack[--depth];
		if (chdir("..") < 0) {
			free(subdir);
			return -errno;
		}
		err = rmdir(subdir);
		free(subdir);
		if (err < 0)
			return -errno;
	}
	free(stack);

	if (chdir("/") < 0)
		return -errno;
	return rmdir(absolute) < 0 ? -errno : 0;
}

int juno_rm_tree(const char *path)
{
	struct stat st;
	pid_t child;
	int status;

	if (lstat(path, &st) < 0)
		return -errno;
	fflush(NULL);
	child = fork();
	if (child < 0)
		return -errno;
	if (child == 0)
		_exit(remove_tree_iteratively(path) == 0 ? 0 : 1);
	waitpid(child, &status, 0);
	return lstat(path, &st) < 0 ? 0 : -EACCES;
}

/* A running supervisor holds a shared-lockable file lock on <runtime>/lock. */
static int lock_held(const char *runtime_dir)
{
	char path[700];
	int fd, held;

	snprintf(path, sizeof path, "%s/lock", runtime_dir);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	held = flock(fd, LOCK_SH | LOCK_NB) < 0 && errno == EWOULDBLOCK;
	close(fd);
	return held;
}

/* The value of "key=value" in a small state file; 0 when found. */
static int read_state_value(const char *path, const char *key, char *out, size_t len)
{
	FILE *fp = fopen(path, "re");
	char line[512];
	size_t key_len = strlen(key);
	int found = 0;

	if (!fp)
		return -1;
	while (fgets(line, sizeof line, fp)) {
		if (!strncmp(line, key, key_len) && line[key_len] == '=') {
			line[strcspn(line, "\n")] = 0;
			snprintf(out, len, "%s", line + key_len + 1);
			found = 1;
			break;
		}
	}
	fclose(fp);
	return found ? 0 : -1;
}

/* --- client side of the control socket --- */

int juno_ctl_connect(const char *name)
{
	char runtime_dir[PATH_BUF], data_dir[PATH_BUF];
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd;

	if (!juno_valid_name(name) || juno_dirs(name, runtime_dir, data_dir, sizeof runtime_dir) < 0) {
		juno_seterr("bad cell name '%s'", name ? name : "");
		return -EINVAL;
	}
	if (snprintf(addr.sun_path, sizeof addr.sun_path, "%s/sock", runtime_dir) >= (int)sizeof addr.sun_path) {
		juno_seterr("control socket path too long (%zu bytes, the limit is %zu): %.200s/sock",
			strlen(runtime_dir) + 5, sizeof addr.sun_path - 1, runtime_dir);
		return -ENAMETOOLONG;
	}

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
		int saved = errno;

		close(fd);
		juno_seterr("cell '%s' is not running (%s)", name, strerror(saved));
		return saved == ENOENT || saved == ECONNREFUSED ? -ESRCH : -saved;
	}
	return fd;
}

/* Read (or write, when sending) exactly len bytes. */
static int transfer(int fd, void *buf, size_t len, int sending)
{
	size_t done = 0;

	while (done < len) {
		ssize_t n = sending ? send(fd, (char *)buf + done, len - done, MSG_NOSIGNAL)
				    : read(fd, (char *)buf + done, len - done);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return -1;
		done += n;
	}
	return 0;
}

/* A reply is: u32 length (counting the status), i32 status, payload; an fd may ride along. */
static int read_reply(int fd, char **resp, size_t *resp_len, int *resp_fd)
{
	uint32_t length;
	int32_t status;
	char control[CMSG_SPACE(sizeof(int))];
	struct iovec iov = { &length, 4 };
	struct msghdr msg = {
		.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof control,
	};
	ssize_t got;
	char *payload;

	do {
		got = recvmsg(fd, &msg, MSG_CMSG_CLOEXEC);
	} while (got < 0 && errno == EINTR);
	if (got <= 0)
		return -EPIPE;

	if (resp_fd) {
		struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

		*resp_fd = -1;
		if (cmsg && cmsg->cmsg_type == SCM_RIGHTS)
			memcpy(resp_fd, CMSG_DATA(cmsg), sizeof(int));
	}
	if ((size_t)got < 4 && transfer(fd, (char *)&length + got, 4 - got, 0))
		return -EPIPE;
	if (length < 4 || length > MAX_CTL_MESSAGE || transfer(fd, &status, 4, 0))
		return -EPIPE;

	payload = malloc(length - 4 + 1);
	if (!payload)
		return -ENOMEM;
	if (length > 4 && transfer(fd, payload, length - 4, 0)) {
		free(payload);
		return -EPIPE;
	}
	payload[length - 4] = 0;

	if (resp)
		*resp = payload;
	else
		free(payload);
	if (resp_len)
		*resp_len = length - 4;
	return status;
}

/* Send one request (u32 length, op byte, payload, optional fds) and read the reply. */
int juno_ctl_call(int fd, int op, const void *payload, size_t payload_len, int *fds, int nfds,
	char **resp, size_t *resp_len, int *resp_fd)
{
	uint32_t length = payload_len + 1;
	char *message = malloc(4 + length);
	char control[CMSG_SPACE(sizeof(int) * CTL_MAX_FDS)] = { 0 };
	struct iovec iov;
	struct msghdr msg = { .msg_iovlen = 1 };
	ssize_t sent;

	if (!message)
		return -ENOMEM;
	memcpy(message, &length, 4);
	message[4] = op;
	if (payload_len)
		memcpy(message + 5, payload, payload_len);

	iov = (struct iovec){ message, 4 + length };
	msg.msg_iov = &iov;
	if (nfds) {
		struct cmsghdr *cmsg;

		msg.msg_control = control;
		msg.msg_controllen = CMSG_SPACE(sizeof(int) * nfds);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int) * nfds);
		memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * nfds);
	}

	sent = sendmsg(fd, &msg, MSG_NOSIGNAL);
	if (sent > 0 && (size_t)sent < 4 + length)
		transfer(fd, message + sent, 4 + length - sent, 1);
	free(message);
	if (sent < 0)
		return -errno;
	return read_reply(fd, resp, resp_len, resp_fd);
}

static int call_named(const char *name, int op, const void *payload, size_t payload_len, char **resp)
{
	int fd = juno_ctl_connect(name);
	int rc;

	if (fd < 0)
		return fd;
	rc = juno_ctl_call(fd, op, payload, payload_len, NULL, 0, resp, NULL, NULL);
	close(fd);
	return rc;
}

/* --- remote cell handle --- */

static int remote_kill(juno_cell *cell, int sig)
{
	int32_t signal_number = sig;

	return call_named(cell->name, CTL_KILL, &signal_number, sizeof signal_number, NULL);
}

static int last_exit_status(const char *name, int *status)
{
	char runtime_dir[PATH_BUF], data_dir[PATH_BUF], path[1100], value[64];

	juno_dirs(name, runtime_dir, data_dir, sizeof runtime_dir);
	snprintf(path, sizeof path, "%s/last", data_dir);
	if (read_state_value(path, "exit", value, sizeof value) < 0)
		return -1;
	*status = (atoi(value) & 0xff) << 8;
	return 0;
}

static int remote_wait(juno_cell *cell, int *status, int timeout_ms)
{
	uint64_t deadline = timeout_ms < 0 ? 0 : juno_now_ms() + timeout_ms;

	for (;;) {
		char runtime_dir[PATH_BUF], data_dir[PATH_BUF];

		juno_dirs(cell->name, runtime_dir, data_dir, sizeof runtime_dir);
		if (!lock_held(runtime_dir)) {
			int exit_status = 0;

			last_exit_status(cell->name, &exit_status);
			if (status)
				*status = exit_status;
			cell->done = true;
			return 0;
		}
		if (deadline && juno_now_ms() >= deadline)
			return -ETIMEDOUT;
		usleep(POLL_USEC);
	}
}

/* Exec request: flag byte (1 tty, 2 user), optional "uid:gid", then NUL-separated argv. */
#define EXEC_FLAG_TTY 1
#define EXEC_FLAG_USER 2

static char *pack_exec_request(const juno_cell *cell, char *const argv[], int tty, size_t *len)
{
	char user[40] = "";
	size_t total = 1;
	char *buf, *out;

	if (cell->exec_user_set) {
		snprintf(user, sizeof user, "%d:%d", cell->exec_uid, cell->exec_gid);
		total += strlen(user) + 1;
	}
	for (int i = 0; argv[i]; i++)
		total += strlen(argv[i]) + 1;

	buf = malloc(total);
	if (!buf)
		return NULL;
	out = buf + 1;
	buf[0] = (tty ? EXEC_FLAG_TTY : 0) | (cell->exec_user_set ? EXEC_FLAG_USER : 0);
	if (cell->exec_user_set) {
		size_t user_len = strlen(user) + 1;

		memcpy(out, user, user_len);
		out += user_len;
	}
	for (int i = 0; argv[i]; i++) {
		size_t arg_len = strlen(argv[i]) + 1;

		memcpy(out, argv[i], arg_len);
		out += arg_len;
	}
	*len = total;
	return buf;
}

static int remote_exec(juno_cell *cell, char *const argv[], int *status)
{
	int stdio_fds[3] = { 0, 1, 2 };
	char *request, *resp = NULL;
	size_t request_len;
	int fd, rc, exit_status = 0;

	request = pack_exec_request(cell, argv, 0, &request_len);
	if (!request)
		return -ENOMEM;
	fd = juno_ctl_connect(cell->name);
	if (fd < 0) {
		free(request);
		return fd;
	}

	rc = juno_ctl_call(fd, CTL_EXEC, request, request_len, stdio_fds, 3, &resp, NULL, NULL);
	close(fd);
	free(request);
	if (rc < 0) {
		if (resp && *resp)
			juno_seterr("%s", resp);
		free(resp);
		return rc;
	}

	memcpy(&exit_status, resp, sizeof exit_status);
	free(resp);
	if (status)
		*status = exit_status;
	return 0;
}

/* tty mode: the first reply carries the pty master, the second the status */
static int remote_exec_tty(juno_cell *cell, char *const argv[], int *master, int *donefd)
{
	char *request, *resp = NULL;
	size_t request_len;
	int fd, rc, master_fd = -1;

	request = pack_exec_request(cell, argv, 1, &request_len);
	if (!request)
		return -ENOMEM;
	fd = juno_ctl_connect(cell->name);
	if (fd < 0) {
		free(request);
		return fd;
	}

	rc = juno_ctl_call(fd, CTL_EXEC, request, request_len, NULL, 0, &resp, NULL, &master_fd);
	free(request);
	if (rc < 0 || master_fd < 0) {
		if (resp && *resp)
			juno_seterr("%s", resp);
		free(resp);
		close(fd);
		return rc < 0 ? rc : -EIO;
	}
	free(resp);
	*master = master_fd;
	*donefd = fd;
	return 0;
}

static int remote_exec_done(juno_cell *cell, int donefd, int *status)
{
	char *resp = NULL;
	int rc, exit_status = 0;

	(void)cell;
	rc = read_reply(donefd, &resp, NULL, NULL);
	close(donefd);
	if (rc < 0) {
		free(resp);
		return rc;
	}
	memcpy(&exit_status, resp, sizeof exit_status);
	free(resp);
	if (status)
		*status = exit_status;
	return 0;
}

static void remote_release(juno_cell *cell) { free(cell->name); }

const struct juno_backend juno_remote_backend = {
	.name = "remote", .kill = remote_kill, .wait = remote_wait, .exec = remote_exec,
	.exec_tty = remote_exec_tty, .exec_done = remote_exec_done, .release = remote_release,
};

int juno_cell_open(const char *name, juno_cell **out)
{
	char *status_text = NULL;
	juno_cell *cell;
	int fd = juno_ctl_connect(name);

	if (fd < 0)
		return fd;
	close(fd);

	cell = calloc(1, sizeof *cell);
	if (!cell)
		return -ENOMEM;
	cell->be = &juno_remote_backend;
	cell->pidfd = cell->ipidfd = -1;
	cell->name = strdup(name);

	if (call_named(name, CTL_STATUS, NULL, 0, &status_text) == 0 && status_text) {
		char *pid_field = strstr(status_text, "pid=");

		if (pid_field)
			cell->pid = atoi(pid_field + 4);
		free(status_text);
	}
	*out = cell;
	return 0;
}

int juno_cell_exec(juno_cell *cell, char *const argv[], int *status)
{
	if (!cell->be->exec) {
		juno_seterr("backend has no exec");
		return -ENOTSUP;
	}
	return cell->be->exec(cell, argv, status);
}

/* --- lifecycle helpers used by the CLI --- */

int juno_list(juno_list_fn callback, void *userdata)
{
	char runtime_dir[PATH_BUF], data_dir[PATH_BUF], base[PATH_BUF];
	DIR *dir;
	struct dirent *entry;

	if (juno_dirs("x", runtime_dir, data_dir, sizeof runtime_dir) < 0)
		return -EINVAL;
	snprintf(base, sizeof base, "%s", runtime_dir);
	*strrchr(base, '/') = 0;

	dir = opendir(base);
	if (!dir)
		return 0;
	while ((entry = readdir(dir))) {
		char cell_dir[1100], file[1200], value[64];
		char state[32] = "starting";
		int pid = 0, restarts = 0;
		long uptime = 0;

		if (entry->d_name[0] == '.' || !juno_valid_name(entry->d_name))
			continue;
		snprintf(cell_dir, sizeof cell_dir, "%s/%s", base, entry->d_name);
		snprintf(file, sizeof file, "%s/lock", cell_dir);
		if (access(file, F_OK) < 0)
			continue;	/* supervisor still creating it */
		if (!lock_held(cell_dir)) {
			juno_rm_tree(cell_dir);
			continue;
		}

		snprintf(file, sizeof file, "%s/status", cell_dir);
		if (read_state_value(file, "state", state, sizeof state) < 0)
			strcpy(state, "starting");
		if (read_state_value(file, "pid", value, sizeof value) == 0)
			pid = atoi(value);
		if (read_state_value(file, "restarts", value, sizeof value) == 0)
			restarts = atoi(value);
		if (read_state_value(file, "started", value, sizeof value) == 0)
			uptime = time(NULL) - atol(value);
		callback(entry->d_name, state, pid, uptime < 0 ? 0 : uptime, restarts, userdata);
	}
	closedir(dir);
	return 0;
}

int juno_cell_status(const char *name, char *buf, size_t len)
{
	char runtime_dir[PATH_BUF], data_dir[PATH_BUF], path[1100];
	char *resp = NULL;
	size_t used;
	FILE *fp;
	int rc = call_named(name, CTL_STATUS, NULL, 0, &resp);

	if (rc == 0) {
		snprintf(buf, len, "%s", resp);
		free(resp);
		return 0;
	}
	free(resp);

	/* not running: report how it ended */
	juno_dirs(name, runtime_dir, data_dir, sizeof runtime_dir);
	snprintf(path, sizeof path, "%s/last", data_dir);
	fp = fopen(path, "re");
	if (!fp)
		return -ENOENT;
	used = snprintf(buf, len, "state=exited\n");
	used += fread(buf + used, 1, len - used - 1, fp);
	buf[used] = 0;
	fclose(fp);
	return 0;
}

static int wait_gone(const char *name, int ms)
{
	char runtime_dir[PATH_BUF], data_dir[PATH_BUF];
	uint64_t deadline;

	juno_dirs(name, runtime_dir, data_dir, sizeof runtime_dir);
	deadline = juno_now_ms() + ms;
	while (lock_held(runtime_dir)) {
		if (juno_now_ms() >= deadline)
			return -ETIMEDOUT;
		usleep(POLL_USEC);
	}
	return 0;
}

int juno_cell_stop(const char *name, int grace_s)
{
	uint32_t grace_ms = grace_s * 1000u;
	int rc = call_named(name, CTL_STOP, &grace_ms, sizeof grace_ms, NULL);

	if (rc < 0)
		return rc;
	return wait_gone(name, grace_s * 1000 + 5000);
}

int juno_cell_signal(const char *name, int sig)
{
	int32_t signal_number = sig;

	return call_named(name, CTL_KILL, &signal_number, sizeof signal_number, NULL);
}

static int copy_fd(int in_fd, int out_fd)
{
	char buf[8192];
	ssize_t got;

	while ((got = read(in_fd, buf, sizeof buf)) > 0) {
		if (write(out_fd, buf, got) < 0)
			return -errno;
	}
	return 0;
}

/* Stream the supervisor's live log to out_fd until it closes the connection. */
static int follow_log(const char *name, int out_fd)
{
	char request[6];
	uint32_t request_len = 2;
	int sock = juno_ctl_connect(name);

	if (sock < 0)
		return sock;
	memcpy(request, &request_len, 4);
	request[4] = CTL_LOGS;
	request[5] = 1;
	if (send(sock, request, 6, MSG_NOSIGNAL) != 6) {
		close(sock);
		return -EPIPE;
	}

	for (;;) {
		uint32_t chunk_len;
		char buf[4096];

		if (transfer(sock, &chunk_len, 4, 0) || chunk_len == 0)
			break;
		while (chunk_len) {
			size_t n = chunk_len < sizeof buf ? chunk_len : sizeof buf;

			if (transfer(sock, buf, n, 0)) {
				close(sock);
				return 0;
			}
			if (write(out_fd, buf, n) < 0) {
				close(sock);
				return -errno;
			}
			chunk_len -= n;
		}
	}
	close(sock);
	return 0;
}

int juno_cell_logs(const char *name, int follow, int fd)
{
	char runtime_dir[PATH_BUF], data_dir[PATH_BUF], path[1100];
	int log_fd, rc;

	if (!juno_valid_name(name) || juno_dirs(name, runtime_dir, data_dir, sizeof runtime_dir) < 0)
		return -EINVAL;
	if (follow && lock_held(runtime_dir))
		return follow_log(name, fd);

	snprintf(path, sizeof path, "%s/log", data_dir);
	log_fd = open(path, O_RDONLY | O_CLOEXEC);
	if (log_fd < 0) {
		juno_seterr("no log for '%s'", name);
		return -ENOENT;
	}
	rc = copy_fd(log_fd, fd);
	close(log_fd);
	return rc;
}

int juno_cell_remove(const char *name, int force)
{
	char runtime_dir[PATH_BUF], data_dir[PATH_BUF], work[600];

	if (!juno_valid_name(name) || juno_dirs(name, runtime_dir, data_dir, sizeof runtime_dir) < 0)
		return -EINVAL;
	if (lock_held(runtime_dir)) {
		if (!force) {
			juno_seterr("cell '%s' is running (use -f)", name);
			return -EBUSY;
		}
		juno_cell_stop(name, 0);
		if (wait_gone(name, 3000))
			return -EBUSY;
	}

	juno_rm_tree(runtime_dir);
	snprintf(work, sizeof work, "%s/upper.work", data_dir);
	juno_rmtree(work);
	if (access(data_dir, F_OK) < 0) {
		juno_seterr("no such cell '%s'", name);
		return -ENOENT;
	}
	return juno_rmtree(data_dir);
}

/* state files are created through a verified directory fd, never through a path that could be a planted symlink */
int juno_put_file_at(int dir_fd, const char *name, const char *data, size_t len)
{
	char temp[80];
	ssize_t written;
	int fd, err;

	snprintf(temp, sizeof temp, "%s.tmp", name);
	unlinkat(dir_fd, temp, 0);
	fd = openat(dir_fd, temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		return -errno;

	written = write(fd, data, len);
	err = written == (ssize_t)len ? 0 : EIO;
	if (close(fd) < 0 && !err)
		err = errno;
	if (!err && renameat(dir_fd, temp, dir_fd, name) < 0)
		err = errno;
	return -err;
}

/* Verify one path component is a real directory (no symlink) owned by us and closed to others. */
static int verify_state_dir(const char *path)
{
	struct stat st;
	int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);

	if (fd < 0 || fstat(fd, &st) < 0) {
		int saved = errno;

		if (fd >= 0)
			close(fd);
		juno_seterr("state directory %s is not a plain directory: %s", path, strerror(saved));
		return -saved;
	}
	close(fd);

	if (st.st_uid != geteuid() || (st.st_mode & 077)) {
		juno_seterr("state directory %s must be owned by uid %u with mode 0700 "
			"(it is uid %u, mode %04o); refusing to use it",
			path, geteuid(), st.st_uid, st.st_mode & 07777);
		return -EACCES;
	}
	return 0;
}

/* mkdir -p with mode 0700; the last nverify components must be real directories (no symlinks)
 * owned by us and closed to everyone else, whether we created them or found them */
int juno_mkdir_secure(const char *path, int nverify)
{
	char buf[1100];
	size_t len = strlen(path);
	int components = 0;
	int index = 0;

	if (len == 0 || len >= sizeof buf || path[0] != '/') {
		juno_seterr("state directory '%s' must be an absolute path", path);
		return -EINVAL;
	}
	memcpy(buf, path, len + 1);

	for (size_t i = 1; i < len; i++) {
		if (buf[i] == '/' && buf[i - 1] != '/')
			components++;
	}
	components++;

	for (size_t i = 1; i <= len; i++) {
		char saved_char;
		int rc;

		if (buf[i] != '/' && buf[i] != 0)
			continue;
		if (buf[i - 1] == '/')
			continue;

		saved_char = buf[i];
		buf[i] = 0;
		index++;
		if (mkdir(buf, 0700) < 0 && errno != EEXIST) {
			int saved = errno;

			juno_seterr("create %s: %s", buf, strerror(saved));
			return -saved;
		}
		if (index > components - nverify) {
			rc = verify_state_dir(buf);
			if (rc)
				return rc;
		}
		buf[i] = saved_char;
	}
	return 0;
}
