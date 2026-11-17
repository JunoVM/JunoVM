/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "internal.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_HANDLERS 32		/* requests being served by helper processes */
#define MAX_FOLLOWERS 8		/* of which log followers */
#define MAX_CLIENTS 64		/* control clients waiting for a complete request */
#define MAX_REQUEST 65536	/* largest accepted request body */
#define MAX_CLIENT_FDS 4
#define CLIENT_TIMEOUT_MS 2000	/* a client must finish its request within this */
#define LOG_DEFAULT_MAX (10ull << 20)
#define DEFAULT_STOP_GRACE_MS 10000
#define STATE_GONE_GRACE_MS 2000
#define POLL_IDLE_MS 500
#define POLL_BUSY_MS 100
#define RESTART_BACKOFF_BASE_MS 100
#define RESTART_BACKOFF_MAX_SHIFT 6
#define RESTART_BACKOFF_CAP_MS 5000
#define START_FAILED_RETRY_MS 1000
#define EXIT_TIMED_OUT 124
#define EXIT_START_FAILED 125
#define SOCKET_PATH_MAX 107	/* sizeof sun_path - 1 */
#define POLL_FIXED_SLOTS 5	/* listener, cell, two tee pipes, log pipe */

struct ctl_client {
	int fd, nfds;
	uint64_t born_ms;
	size_t have, need;
	unsigned char *buf;
	int fds[MAX_CLIENT_FDS];
};

struct supervisor {
	juno_spec *spec;
	const char *name;
	char runtime_dir[512], data_dir[512];
	int runtime_fd, data_fd;	/* the verified state directories */
	int listen_fd, lock_fd;
	juno_cell *cell;
	int restarts, last_exit;
	bool stopping, state_gone;
	uint64_t kill_at_ms, restart_at_ms;
	time_t started;
	ino_t runtime_ino;
	pid_t handlers[MAX_HANDLERS];
	char handler_kind[MAX_HANDLERS];
	int handler_count;
	int log_pipe[2];		/* detached: payload and supervisor output */
	int tee_out[2], tee_err[2];	/* foreground: payload output goes to the terminal and the log */
	int log_fd;
	uint64_t log_size, log_max;
	struct ctl_client clients[MAX_CLIENTS];
	int client_count;
};

static volatile sig_atomic_t stop_requested;
static void on_term(int sig) { (void)sig; stop_requested = 1; }

static const char *state_name(const struct supervisor *sup)
{
	if (sup->stopping)
		return "stopping";
	return sup->cell ? "running" : "restarting";
}

static int format_status(const struct supervisor *sup, char *buf, size_t len)
{
	return snprintf(buf, len, "state=%s\npid=%d\nsupervisor=%d\nstarted=%ld\nrestarts=%d\nexit=%d\n",
		state_name(sup), sup->cell ? juno_cell_pid(sup->cell) : 0, getpid(), (long)sup->started,
		sup->restarts, sup->last_exit);
}

static void write_status(const struct supervisor *sup)
{
	char text[512];
	int len = format_status(sup, text, sizeof text);

	juno_put_file_at(sup->runtime_fd, "status", text, len);
}

/* Reply frame: u32 length (status + payload), i32 status, payload. */
static int reply(int fd, int status, const void *payload, size_t payload_len)
{
	uint32_t length = 4 + payload_len;
	int32_t status_code = status;
	char *frame = malloc(8 + payload_len);
	ssize_t sent;

	if (!frame)
		return -1;
	memcpy(frame, &length, 4);
	memcpy(frame + 4, &status_code, 4);
	if (payload_len)
		memcpy(frame + 8, payload, payload_len);
	sent = send(fd, frame, 8 + payload_len, MSG_NOSIGNAL);
	free(frame);
	return sent < 0 ? -1 : 0;
}

static int reply_with_fd(int fd, int passed_fd)
{
	int32_t header[2] = { 4, 0 };
	char control[CMSG_SPACE(sizeof(int))] = { 0 };
	struct iovec iov = { header, sizeof header };
	struct msghdr msg = {
		.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof control,
	};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &passed_fd, sizeof passed_fd);
	return sendmsg(fd, &msg, MSG_NOSIGNAL) < 0 ? -1 : 0;
}

static void begin_stop(struct supervisor *sup, uint32_t grace_ms)
{
	if (sup->stopping)
		return;
	sup->stopping = true;
	sup->kill_at_ms = juno_now_ms() + grace_ms;
	if (sup->cell)
		juno_cell_kill(sup->cell, SIGTERM);
	write_status(sup);
}

/* --- log: size-capped, one rotation; the payload only ever holds a pipe --- */

static void log_open(struct supervisor *sup)
{
	struct stat st;

	sup->log_fd = openat(sup->data_fd, "log", O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
	sup->log_size = sup->log_fd >= 0 && fstat(sup->log_fd, &st) == 0 ? (uint64_t)st.st_size : 0;
}

static void log_write(struct supervisor *sup, const char *data, size_t len)
{
	ssize_t written;

	if (sup->log_fd < 0)
		return;
	if (sup->log_size + len > sup->log_max) {
		close(sup->log_fd);
		renameat(sup->data_fd, "log", sup->data_fd, "log.1");
		log_open(sup);
		if (sup->log_fd < 0)
			return;
	}
	written = write(sup->log_fd, data, len);
	if (written > 0)
		sup->log_size += written;
}

/* fd -> the log (and, in the foreground, also to out) */
static void pump_output(struct supervisor *sup, int read_fd, int out_fd)
{
	char buf[8192];
	ssize_t got;

	while ((got = read(read_fd, buf, sizeof buf)) > 0) {
		if (out_fd >= 0) {
			ssize_t written = write(out_fd, buf, got);

			(void)written;
		}
		log_write(sup, buf, got);
	}
}

/* --- request handlers: one forked helper per exec or log request --- */

/* Exec request: flag byte (1 tty, 2 user), optional "uid:gid", then NUL-separated argv. */
#define EXEC_FLAG_TTY 1
#define EXEC_FLAG_USER 2

static void __attribute__((noreturn))
handle_exec(struct supervisor *sup, int client_fd, const char *payload, size_t payload_len,
	int *fds, int nfds)
{
	char **argv = NULL;
	int argc = 0;
	int tty = payload_len > 0 && (payload[0] & EXEC_FLAG_TTY);
	int has_user = payload_len > 0 && (payload[0] & EXEC_FLAG_USER);
	size_t pos = 1;
	int status = 0, rc;

	if ((!tty && nfds < 3) || !sup->cell) {
		reply(client_fd, -ESRCH, "cell is not running", 19);
		_exit(1);
	}
	if (has_user) {
		int uid = -1, gid = -1;

		if (sscanf(payload + pos, "%d:%d", &uid, &gid) == 2)
			juno_cell_set_exec_user(sup->cell, uid, gid);
		pos += strnlen(payload + pos, payload_len - pos) + 1;
	}
	while (pos < payload_len) {
		size_t arg_len = strnlen(payload + pos, payload_len - pos);

		juno_append(&argv, &argc, strndup(payload + pos, arg_len));
		pos += arg_len + 1;
	}

	if (tty) {
		int master, done;

		rc = juno_cell_exec_tty(sup->cell, argv, &master, &done);
		if (rc < 0) {
			reply(client_fd, rc, juno_error(), strlen(juno_error()));
			_exit(0);
		}
		reply_with_fd(client_fd, master);
		close(master);
		rc = juno_cell_exec_wait(sup->cell, done, &status);
		reply(client_fd, rc, &status, sizeof status);
		_exit(0);
	}

	for (int i = 0; i < 3; i++)
		dup2(fds[i], i);
	for (int i = 3; i < nfds; i++)
		close(fds[i]);
	rc = juno_cell_exec(sup->cell, argv, &status);
	if (rc < 0)
		reply(client_fd, rc, juno_error(), strlen(juno_error()));
	else
		reply(client_fd, 0, &status, sizeof status);
	_exit(0);
}

/* Stream the log as (u32 length, bytes) chunks ended by a zero length; a follower notices its
 * client hanging up and follows the file across a rotation. */
static void __attribute__((noreturn))
handle_logs(struct supervisor *sup, int client_fd, const char *payload, size_t payload_len)
{
	char buf[4096];
	int log_fd = openat(sup->data_fd, "log", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	pid_t parent = getppid();
	int follow = payload_len > 0 && payload[0];
	int final_drain = 0;
	uint32_t end_marker = 0;

	while (log_fd >= 0) {
		ssize_t got = read(log_fd, buf, sizeof buf);
		struct stat open_st, current_st;
		char probe;

		if (got > 0) {
			uint32_t chunk_len = got;

			if (send(client_fd, &chunk_len, 4, MSG_NOSIGNAL) != 4 ||
			    send(client_fd, buf, got, MSG_NOSIGNAL) != got)
				_exit(0);
			continue;
		}
		if (!follow || final_drain)
			break;
		if (recv(client_fd, &probe, 1, MSG_PEEK | MSG_DONTWAIT) == 0)
			_exit(0);	/* the follower hung up */
		if (getppid() != parent) {	/* supervisor gone: one last drain */
			final_drain = 1;
			continue;
		}
		if (fstat(log_fd, &open_st) == 0 &&
		    fstatat(sup->data_fd, "log", &current_st, AT_SYMLINK_NOFOLLOW) == 0 &&
		    open_st.st_ino != current_st.st_ino) {	/* rotated away: follow the new file */
			close(log_fd);
			log_fd = openat(sup->data_fd, "log", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
			continue;
		}
		usleep(50000);
	}
	send(client_fd, &end_marker, 4, MSG_NOSIGNAL);
	_exit(0);
}

static void spawn_handler(struct supervisor *sup, int client_fd, int op, char *payload, size_t payload_len,
	int *fds, int nfds)
{
	pid_t pid;

	if (sup->handler_count >= MAX_HANDLERS) {
		reply(client_fd, -EBUSY, "too many requests in flight", 27);
		return;
	}
	if (op == CTL_LOGS) {
		int followers = 0;

		for (int i = 0; i < sup->handler_count; i++)
			followers += sup->handler_kind[i] == CTL_LOGS;
		if (followers >= MAX_FOLLOWERS) {
			reply(client_fd, -EBUSY, "too many log followers", 22);
			return;
		}
	}

	pid = fork();
	if (pid < 0) {
		reply(client_fd, -errno, NULL, 0);
		return;
	}
	if (pid == 0) {
		fcntl(client_fd, F_SETFL, 0);
		close(sup->listen_fd);
		close(sup->lock_fd);
		for (int i = 0; i < sup->client_count; i++) {
			if (sup->clients[i].fd != client_fd)
				close(sup->clients[i].fd);
		}
		if (sup->log_pipe[0] >= 0)
			close(sup->log_pipe[0]);

		if (op == CTL_EXEC)
			handle_exec(sup, client_fd, payload, payload_len, fds, nfds);
		handle_logs(sup, client_fd, payload, payload_len);
	}
	sup->handler_kind[sup->handler_count] = op;
	sup->handlers[sup->handler_count++] = pid;
}

static void dispatch(struct supervisor *sup, struct ctl_client *client)
{
	int op = client->buf[4];
	char *payload = (char *)client->buf + 5;
	size_t payload_len = client->need - 5;
	int fd = client->fd;
	char text[512];

	switch (op) {
	case CTL_STATUS:
		reply(fd, 0, text, format_status(sup, text, sizeof text));
		break;
	case CTL_STOP: {
		uint32_t grace_ms = DEFAULT_STOP_GRACE_MS;

		if (payload_len >= 4)
			memcpy(&grace_ms, payload, 4);
		begin_stop(sup, grace_ms);
		reply(fd, 0, NULL, 0);
		break;
	}
	case CTL_KILL: {
		int32_t sig = 0;

		if (payload_len >= 4)
			memcpy(&sig, payload, 4);
		reply(fd, sup->cell ? juno_cell_kill(sup->cell, sig) : -ESRCH, NULL, 0);
		break;
	}
	case CTL_EXEC:
	case CTL_LOGS:
		spawn_handler(sup, fd, op, payload, payload_len, client->fds, client->nfds);
		break;
	default:
		reply(fd, -EINVAL, NULL, 0);
	}
}

static void client_close(struct supervisor *sup, int index)
{
	struct ctl_client *client = &sup->clients[index];

	for (int i = 0; i < client->nfds; i++)
		close(client->fds[i]);
	close(client->fd);
	free(client->buf);
	*client = sup->clients[--sup->client_count];
}

/* Keep the fds that arrived with the request (up to the limit), close the rest. */
static void collect_client_fds(struct ctl_client *client, const struct msghdr *msg)
{
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR((struct msghdr *)msg); cmsg;
	     cmsg = CMSG_NXTHDR((struct msghdr *)msg, cmsg)) {
		int received[MAX_CLIENT_FDS];
		int count;

		if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
			continue;
		count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
		memcpy(received, CMSG_DATA(cmsg), sizeof(int) * (count > MAX_CLIENT_FDS ? MAX_CLIENT_FDS : count));
		for (int i = 0; i < count; i++) {
			if (i < MAX_CLIENT_FDS && client->nfds < MAX_CLIENT_FDS)
				client->fds[client->nfds++] = received[i];
			else if (i < MAX_CLIENT_FDS)
				close(received[i]);
		}
	}
}

/* returns 1 when the client is finished (answered, bad, or gone) */
static int client_read(struct supervisor *sup, struct ctl_client *client)
{
	for (;;) {
		char control[CMSG_SPACE(sizeof(int) * MAX_CLIENT_FDS)];
		size_t want = (client->have < 4 ? 4 : client->need) - client->have;
		struct iovec iov;
		struct msghdr msg;
		ssize_t got;

		if (!client->buf && !(client->buf = malloc(MAX_REQUEST + 8)))
			return 1;
		iov = (struct iovec){ client->buf + client->have, want };
		msg = (struct msghdr){
			.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof control,
		};
		got = recvmsg(client->fd, &msg, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
		if (got < 0)
			return errno == EAGAIN || errno == EINTR ? 0 : 1;
		if (got == 0)
			return 1;

		collect_client_fds(client, &msg);
		client->have += got;

		if (client->have >= 4 && !client->need) {
			uint32_t length;

			memcpy(&length, client->buf, 4);
			if (length < 1 || length > MAX_REQUEST)
				return 1;	/* checked before anything is added to it */
			client->need = 4 + (size_t)length;
		}
		if (client->need && client->have >= client->need) {
			dispatch(sup, client);
			return 1;
		}
	}
}

static int peer_is_us(int fd)
{
	struct ucred cred;
	socklen_t len = sizeof cred;

	return getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0 && cred.uid == geteuid();
}

static int bind_socket(struct supervisor *sup)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	char via_fd[64];
	mode_t old_umask;
	int rc = 0;

	/* the verified directory fd names the directory; the real path is only for clients */
	snprintf(via_fd, sizeof via_fd, "/proc/self/fd/%d/sock", sup->runtime_fd);
	if (strlen(via_fd) >= sizeof addr.sun_path)
		return -ENAMETOOLONG;
	memcpy(addr.sun_path, via_fd, strlen(via_fd) + 1);

	unlinkat(sup->runtime_fd, "sock", 0);
	if (sup->listen_fd >= 0)
		close(sup->listen_fd);

	old_umask = umask(077);	/* only for the socket: payloads keep the caller's umask */
	sup->listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (sup->listen_fd < 0 || bind(sup->listen_fd, (struct sockaddr *)&addr, sizeof addr) < 0 ||
	    fchmodat(sup->runtime_fd, "sock", 0600, 0) < 0 || listen(sup->listen_fd, 16) < 0)
		rc = -errno;
	umask(old_umask);
	return rc;
}

static int exit_code(juno_cell *cell, int wait_status)
{
	if (juno_cell_timed_out(cell))
		return EXIT_TIMED_OUT;
	return WIFEXITED(wait_status) ? WEXITSTATUS(wait_status) : 128 + WTERMSIG(wait_status);
}

/* Tell the launching process how the start went: i32 status, then an optional message. */
static void report_start(int report_fd, int rc, const char *msg)
{
	int32_t status = rc;
	size_t len = msg ? strlen(msg) : 0;

	if (report_fd < 0)
		return;
	if (write(report_fd, &status, 4) < 0 || (len && write(report_fd, msg, len) < 0))
		return;
	close(report_fd);
}

/* Verify and open the runtime and data directories, take the cell's lock. */
static int open_state(struct supervisor *sup, int report_fd)
{
	char err[600];
	struct stat st;
	int rc;

	if (juno_dirs(sup->name, sup->runtime_dir, sup->data_dir, sizeof sup->runtime_dir) < 0) {
		report_start(report_fd, -EINVAL, "cannot determine state directories");
		return -EINVAL;
	}
	if (strlen(sup->runtime_dir) + 5 > SOCKET_PATH_MAX) {
		snprintf(err, sizeof err, "control socket path too long (%zu bytes, the limit is %zu): %.200s/sock",
			strlen(sup->runtime_dir) + 5, (size_t)SOCKET_PATH_MAX, sup->runtime_dir);
		report_start(report_fd, -ENAMETOOLONG, err);
		juno_seterr("%s", err);
		return -ENAMETOOLONG;
	}

	rc = juno_mkdir_secure(sup->runtime_dir, 2);
	if (!rc)
		rc = juno_mkdir_secure(sup->data_dir, 2);
	if (rc) {
		snprintf(err, sizeof err, "%s", juno_error()[0] ? juno_error() : "create state directories failed");
		report_start(report_fd, rc, err);
		return rc;
	}

	sup->runtime_fd = open(sup->runtime_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	sup->data_fd = open(sup->data_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (sup->runtime_fd < 0 || sup->data_fd < 0) {
		rc = -errno;
		report_start(report_fd, rc, "open state directories");
		return rc;
	}
	fstat(sup->runtime_fd, &st);
	sup->runtime_ino = st.st_ino;

	sup->lock_fd = openat(sup->runtime_fd, "lock", O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (sup->lock_fd < 0 || flock(sup->lock_fd, LOCK_EX | LOCK_NB) < 0) {
		snprintf(err, sizeof err, "cell '%s' already exists", sup->name);
		juno_seterr("%s", err);
		report_start(report_fd, -EEXIST, err);
		return -EEXIST;
	}
	return 0;
}

/* Route the payload's output: detached cells write into a pipe the supervisor drains into the
 * log; foreground cells are teed to the terminal as well. */
static int setup_output(struct supervisor *sup, int detach, int report_fd)
{
	if (detach) {
		/* only the supervisor touches the log file */
		int nul = open("/dev/null", O_RDWR | O_CLOEXEC);

		if (nul < 0 || pipe2(sup->log_pipe, O_CLOEXEC) < 0) {
			int rc = -errno;

			report_start(report_fd, rc, "open the log pipe");
			return rc;
		}
		fcntl(sup->log_pipe[0], F_SETFL, O_NONBLOCK);
		juno_spec_set_stdio(sup->spec, nul, sup->log_pipe[1], sup->log_pipe[1]);
		dup2(nul, 0);
		dup2(sup->log_pipe[1], 1);
		dup2(sup->log_pipe[1], 2);
		return 0;
	}

	/* foreground: tee the payload's stdout and stderr to our own and to the log */
	{
		int out_pipe[2], err_pipe[2];

		if (pipe2(out_pipe, O_CLOEXEC | O_NONBLOCK) < 0 || pipe2(err_pipe, O_CLOEXEC | O_NONBLOCK) < 0)
			return -errno;
		sup->tee_out[0] = out_pipe[0];
		sup->tee_out[1] = out_pipe[1];
		sup->tee_err[0] = err_pipe[0];
		sup->tee_err[1] = err_pipe[1];
		juno_spec_set_stdio(sup->spec, -1, out_pipe[1], err_pipe[1]);
	}
	return 0;
}

static void install_signal_handlers(void)
{
	struct sigaction action = { .sa_handler = on_term };

	sigemptyset(&action.sa_mask);
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGHUP, &action, NULL);
}

static void drain_output(struct supervisor *sup)
{
	if (sup->tee_out[0] >= 0) {
		pump_output(sup, sup->tee_out[0], 1);
		pump_output(sup, sup->tee_err[0], 2);
	}
	if (sup->log_pipe[0] >= 0)
		pump_output(sup, sup->log_pipe[0], -1);
}

/* The runtime directory may have been removed under us: nothing could manage the cell then. */
static void check_state_dir(struct supervisor *sup)
{
	struct stat st;

	if (sup->state_gone)
		return;
	if (fstatat(AT_FDCWD, sup->runtime_dir, &st, AT_SYMLINK_NOFOLLOW) < 0 || st.st_ino != sup->runtime_ino) {
		static const char message[] = "supervisor: runtime state removed, stopping the cell\n";

		sup->state_gone = true;
		log_write(sup, message, sizeof message - 1);
		begin_stop(sup, STATE_GONE_GRACE_MS);
	} else if (fstatat(sup->runtime_fd, "sock", &st, AT_SYMLINK_NOFOLLOW) < 0) {
		bind_socket(sup);
	}
}

static void accept_clients(struct supervisor *sup)
{
	int fd;

	while ((fd = accept4(sup->listen_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK)) >= 0) {
		if (sup->client_count >= MAX_CLIENTS || !peer_is_us(fd)) {
			close(fd);
			continue;
		}
		sup->clients[sup->client_count++] = (struct ctl_client){ .fd = fd, .born_ms = juno_now_ms() };
	}
}

static void reap_handlers(struct supervisor *sup)
{
	for (int i = 0; i < sup->handler_count; i++) {
		if (waitpid(sup->handlers[i], NULL, WNOHANG) > 0) {
			sup->handler_kind[i] = sup->handler_kind[sup->handler_count - 1];
			sup->handlers[i--] = sup->handlers[--sup->handler_count];
		}
	}
}

/* One poll round: wait for control clients, payload output or the cell exiting. */
static void poll_and_service(struct supervisor *sup, uint64_t now)
{
	struct pollfd fds[POLL_FIXED_SLOTS + MAX_CLIENTS];
	int nfds = POLL_FIXED_SLOTS + sup->client_count;
	int timeout_ms = POLL_IDLE_MS;

	for (int i = sup->client_count - 1; i >= 0; i--) {
		if (now - sup->clients[i].born_ms > CLIENT_TIMEOUT_MS)
			client_close(sup, i);
	}
	nfds = POLL_FIXED_SLOTS + sup->client_count;

	fds[0] = (struct pollfd){ sup->listen_fd, POLLIN, 0 };
	fds[1] = (struct pollfd){ sup->cell ? juno_cell_fd(sup->cell) : -1, POLLIN, 0 };
	fds[2] = (struct pollfd){ sup->tee_out[0], POLLIN, 0 };
	fds[3] = (struct pollfd){ sup->tee_err[0], POLLIN, 0 };
	fds[4] = (struct pollfd){ sup->log_pipe[0], POLLIN, 0 };
	for (int i = 0; i < sup->client_count; i++)
		fds[POLL_FIXED_SLOTS + i] = (struct pollfd){ sup->clients[i].fd, POLLIN, 0 };

	if (sup->handler_count || sup->client_count)
		timeout_ms = POLL_BUSY_MS;
	if (sup->stopping && sup->cell && sup->kill_at_ms > now && (int)(sup->kill_at_ms - now) < timeout_ms)
		timeout_ms = sup->kill_at_ms - now;
	if (sup->restart_at_ms && !sup->cell)
		timeout_ms = sup->restart_at_ms > now ? (int)(sup->restart_at_ms - now) : 0;
	poll(fds, nfds, timeout_ms);

	drain_output(sup);
	for (int i = sup->client_count - 1; i >= 0; i--) {
		struct pollfd *slot = &fds[POLL_FIXED_SLOTS + i];

		if (slot->fd == sup->clients[i].fd && (slot->revents & (POLLIN | POLLHUP | POLLERR)) &&
		    client_read(sup, &sup->clients[i]))
			client_close(sup, i);
	}
	if (fds[0].revents & POLLIN)
		accept_clients(sup);
	reap_handlers(sup);
}

/* The cell exited: record why and decide whether to restart. Returns 1 when the loop should end. */
static int handle_cell_exit(struct supervisor *sup, int wait_status)
{
	int shift;
	uint64_t delay_ms;
	int again;

	sup->last_exit = exit_code(sup->cell, wait_status);
	juno_cell_free(sup->cell);
	sup->cell = NULL;

	again = !sup->stopping && !stop_requested &&
		(sup->spec->restart == JUNO_RESTART_ALWAYS ||
		 (sup->spec->restart == JUNO_RESTART_ON_FAILURE && sup->last_exit != 0)) &&
		sup->restarts < sup->spec->max_restarts;
	if (!again)
		return 1;

	/* exponential backoff, capped */
	shift = sup->restarts < RESTART_BACKOFF_MAX_SHIFT ? sup->restarts : RESTART_BACKOFF_MAX_SHIFT;
	delay_ms = (uint64_t)RESTART_BACKOFF_BASE_MS << shift;
	sup->restart_at_ms = juno_now_ms() + (delay_ms > RESTART_BACKOFF_CAP_MS ? RESTART_BACKOFF_CAP_MS : delay_ms);
	write_status(sup);
	return 0;
}

/* Restart the cell when its backoff has elapsed. Returns 1 when giving up. */
static int restart_cell(struct supervisor *sup)
{
	sup->restart_at_ms = 0;
	sup->restarts++;
	if (juno_start(sup->spec, &sup->cell)) {
		sup->cell = NULL;
		sup->last_exit = EXIT_START_FAILED;
		if (sup->restarts >= sup->spec->max_restarts)
			return 1;
		sup->restart_at_ms = juno_now_ms() + START_FAILED_RETRY_MS;
	}
	write_status(sup);
	return 0;
}

/* Supervise until the cell is gone for good; returns the exit code. */
static int supervise(struct supervisor *sup)
{
	for (;;) {
		uint64_t now;
		int wait_status;

		if (stop_requested)
			begin_stop(sup, DEFAULT_STOP_GRACE_MS);
		now = juno_now_ms();
		check_state_dir(sup);
		poll_and_service(sup, now);

		if (sup->cell) {
			if (juno_cell_wait(sup->cell, &wait_status, 0) == 0) {
				if (handle_cell_exit(sup, wait_status))
					break;
			} else if (sup->stopping && juno_now_ms() >= sup->kill_at_ms) {
				juno_cell_kill(sup->cell, SIGKILL);
			}
		} else if (sup->stopping) {
			break;
		} else if (sup->restart_at_ms && juno_now_ms() >= sup->restart_at_ms) {
			if (restart_cell(sup))
				break;
		}
	}
	return sup->last_exit;
}

static void close_pair(int *pair)
{
	for (int i = 0; i < 2; i++) {
		if (pair[i] >= 0)
			close(pair[i]);
	}
}

/* Everything after supervision: stop helpers, flush output, record how it ended, remove the state. */
static void finish(struct supervisor *sup, int rc, int report_fd)
{
	if (sup->cell)
		juno_cell_free(sup->cell);
	drain_output(sup);
	for (int i = 0; i < sup->handler_count; i++) {	/* a follower finishes by itself once we are gone */
		if (sup->handler_kind[i] == CTL_EXEC) {
			kill(sup->handlers[i], SIGKILL);
			waitpid(sup->handlers[i], NULL, 0);
		}
	}
	while (sup->client_count)
		client_close(sup, 0);

	close_pair(sup->tee_out);
	close_pair(sup->tee_err);
	close_pair(sup->log_pipe);
	if (sup->log_fd >= 0)
		close(sup->log_fd);
	if (sup->listen_fd >= 0)
		close(sup->listen_fd);
	if (report_fd >= 0)
		report_start(report_fd, rc < 0 ? rc : -EIO, "supervisor failed");

	if (sup->data_fd >= 0) {
		char text[160];
		int len = snprintf(text, sizeof text, "exit=%d\nrestarts=%d\nended=%ld\n",
				   rc < 0 ? EXIT_START_FAILED : rc, sup->restarts, (long)time(NULL));

		juno_put_file_at(sup->data_fd, "last", text, len);
	}
	juno_rm_tree(sup->runtime_dir);
	if (sup->lock_fd >= 0)
		close(sup->lock_fd);
	if (sup->runtime_fd >= 0)
		close(sup->runtime_fd);
	if (sup->data_fd >= 0)
		close(sup->data_fd);
	juno_spec_free(sup->spec);
}

static int serve(const juno_spec *spec, const char *name, int detach, int report_fd)
{
	struct supervisor sup = {
		.name = name, .listen_fd = -1, .lock_fd = -1, .runtime_fd = -1, .data_fd = -1, .log_fd = -1,
		.log_pipe = { -1, -1 }, .tee_out = { -1, -1 }, .tee_err = { -1, -1 },
	};
	char err[600];
	int rc;

	rc = open_state(&sup, report_fd);
	if (rc)
		return rc;

	sup.spec = juno_spec_dup(spec);
	if (!sup.spec) {
		report_start(report_fd, -ENOMEM, "spec copy failed");
		return -ENOMEM;
	}
	sup.spec->die_with_parent = true;
	sup.log_max = sup.spec->log_max ? sup.spec->log_max : LOG_DEFAULT_MAX;
	if (sup.spec->root_kind == JUNO_ROOT_OVERLAY && !sup.spec->root_path) {
		char upper[700];

		snprintf(upper, sizeof upper, "%s/upper", sup.data_dir);
		juno_spec_set_root(sup.spec, JUNO_ROOT_OVERLAY, upper);
	}
	juno_spec_save_at(sup.spec, sup.data_fd, "spec");

	log_open(&sup);
	if (sup.log_fd < 0) {
		rc = -errno;
		snprintf(err, sizeof err, "open log: %s", strerror(errno));
		report_start(report_fd, rc, err);
		juno_seterr("%s", err);
		goto done;
	}

	rc = setup_output(&sup, detach, report_fd);
	if (rc)
		goto done;

	rc = bind_socket(&sup);
	if (rc) {
		snprintf(err, sizeof err, "control socket: %s", strerror(-rc));
		report_start(report_fd, rc, err);
		juno_seterr("%s", err);
		goto done;
	}
	install_signal_handlers();

	sup.started = time(NULL);
	rc = juno_start(sup.spec, &sup.cell);
	if (rc) {
		snprintf(err, sizeof err, "%s", juno_error());
		report_start(report_fd, rc, err);
		juno_seterr("%s", err);
		sup.cell = NULL;
		goto done;
	}
	write_status(&sup);
	report_start(report_fd, 0, NULL);
	report_fd = -1;

	rc = supervise(&sup);
done:
	finish(&sup, rc, report_fd);
	return rc;
}

/* Run a named cell under a supervisor: in this process (foreground) or in a detached daemon whose
 * start result is passed back through a pipe. */
int juno_run_named(const juno_spec *spec, const char *name, int detach)
{
	char msg[512] = "supervisor exited before reporting";
	int report_pipe[2];
	int32_t rc = -EIO;
	pid_t child;

	if (!juno_valid_name(name)) {
		juno_seterr("invalid cell name '%s'", name ? name : "");
		return -EINVAL;
	}
	if (!detach)
		return serve(spec, name, 0, -1);

	if (pipe(report_pipe) < 0)
		return -errno;
	fflush(NULL);
	child = fork();
	if (child < 0)
		return -errno;
	if (child == 0) {
		int serve_rc;

		close(report_pipe[0]);
		setsid();
		if (fork() > 0)
			_exit(0);
		serve_rc = serve(spec, name, 1, report_pipe[1]);
		_exit(serve_rc < 0 ? 1 : 0);
	}

	close(report_pipe[1]);
	waitpid(child, NULL, 0);
	if (read(report_pipe[0], &rc, 4) == 4 && rc < 0) {
		ssize_t got = read(report_pipe[0], msg, sizeof msg - 1);

		msg[got > 0 ? got : 0] = 0;
	}
	close(report_pipe[0]);
	if (rc < 0)
		juno_seterr("%s", msg);
	return rc;
}
