/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "ns.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define LISTEN_BACKLOG 64
#define MAX_CONNS 256
#define CONNECT_MS 3000
#define RELAY_BUF_SIZE 16384
#define POLL_IDLE_MS 200
#define POLL_PAUSED_MS 100
#define FD_EXHAUSTED_PAUSE_MS 200
/* polled entries per live connection: connecting uses one, relaying uses four */
#define POLL_SLOTS_PER_CONN 4

/* Parse "[A.B.C.D:]HOSTPORT:CELLPORT"; the bind address defaults to loopback. */
static void parse_publish(const char *text, struct sockaddr_in *addr, unsigned *cell_port)
{
	unsigned a = 127, b = 0, c = 0, d = 1, host_port = 0, port = 0;

	if (sscanf(text, "%u.%u.%u.%u:%u:%u", &a, &b, &c, &d, &host_port, &port) != 6) {
		a = 127;
		b = c = 0;
		d = 1;
		sscanf(text, "%u:%u", &host_port, &port);
	}
	addr->sin_family = AF_INET;
	addr->sin_port = htons(host_port);
	addr->sin_addr.s_addr = htonl(a << 24 | b << 16 | c << 8 | d);
	*cell_port = port;
}

static void close_listeners(int *listen_fds, int count)
{
	while (count)
		close(listen_fds[--count]);
}

int ns_fwd_bind(const juno_spec *spec, int *listen_fds, int *cell_ports, int max)
{
	int count = 0;

	for (int i = 0; i < spec->npubs && count < max; i++) {
		struct sockaddr_in addr = { 0 };
		unsigned cell_port;
		int fd, one = 1, saved;

		parse_publish(spec->pubs[i], &addr, &cell_port);
		fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
		if (fd < 0) {
			saved = errno;
			juno_seterr("publish: socket: %s", strerror(saved));
			close_listeners(listen_fds, count);
			return -saved;
		}
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
		if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0 || listen(fd, LISTEN_BACKLOG) < 0) {
			saved = errno;
			juno_seterr("publish: bind %s: %s", spec->pubs[i], strerror(saved));
			close(fd);
			close_listeners(listen_fds, count);
			return -saved;
		}
		listen_fds[count] = fd;
		cell_ports[count++] = cell_port;
	}
	return count;
}

/* A connection first waits for a helper inside the cell to connect (so one wedged backend never
 * holds up the others), then relays with two bounded buffers. */
struct conn {
	int connecting;
	int fd[2];			/* 0 client, 1 cell */
	int helper_sock;		/* the helper's end while connecting */
	pid_t helper;
	uint64_t born_ms;
	char *buf[2];			/* buf[d] carries fd[d] -> fd[1-d] */
	size_t len[2], off[2];
	bool eof[2], shut[2];
};

/* In the helper: enter the cell's network namespace, connect to 127.0.0.1:port and send the
 * result (errno, plus the connected fd on success) back over sock. */
static void helper_connect(int sock, int init_fd, int port, int holder_user, int holder_net)
{
	struct sockaddr_in loopback = {
		.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	char control[CMSG_SPACE(sizeof(int))] = { 0 };
	int result = 0, fd = -1;
	struct iovec iov = { &result, sizeof result };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };

	if (holder_user >= 0) {	/* shared network: the holder owns it */
		if (setns(holder_user, CLONE_NEWUSER) < 0 || setns(holder_net, CLONE_NEWNET) < 0)
			result = errno;
	} else if (setns(init_fd, CLONE_NEWUSER) < 0 || setns(init_fd, CLONE_NEWNET) < 0) {
		result = errno;
	}
	if (!result) {
		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0 || connect(fd, (struct sockaddr *)&loopback, sizeof loopback) < 0)
			result = errno;
	}
	if (!result) {
		struct cmsghdr *cmsg;

		msg.msg_control = control;
		msg.msg_controllen = sizeof control;
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &fd, sizeof fd);
	}
	sendmsg(sock, &msg, 0);
	_exit(0);
}

static int start_connect(int init_fd, int port, int holder_user, int holder_net, int *sock_out,
	pid_t *helper_out)
{
	int pair[2];
	pid_t helper;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) < 0)
		return -1;
	helper = fork();
	if (helper < 0) {
		close(pair[0]);
		close(pair[1]);
		return -1;
	}
	if (helper == 0) {
		close(pair[0]);
		helper_connect(pair[1], init_fd, port, holder_user, holder_net);
	}
	close(pair[1]);
	*sock_out = pair[0];
	*helper_out = helper;
	return 0;
}

/* the helper's answer: the connected fd, or -1 */
static int finish_connect(struct conn *conn)
{
	char control[CMSG_SPACE(sizeof(int))];
	int result = -1, fd = -1;
	struct iovec iov = { &result, sizeof result };
	struct msghdr msg = {
		.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof control,
	};

	if (recvmsg(conn->helper_sock, &msg, MSG_CMSG_CLOEXEC | MSG_DONTWAIT) > 0 && result == 0) {
		struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

		if (cmsg && cmsg->cmsg_type == SCM_RIGHTS)
			memcpy(&fd, CMSG_DATA(cmsg), sizeof fd);
	}
	close(conn->helper_sock);
	conn->helper_sock = -1;
	waitpid(conn->helper, NULL, 0);
	return fd;
}

static void conn_close(struct conn *conn)
{
	if (conn->helper_sock >= 0) {
		close(conn->helper_sock);
		kill(conn->helper, SIGKILL);
		waitpid(conn->helper, NULL, 0);
	}
	if (conn->fd[0] >= 0)
		close(conn->fd[0]);
	if (conn->fd[1] >= 0)
		close(conn->fd[1]);
	free(conn->buf[0]);
	free(conn->buf[1]);
	free(conn);
}

static int conn_done(const struct conn *conn)
{
	return !conn->connecting && conn->shut[0] && conn->shut[1];
}

/* Move data in direction dir (0 client->cell, 1 cell->client); returns 0 on progress, -1 on fatal error. */
static int pump(struct conn *conn, int dir)
{
	if (conn->len[dir] == 0 && !conn->eof[dir]) {
		ssize_t got = read(conn->fd[dir], conn->buf[dir], RELAY_BUF_SIZE);

		if (got > 0) {
			conn->len[dir] = got;
			conn->off[dir] = 0;
		} else if (got == 0 || (errno != EAGAIN && errno != EINTR)) {
			conn->eof[dir] = true;
		}
	}

	while (conn->len[dir] > conn->off[dir]) {
		ssize_t sent = write(conn->fd[1 - dir], conn->buf[dir] + conn->off[dir],
				     conn->len[dir] - conn->off[dir]);

		if (sent > 0)
			conn->off[dir] += sent;
		else if (errno == EAGAIN || errno == EINTR)
			break;
		else
			return -1;
	}
	if (conn->off[dir] == conn->len[dir])
		conn->len[dir] = conn->off[dir] = 0;

	if (conn->eof[dir] && conn->len[dir] == 0 && !conn->shut[dir]) {
		shutdown(conn->fd[1 - dir], SHUT_WR);
		conn->shut[dir] = true;
	}
	return 0;
}

struct fwd_state {
	int *listen_fds;
	int *cell_ports;
	int listener_count;
	int init_fd;
	int holder_user, holder_net;
	struct conn **conns;
	int conn_count;
	uint64_t paused_until_ms;
};

/* Build the poll set: the cell pidfd, the listeners, then what each connection waits for.
 * Entries with nothing to wait for are dropped: an fd left in would spin on POLLHUP, and poll()
 * fails with EINVAL when nfds exceeds RLIMIT_NOFILE. Returns the live entry count. */
static int build_pollset(const struct fwd_state *fwd, int cell_fd, uint64_t now, struct pollfd *set)
{
	int count = 0;

	set[count++] = (struct pollfd){ cell_fd, POLLIN, 0 };
	for (int i = 0; i < fwd->listener_count; i++) {
		/* out of fds: stop listening for a moment instead of spinning */
		set[count++] = (struct pollfd){ now < fwd->paused_until_ms ? -1 : fwd->listen_fds[i], POLLIN, 0 };
	}

	for (int i = 0; i < fwd->conn_count; i++) {
		struct conn *conn = fwd->conns[i];

		if (conn->connecting) {
			set[count++] = (struct pollfd){ conn->helper_sock, POLLIN, 0 };
			continue;
		}
		for (int dir = 0; dir < 2; dir++) {
			short read_events = (conn->len[dir] == 0 && !conn->eof[dir]) ? POLLIN : 0;
			short write_events = conn->len[dir] > conn->off[dir] ? POLLOUT : 0;

			set[count++] = (struct pollfd){ read_events ? conn->fd[dir] : -1, read_events, 0 };
			set[count++] = (struct pollfd){ write_events ? conn->fd[1 - dir] : -1, write_events, 0 };
		}
	}

	int live = 0;

	for (int i = 0; i < count; i++) {
		if (set[i].fd >= 0)
			set[live++] = set[i];
	}
	return live;
}

static void accept_clients(struct fwd_state *fwd, uint64_t now)
{
	for (int i = 0; i < fwd->listener_count; i++) {
		int client;

		if (now < fwd->paused_until_ms)
			break;
		while ((client = accept4(fwd->listen_fds[i], NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK)) >= 0) {
			struct conn *conn;

			if (fwd->conn_count >= MAX_CONNS) {
				close(client);
				continue;
			}
			conn = calloc(1, sizeof *conn);
			if (!conn) {
				close(client);
				continue;
			}
			conn->fd[0] = client;
			conn->fd[1] = -1;
			conn->connecting = 1;
			conn->born_ms = now;
			conn->helper_sock = -1;
			if (start_connect(fwd->init_fd, fwd->cell_ports[i], fwd->holder_user, fwd->holder_net,
					  &conn->helper_sock, &conn->helper) < 0) {
				close(client);
				free(conn);
				continue;
			}
			fwd->conns = realloc(fwd->conns, sizeof *fwd->conns * (fwd->conn_count + 1));
			fwd->conns[fwd->conn_count++] = conn;
		}
		if (errno == EMFILE || errno == ENFILE)
			fwd->paused_until_ms = now + FD_EXHAUSTED_PAUSE_MS;
	}
}

/* Returns 1 when the connection should be dropped. */
static int advance_conn(struct conn *conn, uint64_t now)
{
	if (!conn->connecting)
		return pump(conn, 0) < 0 || pump(conn, 1) < 0 || conn_done(conn);

	struct pollfd probe = { conn->helper_sock, POLLIN, 0 };

	if (poll(&probe, 1, 0) > 0) {
		int fd = finish_connect(conn);

		if (fd < 0)
			return 1;
		fcntl(fd, F_SETFL, O_NONBLOCK);
		conn->fd[1] = fd;
		conn->connecting = 0;
		conn->buf[0] = malloc(RELAY_BUF_SIZE);
		conn->buf[1] = malloc(RELAY_BUF_SIZE);
		return !conn->buf[0] || !conn->buf[1];
	}
	return now - conn->born_ms > CONNECT_MS;
}

static void serve(int *listen_fds, int *cell_ports, int count, int init_fd, int cell_fd,
	int holder_user, int holder_net)
{
	struct fwd_state fwd = {
		.listen_fds = listen_fds, .cell_ports = cell_ports, .listener_count = count,
		.init_fd = init_fd, .holder_user = holder_user, .holder_net = holder_net,
	};

	signal(SIGPIPE, SIG_IGN);
	prctl(PR_SET_PDEATHSIG, SIGKILL);
	for (int i = 0; i < count; i++)
		fcntl(listen_fds[i], F_SETFL, O_NONBLOCK);

	for (;;) {
		uint64_t now = juno_now_ms();
		size_t slots = 1 + count + POLL_SLOTS_PER_CONN * fwd.conn_count;
		struct pollfd *set = calloc(slots, sizeof *set);
		int timeout = fwd.conn_count ? POLL_IDLE_MS : -1;
		int live, cell_gone;

		if (fwd.paused_until_ms > now)
			timeout = POLL_PAUSED_MS;
		live = build_pollset(&fwd, cell_fd, now, set);
		if (poll(set, live, timeout) < 0 && errno != EINTR)
			usleep(10000);
		cell_gone = set[0].revents != 0;
		free(set);
		if (cell_gone)
			_exit(0);

		now = juno_now_ms();
		accept_clients(&fwd, now);
		for (int i = 0; i < fwd.conn_count; i++) {
			struct conn *conn = fwd.conns[i];

			if (advance_conn(conn, now)) {
				conn_close(conn);
				fwd.conns[i--] = fwd.conns[--fwd.conn_count];
			}
		}
	}
}

int ns_fwd_spawn(juno_cell *cell, int *listen_fds, int *cell_ports, int count)
{
	int holder_user = -1, holder_net = -1;
	pid_t pid;

	if (cell->spec->net == JUNO_NET_SHARED &&
	    ns_net_holder(cell->spec->netname, &holder_user, &holder_net) < 0)
		return -1;
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		setsid();
		serve(listen_fds, cell_ports, count, cell->ipidfd, cell->pidfd, holder_user, holder_net);
		_exit(0);
	}

	if (holder_user >= 0) {
		close(holder_user);
		close(holder_net);
	}
	cell->fwdpid = pid;
	for (int i = 0; i < count; i++)
		close(listen_fds[i]);
	return 0;
}
