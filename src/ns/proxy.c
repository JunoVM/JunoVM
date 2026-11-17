/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "ns.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
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

/* Egress proxy for cells that may reach a few named endpoints and nothing else.
 * The listener lives inside the cell's network namespace (127.0.0.1:3128); the
 * process serving it stays in the host's, resolves names there and connects
 * out only to exact allowlisted host:port pairs. */

#define PROXY_PORT 3128
#define HEAD_MAX 8192
#define MAX_CONNS 64
#define HEAD_TIMEOUT_MS 10000
#define CONNECT_TIMEOUT_MS 8000
#define RELAY_BUF_SIZE 16384
#define TARGET_MAX 260
#define LISTEN_BACKLOG 32

static const struct juno_spec *proxy_spec;

static int is_ip_literal(const char *host)
{
	if (strchr(host, ':'))
		return 1;
	for (const char *p = host; *p; p++) {
		if (!isdigit((unsigned char)*p) && *p != '.')
			return 0;
	}
	return *host != 0;
}

/* Exact "host:port" entries, or "*.suffix:port" for names (never for IP literals). */
static int host_allowed(const char *host, int port)
{
	size_t host_len = strlen(host);

	for (int i = 0; i < proxy_spec->nproxy; i++) {
		const char *entry = proxy_spec->proxy_allow[i];
		const char *colon = strrchr(entry, ':');
		size_t entry_len;

		if (atoi(colon + 1) != port)
			continue;
		entry_len = colon - entry;
		if (entry_len > 2 && entry[0] == '*' && entry[1] == '.') {
			size_t suffix_len = entry_len - 1;	/* ".suffix" */

			if (!is_ip_literal(host) && host_len > suffix_len &&
			    !strncmp(host + host_len - suffix_len, entry + 1, suffix_len))
				return 1;
		} else if (entry_len == host_len && !strncmp(entry, host, entry_len)) {
			return 1;
		}
	}
	return 0;
}

static void reply(int fd, const char *status)
{
	char msg[200];
	int len = snprintf(msg, sizeof msg,
			   "HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status);
	ssize_t written = write(fd, msg, len);

	(void)written;
}

static void log_line(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void log_line(const char *fmt, ...)
{
	char msg[512];
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = vsnprintf(msg, sizeof msg, fmt, ap);
	va_end(ap);
	if (len > 0) {
		ssize_t written = write(2, msg, len < (int)sizeof msg ? len : (int)sizeof msg - 1);

		(void)written;
	}
}

/* Connect with a bounded wait; the returned socket is blocking again. */
static int connect_out(const char *host, int port)
{
	struct addrinfo hints = { .ai_socktype = SOCK_STREAM }, *result = NULL;
	char port_text[8];
	int fd = -1;

	snprintf(port_text, sizeof port_text, "%d", port);
	if (getaddrinfo(host, port_text, &hints, &result) != 0)
		return -1;

	for (struct addrinfo *ai = result; ai && fd < 0; ai = ai->ai_next) {
		int sock = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);

		if (sock < 0)
			continue;
		fcntl(sock, F_SETFL, O_NONBLOCK);
		if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0) {
			fcntl(sock, F_SETFL, 0);
			fd = sock;
			continue;
		}
		if (errno == EINPROGRESS) {
			struct pollfd waiting = { sock, POLLOUT, 0 };
			int so_error = 0;
			socklen_t so_len = sizeof so_error;

			if (poll(&waiting, 1, CONNECT_TIMEOUT_MS) > 0 &&
			    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &so_len) == 0 && so_error == 0) {
				fcntl(sock, F_SETFL, 0);
				fd = sock;
				continue;
			}
		}
		close(sock);
	}
	freeaddrinfo(result);
	return fd;
}

/* Copy both ways until both sides are done; initial is data already read past the request head. */
static void relay(int client, int upstream, const char *initial, size_t initial_len,
	unsigned long *bytes_up, unsigned long *bytes_down)
{
	char buf[RELAY_BUF_SIZE];
	int open_side[2] = { 1, 1 };

	if (initial_len && write(upstream, initial, initial_len) == (ssize_t)initial_len)
		*bytes_up += initial_len;

	while (open_side[0] || open_side[1]) {
		struct pollfd fds[2] = {
			{ open_side[0] ? client : -1, POLLIN, 0 },
			{ open_side[1] ? upstream : -1, POLLIN, 0 },
		};

		if (poll(fds, 2, -1) < 0 && errno != EINTR)
			break;
		for (int side = 0; side < 2; side++) {
			int from = side ? upstream : client;
			int to = side ? client : upstream;
			ssize_t got;

			if (!(fds[side].revents & (POLLIN | POLLHUP | POLLERR)))
				continue;
			got = read(from, buf, sizeof buf);
			if (got <= 0) {
				open_side[side] = 0;
				shutdown(to, SHUT_WR);
				continue;
			}
			for (ssize_t done = 0; done < got; ) {
				ssize_t sent = write(to, buf + done, got - done);

				if (sent <= 0) {
					open_side[0] = open_side[1] = 0;
					break;
				}
				done += sent;
			}
			if (side)
				*bytes_down += got;
			else
				*bytes_up += got;
		}
	}
}

/* Read until the blank line that ends the request head; returns its end or NULL (already answered). */
static char *read_request_head(int client, char *head, size_t *len)
{
	char *end = NULL;

	*len = 0;
	while (!end) {
		struct pollfd waiting = { client, POLLIN, 0 };
		ssize_t got;

		if (*len >= HEAD_MAX) {
			reply(client, "431 Request Header Fields Too Large");
			log_line("proxy: denied (request head over %d bytes)\n", HEAD_MAX);
			return NULL;
		}
		if (poll(&waiting, 1, HEAD_TIMEOUT_MS) <= 0)
			return NULL;
		got = read(client, head + *len, HEAD_MAX - *len);
		if (got <= 0)
			return NULL;
		*len += got;
		head[*len] = 0;
		end = memmem(head, *len, "\r\n\r\n", 4);
	}
	return end;
}

/* Validate "CONNECT host:port HTTP/1.x" and split out the lowercase host and port.
 * Replies and logs on rejection and returns -1. */
static int parse_connect_line(int client, char *head, size_t head_len, char **host, long *port)
{
	char *eol = memchr(head, '\r', head_len);
	char *space1, *space2, *target, *colon, *port_end;

	*eol = 0;
	if (memchr(head, 0, eol - head)) {
		reply(client, "400 Bad Request");
		log_line("proxy: denied (malformed request line)\n");
		return -1;
	}
	space1 = strchr(head, ' ');
	space2 = space1 ? strchr(space1 + 1, ' ') : NULL;
	if (!space1 || !space2 || strncmp(space2 + 1, "HTTP/1.", 7)) {
		reply(client, "400 Bad Request");
		log_line("proxy: denied (malformed request line)\n");
		return -1;
	}
	*space1 = *space2 = 0;

	if (strcmp(head, "CONNECT")) {
		reply(client, "403 Forbidden");
		log_line("proxy: %.20s denied (only CONNECT to allowlisted host:port pairs is proxied)\n", head);
		return -1;
	}

	target = space1 + 1;
	colon = strrchr(target, ':');
	*port = colon ? strtol(colon + 1, &port_end, 10) : 0;
	if (!colon || colon == target || *port_end || *port < 1 || *port > 65535 ||
	    strlen(target) > TARGET_MAX) {
		reply(client, "400 Bad Request");
		log_line("proxy: denied (malformed CONNECT target)\n");
		return -1;
	}
	*colon = 0;

	*host = target;
	if ((*host)[0] == '[' && colon[-1] == ']') {
		(*host)++;
		colon[-1] = 0;
	}
	for (char *p = *host; *p; p++) {
		if ((unsigned char)*p <= ' ' || *p == '/' || *p == '@') {
			reply(client, "400 Bad Request");
			log_line("proxy: denied (bad character in host)\n");
			return -1;
		}
		*p = tolower((unsigned char)*p);
	}
	return 0;
}

/* one client connection, in its own process */
static void handle(int client)
{
	static const char established[] = "HTTP/1.1 200 Connection established\r\n\r\n";
	char head[HEAD_MAX + 1];
	size_t head_len, request_len;
	unsigned long bytes_up = 0, bytes_down = 0;
	char *end, *host;
	long port;
	int upstream;

	end = read_request_head(client, head, &head_len);
	if (!end)
		return;
	request_len = end + 4 - head;
	if (parse_connect_line(client, head, request_len, &host, &port) < 0)
		return;

	if (!host_allowed(host, (int)port)) {
		reply(client, "403 Forbidden");
		log_line("proxy: CONNECT %.255s:%ld denied\n", host, port);
		return;
	}
	upstream = connect_out(host, (int)port);
	if (upstream < 0) {
		reply(client, "502 Bad Gateway");
		log_line("proxy: CONNECT %.255s:%ld allowed but the connection failed\n", host, port);
		return;
	}
	if (write(client, established, strlen(established)) < 0) {
		close(upstream);
		return;
	}

	relay(client, upstream, head + request_len, head_len - request_len, &bytes_up, &bytes_down);
	log_line("proxy: CONNECT %.255s:%ld allowed up=%lu down=%lu bytes\n", host, port, bytes_up, bytes_down);
	close(upstream);
}

static void serve(int listen_fd, int cell_fd)
{
	int child_count = 0;

	signal(SIGPIPE, SIG_IGN);
	prctl(PR_SET_PDEATHSIG, SIGKILL);
	for (;;) {
		struct pollfd fds[2] = { { cell_fd, POLLIN, 0 }, { listen_fd, POLLIN, 0 } };
		int client;
		pid_t child;

		poll(fds, 2, 1000);
		if (fds[0].revents)
			_exit(0);
		while (child_count > 0 && waitpid(-1, NULL, WNOHANG) > 0)
			child_count--;
		if (!(fds[1].revents & POLLIN))
			continue;

		client = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
		if (client < 0)
			continue;
		if (child_count >= MAX_CONNS) {
			close(client);
			continue;
		}
		child = fork();
		if (child == 0) {
			close(listen_fd);
			prctl(PR_SET_PDEATHSIG, SIGKILL);
			handle(client);
			_exit(0);
		}
		if (child > 0)
			child_count++;
		close(client);
	}
}

/* In the helper: join the cell's namespaces and bind the listener, sending it back over sock. */
static void helper_listen(int sock, int pidfd)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET, .sin_port = htons(PROXY_PORT), .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	int one = 1;
	int fd = -1;

	if (setns(pidfd, CLONE_NEWUSER) == 0 && setns(pidfd, CLONE_NEWNET) == 0 && ns_net_up() == 0) {
		fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
		if (fd >= 0) {
			setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
			if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0 || listen(fd, LISTEN_BACKLOG) < 0)
				fd = -1;
		}
	}
	if (fd >= 0)
		ns_send_fd(sock, fd);
	_exit(fd >= 0 ? 0 : 1);
}

/* Create the listener inside the cell's namespaces (its init is the clone child
 * holding pidfd) and serve it from a process of ours. */
int ns_proxy_spawn(const juno_spec *spec, int pidfd, juno_cell *cell)
{
	int pair[2];
	int listen_fd;
	pid_t helper, server;

	if (!spec->nproxy)
		return 0;
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) < 0)
		return -errno;

	fflush(NULL);
	helper = fork();
	if (helper < 0) {
		close(pair[0]);
		close(pair[1]);
		return -errno;
	}
	if (helper == 0) {
		close(pair[0]);
		helper_listen(pair[1], pidfd);
	}

	close(pair[1]);
	listen_fd = ns_recv_fd(pair[0]);
	close(pair[0]);
	waitpid(helper, NULL, 0);
	if (listen_fd < 0) {
		juno_seterr("egress proxy: cannot listen on 127.0.0.1:%d inside the cell", PROXY_PORT);
		return -EIO;
	}

	proxy_spec = spec;
	server = fork();
	if (server == 0) {
		setsid();
		serve(listen_fd, pidfd);
		_exit(0);
	}
	close(listen_fd);
	if (server < 0)
		return -errno;
	cell->proxypid = server;
	return 0;
}
