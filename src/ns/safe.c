/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "ns.h"
#include <errno.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

/* Minimal printf for the forked child: %s %d %u %% only, no allocation, always terminated. */
size_t ns_vfmt(char *buf, size_t size, const char *fmt, va_list ap)
{
	size_t len = 0;

	if (!size)
		return 0;

#define PUT(ch) do { if (len + 1 < size) buf[len] = (ch); len++; } while (0)
	for (; *fmt; fmt++) {
		if (*fmt != '%') {
			PUT(*fmt);
			continue;
		}
		fmt++;
		if (*fmt == 's') {
			const char *str = va_arg(ap, const char *);

			if (!str)
				str = "(null)";
			while (*str)
				PUT(*str++);
		} else if (*fmt == 'd' || *fmt == 'u') {
			long long value = *fmt == 'd' ? va_arg(ap, int) : (long long)va_arg(ap, unsigned);
			unsigned long long magnitude = value < 0 ? -(unsigned long long)value
								  : (unsigned long long)value;
			char digits[24];
			int ndigits = 0;

			if (value < 0)
				PUT('-');
			do {
				digits[ndigits++] = '0' + magnitude % 10;
				magnitude /= 10;
			} while (magnitude);
			while (ndigits)
				PUT(digits[--ndigits]);
		} else if (*fmt == '%') {
			PUT('%');
		}
	}
	buf[len < size ? len : size - 1] = 0;
	return len < size ? len : size - 1;
#undef PUT
}

size_t ns_fmt(char *buf, size_t size, const char *fmt, ...)
{
	va_list ap;
	size_t len;

	va_start(ap, fmt);
	len = ns_vfmt(buf, size, fmt, ap);
	va_end(ap);
	return len;
}

void ns_die(struct ns_ctx *ctx, const char *fmt, ...)
{
	struct ns_err msg;
	va_list ap;
	ssize_t written;

	msg.err = errno;
	va_start(ap, fmt);
	ns_vfmt(msg.step, sizeof msg.step, fmt, ap);
	va_end(ap);

	written = write(ctx->errfd, &msg, sizeof msg.err + strlen(msg.step) + 1);
	(void)written;

	/* an aborted start must not leave its stage dir behind */
	if (ctx->stage && !ctx->pivoted) {
		umount2(ctx->stage, MNT_DETACH);
		rmdir(ctx->stage);
	}
	_exit(127);
}

int ns_send_fd(int sock, int fd)
{
	char control[CMSG_SPACE(sizeof(int))] = { 0 };
	char payload = 'F';
	struct iovec iov = { &payload, 1 };
	struct msghdr msg = {
		.msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = control, .msg_controllen = sizeof control,
	};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof fd);
	return sendmsg(sock, &msg, 0) < 0 ? -1 : 0;
}

int ns_recv_fd(int sock)
{
	char control[CMSG_SPACE(sizeof(int))];
	char payload;
	struct iovec iov = { &payload, 1 };
	struct msghdr msg = {
		.msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = control, .msg_controllen = sizeof control,
	};
	struct cmsghdr *cmsg;
	int fd = -1;

	if (recvmsg(sock, &msg, MSG_CMSG_CLOEXEC) <= 0)
		return -1;
	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg && cmsg->cmsg_type == SCM_RIGHTS)
		memcpy(&fd, CMSG_DATA(cmsg), sizeof fd);
	return fd;
}
