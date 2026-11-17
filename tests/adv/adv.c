/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
/* Attack helper run inside cells by tests/adversarial.sh. Each command prints
 * one line, "OK <detail>" when the attack worked and "DENIED <errno text>"
 * when the kernel or the cell policy refused it. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/sched.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/sysmacros.h>
#include <sys/io.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#ifndef SYS_clone3
#define SYS_clone3 435
#endif

static int report_denied(void)
{
	printf("DENIED %s\n", strerror(errno));
	return 1;
}
static int report_ok(const char *fmt, const char *arg)
{
	printf("OK ");
	printf(fmt, arg);
	printf("\n");
	return 0;
}
#define RES(cond, what) ((cond) ? report_ok("%s", what) : report_denied())

static int c_fds(void)
{
	DIR *d = opendir("/proc/self/fd");
	struct dirent *e;
	char p[64], t[256];
	int self = dirfd(d);
	while ((e = readdir(d))) {
		if (e->d_name[0] == '.' || atoi(e->d_name) == self) continue;
		snprintf(p, sizeof p, "/proc/self/fd/%s", e->d_name);
		ssize_t n = readlink(p, t, sizeof t - 1);
		t[n > 0 ? n : 0] = 0;
		printf("fd %s -> %s\n", e->d_name, t);
	}
	return 0;
}

static int c_tty(void)
{
	int fd = open("/dev/tty", O_RDWR | O_NOCTTY);
	if (fd < 0) return report_denied();
	char c = 'x';
	if (ioctl(fd, TIOCSTI, &c) < 0) {
		printf("OPENED /dev/tty, TIOCSTI: %s\n", strerror(errno));
		return 2;
	}
	return report_ok("%s", "TIOCSTI injected a byte");
}

static int c_userns(const char *how)
{
	if (!strcmp(how, "unshare")) return RES(unshare(CLONE_NEWUSER) == 0, "unshare(CLONE_NEWUSER)");
	if (!strcmp(how, "clone")) {
		long r = syscall(SYS_clone, SIGCHLD | CLONE_NEWUSER, 0, 0, 0, 0);
		if (r == 0) _exit(0);
		if (r > 0) waitpid(r, NULL, 0);
		return RES(r > 0, "clone(CLONE_NEWUSER)");
	}
	if (!strcmp(how, "clone-hi")) {	/* the same flag with junk in the upper half */
		long r = syscall(SYS_clone, (unsigned long)SIGCHLD | CLONE_NEWUSER | (1ul << 40), 0, 0, 0, 0);
		if (r == 0) _exit(0);
		if (r > 0) waitpid(r, NULL, 0);
		return RES(r > 0, "clone(CLONE_NEWUSER | high bits)");
	}
	if (!strcmp(how, "clone3")) {
		struct clone_args ca;
		memset(&ca, 0, sizeof ca);
		ca.flags = CLONE_NEWUSER;
		ca.exit_signal = SIGCHLD;
		long r = syscall(SYS_clone3, &ca, sizeof ca);
		if (r == 0) _exit(0);
		if (r > 0) waitpid(r, NULL, 0);
		return RES(r > 0, "clone3(CLONE_NEWUSER)");
	}
	return 2;
}

static int c_sys(const char *n)
{
	long r = -1;
	errno = 0;
	if (!strcmp(n, "io_uring")) {
		char buf[120] = { 0 };
		r = syscall(425 /* io_uring_setup */, 4, buf);
	} else if (!strcmp(n, "userfaultfd")) r = syscall(SYS_userfaultfd, 0);
	else if (!strcmp(n, "personality")) r = personality(PER_LINUX32 | ADDR_NO_RANDOMIZE) < 0 ? -1 : 0;
	else if (!strcmp(n, "setns")) {
		int fd = open("/proc/self/ns/user", O_RDONLY);
		r = setns(fd, CLONE_NEWUSER);
	}
	else if (!strcmp(n, "setns-net")) {
		int fd = open("/proc/self/ns/net", O_RDONLY);
		r = setns(fd, CLONE_NEWNET);
	}
	else if (!strcmp(n, "unshare-mnt")) r = unshare(CLONE_NEWNS);
	else if (!strcmp(n, "unshare-net")) r = unshare(CLONE_NEWNET);
	else if (!strcmp(n, "fsopen")) r = syscall(430, "tmpfs", 0);
	else if (!strcmp(n, "open_tree")) r = syscall(428, -100, "/", 1 | 0x8000 | 0x80000);
	else if (!strcmp(n, "mount_setattr")) { long a[4] = { 0 }; r = syscall(442, -100, "/", 0, a, 32); }
	else if (!strcmp(n, "move_mount")) r = syscall(429, -1, "", -100, "/mnt", 4);
	else if (!strcmp(n, "bpf")) r = syscall(SYS_bpf, 0, NULL, 0);
	else if (!strcmp(n, "perf")) r = syscall(SYS_perf_event_open, NULL, 0, -1, -1, 0);
	else if (!strcmp(n, "keyctl")) r = syscall(SYS_keyctl, 0, 0, 0, 0, 0);
	else if (!strcmp(n, "kexec")) r = syscall(SYS_kexec_load, 0, 0, NULL, 0);
	else if (!strcmp(n, "init_module")) r = syscall(SYS_init_module, NULL, 0, "");
	else if (!strcmp(n, "reboot")) r = syscall(SYS_reboot, 0, 0, 0, NULL);
	else if (!strcmp(n, "settime")) { struct timespec t = { 1, 0 }; r = clock_settime(CLOCK_REALTIME, &t); }
	else if (!strcmp(n, "mount-tmpfs")) r = mount("tmpfs", "/mnt", "tmpfs", 0, NULL);
	else if (!strcmp(n, "chroot")) r = chroot("/tmp");
	else if (!strcmp(n, "pivot_root")) r = syscall(SYS_pivot_root, "/tmp", "/tmp");
	else if (!strcmp(n, "sethostname")) r = sethostname("x", 1);
	else if (!strcmp(n, "ptrace-self-child")) {
		pid_t p = fork();
		if (p == 0) {
			ptrace(PTRACE_TRACEME, 0, 0, 0);
			raise(SIGSTOP);
			_exit(0);
		}
		waitpid(p, NULL, WUNTRACED);
		r = ptrace(PTRACE_CONT, p, 0, 0);
		kill(p, SIGKILL);
		waitpid(p, NULL, 0);
	} else if (!strcmp(n, "ptrace-init")) r = ptrace(PTRACE_ATTACH, 1, 0, 0);
	else if (!strcmp(n, "mknod")) r = mknod("/tmp/nul", S_IFCHR | 0666, makedev(1, 3));
	else if (!strcmp(n, "kill-init")) {
		r = kill(1, SIGKILL);
		if (r == 0) {
			usleep(300000);
			return report_ok("%s", "kill(1, SIGKILL) returned 0, init still running");
		}
	}
	else if (!strcmp(n, "kill-all")) r = kill(-1, SIGTERM) < 0 ? -1 : 0;
	else if (!strcmp(n, "kill-ppid")) {
		r = getppid() == 0 ? -1 : kill(getppid(), 0);
	}
	else if (!strcmp(n, "pidfd_open-1")) {
		r = syscall(SYS_pidfd_open, 1, 0);
	}
	else if (!strcmp(n, "pidfd_getfd")) {
		int pf = syscall(SYS_pidfd_open, 1, 0);
		r = pf < 0 ? -1 : syscall(438 + 0 + 0, 0);
		r = pf < 0 ? -1 : syscall(438, pf, 0, 0);
	}
	else if (!strcmp(n, "kcmp")) r = syscall(SYS_kcmp, 1, 1, 0, 0, 0);
	else if (!strcmp(n, "swapon")) r = syscall(SYS_swapon, "/tmp/x", 0);
	else if (!strcmp(n, "acct")) r = syscall(SYS_acct, "/tmp/x");
	else if (!strcmp(n, "ioperm")) r = ioperm(0x80, 1, 1);
	else if (!strcmp(n, "mlockall")) r = mlockall(MCL_CURRENT);
	else if (!strcmp(n, "shmget")) r = syscall(SYS_shmget, 0x4a554e4f, 4096, 01000 | 0600);
	else return 2;
	return RES(r >= 0, n);
}

static int c_write(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return report_denied();
	ssize_t n = write(fd, text ? text : "x", strlen(text ? text : "x"));
	close(fd);
	return RES(n > 0, path);
}

static int c_read(const char *path)
{
	char b[512];
	int fd = open(path, O_RDONLY);
	if (fd < 0) return report_denied();
	ssize_t n = read(fd, b, sizeof b - 1);
	if (n < 0) return report_denied();
	b[n] = 0;
	b[strcspn(b, "\n")] = 0;
	printf("OK read %zd bytes: %.80s\n", n, b);
	return 0;
}

static int c_caps(void)
{
	char l[256];
	FILE *f = fopen("/proc/self/status", "r");
	while (fgets(l, sizeof l, f))
		if (!strncmp(l, "Cap", 3) || !strncmp(l, "NoNewPrivs", 10) || !strncmp(l, "Seccomp:", 8) || !strncmp(l, "Uid", 3))
			fputs(l, stdout);
	return 0;
}

static int c_connect(const char *ip, int port, int ms)
{
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) };
	inet_pton(AF_INET, ip, &sa.sin_addr);
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) return report_denied();
	int r = connect(fd, (struct sockaddr *)&sa, sizeof sa);
	if (r < 0 && errno == EINPROGRESS) {
		fd_set w;
		struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
		FD_ZERO(&w); FD_SET(fd, &w);
		if (select(fd + 1, NULL, &w, NULL, &tv) > 0) {
			int e = 0; socklen_t l = sizeof e;
			getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &l);
			if (e) {
				errno = e;
				return report_denied();
			}
			return report_ok("%s", "connected");
		}
		errno = ETIMEDOUT;
		return report_denied();
	}
	return RES(r == 0, "connected");
}

static int c_raw(const char *kind)
{
	int fd;
	if (!strcmp(kind, "packet")) fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	else if (!strcmp(kind, "icmp")) fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	else if (!strcmp(kind, "ping")) fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	else if (!strcmp(kind, "netlink")) fd = socket(AF_NETLINK, SOCK_RAW, 0);
	else return 2;
	return RES(fd >= 0, kind);
}

static int c_abstract(const char *name)
{
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	size_t n = strlen(name);
	memcpy(sa.sun_path + 1, name, n);
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	int r = connect(fd, (struct sockaddr *)&sa, offsetof(struct sockaddr_un, sun_path) + 1 + n);
	return RES(r == 0, "connected to abstract socket");
}

static int c_abstract_listen(const char *name)
{
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	size_t n = strlen(name);
	memcpy(sa.sun_path + 1, name, n);
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (bind(fd, (struct sockaddr *)&sa, offsetof(struct sockaddr_un, sun_path) + 1 + n) < 0) return report_denied();
	listen(fd, 5);
	printf("OK listening\n");
	fflush(stdout);
	int c = accept(fd, NULL, NULL);
	char b[64];
	ssize_t k = read(c, b, sizeof b);
	printf("OK got %zd bytes\n", k);
	return 0;
}

static int c_flood(const char *what, const char *arg)
{
	long n = atol(arg);
	if (!strcmp(what, "fork")) {
		long ok = 0;
		pid_t kids[4096];
		for (long i = 0; i < n && i < 4096; i++) {
			pid_t p = fork();
			if (p == 0) {
				pause();
				_exit(0);
			}
			if (p < 0) break;
			kids[ok++] = p;
		}
		printf("forked %ld\n", ok);
		for (long i = 0; i < ok; i++) kill(kids[i], SIGKILL);
		while (wait(NULL) > 0) ;
		return 0;
	}
	if (!strcmp(what, "open")) {
		long ok = 0;
		while (open("/dev/null", O_RDONLY) >= 0) ok++;
		printf("opened %ld\n", ok);
		return 0;
	}
	if (!strcmp(what, "tmpfs")) {	/* write MB to a path given in $FILL, report how many fit */
		const char *path = getenv("FILL");
		int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd < 0) return report_denied();
		static char buf[1 << 20];
		long mb = 0;
		memset(buf, 'x', sizeof buf);
		while (mb < n && write(fd, buf, sizeof buf) == sizeof buf) mb++;
		printf("wrote %ld MB (errno %s)\n", mb, mb < n ? strerror(errno) : "none");
		unlink(path);
		return 0;
	}
	if (!strcmp(what, "mem")) {
		long mb = 0;
		while (mb < n) {
			char *p = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (p == MAP_FAILED) break;
			memset(p, 1, 1 << 20);
			mb++;
		}
		printf("allocated %ld MB\n", mb);
		return 0;
	}
	return 2;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc < 2) return 2;
	const char *c = argv[1], *a = argc > 2 ? argv[2] : "", *b = argc > 3 ? argv[3] : NULL;
	if (!strcmp(c, "fds")) return c_fds();
	if (!strcmp(c, "tty")) return c_tty();
	if (!strcmp(c, "userns")) return c_userns(a);
	if (!strcmp(c, "sys")) return c_sys(a);
	if (!strcmp(c, "write")) return c_write(a, b);
	if (!strcmp(c, "read")) return c_read(a);
	if (!strcmp(c, "caps")) return c_caps();
	if (!strcmp(c, "connect")) return c_connect(a, atoi(b), argc > 4 ? atoi(argv[4]) : 1500);
	if (!strcmp(c, "raw")) return c_raw(a);
	if (!strcmp(c, "abstract")) return c_abstract(a);
	if (!strcmp(c, "abstract-listen")) return c_abstract_listen(a);
	if (!strcmp(c, "flood")) return c_flood(a, b ? b : "0");
	if (!strcmp(c, "deep")) {	/* a directory chain deeper than any path buffer: "d/d/d/..." built with chdir */
		long n = atol(a), i;
		for (i = 0; i < n; i++)
			if (mkdir("d", 0755) < 0 || chdir("d") < 0) break;
		printf("built %ld levels\n", i);
		return 0;
	}
	if (!strcmp(c, "symlinks")) {	/* leave links to host-looking places behind in cwd */
		symlink("/", "root-link");
		symlink(a, "target-link");
		printf("OK links created\n");
		return 0;
	}
	return 2;
}
