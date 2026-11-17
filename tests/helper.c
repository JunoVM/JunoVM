/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
/* Static helper run inside cells by the test suite. */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <grp.h>
#include <unistd.h>

static int cmd_forkcount(int n)
{
	pid_t kids[512];
	int ok = 0;
	for (int i = 0; i < n && i < 512; i++) {
		pid_t p = fork();
		if (p == 0) {
			pause();
			_exit(0);
		}
		if (p < 0) break;
		kids[ok++] = p;
	}
	printf("%d\n", ok);
	fflush(stdout);
	for (int i = 0; i < ok; i++) kill(kids[i], SIGKILL);
	while (wait(NULL) > 0) ;
	return 0;
}

static int cmd_openmany(void)
{
	int n = 0;
	while (open("/dev/null", O_RDONLY) >= 0) n++;
	printf("%d\n", n);
	return 0;
}

/* orphan a grandchild, let it die, then count zombies visible in /proc */
static int cmd_zombies(void)
{
	pid_t p = fork();
	if (p == 0) {
		if (fork() == 0) {
			usleep(200000);
			_exit(0);
		}
		_exit(0);
	}
	waitpid(p, NULL, 0);
	usleep(700000);
	DIR *d = opendir("/proc");
	struct dirent *e;
	int z = 0;
	while ((e = readdir(d))) {
		char path[300], buf[512];
		if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
		snprintf(path, sizeof path, "/proc/%s/stat", e->d_name);
		int fd = open(path, O_RDONLY);
		if (fd < 0) continue;
		ssize_t n = read(fd, buf, sizeof buf - 1);
		close(fd);
		if (n <= 0) continue;
		buf[n] = 0;
		char *rp = strrchr(buf, ')');
		if (rp && rp[2] == 'Z') z++;
	}
	printf("%d\n", z);
	return 0;
}

static int report(const char *what, long r)
{
	printf("%s %s\n", what, r < 0 ? strerror(errno) : "ok");
	return r < 0 ? 1 : 0;
}

static int server(int port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0 || listen(fd, 8) < 0) {
		perror("listen");
		exit(1);
	}
	return fd;
}

/* listen PORT: greet every client; echo PORT: send back everything received */
static int cmd_serve(int port, int echo)
{
	int fd = server(port);
	for (;;) {
		int c = accept(fd, NULL, NULL);
		if (c < 0) continue;
		if (!echo) {
			ssize_t w = write(c, "hello\n", 6);
			(void)w;
			close(c);
			continue;
		}
		size_t cap = 1 << 20, n = 0;
		char *b = malloc(cap);
		ssize_t k;
		while ((k = read(c, b + n, cap - n)) > 0) {
			n += k;
			if (n == cap) b = realloc(b, cap *= 2);
		}
		for (size_t o = 0; o < n; ) {
			k = write(c, b + o, n - o);
			if (k <= 0) break;
			o += k;
		}
		free(b);
		close(c);
	}
	return 0;
}

static int dial(const char *host, int port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) };
	inet_pton(AF_INET, host, &sa.sin_addr);
	if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
		printf("connect: %s\n", strerror(errno));
		exit(1);
	}
	return fd;
}

/* xfer HOST PORT IN OUT: send IN, half-close, store the reply in OUT */
static int cmd_xfer(char **a)
{
	int fd = dial(a[0], atoi(a[1]));
	int in = open(a[2], O_RDONLY), out = open(a[3], O_WRONLY | O_CREAT | O_TRUNC, 0600);
	char b[65536];
	ssize_t k;
	while ((k = read(in, b, sizeof b)) > 0)
		for (ssize_t o = 0; o < k; ) {
			ssize_t w = write(fd, b + o, k - o);
			if (w <= 0) {
				printf("xfer: write: %s\n", strerror(errno));
				return 1;
			}
			o += w;
		}
	shutdown(fd, SHUT_WR);
	size_t total = 0;
	while ((k = read(fd, b, sizeof b)) > 0) {
		if (write(out, b, k) < 0) return 1;
		total += k;
	}
	if (k < 0) {
		printf("xfer: read: %s\n", strerror(errno));
		return 1;
	}
	printf("xfer: %zu bytes back\n", total);
	return 0;
}

static int report_bool(const char *what, int ok)
{
	if (ok) printf("%s ok\n", what);
	else printf("%s FAIL %s\n", what, strerror(errno));
	return ok ? 0 : 1;
}

static int connect_with_timeout(int fd, struct sockaddr *sa, socklen_t l)
{
	fcntl(fd, F_SETFL, O_NONBLOCK);
	if (connect(fd, sa, l) == 0) return 0;
	if (errno != EINPROGRESS) return -1;
	struct pollfd p = { fd, POLLOUT, 0 };
	if (poll(&p, 1, 3000) <= 0) {
		errno = ETIMEDOUT;
		return -1;
	}
	int e = 0;
	socklen_t el = sizeof e;
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &el);
	if (e) {
		errno = e;
		return -1;
	}
	return 0;
}

static int cmd_tcp(const char *host, int port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) };
	inet_pton(AF_INET, host, &sa.sin_addr);
	return report_bool("tcp", connect_with_timeout(fd, (struct sockaddr *)&sa, sizeof sa) == 0);
}

static int cmd_gwconnect(int port)
{
	FILE *f = fopen("/proc/net/route", "r");
	char line[256], ifn[32];
	unsigned dst, gw = 0;
	while (f && fgets(line, sizeof line, f))
		if (sscanf(line, "%31s %x %x", ifn, &dst, &gw) == 3 && dst == 0 && gw) break;
	if (!gw) {
		printf("tcp FAIL no default route\n");
		return 1;
	}
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = gw };
	return report_bool("tcp", connect_with_timeout(fd, (struct sockaddr *)&sa, sizeof sa) == 0);
}

static int cmd_unix(const char *path, int abstract)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	socklen_t l;
	if (abstract) {
		strncpy(sa.sun_path + 1, path, sizeof sa.sun_path - 2);
		l = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(path);
	}
	else {
		strncpy(sa.sun_path, path, sizeof sa.sun_path - 1);
		l = sizeof sa;
	}
	return report_bool(abstract ? "abstract" : "unix", connect(fd, (struct sockaddr *)&sa, l) == 0);
}

static int cmd_unixreq(const char *path, const char *msg)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	strncpy(sa.sun_path, path, sizeof sa.sun_path - 1);
	if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) return report_bool("broker", 0);
	dprintf(fd, "%s\n", msg);
	char b[256];
	ssize_t n = read(fd, b, sizeof b - 1);
	if (n <= 0) {
		errno = EIO;
		return report_bool("broker", 0);
	}
	b[n] = 0;
	printf("%s", b);
	return 0;
}

static int cmd_caps(void)
{
	FILE *f = fopen("/proc/self/status", "r");
	char line[256], out[300] = "";
	while (f && fgets(line, sizeof line, f))
		if (!strncmp(line, "CapEff:", 7) || !strncmp(line, "NoNewPrivs:", 11) || !strncmp(line, "Uid:", 4)) {
			line[strcspn(line, "\n")] = 0;
			strcat(out, line);
			strcat(out, " | ");
		}
	printf("%s\n", out);
	return 0;
}

static int cmd_dropuid(int uid)
{
	if (setgroups(0, NULL) < 0) {
		printf("setgroups FAIL %s\n", strerror(errno));
		return 1;
	}
	if (setgid(uid) < 0) {
		printf("setgid FAIL %s\n", strerror(errno));
		return 1;
	}
	if (setuid(uid) < 0) {
		printf("setuid FAIL %s\n", strerror(errno));
		return 1;
	}
	printf("dropped uid=%d euid=%d\n", getuid(), geteuid());
	return 0;
}

static int cmd_kallsyms(void)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char line[512];
	long total = 0, nonzero = 0;
	if (!f) return report_bool("kallsyms", 0);
	while (fgets(line, sizeof line, f)) {
		unsigned long long a = strtoull(line, NULL, 16);
		total++;
		if (a) nonzero++;
	}
	printf("kallsyms %ld symbols, %ld with a non-zero address\n", total, nonzero);
	return nonzero ? 1 : 0;
}

static int cmd_ptrace(void)
{
	pid_t c = fork();
	if (c == 0) {
		pause();
		_exit(0);
	}
	long r = ptrace(PTRACE_ATTACH, c, 0, 0);
	int e = errno;
	kill(c, SIGKILL);
	waitpid(c, NULL, 0);
	errno = e;
	return report_bool("ptrace", r == 0);
}

static int cmd_writefile(const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return report_bool("write", 0);
	ssize_t w = write(fd, "x", 1);
	close(fd);
	return report_bool("write", w == 1);
}

static int proxy_dial(void)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(3128) };
	inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
	if (connect_with_timeout(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
		printf("proxy FAIL %s\n", strerror(errno));
		exit(1);
	}
	fcntl(fd, F_SETFL, 0);
	return fd;
}

/* reads the response head and prints its status, "closed" when the proxy hangs up */
static int proxy_status(int fd, int *code)
{
	char b[512];
	size_t n = 0;
	struct pollfd p = { fd, POLLIN, 0 };
	while (n < sizeof b - 1 && poll(&p, 1, 5000) > 0) {
		ssize_t k = read(fd, b + n, sizeof b - 1 - n);
		if (k <= 0) break;
		n += k;
		b[n] = 0;
		if (strstr(b, "\r\n\r\n")) break;
	}
	if (n < 12 || sscanf(b, "HTTP/1.%*d %d", code) != 1) {
		printf("status closed\n");
		return -1;
	}
	printf("status %d\n", *code);
	return 0;
}

static int cmd_connectproxy(const char *target)
{
	int fd = proxy_dial(), code = 0;
	dprintf(fd, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target);
	if (proxy_status(fd, &code) < 0 || code != 200) return 1;
	dprintf(fd, "ping through the proxy\n");
	shutdown(fd, SHUT_WR);	/* the echo server answers after our EOF: half-close must pass the proxy */
	char b[128];
	ssize_t k = read(fd, b, sizeof b - 1);
	if (k > 0) {
		b[k] = 0;
		printf("echo %s", b);
	}
	return 0;
}

static int cmd_rawproxy(const char *kind)
{
	int fd = proxy_dial(), code = 0;
	if (!strcmp(kind, "get")) dprintf(fd, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n");
	else if (!strcmp(kind, "junk")) {
		ssize_t w = write(fd, "\x01\x02\xff garbage\r\n\r\n", 15);
		(void)w;
	}
	else if (!strcmp(kind, "nullbyte")) {
		ssize_t w = write(fd, "CONNECT a\0b:443 HTTP/1.1\r\n\r\n", 27);
		(void)w;
	}
	else if (!strcmp(kind, "big")) {
		char a[1024];
		memset(a, 'A', sizeof a);
		for (int i = 0; i < 40; i++) if (write(fd, a, sizeof a) < 0) break;
	} else if (!strcmp(kind, "hugetarget")) {
		char a[2048];
		memset(a, 'a', sizeof a - 1);
		a[sizeof a - 1] = 0;
		dprintf(fd, "CONNECT %s:443 HTTP/1.1\r\n\r\n", a);
	}
	return proxy_status(fd, &code) < 0 ? 0 : 0;
}

static int cmd_ctlstatus(const char *path)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	strncpy(sa.sun_path, path, sizeof sa.sun_path - 1);
	if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) return report_bool("ctl", 0);
	unsigned char req[5] = { 1, 0, 0, 0, 1 };	/* length 1, op STATUS */
	if (write(fd, req, 5) != 5) return report_bool("ctl", 0);
	char b[512];
	ssize_t n = read(fd, b, sizeof b);
	if (n > 8) printf("ctl reply %zd bytes\n", n);
	else printf("ctl closed without a reply\n");
	return 0;
}

int main(int argc, char **argv)
{
	signal(SIGPIPE, SIG_IGN);
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc < 2) return 2;
	if (!strcmp(argv[1], "forkcount")) return cmd_forkcount(argc > 2 ? atoi(argv[2]) : 30);
	if (!strcmp(argv[1], "connectproxy") && argc > 2) return cmd_connectproxy(argv[2]);
	if (!strcmp(argv[1], "rawproxy") && argc > 2) return cmd_rawproxy(argv[2]);
	if (!strcmp(argv[1], "ctlstatus") && argc > 2) return cmd_ctlstatus(argv[2]);
	if (!strcmp(argv[1], "tcp") && argc > 3) return cmd_tcp(argv[2], atoi(argv[3]));
	if (!strcmp(argv[1], "gwconnect") && argc > 2) return cmd_gwconnect(atoi(argv[2]));
	if (!strcmp(argv[1], "unix") && argc > 2) return cmd_unix(argv[2], 0);
	if (!strcmp(argv[1], "abstract") && argc > 2) return cmd_unix(argv[2], 1);
	if (!strcmp(argv[1], "unixreq") && argc > 3) return cmd_unixreq(argv[2], argv[3]);
	if (!strcmp(argv[1], "caps")) return cmd_caps();
	if (!strcmp(argv[1], "dropuid") && argc > 2) return cmd_dropuid(atoi(argv[2]));
	if (!strcmp(argv[1], "kallsyms")) return cmd_kallsyms();
	if (!strcmp(argv[1], "ptrace")) return cmd_ptrace();
	if (!strcmp(argv[1], "writefile") && argc > 2) return cmd_writefile(argv[2]);
	if (!strcmp(argv[1], "readfile") && argc > 2) {
		int fd = open(argv[2], O_RDONLY);
		char b[64];
		return report_bool("read", fd >= 0 && read(fd, b, sizeof b) >= 0);
	}
	if (!strcmp(argv[1], "mknod") && argc > 2) return report_bool("mknod", mknod(argv[2], S_IFCHR | 0600, makedev(1, 3)) == 0);
	if (!strcmp(argv[1], "kmod")) return report_bool("init_module", syscall(SYS_init_module, NULL, 0, "") == 0);
	if (!strcmp(argv[1], "bpf")) return report_bool("bpf", syscall(SYS_bpf, 0, NULL, 0) >= 0 || errno != EPERM);
	if (!strcmp(argv[1], "raiselimit")) {
		struct rlimit r;
		getrlimit(RLIMIT_NOFILE, &r);
		r.rlim_cur = r.rlim_max = r.rlim_max + 1;
		return report_bool("setrlimit", setrlimit(RLIMIT_NOFILE, &r) == 0);
	}
	if (!strcmp(argv[1], "kill") && argc > 2) return report_bool("kill", kill(atoi(argv[2]), 0) == 0);
	if (!strcmp(argv[1], "listen") && argc > 2) return cmd_serve(atoi(argv[2]), 0);
	if (!strcmp(argv[1], "echo") && argc > 2) return cmd_serve(atoi(argv[2]), 1);
	if (!strcmp(argv[1], "xfer") && argc > 5) return cmd_xfer(argv + 2);
	if (!strcmp(argv[1], "connect") && argc > 3) {
		int fd = dial(argv[2], atoi(argv[3]));
		char b[256];
		ssize_t k = read(fd, b, sizeof b);
		if (k > 0) fwrite(b, 1, k, stdout);
		return 0;
	}
	if (!strcmp(argv[1], "segv")) {
		*(volatile int *)0 = 1;
		return 0;
	}
	if (!strcmp(argv[1], "openmany")) return cmd_openmany();
	if (!strcmp(argv[1], "zombies")) return cmd_zombies();
	if (!strcmp(argv[1], "userns")) return report("unshare-user", unshare(CLONE_NEWUSER));
	if (!strcmp(argv[1], "keyctl"))
		return report("keyctl", syscall(SYS_keyctl, 0 /* GET_KEYRING_ID */, -3, 0) >= 0 ||
			errno != EPERM ? 0 : -1);
	if (!strcmp(argv[1], "mount"))
		return report("mount", mount("tmpfs", "/tmp", "tmpfs", 0, NULL));
	if (!strcmp(argv[1], "mountany")) return report_bool("mount", mount("tmpfs", argc > 2 ? argv[2] : "/work", "tmpfs", 0, NULL) == 0);
	if (!strcmp(argv[1], "alloc")) {
		size_t mb = argc > 2 ? strtoul(argv[2], NULL, 0) : 64;
		for (size_t i = 0; i < mb; i++) {
			char *p = malloc(1 << 20);
			if (!p) {
				puts("alloc failed");
				return 3;
			}
			memset(p, 1, 1 << 20);
		}
		puts("alloc ok");
		return 0;
	}
	return 2;
}
