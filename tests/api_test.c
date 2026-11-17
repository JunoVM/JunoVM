/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
/* Drives the library API directly. One PASS|FAIL|SKIP line per test. */
#include "juno.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdatomic.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int pass_count, fail_count, skip_count;

static void report_result(const char *tag, const char *name, const char *fmt, ...)
{
	va_list ap;
	char buf[1024];
	va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	for (char *p = buf; *p; p++)
		if (*p == '\n') *p = '|';
	printf("%s %s - %s\n", tag, name, buf);
}
#define PASS(n, ...) do { pass_count++; report_result("PASS", n, __VA_ARGS__); } while (0)
#define FAIL(n, ...) do { fail_count++; report_result("FAIL", n, __VA_ARGS__); } while (0)
#define SKIP(n, ...) do { skip_count++; report_result("SKIP", n, __VA_ARGS__); } while (0)
#define CHECK(n, cond, ...) do { if (cond) PASS(n, __VA_ARGS__); else FAIL(n, __VA_ARGS__); } while (0)

static uint64_t now_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000ull + t.tv_nsec / 1000000;
}

static int is_readable(int fd, int ms)
{
	struct pollfd p = { fd, POLLIN, 0 };
	return poll(&p, 1, ms) > 0 && (p.revents & POLLIN);
}

static juno_spec *make_spec(char *const argv[])
{
	juno_spec *s = juno_spec_new();
	if (s && juno_spec_set_argv(s, argv)) {
		juno_spec_free(s);
		return NULL;
	}
	return s;
}

/* Start spec with stdout captured; returns wait status or -1. */
static int run_capture(juno_spec *s, char *out, size_t len, int *started)
{
	int p[2], st = -1;
	juno_cell *c;
	size_t n = 0;
	out[0] = 0;
	if (pipe(p) < 0) return -1;
	juno_spec_set_stdio(s, -1, p[1], -1);
	int r = juno_start(s, &c);
	close(p[1]);
	if (started) *started = (r == 0);
	if (r == 0) {
		ssize_t k;
		while (n + 1 < len && (k = read(p[0], out + n, len - n - 1)) > 0) n += k;
		out[n] = 0;
		juno_cell_wait(c, &st, -1);
		juno_cell_free(c);
	}
	close(p[0]);
	return st;
}

static void t_backend(void)
{
	char *av[] = { "true", NULL };
	juno_spec *s = make_spec(av);
	juno_cell *c = NULL;
	juno_spec_set_backend(s, "qemu");
	int r = juno_start(s, &c);
	CHECK("api-backend-qemu-fails", r < 0 && !c && strstr(juno_error(), "qemu"),
	      "r=%d error='%s'", r, juno_error());
	juno_spec_set_backend(s, "ns");
	r = juno_start(s, &c);
	int st = -1;
	if (r == 0) {
		juno_cell_wait(c, &st, -1);
		juno_cell_free(c);
	}
	CHECK("api-backend-ns-starts", r == 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0,
	      "r=%d status=%d", r, st);
	juno_spec_free(s);
}

static void t_args(void)
{
	juno_spec *s = juno_spec_new();
	int a = juno_spec_pass_fd(s, 0, 1), b = juno_spec_add_landlock(s, "/", 0);
	int c = juno_spec_set_root(s, JUNO_ROOT_DIR, NULL), d = juno_spec_set_limit(s, 99, 1);
	int e = juno_spec_set_net(s, 77, NULL), f = juno_spec_keep_cap(s, 64);
	CHECK("api-invalid-args", a == -EINVAL && b == -EINVAL && c == -EINVAL && d == -EINVAL &&
	      e == -EINVAL && f == -EINVAL, "pass_fd(<3)=%d landlock(0)=%d root(dir,NULL)=%d limit(99)=%d net(77)=%d cap(64)=%d",
	      a, b, c, d, e, f);
	CHECK("api-cap-names", juno_cap_from_name("sys_admin") == 21 && juno_cap_from_name("CAP_NET_RAW") == 13 &&
	      juno_cap_from_name("12") == 12 && juno_cap_from_name("bogus") < 0,
	      "sys_admin=%d CAP_NET_RAW=%d 12=%d bogus=%d", juno_cap_from_name("sys_admin"),
	      juno_cap_from_name("CAP_NET_RAW"), juno_cap_from_name("12"), juno_cap_from_name("bogus"));
	juno_spec_free(s);
}

static void t_probe(void)
{
	char rep[2048];
	int r = juno_probe("ns", rep, sizeof rep);
	int bad = juno_probe("qemu", rep, sizeof rep);
	juno_probe("ns", rep, sizeof rep);
	CHECK("api-probe", r == 0 && strstr(rep, "userns: yes") && bad < 0, "ns=%d qemu=%d", r, bad);
}

static void t_cwd_env_status(void)
{
	char out[256];
	int started;
	char *av[] = { "sh", "-c", "pwd; echo $K; exit 9", NULL };
	juno_spec *s = make_spec(av);
	juno_spec_set_cwd(s, "/tmp");
	juno_spec_set_env(s, "K", "v1");
	juno_spec_set_env(s, "K", "v2");
	int st = run_capture(s, out, sizeof out, &started);
	CHECK("api-cwd-env-status", started && !strcmp(out, "/tmp\nv2\n") && WIFEXITED(st) && WEXITSTATUS(st) == 9,
	      "out='%s' status=%d", out, st);
	juno_spec_free(s);
}

static void t_fd_polling_kill(void)
{
	char *av[] = { "sleep", "30", NULL };
	juno_spec *s = make_spec(av);
	juno_cell *c;
	int r = juno_start(s, &c), st = -1;
	juno_spec_free(s);
	if (r) {
		FAIL("api-cell-fd-poll", "start: %s", juno_error());
		return;
	}
	int fd = juno_cell_fd(c);
	int before = is_readable(fd, 200);
	int w = juno_cell_wait(c, &st, 100);
	int k = juno_cell_kill(c, SIGKILL);
	uint64_t t0 = now_ms();
	int after = is_readable(fd, 3000);
	int w2 = juno_cell_wait(c, &st, 1000);
	CHECK("api-cell-fd-poll", fd >= 0 && !before && w == -ETIMEDOUT && k == 0 && after && w2 == 0,
	      "readable before=%d wait(100ms)=%d kill=%d readable after=%d (%llums) wait=%d",
	      before, w, k, after, (unsigned long long)(now_ms() - t0), w2);
	CHECK("api-kill-sigkill-status", WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL, "status=%d", st);
	int again = juno_cell_kill(c, SIGTERM);
	CHECK("api-kill-after-exit", again == -ESRCH, "kill on finished cell = %d", again);
	juno_cell_free(c);
}

static void t_sigterm(void)
{
	char *av[] = { "sleep", "30", NULL };
	juno_spec *s = make_spec(av);
	juno_cell *c;
	int st = -1;
	if (juno_start(s, &c)) {
		FAIL("api-sigterm-forwarded", "start: %s", juno_error());
		juno_spec_free(s);
		return;
	}
	juno_cell_kill(c, SIGTERM);
	int w = juno_cell_wait(c, &st, 3000);
	CHECK("api-sigterm-forwarded", w == 0 && WIFEXITED(st) && WEXITSTATUS(st) == 128 + SIGTERM,
	      "tiny init forwarded SIGTERM: wait=%d status=%d", w, st);
	juno_cell_free(c);

	/* negative: a payload that is pid 1 without a handler ignores SIGTERM */
	juno_spec_set_init(s, JUNO_INIT_NONE);
	if (juno_start(s, &c)) {
		FAIL("api-sigterm-ignored-by-pid1", "start: %s", juno_error());
		juno_spec_free(s);
		return;
	}
	usleep(200000);
	juno_cell_kill(c, SIGTERM);
	w = juno_cell_wait(c, &st, 600);
	int still = (w == -ETIMEDOUT);
	juno_cell_kill(c, SIGKILL);
	juno_cell_wait(c, &st, 3000);
	CHECK("api-sigterm-ignored-by-pid1", still, "init none: wait after SIGTERM = %d (expect timeout)", w);
	juno_cell_free(c);
	juno_spec_free(s);
}

static void t_timeout(void)
{
	char *av[] = { "sleep", "30", NULL };
	juno_spec *s = make_spec(av);
	juno_cell *c;
	int st = -1;
	juno_spec_set_limit(s, JUNO_LIMIT_TIMEOUT_MS, 300);
	uint64_t t0 = now_ms();
	if (juno_start(s, &c)) {
		FAIL("api-timeout-limit", "start: %s", juno_error());
		juno_spec_free(s);
		return;
	}
	int w = juno_cell_wait(c, &st, -1);
	uint64_t el = now_ms() - t0;
	CHECK("api-timeout-limit", w == 0 && juno_cell_timed_out(c) && WIFSIGNALED(st) && el < 5000,
	      "wait=%d timed_out=%d status=%d after %llums", w, juno_cell_timed_out(c), st, (unsigned long long)el);
	juno_cell_free(c);
	char *av2[] = { "true", NULL };
	juno_spec_set_argv(s, av2);
	juno_start(s, &c);
	juno_cell_wait(c, &st, -1);
	CHECK("api-timeout-not-hit", !juno_cell_timed_out(c) && WIFEXITED(st), "fast payload: timed_out=%d status=%d",
	      juno_cell_timed_out(c), st);
	juno_cell_free(c);
	juno_spec_free(s);
}

static int has_fd(const char *list, int fd)
{
	char pat[24], buf[600];
	snprintf(pat, sizeof pat, " %d ", fd);
	snprintf(buf, sizeof buf, " %s", list);
	return strstr(buf, pat) != NULL;
}

static void t_pass_fd(void)
{
	/* extra is a caller fd that is not passed; the pipes land on numbers that
	 * collide with the requested cell fd (7) to exercise the remapping */
	int extra = fcntl(open("/etc/hostname", O_RDONLY), F_DUPFD, 40);
	int pa[2], pb[2];
	char out[512], got[64] = "";
	int started;
	if (extra < 0 || pipe(pa) < 0 || pipe(pb) < 0) {
		FAIL("api-pass-fd", "setup: %s", strerror(errno));
		return;
	}
	char *av[] = { "sh", "-c", "echo viafd >&7; ls /proc/self/fd | tr '\\n' ' '", NULL };
	juno_spec *s = make_spec(av);
	int r = juno_spec_pass_fd(s, pa[1], 7);
	run_capture(s, out, sizeof out, &started);
	close(pa[1]);
	ssize_t n = read(pa[0], got, sizeof got - 1);
	got[n > 0 ? n : 0] = 0;
	CHECK("api-pass-fd", r == 0 && started && !strcmp(got, "viafd\n") && has_fd(out, 7),
	      "host fd %d written from cell fd 7: got '%.20s'; cell fds [%s]", pa[1], got, out);
	CHECK("api-caller-fd-absent", started && !has_fd(out, extra) && !has_fd(out, pa[0]) && !has_fd(out, pb[0]),
	      "caller fds %d,%d,%d not in cell fds [%s]", extra, pa[0], pb[0], out);
	juno_spec_free(s);

	/* negative: without pass_fd there is no fd 7 and the write fails */
	char *av2[] = { "sh", "-c", "{ echo viafd >&7; } 2>/dev/null; ls /proc/self/fd | tr '\\n' ' '", NULL };
	juno_spec *s2 = make_spec(av2);
	run_capture(s2, out, sizeof out, &started);
	CHECK("api-pass-fd-absent-without", started && !has_fd(out, 7), "no pass_fd: cell fds [%s]", out);
	juno_spec_free(s2);
	close(pa[0]); close(pb[0]); close(pb[1]); close(extra);
}

static void t_start_error(void)
{
	char *av[] = { "true", NULL };
	juno_spec *s = make_spec(av);
	juno_cell *c = NULL;
	juno_spec_add_mount(s, JUNO_MOUNT_BIND, "/nonexistent/abc", "/x", 0);
	int r = juno_start(s, &c);
	CHECK("api-start-error-step", r < 0 && !c && strstr(juno_error(), "mount bind") && strstr(juno_error(), "/nonexistent/abc"),
	      "r=%d error='%s'", r, juno_error());
	juno_spec_free(s);
}

static void t_tmpdir_clean(void)
{
	/* a failed or finished start must not leave stage directories behind */
	int before = 0, after = 0;
	FILE *f = popen("ls -A \"$TMPDIR\" | wc -l", "r");
	if (f) {
		if (fscanf(f, "%d", &before) != 1) before = 0;
		pclose(f);
	}
	char *av[] = { "true", NULL };
	for (int i = 0; i < 3; i++) {
		juno_spec *s = make_spec(av);
		juno_cell *c;
		if (i == 2) juno_spec_add_mount(s, JUNO_MOUNT_BIND, "/nonexistent", "/x", 0);
		if (!juno_start(s, &c)) {
			int st;
			juno_cell_wait(c, &st, -1);
			juno_cell_free(c);
		}
		juno_spec_free(s);
	}
	f = popen("ls -A \"$TMPDIR\" | wc -l", "r");
	if (f) {
		if (fscanf(f, "%d", &after) != 1) after = -1;
		pclose(f);
	}
	CHECK("api-stage-dir-cleanup", after == before && after == 0, "entries in the private TMPDIR before=%d after=%d (finished and failed starts)", before, after);
}

static int exec_capture(juno_cell *c, char *const argv[], char *out, size_t len, int *st)
{
	int p[2], save, r;
	size_t n = 0;
	ssize_t k;
	out[0] = 0;
	if (pipe(p) < 0) return -errno;
	fflush(stdout);
	save = dup(1);
	dup2(p[1], 1);
	r = juno_cell_exec(c, argv, st);
	dup2(save, 1);
	close(save);
	close(p[1]);
	while (n + 1 < len && (k = read(p[0], out + n, len - n - 1)) > 0) n += k;
	out[n] = 0;
	close(p[0]);
	return r;
}

static int slurp(const char *path, char *buf, size_t len)
{
	FILE *f = fopen(path, "r");
	size_t n;
	if (!f) return -1;
	n = fread(buf, 1, len - 1, f);
	buf[n] = 0;
	fclose(f);
	return 0;
}

static void t_spec_roundtrip(void)
{
	char a[4096], b[4096], tmp1[] = "/tmp/juno-spec1-XXXXXX", tmp2[] = "/tmp/juno-spec2-XXXXXX", bad[] = "/tmp/juno-spec3-XXXXXX";
	juno_spec *s = juno_spec_new(), *l = NULL, *l2 = NULL;
	static const char *const kv[][2] = {
		{ "root", "overlay:/tmp/up" }, { "layer", "/tmp/l1" }, { "layer", "/tmp/l2" }, { "bind", "/a:/b" },
		{ "bind-ro", "/c:/d" }, { "tmpfs", "/scratch" }, { "net", "nat:lan" }, { "egress-deny", "10.9.0.0/16" }, { "egress-allow", "10.9.1.2" }, { "egress-proxy-allow", "api.example.com:443" },
		{ "egress-proxy-allow", "*.example.org:8443" }, { "idmap", "full" }, { "user", "100:100" },
		{ "net", "shared:n7" }, { "hostname", "box" },
		{ "env", "A=1" }, { "env", "B=two words" }, { "cwd", "/tmp" }, { "mem", "1048576" }, { "pids", "20" },
		{ "nofile", "64" }, { "cpu-weight", "50" }, { "timeout", "2.5" }, { "seccomp", "strict" },
		{ "keep-cap", "net_raw" }, { "keep-cap", "21" }, { "landlock-ro", "/usr" }, { "landlock-rw", "/tmp" },
		{ "init", "none" }, { "nesting", "allow" }, { "publish", "8080:80" }, { "publish", "127.0.0.2:81:82" },
		{ "restart", "on-failure" }, { "max-restarts", "4" },
		{ "argv", "sh -c 'echo \"a b\"; exit 3' 'it'\\''s'" },
	};
	int r = 0, fd1 = mkstemp(tmp1), fd2 = mkstemp(tmp2), fd3 = mkstemp(bad);
	for (size_t i = 0; i < sizeof kv / sizeof *kv && !r; i++) r = juno_spec_set_option(s, kv[i][0], kv[i][1]);
	/* values with a newline, a backslash and edge spaces survive the text form unchanged */
	r |= juno_spec_set_env(s, "NL", "a\nb\\c  \n bind = /home:/h ");
	int rs = juno_spec_save(s, tmp1);
	int rl = juno_spec_load(tmp1, &l);
	int rs2 = rl ? -1 : juno_spec_save(l, tmp2);
	rl = rl ?: juno_spec_load(tmp2, &l2);
	int same = !slurp(tmp1, a, sizeof a) && !slurp(tmp2, b, sizeof b) && !strcmp(a, b);
	CHECK("api-spec-roundtrip", r == 0 && rs == 0 && rs2 == 0 && rl == 0 && same && strstr(a, "argv = sh -c 'echo \"a b\"; exit 3' 'it'\\\\''s'") && !strstr(a, "\nbind = /home:/h"),
	      "set=%d save=%d load/save/load=%d identical=%d (%zu bytes)", r, rs, rl, same, strlen(a));
	juno_spec_free(s); juno_spec_free(l); juno_spec_free(l2);

	FILE *f = fdopen(fd3, "w");
	fputs("# header\nroot = host-ro\nnosuchkey = 1\n", f);
	fclose(f);
	juno_spec *e = NULL;
	r = juno_spec_load(bad, &e);
	CHECK("api-spec-error-line", r < 0 && !e && strstr(juno_error(), bad) && strstr(juno_error(), ":3:") && strstr(juno_error(), "nosuchkey"),
	      "r=%d '%s'", r, juno_error());
	f = fopen(bad, "w");
	fputs("root = host-ro\nmem = 12abc\n", f);
	fclose(f);
	r = juno_spec_load(bad, &e);
	CHECK("api-spec-bad-value", r < 0 && strstr(juno_error(), ":2:") && strstr(juno_error(), "mem"), "'%s'", juno_error());
	juno_spec *s2 = juno_spec_new();
	int a1 = juno_spec_set_option(s2, "argv", "'unterminated"), a2 = juno_spec_set_option(s2, "publish", "0:80"),
	    a3 = juno_spec_set_option(s2, "net", "shared:bad name");
	CHECK("api-spec-bad-options", a1 < 0 && a2 < 0 && a3 < 0, "argv=%d publish=%d net=%d", a1, a2, a3);
	juno_spec_free(s2);
	unlink(tmp1); unlink(tmp2); unlink(bad);
	close(fd1); close(fd2);
}

static void t_timeout_poll_only(void)
{
	char *av[] = { "sleep", "30", NULL };
	juno_spec *s = make_spec(av);
	juno_cell *c;
	int st = -1;
	juno_spec_set_limit(s, JUNO_LIMIT_TIMEOUT_MS, 400);
	if (juno_start(s, &c)) {
		FAIL("api-timeout-poll-only", "start: %s", juno_error());
		juno_spec_free(s);
		return;
	}
	uint64_t t0 = now_ms();
	int early = is_readable(juno_cell_fd(c), 150);
	int late = is_readable(juno_cell_fd(c), 3000);
	uint64_t el = now_ms() - t0;
	int w = juno_cell_wait(c, &st, 1000);
	CHECK("api-timeout-poll-only", !early && late && w == 0 && juno_cell_timed_out(c) && el < 3000,
	      "never called wait: fd readable after %llums (early=%d), then wait=%d timed_out=%d status=%d",
	      (unsigned long long)el, early, w, juno_cell_timed_out(c), st);
	juno_cell_free(c);
	juno_spec_free(s);
}

static void t_local_exec(void)
{
	char out[256];
	char *av[] = { "sleep", "30", NULL };
	juno_spec *s = make_spec(av);
	juno_cell *c;
	int st = -1;
	if (juno_start(s, &c)) {
		FAIL("api-exec-local", "start: %s", juno_error());
		juno_spec_free(s);
		return;
	}
	char *ex[] = { "sh", "-c", "echo $$; grep NoNewPrivs /proc/self/status; exit 4", NULL };
	int r = exec_capture(c, ex, out, sizeof out, &st);
	int pid = atoi(out);
	CHECK("api-exec-local", r == 0 && pid > 0 && pid < 20 && strstr(out, "NoNewPrivs:\t1") && WIFEXITED(st) && WEXITSTATUS(st) == 4,
	      "r=%d status=%d out='%s'", r, st, out);
	char *bad[] = { "/nonexistent/prog", NULL };
	r = exec_capture(c, bad, out, sizeof out, &st);
	CHECK("api-exec-bad-command", r < 0 && strstr(juno_error(), "/nonexistent/prog"), "r=%d '%s'", r, juno_error());
	juno_cell_kill(c, SIGKILL);
	juno_cell_wait(c, &st, 3000);
	r = exec_capture(c, ex, out, sizeof out, &st);
	CHECK("api-exec-after-exit", r == -ESRCH, "exec on a finished cell = %d", r);
	juno_cell_free(c);
	juno_spec_free(s);
}

static void t_named_api(void)
{
	char out[256];
	char *av[] = { "sleep", "60", NULL };
	juno_spec *s = make_spec(av);
	juno_cell *c = NULL;
	int st = -1;
	int r = juno_run_named(s, "apicell", 1);
	int dup = juno_run_named(s, "apicell", 1);
	int none = juno_cell_open("nosuchapicell", &c);
	CHECK("api-named-start-and-dup", r == 0 && dup == -EEXIST && none < 0, "start=%d duplicate=%d open-missing=%d", r, dup, none);
	if (juno_cell_open("apicell", &c)) {
		FAIL("api-named-exec", "open: %s", juno_error());
		juno_spec_free(s);
		return;
	}
	char *ex[] = { "sh", "-c", "echo in-$$; exit 6", NULL };
	r = exec_capture(c, ex, out, sizeof out, &st);
	CHECK("api-named-exec", r == 0 && !strncmp(out, "in-", 3) && atoi(out + 3) < 20 && WIFEXITED(st) && WEXITSTATUS(st) == 6,
	      "r=%d status=%d out='%s'", r, st, out);
	int w0 = juno_cell_wait(c, &st, 100);
	int k = juno_cell_kill(c, SIGKILL);
	int w1 = juno_cell_wait(c, &st, 5000);
	CHECK("api-named-kill-wait", w0 == -ETIMEDOUT && k == 0 && w1 == 0 && WIFEXITED(st) && WEXITSTATUS(st) == 137,
	      "wait(100ms)=%d kill=%d wait=%d status=%d", w0, k, w1, st);
	juno_cell_free(c);
	juno_cell_stop("apicell", 1);
	juno_spec_free(s);
}

/* --- seccomp filter, run through a tiny classic-BPF interpreter --- */
int ns_seccomp_build(int profile, int nesting, int compat32, struct sock_filter *out, int *n);

static unsigned bpf_run(const struct sock_filter *f, int n, const struct seccomp_data *d)
{
	unsigned a = 0;
	int pc = 0;
	while (pc >= 0 && pc < n) {
		const struct sock_filter *i = &f[pc];
		switch (i->code) {
		case BPF_LD | BPF_W | BPF_ABS: memcpy(&a, (const char *)d + i->k, 4); pc++; break;
		case BPF_JMP | BPF_JEQ | BPF_K: pc += 1 + (a == i->k ? i->jt : i->jf); break;
		case BPF_JMP | BPF_JSET | BPF_K: pc += 1 + ((a & i->k) ? i->jt : i->jf); break;
		case BPF_JMP | BPF_JA: pc += 1 + i->k; break;
		case BPF_RET | BPF_K: return i->k;
		default: return 0xdeadbeef;
		}
	}
	return 0xdeadbeef;
}

#define A_ALLOW SECCOMP_RET_ALLOW
#define A_EPERM (SECCOMP_RET_ERRNO | EPERM)
#define A_NOSYS (SECCOMP_RET_ERRNO | ENOSYS)
#define A_KILL SECCOMP_RET_KILL_PROCESS

struct bcase {
	unsigned arch;
	int nr;
	unsigned long long a0;
	unsigned want_default, want_strict;
	int compat, nesting;
	const char *what;
};

static void t_seccomp_filter(void)
{
#ifdef __x86_64__
	enum { A64 = AUDIT_ARCH_X86_64, I386 = AUDIT_ARCH_I386, AA64 = 0xC00000B7 };
	static const struct bcase cases[] = {
		{ A64, 0, 0, A_ALLOW, A_ALLOW, 0, 0, "x86_64 read" },
		{ A64, 321, 0, A_EPERM, A_EPERM, 0, 0, "x86_64 bpf" },
		{ A64, 165, 0, A_ALLOW, A_EPERM, 0, 0, "x86_64 mount" },
		{ A64, 101, 0, A_ALLOW, A_EPERM, 0, 0, "x86_64 ptrace" },
		{ A64, 435, 0, A_NOSYS, A_NOSYS, 0, 0, "x86_64 clone3" },
		{ A64, 435, 0, A_ALLOW, A_ALLOW, 0, 1, "x86_64 clone3 with nesting" },
		{ A64, 272, 0x10000000, A_EPERM, A_EPERM, 0, 0, "x86_64 unshare(NEWUSER)" },
		{ A64, 272, 0x00020000, A_ALLOW, A_EPERM, 0, 0, "x86_64 unshare(NEWNS)" },
		{ A64, 272, 0x10000000, A_ALLOW, A_EPERM, 0, 1, "x86_64 unshare(NEWUSER) with nesting" },
		{ A64, 56, 0x10000000, A_EPERM, A_EPERM, 0, 0, "x86_64 clone(NEWUSER)" },
		{ A64, 0x40000000, 0, A_KILL, A_KILL, 0, 0, "x32 read" },
		{ A64, 0x40000000 | 321, 0, A_KILL, A_KILL, 1, 0, "x32 bpf with compat32" },
		{ AA64, 0, 0, A_KILL, A_KILL, 0, 0, "aarch64 read" },
		{ I386, 3, 0, A_KILL, A_KILL, 0, 0, "i386 read, native only" },
		{ I386, 3, 0, A_ALLOW, A_ALLOW, 1, 0, "i386 read" },
		{ I386, 357, 0, A_EPERM, A_EPERM, 1, 0, "i386 bpf" },
		{ I386, 21, 0, A_ALLOW, A_EPERM, 1, 0, "i386 mount" },
		{ I386, 26, 0, A_ALLOW, A_EPERM, 1, 0, "i386 ptrace" },
		{ I386, 310, 0x10000000, A_EPERM, A_EPERM, 1, 0, "i386 unshare(NEWUSER)" },
		{ I386, 120, 0x10000000, A_EPERM, A_EPERM, 1, 0, "i386 clone(NEWUSER)" },
		{ I386, 310, 0x10000000, A_ALLOW, A_EPERM, 1, 1, "i386 unshare(NEWUSER) with nesting" },
		{ A64, 321, 0, A_EPERM, A_EPERM, 1, 0, "x86_64 bpf with compat32" },
		{ A64, 0, 0, A_ALLOW, A_ALLOW, 1, 0, "x86_64 read with compat32" },
		{ A64, 425, 0, A_EPERM, A_EPERM, 0, 0, "x86_64 io_uring_setup" },
		{ A64, 426, 0, A_EPERM, A_EPERM, 0, 0, "x86_64 io_uring_enter" },
		{ A64, 427, 0, A_EPERM, A_EPERM, 0, 0, "x86_64 io_uring_register" },
		{ A64, 312, 0, A_EPERM, A_EPERM, 0, 0, "x86_64 kcmp" },
		{ A64, 303, 0, A_EPERM, A_EPERM, 0, 0, "x86_64 name_to_handle_at" },
		{ A64, 438, 0, A_EPERM, A_EPERM, 0, 0, "x86_64 pidfd_getfd" },
		{ A64, 440, 0, A_EPERM, A_EPERM, 0, 0, "x86_64 process_madvise" },
		{ A64, 279, 0, A_EPERM, A_EPERM, 0, 0, "x86_64 move_pages" },
		{ A64, 237, 0, A_EPERM, A_EPERM, 0, 0, "x86_64 mbind" },
		{ A64, 256, 0, A_EPERM, A_EPERM, 0, 0, "x86_64 migrate_pages" },
		{ A64, 238, 0, A_EPERM, A_EPERM, 0, 0, "x86_64 set_mempolicy" },
		{ A64, 153, 0, A_EPERM, A_EPERM, 0, 0, "x86_64 vhangup" },
		{ A64, 103, 0, A_EPERM, A_EPERM, 0, 0, "x86_64 syslog" },
		{ A64, 180, 0, A_EPERM, A_EPERM, 0, 0, "x86_64 nfsservctl" },
		{ A64, 134, 0, A_EPERM, A_EPERM, 0, 0, "x86_64 uselib" },
		{ A64, 136, 0, A_EPERM, A_EPERM, 0, 0, "x86_64 ustat" },
		{ A64, 139, 0, A_EPERM, A_EPERM, 0, 0, "x86_64 sysfs" },
		{ A64, 156, 0, A_EPERM, A_EPERM, 0, 0, "x86_64 _sysctl" },
		{ A64, 300, 0, A_EPERM, A_EPERM, 0, 0, "x86_64 fanotify_init" },
		{ A64, 135, 0, A_ALLOW, A_ALLOW, 0, 0, "x86_64 personality(0)" },
		{ A64, 135, 0xffffffffu, A_ALLOW, A_ALLOW, 0, 0, "x86_64 personality(query)" },
		{ A64, 135, 8, A_EPERM, A_EPERM, 0, 0, "x86_64 personality(8)" },
		{ A64, 135, 0x0400000, A_EPERM, A_EPERM, 0, 1, "x86_64 personality(ADDR_NO_RANDOMIZE) with nesting" },
		{ A64, 272, 0x00020000, A_ALLOW, A_EPERM, 0, 0, "x86_64 unshare(NEWNS) strict" },
		{ A64, 56, 0x00020000, A_ALLOW, A_EPERM, 0, 0, "x86_64 clone(NEWNS) strict" },
		{ A64, 56, 0x02000000, A_ALLOW, A_EPERM, 0, 0, "x86_64 clone(NEWCGROUP) strict" },
		{ A64, 56, 0x40000000, A_ALLOW, A_EPERM, 0, 0, "x86_64 clone(NEWNET) strict" },
		{ A64, 56, 0x00000011, A_ALLOW, A_ALLOW, 0, 0, "x86_64 clone(SIGCHLD) strict" },
		{ I386, 425, 0, A_EPERM, A_EPERM, 1, 0, "i386 io_uring_setup" },
		{ I386, 349, 0, A_EPERM, A_EPERM, 1, 0, "i386 kcmp" },
		{ I386, 435, 0, A_NOSYS, A_NOSYS, 1, 0, "i386 clone3" },
		{ I386, 435, 0, A_ALLOW, A_ALLOW, 1, 1, "i386 clone3 with nesting" },
		{ I386, 103, 0, A_EPERM, A_EPERM, 1, 0, "i386 syslog" },
		{ I386, 136, 6, A_EPERM, A_EPERM, 1, 0, "i386 personality(6)" },
		{ I386, 136, 0, A_ALLOW, A_ALLOW, 1, 0, "i386 personality(0)" },
		{ I386, 310, 0x00020000, A_ALLOW, A_EPERM, 1, 0, "i386 unshare(NEWNS) strict" },
		{ I386, 120, 0x40000000, A_ALLOW, A_EPERM, 1, 0, "i386 clone(NEWNET) strict" },
	};
	int bad = 0, total = 0;
	char first[200] = "";
	for (int prof = JUNO_SECCOMP_DEFAULT; prof <= JUNO_SECCOMP_STRICT; prof++)
		for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
			const struct bcase *c = &cases[i];
			struct sock_filter f[256];
			int n = 0;
			if (ns_seccomp_build(prof, c->nesting, c->compat, f, &n)) {
				bad++;
				continue;
			}
			struct seccomp_data d = { .nr = c->nr, .arch = c->arch, .args = { c->a0 } };
			unsigned got = bpf_run(f, n, &d), want = prof == JUNO_SECCOMP_STRICT ? c->want_strict : c->want_default;
			total++;
			if (got != want) {
				if (!first[0]) snprintf(first, sizeof first, "%s (%s): got %#x want %#x", c->what,
					prof == JUNO_SECCOMP_STRICT ? "strict" : "default", got, want);
				bad++;
			}
		}
	CHECK("api-seccomp-filter-interpreted", bad == 0, "%d (arch, nr, profile) cases through a BPF interpreter, %d wrong %s", total, bad, first);
	struct sock_filter f[256];
	int n1 = 0, n2 = 0;
	ns_seccomp_build(JUNO_SECCOMP_STRICT, 0, 0, f, &n1);
	ns_seccomp_build(JUNO_SECCOMP_STRICT, 0, 1, f, &n2);
	CHECK("api-seccomp-compat32-opt-in", n2 > n1, "native-only filter %d instructions, with compat32 %d", n1, n2);
#else
	SKIP("api-seccomp-filter-interpreted", "x86_64 only");
#endif
}

/* --- concurrent starts --- */
static atomic_int g_ok, g_stop_alloc;

static void *start_worker(void *arg)
{
	(void)arg;
	for (int i = 0; i < 10; i++) {
		char *av[] = { "true", NULL };
		juno_spec *s = make_spec(av);
		juno_cell *c;
		int st = -1;
		if (s && juno_start(s, &c) == 0) {
			if (juno_cell_wait(c, &st, 10000) == 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0) g_ok++;
			juno_cell_free(c);
		}
		juno_spec_free(s);
	}
	return NULL;
}

static void *alloc_worker(void *arg)
{
	(void)arg;
	while (!g_stop_alloc) {
		void *p[64];
		for (int i = 0; i < 64; i++) p[i] = malloc(16 + i * 40);
		for (int i = 0; i < 64; i++) free(p[i]);
	}
	return NULL;
}

static void t_threads(void)
{
	pthread_t th[4], al;
	pthread_create(&al, NULL, alloc_worker, NULL);
	for (int i = 0; i < 4; i++) pthread_create(&th[i], NULL, start_worker, NULL);
	for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
	g_stop_alloc = 1;
	pthread_join(al, NULL);
	CHECK("api-start-from-threads", g_ok == 40, "%d of 40 cells started and exited 0 (4 threads x 10, malloc/free loop beside them)", (int)g_ok);
}

static void t_timeout_oob(void)
{
	char *av[] = { "sh", "-c", "exit 124", NULL };
	juno_spec *s = make_spec(av);
	juno_cell *c;
	int st = -1;
	juno_spec_set_limit(s, JUNO_LIMIT_TIMEOUT_MS, 60000);
	if (juno_start(s, &c)) {
		FAIL("api-timeout-exit124-not-misread", "start: %s", juno_error());
		juno_spec_free(s);
		return;
	}
	juno_cell_wait(c, &st, 10000);
	CHECK("api-timeout-exit124-not-misread", WIFEXITED(st) && WEXITSTATUS(st) == 124 && !juno_cell_timed_out(c),
	      "payload exiting 124 by itself: status=%d timed_out=%d", st, juno_cell_timed_out(c));
	juno_cell_free(c);
	char *av2[] = { "sh", "-c", "sleep 30; exit 124", NULL };
	juno_spec_set_argv(s, av2);
	juno_spec_set_limit(s, JUNO_LIMIT_TIMEOUT_MS, 300);
	if (juno_start(s, &c)) {
		FAIL("api-timeout-reported-by-init", "start: %s", juno_error());
		juno_spec_free(s);
		return;
	}
	int ready = is_readable(juno_cell_fd(c), 3000);
	juno_cell_wait(c, &st, 3000);
	CHECK("api-timeout-reported-by-init", ready && juno_cell_timed_out(c) && WIFEXITED(st) && WEXITSTATUS(st) == 137,
	      "real timeout seen only through the init's status byte: timed_out=%d status=%d", juno_cell_timed_out(c), st);
	juno_cell_free(c);
	juno_spec_free(s);
}

static void t_compat32_spec(void)
{
	juno_spec *s = juno_spec_new();
	int r = juno_spec_set_option(s, "compat32", "yes"), r2 = juno_spec_set_option(s, "compat32", "maybe");
#ifdef __x86_64__
	CHECK("api-compat32-option", r == 0 && r2 < 0, "yes=%d maybe=%d", r, r2);
#else
	CHECK("api-compat32-option", r < 0, "unsupported architecture: %d", r);
#endif
	juno_spec_free(s);
}

/* --- parsers under random input --- */
static unsigned long long rng_state = 88172645463325252ull;
static unsigned rnd(void)
{
	rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17;
	return (unsigned)(rng_state >> 11);
}

static void t_fuzz_ctl(void)
{
	char *av[] = { "sleep", "120", NULL };
	juno_spec *s = make_spec(av);
	char path[600];
	const char *rt = getenv("JUNO_RUNTIME_DIR");
	juno_spec_set_restart(s, JUNO_RESTART_ALWAYS, 100);
	int r = juno_run_named(s, "fuzzcell", 1);
	juno_spec_free(s);
	if (r) {
		FAIL("api-fuzz-control-socket", "start: %s", juno_error());
		return;
	}
	snprintf(path, sizeof path, "%s/fuzzcell/sock", rt);
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	if (strlen(path) >= sizeof sa.sun_path) {
		FAIL("api-fuzz-control-socket", "socket path too long");
		return;
	}
	memcpy(sa.sun_path, path, strlen(path) + 1);
	int sent = 0, answered = 0;
	for (int i = 0; i < 2000; i++) {
		unsigned char buf[300];
		size_t n = 0;
		unsigned kind = rnd() % 9;
		memset(buf, 0, sizeof buf);
		switch (kind) {
		case 0: n = 1 + rnd() % 200; for (size_t k = 0; k < n; k++) buf[k] = rnd(); break;
		case 1: {
			unsigned len = 1 + rnd() % 40;
			buf[0] = len;
			buf[4] = 6 + rnd() % 250;
			n = 5 + (len - 1);
			for (size_t k = 5; k < n; k++) buf[k] = rnd();
			break;
		}
		case 2: memset(buf, 0xff, 8); n = 8; break;
		case 3: n = 4; break;
		case 4: buf[0] = 1; buf[4] = 1; n = 3; break;
		case 5: buf[0] = 100; buf[4] = 1; n = 10; break;
		case 6: {
			unsigned len = 1 + rnd() % 60;
			buf[0] = len;
			buf[4] = 4;
			n = 5 + (len - 1);
			for (size_t k = 5; k < n; k++) buf[k] = rnd() % 4 ? 'a' + rnd() % 26 : 0;
			break;
		}
		case 7: buf[0] = 2; buf[4] = 5; buf[5] = rnd(); n = 6; break;	/* LOGS, random follow flag */
		default:	/* STATUS, sometimes with a bent length */
			buf[0] = 1;
			buf[4] = 1;
			n = 5;
			if (rnd() % 2)
				buf[1] = rnd() % 3;
			break;
		}
		if (kind == 8 && buf[1]) {	/* keep STOP/KILL-sized frames out of the random set */
			buf[0] = 1;
			buf[1] = 0;
		}
		int fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (fd < 0) continue;
		if (connect(fd, (struct sockaddr *)&sa, sizeof sa) == 0) {
			sent++;
			if (send(fd, buf, n, MSG_NOSIGNAL) > 0) {
				struct pollfd p = { fd, POLLIN, 0 };
				char rb[256];
				if (poll(&p, 1, kind == 7 ? 5 : 15) > 0 && read(fd, rb, sizeof rb) > 0) answered++;
			}
		}
		close(fd);
	}
	char st[512];
	int alive = juno_cell_status("fuzzcell", st, sizeof st);
	CHECK("api-fuzz-control-socket", alive == 0 && strstr(st, "state=running"),
	      "%d random/mutated frames sent (%d connections answered something); a valid STATUS afterwards: %s", sent, answered,
	      alive == 0 ? "state=running" : "no answer");
	juno_cell_stop("fuzzcell", 1);
}

static void t_fuzz_spec(void)
{
	static const char *base =
		"root = host-ro\nbind-ro = /usr:/usr2\nenv = A=1\nnet = nat:lan\negress-deny = 10.9.0.0/16\negress-allow = 10.9.1.2\n"
		"egress-proxy-allow = api.example.com:443\nmem = 1048576\ntimeout = 2.5\nseccomp = strict\nkeep-cap = net_raw\n"
		"landlock-rw = /tmp\nidmap = full\nuser = 100:100\npublish = 8080:80\nrestart = on-failure\nargv = sh -c 'echo \"a b\"' x\n";
	char path[600];
	const char *tm = getenv("TMPDIR");
	snprintf(path, sizeof path, "%s/fuzz.spec", tm ? tm : "/tmp");
	size_t bl = strlen(base);
	int ok = 0, rejected = 0;
	for (int i = 0; i < 2000; i++) {
		char *m = malloc(bl * 3 + 70000), *p = m;
		memcpy(m, base, bl);
		size_t len = bl;
		int muts = 1 + rnd() % 6;
		while (muts--) {
			switch (rnd() % 7) {
			case 0: m[rnd() % len] = rnd(); break;
			case 1: if (len > 4) len = 1 + rnd() % len; break;
			case 2: {
				size_t at = rnd() % len;
				size_t cnt = rnd() % 40;
				for (size_t k = 0; k < cnt && at + k < len; k++) m[at + k] = '=' ;
				break;
			}
			case 3: {
				size_t at = rnd() % len;
				size_t cnt = 1 + rnd() % 9000;
				memmove(m + at + cnt, m + at, len - at);
				memset(m + at, 'x', cnt);
				len += cnt;
				break;
			}
			case 4: {
				size_t at = rnd() % len;
				size_t cnt = rnd() % 30;

				if (at + cnt < len) {
					memmove(m + at, m + at + cnt, len - at - cnt);
					len -= cnt;
				}
				break;
			}
			case 5: {
				size_t at = rnd() % len;
				m[at] = 0;
				break;
			}
			default: {
				size_t at = rnd() % len;
				size_t cnt = rnd() % 60;

				if (at + cnt < len) {
					memmove(m + at + cnt, m + at, len - at);
					memmove(m + at, m, cnt);
					len += cnt;
				}
				break;
			}
			}
		}
		(void)p;
		FILE *f = fopen(path, "wb");
		if (f) {
			fwrite(m, 1, len, f);
			fclose(f);
		}
		juno_spec *sp = NULL;
		if (juno_spec_load(path, &sp) == 0) {
			ok++;
			juno_spec_free(sp);
		} else {
			rejected++;
		}
		free(m);
	}
	for (int i = 0; i < 2000; i++) {
		juno_spec *sp = juno_spec_new();
		char k[40], v[200];
		static const char *const keys[] = { "root", "bind", "net", "env", "mem", "timeout", "egress-deny", "egress-allow",
			"egress-proxy-allow", "publish", "user", "keep-cap", "argv", "landlock-ro", "idmap", "restart", "seccomp", "nesting" };
		snprintf(k, sizeof k, "%s", keys[rnd() % (sizeof keys / sizeof *keys)]);
		size_t vl = rnd() % sizeof v;
		for (size_t j = 0; j < vl; j++) v[j] = rnd() % 5 ? 32 + rnd() % 95 : rnd();
		v[vl] = 0;
		for (size_t j = 0; j < vl; j++) if (!v[j]) v[j] = 'z';
		if (juno_spec_set_option(sp, k, v) == 0) ok++; else rejected++;
		juno_spec_free(sp);
	}
	unlink(path);
	CHECK("api-fuzz-spec-loader", ok + rejected == 4000, "2000 mutated spec files and 2000 random option values: %d accepted, %d rejected, no crash", ok, rejected);
}

static char g_clean[1400];

static void cleanup_dirs(void)
{
	if (g_clean[0] && system(g_clean)) g_clean[0] = 0;
	g_clean[0] = 0;
}

static void on_fatal(int sig)
{
	cleanup_dirs();
	_exit(128 + sig);
}

int main(void)
{
	atexit(cleanup_dirs);
	signal(SIGINT, on_fatal); signal(SIGTERM, on_fatal); signal(SIGSEGV, on_fatal);
	signal(SIGFPE, on_fatal); signal(SIGABRT, on_fatal);
	char probe[1024];
	if (juno_probe("ns", probe, sizeof probe) != 0) {
		SKIP("api-all", "namespace backend unavailable: %s", probe);
		printf("SUMMARY api_test: %d passed, %d failed, %d skipped\n", pass_count, fail_count, skip_count);
		return 0;
	}
	const char *base = getenv("JUNO_TEST_TMP") ? getenv("JUNO_TEST_TMP") : "/tmp";
	char rt[400], dt[400], tm[400];
	snprintf(rt, sizeof rt, "%s/juno-art-XXXXXX", base);
	snprintf(dt, sizeof dt, "%s/juno-adt-XXXXXX", base);
	snprintf(tm, sizeof tm, "%s/juno-atmp-XXXXXX", base);
	if (mkdtemp(rt) && mkdtemp(dt) && mkdtemp(tm)) {
		snprintf(g_clean, sizeof g_clean, "rm -rf %s %s %s", rt, dt, tm);
		setenv("JUNO_RUNTIME_DIR", rt, 1); setenv("JUNO_DATA_DIR", dt, 1); setenv("TMPDIR", tm, 1);
	}
	t_backend();
	t_args();
	t_probe();
	t_cwd_env_status();
	t_fd_polling_kill();
	t_sigterm();
	t_timeout();
	t_pass_fd();
	t_start_error();
	t_tmpdir_clean();
	t_seccomp_filter();
	t_compat32_spec();
	t_timeout_oob();
	t_threads();
	t_spec_roundtrip();
	t_timeout_poll_only();
	t_local_exec();
	t_named_api();
	t_fuzz_ctl();
	t_fuzz_spec();
	{
		char cmd[1300];
		int left = 0;
		FILE *f = popen("ls -A \"$TMPDIR\" | wc -l", "r");
		if (f) {
			if (fscanf(f, "%d", &left) != 1) left = -1;
			pclose(f);
		}
		CHECK("api-no-leftover-stage-dirs", left == 0, "stage dirs left in the private TMPDIR after the whole run: %d", left);
		(void)cmd;
		snprintf(g_clean, sizeof g_clean, "rm -rf %s %s %s", rt, dt, tm);
		cleanup_dirs();
	}
	printf("SUMMARY api_test: %d passed, %d failed, %d skipped\n", pass_count, fail_count, skip_count);
	return fail_count ? 1 : 0;
}
