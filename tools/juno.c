/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "juno.h"
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <unistd.h>

#define EXIT_USAGE 2
#define EXIT_FAILED 125
#define EXIT_TIMED_OUT 124
#define CAP_SYS_ADMIN_NUMBER 21
#define OPTION_NAME_MAX 64
#define DEFAULT_STOP_SECONDS 10

/* the cell that signals and Ctrl-C are relayed to */
static juno_cell *foreground_cell;

static void relay_signal(int sig)
{
	if (foreground_cell)
		juno_cell_kill(foreground_cell, sig);
}

static volatile sig_atomic_t window_resized;
static void on_winch(int sig) { (void)sig; window_resized = 1; }

static void copy_window_size(int master)
{
	struct winsize size;

	if (ioctl(0, TIOCGWINSZ, &size) == 0)
		ioctl(master, TIOCSWINSZ, &size);
}

/* Relay the caller's terminal to a pty master until the process behind it is done. */
static void tty_relay(int master, int done_fd)
{
	struct termios saved, raw;
	struct sigaction action = { .sa_handler = on_winch };
	int is_raw = 0, stdin_closed = 0;
	char buf[4096];

	sigemptyset(&action.sa_mask);
	sigaction(SIGWINCH, &action, NULL);
	if (isatty(0) && tcgetattr(0, &saved) == 0) {
		raw = saved;
		cfmakeraw(&raw);
		tcsetattr(0, TCSANOW, &raw);
		is_raw = 1;
	}
	copy_window_size(master);

	for (;;) {
		struct pollfd fds[3] = {
			{ stdin_closed ? -1 : 0, POLLIN, 0 }, { master, POLLIN, 0 }, { done_fd, POLLIN, 0 },
		};

		if (window_resized) {
			window_resized = 0;
			copy_window_size(master);
		}
		if (poll(fds, 3, -1) < 0)
			continue;

		if (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
			ssize_t got = read(master, buf, sizeof buf);

			if (got <= 0 || write(1, buf, got) < 0)
				break;
			continue;
		}
		if (fds[0].revents & (POLLIN | POLLHUP)) {
			ssize_t got = read(0, buf, sizeof buf);

			if (got > 0) {
				if (write(master, buf, got) < 0)
					break;
			} else {
				stdin_closed = 1;
			}
		}
		if (fds[2].revents) {	/* done: drain what is left */
			ssize_t got;

			fcntl(master, F_SETFL, fcntl(master, F_GETFL) | O_NONBLOCK);
			while ((got = read(master, buf, sizeof buf)) > 0) {
				if (write(1, buf, got) < 0)
					break;
			}
			break;
		}
	}
	if (is_raw)
		tcsetattr(0, TCSANOW, &saved);
}

static int usage(void)
{
	fputs("usage: juno probe | version\n"
	      "       juno run [options] -- cmd [args...]\n"
	      "       juno ps | status NAME | exec NAME -- cmd | stop NAME [--time S]\n"
	      "       juno kill NAME [SIG] | logs [-f] NAME | rm [-f] NAME | net ls | net rm NAME\n"
	      "       juno up DIR | down DIR | exec [-t] [--user U[:G]] NAME -- cmd\n"
	      "run options: --name NAME  -d  --spec FILE  --root host-ro|dir:PATH|overlay[:UPPER]\n"
	      "  --layer PATH  --bind SRC:DST  --bind-ro SRC:DST  --tmpfs DST  --net none|host|shared:NAME\n"
	      "  --publish [ADDR:]HOSTPORT:CELLPORT  --hostname N  --env K=V  --cwd P  --mem BYTES\n"
	      "  --pids N  --nofile N  --cpu-weight N  --timeout SECONDS  --seccomp default|strict|off\n"
	      "  --keep-cap CAP  --landlock-ro PATH  --landlock-rw PATH  --init tiny|none  --nesting\n"
	      "  --restart no|on-failure|always  --max-restarts N  --compat32  -t\n"
	      "  --net nat[:lan|:host]  --mem-fallback rlimit  --tmp-size N  --run-size N  --shm-size N\n"
	      "  --log-max N  --egress-deny CIDR  --egress-allow CIDR  --egress-proxy-allow HOST:PORT\n"
	      "  --idmap full|single  --user UID[:GID]  --preset agent|service  --workspace DIR\n"
	      "  --broker SOCKET\n", stderr);
	return EXIT_USAGE;
}

static int fail(const char *what, int err)
{
	fprintf(stderr, "juno: %s: %s\n", what, juno_error()[0] ? juno_error() : strerror(-err));
	return EXIT_FAILED;
}

static int exit_code(int status)
{
	return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

/* Options of "juno run" that take a value (--name and --spec are handled separately). */
static const char *const value_options[] = {
	"root", "layer", "bind", "bind-ro", "tmpfs", "net", "hostname", "env", "cwd", "mem", "pids",
	"nofile", "cpu-weight", "timeout", "seccomp", "keep-cap", "landlock-ro", "landlock-rw", "init",
	"publish", "restart", "max-restarts", "idmap", "user", "preset", "workspace", "broker",
	"mem-fallback", "tmp-size", "run-size", "shm-size", "tmpfs-size", "log-max", "egress-deny",
	"egress-allow", "egress-proxy-allow",
};

static int is_value_option(const char *key)
{
	if (!strcmp(key, "name") || !strcmp(key, "spec"))
		return 1;
	for (size_t i = 0; i < sizeof value_options / sizeof *value_options; i++) {
		if (!strcmp(value_options[i], key))
			return 1;
	}
	return 0;
}

struct run_args {
	const char *name;
	int detach;
	int tty;
};

/* Start from --spec FILE if given (the last one wins), else an empty spec. */
static int load_base_spec(int argc, char **argv, juno_spec **spec)
{
	int rc;

	for (int i = 0; i < argc && strcmp(argv[i], "--"); i++) {
		if (!strcmp(argv[i], "--spec") && i + 1 < argc) {
			if (*spec) {
				juno_spec_free(*spec);
				*spec = NULL;
			}
			rc = juno_spec_load(argv[i + 1], spec);
			if (rc)
				return fail("spec", rc);
		}
	}
	if (!*spec && !(*spec = juno_spec_new()))
		return fail("spec", -ENOMEM);
	return 0;
}

/* Presets come first, everything else overrides them. */
static int apply_presets(int argc, char **argv, juno_spec *spec)
{
	for (int i = 0; i < argc && strcmp(argv[i], "--"); i++) {
		if (!strcmp(argv[i], "--preset") && i + 1 < argc) {
			int rc = juno_spec_apply_preset(spec, argv[i + 1]);

			if (rc)
				return fail("preset", rc);
		}
	}
	return 0;
}

/* Parse the options before "--". On success *command_index is where "--" sits (or argc). */
static int parse_run_options(int argc, char **argv, juno_spec *spec, struct run_args *args, int *command_index)
{
	int i;

	for (i = 0; i < argc && strcmp(argv[i], "--"); i++) {
		char *arg = argv[i];
		char *equals = strchr(arg, '=');
		char *value = NULL;
		char key[OPTION_NAME_MAX];
		size_t key_len;
		int rc;

		if (!strcmp(arg, "-d") || !strcmp(arg, "--detach")) {
			args->detach = 1;
			continue;
		}
		if (!strcmp(arg, "--nesting")) {
			juno_spec_set_nesting(spec, 1);
			continue;
		}
		if (!strcmp(arg, "--compat32")) {
			rc = juno_spec_set_compat32(spec, 1);
			if (rc)
				return fail("compat32", rc);
			continue;
		}
		if (!strcmp(arg, "-t") || !strcmp(arg, "--tty")) {
			args->tty = 1;
			continue;
		}
		if (strncmp(arg, "--", 2)) {
			fprintf(stderr, "juno: unexpected argument %s\n", arg);
			return usage();
		}

		key_len = equals ? (size_t)(equals - arg) : strlen(arg);
		if (key_len < 3 || key_len - 2 >= sizeof key) {
			fprintf(stderr, "juno: unknown option %s\n", arg);
			return usage();
		}
		memcpy(key, arg + 2, key_len - 2);
		key[key_len - 2] = 0;
		if (!is_value_option(key)) {
			fprintf(stderr, "juno: unknown option %s\n", arg);
			return usage();
		}

		if (equals) {
			value = equals + 1;
		} else if (i + 1 < argc) {
			value = argv[++i];
		} else {
			fprintf(stderr, "juno: %s needs a value\n", arg);
			return usage();
		}

		if (!strcmp(key, "name"))
			args->name = value;
		else if (!strcmp(key, "keep-cap") && juno_cap_from_name(value) == CAP_SYS_ADMIN_NUMBER)
			fputs("juno: warning: --keep-cap sys_admin lets the cell remount --bind-ro mounts "
			      "read-write and reach far more of the kernel\n", stderr);

		/* --name, --spec and --preset were handled before */
		if (strcmp(key, "name") && strcmp(key, "spec") && strcmp(key, "preset") &&
		    juno_spec_set_option(spec, key, value)) {
			fprintf(stderr, "juno: %s\n", juno_error());
			return usage();
		}
	}
	*command_index = i;
	return 0;
}

/* Run in this process: relay signals to the cell and mirror its exit status. */
static int run_foreground(juno_spec *spec, const struct run_args *args)
{
	struct sigaction action = { .sa_handler = relay_signal, .sa_flags = SA_RESTART };
	juno_cell *cell;
	int status = 0, code, rc;

	rc = juno_start(spec, &cell);
	juno_spec_free(spec);
	if (rc) {
		fprintf(stderr, "juno: %s\n", juno_error());
		return EXIT_FAILED;
	}

	foreground_cell = cell;
	sigemptyset(&action.sa_mask);
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGHUP, &action, NULL);

	if (args->tty)
		tty_relay(juno_cell_tty(cell), juno_cell_fd(cell));
	rc = juno_cell_wait(cell, &status, -1);
	if (rc)
		code = fail("wait", rc);
	else if (juno_cell_timed_out(cell))
		code = EXIT_TIMED_OUT;
	else
		code = exit_code(status);

	foreground_cell = NULL;
	juno_cell_free(cell);
	return code;
}

/* *owned receives the spec while this function still owns it, NULL once it has been consumed. */
static int run_command(int argc, char **argv, juno_spec **owned)
{
	juno_spec *spec = NULL;
	struct run_args args = { 0 };
	int command_index, rc;

	rc = load_base_spec(argc, argv, &spec);
	if (rc)
		return rc;
	*owned = spec;
	rc = apply_presets(argc, argv, spec);
	if (rc)
		return rc;
	rc = parse_run_options(argc, argv, spec, &args, &command_index);
	if (rc)
		return rc;

	if (command_index < argc && command_index + 1 < argc) {
		rc = juno_spec_set_argv(spec, argv + command_index + 1);
		if (rc)
			return fail("argv", rc);
	} else if (command_index < argc) {
		fputs("juno: no command given\n", stderr);
		return usage();
	}

	if (args.tty && args.name) {
		fputs("juno: -t does not combine with --name\n", stderr);
		return EXIT_USAGE;
	}
	if (args.tty)
		juno_spec_set_tty(spec, 1);

	if (args.name) {
		rc = juno_run_named(spec, args.name, args.detach);
		juno_spec_free(spec);
		*owned = NULL;
		return rc < 0 ? fail("run", rc) : rc;
	}
	if (args.detach) {
		fputs("juno: -d needs --name\n", stderr);
		return usage();
	}

	*owned = NULL;	/* run_foreground frees it */
	return run_foreground(spec, &args);
}

static int cmd_run(int argc, char **argv)
{
	juno_spec *owned = NULL;
	int rc = run_command(argc, argv, &owned);

	juno_spec_free(owned);
	return rc;
}

static int parse_signal(const char *text)
{
	static const struct { const char *name; int number; } signals[] = {
		{ "HUP", SIGHUP }, { "INT", SIGINT }, { "QUIT", SIGQUIT }, { "KILL", SIGKILL },
		{ "USR1", SIGUSR1 }, { "USR2", SIGUSR2 }, { "TERM", SIGTERM }, { "CONT", SIGCONT },
		{ "STOP", SIGSTOP },
	};

	if (isdigit((unsigned char)*text))
		return atoi(text);
	if (!strncasecmp(text, "SIG", 3))
		text += 3;
	for (size_t i = 0; i < sizeof signals / sizeof *signals; i++) {
		if (!strcasecmp(text, signals[i].name))
			return signals[i].number;
	}
	return -1;
}

static void print_row(const char *name, const char *state, int pid, long uptime, int restarts, void *userdata)
{
	(void)userdata;
	printf("%-20s %-11s %-8d %-8ld %d\n", name, state, pid, uptime, restarts);
}

static int cmd_net(int argc, char **argv)
{
	int rc;

	if (!strcmp(argv[2], "ls")) {
		char list[4096];

		juno_net_list(list, sizeof list);
		printf("NAME PID CELLS\n%s", list);
		return 0;
	}
	if (!strcmp(argv[2], "rm") && argc == 4) {
		rc = juno_net_remove(argv[3]);
		return rc ? fail("net rm", rc) : 0;
	}
	return usage();
}

static int cmd_rmtree(int argc, char **argv)
{
	int bad = 0;

	for (int i = 2; i < argc; i++) {
		if (juno_rmtree(argv[i])) {
			fprintf(stderr, "juno: rmtree %s: %s\n", argv[i], juno_error());
			bad = 1;
		}
	}
	return bad;
}

static int cmd_logs(int argc, char **argv)
{
	const char *name = argv[2];
	int follow = argc >= 4 && !strcmp(argv[3], "-f");
	int rc;

	if (!strcmp(argv[2], "-f")) {	/* juno logs -f NAME */
		if (argc < 4)
			return usage();
		name = argv[3];
		follow = 1;
	}
	rc = juno_cell_logs(name, follow, 1);
	return rc ? fail("logs", rc) : 0;
}

static int cmd_rm(int argc, char **argv)
{
	int force = !strcmp(argv[2], "-f");
	int rc;

	if (force && argc < 4)
		return usage();
	rc = juno_cell_remove(force ? argv[3] : argv[2], force);
	return rc ? fail("rm", rc) : 0;
}

struct exec_options {
	int tty;
	int uid, gid;
};

/* "exec [-t] [--user U[:G]] NAME -- cmd": consume the leading options, shifting argv. */
static int parse_exec_options(int *argc, char ***argv, struct exec_options *opts)
{
	while (*argc >= 4 && (!strcmp((*argv)[2], "-t") || !strcmp((*argv)[2], "--user"))) {
		if (!strcmp((*argv)[2], "-t")) {
			opts->tty = 1;
			(*argv)++;
			(*argc)--;
			continue;
		}
		if (*argc < 5)
			return -1;
		char *end;

		opts->uid = (int)strtol((*argv)[3], &end, 10);
		if (*end == ':')
			opts->gid = atoi(end + 1);
		*argv += 2;
		*argc -= 2;
	}
	return 0;
}

static int cmd_exec(int argc, char **argv, const struct exec_options *opts)
{
	const char *name = argv[2];
	int first = 3;
	juno_cell *cell;
	int status = 0, rc;

	if (first < argc && !strcmp(argv[first], "--"))
		first++;
	if (first >= argc)
		return usage();

	rc = juno_cell_open(name, &cell);
	if (rc)
		return fail("exec", rc);
	if (opts->uid >= 0)
		juno_cell_set_exec_user(cell, opts->uid, opts->gid);

	if (opts->tty) {
		int master, done;

		rc = juno_cell_exec_tty(cell, argv + first, &master, &done);
		if (rc) {
			juno_cell_free(cell);
			return fail("exec", rc);
		}
		tty_relay(master, done);
		rc = juno_cell_exec_wait(cell, done, &status);
		close(master);
	} else {
		rc = juno_cell_exec(cell, argv + first, &status);
	}
	juno_cell_free(cell);
	return rc ? fail("exec", rc) : exit_code(status);
}

int main(int argc, char **argv)
{
	struct exec_options exec_opts = { .uid = -1, .gid = -1 };
	const char *cmd, *name;
	int rc;

	if (argc < 2)
		return usage();
	cmd = argv[1];

	if (!strcmp(cmd, "probe")) {
		char report[2048];

		rc = juno_probe("ns", report, sizeof report);
		fputs(report, stdout);
		return rc ? 1 : 0;
	}
	if (!strcmp(cmd, "version") || !strcmp(cmd, "--version")) {
		puts("juno " JUNO_VERSION);
		return 0;
	}
	if (!strcmp(cmd, "run"))
		return cmd_run(argc - 2, argv + 2);
	if (!strcmp(cmd, "ps")) {
		printf("%-20s %-11s %-8s %-8s %s\n", "NAME", "STATE", "PID", "UPTIME", "RESTARTS");
		return juno_list(print_row, NULL) ? 1 : 0;
	}
	if (!strcmp(cmd, "net") && argc >= 3)
		return cmd_net(argc, argv);
	if (!strcmp(cmd, "up") || !strcmp(cmd, "down")) {
		if (argc < 3)
			return usage();
		rc = !strcmp(cmd, "up") ? juno_up(argv[2], stdout) : juno_down(argv[2], stdout);
		return rc ? 1 : 0;
	}
	if (!strcmp(cmd, "rmtree"))
		return cmd_rmtree(argc, argv);

	if (argc < 3)
		return usage();
	if (!strcmp(cmd, "exec") && parse_exec_options(&argc, &argv, &exec_opts) < 0)
		return usage();
	name = argv[2];

	if (!strcmp(cmd, "status")) {
		char text[1024];

		rc = juno_cell_status(name, text, sizeof text);
		if (rc)
			return fail("status", rc);
		fputs(text, stdout);
		return 0;
	}
	if (!strcmp(cmd, "stop")) {
		int grace_s = DEFAULT_STOP_SECONDS;

		if (argc >= 5 && !strcmp(argv[3], "--time"))
			grace_s = atoi(argv[4]);
		rc = juno_cell_stop(name, grace_s);
		return rc ? fail("stop", rc) : 0;
	}
	if (!strcmp(cmd, "kill")) {
		int sig = argc >= 4 ? parse_signal(argv[3]) : SIGTERM;

		if (sig < 0) {
			fprintf(stderr, "juno: bad signal %s\n", argv[3]);
			return EXIT_USAGE;
		}
		rc = juno_cell_signal(name, sig);
		return rc ? fail("kill", rc) : 0;
	}
	if (!strcmp(cmd, "logs"))
		return cmd_logs(argc, argv);
	if (!strcmp(cmd, "rm"))
		return cmd_rm(argc, argv);
	if (!strcmp(cmd, "exec"))
		return cmd_exec(argc, argv, &exec_opts);
	return usage();
}
