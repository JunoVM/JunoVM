/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
/* The init of a cell: a separate static image, exec'd inside the cell so that nothing of the
 * launcher (environment, argument list, heap) survives in pid 1.
 * usage: juno-init PAYLOAD_PID TIMEOUT_MS TIMEOUT_FD */
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#define EXIT_INIT_FAILED 125
#define MAX_SIGNAL 32

static volatile pid_t payload_pid;
static volatile sig_atomic_t timed_out;
static int timeout_fd = -1;

static void forward_signal(int sig)
{
	if (payload_pid > 0)
		kill(payload_pid, sig);
}

static void on_timeout(int sig)
{
	(void)sig;
	timed_out = 1;
	if (timeout_fd >= 0) {
		ssize_t written = write(timeout_fd, "T", 1);

		(void)written;
	}
	if (payload_pid > 0)
		kill(payload_pid, SIGKILL);
}

/* Signals the init must keep for itself (or cannot catch). */
static int is_reserved_signal(int sig)
{
	return sig == SIGALRM || sig == SIGKILL || sig == SIGSTOP || sig == SIGCHLD || sig == SIGSEGV ||
	       sig == SIGBUS || sig == SIGILL || sig == SIGFPE || sig == SIGTRAP;
}

static void start_timeout(long ms)
{
	struct sigaction action = { .sa_handler = on_timeout };
	struct itimerval timer = { .it_value = { ms / 1000, (ms % 1000) * 1000 } };

	sigemptyset(&action.sa_mask);
	sigaction(SIGALRM, &action, NULL);
	if (!timer.it_value.tv_sec && !timer.it_value.tv_usec)
		timer.it_value.tv_usec = 1;
	setitimer(ITIMER_REAL, &timer, NULL);
}

int main(int argc, char **argv)
{
	struct sigaction forward = { .sa_handler = forward_signal, .sa_flags = SA_RESTART };
	sigset_t no_signals;
	long timeout_ms;

	if (argc != 4)
		return EXIT_INIT_FAILED;
	payload_pid = atoi(argv[1]);
	timeout_ms = atol(argv[2]);
	timeout_fd = atoi(argv[3]);
	if (payload_pid <= 0)
		return EXIT_INIT_FAILED;

	/* the payload (and exec'd tools) read nothing of us they should not, but they may inspect us */
	prctl(PR_SET_DUMPABLE, 1);

	sigfillset(&forward.sa_mask);
	for (int sig = 1; sig < MAX_SIGNAL; sig++) {
		if (!is_reserved_signal(sig))
			sigaction(sig, &forward, NULL);
	}
	if (timeout_ms > 0)
		start_timeout(timeout_ms);

	sigemptyset(&no_signals);
	sigprocmask(SIG_SETMASK, &no_signals, NULL);	/* the caller left everything blocked until now */

	/* reap orphans; leave with the payload's status */
	for (;;) {
		int status;
		pid_t child = waitpid(-1, &status, 0);

		if (child < 0) {
			if (errno == EINTR)
				continue;
			_exit(EXIT_INIT_FAILED);
		}
		if (child != payload_pid)
			continue;
		if (WIFEXITED(status))
			_exit(WEXITSTATUS(status));
		_exit(128 + WTERMSIG(status));
	}
}
