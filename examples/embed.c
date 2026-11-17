/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
/* Runs a command in a cell and waits for it by polling juno_cell_fd(). */
#include "juno.h"
#include <poll.h>
#include <stdio.h>
#include <sys/wait.h>

int main(int argc, char **argv)
{
	char *echo[] = { "echo", "hello from a cell", NULL };
	char **cmd = argc > 1 ? argv + 1 : echo;
	juno_spec *spec = juno_spec_new();
	juno_cell *cell;
	int r, status;

	if (!spec) return 1;
	if ((r = juno_spec_set_argv(spec, cmd)) || (r = juno_spec_set_limit(spec, JUNO_LIMIT_TIMEOUT_MS, 10000))) {
		fprintf(stderr, "spec: %s\n", juno_error());
		return 1;
	}
	if ((r = juno_start(spec, &cell))) {
		fprintf(stderr, "start: %s\n", juno_error());
		return 1;
	}
	juno_spec_free(spec);

	/* The fd becomes readable when the cell has exited; a real program
	 * would put it in its event loop next to its other descriptors. */
	struct pollfd pf = { juno_cell_fd(cell), POLLIN, 0 };
	while (poll(&pf, 1, -1) < 0) ;
	if ((r = juno_cell_wait(cell, &status, 0))) {
		fprintf(stderr, "wait: %s\n", juno_error());
		return 1;
	}
	printf("cell pid %d exited with status %d\n", juno_cell_pid(cell), WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status));
	juno_cell_free(cell);
	return 0;
}
