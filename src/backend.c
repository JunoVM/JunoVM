/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "internal.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>

static const struct juno_backend *const backends[] = { &juno_ns_backend };

const struct juno_backend *juno_backend_find(const char *name)
{
	for (size_t i = 0; i < sizeof backends / sizeof *backends; i++) {
		if (!strcmp(backends[i]->name, name))
			return backends[i];
	}
	return NULL;
}

int juno_backend_need(const struct juno_backend *backend, const char *name)
{
	if (!backend) {
		juno_seterr("backend '%s' is not available (only 'ns' is implemented)", name);
		return -ENOTSUP;
	}
	return 0;
}

int juno_start(const juno_spec *spec, juno_cell **out)
{
	const struct juno_backend *backend = juno_backend_find(spec->backend);
	juno_cell *cell;
	int rc = juno_backend_need(backend, spec->backend);

	if (rc)
		return rc;
	if (!spec->argv || !spec->argv[0]) {
		juno_seterr("spec: no command given");
		return -EINVAL;
	}

	cell = calloc(1, sizeof *cell);
	if (!cell)
		return -ENOMEM;
	cell->be = backend;
	cell->pidfd = cell->ipidfd = -1;

	rc = backend->start(spec, cell);
	if (rc) {
		juno_cell_free(cell);
		return rc;
	}
	*out = cell;
	return 0;
}

int juno_cell_fd(const juno_cell *cell) { return cell->pidfd; }
int juno_cell_pid(const juno_cell *cell) { return cell->pid; }
int juno_cell_timed_out(const juno_cell *cell) { return cell->timed_out; }
int juno_cell_kill(juno_cell *cell, int sig) { return cell->be->kill(cell, sig); }

int juno_cell_wait(juno_cell *cell, int *status, int timeout_ms)
{
	return cell->be->wait(cell, status, timeout_ms);
}

void juno_cell_free(juno_cell *cell)
{
	if (!cell)
		return;
	if (cell->be && cell->be->release)
		cell->be->release(cell);
	free(cell);
}

int juno_cell_tty(const juno_cell *cell) { return cell->ttyfd; }

int juno_cell_exec_tty(juno_cell *cell, char *const argv[], int *master, int *donefd)
{
	if (!cell->be->exec_tty) {
		juno_seterr("backend has no exec");
		return -ENOTSUP;
	}
	return cell->be->exec_tty(cell, argv, master, donefd);
}

int juno_cell_exec_wait(juno_cell *cell, int donefd, int *status)
{
	return cell->be->exec_done(cell, donefd, status);
}

int juno_cell_set_exec_user(juno_cell *cell, int uid, int gid)
{
	if (uid < 0 || uid > 65535)
		return -EINVAL;
	cell->exec_user_set = true;
	cell->exec_uid = uid;
	cell->exec_gid = gid < 0 ? uid : gid;
	return 0;
}
