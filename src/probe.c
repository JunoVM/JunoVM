/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "internal.h"

int juno_probe(const char *backend_name, char *report, size_t len)
{
	const char *name = backend_name ? backend_name : "ns";
	const struct juno_backend *backend = juno_backend_find(name);
	int rc = juno_backend_need(backend, name);

	if (rc)
		return rc;
	if (len)
		report[0] = 0;
	return backend->probe(report, len);
}
