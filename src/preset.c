/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "internal.h"
#include "ns/ns.h"
#include <errno.h>
#include <string.h>

/* Presets are plain option lists applied through juno_spec_set_option, so a
 * saved spec never needs to know about them. Later options override. */
struct preset_option { const char *key, *value; };

static const struct preset_option agent_options[] = {
	{ "root", "host-ro" }, { "net", "none" }, { "seccomp", "strict" }, { "nesting", "deny" },
	{ "pids", "256" }, { "nofile", "1024" }, { "env", "HOME=/work" },
	/* read anything the cell can see, write only /work (added with the workspace), /tmp and the
	 * few device files programs use */
	{ "landlock-ro", "/" }, { "landlock-rw-opt", "/tmp" }, { "landlock-rw-opt", "/dev/null" },
	{ "landlock-rw-opt", "/dev/zero" }, { "landlock-rw-opt", "/dev/full" },
	{ "landlock-rw-opt", "/dev/random" }, { "landlock-rw-opt", "/dev/urandom" },
};

#define AGENT_MEMORY_LIMIT "2147483648"

int juno_cgroups_usable(void)
{
	char base[400], why[256];

	return ns_cgroup_probe(base, sizeof base, why, sizeof why);
}

static int apply_options(juno_spec *spec, const struct preset_option *options, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		int rc = juno_spec_set_option(spec, options[i].key, options[i].value);

		if (rc)
			return rc;
	}
	return 0;
}

static int apply_agent_preset(juno_spec *spec)
{
	int rc = apply_options(spec, agent_options, sizeof agent_options / sizeof *agent_options);

	if (rc)
		return rc;
	/* fail closed: without a delegated cgroup the start is refused unless --mem-fallback rlimit was given */
	return juno_spec_set_option(spec, "mem", AGENT_MEMORY_LIMIT);
}

/* Use what the host offers: full id maps and nat when available, the safe fallbacks otherwise. */
static int apply_service_preset(juno_spec *spec)
{
	char why[200];
	int rc;

	rc = juno_spec_set_option(spec, "restart", "on-failure");
	if (rc)
		return rc;
	rc = juno_spec_set_option(spec, "seccomp", "default");
	if (rc)
		return rc;
	rc = juno_spec_set_option(spec, "idmap", juno_idmap_full_available(why, sizeof why) ? "full" : "single");
	if (rc)
		return rc;
	return juno_spec_set_option(spec, "net", juno_pasta_available(NULL, 0) ? "nat" : "none");
}

int juno_spec_apply_preset(juno_spec *spec, const char *name)
{
	if (!strcmp(name, "agent"))
		return apply_agent_preset(spec);
	if (!strcmp(name, "service"))
		return apply_service_preset(spec);

	juno_seterr("unknown preset '%s' (agent, service)", name);
	return -EINVAL;
}

/* workspace = DIR and broker = SOCKET belong to the agent preset */
int juno_preset_param(juno_spec *spec, const char *key, const char *value)
{
	char bind_arg[1200];
	int rc;

	if (!strcmp(key, "workspace")) {
		snprintf(bind_arg, sizeof bind_arg, "%s:/work", value);
		rc = juno_spec_set_option(spec, "bind", bind_arg);
		if (rc)
			return rc;
		rc = juno_spec_set_option(spec, "cwd", "/work");
		if (rc)
			return rc;
		return juno_spec_set_option(spec, "landlock-rw", "/work");
	}
	snprintf(bind_arg, sizeof bind_arg, "%s:/run/broker.sock", value);
	return juno_spec_set_option(spec, "bind", bind_arg);
}
