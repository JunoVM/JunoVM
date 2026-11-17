/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "internal.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <strings.h>

#define DEFAULT_MAX_RESTARTS 10
#define MAX_HOSTNAME_LEN 64
#define MAX_NAME_LEN 64
#define MAX_ID 65535
#define MAX_PORT 65535
#define MAX_PROXY_ENTRY_LEN 200
#define NUM_CAPS 64
#define MIN_CELL_FD 3

juno_spec *juno_spec_new(void)
{
	juno_spec *spec = calloc(1, sizeof *spec);

	if (!spec)
		return NULL;
	strcpy(spec->backend, "ns");
	spec->root_kind = JUNO_ROOT_HOST_RO;
	spec->net = JUNO_NET_NONE;
	spec->stdio[0] = spec->stdio[1] = spec->stdio[2] = -1;
	spec->max_restarts = DEFAULT_MAX_RESTARTS;
	return spec;
}

static void free_strv(char **list)
{
	for (char **entry = list; entry && *entry; entry++)
		free(*entry);
	free(list);
}

void juno_spec_free(juno_spec *spec)
{
	if (!spec)
		return;
	free(spec->root_path);
	free_strv(spec->layers);
	for (int i = 0; i < spec->nmounts; i++) {
		free(spec->mounts[i].src);
		free(spec->mounts[i].dst);
	}
	free(spec->mounts);
	for (int i = 0; i < spec->nll; i++)
		free(spec->ll[i].path);
	free(spec->ll);
	free_strv(spec->argv);
	free_strv(spec->env);
	free_strv(spec->pubs);
	free_strv(spec->egress_deny);
	free_strv(spec->egress_allow);
	free_strv(spec->proxy_allow);
	free(spec->netname);
	free(spec->cwd);
	free(spec->hostname);
	free(spec->fds);
	free(spec);
}

/* Replace *dst with a copy of value. */
static int replace_string(char **dst, const char *value)
{
	char *copy = strdup(value);

	if (!copy)
		return -ENOMEM;
	free(*dst);
	*dst = copy;
	return 0;
}

int juno_spec_set_backend(juno_spec *spec, const char *name)
{
	if (!name || strlen(name) >= sizeof spec->backend)
		return -EINVAL;
	strcpy(spec->backend, name);
	return 0;
}

#define TOO_LONG(str) ((str) && strlen(str) > JUNO_MAX_VALUE)

int juno_spec_set_root(juno_spec *spec, int kind, const char *path)
{
	if (TOO_LONG(path))
		return -E2BIG;
	if (kind < JUNO_ROOT_HOST_RO || kind > JUNO_ROOT_OVERLAY)
		return -EINVAL;
	if (kind == JUNO_ROOT_DIR && (!path || path[0] == 0))
		return -EINVAL;
	if (path && !path[0])
		path = NULL;

	spec->root_kind = kind;
	if (!path) {
		free(spec->root_path);
		spec->root_path = NULL;
		return 0;
	}
	return replace_string(&spec->root_path, path);
}

int juno_spec_add_layer(juno_spec *spec, const char *lower)
{
	char *copy;

	if (TOO_LONG(lower))
		return -E2BIG;
	copy = lower ? strdup(lower) : NULL;
	if (!copy)
		return -ENOMEM;
	return juno_append(&spec->layers, &spec->nlayers, copy) ? -ENOMEM : 0;
}

int juno_spec_add_mount(juno_spec *spec, int kind, const char *src, const char *dst, unsigned flags)
{
	struct juno_mount *grown, *mount;

	if (TOO_LONG(src) || TOO_LONG(dst))
		return -E2BIG;
	if ((kind != JUNO_MOUNT_BIND && kind != JUNO_MOUNT_TMPFS) || !dst || dst[0] != '/')
		return -EINVAL;
	if (kind == JUNO_MOUNT_BIND && !src)
		return -EINVAL;

	grown = realloc(spec->mounts, sizeof *grown * (spec->nmounts + 1));
	if (!grown)
		return -ENOMEM;
	spec->mounts = grown;

	mount = &grown[spec->nmounts];
	mount->kind = kind;
	mount->flags = flags;
	mount->src = src ? strdup(src) : NULL;
	mount->dst = strdup(dst);
	if (!mount->dst || (src && !mount->src)) {
		free(mount->src);
		free(mount->dst);
		return -ENOMEM;
	}
	spec->nmounts++;
	return 0;
}

int juno_spec_set_net(juno_spec *spec, int mode, const char *name)
{
	if (mode < JUNO_NET_NONE || mode > JUNO_NET_NAT)
		return -EINVAL;

	spec->nat_host = spec->nat_lan = false;
	if (mode == JUNO_NET_NAT && name) {
		if (!strcmp(name, "host"))
			spec->nat_host = spec->nat_lan = true;	/* the gateway reaches the host; implies lan */
		else if (!strcmp(name, "lan"))
			spec->nat_lan = true;
		else
			return -EINVAL;
	}
	if (mode == JUNO_NET_SHARED) {
		if (!juno_valid_name(name))
			return -EINVAL;
		free(spec->netname);
		spec->netname = strdup(name);
		if (!spec->netname)
			return -ENOMEM;
	}
	spec->net = mode;
	return 0;
}

int juno_spec_set_limit(juno_spec *spec, int which, uint64_t value)
{
	if (which <= 0 || which >= JUNO_LIMIT_MAX)
		return -EINVAL;
	spec->limit[which] = value;
	spec->limit_set[which] = true;
	return 0;
}

int juno_spec_set_seccomp(juno_spec *spec, int profile)
{
	if (profile < JUNO_SECCOMP_DEFAULT || profile > JUNO_SECCOMP_OFF)
		return -EINVAL;
	spec->seccomp = profile;
	return 0;
}

int juno_spec_keep_cap(juno_spec *spec, int cap)
{
	if (cap < 0 || cap >= NUM_CAPS)
		return -EINVAL;
	spec->keepcaps |= 1ull << cap;
	return 0;
}

int juno_spec_add_landlock(juno_spec *spec, const char *path, unsigned access)
{
	struct juno_ll *grown, *rule;

	if (TOO_LONG(path))
		return -E2BIG;
	if (!path || !(access & (JUNO_LL_READ | JUNO_LL_WRITE)))
		return -EINVAL;

	grown = realloc(spec->ll, sizeof *grown * (spec->nll + 1));
	if (!grown)
		return -ENOMEM;
	spec->ll = grown;

	rule = &grown[spec->nll];
	rule->path = strdup(path);
	if (!rule->path)
		return -ENOMEM;
	rule->access = access;
	spec->nll++;
	return 0;
}

/* Deep copy of a string array into a NULL-terminated list; 0 on success. */
static int copy_strv(char ***out, char *const *list, int count)
{
	char **copy = NULL;
	int copied = 0;

	for (int i = 0; i < count; i++) {
		char *entry = strdup(list[i]);

		if (!entry || juno_append(&copy, &copied, entry)) {
			free_strv(copy);
			return -ENOMEM;
		}
	}
	*out = copy;
	return 0;
}

int juno_spec_set_argv(juno_spec *spec, char *const argv[])
{
	int count = 0;
	char **copy;

	for (int i = 0; argv && argv[i]; i++) {
		if (TOO_LONG(argv[i]))
			return -E2BIG;
	}
	if (!argv || !argv[0])
		return -EINVAL;

	while (argv[count])
		count++;
	if (copy_strv(&copy, argv, count))
		return -ENOMEM;
	free_strv(spec->argv);
	spec->argv = copy;
	return 0;
}

int juno_spec_set_env(juno_spec *spec, const char *name, const char *value)
{
	size_t name_len;
	char *entry;

	if (TOO_LONG(name) || TOO_LONG(value))
		return -E2BIG;
	if (!name || !*name || strchr(name, '=') || !value)
		return -EINVAL;

	name_len = strlen(name);
	entry = malloc(name_len + strlen(value) + 2);
	if (!entry)
		return -ENOMEM;
	sprintf(entry, "%s=%s", name, value);

	for (int i = 0; i < spec->nenv; i++) {
		if (!strncmp(spec->env[i], name, name_len) && spec->env[i][name_len] == '=') {
			free(spec->env[i]);
			spec->env[i] = entry;
			return 0;
		}
	}
	return juno_append(&spec->env, &spec->nenv, entry) ? -ENOMEM : 0;
}

int juno_spec_set_cwd(juno_spec *spec, const char *path)
{
	if (TOO_LONG(path))
		return -E2BIG;
	if (!path || path[0] != '/')
		return -EINVAL;
	return replace_string(&spec->cwd, path);
}

int juno_spec_set_hostname(juno_spec *spec, const char *name)
{
	if (!name || !*name || strlen(name) > MAX_HOSTNAME_LEN)
		return -EINVAL;
	return replace_string(&spec->hostname, name);
}

int juno_spec_set_stdio(juno_spec *spec, int in, int out, int err)
{
	spec->stdio[0] = in;
	spec->stdio[1] = out;
	spec->stdio[2] = err;
	return 0;
}

int juno_spec_pass_fd(juno_spec *spec, int host_fd, int cell_fd)
{
	struct juno_fdmap *grown;

	if (host_fd < 0 || cell_fd < MIN_CELL_FD)
		return -EINVAL;
	for (int i = 0; i < spec->nfds; i++) {
		if (spec->fds[i].dst == cell_fd)
			return -EEXIST;
	}

	grown = realloc(spec->fds, sizeof *grown * (spec->nfds + 1));
	if (!grown)
		return -ENOMEM;
	spec->fds = grown;
	grown[spec->nfds].src = host_fd;
	grown[spec->nfds].dst = cell_fd;
	spec->nfds++;
	return 0;
}

int juno_spec_set_init(juno_spec *spec, int mode)
{
	if (mode != JUNO_INIT_TINY && mode != JUNO_INIT_NONE)
		return -EINVAL;
	spec->init = mode;
	return 0;
}

/* indexed by capability number */
static const char *const cap_names[] = {
	"chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill",
	"setgid", "setuid", "setpcap", "linux_immutable", "net_bind_service",
	"net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner",
	"sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct",
	"sys_admin", "sys_boot", "sys_nice", "sys_resource", "sys_time",
	"sys_tty_config", "mknod", "lease", "audit_write", "audit_control",
	"setfcap", "mac_override", "mac_admin", "syslog", "wake_alarm",
	"block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore",
};

/* "net_admin", "CAP_NET_ADMIN" or a plain number */
int juno_cap_from_name(const char *name)
{
	char *end;
	long number;

	if (!name || !*name)
		return -EINVAL;
	if (!strncasecmp(name, "cap_", 4))
		name += 4;

	number = strtol(name, &end, 10);
	if (!*end)
		return (number >= 0 && number < NUM_CAPS) ? (int)number : -EINVAL;
	for (size_t i = 0; i < sizeof cap_names / sizeof *cap_names; i++) {
		if (!strcasecmp(name, cap_names[i]))
			return (int)i;
	}
	return -EINVAL;
}

int juno_spec_set_nesting(juno_spec *spec, int allow)
{
	spec->nesting = !!allow;
	return 0;
}

/* "[A.B.C.D:]HOSTPORT:CELLPORT"; the bind address defaults to 127.0.0.1 */
int juno_spec_add_publish(juno_spec *spec, const char *text)
{
	unsigned a = 127, b = 0, c = 0, d = 1, host_port, cell_port;
	char trailing;
	char *copy;

	if (sscanf(text, "%u.%u.%u.%u:%u:%u%c", &a, &b, &c, &d, &host_port, &cell_port, &trailing) != 6) {
		a = 127;
		b = c = 0;
		d = 1;
		if (sscanf(text, "%u:%u%c", &host_port, &cell_port, &trailing) != 2)
			return -EINVAL;
	}
	if (a > 255 || b > 255 || c > 255 || d > 255 ||
	    !host_port || host_port > MAX_PORT || !cell_port || cell_port > MAX_PORT)
		return -EINVAL;

	copy = strdup(text);
	return (copy && !juno_append(&spec->pubs, &spec->npubs, copy)) ? 0 : -ENOMEM;
}

int juno_spec_set_restart(juno_spec *spec, int policy, int max)
{
	if (policy < JUNO_RESTART_NO || policy > JUNO_RESTART_ALWAYS || max < 0)
		return -EINVAL;
	spec->restart = policy;
	spec->max_restarts = max;
	return 0;
}

int juno_valid_name(const char *name)
{
	if (!name || !*name || strlen(name) > MAX_NAME_LEN || name[0] == '.' || name[0] == '-')
		return 0;
	for (; *name; name++) {
		int ok = (*name >= 'a' && *name <= 'z') || (*name >= 'A' && *name <= 'Z') ||
			 (*name >= '0' && *name <= '9') || *name == '-' || *name == '_' || *name == '.';

		if (!ok)
			return 0;
	}
	return 1;
}

static int dup_mounts(juno_spec *dst, const juno_spec *src)
{
	if (!src->nmounts)
		return 0;
	dst->mounts = calloc(src->nmounts, sizeof *dst->mounts);
	if (!dst->mounts)
		return -ENOMEM;
	dst->nmounts = src->nmounts;
	for (int i = 0; i < src->nmounts; i++) {
		dst->mounts[i] = src->mounts[i];
		dst->mounts[i].src = src->mounts[i].src ? strdup(src->mounts[i].src) : NULL;
		dst->mounts[i].dst = strdup(src->mounts[i].dst);
		if (!dst->mounts[i].dst || (src->mounts[i].src && !dst->mounts[i].src))
			return -ENOMEM;
	}
	return 0;
}

static int dup_landlock(juno_spec *dst, const juno_spec *src)
{
	if (!src->nll)
		return 0;
	dst->ll = calloc(src->nll, sizeof *dst->ll);
	if (!dst->ll)
		return -ENOMEM;
	dst->nll = src->nll;
	for (int i = 0; i < src->nll; i++) {
		dst->ll[i] = src->ll[i];
		dst->ll[i].path = strdup(src->ll[i].path);
		if (!dst->ll[i].path)
			return -ENOMEM;
	}
	return 0;
}

/* Deep copy of the spec itself (no text round trip, so no value can change meaning). */
juno_spec *juno_spec_dup(const juno_spec *spec)
{
	juno_spec *copy = malloc(sizeof *copy);
	int argc = 0;

	if (!copy)
		return NULL;
	*copy = *spec;
	copy->root_path = spec->root_path ? strdup(spec->root_path) : NULL;
	copy->cwd = spec->cwd ? strdup(spec->cwd) : NULL;
	copy->hostname = spec->hostname ? strdup(spec->hostname) : NULL;
	copy->netname = spec->netname ? strdup(spec->netname) : NULL;

	/* from here on the copy owns nothing it shares with the original */
	copy->mounts = NULL;
	copy->ll = NULL;
	copy->fds = NULL;
	copy->layers = copy->argv = copy->env = NULL;
	copy->egress_deny = copy->egress_allow = copy->proxy_allow = copy->pubs = NULL;
	copy->nfds = 0;
	copy->nmounts = copy->nll = 0;
	copy->stdio[0] = copy->stdio[1] = copy->stdio[2] = -1;

	if ((spec->root_path && !copy->root_path) || (spec->cwd && !copy->cwd) ||
	    (spec->hostname && !copy->hostname) || (spec->netname && !copy->netname))
		goto fail;

#define COPY_LIST(field, count) \
	do { \
		if (spec->count && copy_strv(&copy->field, spec->field, spec->count)) \
			goto fail; \
	} while (0)
	COPY_LIST(layers, nlayers);
	COPY_LIST(env, nenv);
	COPY_LIST(egress_deny, n_deny);
	COPY_LIST(egress_allow, n_allow);
	COPY_LIST(proxy_allow, nproxy);
	COPY_LIST(pubs, npubs);
#undef COPY_LIST

	if (spec->argv) {
		while (spec->argv[argc])
			argc++;
		if (copy_strv(&copy->argv, spec->argv, argc))
			goto fail;
	}
	if (dup_mounts(copy, spec) || dup_landlock(copy, spec))
		goto fail;
	return copy;

fail:
	juno_spec_free(copy);
	return NULL;
}

int juno_spec_set_compat32(juno_spec *spec, int allow)
{
#ifdef __x86_64__
	spec->compat32 = !!allow;
	return 0;
#else
	(void)spec;
	if (allow) {
		juno_seterr("compat32 is only available on x86_64");
		return -ENOTSUP;
	}
	return 0;
#endif
}

int juno_spec_set_tty(juno_spec *spec, int on)
{
	spec->tty = !!on;
	return 0;
}

int juno_spec_set_idmap_full(juno_spec *spec, int full)
{
	spec->idmap_full = !!full;
	return 0;
}

int juno_spec_set_user(juno_spec *spec, int uid, int gid)
{
	if (uid < 0 || uid > MAX_ID || gid > MAX_ID)
		return -EINVAL;
	spec->user_set = true;
	spec->uid = uid;
	spec->gid = gid < 0 ? uid : gid;
	return 0;
}

/* a.b.c.d[/n] -> network order address and prefix length */
int juno_parse_cidr(const char *text, uint32_t *addr, int *plen)
{
	unsigned a, b, c, d, prefix = 32;
	char trailing;
	int matched = sscanf(text, "%u.%u.%u.%u/%u%c", &a, &b, &c, &d, &prefix, &trailing);

	if (matched != 5 && (matched = sscanf(text, "%u.%u.%u.%u%c", &a, &b, &c, &d, &trailing)) != 4)
		return -EINVAL;
	if (a > 255 || b > 255 || c > 255 || d > 255 || prefix > 32)
		return -EINVAL;
	*addr = htonl(a << 24 | b << 16 | c << 8 | d);
	*plen = prefix;
	return 0;
}

int juno_spec_add_egress(juno_spec *spec, int allow, const char *cidr)
{
	uint32_t addr;
	int plen;
	char *copy;

	if (!cidr || juno_parse_cidr(cidr, &addr, &plen))
		return -EINVAL;
	copy = strdup(cidr);
	if (!copy)
		return -ENOMEM;
	if (allow)
		return juno_append(&spec->egress_allow, &spec->n_allow, copy) ? -ENOMEM : 0;
	return juno_append(&spec->egress_deny, &spec->n_deny, copy) ? -ENOMEM : 0;
}

/* HOST:PORT, host case-insensitive, optional leading "*." */
int juno_spec_add_proxy_allow(juno_spec *spec, const char *host_port)
{
	const char *colon = host_port ? strrchr(host_port, ':') : NULL;
	char *end, *copy;
	long port;

	if (!colon || colon == host_port || strlen(host_port) > MAX_PROXY_ENTRY_LEN)
		return -EINVAL;
	port = strtol(colon + 1, &end, 10);
	if (*end || port < 1 || port > MAX_PORT)
		return -EINVAL;
	for (const char *p = host_port; p < colon; p++) {
		if ((unsigned char)*p <= ' ' || *p == '/')
			return -EINVAL;
	}

	copy = strdup(host_port);
	if (!copy)
		return -ENOMEM;
	for (char *p = copy; p < copy + (colon - host_port); p++) {
		if (*p >= 'A' && *p <= 'Z')
			*p += 'a' - 'A';
	}
	return juno_append(&spec->proxy_allow, &spec->nproxy, copy) ? -ENOMEM : 0;
}
