/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "internal.h"
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE (8u << 20)
#define MAX_RESTARTS_LIMIT 1000000
#define MAX_TIMEOUT_SECONDS 3.0e8
#define MAX_SIZE_VALUE (1ull << 50)
#define NUM_CAPS 64

/* Splits a shell-like quoted word list: 'single', "double" with \\ escapes, \x outside. */
static int shell_split(const char *text, char ***out, int *count)
{
	char *word = malloc(strlen(text) + 1);

	if (!word)
		return -ENOMEM;
	*out = NULL;
	*count = 0;

	for (;;) {
		size_t len = 0;
		char *copy;

		while (isspace((unsigned char)*text))
			text++;
		if (!*text)
			break;

		while (*text && !isspace((unsigned char)*text)) {
			if (*text == '\'') {
				const char *close = strchr(text + 1, '\'');

				if (!close)
					goto bad;
				memcpy(word + len, text + 1, close - text - 1);
				len += close - text - 1;
				text = close + 1;
			} else if (*text == '"') {
				for (text++; *text != '"'; text++) {
					if (!*text)
						goto bad;
					if (*text == '\\' && text[1])
						text++;
					word[len++] = *text;
				}
				text++;
			} else {
				if (*text == '\\' && text[1])
					text++;
				word[len++] = *text++;
			}
		}
		word[len] = 0;

		copy = strdup(word);
		if (!copy || juno_append(out, count, copy))
			goto bad;
	}
	free(word);
	return *count ? 0 : -EINVAL;

bad:
	free(word);
	for (int i = 0; i < *count; i++)
		free((*out)[i]);
	free(*out);
	*out = NULL;
	*count = 0;
	return -EINVAL;
}

static void put_quoted(FILE *fp, const char *arg)
{
	if (*arg && !strpbrk(arg, " \t\n'\"\\#$&;|<>()*?[]{}~`!")) {
		fputs(arg, fp);
		return;
	}
	fputc('\'', fp);
	for (; *arg; arg++) {
		if (*arg == '\'')
			fputs("'\\''", fp);
		else
			fputc(*arg, fp);
	}
	fputc('\'', fp);
}

static int parse_number(const char *value, uint64_t *out)
{
	char *end;

	errno = 0;
	if (!*value || *value == '-')
		return -EINVAL;
	*out = strtoull(value, &end, 0);
	return (*end || errno) ? -EINVAL : 0;
}

/* bytes, with an optional K, M or G suffix */
static int parse_size(const char *value, uint64_t *out)
{
	unsigned long long number, multiplier = 1;
	char *end;

	errno = 0;
	if (!*value || *value == '-')
		return -EINVAL;
	number = strtoull(value, &end, 10);
	if (errno || end == value)
		return -EINVAL;

	if (*end == 'k' || *end == 'K') {
		multiplier = 1ull << 10;
		end++;
	} else if (*end == 'm' || *end == 'M') {
		multiplier = 1ull << 20;
		end++;
	} else if (*end == 'g' || *end == 'G') {
		multiplier = 1ull << 30;
		end++;
	}
	if (*end || number > MAX_SIZE_VALUE / multiplier)
		return -EINVAL;
	*out = number * multiplier;
	return 0;
}

static int split_bind(juno_spec *spec, const char *arg, unsigned flags)
{
	char *copy = strdup(arg);
	char *colon = copy ? strchr(copy, ':') : NULL;
	int rc = -EINVAL;

	if (colon) {
		*colon = 0;
		rc = juno_spec_add_mount(spec, JUNO_MOUNT_BIND, copy, colon + 1, flags);
	}
	free(copy);
	return rc;
}

/* One handler per spec key; each returns 0 or -errno and the caller reports the bad value. */

static int opt_root(juno_spec *spec, const char *value)
{
	if (!strcmp(value, "host-ro"))
		return juno_spec_set_root(spec, JUNO_ROOT_HOST_RO, NULL);
	if (!strncmp(value, "dir:", 4))
		return juno_spec_set_root(spec, JUNO_ROOT_DIR, value + 4);
	if (!strcmp(value, "overlay"))
		return juno_spec_set_root(spec, JUNO_ROOT_OVERLAY, NULL);
	if (!strncmp(value, "overlay:", 8))
		return juno_spec_set_root(spec, JUNO_ROOT_OVERLAY, value + 8);
	return -EINVAL;
}

static int opt_layer(juno_spec *spec, const char *value) { return juno_spec_add_layer(spec, value); }
static int opt_bind(juno_spec *spec, const char *value) { return split_bind(spec, value, 0); }
static int opt_bind_ro(juno_spec *spec, const char *value) { return split_bind(spec, value, JUNO_MNT_RO); }

static int opt_tmpfs(juno_spec *spec, const char *value)
{
	return juno_spec_add_mount(spec, JUNO_MOUNT_TMPFS, NULL, value, 0);
}

static int opt_net(juno_spec *spec, const char *value)
{
	if (!strcmp(value, "none"))
		return juno_spec_set_net(spec, JUNO_NET_NONE, NULL);
	if (!strcmp(value, "host"))
		return juno_spec_set_net(spec, JUNO_NET_HOST, NULL);
	if (!strncmp(value, "shared:", 7))
		return juno_spec_set_net(spec, JUNO_NET_SHARED, value + 7);
	if (!strcmp(value, "nat"))
		return juno_spec_set_net(spec, JUNO_NET_NAT, NULL);
	if (!strcmp(value, "nat:host"))
		return juno_spec_set_net(spec, JUNO_NET_NAT, "host");
	if (!strcmp(value, "nat:lan"))
		return juno_spec_set_net(spec, JUNO_NET_NAT, "lan");
	return -EINVAL;
}

static int opt_hostname(juno_spec *spec, const char *value) { return juno_spec_set_hostname(spec, value); }

static int opt_env(juno_spec *spec, const char *value)
{
	char *copy = strdup(value);
	char *equals = copy ? strchr(copy, '=') : NULL;
	int rc = -EINVAL;

	if (equals) {
		*equals = 0;
		rc = juno_spec_set_env(spec, copy, equals + 1);
	}
	free(copy);
	return rc;
}

static int opt_cwd(juno_spec *spec, const char *value) { return juno_spec_set_cwd(spec, value); }

static int set_numeric_limit(juno_spec *spec, int which, const char *value)
{
	uint64_t number;
	int rc = parse_number(value, &number);

	return rc ?: juno_spec_set_limit(spec, which, number);
}

static int opt_mem(juno_spec *spec, const char *value) { return set_numeric_limit(spec, JUNO_LIMIT_MEMORY, value); }
static int opt_pids(juno_spec *spec, const char *value) { return set_numeric_limit(spec, JUNO_LIMIT_PIDS, value); }
static int opt_nofile(juno_spec *spec, const char *value) { return set_numeric_limit(spec, JUNO_LIMIT_NOFILE, value); }
static int opt_cpu_weight(juno_spec *spec, const char *value)
{
	return set_numeric_limit(spec, JUNO_LIMIT_CPU_WEIGHT, value);
}

static int opt_timeout(juno_spec *spec, const char *value)
{
	char *end;
	double seconds = strtod(value, &end);

	/* finite and bounded: no nan, no inf, no value that overflows the millisecond counter */
	if (*end || !*value || !(seconds >= 0) || seconds > MAX_TIMEOUT_SECONDS)
		return -EINVAL;
	return juno_spec_set_limit(spec, JUNO_LIMIT_TIMEOUT_MS, (uint64_t)(seconds * 1000 + 0.5));
}

static int opt_seccomp(juno_spec *spec, const char *value)
{
	if (!strcmp(value, "default"))
		return juno_spec_set_seccomp(spec, JUNO_SECCOMP_DEFAULT);
	if (!strcmp(value, "strict"))
		return juno_spec_set_seccomp(spec, JUNO_SECCOMP_STRICT);
	if (!strcmp(value, "off"))
		return juno_spec_set_seccomp(spec, JUNO_SECCOMP_OFF);
	return -EINVAL;
}

static int opt_keep_cap(juno_spec *spec, const char *value)
{
	int cap = juno_cap_from_name(value);

	return cap < 0 ? cap : juno_spec_keep_cap(spec, cap);
}

static int opt_landlock_ro(juno_spec *spec, const char *value)
{
	return juno_spec_add_landlock(spec, value, JUNO_LL_READ);
}

static int opt_landlock_rw(juno_spec *spec, const char *value)
{
	return juno_spec_add_landlock(spec, value, JUNO_LL_READ | JUNO_LL_WRITE);
}

static int opt_landlock_ro_opt(juno_spec *spec, const char *value)
{
	return juno_spec_add_landlock(spec, value, JUNO_LL_READ | JUNO_LL_OPTIONAL);
}

static int opt_landlock_rw_opt(juno_spec *spec, const char *value)
{
	return juno_spec_add_landlock(spec, value, JUNO_LL_READ | JUNO_LL_WRITE | JUNO_LL_OPTIONAL);
}

static int opt_mem_fallback(juno_spec *spec, const char *value)
{
	if (!strcmp(value, "rlimit"))
		spec->mem_fallback = true;
	else if (!strcmp(value, "none"))
		spec->mem_fallback = false;
	else
		return -EINVAL;
	return 0;
}

static int opt_tmp_size(juno_spec *spec, const char *value) { return parse_size(value, &spec->tmp_size); }
static int opt_run_size(juno_spec *spec, const char *value) { return parse_size(value, &spec->run_size); }
static int opt_shm_size(juno_spec *spec, const char *value) { return parse_size(value, &spec->shm_size); }
static int opt_tmpfs_size(juno_spec *spec, const char *value) { return parse_size(value, &spec->tmpfs_size); }
static int opt_log_max(juno_spec *spec, const char *value) { return parse_size(value, &spec->log_max); }

static int opt_egress_deny(juno_spec *spec, const char *value) { return juno_spec_add_egress(spec, 0, value); }
static int opt_egress_allow(juno_spec *spec, const char *value) { return juno_spec_add_egress(spec, 1, value); }
static int opt_proxy_allow(juno_spec *spec, const char *value) { return juno_spec_add_proxy_allow(spec, value); }

static int opt_idmap(juno_spec *spec, const char *value)
{
	if (!strcmp(value, "full"))
		return juno_spec_set_idmap_full(spec, 1);
	if (!strcmp(value, "single"))
		return juno_spec_set_idmap_full(spec, 0);
	return -EINVAL;
}

/* UID or UID:GID */
static int opt_user(juno_spec *spec, const char *value)
{
	char *end;
	long uid = strtol(value, &end, 10);
	long gid = -1;

	if (end == value || uid < 0)
		return -EINVAL;
	if (*end == ':') {
		char *gid_end;

		gid = strtol(end + 1, &gid_end, 10);
		if (gid_end == end + 1 || *gid_end)
			return -EINVAL;
	} else if (*end) {
		return -EINVAL;
	}
	return juno_spec_set_user(spec, (int)uid, (int)gid);
}

static int opt_preset(juno_spec *spec, const char *value) { return juno_spec_apply_preset(spec, value); }

static int opt_init(juno_spec *spec, const char *value)
{
	if (!strcmp(value, "tiny"))
		return juno_spec_set_init(spec, JUNO_INIT_TINY);
	if (!strcmp(value, "none"))
		return juno_spec_set_init(spec, JUNO_INIT_NONE);
	return -EINVAL;
}

static int opt_nesting(juno_spec *spec, const char *value)
{
	if (!strcmp(value, "allow"))
		return juno_spec_set_nesting(spec, 1);
	if (!strcmp(value, "deny"))
		return juno_spec_set_nesting(spec, 0);
	return -EINVAL;
}

static int opt_compat32(juno_spec *spec, const char *value)
{
	if (!strcmp(value, "yes"))
		return juno_spec_set_compat32(spec, 1);
	if (!strcmp(value, "no"))
		return juno_spec_set_compat32(spec, 0);
	return -EINVAL;
}

static int opt_publish(juno_spec *spec, const char *value) { return juno_spec_add_publish(spec, value); }

static int opt_restart(juno_spec *spec, const char *value)
{
	if (!strcmp(value, "no"))
		return juno_spec_set_restart(spec, JUNO_RESTART_NO, spec->max_restarts);
	if (!strcmp(value, "on-failure"))
		return juno_spec_set_restart(spec, JUNO_RESTART_ON_FAILURE, spec->max_restarts);
	if (!strcmp(value, "always"))
		return juno_spec_set_restart(spec, JUNO_RESTART_ALWAYS, spec->max_restarts);
	return -EINVAL;
}

static int opt_max_restarts(juno_spec *spec, const char *value)
{
	uint64_t number;

	if (parse_number(value, &number) || number > MAX_RESTARTS_LIMIT)
		return -EINVAL;
	return juno_spec_set_restart(spec, spec->restart, (int)number);
}

static int opt_argv(juno_spec *spec, const char *value)
{
	char **words;
	int count;
	int rc = shell_split(value, &words, &count);

	if (rc)
		return rc;
	rc = juno_spec_set_argv(spec, words);
	for (int i = 0; i < count; i++)
		free(words[i]);
	free(words);
	return rc;
}

static const struct spec_option {
	const char *key;
	int (*handler)(juno_spec *spec, const char *value);
} spec_options[] = {
	{ "root", opt_root }, { "layer", opt_layer }, { "bind", opt_bind }, { "bind-ro", opt_bind_ro },
	{ "tmpfs", opt_tmpfs }, { "net", opt_net }, { "hostname", opt_hostname }, { "env", opt_env },
	{ "cwd", opt_cwd }, { "mem", opt_mem }, { "pids", opt_pids }, { "nofile", opt_nofile },
	{ "cpu-weight", opt_cpu_weight }, { "timeout", opt_timeout }, { "seccomp", opt_seccomp },
	{ "keep-cap", opt_keep_cap }, { "landlock-ro", opt_landlock_ro }, { "landlock-rw", opt_landlock_rw },
	{ "landlock-ro-opt", opt_landlock_ro_opt }, { "landlock-rw-opt", opt_landlock_rw_opt },
	{ "mem-fallback", opt_mem_fallback }, { "tmp-size", opt_tmp_size }, { "run-size", opt_run_size },
	{ "shm-size", opt_shm_size }, { "tmpfs-size", opt_tmpfs_size }, { "log-max", opt_log_max },
	{ "egress-deny", opt_egress_deny }, { "egress-allow", opt_egress_allow },
	{ "egress-proxy-allow", opt_proxy_allow }, { "idmap", opt_idmap }, { "user", opt_user },
	{ "preset", opt_preset }, { "init", opt_init }, { "nesting", opt_nesting },
	{ "compat32", opt_compat32 }, { "publish", opt_publish }, { "restart", opt_restart },
	{ "max-restarts", opt_max_restarts }, { "argv", opt_argv },
};

int juno_spec_set_option(juno_spec *spec, const char *key, const char *value)
{
	int (*handler)(juno_spec *, const char *) = NULL;
	int rc;

	if (strlen(value) > JUNO_MAX_VALUE) {
		juno_seterr("value of '%s' is longer than %u bytes", key, (unsigned)JUNO_MAX_VALUE);
		return -E2BIG;
	}

	for (size_t i = 0; i < sizeof spec_options / sizeof *spec_options; i++) {
		if (!strcmp(key, spec_options[i].key)) {
			handler = spec_options[i].handler;
			break;
		}
	}
	/* workspace = DIR and broker = SOCKET belong to the agent preset */
	if (!handler && (!strcmp(key, "workspace") || !strcmp(key, "broker"))) {
		rc = juno_preset_param(spec, key, value);
	} else if (!handler) {
		juno_seterr("unknown key '%s'", key);
		return -EINVAL;
	} else {
		rc = handler(spec, value);
	}

	if (rc)
		juno_seterr("bad value for '%s': '%s'", key, value);
	return rc;
}

/* \\ \n \r \xHH; anything else keeps its backslash */
static void unescape(char *value)
{
	char *out = value;

	for (char *p = value; *p; p++) {
		if (*p != '\\' || !p[1]) {
			*out++ = *p;
			continue;
		}
		p++;
		if (*p == '\\') {
			*out++ = '\\';
		} else if (*p == 'n') {
			*out++ = '\n';
		} else if (*p == 'r') {
			*out++ = '\r';
		} else if (*p == 'x' && isxdigit((unsigned char)p[1]) && isxdigit((unsigned char)p[2])) {
			char hex[3] = { p[1], p[2], 0 };
			char ch = (char)strtol(hex, NULL, 16);

			if (ch)
				*out++ = ch;
			p += 2;
		} else {
			*out++ = '\\';
			*out++ = *p;
		}
	}
	*out = 0;
}

int juno_spec_read(FILE *fp, const char *label, juno_spec **out)
{
	char *line = NULL;
	size_t cap = 0;
	ssize_t got;
	int line_no = 0, rc = 0;
	juno_spec *spec = juno_spec_new();

	if (!spec)
		return -ENOMEM;

	while ((got = getline(&line, &cap, fp)) >= 0) {
		char *key, *equals, *key_end, *value, *end;
		char option_error[480];

		line_no++;
		if ((size_t)got > MAX_LINE) {
			juno_seterr("%s:%d: line longer than %u bytes", label, line_no, MAX_LINE);
			rc = -E2BIG;
			break;
		}

		key = line;
		while (isspace((unsigned char)*key))
			key++;
		if (!*key || *key == '#')
			continue;
		key[strcspn(key, "\n")] = 0;
		end = key + strlen(key);
		while (end > key && isspace((unsigned char)end[-1]))
			*--end = 0;

		equals = strchr(key, '=');
		if (!equals) {
			juno_seterr("%s:%d: expected 'key = value'", label, line_no);
			rc = -EINVAL;
			break;
		}
		key_end = equals;
		while (key_end > key && isspace((unsigned char)key_end[-1]))
			key_end--;
		*key_end = 0;
		value = equals + 1;
		while (isspace((unsigned char)*value))
			value++;
		if (!*key) {
			juno_seterr("%s:%d: empty key", label, line_no);
			rc = -EINVAL;
			break;
		}

		unescape(value);
		if (juno_spec_set_option(spec, key, value)) {
			snprintf(option_error, sizeof option_error, "%s", juno_error());
			juno_seterr("%s:%d: %s", label, line_no, option_error);
			rc = -EINVAL;
			break;
		}
	}
	free(line);

	if (rc) {
		juno_spec_free(spec);
		return rc;
	}
	*out = spec;
	return 0;
}

int juno_spec_load(const char *path, juno_spec **out)
{
	FILE *fp = fopen(path, "re");
	int rc;

	if (!fp) {
		juno_seterr("%s: %s", path, strerror(errno));
		return -errno;
	}
	rc = juno_spec_read(fp, path, out);
	fclose(fp);
	return rc;
}

/* values are escaped so that no value can change the meaning of another line */
static void put_escaped(FILE *fp, const char *value)
{
	size_t len = strlen(value);

	for (size_t i = 0; i < len; i++) {
		unsigned char ch = value[i];

		if (ch == '\\')
			fputs("\\\\", fp);
		else if (ch == '\n')
			fputs("\\n", fp);
		else if (ch == '\r')
			fputs("\\r", fp);
		else if (ch < 0x20 || ch == 0x7f || (ch == ' ' && (i == 0 || i + 1 == len)))
			fprintf(fp, "\\x%02x", ch);
		else
			fputc(ch, fp);
	}
}

static void put_key_value(FILE *fp, const char *key, const char *value)
{
	fprintf(fp, "%s = ", key);
	put_escaped(fp, value);
	fputc('\n', fp);
}

static void write_root(const juno_spec *spec, FILE *fp)
{
	if (spec->root_kind == JUNO_ROOT_HOST_RO) {
		fputs("root = host-ro\n", fp);
	} else if (spec->root_kind == JUNO_ROOT_DIR) {
		fputs("root = dir:", fp);
		put_escaped(fp, spec->root_path);
		fputc('\n', fp);
	} else if (spec->root_path) {
		fputs("root = overlay:", fp);
		put_escaped(fp, spec->root_path);
		fputc('\n', fp);
	} else {
		fputs("root = overlay\n", fp);
	}
}

static void write_mounts(const juno_spec *spec, FILE *fp)
{
	for (int i = 0; i < spec->nlayers; i++)
		put_key_value(fp, "layer", spec->layers[i]);

	for (int i = 0; i < spec->nmounts; i++) {
		const struct juno_mount *mount = &spec->mounts[i];

		if (mount->kind == JUNO_MOUNT_TMPFS) {
			put_key_value(fp, "tmpfs", mount->dst);
			continue;
		}
		fprintf(fp, "%s = ", mount->flags & JUNO_MNT_RO ? "bind-ro" : "bind");
		put_escaped(fp, mount->src);
		fputc(':', fp);
		put_escaped(fp, mount->dst);
		fputc('\n', fp);
	}
}

static void write_net(const juno_spec *spec, FILE *fp)
{
	if (spec->net == JUNO_NET_SHARED) {
		fputs("net = shared:", fp);
		put_escaped(fp, spec->netname);
		fputc('\n', fp);
	} else if (spec->net == JUNO_NET_NAT) {
		fprintf(fp, "net = %s\n", spec->nat_host ? "nat:host" : spec->nat_lan ? "nat:lan" : "nat");
	} else {
		fprintf(fp, "net = %s\n", spec->net == JUNO_NET_HOST ? "host" : "none");
	}
}

static void write_limits(const juno_spec *spec, FILE *fp)
{
	static const struct { int id; const char *key; } limits[] = {
		{ JUNO_LIMIT_MEMORY, "mem" }, { JUNO_LIMIT_PIDS, "pids" }, { JUNO_LIMIT_NOFILE, "nofile" },
		{ JUNO_LIMIT_CPU_WEIGHT, "cpu-weight" },
	};

	for (size_t i = 0; i < sizeof limits / sizeof *limits; i++) {
		if (spec->limit_set[limits[i].id])
			fprintf(fp, "%s = %llu\n", limits[i].key, (unsigned long long)spec->limit[limits[i].id]);
	}
	if (spec->limit_set[JUNO_LIMIT_TIMEOUT_MS])
		fprintf(fp, "timeout = %.3f\n", spec->limit[JUNO_LIMIT_TIMEOUT_MS] / 1000.0);
	if (spec->mem_fallback)
		fputs("mem-fallback = rlimit\n", fp);
	if (spec->tmp_size)
		fprintf(fp, "tmp-size = %llu\n", (unsigned long long)spec->tmp_size);
	if (spec->run_size)
		fprintf(fp, "run-size = %llu\n", (unsigned long long)spec->run_size);
	if (spec->shm_size)
		fprintf(fp, "shm-size = %llu\n", (unsigned long long)spec->shm_size);
	if (spec->tmpfs_size)
		fprintf(fp, "tmpfs-size = %llu\n", (unsigned long long)spec->tmpfs_size);
	if (spec->log_max)
		fprintf(fp, "log-max = %llu\n", (unsigned long long)spec->log_max);
}

static void write_argv(const juno_spec *spec, FILE *fp)
{
	char *text = NULL;
	size_t text_len = 0;
	FILE *mem;

	if (!spec->argv)
		return;
	/* the quoted word list is escaped like any other value */
	mem = open_memstream(&text, &text_len);
	if (!mem)
		return;
	for (char **arg = spec->argv; *arg; arg++) {
		if (arg != spec->argv)
			fputc(' ', mem);
		put_quoted(mem, *arg);
	}
	fclose(mem);
	put_key_value(fp, "argv", text);
	free(text);
}

int juno_spec_write(const juno_spec *spec, FILE *fp)
{
	static const char *const seccomp_names[] = { "default", "strict", "off" };
	char key[64];

	write_root(spec, fp);
	write_mounts(spec, fp);
	write_net(spec, fp);
	if (spec->hostname)
		put_key_value(fp, "hostname", spec->hostname);
	for (int i = 0; i < spec->nenv; i++)
		put_key_value(fp, "env", spec->env[i]);
	if (spec->cwd)
		put_key_value(fp, "cwd", spec->cwd);
	write_limits(spec, fp);

	fprintf(fp, "seccomp = %s\n", seccomp_names[spec->seccomp]);
	for (int cap = 0; cap < NUM_CAPS; cap++) {
		if (spec->keepcaps >> cap & 1)
			fprintf(fp, "keep-cap = %d\n", cap);
	}
	for (int i = 0; i < spec->nll; i++) {
		snprintf(key, sizeof key, "landlock-%s%s", spec->ll[i].access & JUNO_LL_WRITE ? "rw" : "ro",
			 spec->ll[i].access & JUNO_LL_OPTIONAL ? "-opt" : "");
		put_key_value(fp, key, spec->ll[i].path);
	}

	fprintf(fp, "init = %s\n", spec->init == JUNO_INIT_NONE ? "none" : "tiny");
	fprintf(fp, "nesting = %s\n", spec->nesting ? "allow" : "deny");
	fprintf(fp, "compat32 = %s\n", spec->compat32 ? "yes" : "no");
	for (int i = 0; i < spec->n_deny; i++)
		put_key_value(fp, "egress-deny", spec->egress_deny[i]);
	for (int i = 0; i < spec->n_allow; i++)
		put_key_value(fp, "egress-allow", spec->egress_allow[i]);
	for (int i = 0; i < spec->nproxy; i++)
		put_key_value(fp, "egress-proxy-allow", spec->proxy_allow[i]);
	fprintf(fp, "idmap = %s\n", spec->idmap_full ? "full" : "single");
	if (spec->user_set)
		fprintf(fp, "user = %d:%d\n", spec->uid, spec->gid);
	for (int i = 0; i < spec->npubs; i++)
		put_key_value(fp, "publish", spec->pubs[i]);

	fprintf(fp, "restart = %s\n", spec->restart == JUNO_RESTART_ALWAYS ? "always" :
		spec->restart == JUNO_RESTART_ON_FAILURE ? "on-failure" : "no");
	fprintf(fp, "max-restarts = %d\n", spec->max_restarts);
	write_argv(spec, fp);
	return ferror(fp) ? -EIO : 0;
}

int juno_spec_save(const juno_spec *spec, const char *path)
{
	FILE *fp = fopen(path, "we");
	int rc;

	if (!fp) {
		juno_seterr("%s: %s", path, strerror(errno));
		return -errno;
	}
	rc = juno_spec_write(spec, fp);
	if (fclose(fp) && !rc)
		rc = -EIO;
	return rc;
}

int juno_spec_save_at(const juno_spec *spec, int dir_fd, const char *name)
{
	char *text = NULL;
	size_t text_len = 0;
	FILE *mem = open_memstream(&text, &text_len);
	int rc;

	if (!mem)
		return -ENOMEM;
	rc = juno_spec_write(spec, mem);
	fclose(mem);
	if (!rc)
		rc = juno_put_file_at(dir_fd, name, text, text_len);
	free(text);
	return rc;
}
