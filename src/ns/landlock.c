/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "ns.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int ns_landlock_abi(void)
{
#ifdef __NR_landlock_create_ruleset
	long version = syscall(__NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);

	return version < 0 ? -errno : (int)version;
#else
	return -ENOSYS;
#endif
}

#ifdef __NR_landlock_create_ruleset
#define FILE_RIGHTS (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | \
	LANDLOCK_ACCESS_FS_WRITE_FILE)

/* ABI 1 rights: bits 0..12, EXECUTE through MAKE_SYM */
#define ABI1_FS_RIGHTS 0x1fffull

static unsigned long long handled_for(int abi)
{
	unsigned long long handled = ABI1_FS_RIGHTS;

	if (abi >= 2)
		handled |= LANDLOCK_ACCESS_FS_REFER;
	if (abi >= 3)
		handled |= LANDLOCK_ACCESS_FS_TRUNCATE;
#ifdef LANDLOCK_ACCESS_FS_IOCTL_DEV
	if (abi >= 5)
		handled |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
#endif
	return handled;
}

/* rights that make sense on a non-directory */
static unsigned long long file_only_rights(void)
{
	unsigned long long rights = FILE_RIGHTS | LANDLOCK_ACCESS_FS_TRUNCATE;

#ifdef LANDLOCK_ACCESS_FS_IOCTL_DEV
	rights |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
#endif
	return rights;
}

/* Add one rule; on failure close the ruleset and describe the step in why. */
static int add_path_rule(int ruleset_fd, const juno_spec *spec, int index,
	unsigned long long read_only, unsigned long long all, char *why, size_t why_len)
{
	const struct juno_ll *entry = &spec->ll[index];
	unsigned long long access = (entry->access & JUNO_LL_WRITE) ? all : read_only;
	struct landlock_path_beneath_attr rule;
	struct stat st;
	int saved;
	long rc;
	int fd;

	fd = open(entry->path, O_PATH | O_CLOEXEC);
	if (fd < 0 && errno == ENOENT && (entry->access & JUNO_LL_OPTIONAL))
		return 0;
	if (fd < 0) {
		saved = errno;
		close(ruleset_fd);
		ns_fmt(why, why_len, "path %s", entry->path);
		return -saved;
	}

	if (fstat(fd, &st) == 0 && !S_ISDIR(st.st_mode))
		access &= file_only_rights();

	rule.allowed_access = access & all;
	rule.parent_fd = fd;
	rc = syscall(__NR_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &rule, 0);
	saved = errno;
	close(fd);
	if (rc < 0) {
		close(ruleset_fd);
		ns_fmt(why, why_len, "rule %s", entry->path);
		return -saved;
	}
	return 0;
}

/* the cell's own init must stay executable */
static void allow_cell_init(int ruleset_fd, unsigned long long all)
{
	int fd = open(NS_INIT_IN_CELL, O_PATH | O_CLOEXEC);
	struct landlock_path_beneath_attr rule;

	if (fd < 0)
		return;
	rule.allowed_access = (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE) & all;
	rule.parent_fd = fd;
	syscall(__NR_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &rule, 0);
	close(fd);
}
#endif

int ns_landlock_apply(const juno_spec *spec, char *why, size_t why_len)
{
#ifdef __NR_landlock_create_ruleset
	if (!spec->nll)
		return 0;

	int abi = ns_landlock_abi();
	if (abi < 1) {
		ns_fmt(why, why_len, "unavailable");
		return abi < 0 ? abi : -ENOSYS;
	}

	unsigned long long all = handled_for(abi);
	unsigned long long read_only = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE |
		LANDLOCK_ACCESS_FS_READ_DIR;
	struct landlock_ruleset_attr attr = { .handled_access_fs = all };
	int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr, sizeof attr, 0);

	if (ruleset_fd < 0)
		return -errno;

	for (int i = 0; i < spec->nll; i++) {
		int err = add_path_rule(ruleset_fd, spec, i, read_only, all, why, why_len);

		if (err)
			return err;
	}
	if (spec->init == JUNO_INIT_TINY)
		allow_cell_init(ruleset_fd, all);

	long rc = syscall(__NR_landlock_restrict_self, ruleset_fd, 0);
	int saved = errno;

	close(ruleset_fd);
	return rc < 0 ? -saved : 0;
#else
	return spec->nll ? -ENOSYS : 0;
#endif
}
