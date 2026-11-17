/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "ns.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <net/if.h>
#include <sched.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY 1
#endif
#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif

#define NAME_MAX_COMPONENT 256
#define STAGE_PATH_MAX 4200

/* Step into one path component of dir_fd, creating it. Returns the new fd or -1 with errno set. */
static int open_component(int dir_fd, const char *name, int is_last, int is_file)
{
	int fd;

	if (is_last && is_file) {
		fd = openat(dir_fd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
		if (fd < 0 && errno == ENOENT) {
			int created = openat(dir_fd, name, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0644);

			if (created >= 0) {
				close(created);
				fd = openat(dir_fd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
			}
		}
	} else {
		if (mkdirat(dir_fd, name, 0755) < 0 && errno != EEXIST)
			return -1;
		fd = openat(dir_fd, name, O_PATH | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC);
	}
	return fd;
}

/* Open (creating) rel below root_fd one component at a time, refusing symlinks,
 * so a hostile rootfs cannot redirect a mount outside itself. */
int ns_open_in(int root_fd, const char *rel, int is_file)
{
	int cur = dup(root_fd);
	const char *pos = rel;

	if (cur < 0)
		return -1;
	for (;;) {
		char name[NAME_MAX_COMPONENT];
		const char *comp_end, *after;
		size_t comp_len;
		int fd, saved;

		while (*pos == '/')
			pos++;
		if (!*pos)
			break;

		comp_end = pos;
		while (*comp_end && *comp_end != '/')
			comp_end++;
		comp_len = comp_end - pos;
		if (comp_len >= sizeof name) {
			close(cur);
			errno = ENAMETOOLONG;
			return -1;
		}
		memcpy(name, pos, comp_len);
		name[comp_len] = 0;
		if (!strcmp(name, "..") || !strcmp(name, ".")) {
			close(cur);
			errno = EINVAL;
			return -1;
		}

		after = comp_end;
		while (*after == '/')
			after++;

		fd = open_component(cur, name, !*after, is_file);
		saved = errno;
		close(cur);
		if (fd < 0) {
			errno = saved;
			return -1;
		}
		cur = fd;
		pos = comp_end;
	}
	return cur;
}

static int mount_fd(const char *src, int target_fd, const char *type, unsigned long flags, const char *data)
{
	char path[64];

	ns_fmt(path, sizeof path, "/proc/self/fd/%d", target_fd);
	return mount(src, path, type, flags, data);
}

static int set_readonly(int root_fd, const char *rel, int is_file)
{
	struct mount_attr attr = { .attr_set = MOUNT_ATTR_RDONLY };
	int fd = ns_open_in(root_fd, rel, is_file);
	long rc;
	int saved;

	if (fd < 0)
		return -1;
	rc = syscall(SYS_mount_setattr, fd, "", AT_EMPTY_PATH | AT_RECURSIVE, &attr, sizeof attr);
	saved = errno;
	close(fd);
	errno = saved;
	return (int)rc;
}

/* mount src (or a fresh fs) at rel below root_fd */
int ns_mount_at(int root_fd, const char *src, const char *rel, const char *type,
	unsigned long flags, const char *data, int is_file, int readonly)
{
	int fd = ns_open_in(root_fd, rel, is_file);
	int rc, saved;

	if (fd < 0)
		return -1;
	rc = mount_fd(src, fd, type, flags, data);
	saved = errno;
	close(fd);
	if (rc < 0) {
		errno = saved;
		return -1;
	}
	return readonly ? set_readonly(root_fd, rel, is_file) : 0;
}

#define STEP(...) ns_die(ctx, __VA_ARGS__)

/* Create name in dir_fd with content; refuses to follow or overwrite anything. */
static int write_new_file(int dir_fd, const char *name, const char *content)
{
	int fd = openat(dir_fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
	size_t len = strlen(content);
	ssize_t written;

	if (fd < 0)
		return -1;
	written = write(fd, content, len);
	close(fd);
	return written == (ssize_t)len ? 0 : -1;
}

/* Only these host /etc entries are exposed, read-only, when they exist. */
static const char *const etc_binds[] = {
	"ld.so.cache", "ld.so.conf", "ld.so.conf.d", "alternatives", "ssl/certs",
	"ca-certificates", "localtime",
};

#define NAT_RESOLV "nameserver 10.0.2.3\n"

/* Recreate the usual top-level links, or bind the directories where the host has real ones. */
static void link_host_dirs(struct ns_ctx *ctx, int root_fd)
{
	static const char *const names[] = { "bin", "sbin", "lib", "lib32", "lib64", "libx32" };
	char host_path[64], target[512];
	struct stat st;

	for (size_t i = 0; i < sizeof names / sizeof *names; i++) {
		ns_fmt(host_path, sizeof host_path, "/%s", names[i]);
		if (lstat(host_path, &st) < 0)
			continue;
		if (S_ISLNK(st.st_mode)) {
			ssize_t len = readlink(host_path, target, sizeof target - 1);

			if (len < 0)
				STEP("readlink %s", host_path);
			target[len] = 0;
			if (symlinkat(target, root_fd, names[i]) < 0)
				STEP("symlink %s", host_path);
		} else if (ns_mount_at(root_fd, host_path, host_path, NULL, MS_BIND | MS_REC, NULL, 0, 1) < 0) {
			STEP("bind-ro host %s", host_path);
		}
	}
}

/* Generated /etc files plus the read-only host entries. */
static void populate_etc(struct ns_ctx *ctx, int root_fd, int etc_fd)
{
	char hostname_line[300];
	struct stat st;

	if (write_new_file(etc_fd, "passwd", ctx->passwd) < 0 ||
	    write_new_file(etc_fd, "group", ctx->group) < 0 ||
	    write_new_file(etc_fd, "nsswitch.conf", "passwd: files\ngroup: files\nhosts: files dns\n") < 0 ||
	    write_new_file(etc_fd, "hosts", ctx->hosts) < 0)
		STEP("write generated /etc files");
	ns_fmt(hostname_line, sizeof hostname_line, "%s\n", ctx->hostname);
	if (write_new_file(etc_fd, "hostname", hostname_line) < 0)
		STEP("write /etc/hostname");

	for (size_t i = 0; i < sizeof etc_binds / sizeof *etc_binds; i++) {
		char src[96], dst[96];

		ns_fmt(src, sizeof src, "/etc/%s", etc_binds[i]);
		if (stat(src, &st) < 0)
			continue;
		ns_fmt(dst, sizeof dst, "/etc/%s", etc_binds[i]);
		if (ns_mount_at(root_fd, src, dst, NULL, MS_BIND | MS_REC, NULL, !S_ISDIR(st.st_mode), 1) < 0)
			STEP("bind-ro host %s", src);
	}

	if (ctx->spec->net == JUNO_NET_NAT) {
		int fd = openat(etc_fd, "resolv.conf", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);

		if (fd < 0 || write(fd, NAT_RESOLV, sizeof NAT_RESOLV - 1) != sizeof NAT_RESOLV - 1)
			STEP("write /etc/resolv.conf");
		close(fd);
	}
	if (ctx->spec->net == JUNO_NET_HOST && stat("/etc/resolv.conf", &st) == 0 &&
	    ns_mount_at(root_fd, "/etc/resolv.conf", "/etc/resolv.conf", NULL, MS_BIND, NULL, 1, 1) < 0)
		STEP("bind-ro host /etc/resolv.conf");
}

static void host_ro_root(struct ns_ctx *ctx)
{
	int root_fd, etc_fd;

	if (mount("tmpfs", ctx->stage, "tmpfs", MS_NOSUID | MS_NODEV, "mode=755,size=4m") < 0)
		STEP("mount root tmpfs");
	root_fd = open(ctx->stage, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (root_fd < 0)
		STEP("open stage");

	if (ns_mount_at(root_fd, "/usr", "/usr", NULL, MS_BIND | MS_REC, NULL, 0, 1) < 0)
		STEP("bind-ro host /usr");
	link_host_dirs(ctx, root_fd);

	etc_fd = ns_open_in(root_fd, "/etc", 0);
	if (etc_fd < 0)
		STEP("create /etc");
	populate_etc(ctx, root_fd, etc_fd);
	close(etc_fd);
	close(root_fd);
}

/* overlay option strings use ',' and ':' as separators */
static void check_overlay_path(struct ns_ctx *ctx, const char *path, const char *what)
{
	if (strpbrk(path, ",:")) {
		errno = EINVAL;
		STEP("overlay %s %s", what, path);
	}
}

static void overlay_root(struct ns_ctx *ctx)
{
	const juno_spec *spec = ctx->spec;
	char opts[4096];
	size_t len;

	if (!spec->nlayers) {
		errno = EINVAL;
		STEP("overlay: no lower layer given");
	}
	len = ns_fmt(opts, sizeof opts, "lowerdir=");
	for (int i = 0; i < spec->nlayers; i++) {
		check_overlay_path(ctx, spec->layers[i], "layer");
		len += ns_fmt(opts + len, sizeof opts - len, "%s%s", i ? ":" : "", spec->layers[i]);
	}
	if (strpbrk(spec->root_path, ",:") || strpbrk(ctx->workdir, ",:")) {
		errno = EINVAL;
		STEP("overlay upper %s", spec->root_path);
	}
	len += ns_fmt(opts + len, sizeof opts - len, ",upperdir=%s,workdir=%s", spec->root_path, ctx->workdir);
	if (len + 12 >= sizeof opts) {
		errno = ENAMETOOLONG;
		STEP("overlay options");
	}

	if (mount("overlay", ctx->stage, "overlay", MS_NODEV | MS_NOSUID, opts) < 0) {
		/* unprivileged overlay needs user xattrs on some kernels */
		strcpy(opts + len, ",userxattr");
		if (mount("overlay", ctx->stage, "overlay", MS_NODEV | MS_NOSUID, opts) < 0)
			STEP("mount overlay (upper %s)", spec->root_path);
	}
}

int ns_net_up(void)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	int rc, saved;

	if (fd < 0)
		return -1;
	memset(&ifr, 0, sizeof ifr);
	strcpy(ifr.ifr_name, "lo");
	rc = ioctl(fd, SIOCGIFFLAGS, &ifr);
	if (rc == 0) {
		ifr.ifr_flags |= IFF_UP;
		rc = ioctl(fd, SIOCSIFFLAGS, &ifr);
	}
	saved = errno;
	close(fd);
	errno = saved;
	return rc;
}

/* A nat cell on a dir/overlay root without its own resolv.conf gets a generated one. */
static void bind_generated_resolv(struct ns_ctx *ctx, int root_fd)
{
	char src[STAGE_PATH_MAX];
	int run_fd = ns_open_in(root_fd, "/run", 0);
	int file_fd = -1;

	/* a file on our own /run tmpfs is the bind source (memfd files cannot be bind mounted) */
	if (run_fd >= 0)
		file_fd = openat(run_fd, ".juno-resolv.conf",
				 O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
	if (file_fd < 0 || write(file_fd, NAT_RESOLV, sizeof NAT_RESOLV - 1) != sizeof NAT_RESOLV - 1)
		STEP("write the generated resolv.conf");
	close(file_fd);
	close(run_fd);

	ns_fmt(src, sizeof src, "%s/run/.juno-resolv.conf", ctx->stage);
	if (ns_mount_at(root_fd, src, "/etc/resolv.conf", NULL, MS_BIND, NULL, 1, 1) < 0)
		STEP("bind /etc/resolv.conf");
}

static void mount_user_mounts(struct ns_ctx *ctx, int root_fd)
{
	const juno_spec *spec = ctx->spec;

	for (int i = 0; i < spec->nmounts; i++) {
		const struct juno_mount *mnt = &spec->mounts[i];
		int readonly = !!(mnt->flags & JUNO_MNT_RO);
		struct stat st;

		if (mnt->kind == JUNO_MOUNT_TMPFS) {
			if (ns_mount_at(root_fd, "tmpfs", mnt->dst, "tmpfs", MS_NOSUID | MS_NODEV,
					ctx->utmpopt, 0, readonly) < 0)
				STEP("mount tmpfs at %s", mnt->dst);
			continue;
		}
		if (stat(mnt->src, &st) < 0)
			STEP("mount bind: source %s", mnt->src);
		if (ns_mount_at(root_fd, mnt->src, mnt->dst, NULL, MS_BIND | MS_REC, NULL,
				!S_ISDIR(st.st_mode), readonly) < 0)
			STEP("mount bind %s -> %s", mnt->src, mnt->dst);
	}
}

/* Make the staged tree the root and detach the old one. */
static void pivot_into_stage(struct ns_ctx *ctx)
{
	int old_root_fd;

	if (chdir(ctx->stage) < 0)
		STEP("chdir new root");
	old_root_fd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (syscall(SYS_pivot_root, ".", ".") < 0)
		STEP("pivot_root");
	ctx->pivoted = 1;

	/* the stage dir is no longer a mount point: remove it from the host before letting go of the old root */
	if (old_root_fd >= 0) {
		unlinkat(old_root_fd, ctx->stage + 1, AT_REMOVEDIR);
		close(old_root_fd);
	}
	if (umount2(".", MNT_DETACH) < 0)
		STEP("detach old root");
	if (chdir("/") < 0)
		STEP("chdir /");
}

int ns_build_root(struct ns_ctx *ctx)
{
	const juno_spec *spec = ctx->spec;
	int root_fd;

	switch (spec->root_kind) {
	case JUNO_ROOT_HOST_RO:
		host_ro_root(ctx);
		break;
	case JUNO_ROOT_DIR:
		if (mount(spec->root_path, ctx->stage, NULL, MS_BIND | MS_REC, NULL) < 0)
			STEP("bind root dir %s", spec->root_path);
		break;
	case JUNO_ROOT_OVERLAY:
		overlay_root(ctx);
		break;
	default:
		errno = EINVAL;
		STEP("root kind");
	}

	root_fd = open(ctx->stage, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (root_fd < 0)
		STEP("open new root");

	if (ns_mount_at(root_fd, "proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL, 0, 0) < 0)
		STEP("mount /proc");
	if (ns_mount_dev(root_fd, ctx->shmopt) < 0)
		STEP("setup /dev");
	if (ns_mount_at(root_fd, "tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, ctx->tmpopt, 0, 0) < 0)
		STEP("mount /tmp");
	if (ns_mount_at(root_fd, "tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV, ctx->runopt, 0, 0) < 0)
		STEP("mount /run");
	if ((spec->init == JUNO_INIT_TINY || spec->nesting) &&
	    ns_mount_at(root_fd, ctx->initpath, NS_INIT_IN_CELL, NULL, MS_BIND, NULL, 1, 1) < 0)
		STEP("bind the cell init %s", ctx->initpath);
	if (ctx->cg == 2 && ns_mount_at(root_fd, "cgroup2", "/sys/fs/cgroup", "cgroup2",
					MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL, 0, 0) < 0)
		STEP("mount cgroup2 for the delegated subtree");

	if (spec->net == JUNO_NET_NAT && spec->root_kind != JUNO_ROOT_HOST_RO &&
	    faccessat(root_fd, "etc/resolv.conf", F_OK, AT_SYMLINK_NOFOLLOW) < 0)
		bind_generated_resolv(ctx, root_fd);

	mount_user_mounts(ctx, root_fd);
	close(root_fd);

	pivot_into_stage(ctx);
	return 0;
}
