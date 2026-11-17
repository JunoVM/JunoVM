/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "ns.h"
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__x86_64__)
#define JUNO_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define JUNO_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "seccomp: unsupported architecture"
#endif

#define N(x) ((long)(x))
static const long deny_default[] = {
#ifdef __NR_io_uring_setup
	N(__NR_io_uring_setup),
#endif
#ifdef __NR_io_uring_enter
	N(__NR_io_uring_enter),
#endif
#ifdef __NR_io_uring_register
	N(__NR_io_uring_register),
#endif
#ifdef __NR_kcmp
	N(__NR_kcmp),
#endif
#ifdef __NR_name_to_handle_at
	N(__NR_name_to_handle_at),
#endif
#ifdef __NR_pidfd_getfd
	N(__NR_pidfd_getfd),
#endif
#ifdef __NR_process_madvise
	N(__NR_process_madvise),
#endif
#ifdef __NR_move_pages
	N(__NR_move_pages),
#endif
#ifdef __NR_mbind
	N(__NR_mbind),
#endif
#ifdef __NR_migrate_pages
	N(__NR_migrate_pages),
#endif
#ifdef __NR_set_mempolicy
	N(__NR_set_mempolicy),
#endif
#ifdef __NR_vhangup
	N(__NR_vhangup),
#endif
#ifdef __NR_syslog
	N(__NR_syslog),
#endif
#ifdef __NR_nfsservctl
	N(__NR_nfsservctl),
#endif
#ifdef __NR_uselib
	N(__NR_uselib),
#endif
#ifdef __NR_ustat
	N(__NR_ustat),
#endif
#ifdef __NR_sysfs
	N(__NR_sysfs),
#endif
#ifdef __NR__sysctl
	N(__NR__sysctl),
#endif
#ifdef __NR_fanotify_init
	N(__NR_fanotify_init),
#endif
#ifdef __NR_kexec_load
	N(__NR_kexec_load),
#endif
#ifdef __NR_kexec_file_load
	N(__NR_kexec_file_load),
#endif
#ifdef __NR_init_module
	N(__NR_init_module),
#endif
#ifdef __NR_finit_module
	N(__NR_finit_module),
#endif
#ifdef __NR_delete_module
	N(__NR_delete_module),
#endif
#ifdef __NR_bpf
	N(__NR_bpf),
#endif
#ifdef __NR_perf_event_open
	N(__NR_perf_event_open),
#endif
#ifdef __NR_add_key
	N(__NR_add_key),
#endif
#ifdef __NR_request_key
	N(__NR_request_key),
#endif
#ifdef __NR_keyctl
	N(__NR_keyctl),
#endif
#ifdef __NR_userfaultfd
	N(__NR_userfaultfd),
#endif
#ifdef __NR_open_by_handle_at
	N(__NR_open_by_handle_at),
#endif
#ifdef __NR_swapon
	N(__NR_swapon),
#endif
#ifdef __NR_swapoff
	N(__NR_swapoff),
#endif
#ifdef __NR_reboot
	N(__NR_reboot),
#endif
#ifdef __NR_settimeofday
	N(__NR_settimeofday),
#endif
#ifdef __NR_clock_settime
	N(__NR_clock_settime),
#endif
#ifdef __NR_clock_adjtime
	N(__NR_clock_adjtime),
#endif
#ifdef __NR_adjtimex
	N(__NR_adjtimex),
#endif
#ifdef __NR_iopl
	N(__NR_iopl),
#endif
#ifdef __NR_ioperm
	N(__NR_ioperm),
#endif
#ifdef __NR_acct
	N(__NR_acct),
#endif
#ifdef __NR_quotactl
	N(__NR_quotactl),
#endif
#ifdef __NR_lookup_dcookie
	N(__NR_lookup_dcookie),
#endif
};

static const long deny_strict[] = {
#ifdef __NR_unshare
	N(__NR_unshare),
#endif
#ifdef __NR_mount
	N(__NR_mount),
#endif
#ifdef __NR_umount2
	N(__NR_umount2),
#endif
#ifdef __NR_pivot_root
	N(__NR_pivot_root),
#endif
#ifdef __NR_chroot
	N(__NR_chroot),
#endif
#ifdef __NR_move_mount
	N(__NR_move_mount),
#endif
#ifdef __NR_open_tree
	N(__NR_open_tree),
#endif
#ifdef __NR_fsopen
	N(__NR_fsopen),
#endif
#ifdef __NR_fsconfig
	N(__NR_fsconfig),
#endif
#ifdef __NR_fsmount
	N(__NR_fsmount),
#endif
#ifdef __NR_fspick
	N(__NR_fspick),
#endif
#ifdef __NR_mount_setattr
	N(__NR_mount_setattr),
#endif
#ifdef __NR_ptrace
	N(__NR_ptrace),
#endif
#ifdef __NR_process_vm_readv
	N(__NR_process_vm_readv),
#endif
#ifdef __NR_process_vm_writev
	N(__NR_process_vm_writev),
#endif
#ifdef __NR_setns
	N(__NR_setns),
#endif
#ifdef __NR_sethostname
	N(__NR_sethostname),
#endif
#ifdef __NR_setdomainname
	N(__NR_setdomainname),
#endif
};

#ifdef __x86_64__
/* i386 numbers, hard-coded: the 64-bit headers do not carry them */
static const long deny_default_i386[] = {
	283, 128, 350, 129, 357, 336, 286, 287, 288, 374, 342, 87, 115, 88, 79, 264, 343, 124, 110, 101, 51,
	131, 253,
	425, 426, 427, 349, 341, 438, 440, 317, 274, 294, 276, 111, 103, 169, 86, 62, 135, 149, 338,
};
static const long deny_strict_i386[] = {
	21, 52, 217, 61, 429, 428, 430, 431, 432, 433, 442, 26, 347, 348, 346, 74, 121, 310,
};
#define I386_CLONE 120
#define I386_UNSHARE 310
#endif

/* forward-jump targets, resolved to relative offsets once the program is complete */
enum { L_ALLOW = 1, L_EPERM, L_NOSYS, L_KILL, L_I386, L_COUNT };

/* a conditional jump encodes its distance in one byte */
#define MAX_JUMP 255

/* BPF instructions that follow a syscall-number match and are skipped on a mismatch */
#define SKIP_MASK_CHECK 2	/* load arg0, test mask */
#define SKIP_PERSONALITY_CHECK 3	/* load arg0, test 0, test query value */

/* the final stubs (allow, EPERM, ENOSYS, kill) appended after every rule */
#define EPILOGUE_INSNS 4

#define X32_SYSCALL_BIT 0x40000000
#define PERSONALITY_QUERY 0xffffffffu
#define I386_NR_CLONE3 435
#define I386_NR_PERSONALITY 136

struct prog {
	struct sock_filter insn[NS_SECCOMP_MAXINS];
	unsigned char jump_true[NS_SECCOMP_MAXINS];	/* label ids, 0 = literal offset */
	unsigned char jump_false[NS_SECCOMP_MAXINS];
	int count;
};

static int emit(struct prog *prog, unsigned short code, unsigned k, int label_true, int label_false)
{
	/* keep room for the epilogue */
	if (prog->count >= NS_SECCOMP_MAXINS - (EPILOGUE_INSNS + 2))
		return -1;

	prog->insn[prog->count] = (struct sock_filter)BPF_STMT(code, k);
	prog->jump_true[prog->count] = label_true;
	prog->jump_false[prog->count] = label_false;
	prog->count++;
	return 0;
}

static int emit_load(struct prog *prog, unsigned offset)
{
	return emit(prog, BPF_LD | BPF_W | BPF_ABS, offset, 0, 0);
}

static int emit_jeq(struct prog *prog, unsigned value, int label_true, int label_false)
{
	return emit(prog, BPF_JMP | BPF_JEQ | BPF_K, value, label_true, label_false);
}

static int emit_return(struct prog *prog, unsigned action)
{
	return emit(prog, BPF_RET | BPF_K, action, 0, 0);
}

static int add_deny_list(struct prog *prog, const long *list, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		if (emit_jeq(prog, list[i], L_EPERM, 0))
			return -1;
	}
	return 0;
}

/* if nr == sys: reject when arg0 has any bit of mask set; otherwise allow */
static int add_mask_check(struct prog *prog, long sys, unsigned mask)
{
	if (emit_jeq(prog, sys, 0, 0))
		return -1;
	prog->insn[prog->count - 1].jf = SKIP_MASK_CHECK;

	if (emit_load(prog, offsetof(struct seccomp_data, args[0])))
		return -1;
	return emit(prog, BPF_JMP | BPF_JSET | BPF_K, mask, L_EPERM, L_ALLOW);
}

#define ANY_NEW_NAMESPACE (CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | \
			   CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET)

/* personality(): only 0 and the 0xffffffff query are allowed */
static int add_personality_check(struct prog *prog, long sys)
{
	if (emit_jeq(prog, sys, 0, 0))
		return -1;
	prog->insn[prog->count - 1].jf = SKIP_PERSONALITY_CHECK;

	if (emit_load(prog, offsetof(struct seccomp_data, args[0])))
		return -1;
	if (emit_jeq(prog, 0, L_ALLOW, 0))
		return -1;
	return emit_jeq(prog, PERSONALITY_QUERY, L_ALLOW, L_EPERM);
}

/* clone/unshare may not create a user namespace (any namespace under strict) without nesting */
static int add_namespace_checks(struct prog *prog, int profile, long clone_nr, long unshare_nr)
{
	int strict = profile == JUNO_SECCOMP_STRICT;

	if (add_mask_check(prog, clone_nr, strict ? ANY_NEW_NAMESPACE : CLONE_NEWUSER))
		return -1;
	/* strict denies unshare outright */
	if (!strict && add_mask_check(prog, unshare_nr, CLONE_NEWUSER))
		return -1;
	return 0;
}

#ifdef __x86_64__
static int add_i386_branch(struct prog *prog, int profile, int nesting, int *label_pos)
{
	if (emit_return(prog, SECCOMP_RET_ALLOW))
		return -1;

	label_pos[L_I386] = prog->count;
	if (emit_load(prog, offsetof(struct seccomp_data, nr)))
		return -1;
	if (!nesting) {
		if (emit_jeq(prog, I386_NR_CLONE3, L_NOSYS, 0))
			return -1;
		if (add_namespace_checks(prog, profile, I386_CLONE, I386_UNSHARE))
			return -1;
	}
	if (add_personality_check(prog, I386_NR_PERSONALITY))
		return -1;
	if (add_deny_list(prog, deny_default_i386, sizeof deny_default_i386 / sizeof *deny_default_i386))
		return -1;
	if (profile == JUNO_SECCOMP_STRICT &&
	    add_deny_list(prog, deny_strict_i386, sizeof deny_strict_i386 / sizeof *deny_strict_i386))
		return -1;
	return 0;
}
#endif

static int add_prologue(struct prog *prog, int compat32)
{
	if (emit_load(prog, offsetof(struct seccomp_data, arch)))
		return -1;
#ifdef __x86_64__
	if (compat32 && emit_jeq(prog, AUDIT_ARCH_I386, L_I386, 0))
		return -1;
#else
	(void)compat32;
#endif
	if (emit_jeq(prog, JUNO_AUDIT_ARCH, 0, L_KILL))
		return -1;
	return emit_load(prog, offsetof(struct seccomp_data, nr));
}

static int add_native_rules(struct prog *prog, int profile, int nesting)
{
#ifdef __x86_64__
	/* x32 syscalls share the arch value but would dodge the number list */
	if (emit(prog, BPF_JMP | BPF_JSET | BPF_K, X32_SYSCALL_BIT, L_KILL, 0))
		return -1;
#endif
	/* clone3 flags live in memory, so make glibc fall back to clone() */
#ifdef __NR_clone3
	if (!nesting && emit_jeq(prog, __NR_clone3, L_NOSYS, 0))
		return -1;
#endif
	if (!nesting) {
#ifdef __NR_clone
		if (profile == JUNO_SECCOMP_STRICT
		    ? add_mask_check(prog, __NR_clone, ANY_NEW_NAMESPACE)
		    : add_mask_check(prog, __NR_clone, CLONE_NEWUSER))
			return -1;
#endif
#ifdef __NR_unshare
		if (profile != JUNO_SECCOMP_STRICT && add_mask_check(prog, __NR_unshare, CLONE_NEWUSER))
			return -1;
#endif
	}
#ifdef __NR_personality
	if (add_personality_check(prog, __NR_personality))
		return -1;
#endif
	if (add_deny_list(prog, deny_default, sizeof deny_default / sizeof *deny_default))
		return -1;
	if (profile == JUNO_SECCOMP_STRICT &&
	    add_deny_list(prog, deny_strict, sizeof deny_strict / sizeof *deny_strict))
		return -1;
	return 0;
}

/* turn label ids into relative jump distances; a jump must go forward and fit in a byte */
static int resolve_jumps(struct prog *prog, const int *label_pos, int rule_count)
{
	for (int i = 0; i < rule_count; i++) {
		if (!(prog->insn[i].code & BPF_JMP))
			continue;

		if (prog->jump_true[i]) {
			int dist = label_pos[prog->jump_true[i]] - (i + 1);

			if (dist > MAX_JUMP || dist < 0)
				return -1;
			prog->insn[i].jt = dist;
		}
		if (prog->jump_false[i]) {
			int dist = label_pos[prog->jump_false[i]] - (i + 1);

			if (dist > MAX_JUMP || dist < 0)
				return -1;
			prog->insn[i].jf = dist;
		}
	}
	return 0;
}

int ns_seccomp_build(int profile, int nesting, int compat32, struct sock_filter *out, int *out_count)
{
	struct prog prog;
	int label_pos[L_COUNT] = { 0 };
	int rule_count;

	memset(&prog, 0, sizeof prog);
#ifndef __x86_64__
	if (compat32)
		return -ENOTSUP;
#endif

	if (add_prologue(&prog, compat32) || add_native_rules(&prog, profile, nesting))
		return -E2BIG;
#ifdef __x86_64__
	if (compat32 && add_i386_branch(&prog, profile, nesting, label_pos))
		return -E2BIG;
#endif

	rule_count = prog.count;
	label_pos[L_ALLOW] = rule_count;
	label_pos[L_EPERM] = rule_count + 1;
	label_pos[L_NOSYS] = rule_count + 2;
	label_pos[L_KILL] = rule_count + 3;
	if (emit_return(&prog, SECCOMP_RET_ALLOW) ||
	    emit_return(&prog, SECCOMP_RET_ERRNO | EPERM) ||
	    emit_return(&prog, SECCOMP_RET_ERRNO | ENOSYS) ||
	    emit_return(&prog, SECCOMP_RET_KILL_PROCESS))
		return -E2BIG;

	if (resolve_jumps(&prog, label_pos, rule_count))
		return -E2BIG;

	memcpy(out, prog.insn, sizeof(struct sock_filter) * prog.count);
	*out_count = prog.count;
	return 0;
}

int ns_seccomp_apply(const juno_spec *s)
{
	struct sock_filter insns[NS_SECCOMP_MAXINS];
	int count = 0;
	int err;

	if (s->seccomp == JUNO_SECCOMP_OFF)
		return 0;

	err = ns_seccomp_build(s->seccomp, s->nesting, s->compat32, insns, &count);
	if (err)
		return err;

	struct sock_fprog fprog = { .len = count, .filter = insns };
	if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &fprog) < 0)
		return -errno;
	return 0;
}
