/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
/* Freestanding i386 attack program (raw int 0x80, no libc). Prints one line. */
static long sc(long n, long a, long b, long c)
{
	long r;
	__asm__ volatile("int $0x80" : "=a"(r) : "a"(n), "b"(a), "c"(b), "d"(c) : "memory");
	return r;
}

static void put(const char *s)
{
	long n = 0;
	while (s[n]) n++;
	sc(4, 1, (long)s, n);
}

static const char *name(long r)
{
	return r >= 0 ? "ok" : r == -1 ? "EPERM" : r == -22 ? "EINVAL" : r == -38 ? "ENOSYS" : r == -14 ? "EFAULT" : "other";
}

struct clone_args32 {
	unsigned long long flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls;
};

void main32(long *sp)
{
	const char *a = ((char **)(sp + 1))[1];
	long r;
	switch (a ? a[0] : 0) {
	case 'c': {	/* clone3(CLONE_NEWUSER) through the i386 entry */
		struct clone_args32 ca = { .flags = 0x10000000ull, .exit_signal = 17 };
		r = sc(435, (long)&ca, sizeof ca, 0);
		if (r == 0) sc(1, 0, 0, 0);
		if (r > 0) {
			long st;
			sc(114, r, (long)&st, 0);
			r = 0;
		}
		put("clone3-newuser ");
		put(name(r));
		put("\n");
		break;
	}
	case 'm': {	/* clone3(NEWUSER|NEWNS), then mount a tmpfs in the child: proves CAP_SYS_ADMIN in a fresh user namespace */
		struct clone_args32 ca = { .flags = 0x10020000ull, .exit_signal = 17 };
		static const char tmpfs[] = "tmpfs";
		r = sc(435, (long)&ca, sizeof ca, 0);
		if (r == 0) {
			long m;
			__asm__ volatile("int $0x80" : "=a"(m) : "a"(21), "b"((long)tmpfs), "c"((long)"/tmp"), "d"((long)tmpfs), "S"(0), "D"(0) : "memory");
			sc(1, m == 0 ? 0 : 1, 0, 0);
		}
		if (r > 0) {
			long st = -1;
			sc(114, r, (long)&st, 0);
			put("clone3-newuser-mount ");
			put(r > 0 && (st & 0xff00) == 0 ? "ok" : "EPERM");
			put("\n");
			break;
		}
		put("clone3-newuser-mount ");
		put(name(r));
		put("\n");
		break;
	}
	case 'i': {	/* io_uring_setup */
		char buf[120] = { 0 };

		r = sc(425, 4, (long)buf, 0);
		put("io_uring ");
		put(name(r));
		put("\n");
		break;
	}
	case 'u':
		r = sc(310, 0x10000000, 0, 0);
		put("unshare-newuser ");
		put(name(r));
		put("\n");
		break;
	default: put("none\n");
	}
	sc(1, 0, 0, 0);
}

__asm__(".global _start\n_start:\n\tmov %esp, %eax\n\tand $-16, %esp\n\tpush %eax\n\tcall main32\n");
