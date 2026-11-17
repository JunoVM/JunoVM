/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
/* Freestanding i386 program: raw int 0x80 calls, no libc, so it builds without a 32-bit toolchain. */
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

static void result(const char *what, long r)
{
	put(what);
	put(" ");
	put(r == -1 ? "EPERM" : r == -22 ? "EINVAL" : r == -38 ? "ENOSYS" : r == -14 ? "EFAULT" : r == 0 ? "ok" : "other");
	put("\n");
}

void main32(long *sp)
{
	const char *a = ((char **)(sp + 1))[1];
	switch (a ? a[0] : 0) {
	case 'b': result("bpf", sc(357, 0, 0, 0)); break;
	case 'u': result("unshare", sc(310, 0x10000000, 0, 0)); break;
	case 'm': result("mount", sc(21, 0, 0, 0)); break;
	default: result("getpid", sc(20, 0, 0, 0) > 0 ? 0 : -1);
	}
	sc(1, 0, 0, 0);
}

__asm__(".global _start\n_start:\n\tmov %esp, %eax\n\tand $-16, %esp\n\tpush %eax\n\tcall main32\n");
