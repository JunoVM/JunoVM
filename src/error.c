/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "internal.h"
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

static _Thread_local char error_buf[512];

void juno_seterr(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(error_buf, sizeof error_buf, fmt, ap);
	va_end(ap);
}

const char *juno_error(void) { return error_buf; }

uint64_t juno_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Append item to a NULL-terminated array; takes ownership of item even on failure. */
int juno_append(char ***array, int *count, char *item)
{
	char **grown = realloc(*array, sizeof(char *) * (*count + 2));

	if (!grown) {
		free(item);
		return -1;
	}
	grown[(*count)++] = item;
	grown[*count] = NULL;
	*array = grown;
	return 0;
}
