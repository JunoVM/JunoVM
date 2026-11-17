/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "internal.h"
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static int compare_names(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

#define CELL_SUFFIX ".cell"
#define CELL_SUFFIX_LEN (sizeof CELL_SUFFIX - 1)

/* the *.cell files of dir, sorted; names without the suffix */
static int list_cells(const char *dir, char ***out)
{
	DIR *dh = opendir(dir);
	struct dirent *entry;
	char **names = NULL;
	int count = 0;

	if (!dh) {
		juno_seterr("%s: %s", dir, strerror(errno));
		return -errno;
	}
	while ((entry = readdir(dh))) {
		size_t len = strlen(entry->d_name);
		char *name;

		if (len <= CELL_SUFFIX_LEN || strcmp(entry->d_name + len - CELL_SUFFIX_LEN, CELL_SUFFIX))
			continue;
		name = strndup(entry->d_name, len - CELL_SUFFIX_LEN);
		if (!name || juno_append(&names, &count, name)) {
			closedir(dh);
			return -ENOMEM;
		}
	}
	closedir(dh);

	if (count)
		qsort(names, count, sizeof *names, compare_names);
	*out = names;
	return count;
}

static void free_names(char **names, int count)
{
	for (int i = 0; i < count; i++)
		free(names[i]);
	free(names);
}

int juno_up(const char *dir, FILE *out)
{
	char **names = NULL, path[1200];
	int count = list_cells(dir, &names);
	int failed = 0;

	if (count < 0)
		return count;
	for (int i = 0; i < count; i++) {
		juno_spec *spec = NULL;
		int rc;

		snprintf(path, sizeof path, "%s/%s" CELL_SUFFIX, dir, names[i]);
		rc = juno_spec_load(path, &spec);
		if (!rc) {
			rc = juno_run_named(spec, names[i], 1);
			juno_spec_free(spec);
		}

		if (rc == 0) {
			fprintf(out, "%s: started\n", names[i]);
		} else if (rc == -EEXIST) {
			fprintf(out, "%s: already running\n", names[i]);
		} else {
			fprintf(out, "%s: failed: %s\n", names[i], juno_error());
			failed++;
		}
	}
	free_names(names, count);
	return failed ? -EIO : 0;
}

/* reverse order, so cells started first are stopped last */
int juno_down(const char *dir, FILE *out)
{
	char **names = NULL;
	int count = list_cells(dir, &names);
	int failed = 0;

	if (count < 0)
		return count;
	for (int i = count - 1; i >= 0; i--) {
		int rc;

		juno_cell_stop(names[i], 3);
		rc = juno_cell_remove(names[i], 1);
		if (rc == 0) {
			fprintf(out, "%s: stopped and removed\n", names[i]);
		} else if (rc == -ENOENT) {
			fprintf(out, "%s: not present\n", names[i]);
		} else {
			fprintf(out, "%s: failed: %s\n", names[i], juno_error());
			failed++;
		}
	}
	free_names(names, count);
	return failed ? -EIO : 0;
}
