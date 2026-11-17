#!/bin/sh
# Copyright 2026, Dario Casalinuovo.
# SPDX-License-Identifier: LGPL-2.1-or-later
# Runs a command as an agent cell: no network, writes only to $1 (the workspace) and /tmp.
# Usage: run.sh WORKSPACE_DIR COMMAND [ARGS...]
set -e
ws=$1; shift
JUNO=${JUNO:-$(dirname "$0")/../../build/juno}
# The agent preset needs a delegated cgroup for its 2 GiB limit; set MEM_FALLBACK=1 to accept RLIMIT_AS instead.
exec "$JUNO" run --preset agent ${MEM_FALLBACK:+--mem-fallback rlimit} --workspace "$ws" --timeout 60 -- "$@"
