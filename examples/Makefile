# Copyright 2026, Dario Casalinuovo.
# SPDX-License-Identifier: LGPL-2.1-or-later
# Build the tree first (make in the parent directory).
embed: embed.c ../build/libjuno.a
	cc -std=c11 -D_GNU_SOURCE -O2 -Wall -I../include embed.c ../build/libjuno.a -o embed
clean:
	rm -f embed
