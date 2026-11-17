#!/bin/bash
# Copyright 2026, Dario Casalinuovo.
# SPDX-License-Identifier: LGPL-2.1-or-later
# make install into a temp DESTDIR, build a program against it through juno.pc, then uninstall.
. "$(dirname "$0")/lib.sh"
D=$T/dest
cd "$ROOT" || exit 1
make -s install PREFIX=/usr/local DESTDIR="$D" >/dev/null 2>"$T/inst.err"; rc=$?
[ $rc -eq 0 ] && [ -x "$D/usr/local/bin/juno" ] && [ -f "$D/usr/local/lib/libjuno.a" ] && [ -f "$D/usr/local/include/juno.h" ] && [ -f "$D/usr/local/lib/pkgconfig/juno.pc" ]
r=$?; chk install-files "binary, static library, header and juno.pc installed under a temp DESTDIR (rc=$rc)"
if command -v pkg-config >/dev/null; then
	export PKG_CONFIG_PATH=$D/usr/local/lib/pkgconfig PKG_CONFIG_SYSROOT_DIR=$D
	flags=$(pkg-config --cflags --libs juno); frc=$?; ver=$(pkg-config --modversion juno)
	cat > "$T/hello.c" <<'EOF'
#include <juno.h>
#include <stdio.h>
int main(void) { char r[1024]; int rc = juno_probe("ns", r, sizeof r); printf("%s %d\n", JUNO_VERSION, rc); return rc != 0; }
EOF
	gcc -o "$T/hello" "$T/hello.c" $flags 2>"$T/cc.err"; crc=$?
	out=$("$T/hello"); hrc=$?
	[ $frc -eq 0 ] && [ $crc -eq 0 ] && [ "$out" = "0.1.0 0" ] && [ "$ver" = 0.1.0 ] && [ "$("$D/usr/local/bin/juno" version)" = "juno 0.1.0" ]
	r=$?; chk install-pkg-config "pkg-config says '$flags' (version $ver); a program built from it ran: '$out'; $("$D/usr/local/bin/juno" version)"
else
	skp install-pkg-config "pkg-config is not installed"
fi
make -s uninstall PREFIX=/usr/local DESTDIR="$D" >/dev/null 2>&1
[ -z "$(find "$D" -type f)" ]; r=$?; chk uninstall-removes-files "no installed file remains after make uninstall"
summary install_test.sh
