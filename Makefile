# Copyright 2026, Dario Casalinuovo.
# SPDX-License-Identifier: LGPL-2.1-or-later
CC      ?= cc
INITDEF := -DJUNO_INIT_DEFAULT='"$(CURDIR)/build/juno-init"'
CFLAGS  := -std=c11 -D_GNU_SOURCE -O2 -g -Wall -Wextra -Werror -Iinclude
SRCS    := src/spec.c src/error.c src/backend.c src/probe.c src/specfile.c src/ctl.c src/supervisor.c \
           src/ns/start.c src/ns/root.c src/ns/dev.c src/ns/idmap.c src/ns/init.c \
           src/ns/harden.c src/ns/seccomp.c src/ns/landlock.c src/ns/cgroup.c \
           src/ns/net.c src/ns/fwd.c src/ns/exec.c src/ns/safe.c src/ns/pasta.c src/ns/egress.c src/ns/proxy.c src/preset.c src/up.c
OBJS    := $(SRCS:%.c=build/%.o)

all: build/libjuno.a build/juno build/juno-init build/api_test build/juno_helper build/juno_helper32

build/%.o: %.c src/internal.h src/ns/ns.h include/juno.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INITDEF) -c $< -o $@

build/libjuno.a: $(OBJS)
	ar rcs $@ $^

build/juno-init: tools/init.c
	@mkdir -p build
	$(CC) $(CFLAGS) -static $< -o $@

build/juno: tools/juno.c build/libjuno.a
	$(CC) $(CFLAGS) $< build/libjuno.a -o $@

build/api_test: tests/api_test.c build/libjuno.a
	$(CC) $(CFLAGS) -pthread $< build/libjuno.a -o $@

build/juno_helper: tests/helper.c
	@mkdir -p build
	$(CC) $(CFLAGS) -static $< -o $@

# freestanding 32-bit test program; skipped quietly when the compiler cannot build it
build/juno_helper32: tests/helper32.c
	@mkdir -p build
	-@$(CC) -m32 -nostdlib -static -ffreestanding -fno-pic -no-pie -fno-stack-protector -O1 -o $@ $< 2>/dev/null || rm -f $@

test: all
	@export JUNO_TEST_TMP=$$(mktemp -d /tmp/juno-make.XXXXXX); rc=0; \
	bash tests/run.sh || rc=1; ./build/api_test || rc=1; bash tests/cgroup.sh || rc=1; \
	bash tests/trial_agent.sh || rc=1; bash tests/trial_mail.sh || rc=1; bash tests/install_test.sh || rc=1; \
	bash tests/adversarial.sh || rc=1; $(MAKE) -s check-tmp || rc=1; exit $$rc

test-cgroup: all
	@bash tests/cgroup.sh

test-adversarial: all
	@bash tests/adversarial.sh

# nothing may remain under this run's private tree once every script has cleaned up
# (other juno users may have their own /tmp/juno-* directories: they are not ours to judge)
check-tmp:
	@l=$$(ls -A "$$JUNO_TEST_TMP" 2>/dev/null | tr '\n' ' '); \
	if [ -z "$$l" ]; then echo "PASS no-leftover-tmp-dirs - nothing left under this run's private tree $$JUNO_TEST_TMP"; rmdir "$$JUNO_TEST_TMP"; else echo "FAIL no-leftover-tmp-dirs - $$JUNO_TEST_TMP: $$l"; exit 1; fi

# The whole suite under AddressSanitizer + UBSan. The in-cell helpers stay unsanitized.
ASAN     := -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -static-libasan
AOBJS    := $(SRCS:%.c=build-asan/%.o)

build-asan/%.o: %.c src/internal.h src/ns/ns.h include/juno.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INITDEF) $(ASAN) -c $< -o $@

build-asan/libjuno.a: $(AOBJS)
	ar rcs $@ $^

build-asan/juno: tools/juno.c build-asan/libjuno.a
	$(CC) $(CFLAGS) $(ASAN) $< build-asan/libjuno.a -o $@

build-asan/api_test: tests/api_test.c build-asan/libjuno.a
	$(CC) $(CFLAGS) $(ASAN) -pthread $< build-asan/libjuno.a -o $@

test-asan: build/juno-init build-asan/juno build-asan/api_test build/juno_helper build/juno_helper32
	@rm -f build-asan/report.*; rc=0; export JUNO_TEST_TMP=$$(mktemp -d /tmp/juno-make.XXXXXX); \
	export JUNO_ASAN=1 ASAN_OPTIONS=detect_leaks=1:log_path=$(CURDIR)/build-asan/report UBSAN_OPTIONS=print_stacktrace=1:log_path=$(CURDIR)/build-asan/report; \
	JUNO=$(CURDIR)/build-asan/juno bash tests/run.sh || rc=1; \
	./build-asan/api_test || rc=1; \
	JUNO=$(CURDIR)/build-asan/juno bash tests/cgroup.sh || rc=1; \
	JUNO=$(CURDIR)/build-asan/juno bash tests/trial_agent.sh || rc=1; \
	JUNO=$(CURDIR)/build-asan/juno bash tests/trial_mail.sh || rc=1; \
	JUNO=$(CURDIR)/build-asan/juno bash tests/install_test.sh || rc=1; \
	JUNO=$(CURDIR)/build-asan/juno bash tests/adversarial.sh || rc=1; \
	$(MAKE) -s check-tmp || rc=1; \
	if ls build-asan/report.* >/dev/null 2>&1; then echo "FAIL sanitizer-reports - $$(ls build-asan/report.* | wc -l) report files in build-asan/ (first: $$(head -3 $$(ls build-asan/report.* | head -1) | tr '\n' ' '))"; rc=1; \
	else echo "PASS sanitizer-reports - no ASan/UBSan/LSan report from any process of the suite, including daemons and cell inits"; fi; exit $$rc

PREFIX ?= /usr/local
DESTDIR ?=

build/juno.pc: Makefile include/juno.h
	@mkdir -p build
	@printf 'prefix=$(PREFIX)\nlibdir=$${prefix}/lib\nincludedir=$${prefix}/include\n\nName: juno\nDescription: rootless container engine library\nVersion: 0.1.0\nLibs: -L$${libdir} -ljuno\nCflags: -I$${includedir}\n' > $@

install: all build/juno.pc
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/lib/pkgconfig $(DESTDIR)$(PREFIX)/include
	install -m 755 build/juno $(DESTDIR)$(PREFIX)/bin/juno
	install -d $(DESTDIR)$(PREFIX)/libexec/juno
	install -m 755 build/juno-init $(DESTDIR)$(PREFIX)/libexec/juno/juno-init
	install -m 644 build/libjuno.a $(DESTDIR)$(PREFIX)/lib/libjuno.a
	install -m 644 include/juno.h $(DESTDIR)$(PREFIX)/include/juno.h
	install -m 644 build/juno.pc $(DESTDIR)$(PREFIX)/lib/pkgconfig/juno.pc

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/juno $(DESTDIR)$(PREFIX)/libexec/juno/juno-init $(DESTDIR)$(PREFIX)/lib/libjuno.a $(DESTDIR)$(PREFIX)/include/juno.h \
		$(DESTDIR)$(PREFIX)/lib/pkgconfig/juno.pc

clean:
	rm -rf build build-asan

.PHONY: all test test-adversarial test-cgroup test-asan check-tmp install uninstall clean
