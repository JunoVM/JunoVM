# Copyright 2026, Dario Casalinuovo.
# SPDX-License-Identifier: LGPL-2.1-or-later
# Run a command with a fresh pseudo-terminal as its controlling terminal and
# print what it wrote. Usage: runpty.py [--feed TEXT] cmd args...
import os, pty, select, sys, time

args = sys.argv[1:]
feed = None
if args[:1] == ["--feed"]:
    feed, args = args[1].encode().decode("unicode_escape").encode(), args[2:]
pid, fd = pty.fork()
if pid == 0:
    os.execv(args[0], args)
out = b""
started = time.time()
status = None
while time.time() - started < 20:
    readable, _, _ = select.select([fd], [], [], 0.3)
    if readable:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    exited, wait_status = os.waitpid(pid, os.WNOHANG)
    if exited:
        status = wait_status
        try:
            while select.select([fd], [], [], 0.1)[0]:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                out += chunk
        except OSError:
            pass
        break
sys.stdout.write(out.decode(errors="replace").replace("\r\n", "\n"))
sys.exit(0 if status is None else os.waitstatus_to_exitcode(status))
