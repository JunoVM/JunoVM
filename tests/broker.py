# Copyright 2026, Dario Casalinuovo.
# SPDX-License-Identifier: LGPL-2.1-or-later
# Host-side broker for the agent trial: one Unix socket, answers "pong:<line>".
import os, socket, sys

path = sys.argv[1]
if os.path.exists(path):
    os.unlink(path)
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
server.listen(8)
while True:
    conn, _ = server.accept()
    line = conn.makefile("rb").readline().decode().strip()
    conn.sendall(("pong:" + line + "\n").encode())
    conn.close()
