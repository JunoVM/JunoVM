# Copyright 2026, Dario Casalinuovo.
# SPDX-License-Identifier: LGPL-2.1-or-later
# Minimal SMTP receiver for the mail trial: starts as root, binds, drops to UID, spools one file per message.
# usage: smtpd.py PORT SPOOLDIR UID
import os, socket, sys, time

port, spool, uid = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", port))
server.listen(16)
os.makedirs(spool, exist_ok=True)
os.chown(spool, uid, uid)
os.setgroups([])
os.setgid(uid)
os.setuid(uid)
print("smtpd: listening on %d, running as uid %d" % (port, os.getuid()), flush=True)

stored = 0
while True:
    conn, _ = server.accept()
    stream = conn.makefile("rwb", buffering=0)
    try:
        stream.write(b"220 juno ESMTP ready\r\n")
        while True:
            line = stream.readline()
            if not line:
                break
            command = line.decode(errors="replace").strip().upper()
            if command.startswith(("HELO", "EHLO")):
                stream.write(b"250 juno\r\n")
            elif command.startswith(("MAIL FROM", "RCPT TO", "RSET", "NOOP")):
                stream.write(b"250 ok\r\n")
            elif command == "DATA":
                stream.write(b"354 end with <CRLF>.<CRLF>\r\n")
                body = []
                while True:
                    data_line = stream.readline()
                    if data_line in (b".\r\n", b".\n", b""):
                        break
                    body.append(data_line[1:] if data_line.startswith(b"..") else data_line)
                stored += 1
                name = "msg-%d-%d.eml" % (time.time_ns(), stored)
                with open(os.path.join(spool, name), "wb") as out:
                    out.write(b"".join(body))
                print("smtpd: stored %s (%d bytes)" % (name, sum(map(len, body))), flush=True)
                stream.write(b"250 queued\r\n")
            elif command == "QUIT":
                stream.write(b"221 bye\r\n")
                break
            else:
                stream.write(b"500 unknown\r\n")
    except OSError:
        pass
    conn.close()
