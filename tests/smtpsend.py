# Copyright 2026, Dario Casalinuovo.
# SPDX-License-Identifier: LGPL-2.1-or-later
# usage: smtpsend.py HOST PORT BODY_TEXT [EXPECT_FILE]   (EXPECT_FILE gets the CRLF form the server must store)
import smtplib, sys

host, port, text = sys.argv[1], int(sys.argv[2]), sys.argv[3]
msg = "From: trial@juno\r\nTo: box@juno\r\nSubject: trial\r\n\r\n" + text.replace("\n", "\r\n") + "\r\n"
if len(sys.argv) > 4:
    with open(sys.argv[4], "wb") as expect_file:
        expect_file.write(msg.encode())
with smtplib.SMTP(host, port, timeout=8) as smtp:
    smtp.sendmail("trial@juno", ["box@juno"], msg)
print("sent")
