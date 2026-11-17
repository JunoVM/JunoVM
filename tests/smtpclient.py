# Copyright 2026, Dario Casalinuovo.
# SPDX-License-Identifier: LGPL-2.1-or-later
# Runs in the client cell: submits one message to the host's published port through the nat gateway.
# usage: smtpclient.py PORT TEXT
import smtplib, sys, time

def gateway():
    for line in open("/proc/net/route").read().splitlines()[1:]:
        fields = line.split()
        if fields[1] == "00000000":
            gateway_addr = int(fields[2], 16)
            return ".".join(str((gateway_addr >> (8 * i)) & 255) for i in range(4))

port, text = int(sys.argv[1]), sys.argv[2]
msg = "From: client@juno\r\nTo: box@juno\r\nSubject: from the client cell\r\n\r\n" + text + "\r\n"
last = None
for _ in range(60):
    try:
        with smtplib.SMTP(gateway(), port, timeout=3) as smtp:
            smtp.sendmail("client@juno", ["box@juno"], msg)
        print("client: sent via", gateway(), flush=True)
        sys.exit(0)
    except Exception as err:
        last = err
        print('client: attempt failed:', err, flush=True)
        time.sleep(0.5)
print("client: gave up:", last, flush=True)
sys.exit(1)
