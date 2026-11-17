# Networking

| Mode | What the cell has | Reaches | Does not reach |
|---|---|---|---|
| `none` (default) | new netns, loopback up | its own loopback | everything else; the host's loopback services and abstract unix sockets |
| `host` | the host's netns | everything the user can, including host loopback services and the host's abstract unix sockets (X11, D-Bus sessions) | raw/packet sockets (no capability) |
| `shared:NAME` | the netns of a holder process; cells with the same NAME share loopback | each other over 127.0.0.1 | the outside; a cell keeping `net_raw`/`net_admin` gets no rights over the shared namespace (tested) |
| `nat` | own netns with an `eth0` configured by `pasta` (10.0.2.15/24, gateway 10.0.2.2, DNS forwarder 10.0.2.3); needs `pasta` in PATH | the public internet; DNS through the forwarder | RFC 1918 ranges, 100.64.0.0/10, 169.254.0.0/16, 192.0.0.0/24, multicast, 240.0.0.0/4, the gateway, the host's loopback |
| `nat:lan` | as `nat` | additionally the private and CGNAT ranges (LAN, docker bridges, VPN/mesh) | link-local, multicast, the gateway, the host's loopback |
| `nat:host` | as `nat:lan`, and 10.0.2.2 maps to the host's loopback | additionally host loopback services through 10.0.2.2 | link-local, multicast |

Measured on a host with a loopback-only service, a wildcard service and a LAN address (`tests/adversarial.sh` `net-*`): `none` refused all; `nat` connected to the LAN address's wildcard service and to 169.254.169.254, refused 127.0.0.1 and 10.0.2.2; `nat:host` connected to the loopback service through 10.0.2.2.

IPv4 only (`pasta -4`). Inbound connections to a `nat` cell are not forwarded; use `--publish`.

## Shared networks

`juno run --net shared:demo --name s1 -d -- sleep 20` starts a holder process; `juno net ls` shows it:
```
NAME PID CELLS
demo 96179 1
```
The holder exits about 3 seconds after the last member is gone. `juno net rm NAME` ends it at once. Shared cells cannot use `--idmap full`.

## Published ports

`--publish [ADDR:]HOSTPORT:CELLPORT` makes the supervisor (the process that runs the cell) listen on the host at ADDR (default 127.0.0.1) and, per connection, open a TCP connection to `127.0.0.1:CELLPORT` inside the cell's network namespace. It needs `none`, `shared` or `nat`. Ports below 1024 need the usual host privilege. Verified:
```
$ juno run --name web -d --publish 39777:8080 -- python3 -m http.server 8080 --bind 127.0.0.1
$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:39777/
200
```
The forwarder serves all ports of a cell from one process. Each connection first waits, without blocking the others, for a helper inside the cell to connect (3 s limit), then relays through two 16 KB buffers; at most 256 connections are open at once, and when the process runs out of descriptors it stops accepting for 200 ms instead of spinning. Do not bind a published port to a public address without a limit in front of it.

## Egress policy (`nat`)
The rules are `unreachable` routes installed in the cell's own network namespace by the cell's root before its capabilities are dropped (rtnetlink, no external tool), plus more specific routes for exceptions. The payload cannot change them: it has no `CAP_NET_ADMIN`, and a spec that keeps `net_admin` together with `net = nat` is refused. Connections to a denied address fail at once with "No route to host". The DNS forwarder 10.0.2.3 keeps working, so the cell can resolve any name; it cannot connect to what the policy denies.

`--egress-deny CIDR` adds a denied prefix, `--egress-allow ADDR/N` opens one (longest prefix wins; at an equal prefix allow wins). Example: `juno run --net nat --egress-allow 192.168.1.10/32 -- ...` opens exactly that LAN address.

## Egress proxy (`--egress-proxy-allow HOST:PORT`)
For a cell that needs a few HTTPS endpoints and nothing else (it works with `net none`). Repeatable; spec key `egress-proxy-allow`. A process on the host side listens **inside the cell's network namespace** on `127.0.0.1:3128` and answers `CONNECT host:port` only for exact allowlisted pairs: host names match case-insensitively, a leading `*.` matches subdomains (not the bare domain), IP literals only if listed literally; names are resolved on the host. Everything else gets `403` (`400` for a malformed request, `431` for a head over 8 KB, plain `GET http://...` is refused). `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY` and `http_proxy` are set in the cell. Each decision is written to the cell log (`proxy: CONNECT host:port allowed up=N down=M bytes` or `denied`). With no entries there is no listener. The proxy ends with the cell. Not supported with `shared:` networks.
