/* Copyright 2026, Dario Casalinuovo.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "ns.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Egress policy of a nat cell: unreachable routes for what must not be reached,
 * more specific routes for the exceptions. Installed by the cell's root before
 * its capabilities are dropped, so the payload cannot undo them. */

#define GW "10.0.2.2"
#define DNS "10.0.2.3"

/* what a rule does to the destination prefix */
enum { EGRESS_BLOCK = 0, EGRESS_ALLOW, EGRESS_LINK };

#define MAX_EGRESS_RULES ((int)(sizeof ((struct ns_ctx *)0)->egress_rules / \
			       sizeof ((struct ns_ctx *)0)->egress_rules[0]))

/* pasta needs this long to answer ARP on a busy host */
#define GATEWAY_POLLS 150
#define GATEWAY_POLL_USEC 20000
#define DISCARD_PORT 9
#define ARP_COMPLETE_FLAG "0x2"

static int add_rule(struct ns_ctx *ctx, const char *cidr, int action)
{
	uint32_t addr;
	int plen;

	if (ctx->egress_count >= MAX_EGRESS_RULES)
		return -E2BIG;
	if (juno_parse_cidr(cidr, &addr, &plen))
		return -EINVAL;

	ctx->egress_rules[ctx->egress_count].addr = addr;
	ctx->egress_rules[ctx->egress_count].plen = plen;
	ctx->egress_rules[ctx->egress_count].action = action;
	ctx->egress_count++;
	return 0;
}

/* Parent side: the rules, in the order they will be installed (later wins at equal prefix). */
int ns_egress_plan(const juno_spec *spec, struct ns_ctx *ctx)
{
	static const char *const reserved[] = {
		"169.254.0.0/16", "192.0.0.0/24", "224.0.0.0/4", "240.0.0.0/4",
	};
	static const char *const private_ranges[] = {
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
	};
	int rc = 0;

	ctx->egress_count = 0;
	if (spec->net != JUNO_NET_NAT)
		return 0;

	for (size_t i = 0; i < sizeof reserved / sizeof *reserved && !rc; i++)
		rc = add_rule(ctx, reserved[i], EGRESS_BLOCK);

	if (!spec->nat_lan) {
		for (size_t i = 0; i < sizeof private_ranges / sizeof *private_ranges && !rc; i++)
			rc = add_rule(ctx, private_ranges[i], EGRESS_BLOCK);
	}
	if (!rc && !spec->nat_host)
		rc = add_rule(ctx, "10.0.2.0/24", EGRESS_BLOCK);	/* includes the gateway */
	if (!rc)
		rc = add_rule(ctx, DNS "/32", EGRESS_LINK);

	for (int i = 0; i < spec->n_deny && !rc; i++)
		rc = add_rule(ctx, spec->egress_deny[i], EGRESS_BLOCK);
	for (int i = 0; i < spec->n_allow && !rc; i++)
		rc = add_rule(ctx, spec->egress_allow[i], EGRESS_ALLOW);
	return rc;
}

static int add_attr(char *msg, size_t max, int type, const void *data, size_t len)
{
	struct nlmsghdr *header = (struct nlmsghdr *)msg;
	size_t offset = NLMSG_ALIGN(header->nlmsg_len);
	struct rtattr *attr;

	if (offset + RTA_LENGTH(len) > max)
		return -1;
	attr = (struct rtattr *)(msg + offset);
	attr->rta_type = type;
	attr->rta_len = RTA_LENGTH(len);
	memcpy((char *)attr + RTA_LENGTH(0), data, len);
	header->nlmsg_len = offset + RTA_ALIGN(attr->rta_len);
	return 0;
}

static int install_route(int sock, int seq, const struct ns_egress_rule *rule, int out_if, uint32_t gateway)
{
	char msg[256] __attribute__((aligned(8)));
	char reply[256] __attribute__((aligned(8)));
	struct nlmsghdr *header = (struct nlmsghdr *)msg;
	struct rtmsg *route = NLMSG_DATA(header);
	struct nlmsghdr *reply_header = (struct nlmsghdr *)reply;
	ssize_t got;

	memset(msg, 0, sizeof msg);
	header->nlmsg_len = NLMSG_LENGTH(sizeof *route);
	header->nlmsg_type = RTM_NEWROUTE;
	header->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
	header->nlmsg_seq = seq;
	route->rtm_family = AF_INET;
	route->rtm_dst_len = rule->plen;
	route->rtm_table = RT_TABLE_MAIN;
	route->rtm_protocol = RTPROT_BOOT;
	route->rtm_scope = RT_SCOPE_UNIVERSE;
	route->rtm_type = RTN_UNREACHABLE;
	if (rule->action == EGRESS_ALLOW) {
		route->rtm_type = RTN_UNICAST;
		route->rtm_flags = RTNH_F_ONLINK;
	}
	if (rule->action == EGRESS_LINK) {
		route->rtm_type = RTN_UNICAST;
		route->rtm_scope = RT_SCOPE_LINK;
	}

	if (add_attr(msg, sizeof msg, RTA_DST, &rule->addr, 4))
		return -E2BIG;
	if (rule->action == EGRESS_ALLOW && add_attr(msg, sizeof msg, RTA_GATEWAY, &gateway, 4))
		return -E2BIG;
	if (rule->action != EGRESS_BLOCK && add_attr(msg, sizeof msg, RTA_OIF, &out_if, 4))
		return -E2BIG;
	if (send(sock, msg, header->nlmsg_len, 0) < 0)
		return -errno;

	got = recv(sock, reply, sizeof reply, 0);
	if (got < (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr)))
		return -EIO;
	if (reply_header->nlmsg_type != NLMSG_ERROR)
		return -EIO;
	return ((struct nlmsgerr *)NLMSG_DATA(reply_header))->error;
}

/* pasta answers ARP only once its main loop runs: wait until the gateway resolves, so the
 * payload never starts against a network that is configured but not yet served. */
void ns_wait_gateway(void)
{
	int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	struct sockaddr_in gateway = {
		.sin_family = AF_INET, .sin_port = htons(DISCARD_PORT), .sin_addr.s_addr = inet_addr(GW),
	};

	if (sock < 0)
		return;
	if (connect(sock, (struct sockaddr *)&gateway, sizeof gateway) == 0) {
		for (int i = 0; i < GATEWAY_POLLS; i++) {
			char table[2048];
			ssize_t got = -1;
			int fd;

			if (send(sock, "x", 1, 0) < 0)
				break;
			fd = open("/proc/self/net/arp", O_RDONLY | O_CLOEXEC);
			if (fd >= 0) {
				got = read(fd, table, sizeof table - 1);
				close(fd);
			}
			if (got > 0) {
				char *entry;

				table[got] = 0;
				entry = strstr(table, GW " ");
				if (entry && strstr(entry, ARP_COMPLETE_FLAG))
					break;
			}
			usleep(GATEWAY_POLL_USEC);
		}
	}
	close(sock);
}

/* Child side, as cell root: no allocation, no stdio. */
int ns_egress_apply(struct ns_ctx *ctx)
{
	uint32_t gateway = inet_addr(GW);
	int sock, out_if, rc;

	if (!ctx->egress_count)
		return 0;
	sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (sock < 0)
		return -errno;

	out_if = if_nametoindex("eth0");
	rc = out_if ? 0 : -ENODEV;
	for (int i = 0; i < ctx->egress_count && !rc; i++)
		rc = install_route(sock, i + 1, &ctx->egress_rules[i], out_if, gateway);
	close(sock);
	return rc;
}
