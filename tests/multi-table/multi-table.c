/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 */

#include <arpa/inet.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/mat.h>
#include <net/mat/parser.h>
#include <net/mat/table.h>
#include <tests.h>

/* Testing a pipeline of multiple tables. The test creates a three exact-match
 * tables (A,B,C):
 *
 *	A) Send TCP packets to B, others to C.
 *	B) Drop packets unless the port is 22. Set the traffic class of such packets. Continue with C.
 *	C) Drop packets unless the destination MAC address is ours.
 *
 * The order is of course not optimal, but chosen to demonstrate multiple
 * tables working.
 */

struct test_data {
	mat_table_index a, b, c;
};

static void prepare_table_a(struct test_data *test);
static void prepare_table_b(struct test_data *test);
static void prepare_table_c(struct test_data *test);

static void setup_table_a(struct test_data *test);
static void setup_table_b(struct test_data *test);
static void setup_table_c(struct test_data *test);

static void test_packets();

int main(int argc, char ** argv)
{
	struct test_data td;

	log("registering tables");

	prepare_table_a(&td);
	prepare_table_b(&td);
	prepare_table_c(&td);

	setup_table_a(&td);
	setup_table_b(&td);
	setup_table_c(&td);

	unsigned ingress_block = mat_nl_table_get_block_index(td.a);
	tc_modify_qdisc(test_netdev, ingress_block, 0);
	hr();

	log("testing packet delivery:");
	log("\t 1. packet should be dropped by B");
	log("\t 2. packet should be set TC by B, but dropped by C");
	log("\t 3. packet should avoid B, and dropped by C");
	log("\t 4. packet should be delivered with TC 42 after going through all the tables");

	test_packets();
	return 0;
}

static void prepare_table_a(struct test_data *test)
{

	mat_field_index fields [] = {
		MAT_FIELD_ETHERTYPE,
		MAT_FIELD_IP_PROTO,
	};

	struct mat_table_template templ = {
		.type = MAT_TABLE_TYPE_EXACT,

		.fields = fields,
		.field_count = ARRAY_SIZE(fields),
	};

	test->a = mat_nl_table_register(&templ);
	assert(test->a);
}

static void prepare_table_b(struct test_data *test)
{

	mat_field_index fields [] = {
		MAT_FIELD_TCP_DPORT,
	};

	struct mat_table_template templ = {
		.type = MAT_TABLE_TYPE_EXACT,

		.fields = fields,
		.field_count = ARRAY_SIZE(fields),
	};

	test->b = mat_nl_table_register(&templ);
	assert(test->b);
}

static void prepare_table_c(struct test_data *test)
{

	mat_field_index fields [] = {
		MAT_FIELD_ETHERNET_MAC_DST,
	};

	struct mat_table_template templ = {
		.type = MAT_TABLE_TYPE_EXACT,

		.fields = fields,
		.field_count = ARRAY_SIZE(fields),
	};

	test->c = mat_nl_table_register(&templ);
	assert(test->c);
}

static void setup_table_a(struct test_data *test)
{
	struct mat_msg_arg set_default_chain_args [] = {
		{
			.type = MAT_FLOW_ARG_ACTION,
			.action.op = MAT_ACT_PRINT,
			.action.print.str = "Table A: missed",
		},
		{
			.type = MAT_FLOW_ARG_ACTION,
			.action.op = MAT_ACT_SET_NEXT,
			.action.set_next.table = test->c,
		},
	};

	MAT_NL_MSG_PREPARE(set_default_chain_msg, MAT_MSG_SET_DEFAULT_CHAIN, test->a, set_default_chain_args);

	int err = mat_nl_msg(set_default_chain_msg);
	assert(!err);

	struct mat_msg_arg flow_args [] = {
		{
			.type = MAT_FLOW_ARG_FIELD_VALUE,
			.field.field = MAT_FIELD_ETHERTYPE,
			.field.value = ETH_P_IP,
		},
		{
			.type = MAT_FLOW_ARG_FIELD_VALUE,
			.field.field = MAT_FIELD_IP_PROTO,
			.field.value = IPPROTO_TCP,
		},
		{
			.type = MAT_FLOW_ARG_ACTION,
			.action.op = MAT_ACT_PRINT,
			.action.print.str = "Table A: TCP packet",
		},
		{
			.type = MAT_FLOW_ARG_ACTION,
			.action.op = MAT_ACT_SET_NEXT,
			.action.set_next.table = test->b,
		},
	};

	MAT_NL_MSG_PREPARE(flow_msg, MAT_MSG_FLOW_INSERT, test->a, flow_args);

	err = mat_nl_msg(flow_msg);
	assert(!err);
}

static void setup_table_b(struct test_data *test)
{
	struct mat_msg_arg set_default_chain_args [] = {
		{
			.type = MAT_FLOW_ARG_ACTION,
			.action.op = MAT_ACT_PRINT,
			.action.print.str = "Table B: missed",
		},
		{
			.type = MAT_FLOW_ARG_ACTION,
			.action.op = MAT_ACT_DROP,
		},
	};

	MAT_NL_MSG_PREPARE(set_default_chain_msg, MAT_MSG_SET_DEFAULT_CHAIN, test->b, set_default_chain_args);

	int err = mat_nl_msg(set_default_chain_msg);
	assert(!err);

	struct mat_msg_arg flow_args [] = {
		{
			.type = MAT_FLOW_ARG_FIELD_VALUE,
			.field.field = MAT_FIELD_TCP_DPORT,
			.field.value = 22,
		},
		{
			.type = MAT_FLOW_ARG_ACTION,
			.action.op = MAT_ACT_PRINT,
			.action.print.str = "Table B: Port 22",
		},
		{
			.type = MAT_FLOW_ARG_ACTION,
			.action.op = MAT_ACT_SET_TC,
			.action.set_tc.index = 42,
		},
		{
			.type = MAT_FLOW_ARG_ACTION,
			.action.op = MAT_ACT_SET_NEXT,
			.action.set_next.table = test->c,
		},
	};

	MAT_NL_MSG_PREPARE(flow_msg, MAT_MSG_FLOW_INSERT, test->b, flow_args);

	err = mat_nl_msg(flow_msg);
	assert(!err);
}

static void setup_table_c(struct test_data *test)
{
	struct mat_msg_arg set_default_chain_args [] = {
		{
			.type = MAT_FLOW_ARG_ACTION,
			.action.op = MAT_ACT_PRINT,
			.action.print.str = "Table C: missed",
		},
		{
			.type = MAT_FLOW_ARG_ACTION,
			.action.op = MAT_ACT_DROP,
		},
	};

	MAT_NL_MSG_PREPARE(set_default_chain_msg, MAT_MSG_SET_DEFAULT_CHAIN, test->c, set_default_chain_args);

	int err = mat_nl_msg(set_default_chain_msg);
	assert(!err);

	struct mat_msg_arg flow_args [] = {
		{
			.type = MAT_FLOW_ARG_FIELD_VALUE,
			.field.field = MAT_FIELD_ETHERNET_MAC_DST,
			.field.value = 0xCAFECAFECAFE,
		},
		{
			.type = MAT_FLOW_ARG_ACTION,
			.action.op = MAT_ACT_PRINT,
			.action.print.str = "Table C: hit",
		},
	};

	MAT_NL_MSG_PREPARE(flow_msg, MAT_MSG_FLOW_INSERT, test->c, flow_args);

	err = mat_nl_msg(flow_msg);
	assert(!err);
}

static struct sk_buff skbs [4];

static void test_packets()
{
	netif_receive_skb(&skbs[0]);
	hr()
	netif_receive_skb(&skbs[1]);
	hr()
	netif_receive_skb(&skbs[2]);
	hr()
	netif_receive_skb(&skbs[3]);
}

static struct sk_buff skbs [4] = {
	{ .dev = test_netdev, .data = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Dest. MAC
		0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xFF, // Src. MAC
		0x08, 0x00, // Ethertype = IP

		0x45, 0x00, 0x00, 0xFF, // Version, ToS, Total length
		0xCA, 0xCA, 0x00, 0x00, // Identifier, Flags, Offset
		0xFF, 0x06, 0x00, 0x00, // TTL, Protocol = TCP, Chsum
		0x0D, 0xF0, 0xAD, 0x0B, // Source IP
		0x42, 0xEF, 0xCD, 0xAB, // Dest IP

		0x00, 0x2A, 0x00, 0x2A, // Source + Dest port (= 42)
		0x00, 0x00, 0x00, 0x00, // Seq. no
		0x00, 0x00, 0x00, 0x00, // ACK no
		0x50, 0x00, 0x00, 0x00, // Length, Flats, Win. size
	}},
	{ .dev = test_netdev, .data = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Dest. MAC
		0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xFF, // Src. MAC
		0x08, 0x00, // Ethertype = IP

		0x45, 0x00, 0x00, 0xFF, // Version, ToS, Total length
		0xCA, 0xCA, 0x00, 0x00, // Identifier, Flags, Offset
		0xFF, 0x06, 0x00, 0x00, // TTL, Protocol = TCP, Chsum
		0x0D, 0xF0, 0xAD, 0x0B, // Source IP
		0x42, 0xEF, 0xCD, 0xAB, // Dest IP

		0x00, 0x2A, 0x00, 0x16, // Source (42) + Dest port (22)
		0x00, 0x00, 0x00, 0x00, // Seq. no
		0x00, 0x00, 0x00, 0x00, // ACK no
		0x50, 0x00, 0x00, 0x00, // Length, Flats, Win. size
	}},
	{ .dev = test_netdev, .data = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Dest. MAC
		0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xFF, // Src. MAC
		0x08, 0x00, // Ethertype = IP

		0x45, 0x00, 0x00, 0xFF, // Version, ToS, Total length
		0xCA, 0xCA, 0x00, 0x00, // Identifier, Flags, Offset
		0xFF, 0x11, 0x00, 0x00, // TTL, Protocol = UDP, Chsum
		0x0D, 0xF0, 0xAD, 0x0B, // Source IP
		0x42, 0xEF, 0xCD, 0xAB, // Dest IP

		0x00, 0x2A, 0x00, 0x2A, // Source + Dest port (= 42)
		0x00, 0x00, 0x00, 0x00, // Length + Checksum
	}},
	{ .dev = test_netdev, .data = {
		0xCA, 0xFE, 0xCA, 0xFE, 0xCA, 0xFE, // Dest. MAC
		0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xFF, // Src. MAC
		0x08, 0x00, // Ethertype = IP

		0x45, 0x00, 0x00, 0xFF, // Version, ToS, Total length
		0xCA, 0xCA, 0x00, 0x00, // Identifier, Flags, Offset
		0xFF, 0x06, 0x00, 0x00, // TTL, Protocol = TCP, Chsum
		0x0D, 0xF0, 0xAD, 0x0B, // Source IP
		0x42, 0xEF, 0xCD, 0xAB, // Dest IP

		0x00, 0x2A, 0x00, 0x16, // Source (42) + Dest port (22)
		0x00, 0x00, 0x00, 0x00, // Seq. no
		0x00, 0x00, 0x00, 0x00, // ACK no
		0x50, 0x00, 0x00, 0x00, // Length, Flats, Win. size
	}},
};

