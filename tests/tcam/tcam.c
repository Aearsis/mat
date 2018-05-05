/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 */

#include <linux/in.h>
#include <linux/mat.h>
#include <net/mat/parser.h>
#include <net/mat/table.h>
#include <tests.h>

/* Testing mask-value tables. The test:
 *	1) registers a TCAM table
 *	2) binds the MAT block to ingress
 *	3) sets a default chain
 *	4) inserts a matching flow
 *
 * After each step, a packet is received. Throughout the test, the subsystem
 * should:
 *	1) not see the packet
 *	2) see the packet, do nothing
 *	3) execute default action
 *	4) match the flow and drop the packet
 *
 *	At the end, a different packet is received. That one should pass.
 */

int main(int argc, char ** argv)
{
	log("registering table");

	mat_field_index fields [] = {
		MAT_FIELD_IP_SRC,
	};

	struct mat_table_template tbl_templ = {
		.type = MAT_TABLE_TYPE_TCAM,

		.fields = fields,
		.field_count = sizeof(fields) / sizeof(*fields),
	};

	mat_table_index table = mat_nl_table_register(&tbl_templ);
	unsigned ingress_block = mat_nl_table_get_block_index(table);
	hr();

	log("testing packet delivery (nothing should happen yet)");
	netif_receive_skb(sample_skb);
	hr();

	/* Simulate creating clsact qdisc with specified blocks attached. This is
	 * a test which is in fact initiated from userspace, but we rather avoid
	 * mocking the TC userspace API.
	 */
	log("hooking block %u to netdev's ingress", ingress_block);
	tc_modify_qdisc(test_netdev, ingress_block, 0);
	hr();

	log("testing packet delivery (MAT should see the packet)");
	netif_receive_skb(sample_skb);
	hr();

	log("setting the default chain");

	struct mat_msg_arg set_default_chain_args [] = {
		{
			.type = MAT_FLOW_ARG_ACTION,
			.action.op = MAT_ACT_PRINT,
			.action.print.str = "The flow did not match.",
		},
	};

	MAT_NL_MSG_PREPARE(set_default_chain_msg, MAT_MSG_SET_DEFAULT_CHAIN, table, set_default_chain_args);

	if ((mat_nl_msg(set_default_chain_msg)))
		perror("sending message");

	hr();

	log("testing packet delivery (MAT should execute default chain)");
	netif_receive_skb(sample_skb);
	hr();

	log("inserting a flow to drop the packet");

	struct mat_msg_arg flow_args [] = {
		{
			.type = MAT_FLOW_ARG_FIELD_MASK,
			.field.field = MAT_FIELD_IP_SRC,
			.field.value = 0x0000FFFF,
		},
		{
			.type = MAT_FLOW_ARG_FIELD_VALUE,
			.field.field = MAT_FIELD_IP_SRC,
			.field.value = 0x0000CDAB,
		},
		{
			.type = MAT_FLOW_ARG_ACTION,
			.action.op = MAT_ACT_PRINT,
			.action.print.str = "You shall not pass!",
		},
		{
			.type = MAT_FLOW_ARG_ACTION,
			.action.op = MAT_ACT_DROP,
		},
	};

	MAT_NL_MSG_PREPARE(flow_msg, MAT_MSG_FLOW_INSERT, table, flow_args);

	if ((mat_nl_msg(flow_msg)))
		perror("sending message");

	hr();

	log("testing packet delivery (MAT should drop the packet)");
	netif_receive_skb(sample_skb);
	hr();

	log("testing another packet delivery (MAT should see, but pass the packet)");
	netif_receive_skb(sample_skb_2);
}
