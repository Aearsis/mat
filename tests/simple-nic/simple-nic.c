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

#include "nic.h"

/* Testing a simple NIC, that is able to offload a well-known table.
 *	1) make the testing nic an instance of simple NIC
 *	2) register a 5-tuple filter, bind to ingress
 *	3) insert a flow to drop
 *
 * After some steps, a packet is delivered. The packet should:
 *	2) deliver the packet
 *	3) drop the packet in the "hardware"
 *
 * No packet should be seen by MAT, as the table is "offloaded".
 */

int main(int argc, char ** argv)
{
	struct net_device nic;
	simple_nic_init(&nic);

	log("registering table");

	mat_field_index fields [] = {
		MAT_FIELD_IP_SRC,
		MAT_FIELD_IP_DST,
	};

	struct mat_table_template tbl_templ = {
		.type = MAT_TABLE_TYPE_TCAM,

		.fields = fields,
		.field_count = sizeof(fields) / sizeof(*fields),
	};

	mat_table_index table = mat_nl_table_register(&tbl_templ);
	unsigned ingress_block = mat_nl_table_get_block_index(table);

	log("hooking block %u to netdev's ingress", ingress_block);
	tc_modify_qdisc(&nic, ingress_block, 0);
	hr();

	log("testing packet delivery (both should be delivered, HW filter misses them, software not invoked)");
	simple_nic_receive(&nic, sample_skb);
	simple_nic_receive(&nic, sample_skb_2);
	hr();

	log("inserting a flow to drop the packet A");

	struct mat_msg_arg flow_args_a [] = {
		{
			.type = MAT_FLOW_ARG_FIELD_VALUE,
			.field.field = MAT_FIELD_IP_SRC,
			.field.value = 0xABCDEF42,
		},
		{
			.type = MAT_FLOW_ARG_FIELD_VALUE,
			.field.field = MAT_FIELD_IP_DST,
			.field.value = 0x0BADF00D,
		},
		{
			.type = MAT_FLOW_ARG_FIELD_MASK,
			.field.field = MAT_FIELD_IP_SRC,
			.field.value = MAT_MASK_ONES,
		},
		{
			.type = MAT_FLOW_ARG_FIELD_MASK,
			.field.field = MAT_FIELD_IP_DST,
			.field.value = MAT_MASK_ONES,
		},
		{
			.type = MAT_FLOW_ARG_ACTION,
			.action.op = MAT_ACT_PRINT,
			.action.print.str = "This action is executed in software.",
		},
		{
			.type = MAT_FLOW_ARG_ACTION,
			.action.op = MAT_ACT_DROP,
		},
	};

	MAT_NL_MSG_PREPARE(flow_msg_a, MAT_MSG_FLOW_INSERT, table, flow_args_a);

	if ((mat_nl_msg(flow_msg_a)))
		perror("sending message");

	hr();

	log("testing packet A delivery (the NIC should drop the packet in hardware)");
	simple_nic_receive(&nic, sample_skb);
	hr();

	log("inserting a flow to comment packet B (but not drop)");

	struct mat_msg_arg flow_args_b [] = {
		{
			.type = MAT_FLOW_ARG_FIELD_VALUE,
			.field.field = MAT_FIELD_IP_SRC,
			.field.value = 0x0BADF00D,
		},
		{
			.type = MAT_FLOW_ARG_FIELD_MASK,
			.field.field = MAT_FIELD_IP_SRC,
			.field.value = MAT_MASK_ONES,
		},
		{
			.type = MAT_FLOW_ARG_ACTION,
			.action.op = MAT_ACT_PRINT,
			.action.print.str = "This action is executed in software.",
		},
	};

	MAT_NL_MSG_PREPARE(flow_msg_b, MAT_MSG_FLOW_INSERT, table, flow_args_b);

	if ((mat_nl_msg(flow_msg_b)))
		perror("sending message");

	hr();

	log("testing packet B (packet should be classified by HW, commented by sw, then delivered)");
	simple_nic_receive(&nic, sample_skb_2);

	simple_nic_destroy(&nic);
}
