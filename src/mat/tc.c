/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 */

#include <mock.h>

#include <net/mat/executor.h>
#include <net/mat/tc.h>

#define log(format, ...) log_comp("mat_tc", format, ##__VA_ARGS__)

/* The implementation of MAT TC filter. */
static int mat_tc_classify(struct sk_buff *skb, const struct tcf_proto *proto,
	struct tcf_result *cl_res)
{

	struct mat_executor exec = {
		.state = MAT_EXEC_PRE_CHAIN,
		.table = proto->data,
		.ttl = MAT_EXEC_DEFAULT_TTL,
	};

	int err = mat_executor_run(&exec, skb);

	switch (err) {
		case MAT_RES_NEXT:
			cl_res->classid = exec.tc_index;
			return TC_ACT_OK;
		case MAT_RES_DROP:
		case MAT_RES_BREAK:
			return TC_ACT_SHOT;
		default:
			return err;
	}
}

/* Initialize the TC block for a table. */
int mat_tc_init(struct mat_table *tbl)
{
	tbl->block = tcf_block_alloc_shared(TCF_BLOCK_MAT);

	tbl->block->filter = kzalloc(sizeof(*tbl->block->filter), GFP_KERNEL);
	tbl->block->filter->data = tbl;
	tbl->block->filter->classify = mat_tc_classify;

	log("created block %i", tbl->block->index);
	return 0;
}
