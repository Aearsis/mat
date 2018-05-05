/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 */


#include <mock.h>

#include <net/mat/table.h>

#define log(fmt, ...) log_comp("kernel", fmt, ##__VA_ARGS__)

/* Handle ingress clsact chain. Does not iterate over classification, just
 * calls the only filter's classify callback, as we do not use more than one in
 * the demonstrator.
 */
static struct sk_buff *sch_handle_ingress(struct sk_buff *skb)
{
	struct net_device *orig_dev = skb->dev;
	struct tcf_block *block = orig_dev->ingress_block;

	if (skb->tc_skip_classify || !block)
		return skb;

	struct tcf_proto *filter = block->filter;

	struct tcf_result cl_res;

	switch (filter->classify(skb, filter, &cl_res)) {
	case TC_ACT_OK:
	case TC_ACT_RECLASSIFY:
		skb->tc_index = TC_H_MIN(cl_res.classid);
		break;
	case TC_ACT_SHOT:
	case TC_ACT_STOLEN:
		return NULL;
	case TC_ACT_QUEUED:
	case TC_ACT_TRAP:
	case TC_ACT_REDIRECT:
	default:
		return skb;
	}

	return skb;
}

/* We skip almost everything this function in reality does. */
extern int netif_receive_skb(struct sk_buff *skb)
{
	assert(skb);
	assert(skb->dev);

	skb = sch_handle_ingress(skb);
	if (!skb)
		return 0;

	log("skb of traffic class %u is to be received.", skb->tc_index);
	return 0;
}

/* Real kernel uses idr.
 *
 * Index 0 is invalid. Lets start from 100 to distinguish blocks from tables in
 * outputs.
 */
static struct tcf_block *shared_blocks [1024] = { 0 };

static int shared_blocks_count = 100;


/* Returns a shared block with unused index. This method does not exist in the
 * kernel, but is fairly simple to implement, as the kernel uses idr to manage
 * blocks.
 */
struct tcf_block *tcf_block_alloc_shared(enum tcf_block_type type)
{
	struct tcf_block *block = kzalloc(sizeof(*block), GFP_KERNEL);
	block->type = type;
	block->index = shared_blocks_count++;

	shared_blocks[block->index] = block;

	return block;
}

static int tcf_block_get(struct tcf_block **p_block, u32 index)
{
	assert(index < 1024);
	assert(p_block);

	if (shared_blocks[index]) {
		*p_block = shared_blocks[index];
		return 0;
	}
	return ENOENT;
}

static int tcf_block_offload_cmd(struct tcf_block *block,
				 struct net_device *dev,
				 enum tcf_block_binder_type binder_type,
				 enum tc_block_command command)
{
	struct tc_block_offload bo = {};

	bo.command = command;
	bo.binder_type = binder_type;
	bo.block = block;
	return dev->netdev_ops->ndo_setup_tc(dev, TC_SETUP_BLOCK, &bo);
}

/* This has probably only the name in common with the original. In this mock,
 * this function simulates creating a clsact qdisc on a netdev, with
 * ingress_block and egress_block attached. As opposed to the original, it does
 * not create blocks if they do not exist -- we focus on MAT blocks only.
 */
int tc_modify_qdisc(struct net_device *dev, u32 ingress_block, u32 egress_block)
{
	if (!tcf_block_get(&dev->ingress_block, ingress_block))
		tcf_block_offload_cmd(dev->ingress_block, dev,
			TCF_BLOCK_BINDER_TYPE_CLSACT_INGRESS, TC_BLOCK_BIND);

	if (!tcf_block_get(&dev->egress_block, egress_block))
		tcf_block_offload_cmd(dev->egress_block, dev,
			TCF_BLOCK_BINDER_TYPE_CLSACT_EGRESS, TC_BLOCK_BIND);

	return 0;
}
