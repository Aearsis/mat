/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 */

#include <linux/list.h>
#include <net/mat/netdev.h>

#define log(format, ...) log_comp("netdev", format, ##__VA_ARGS__)

/* Private structure to keep list of registered drivers per table */
struct mat_netdev_binder {
	struct list_head in_tbl;
	struct net_device *dev;
	struct mat_netdev_ops *ops;
};

int mat_netdev_bind(struct mat_table *tbl,
	struct net_device *dev, struct mat_netdev_ops *ops)
{
	struct mat_netdev_binder *binder;
	assert(tbl && dev && ops);

	if (tbl->events_announced) {
		log("Replaying events for late-bound tables not supported yet.");
		return -EOPNOTSUPP;
	}

	binder = kzalloc(sizeof(*binder), GFP_KERNEL);
	if (!binder)
		return ENOMEM;


	binder->dev = dev;
	binder->ops = ops;
	INIT_LIST_HEAD(&binder->in_tbl);

	log("netdev bound to table %u", mat_table_get_index(tbl));

	list_add(&binder->in_tbl, &tbl->netdevs);
	return 0;
}

int mat_netdev_flow_insert(struct mat_table *tbl,
	struct mat_flow_key *mask, struct mat_flow_key *value,
	u64 action_id)
{
	struct mat_netdev_binder *b;
	tbl->events_announced++;

	list_for_each_entry(b, &tbl->netdevs, in_tbl) {
		if (b->ops->flow_insert)
			b->ops->flow_insert(b->dev, tbl, mask, value, action_id);
	}

	return 0;
}

int mat_netdev_set_table_chain(struct mat_table *tbl,
	enum mat_table_chain chain_kind, struct mat_action_chain *chain)
{
	struct mat_netdev_binder *b;
	tbl->events_announced++;

	list_for_each_entry(b, &tbl->netdevs, in_tbl) {
		if (b->ops->set_table_chain)
			b->ops->set_table_chain(b->dev, tbl, chain_kind, chain);
	}

	return 0;
}
