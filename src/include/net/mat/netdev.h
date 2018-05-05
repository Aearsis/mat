/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 *
 * The interaction of MAT with netdev drivers.
 *
 * The communication is done on per-table basis. When the driver is announced
 * a block bind (through ndo_setup_tc), the driver parses the event and ends up
 * with a block of type TC_BLOCK_MAT.
 *
 * The driver then checks the table whether it can offload it. If so, it does
 * the necessary setup (create the table in hardware) and registers for events
 * in the MAT subsystem with struct mat_netdev_bind. The events are announced
 * by calling mat_netdev_ops.
 *
 * Initially, the current setup will be replayed. (Not supported yet.)
 *
 * The driver must carefully examine all the action chains. If there's anything
 * what stops the driver from offloading, it must temporarily stop the offload
 * of the whole table (unless it can do at least the classification).
 *
 * To support multi-table graphs, the driver already has enough information.
 * While parsing the actions, it can notice the other tables and bind to them
 * as well. We will probably add some helpers in the future.
 */

#pragma once

#include <mock.h>

#include <net/mat/table.h>
#include <net/mat/executor.h>

/* The operations to manipulate tables offloaded to the hardware. */
struct mat_netdev_ops {
	int (*flow_insert)(struct net_device *dev,
		struct mat_table *tbl,
		struct mat_flow_key *mask,
		struct mat_flow_key *value,
		u64 action_id);

	/* flow_remove, flow_modify, ... */

	int (*set_table_chain)(struct net_device *dev,
		struct mat_table *tbl,
		enum mat_table_chain chain_kind,
		struct mat_action_chain *chain);
};

/* Call from driver to register for notifications on a table. */
int mat_netdev_bind(struct mat_table *tbl, struct net_device *dev, struct mat_netdev_ops *ops);

/* Announce a flow insertion to drivers. */
int mat_netdev_flow_insert(struct mat_table *tbl,
	struct mat_flow_key *mask,
	struct mat_flow_key *value,
	u64 action_id);

/* Announce a table chain change to drivers. */
int mat_netdev_set_table_chain(struct mat_table *tbl,
	enum mat_table_chain chain_kind, struct mat_action_chain *chain);
