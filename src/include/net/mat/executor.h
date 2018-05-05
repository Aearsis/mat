/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 */

#pragma once

#include <mock.h>
#include <linux/mat.h>

/* Result codes of running the executor. */
#define MAT_RES_NEXT	0	/* Processing is over. */
#define MAT_RES_DROP	1	/* The skb should be dropped. */
#define MAT_RES_BREAK	2	/* Processing did not finish due to TTL reaching zero. */

/* The TTL that is used to run the executor by default (32 tables) */
#define MAT_EXEC_DEFAULT_TTL (32 * __MAT_EXEC_STATE_COUNT)


/* A holder for a chain of actions. The size of this structure is determined
 * from the number of actions.
 */
struct mat_action_chain {
	struct hashtable_entry entry;
	size_t len;
	struct mat_action chain [];
};

/* The current state number of the executor. When invoked, the executor always
 * visits all of these states in order. The functionality of the executor is
 * split between these states:
 *
 * MAT_EXEC_NEXT_TABLE:
 *     Get the next table according to the number in exec.next_table.
 *     Reinitializes next_table, stopped and action_chain fields. If
 *     exec.next_table is 0 or invalid, the execution ends with MAT_RES_NEXT.
 * MAT_EXEC_PRE_CHAIN:
 *     Execute the pre-chain of the current table. Useful to start execution
 *     when the table memory address is known.
 * MAT_EXEC_FLOW_LOOKUP:
 *     Perform the classification step of the table - determine the chain ID.
 *     The ID is recorded in exec.action_chain. If no flow matches, the chain
 *     ID is 0.
 * MAT_EXEC_FLOW_CHAIN:
 *     Get and execute the flow action chain. If the chain ID is 0 or the chain
 *     does not exist, the default chain is executed.
 *     Useful to start execution when the NIC is able to classify the packet.
 * MAT_EXEC_POST_CHAIN:
 *     Execute the post-chain of the current table.
 */
enum mat_executor_state {
	MAT_EXEC_NEXT_TABLE,
	MAT_EXEC_PRE_CHAIN,
	MAT_EXEC_FLOW_LOOKUP,
	MAT_EXEC_FLOW_CHAIN,
	MAT_EXEC_POST_CHAIN,
	__MAT_EXEC_STATE_COUNT,
};

/* The stored state of the executor. The drivers can initialize it to "resume"
 * execution after a partial offload. Also, the TTL can be used to "pause" the
 * execution after a fixed number of steps to continue in the hardware.
 */
struct mat_executor {
	enum mat_executor_state state;
	struct mat_table *table;
	unsigned ttl;

	mat_table_index next_table;
	u64 action_chain;
	bool stopped;

	u16 tc_index;
};
int mat_executor_run(struct mat_executor *exec, struct sk_buff *skb);

struct mat_action_chain *mat_action_chain_create(size_t len);
struct mat_action_chain *mat_action_chain_clone(struct mat_action_chain *chain);
void mat_action_chain_destroy(struct mat_action_chain *chain);

bool mat_action_chain_is_drop_only(struct mat_action_chain *chain);
bool mat_action_is_noop(struct mat_action *action);
