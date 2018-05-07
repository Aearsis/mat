/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 */

#include <net/mat/executor.h>
#include <net/mat/table.h>

#define log(format, ...) log_comp("executor", format, ##__VA_ARGS__)

/* Execute one action. */
static int mat_execute_action(struct mat_executor *exec,
	struct mat_action *act, struct sk_buff *skb)
{
	switch (act->op) {
		case MAT_ACT_PASS:
			log("\tpass");
			return MAT_RES_NEXT;

		case MAT_ACT_DROP:
			log("\tdrop");
			return MAT_RES_DROP;

		case MAT_ACT_SET_NEXT:
			log("\tset next table to %u", act->set_next.table);
			exec->next_table = act->set_next.table;
			return MAT_RES_NEXT;

		case MAT_ACT_SET_TC:
			log("\tset traffic class to %u", act->set_tc.index);
			exec->tc_index = act->set_tc.index;
			return MAT_RES_NEXT;

		case MAT_ACT_STOP:
			return MAT_RES_BREAK;

		case MAT_ACT_PRINT:
			log("\tprint: %s", act->print.str);
			return MAT_RES_NEXT;

		default:
			return -EINVAL;
	}
}

/* Execute a chain of actions. */
static int mat_execute_action_chain(struct mat_executor *exec,
	struct mat_action_chain *chain, struct sk_buff *skb)
{
	int err = MAT_RES_NEXT;
	unsigned i;

	for (i = 0; i < chain->len; i++) {
		if ((err = mat_execute_action(exec, &chain->chain[i], skb)))
			break;
	}

	if (err == MAT_RES_BREAK) {
		exec->stopped = true;
		err = MAT_RES_NEXT;
	}

	return err;
}


/* Continue execution of an initialized executor.
 *
 * When actions are executed, two extraordinary things can happen:
 *  1) The STOP action is executed. In that case, exec.stopped is set to one
 *     and the cycle continues until fetching the next table, which clears the
 *     flag. This is needed to properly count TTL.
 *  2) The DROP action is executed. Dropped packets undergo no further
 *     processing, therefore the MAT_RES_DROP result is returned immediately.
 */
int mat_executor_run(struct mat_executor *exec, struct sk_buff *skb)
{
	struct mat_table *tbl = exec->table;
	struct mat_action_chain *ac = NULL;
	struct mat_flow_key *fkey;
	int err;

	if (!tbl)
		return -EFAULT;

	if (!exec->ttl)
		return -EINVAL;

	while (tbl) {
		if (!exec->ttl)
			return MAT_RES_BREAK;

		exec->ttl--;

		switch (exec->state) {
		case MAT_EXEC_NEXT_TABLE:
			exec->table = tbl = mat_table_get(exec->next_table);
			exec->next_table = 0;
			exec->stopped = false;
			exec->state = MAT_EXEC_PRE_CHAIN;
			break;

		case MAT_EXEC_PRE_CHAIN:
			if (!exec->stopped) {
				ac = tbl->table_chains[MAT_TABLE_CHAIN_PRE];
				if (ac) {
					log("executing pre chain");
					if ((err = mat_execute_action_chain(exec, ac, skb)))
						return -err;
				}
			}
			exec->state = MAT_EXEC_FLOW_LOOKUP;
			break;

		case MAT_EXEC_FLOW_LOOKUP:
			if (!exec->stopped) {
				log("looking up flow in table %u", mat_table_get_index(tbl));
				fkey = alloca(mat_flow_key_size(tbl));
				if (!fkey)
					return -ENOMEM;

				if ((err = mat_table_compute_key(fkey, tbl, skb)))
					return err;

				exec->action_chain = mat_table_flow_get_chain(tbl, fkey);
			}
			exec->state = MAT_EXEC_FLOW_CHAIN;
			break;

		case MAT_EXEC_FLOW_CHAIN:
			if (!exec->stopped) {
				ac = mat_table_get_action_chain(tbl, exec->action_chain);
				if (ac) {
					log("executing flow chain");
				} else {
					ac = tbl->table_chains[MAT_TABLE_CHAIN_DEFAULT];
					log("executing default chain");
				}
				if (ac && (err = mat_execute_action_chain(exec, ac, skb)))
					return err;

				exec->action_chain = 0;
			}
			exec->state = MAT_EXEC_POST_CHAIN;
			break;

		case MAT_EXEC_POST_CHAIN:
			if (!exec->stopped) {
				ac = tbl->table_chains[MAT_TABLE_CHAIN_POST];
				if (ac) {
					log("executing post chain");
					if ((err = mat_execute_action_chain(exec, ac, skb)))
						return err;
				}
			}
			exec->state = MAT_EXEC_NEXT_TABLE;
			break;

		default:
			return -EINVAL;
		}
	}

	return MAT_RES_NEXT;
}

/* Allocate an action chain. */
struct mat_action_chain *mat_action_chain_create(size_t len)
{
	return kzalloc(offsetof(struct mat_action_chain, chain[len]), GFP_KERNEL);
}

/* In reality, we would have used refcounts and cloning would not be needed. */
struct mat_action_chain *mat_action_chain_clone(struct mat_action_chain *chain)
{
	struct mat_action_chain *clone = mat_action_chain_create(chain->len);
	size_t i;

	if (!clone)
		return NULL;

	for (i = 0; i < chain->len; i++) {
		struct mat_action *src = &chain->chain[i];
		struct mat_action *dst = &clone->chain[i];

		memcpy(dst, src, sizeof(*dst));

		switch (dst->op) {
			case MAT_ACT_PRINT:
				if (!(dst->print.str = strdup(src->print.str)))
					goto err;
				break;
			default:
				break;
		}

		clone->len++;
	}

	return clone;

err:
	mat_action_chain_destroy(clone);
	return NULL;
}

/* Destroy a chain along with owned memory. */
void mat_action_chain_destroy(struct mat_action_chain *chain)
{
	size_t i;

	if (!chain)
		return;

	for (i = 0; i < chain->len; i++) {
		struct mat_action *act = &chain->chain[i];

		switch (act->op) {
			case MAT_ACT_PRINT:
				kfree(act->print.str);
				break;
			default:
				break;
		}
	}

	kfree(chain);
}


/* Decide whether the only effect of a chain is to drop the packet.
 * Ignores noops.
 */
bool mat_action_chain_is_drop_only(struct mat_action_chain *chain)
{
	size_t i;

	assert(chain);

	for (i = 0; i < chain->len; i++) {
		struct mat_action *act = &chain->chain[i];

		if (act->op == MAT_ACT_DROP)
			return true;

		if (!mat_action_is_noop(act))
			return false;
	}

	return false;
}

/* Decide whether an action is safe to be ignored when offloaded to the
 * hardware.
 */
bool mat_action_is_noop(struct mat_action *action)
{
	assert(action);

	return action->op == MAT_ACT_PASS || action->op == MAT_ACT_PRINT;
}
