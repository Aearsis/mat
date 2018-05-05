/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 */

#include <net/mat/tcam.h>

void mat_tcam_init(struct mat_tcam *tcam)
{
	INIT_LIST_HEAD(&tcam->prio_list);
}

/* Find first prio structure with prio >= prio. */
static struct mat_tcam_prio *tcam_find_prio(struct mat_tcam *tcam, unsigned prio)
{
	struct mat_tcam_prio *tcam_prio;
	list_for_each_entry(tcam_prio, &tcam->prio_list, in_table) {
		if (tcam_prio->prio >= prio)
			return tcam_prio;
	}
	return NULL;
}

static struct mat_tcam_prio *tcam_get_prio(struct mat_tcam *tcam, unsigned prio)
{
	struct mat_tcam_prio *upper = tcam_find_prio(tcam, prio);

	if (upper && upper->prio == prio)
		return upper;

	struct mat_tcam_prio *tcam_prio = kzalloc(sizeof(*tcam_prio), GFP_KERNEL);
	tcam_prio->prio = prio;
	INIT_LIST_HEAD(&tcam_prio->in_table);
	INIT_LIST_HEAD(&tcam_prio->rules_list);

	list_add_tail(&tcam_prio->in_table, &tcam->prio_list);
	return tcam_prio;
}

int mat_tcam_insert(struct mat_tcam *tcam, unsigned prio, mat_tcam_key mask, mat_tcam_key value, int result)
{
	struct mat_tcam_prio *tcam_prio = tcam_get_prio(tcam, prio);

	struct mat_tcam_rule *rule = kzalloc(sizeof(*rule), GFP_KERNEL);

	rule->mask = mask;
	rule->value = value;
	rule->result = result;
	INIT_LIST_HEAD(&rule->in_prio);

	list_add_tail(&rule->in_prio, &tcam_prio->rules_list);
	return 0;
}

int mat_tcam_lookup(struct mat_tcam *tcam, mat_tcam_key value)
{
	struct mat_tcam_prio *prio;
	struct mat_tcam_rule *rule;

	list_for_each_entry(prio, &tcam->prio_list, in_table) {
		list_for_each_entry(rule, &prio->rules_list, in_prio) {
			mat_tcam_key masked = value & rule->mask;

			if (masked == rule->value)
				return rule->result;
		}
	}

	return 0;
}
