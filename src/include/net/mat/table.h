/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 *
 * The representation of tables and the main functionality of the MAT subsystem.
 */

#pragma once

#include <hashtable.h>
#include <linux/mat.h>
#include <mock.h>

/* The key used to define a flow. Its size is determined by
 * table->flow_key_parts. The interpretation of content also varies with the
 * table. A flow key is always bound to one table, but the pointer to the table
 * is not stored to save space.
 */
struct mat_flow_key {
	u64 part [0];
};

/* Where to find a field value in a flow key. Precomputed at the table creation time. */
struct mat_flow_key_mapping {
	unsigned part, offset;
};

/* A flow in a TCAM table. */
struct mat_tcam_flow_entry {
	struct list_head in_table;
	struct mat_flow_key *mask, *value;
	u64 flow_id;
};

/* A flow in an exact table. */
struct mat_exact_flow_entry {
	struct hlist_node node;
	u64 flow_id;
	struct mat_flow_key fkey [0];
};

struct mat_table {
	struct hashtable_entry entry;

	enum mat_table_type type;
	size_t max_size;

	/* The fields used */
	size_t field_count;
	mat_field_index *fields;

	/* Interpretation & size of the flow key */
	struct mat_flow_key_mapping *field_alloc;
	unsigned flow_key_parts;

	/* Associated TC block */
	struct tcf_block *block;

	/* The action chains. */
	struct hashtable actions;
	struct mat_action_chain *table_chains [__MAT_TABLE_CHAIN_COUNT];

	/* Netdevs possibly offloading this table */
	struct list_head netdevs;
	size_t events_announced;

	/* Type-specific data */
	union {
		struct {
			/* We still want to hash, but we have to select based on flow keys,
			 * not indices, so we have to reimplement the hashtable.
			 */
			struct hlist_head *buckets;
			char hash_order;
		} exact;
		struct {
			/* Hashed tables use the flow hash as the action ID directly. */
		} hash;
		struct {
			/* The list of rules, plain and simple */
			struct list_head rules;
		} tcam;
	};
};

struct mat_table *mat_table_get(mat_table_index idx);
int mat_table_compute_key(struct mat_flow_key *key, struct mat_table *tbl, struct sk_buff *skb);

mat_table_index mat_table_register(const struct mat_table_template *template);
mat_table_index mat_table_get_index(struct mat_table *tbl);

static inline size_t mat_flow_key_size(struct mat_table *tbl)
{
	return offsetof(struct mat_flow_key, part[tbl->flow_key_parts]);
}

static inline size_t mat_table_field_count(struct mat_table *tbl)
{
	return tbl->field_count;
}

/* This function is used in the slow path only, also the number of fields is
 * considered to be rather low.
 */
static inline bool mat_table_uses_field(struct mat_table *tbl, mat_field_index fld)
{
	for (size_t i = 0; i < tbl->field_count; ++i)
		if (tbl->fields[i] == fld)
			return true;
	return false;
}

struct mat_flow_key *mat_flow_key_alloc(struct mat_table *tbl);
void mat_flow_key_set_field(struct mat_flow_key *fkey, struct mat_table *tbl, unsigned field_index, mat_header_field_value value);
mat_header_field_value mat_flow_key_get_field(struct mat_flow_key *fkey, struct mat_table *tbl, unsigned field_index);
void mat_flow_key_dump(struct mat_table *tbl, struct mat_flow_key *key, const char *label);

int mat_table_flow_insert(struct mat_table *tbl, struct mat_flow_key *mask, struct mat_flow_key *value, struct mat_action_chain *chain);
int mat_table_set_table_chain(struct mat_table *tbl, enum mat_table_chain chain_kind, struct mat_action_chain *chain);

u64 mat_table_flow_get_chain(struct mat_table *tbl, struct mat_flow_key *fkey);
struct mat_action_chain *mat_table_get_action_chain(struct mat_table *tbl, u64 flow_id);
