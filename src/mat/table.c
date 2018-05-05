/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 */

#include <mock.h>

#include <net/mat/executor.h>
#include <net/mat/netdev.h>
#include <net/mat/parser.h>
#include <net/mat/table.h>
#include <net/mat/tc.h>

#define log(format, ...) log_comp("table", format, ##__VA_ARGS__)

/* The per-netns storage of tables */
struct hashtable mat_tables = {};

/* As we do not have idr structure, use linear indices */
static mat_table_index table_index = 1;

/* Get a table structure based on index. Returns NULL when no such table
 * exists.
 */
struct mat_table *mat_table_get(mat_table_index idx)
{
	struct hashtable_entry *entry;

	if (!idx)
		return NULL;

	entry = hashtable_lookup(&mat_tables, idx);
	return entry ? container_of(entry, struct mat_table, entry) : NULL;
}

/* Get a table index from a pointer. */
mat_table_index mat_table_get_index(struct mat_table *tbl)
{
	return tbl->entry.index;
}

/* Allocate a flow key on the heap.
 *
 * In this code, it is mostly unused, as we usually use alloca to simplify
 * memory management. In the kernel code, using alloca is discouraged.
 */
struct mat_flow_key *mat_flow_key_alloc(struct mat_table *tbl)
{
	return kzalloc(mat_flow_key_size(tbl), GFP_KERNEL);
}

/* Set a field in the flow key.
 *
 * Beware, the field_index is NOT the global index of the field, but the index
 * among table fields!
 */
void mat_flow_key_set_field(struct mat_flow_key *fkey, struct mat_table *tbl,
	unsigned field_index, mat_header_field_value value)
{
	assert(field_index < tbl->field_count);
	struct mat_flow_key_mapping *mapping = &tbl->field_alloc[field_index];
	unsigned width = mat_field_get_width(tbl->fields[field_index]);
	mat_header_field_value mask = GENMASK_ULL(width, 0);

	fkey->part[mapping->part] |= (value & mask) << mapping->offset;
}

/* Get a field from the flow key.
 *
 * Beware, the field_index is NOT the global index of the field, but the index
 * among table fields!
 */
mat_header_field_value mat_flow_key_get_field(struct mat_flow_key *fkey, struct mat_table *tbl,
	unsigned field_index)
{
	assert(field_index < tbl->field_count);
	struct mat_flow_key_mapping *mapping = &tbl->field_alloc[field_index];
	unsigned width = mat_field_get_width(tbl->fields[field_index]);
	mat_header_field_value mask = GENMASK_ULL(width, 0);

	return (fkey->part[mapping->part] >> mapping->offset) & mask;
}

/* Calculates distribution of selected key values to key parts.
 *
 * There is a room for optimization, as this solves a Bin Packing problem.
 * We implement a greedy algorithm, which can use up to twice as much parts
 * as actually needed.
 */
static void table_init_flow_key_mapping(struct mat_table *tbl)
{
	tbl->field_alloc = kzalloc(tbl->field_count * sizeof(*tbl->field_alloc), GFP_KERNEL);

	unsigned part = 0;
	unsigned offset = 0;

	for (unsigned i = 0; i < tbl->field_count; i++) {
		unsigned width = mat_field_get_width(tbl->fields[i]);

		if (offset + width > 64) {
			part++; offset = 0;
		}

		tbl->field_alloc[i].part = part;
		tbl->field_alloc[i].offset = offset;
		offset += width;
	}

	tbl->flow_key_parts = part + 1;
}

/* Register a new table according to a template. Initialize it. */
mat_table_index mat_table_register(const struct mat_table_template *template)
{
	const mat_table_index idx = table_index++;
	struct mat_table *tbl = kzalloc(sizeof(*tbl), GFP_KERNEL);

	tbl->type = template->type;
	tbl->max_size = template->max_size;
	tbl->field_count = template->field_count;

	const size_t fields_size = template->field_count * sizeof(mat_field_index);
	tbl->fields = kzalloc(fields_size, GFP_KERNEL);
	memcpy(tbl->fields, template->fields, fields_size);

	hashtable_insert(&mat_tables, idx, &tbl->entry);
	mat_tc_init(tbl);
	table_init_flow_key_mapping(tbl);

	INIT_LIST_HEAD(&tbl->netdevs);
	tbl->events_announced = 0;

	switch (tbl->type) {
	case MAT_TABLE_TYPE_EXACT:
		tbl->exact.hash_order = 8;
		tbl->exact.buckets = kzalloc(sizeof(*tbl->exact.buckets) * (1 << tbl->exact.hash_order), GFP_KERNEL);
		break;
	case MAT_TABLE_TYPE_TCAM:
		INIT_LIST_HEAD(&tbl->tcam.rules);
		break;
	default:
		break;
	}

	log("table %i registered (type %i, %u-part key)", idx, tbl->type, tbl->flow_key_parts);
	return idx;
}

/* Calculate a flow key for the given table and skb. */
int mat_table_compute_key(struct mat_flow_key *key, struct mat_table *tbl, struct sk_buff *skb)
{
	int err;

	memset(key, 0, mat_flow_key_size(tbl));

	for (size_t i = 0; i < tbl->field_count; i++) {
		mat_header_field_value val;
		err = mat_parser_extract_field(&val, MAT_PARSER_ETHERNET, tbl->fields[i], skb);
		if (err)
			return err;

		mat_flow_key_set_field(key, tbl, i, val);
	}

	return 0;
}

/* Dump a flow key. Debug purposes only. */
void mat_flow_key_dump(struct mat_table *tbl, struct mat_flow_key *key, const char *label)
{
	size_t size = tbl->flow_key_parts * 19 + 1;
	char buf [size];
	size_t used = 0;

	for (unsigned i = 0; i < tbl->flow_key_parts; i++) {
		used += snprintf(buf + used, size - used, " %#016" PRIx64, key->part[i]);
	}

	log("%s of %u parts: %s", label, tbl->flow_key_parts, buf);
}

/* Compute a binary and of flow keys a and b and store it to dest.
 * All of them must belong to the same table.
 */
void mat_flow_key_and(const struct mat_table *tbl, struct mat_flow_key *dest,
	const struct mat_flow_key *a, const struct mat_flow_key *b)
{

	for (unsigned i = 0; i < tbl->flow_key_parts; i++) {
		dest->part[i] = a->part[i] & b->part[i];
	}
}

/* Decide, whether two flow keys are equal. Both must belong to the same table. */
bool mat_flow_key_equal(const struct mat_table *tbl,
	const struct mat_flow_key *a, const struct mat_flow_key *b)
{
	for (unsigned i = 0; i < tbl->flow_key_parts; i++) {
		if (a->part[i] != b->part[i])
			return false;
	}

	return true;
}

/* Compute an u64 hash value of a flow key by a simple hashing function.
 * Works well enough for the demonstration, should be replaced by a proper hash
 * function in reality.
 */
static u64 mat_flow_key_hash(const struct mat_table *tbl,
	const struct mat_flow_key *key)
{
	u64 hash = 0xdeadbeef;
	for (unsigned i = 0; i < tbl->flow_key_parts; i++)
		hash ^= (179426407 * key->part[i] >> i);
	return hash;
}

/* Insert a rule into exact table. */
static void mat_table_exact_insert(struct mat_table *tbl,
	const struct mat_flow_key *fkey, u64 flow_id)
{
	struct mat_exact_flow_entry *entry = kzalloc(sizeof(*entry) + mat_flow_key_size(tbl), GFP_KERNEL);
	const u64 hash = mat_flow_key_hash(tbl, fkey) & ((1 << tbl->exact.hash_order) - 1);

	memcpy(entry->fkey, fkey, mat_flow_key_size(tbl));
	entry->flow_id = flow_id;

	hlist_add_head(&entry->node, &tbl->exact.buckets[hash]);
}

/* Lookup a rule in exact matching table. */
static u64 mat_table_exact_lookup(struct mat_table *tbl, struct mat_flow_key *fkey)
{
	struct mat_exact_flow_entry *entry;
	const u64 hash = mat_flow_key_hash(tbl, fkey) & ((1 << tbl->exact.hash_order) - 1);

	hlist_for_each_entry(entry, &tbl->exact.buckets[hash], node) {
		if (mat_flow_key_equal(tbl, fkey, entry->fkey))
			return entry->flow_id;
	}

	return 0;
}

/* Insert a rule into a MAT TCAM table. */
static void mat_table_tcam_insert(struct mat_table *tbl,
	const struct mat_flow_key *mask, const struct mat_flow_key *value,
	u64 flow_id)
{
	struct mat_tcam_flow_entry *entry = kzalloc(sizeof(*entry), GFP_KERNEL);

	entry->mask = mat_flow_key_alloc(tbl);
	entry->value = mat_flow_key_alloc(tbl);
	entry->flow_id = flow_id;

	mat_flow_key_and(tbl, entry->mask, mask, mask);
	mat_flow_key_and(tbl, entry->value, mask, value);

	list_add(&entry->in_table, &tbl->tcam.rules);
}


/* Go through rules in a MAT TCAM table and return the first matching one.
 *
 * We could implement a better algorithm here. Either some decision tree or
 * breaking the TCAM into hash tables. For now, let's just walk them one by
 * one.
 */
static u64 mat_table_tcam_lookup(struct mat_table *tbl, struct mat_flow_key *fkey)
{
	struct mat_tcam_flow_entry *entry;
	struct mat_flow_key *cmp = alloca(mat_flow_key_size(tbl));

	list_for_each_entry(entry, &tbl->tcam.rules, in_table) {
		mat_flow_key_and(tbl, cmp, fkey, entry->mask);
		if (mat_flow_key_equal(tbl, cmp, entry->value))
			return entry->flow_id;
	}

	return 0;
}

/* Insert a flow into a MAT table. */
int mat_table_flow_insert(struct mat_table *tbl, struct mat_flow_key *mask,
	struct mat_flow_key *value, struct mat_action_chain *chain_templ)
{
	struct mat_action_chain *chain = mat_action_chain_clone(chain_templ);
	u64 flow_id = (u64) chain;

	switch (tbl->type) {
		case MAT_TABLE_TYPE_TCAM:
			hashtable_insert(&tbl->actions, flow_id, &chain->entry);
			mat_table_tcam_insert(tbl, mask, value, flow_id);
			break;

		case MAT_TABLE_TYPE_EXACT:
			hashtable_insert(&tbl->actions, flow_id, &chain->entry);
			mat_table_exact_insert(tbl, value, flow_id);
			break;

		case MAT_TABLE_TYPE_HASH:
			hashtable_insert(&tbl->actions, mat_flow_key_hash(tbl, value), &chain->entry);
			break;

		default:
			return ENOTSUP;
	}

	mat_netdev_flow_insert(tbl, mask, value, flow_id);
	return 0;
}

/* Lookup a flow in a MAT table, returning the associated flow ID. */
u64 mat_table_flow_get_chain(struct mat_table *tbl, struct mat_flow_key *fkey)
{
	switch (tbl->type) {
		case MAT_TABLE_TYPE_HASH:
			return mat_flow_key_hash(tbl, fkey);
		case MAT_TABLE_TYPE_EXACT:
			return mat_table_exact_lookup(tbl, fkey);
		case MAT_TABLE_TYPE_TCAM:
			return mat_table_tcam_lookup(tbl, fkey);
		default:
			return 0;
	}
}

/* Get an action chain for a given flow ID. */
struct mat_action_chain *mat_table_get_action_chain(struct mat_table *tbl, u64 flow_id)
{
	if (!flow_id)
		return NULL;

	struct hashtable_entry *fact = hashtable_lookup(&tbl->actions, flow_id);
	if (!fact)
		return NULL;

	return container_of(fact, struct mat_action_chain, entry);
}

/* Set one of the table chains. */
int mat_table_set_table_chain(struct mat_table *tbl, enum mat_table_chain chain_kind,
	struct mat_action_chain *chain_templ)
{
	struct mat_action_chain *chain = mat_action_chain_clone(chain_templ);

	mat_action_chain_destroy(tbl->table_chains[chain_kind]);
	tbl->table_chains[chain_kind] = chain;
	return 0;
}
