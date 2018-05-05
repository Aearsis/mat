/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 *
 * Very simple implementation of a hash table mapping u64 to hashtable_entry.
 *
 * The table contains always 256 buckets and uses a simple hash function to
 * distribute the indices evenly.
 */

#pragma once

#include <linux/list.h>

struct hashtable_entry {
	struct hlist_node node;
	u64 index;
};

struct hashtable {
	struct hlist_head buckets [256];
};

/* Multiply value with a big prime, then xor the bytes together.
 * Good enough for our purpose.
 */
static inline u8 simple_hash64(u64 value) {
	value *= 179426407;
	value = (value & 0xfffffff) ^ (value >> 32);
	value = (value & 0xffff)    ^ (value >> 16);
	value = (value & 0xff)      ^ (value >> 8);
	return value;
}

static inline struct hashtable_entry *hashtable_lookup(struct hashtable *ht, u64 index)
{
	struct hashtable_entry *entry;
	const u64 hash = simple_hash64(index);

	hlist_for_each_entry(entry, &ht->buckets[hash], node) {
		if (entry->index == index)
			return entry;
	}

	return NULL;
}

static inline void hashtable_insert(struct hashtable *ht, u64 index, struct hashtable_entry *entry)
{
	const u64 hash = simple_hash64(index);

	entry->index = index;
	hlist_add_head(&entry->node, &ht->buckets[hash]);
}
