/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 */

#pragma once

#include <mock.h>
#include <linux/list.h>
#include <linux/mat.h>

/* This structure simulates TCAM matching table on 64-bit values.
 *
 * Table has many prios, prio has many rules.
 *
 * Table goes over its rules in ascending priority order and returns first
 * match.
 */

#define TCAM_PRIO_MIN 0
#define TCAM_PRIO_MAX -1U

typedef u64 mat_tcam_key;

struct mat_tcam_prio {
	struct list_head in_table;
	struct list_head rules_list;

	unsigned prio;
};

struct mat_tcam_rule {
	struct list_head in_prio;

	mat_tcam_key mask, value;
	int result;
};

struct mat_tcam {
	struct list_head prio_list;
};

void mat_tcam_init(struct mat_tcam *tcam);

int mat_tcam_insert(struct mat_tcam *tcam, unsigned prio, mat_tcam_key mask, mat_tcam_key value, int result);

int mat_tcam_lookup(struct mat_tcam *tcam, mat_tcam_key value);
