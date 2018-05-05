/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 *
 * This module stores the data representation of the parser.
 */

#pragma once

#include <stdlib.h>
#include <linux/mat.h>
#include <mock.h>

#include "tcam.h"

struct mat_header_field {
	const char *name;

	/* Field extraction */
	int offset, width;

	/* Field decoding */
	int shift, add;

	/* Homing parser */
	mat_parser_index parser;
};

struct mat_parser {
	const char *name;

	/* The field that returns how many bytes to skip to reach the next header. */
	mat_field_index hdrsize;

	/* The field that returns a value to look up in the next_parser TCAM. */
	mat_field_index nexthdr;

	/* Next parser selection */
	struct mat_tcam next_parser;
};

mat_field_index mat_field_register(const struct mat_header_field_template *t);
struct mat_header_field *mat_header_field_get(mat_field_index idx);
int mat_field_set_parser(struct mat_header_field *f, struct mat_parser *p);
bool mat_field_is_custom(mat_field_index f);

static inline int mat_field_is_const(struct mat_header_field *f)
{
	return f->width == 0;
}

mat_parser_index mat_parser_register(const char *name,
	mat_field_index nexthdr, mat_field_index hdrsize);
struct mat_parser *mat_parser_get(mat_parser_index idx);

int mat_parser_add_next(mat_parser_index parent, size_t nexthdr, mat_parser_index child);

unsigned mat_field_get_width(mat_field_index field);
int mat_parser_dump();

/* This API is overly simplified for the demonstration - this method is called
 * for every field, thus the packet is parsed all over again.
 *
 * But it is sufficient to show that we have all the information we need to
 * parse the packet.
 */
int mat_parser_extract_field(mat_header_field_value *val,
	mat_parser_index parser, mat_field_index field, struct sk_buff *skb);
