/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 */

#pragma once

#include <mock.h>
#include <hashtable.h>

/* This is the userspace API of the Match-Action Tables subsystem.
 */

#define MAT_FIELD_MAX 256
#define MAT_PARSER_MAX 256

#define MAT_MAX_KEY_SIZE 64
#define MAT_MAX_TABLES 64

/* The parser in ASIC can be fixed. We emulate fully-programmable parser, but
 * that would be hard to offload for simpler devices. Instead, well-known
 * fields have these well-known indices.
 *
 * Beware that the field extraction may vary between SW and HW. For well-nown
 * fields, this is acceptable. The userspace is expected to use these
 * semantically.
 */
enum mat_header_field_type {
	MAT_FIELD_NONE,
	MAT_FIELD_ETHERNET_HLEN,
	MAT_FIELD_ETHERNET_NEXT,
	MAT_FIELD_ETHERNET_MAC_DST,
	MAT_FIELD_ETHERNET_MAC_SRC,
	MAT_FIELD_VLAN_HLEN,
	MAT_FIELD_VLAN_NEXT,
	MAT_FIELD_VLAN_ID,
	MAT_FIELD_VLAN_INNER_ID,
	MAT_FIELD_ETHERTYPE_HLEN,
	MAT_FIELD_ETHERTYPE,
	MAT_FIELD_IP_HLEN,
	MAT_FIELD_IP_PROTO,
	MAT_FIELD_IP_SRC,
	MAT_FIELD_IP_DST,

	/* These two are parsed from an IP header without options directly. Unless
	 * the IP_PROTO is TCP or UDP and the header contains no options, these
	 * fields contain garbage. They are here to reflect how hardware matches
	 * 5-tuples.
	 */
	MAT_FIELD_IP_SPORT,
	MAT_FIELD_IP_DPORT,

	MAT_FIELD_TCP_HDRSIZE,
	MAT_FIELD_TCP_SPORT,
	MAT_FIELD_TCP_DPORT,

	MAT_FIELD_UDP_HDRSIZE,
	MAT_FIELD_UDP_SPORT,
	MAT_FIELD_UDP_DPORT,
	__MAT_FIELD_FIRST_CUSTOM,
	__MAT_FIELD_MAX = MAT_FIELD_MAX
};

enum mat_parser_index {
	MAT_PARSER_NONE,
	MAT_PARSER_ETHERNET,
	MAT_PARSER_VLAN,
	MAT_PARSER_VLAN_INNER,
	MAT_PARSER_ETHERTYPE,
	MAT_PARSER_IP,
	MAT_PARSER_TCP,
	MAT_PARSER_UDP,
	__MAT_PARSER_FIRST_CUSTOM,
	__MAT_PARSER_MAX = MAT_PARSER_MAX
};

enum mat_table_type {
	MAT_TABLE_TYPE_HASH,
	MAT_TABLE_TYPE_EXACT,
	MAT_TABLE_TYPE_TCAM,
};

/* These typedefs would not be part of the uAPI directly, as the subsystem will
 * be controlled via netlink.
 */
typedef uint8_t mat_field_index;
typedef uint8_t mat_parser_index;
typedef uint16_t mat_table_index;

/* Unfortunately, we can not work with fields larger than 64b without
 * complicating the parser code.
 *
 * On the other hand, it might be even worth working with 32b only, splitting
 * large fields into smaller ones (like IPv6 address to 4 chunks of 32b) and
 * letting the userspace handle it properly.
 */
typedef u64 mat_header_field_value;

#define MAT_MASK_ONES (~(0ULL))

/* A field that can be extracted. */
struct mat_header_field_template {
	/* A name for nicer debug prints */
	const char *name;

	/* Field extraction */
	int offset, width;

	/* Field decoding */
	int shift, add;
};

enum mat_table_chain {
	MAT_TABLE_CHAIN_PRE,
	MAT_TABLE_CHAIN_POST,
	MAT_TABLE_CHAIN_DEFAULT,
	__MAT_TABLE_CHAIN_COUNT,
};

/* Available actions: */
enum mat_action_op {
	MAT_ACT_PASS,		/* No-op. */
	MAT_ACT_DROP,		/* Drop the packet. */
	MAT_ACT_SET_NEXT,	/* Set the table to process next. */
	MAT_ACT_SET_TC,		/* As MAT is a classifier, this is the result class. */
	MAT_ACT_STOP,		/* Stop processing this table. */
	MAT_ACT_PRINT,		/* Print a debug log. */
};

/* Action with optional argument. */
struct mat_action {
	enum mat_action_op op;
	union {
		struct {
			mat_table_index table;
		} set_next;
		struct {
			u16 index;
		} set_tc;
		struct {
			const char *str;
		} print;
	};
};

struct mat_table_template {
	enum mat_table_type type;
	size_t max_size;

	size_t field_count;
	mat_field_index *fields;
};

enum mat_msg_arg_type {
	MAT_FLOW_ARG_FIELD_VALUE,
	MAT_FLOW_ARG_FIELD_MASK,
	MAT_FLOW_ARG_ACTION,
};

struct mat_msg_arg {
	enum mat_msg_arg_type type;
	union {
		struct {
			mat_field_index field;
			mat_header_field_value value;
		} field;
		struct mat_action action;
	};
};

enum mat_msg_type {
	MAT_MSG_FLOW_INSERT,
	MAT_MSG_SET_PRE_CHAIN,
	MAT_MSG_SET_POST_CHAIN,
	MAT_MSG_SET_DEFAULT_CHAIN,
};

/* The netlink message. Should end with an array of arg_count arguments.
 * The order of arguments matter for args of type MAT_FLOW_ARG_ACTION.
 */
struct mat_msg {
	enum mat_msg_type type;
	mat_table_index table;
	size_t arg_count;
	struct mat_msg_arg args [];
};


int mat_nl_msg(struct mat_msg *);

mat_field_index mat_nl_field_register(const struct mat_header_field_template *template);
int mat_nl_field_set_parser(mat_parser_index parser, mat_field_index field);

mat_parser_index mat_nl_parser_register(const char *name, mat_field_index nexthdr, mat_field_index hdrsize);
int mat_nl_parser_add_next(mat_parser_index parent, size_t nexthdr, mat_parser_index child);

mat_table_index mat_nl_table_register(const struct mat_table_template *template);
u32 mat_nl_table_get_block_index(mat_table_index table);

int mat_nl_parser_add_field(mat_parser_index parser, mat_field_index field);
