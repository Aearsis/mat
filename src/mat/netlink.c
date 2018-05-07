/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 *
 * This is the layer for translating netlink calls.
 *
 * For the purposes of the demonstrator, we avoid the (un)marshalling of
 * messages by calling the methods directly, when the number of arguments is
 * fixed.
 */

#include <mock.h>
#include <linux/mat.h>

#include <net/mat/executor.h>
#include <net/mat/parser.h>
#include <net/mat/table.h>

#define log(format, ...) log_comp("netlink", format, ##__VA_ARGS__)

/* Register a field according to template */
mat_field_index mat_nl_field_register(const struct mat_header_field_template *template)
{
	return mat_field_register(template);
}

mat_parser_index mat_nl_parser_register(const char *name,
	mat_field_index nexthdr, mat_field_index hdrsize)
{
	return mat_parser_register(name, nexthdr, hdrsize);
}

int mat_nl_parser_add_next(mat_parser_index parent,
	size_t nexthdr, mat_parser_index child)
{
	return mat_parser_add_next(parent, nexthdr, child);
}

int mat_nl_field_set_parser(mat_field_index field,
	mat_parser_index parser)
{
	struct mat_header_field *f = mat_header_field_get(field);
	struct mat_parser *p = mat_parser_get(parser);

	if (!p || !f)
		return -ENOENT;

	return mat_field_set_parser(f, p);
}

mat_table_index mat_nl_table_register(const struct mat_table_template *template)
{
	return mat_table_register(template);
}

u32 mat_nl_table_get_block_index(mat_table_index table)
{
	struct mat_table *tbl = mat_table_get(table);
	return tbl ? tbl->block->index : 0;
}

static int nl_parse_flow_field_arg(struct mat_table *tbl, struct mat_flow_key *fkey,
	struct mat_msg_arg *arg, size_t *processed)
{
	size_t j;

	for (j = 0; j < tbl->field_count; j++) {
		if (arg->field.field == tbl->fields[j]) {
			mat_flow_key_set_field(fkey, tbl, j, arg->field.value);
			return 0;
		}
	}

	return ENOENT;
}

static int nl_parse_flow_key_args(struct mat_table *tbl, struct mat_flow_key *mask, struct mat_flow_key *value,
	struct mat_msg *msg, size_t *processed)
{
	size_t i;

	for (i = 0; i < msg->arg_count; i++) {
		struct mat_msg_arg *arg = &msg->args[i];

		switch (arg->type) {
			case MAT_FLOW_ARG_FIELD_MASK:
				// FIXME: check whether the table acknowledges mask
				*processed += !nl_parse_flow_field_arg(tbl, mask, arg, processed);
				break;
			case MAT_FLOW_ARG_FIELD_VALUE:
				*processed += !nl_parse_flow_field_arg(tbl, value, arg, processed);
				break;

			default:
				break;
		}
	}

	return 0;
}

static int nl_parse_action_args(struct mat_table *tbl, struct mat_action_chain **dest, struct mat_msg *msg,
	size_t *processed)
{
	size_t actions = 0, i;

	for (i = 0; i < msg->arg_count; i++) {
		struct mat_msg_arg *arg = &msg->args[i];
		actions += arg->type == MAT_FLOW_ARG_ACTION;
	}

	struct mat_action_chain *chain = kzalloc(sizeof(*chain)
		+ actions * sizeof(struct mat_action), GFP_KERNEL);
	if (!chain)
		return ENOMEM;

	*dest = chain;

	for (i = 0; i < msg->arg_count; i++) {
		struct mat_msg_arg *arg = &msg->args[i];
		if (arg->type != MAT_FLOW_ARG_ACTION)
			continue;

		struct mat_action *act = &chain->chain[chain->len++];
		memcpy(act, &arg->action, sizeof(*act));

		switch (arg->action.op) {
			case MAT_ACT_PASS:
			case MAT_ACT_DROP:
			case MAT_ACT_SET_NEXT:
			case MAT_ACT_SET_TC:
			case MAT_ACT_STOP:
				break;
			case MAT_ACT_PRINT:
				act->print.str = strdup(arg->action.print.str);
				break;
			default:
				return ENOTSUP;
		}
	}

	*processed += actions;
	return 0;
}


/* Some calls need to have variable args, so its simpler to implement the real
 * protocol.
 */
int mat_nl_msg(struct mat_msg *msg)
{
	struct mat_table *tbl = mat_table_get(msg->table);
	struct mat_action_chain *chain = NULL;
	struct mat_flow_key *mask, *value;
	size_t processed = 0;

	if (!tbl)
		return ENOENT;

	mask = mat_flow_key_alloc(tbl);
	value = mat_flow_key_alloc(tbl);

	switch (msg->type) {
		case MAT_MSG_FLOW_INSERT:
			if ((errno = nl_parse_flow_key_args(tbl, mask, value, msg, &processed))
				|| (errno = nl_parse_action_args(tbl, &chain, msg, &processed)))
				goto err;

			if (msg->arg_count != processed) {
				log("Only %zu/%zu arguments processed.", processed, msg->arg_count);
				errno = EINVAL;
				goto err;
			}

			mat_flow_key_dump(tbl, mask, "mask");
			mat_flow_key_dump(tbl, value, "value");
			if ((errno = mat_table_flow_insert(tbl, mask, value, chain)))
				goto err;

			break;

		case MAT_MSG_SET_PRE_CHAIN:
		case MAT_MSG_SET_DEFAULT_CHAIN:
		case MAT_MSG_SET_POST_CHAIN:
			if ((errno = nl_parse_action_args(tbl, &chain, msg, &processed)))
				goto err;

			if (msg->arg_count != processed) {
				log("not all arguments processed!");
				errno = EINVAL;
				goto err;
			}

			if ((errno = mat_table_set_table_chain(tbl, msg->type - 1, chain)))
				goto err;

			break;

		default:
			log("unknown message");
			errno = ENOTSUP;
			goto err;
	}

err:
	kfree(mask);
	kfree(value);
	mat_action_chain_destroy(chain);
	return errno;
}
