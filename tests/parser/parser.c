/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 */

#include <linux/mat.h>
#include <linux/in.h>
#include <net/mat/parser.h>
#include <net/mat/table.h>
#include <tests.h>

/* A simple test, which extends the parser with the VXLAN header.
 * A table is then created to demonstrate offloading with programmable parser.
 */

const struct mat_header_field_template vxlan_vni_templ = {
	.name = "VNI",
	.offset = 16,
	.width = 16,
};

static int setup_tc(struct net_device *dev, enum tc_setup_type type, void *type_data);

static struct net_device_ops parser_nic_ops = {
	.ndo_setup_tc = setup_tc,
};

int main(int argc, char ** argv)
{
	test_netdev->netdev_ops = &parser_nic_ops;

	log("dumping parser before...");
	mat_parser_dump();
	hr();

	log("registering custom parser");
	mat_parser_index vxlan_parser = mat_nl_parser_register("vxlan", 0, 0);
	mat_nl_parser_add_next(MAT_PARSER_UDP, 4789, vxlan_parser);

	mat_field_index vxlan_vni = mat_nl_field_register(&vxlan_vni_templ);
	mat_nl_field_set_parser(vxlan_vni, vxlan_parser);
	hr();

	log("dumping parser after...");
	mat_parser_dump();

	hr();
	log("registering table");

	mat_field_index fields [] = {
		vxlan_vni
	};

	struct mat_table_template tbl_templ = {
		.type = MAT_TABLE_TYPE_TCAM,

		.fields = fields,
		.field_count = sizeof(fields) / sizeof(*fields),
	};

	mat_table_index table = mat_nl_table_register(&tbl_templ);
	unsigned ingress_block = mat_nl_table_get_block_index(table);

	log("hooking block %u to netdev's ingress", ingress_block);
	tc_modify_qdisc(test_netdev, ingress_block, 0);
	hr();

	return 0;
}

/* Find an offset of a the field inside the transport network layer payload.
 *
 * Starts at UDP or TCP parser and recursively searches for the field. As there
 * might be multiple paths to the field, return 0 only when any offset is found
 * and all offsets are numerically equal.
 */
static int find_hdr_offset(int *offset, mat_parser_index pidx, struct mat_header_field *f)
{
	struct mat_parser *parser = mat_parser_get(pidx);
	struct mat_tcam_prio *prio;
	struct mat_tcam_rule *rule;
	int inner_offset;
	int err;

	/* Look in the current parser */
	*offset = f->parser == pidx ? 0 : -1;

	struct mat_header_field *hdrsize = mat_header_field_get(parser->hdrsize);
	if (!hdrsize)
		goto end;

	/* Limit ourselves to constant-sized headers */
	assert(mat_field_is_const(hdrsize));

	/* Look in next headers */
	list_for_each_entry(prio, &parser->next_parser.prio_list, in_table) {
		list_for_each_entry(rule, &prio->rules_list, in_prio) {
			err = find_hdr_offset(&inner_offset, rule->result, f);
			if (err == ENOENT)
				continue;

			if (err)
				return err;

			inner_offset += hdrsize->add * 8;

			if (*offset != -1 && inner_offset != *offset)
				return EEXIST;

			*offset = inner_offset;
		}
	}

end:
	return *offset == -1 ? ENOENT : 0;
}

int setup_mat(struct net_device *dev, struct tcf_block *mat)
{
	struct mat_table *tbl = mat->filter->data;
	assert(mat->type == TCF_BLOCK_MAT);

	if (tbl->field_count != 1)
		return -EOPNOTSUPP;

	struct mat_header_field *f = mat_header_field_get(tbl->fields[0]);
	int offset = -1;

	if (!find_hdr_offset(&offset, MAT_PARSER_TCP, f)) {
		log("would extract %u bits from offset %u within the TCP payload.",
			f->width, offset + f->offset);
		return 0;
	}

	if (!find_hdr_offset(&offset, MAT_PARSER_UDP, f)) {
		log("would extract %u bits from offset %u within the UDP payload.",
			f->width, f->offset);
		return 0;
	}

	return -EOPNOTSUPP;
}

static int setup_tc(struct net_device *dev, enum tc_setup_type type, void *type_data)
{
	struct tc_block_offload *bo = type_data;

	if (!tc_setup_is_mat(type, type_data))
		return -EOPNOTSUPP;

	return setup_mat(dev, bo->block);
}
