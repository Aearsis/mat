/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 */

#include <tests.h>
#include <net/mat/table.h>

struct sk_buff sample_skb [1] = {{
	.data = {
		0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xFF, // Dest. MAC
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Src. MAC
		0x08, 0x00, // Ethertype = IP

		0x45, 0x00, 0x00, 0xFF, // Version, ToS, Total length
		0xCA, 0xCA, 0x00, 0x00, // Identifier, Flags, Offset
		0xFF, 0x06, 0x00, 0x00, // TTL, Protocol = TCP, Chsum
		0x42, 0xEF, 0xCD, 0xAB, // Source IP
		0x0D, 0xF0, 0xAD, 0x0B, // Dest IP

		0x00, 0x2A, 0x00, 0x2A, // Source + Dest port (= 42)
		0x00, 0x00, 0x00, 0x00, // Seq. no
		0x00, 0x00, 0x00, 0x00, // ACK no
		0x50, 0x00, 0x00, 0x00, // Length, Flats, Win. size

		// Payload
	},
	.dev = test_netdev,
}};

struct sk_buff sample_skb_2 [1] = {{
	.data = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Dest. MAC
		0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xFF, // Src. MAC
		0x08, 0x00, // Ethertype = IP

		0x45, 0x00, 0x00, 0xFF, // Version, ToS, Total length
		0xCA, 0xCA, 0x00, 0x00, // Identifier, Flags, Offset
		0xFF, 0x06, 0x00, 0x00, // TTL, Protocol = TCP, Chsum
		0x0D, 0xF0, 0xAD, 0x0B, // Source IP
		0x42, 0xEF, 0xCD, 0xAB, // Dest IP

		0x00, 0x2A, 0x00, 0x2A, // Source + Dest port (= 42)
		0x00, 0x00, 0x00, 0x00, // Seq. no
		0x00, 0x00, 0x00, 0x00, // ACK no
		0x50, 0x00, 0x00, 0x00, // Length, Flats, Win. size

		// Payload
	},
	.dev = test_netdev,
}};

const char * binder_type_to_str[] = {
	[TCF_BLOCK_BINDER_TYPE_CLSACT_INGRESS] = "ingress",
	[TCF_BLOCK_BINDER_TYPE_CLSACT_EGRESS] = "egress",
};

static int mock_setup_mat(struct net_device *dev, struct tcf_block *mat,
	enum tcf_block_binder_type binder_type)
{
	struct mat_table *tbl;

	tbl = mat->filter->data;
	log("mat table %u bound on %s",
		mat_table_get_index(tbl),
		binder_type_to_str[binder_type]);

	return -EOPNOTSUPP;
}

static int mock_setup_tc(struct net_device *dev, enum tc_setup_type type, void *type_data)
{
	struct tc_block_offload *bo = type_data;

	if (tc_setup_is_mat(type, type_data))
		return mock_setup_mat(dev, bo->block, bo->binder_type);

	return -EOPNOTSUPP;
}

const struct net_device_ops mock_netdev_ops = {
	.ndo_setup_tc = mock_setup_tc,
};

struct net_device test_netdev [1] = {{
	.netdev_ops = &mock_netdev_ops,
}};
