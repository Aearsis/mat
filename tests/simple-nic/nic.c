/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 */


#include <mock.h>
#include <tests.h>
#include <net/mat/netdev.h>
#include <net/mat/table.h>
#include <linux/mat.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "nic.h"

/* This is an example "driver" of a network controller. The controller is able
 * to offload 5-tuple filter. We simulate the rules being offloaded by
 * hardware by keeping a list of rules in the software.
 *
 * The "hardware" matches 5-tuple. Packets to be dropped are dropped right
 * away, more complex actions are handled by executor.
 */


#undef log
#define log(fmt, ...) log_comp("nic", fmt, ##__VA_ARGS__)

/* Private data stored in netdev. */
struct simple_nic_priv {
	struct list_head ftuple_rules;
	struct mat_table *ftuple_tbl;
};

struct ftuple_rule {
	struct list_head in_priv;
	u64 cookie;
	bool drop;
	struct {
		u32 sip, dip;
		u16 sport, dport;
		u8 ipproto;
	} mask, value;
};

/* Insert an offloaded flow "to the hardware". Errors here would actually
 * require the offload to be stopped completely.
 */
int flow_insert(struct net_device *dev, struct mat_table *tbl,
	struct mat_flow_key *mask, struct mat_flow_key *value,
	u64 action_id)
{
	struct simple_nic_priv *priv = netdev_priv(dev);
	struct ftuple_rule *rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	size_t i;

	if (!rule)
		return ENOMEM;

	INIT_LIST_HEAD(&rule->in_priv);
	rule->cookie = action_id;

	for (i = 0; i < tbl->field_count; ++i) {
		switch (tbl->fields[i]) {
		case MAT_FIELD_IP_PROTO:
			rule->mask.ipproto = mat_flow_key_get_field(mask, tbl, i);
			rule->value.ipproto = mat_flow_key_get_field(value, tbl, i);
			break;
		case MAT_FIELD_IP_SRC:
			rule->mask.sip = mat_flow_key_get_field(mask, tbl, i);
			rule->value.sip = mat_flow_key_get_field(value, tbl, i);
			break;
		case MAT_FIELD_IP_DST:
			rule->mask.dip = mat_flow_key_get_field(mask, tbl, i);
			rule->value.dip = mat_flow_key_get_field(value, tbl, i);
			break;
		case MAT_FIELD_IP_SPORT:
			rule->mask.sport = mat_flow_key_get_field(mask, tbl, i);
			rule->value.sport = mat_flow_key_get_field(value, tbl, i);
			break;
		case MAT_FIELD_IP_DPORT:
			rule->mask.dport = mat_flow_key_get_field(mask, tbl, i);
			rule->value.dport = mat_flow_key_get_field(value, tbl, i);
			break;
		}
	}

	struct mat_action_chain *chain = mat_table_get_action_chain(tbl, action_id);
	rule->drop = mat_action_chain_is_drop_only(chain);

	list_add(&rule->in_priv, &priv->ftuple_rules);
	log("rule inserted to the \"hardware\"");

	return 0;
}

int set_table_chain(struct net_device *dev, struct mat_table *tbl,
	enum mat_table_chain chain_kind, struct mat_action_chain *chain)
{
	log("table chain changed");
	return EOPNOTSUPP;
}

struct mat_netdev_ops offload_ftuple = {
	.flow_insert = flow_insert,
	.set_table_chain = set_table_chain,
};

int setup_mat(struct net_device *dev, struct tcf_block *mat)
{
	struct simple_nic_priv *priv = netdev_priv(dev);
	struct mat_table *tbl = mat->filter->data;
	size_t i;

	assert(mat->type == TCF_BLOCK_MAT);

	if (priv->ftuple_tbl) {
		// Un-offload the old table
	}

	if (tbl->type != MAT_TABLE_TYPE_TCAM)
		return -EOPNOTSUPP;

	for (i = 0; i < tbl->field_count; ++i)
		switch (tbl->fields[i]) {
			case MAT_FIELD_IP_PROTO:
			case MAT_FIELD_IP_SRC:
			case MAT_FIELD_IP_DST:
			case MAT_FIELD_IP_SPORT:
			case MAT_FIELD_IP_DPORT:
				break;
			default:
				return -EOPNOTSUPP;
		}

	priv->ftuple_tbl = tbl;

	return -mat_netdev_bind(tbl, dev, &offload_ftuple);
}

static int setup_tc(struct net_device *dev, enum tc_setup_type type, void *type_data)
{
	struct tc_block_offload *bo = type_data;

	if (!tc_setup_is_mat(type, type_data))
		return -EOPNOTSUPP;

	return setup_mat(dev, bo->block);
}

/* A metadata descriptor, which the NIC gives to the software with every packet. */
struct simple_nic_desc {
	struct sk_buff *skb;

	bool ip;
	u8 ipproto;
	u32 sip, dip;

	bool tcp;
	u16 sport, dport;

	u64 cookie;
};

/* Emulate the hardware fixed parser identifying some fields from the packet. */
static void hardware_parser(struct net_device *dev, struct simple_nic_desc *desc)
{
	log("parsing the packet in hardware");

	struct ethhdr *eth = (void *) desc->skb->data;
	desc->ip = (ntohs(eth->h_proto) == ETH_P_IP);

	if (!desc->ip)
		return;

	struct iphdr *iph = (void *) (eth + 1);
	desc->sip = iph->saddr;
	desc->dip = iph->daddr;
	desc->ipproto = iph->protocol;
	desc->tcp = (desc->ipproto == IPPROTO_TCP);

	if (!desc->tcp)
		return;

	struct tcphdr *tcph = (void *) (iph + 1);
	desc->sport = tcph->source;
	desc->dport = tcph->dest;
}

/* Simulate the hardware blacklist 5-tuple filter. */
static void hardware_ftuple_filter(struct net_device *dev, struct simple_nic_desc *desc)
{
	struct simple_nic_priv *priv = netdev_priv(dev);
	struct ftuple_rule *rule;

	/* Only TCP/IP packets are candidates for the filter */
	if (!desc->ip || !desc->tcp)
		return;

	/* Go through rules and skip not-matching */
#define MATCHES(key) (rule->value.key == (desc->key & rule->mask.key))
	list_for_each_entry(rule, &priv->ftuple_rules, in_priv) {
		if (!MATCHES(ipproto)
			|| !MATCHES(sip) || !MATCHES(dip)
			|| !MATCHES(sport) || !MATCHES(dport))
			continue;

		if (rule->drop)
			desc->skb = NULL;

		desc->cookie = rule->cookie;
		return;
	}
#undef MATCHES

	/* Missed packets go through */
	desc->cookie = 0;
}

/* Handle a packet which could have been filtered by the hardware. */
static void offloaded_ftuple_filter(struct net_device *dev, struct simple_nic_desc *desc)
{
	struct simple_nic_priv *priv = netdev_priv(dev);

	if (!priv->ftuple_tbl) {
		log("hardware 5-tuple filter not yet configured.");
		return;
	}

	log("hardware filter allowed the packet, %s cookie", desc->cookie ? "got" : "no");
	struct mat_executor exec = {
		.table = priv->ftuple_tbl,
		.state = MAT_EXEC_FLOW_CHAIN,
		.action_chain = desc->cookie,
		.ttl = MAT_EXEC_DEFAULT_TTL,
	};

	switch (mat_executor_run(&exec, desc->skb)) {
		case MAT_RES_NEXT:
			desc->skb->tc_skip_classify = true;
			break;
		case MAT_RES_DROP:
		case MAT_RES_BREAK:
			desc->skb = NULL;
			break;
	}
}

void simple_nic_receive(struct net_device *dev, struct sk_buff *skb)
{
	struct simple_nic_desc desc [1] = {{
		.skb = skb,
	}};
	skb->dev = dev;

	/* Simulate the hardware pipeline */
	hardware_parser(dev, desc);
	hardware_ftuple_filter(dev, desc);

	if (!desc->skb) {
		log("the packet was dropped in hardware");
		return;
	}

	/* Now the packet was retrieved from the hardware. Let's see what info we got. */

	/* TCP/IP packet are handled by hardware. When a table is offloaded and the
	 * packet is TCP/IP, we know the cookie is valid.
	 */
	if (desc->ip && desc->tcp)
		offloaded_ftuple_filter(dev, desc);

	if (!desc->skb)
		return;

	netif_receive_skb(skb);
}

static struct net_device_ops simple_nic_ops = {
	.ndo_setup_tc = setup_tc,
};

void simple_nic_init(struct net_device *dev)
{
	struct simple_nic_priv *priv = kzalloc(sizeof(*priv), GFP_KERNEL);

	INIT_LIST_HEAD(&priv->ftuple_rules);

	dev->netdev_ops = &simple_nic_ops;
	dev->priv = priv;
}

void simple_nic_destroy(struct net_device *dev)
{
	struct simple_nic_priv *priv = netdev_priv(dev);
	struct ftuple_rule *rule, *n;

	list_for_each_entry_safe(rule, n, &priv->ftuple_rules, in_priv)
		kfree(rule);

	kfree(priv);
}
