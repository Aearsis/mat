/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 */

#include <errno.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/mat.h>
#include <linux/in.h>
#include <stdlib.h>
#include <string.h>

#include <net/mat/parser.h>

#define log(format, ...) log_comp("parser", format, ##__VA_ARGS__)

/* The declaration of the preconfigured header fields. */
static struct mat_header_field mat_header_fields [MAT_FIELD_MAX] = {
	[MAT_FIELD_ETHERNET_HLEN] = {
		.name = "ethernet hlen",
		.width = 0,
		.add = 12,
	},
	[MAT_FIELD_ETHERNET_NEXT] = {
		.name = "ethernet nexthdr",
		.offset = 96,
		.width = 16,
	},
	[MAT_FIELD_ETHERNET_MAC_DST] = {
		.name = "destination mac",
		.offset = 0,
		.width = 48,
		.parser = MAT_PARSER_ETHERNET,
	},
	[MAT_FIELD_ETHERNET_MAC_SRC] = {
		.name = "source mac",
		.offset = 48,
		.width = 48,
		.parser = MAT_PARSER_ETHERNET,
	},
	[MAT_FIELD_VLAN_HLEN] = {
		.name = "vlan hlen",
		.width = 0,
		.add = 2,
	},
	[MAT_FIELD_VLAN_NEXT] = {
		.name = "vlan nexthdr",
		.offset = 32,
		.width = 16,
	},
	[MAT_FIELD_VLAN_ID] = {
		.name = "vlan id",
		.offset = 20,
		.width = 12,
		.parser = MAT_PARSER_VLAN,
	},
	[MAT_FIELD_VLAN_INNER_ID] = {
		.name = "inner vlan id",
		.offset = 20,
		.width = 12,
		.parser = MAT_PARSER_VLAN_INNER,
	},
	[MAT_FIELD_ETHERTYPE_HLEN] = {
		.name = "ethertype hlen",
		.width = 0,
		.add = 2,
	},
	[MAT_FIELD_ETHERTYPE] = {
		.name = "ethertype",
		.width = 16,
		.parser = MAT_PARSER_ETHERTYPE,
	},
	[MAT_FIELD_IP_HLEN] = {
		.name = "ip hlen",
		.offset = 4,
		.width = 4,
		.shift = 2,
	},
	[MAT_FIELD_IP_PROTO] = {
		.name = "ip protocol",
		.offset = 72,
		.width = 8,
		.parser = MAT_PARSER_IP,
	},
	[MAT_FIELD_IP_SRC] = {
		.name = "source ip",
		.offset = 96,
		.width = 32,
		.parser = MAT_PARSER_IP,
	},
	[MAT_FIELD_IP_DST] = {
		.name = "destination ip",
		.offset = 128,
		.width = 32,
		.parser = MAT_PARSER_IP,
	},
	[MAT_FIELD_IP_SPORT] = {
		.name = "source tcp/udp port",
		.offset = 160,
		.width = 16,
		.parser = MAT_PARSER_IP,
	},
	[MAT_FIELD_IP_DPORT] = {
		.name = "destination tcp/udp port",
		.offset = 176,
		.width = 16,
		.parser = MAT_PARSER_IP,
	},
	[MAT_FIELD_TCP_HDRSIZE] = {
		.name = "tcp hdrsize",
		.add = 24,
	},
	[MAT_FIELD_TCP_SPORT] = {
		.name = "source port",
		.offset = 0,
		.width = 16,
		.parser = MAT_PARSER_TCP,
	},
	[MAT_FIELD_TCP_DPORT] = {
		.name = "destination port",
		.offset = 16,
		.width = 16,
		.parser = MAT_PARSER_TCP,
	},
	[MAT_FIELD_UDP_HDRSIZE] = {
		.name = "tcp hdrsize",
		.add = 8,
	},
	[MAT_FIELD_UDP_SPORT] = {
		.name = "source port",
		.offset = 0,
		.width = 16,
		.parser = MAT_PARSER_UDP,
	},
	[MAT_FIELD_UDP_DPORT] = {
		.name = "destination port",
		.offset = 16,
		.width = 16,
		.parser = MAT_PARSER_UDP,
	},
};

/* The declaration of the preconfigured parsers. */
static struct mat_parser mat_parsers [MAT_PARSER_MAX] = {
	[MAT_PARSER_ETHERNET] = {
		.name = "ethernet",
		.hdrsize = MAT_FIELD_ETHERNET_HLEN,
		.nexthdr = MAT_FIELD_ETHERNET_NEXT,
	},
	[MAT_PARSER_VLAN] = {
		.name = "vlan",
		.hdrsize = MAT_FIELD_VLAN_HLEN,
		.nexthdr = MAT_FIELD_VLAN_NEXT,
	},
	[MAT_PARSER_VLAN_INNER] = {
		.name = "inner vlan",
		.hdrsize = MAT_FIELD_VLAN_HLEN,
		.nexthdr = MAT_FIELD_VLAN_NEXT,
	},
	[MAT_PARSER_ETHERTYPE] = {
		.name = "ethertype",
		.hdrsize = MAT_FIELD_ETHERTYPE_HLEN,
		.nexthdr = MAT_FIELD_ETHERTYPE,
	},
	[MAT_PARSER_IP] = {
		.name = "ip",
		.hdrsize = MAT_FIELD_IP_HLEN,
		.nexthdr = MAT_FIELD_IP_PROTO,
	},
	[MAT_PARSER_TCP] = {
		.name = "tcp",
		.hdrsize = MAT_FIELD_TCP_HDRSIZE,
		.nexthdr = MAT_FIELD_TCP_DPORT,
	},
	[MAT_PARSER_UDP] = {
		.name = "udp",
		.hdrsize = MAT_FIELD_UDP_HDRSIZE,
		.nexthdr = MAT_FIELD_UDP_DPORT,
	},
};

static int parser_index = __MAT_PARSER_FIRST_CUSTOM;
static int field_index = __MAT_FIELD_FIRST_CUSTOM;

/* Unfortunately, the TCAM structures are not binary safe, therefore we need to
 * initialize them.
 */
static void __attribute__((constructor)) mat_parser_init()
{
	struct mat_parser *p;

	for (size_t i = 1; i < __MAT_FIELD_FIRST_CUSTOM; i++) {
		mat_tcam_init(&mat_parsers[i].next_parser);
	}

	/* Wiring up the parsers */
	p = &mat_parsers[MAT_PARSER_ETHERNET];
	mat_tcam_insert(&p->next_parser, TCAM_PRIO_MIN, MAT_MASK_ONES, ETH_P_8021Q, MAT_PARSER_VLAN);
	mat_tcam_insert(&p->next_parser, TCAM_PRIO_MAX, 0, 0, MAT_PARSER_ETHERTYPE);

	p = &mat_parsers[MAT_PARSER_VLAN];
	mat_tcam_insert(&p->next_parser, TCAM_PRIO_MIN, MAT_MASK_ONES, ETH_P_8021Q, MAT_PARSER_VLAN_INNER);
	mat_tcam_insert(&p->next_parser, TCAM_PRIO_MAX, 0, 0, MAT_PARSER_ETHERTYPE);

	p = &mat_parsers[MAT_PARSER_VLAN_INNER];
	mat_tcam_insert(&p->next_parser, TCAM_PRIO_MAX, 0, 0, MAT_PARSER_ETHERTYPE);

	p = &mat_parsers[MAT_PARSER_ETHERTYPE];
	mat_tcam_insert(&p->next_parser, TCAM_PRIO_MIN, MAT_MASK_ONES, ETH_P_IP, MAT_PARSER_IP);

	p = &mat_parsers[MAT_PARSER_IP];
	mat_tcam_insert(&p->next_parser, TCAM_PRIO_MIN, MAT_MASK_ONES, IPPROTO_TCP, MAT_PARSER_TCP);
	mat_tcam_insert(&p->next_parser, TCAM_PRIO_MIN, MAT_MASK_ONES, IPPROTO_UDP, MAT_PARSER_UDP);
}

struct mat_parser *mat_parser_get(mat_parser_index idx)
{
	if (!mat_parsers[idx].name || !idx)
		return NULL;

	return &mat_parsers[idx];
}

static mat_parser_index parser_get_index(struct mat_parser *p)
{
	return p - mat_parsers;
}

static bool parser_is_terminal(struct mat_parser *p)
{
	return !p->nexthdr;
}

struct mat_header_field *mat_header_field_get(mat_field_index idx)
{
	if (!mat_header_fields[idx].name || !idx)
		return NULL;

	return &mat_header_fields[idx];
}

static mat_field_index field_get_index(struct mat_header_field *f)
{
	return f - mat_header_fields;
}

/* Check whether a field is custom. Note that we must not inline this to allow
 * binary modules check for this condition.
 */
bool mat_field_is_custom(mat_field_index f)
{
	return f >= __MAT_FIELD_FIRST_CUSTOM;
}

/* Register a field for extraction. */
mat_field_index mat_field_register(const struct mat_header_field_template *t)
{
	const mat_field_index idx = field_index++;
	struct mat_header_field *f = &mat_header_fields[idx];

	f->name = strdup(t->name);
	f->offset = t->offset;
	f->width = t->width;
	f->shift = t->shift;
	f->add = t->add;

	log("registered field %s idx %i", f->name, idx);
	return idx;
}

/* Register a parser. The nexthdr and hdrsize fields must be registered prior
 * to the parser itself. To solve the chicken-and-egg problem, the assignment
 * of field for extraction is done afterwards by mat_field_set_parser if
 * desired.
 */
mat_parser_index mat_parser_register(const char *name,
	mat_field_index nexthdr, mat_field_index hdrsize)
{
	if ((nexthdr == 0) != (hdrsize == 0))
		return EINVAL;

	const mat_parser_index idx = parser_index++;
	struct mat_parser *p = &mat_parsers[idx];

	p->name = strdup(name);
	p->hdrsize = hdrsize;
	p->nexthdr = nexthdr;
	mat_tcam_init(&p->next_parser);

	log("registered parser %s idx %i", p->name, idx);
	return idx;
}

/* Add a parser state as next for another state. */
int mat_parser_add_next(mat_parser_index parent_idx, size_t nexthdr, mat_parser_index child_idx)
{
	struct mat_parser *parent = mat_parser_get(parent_idx);
	if (!parent)
		return ENOENT;

	if (parser_is_terminal(parent))
		return EINVAL;

	struct mat_parser *child = mat_parser_get(child_idx);
	if (!child)
		return ENOENT;

	mat_tcam_insert(&parent->next_parser, 1, MAT_MASK_ONES, nexthdr, child_idx);
	return 0;
}

/* Register a field to be extracted by a parser. */
int mat_field_set_parser(struct mat_header_field *f, struct mat_parser *p)
{
	assert(f && p);
	if (!(mat_field_is_custom(field_get_index(f))))
		return EPERM;

	f->parser = parser_get_index(p);
	return 0;
}

/* Get the number of bits for a given field. */
unsigned mat_field_get_width(mat_field_index idx)
{
	struct mat_header_field *f = mat_header_field_get(idx);
	if (!f)
		return 0;

	return f->width;
}

/* A recursive function to dump the parser tree. For debug purposes only. */
static int mat_parser_dump_indent(struct mat_parser *p, unsigned ind_len, bool seen [])
{
	struct mat_tcam_prio *prio;
	struct mat_tcam_rule *rule;
	char indent [ind_len + 1];

	for (size_t i = 0; i < ind_len; i++)
		indent[i] = "    :   "[i % 8];
	indent[ind_len] = '\0';

	const mat_parser_index idx = parser_get_index(p);
	if (seen[idx]) {
		log("%s(ommited)", indent);
		return 0;
	}
	seen[idx] = true;

	if (!parser_is_terminal(p)) {
		struct mat_header_field *hs = mat_header_field_get(p->hdrsize);
		if (mat_field_is_const(hs))
			log("%sfixed %iB header", indent, hs->add);
		else
			log("%shdrsize (off %i w %i) * %i + %i", indent, hs->offset, hs->width, 1 << hs->shift, hs->add);
	}

	for (mat_field_index i = 1; i < field_index; i++) {
		struct mat_header_field *f = mat_header_field_get(i);
		if (f->parser != idx)
			continue;
		if (!f->shift && !f->add)
			log("%sfield \"%s\" (off %i w %i)", indent, f->name, f->offset, f->width);
		else
			log("%sfield \"%s\" (off %i w %i) * %i + %i", indent, f->name, f->offset, f->width, 1 << f->shift, f->add);
	}

	if (!parser_is_terminal(p)) {
		struct mat_header_field *nh = mat_header_field_get(p->nexthdr);
		if (!nh->shift && !nh->add)
			log("%snexthdr (off %i w %i)", indent, nh->offset, nh->width);
		else
			log("%snexthdr (off %i w %i) * %i + %i", indent, nh->offset, nh->width, 1 << nh->shift, nh->add);

		list_for_each_entry(prio, &p->next_parser.prio_list, in_table) {
			list_for_each_entry(rule, &prio->rules_list, in_prio) {
				struct mat_parser *c = mat_parser_get(rule->result);
				if (!c)
					continue;

				if (rule->mask == MAT_MASK_ONES)
					log("%s:-- [0x%0*" PRIx64 "] -> <%s>", indent, nh->width / 4, rule->value, c->name);
				else if (rule->mask == 0)
					log("%s:-- [else] -> <%s>", indent, c->name);
				else
					log("%s:-- [mask 0x%0*" PRIx64 " val 0x%0*" PRIx64 "] -> <%s>", indent, nh->width / 4, rule->mask, nh->width / 4, rule->value, c->name);
				mat_parser_dump_indent(c, ind_len + 8, seen);
			}
		}
	}

	return 0;
}

/* Dump the parser tree. For debug purposes only. */
int mat_parser_dump()
{
	bool seen [MAT_PARSER_MAX];
	memset(seen, 0, sizeof(seen));

	struct mat_parser *p = mat_parser_get(MAT_PARSER_ETHERNET);
	if (!p)
		return ENOENT;

	log("root <%s>:", p->name);
	return mat_parser_dump_indent(p, 4, seen);
}

/* Here, we would use the in-kernel flow dissector to get known field values.
 * But since we don't have it now and may have to extract custom fields as well,
 * we demonstrate the generic way of parsing fields.
 */
static u64 field_extract_value(struct mat_header_field *f, struct sk_buff *skb,
	unsigned hdr_offset)
{
	int byte_offset = f->offset / 8;
	int bit_offset = f->offset % 8;

	u64 value = * (uint64_t *) &skb->data[hdr_offset + byte_offset];
	value = __builtin_bswap64(value);
	value >>= 64 - bit_offset - f->width;
	value &= (1ULL << f->width) - 1;
	return value;
}

/* Interpret a value from a packet. This is needed especially for hdrsize fields. */
static u64 field_decode_value(struct mat_header_field *f, struct sk_buff *skb,
	unsigned hdr_offset)
{
	u64 value = field_extract_value(f, skb, hdr_offset);

	value <<= f->shift;
	value += f->add;
	return value;
}

/* Parse a packet, returning a value of a field from it.
 *
 * As already noted in the header file, this parses the packet from the
 * beginning. It is not OK to parse the packet over and over. To efficiently
 * parse packets in software, we would need to know which fields can be
 * obtained from the flow dissector and optimize the parser tree specifically
 * for one table with this knowledge. Unused fields can be skipped, unused
 * parsers can be skipped recursively. What's left is a very sparse tree with
 * only relevant fields.
 */
int mat_parser_extract_field(mat_header_field_value *dest, mat_parser_index root_idx, mat_field_index f_idx, struct sk_buff *skb)
{
	struct mat_header_field *f = mat_header_field_get(f_idx);
	mat_parser_index idx = root_idx;
	unsigned hdr_offset = 0;

	if (!f)
		return EINVAL;

	memset(dest, 0, sizeof(*dest));

	while (idx) {
		struct mat_parser *parser = mat_parser_get(idx);
		if (!parser)
			return EFAULT;

		if (f->parser == idx) {
			*dest = field_extract_value(f, skb, hdr_offset);
			log("found <%s> = %lu / %#lx  in <%s>", f->name, *dest, *dest, parser->name);
			return 0;
		}

		/* Get nexthdr value */
		if (parser_is_terminal(parser))
			break;

		struct mat_header_field *nh = mat_header_field_get(parser->nexthdr);
		size_t nexthdr = field_extract_value(nh, skb, hdr_offset);

		struct mat_header_field *hs = mat_header_field_get(parser->hdrsize);
		hdr_offset += field_decode_value(hs, skb, hdr_offset);

		/* Advance parser state */
		idx = mat_tcam_lookup(&parser->next_parser, nexthdr);
	}

	return ENOENT;
}

