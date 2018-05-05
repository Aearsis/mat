/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 1989, 1991 Free Software Foundation, Inc.
 *                          51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 *
 * This file is a partial mock of the Linux kernel. It defines structures and
 * types usable in the kernel to make the demonstrator code more kernel-ish.
 *
 * It is a (modified) copy of chunks from the kernel. Majority of the code is
 * authored by contributors of the Linux kernel.
 *
 * Some structures were modified to allow the extension.
 */

#pragma once

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <linux/list.h>

#define log_comp(comp, format, ...) printf("%10s : " format "\n", comp, ##__VA_ARGS__)

#define assert(cond) do { \
	if (!(cond)) { \
		fprintf(stderr, "Assertion failed: " #cond " (at %s:%d)", __FILE__, __LINE__); \
		exit(1); \
	} \
} while (0)

#define __rcu

typedef uint8_t   u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

struct net_device;

enum tc_setup_type {
	TC_SETUP_QDISC_MQPRIO,
	TC_SETUP_CLSU32,
	TC_SETUP_CLSFLOWER,
	TC_SETUP_CLSMATCHALL,
	TC_SETUP_CLSBPF,
	TC_SETUP_BLOCK,
	TC_SETUP_QDISC_CBS,
	TC_SETUP_QDISC_RED,
	TC_SETUP_QDISC_PRIO,
};

struct net_device_ops {
	int (*ndo_setup_tc)(struct net_device *dev,
						enum tc_setup_type type,
						void *type_data);
};

struct net_device {
	const struct net_device_ops *netdev_ops;

	struct tcf_block *ingress_block;
	struct tcf_block *egress_block;

	void *priv;
};

static inline void *netdev_priv(struct net_device *dev)
{
	return dev->priv;
}

struct sk_buff {
	char data [1500];
	struct net_device *dev;
	u16 tc_index;

	bool tc_skip_classify;
};

/**
 * We forget NAPI and so for demonstration purposes.
 */
extern int netif_receive_skb(struct sk_buff *skb);

/**
 * This type is added by us to differentiate between TC blocks and MAT blocks.
 */
enum tcf_block_type {
	TCF_BLOCK_CLSACT,
	TCF_BLOCK_MAT,
};

struct tcf_result {
	union {
		struct {
			unsigned long	class;
			u32		classid;
		};
		const struct tcf_proto *goto_tp;
	};
};

struct tcf_proto {
	int			(*classify)(struct sk_buff *,
					    const struct tcf_proto *,
					    struct tcf_result *);
	u16			protocol;

	u32			prio;
	void			*data;
};

/**
 * In reality, blocks contain a list of chains, which contains a list of
 * protos, which are filter instances.
 *
 * To simplify matters, we expect block to have exactly one tcf_proto.
 */
struct tcf_block {
	enum tcf_block_type type;
	u32 index;
	struct tcf_proto *filter;
};

enum tc_block_command {
	TC_BLOCK_BIND,
	TC_BLOCK_UNBIND,
};

enum tcf_block_binder_type {
	TCF_BLOCK_BINDER_TYPE_UNSPEC,
	TCF_BLOCK_BINDER_TYPE_CLSACT_INGRESS,
	TCF_BLOCK_BINDER_TYPE_CLSACT_EGRESS,
};

struct tcf_block *tcf_block_alloc_shared(enum tcf_block_type type);

struct tc_block_offload {
	enum tc_block_command command;
	enum tcf_block_binder_type binder_type;
	struct tcf_block *block;
};

static inline bool tc_setup_is_mat(enum tc_setup_type type, void *type_data)
{
	struct tc_block_offload *bo = type_data;

	return type == TC_SETUP_BLOCK
		&& bo->command == TC_BLOCK_BIND
		&& bo->block->type == TCF_BLOCK_MAT;
}

#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7
#define TC_ACT_TRAP		8

#define TC_H_MAJ_MASK (0xFFFF0000U)
#define TC_H_MIN_MASK (0x0000FFFFU)
#define TC_H_MAJ(h) ((h)&TC_H_MAJ_MASK)
#define TC_H_MIN(h) ((h)&TC_H_MIN_MASK)
#define TC_H_MAKE(maj,min) (((maj)&TC_H_MAJ_MASK)|((min)&TC_H_MIN_MASK))

#define TC_H_UNSPEC	(0U)
#define TC_H_ROOT	(0xFFFFFFFFU)
#define TC_H_INGRESS    (0xFFFFFFF1U)
#define TC_H_CLSACT	TC_H_INGRESS

typedef enum {
	GFP_KERNEL,
	GFP_ATOMIC,
	__GFP_HIGHMEM,
	__GFP_HIGH
} gfp_t;

static inline __attribute__((malloc)) void *kzalloc(size_t size, gfp_t flags)
{
	return calloc(1, size);
}

static inline void kfree(const void *ptr)
{
	free((void *) ptr);
}

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	((type *)(__mptr - offsetof(type, member))); })

#define offsetof(TYPE, MEMBER)	((size_t)&((TYPE *)0)->MEMBER)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#ifndef BITS_PER_LONG_LONG
#define BITS_PER_LONG_LONG 64
#endif

/*
 * Create a contiguous bitmask starting at bit position @l and ending at
 * position @h. For example
 * GENMASK_ULL(39, 21) gives us the 64bit vector 0x000000ffffe00000.
 */
#define GENMASK(h, l) \
	(((~0UL) - (1UL << (l)) + 1) & (~0UL >> (BITS_PER_LONG - 1 - (h))))

#define GENMASK_ULL(h, l) \
	(((~0ULL) - (1ULL << (l)) + 1) & \
	 (~0ULL >> (BITS_PER_LONG_LONG - 1 - (h))))

int tc_modify_qdisc(struct net_device *dev, u32 ingress_block, u32 egress_block);
