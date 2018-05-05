/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 *
 * A common header for our testcases. Contains some helpers to reduce the code.
 *
 * As both sk_buffs and net_devices are allocated dynamically and used through
 * pointers, we try to mimic this and  define the pointers as 1-sized arrays.
 */

#pragma once

#include <mock.h>

#define log(fmt, ...) log_comp("test", fmt, ##__VA_ARGS__)
#define hr() log_comp("", "----------------------------------------");

/* Sample packets. */
extern struct sk_buff sample_skb [1];
extern struct sk_buff sample_skb_2 [1];

/* A net_device implementation which logs table binds. */
extern struct net_device test_netdev [1];

/* Prepare a mat_msg structure for given args. */
#define MAT_NL_MSG_PREPARE(msg, tp, tbl, a)				\
	struct mat_msg *msg = alloca(sizeof(*msg) + sizeof(a));	\
	msg->type = tp;						\
	msg->table = tbl;					\
	msg->arg_count = ARRAY_SIZE(a);				\
	memcpy(msg->args, a, sizeof(a));

