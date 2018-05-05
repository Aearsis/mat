/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 */

#pragma once

#include <mock.h>

void simple_nic_init(struct net_device *dev);
void simple_nic_destroy(struct net_device *dev);
void simple_nic_receive(struct net_device *dev, struct sk_buff *skb);
