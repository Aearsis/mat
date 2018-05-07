# SPDX-License-Identifier: GPL-2.0
# Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>

CC = gcc
CFLAGS = -std=gnu89 -O2  -I$(MAT_ROOT)/src/include -I$(MAT_ROOT)/uapi

ifneq (${DEBUG},)
CFLAGS += -g3 -fstack-protector-all
endif

ifneq (${ASAN},)
CFLAGS += -fsanitize=address
LDFLAGS += -lasan
endif

UAPI_HEADERS = $(shell find $(MAT_ROOT)/uapi -iname "*.h")
KERNEL_HEADERS = $(shell find $(MAT_ROOT)/src -iname "*.h")

KERNEL_SOURCES = $(shell find $(MAT_ROOT)/src -iname "*.c")
KERNEL_OBJECTS = $(KERNEL_SOURCES:%.c=%.o)

%.o: %.c $(UAPI_HEADERS) $(KERNEL_HEADERS)
	${CC} ${CFLAGS} -c -o $@ $<
