# SPDX-License-Identifier: GPL-2.0
# Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>

include $(MAT_ROOT)/common.mk

HEADERS = $(shell find . -iname "*.h")
SOURCES = $(shell find . -iname "*.c")
OBJECTS = $(SOURCES:%.c=%.o)

test: $(OBJECTS) $(MAT_ROOT)/libmat.a
	$(CC) $(LDFLAGS) -o $@ $^

%.o: $(HEADERS) $(SOURCES)

clean:
	rm -f test $(OBJECTS)
