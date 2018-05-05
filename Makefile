# SPDX-License-Identifier: GPL-2.0
# Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>

MAT_ROOT = .
include common.mk

TESTS := $(shell find tests -mindepth 1 -maxdepth 1 -type d -exec basename {} \;)
TEST_EXECS := $(TESTS:%=tests/%/test)
TEST_OUTS := $(TESTS:%=tests/%/expected.txt)

tests: $(TEST_EXECS)

$(TEST_EXECS): tests/%/test: libmat.a
	$(MAKE) -C "tests/$*" test
.PHONY: $(TEST_EXECS)

$(TEST_OUTS): tests/%/expected.txt: tests/%/test
	$< >$@

freeze-tests:
	rm -f $(TEST_OUTS)
	$(MAKE) $(TEST_OUTS)


clean-%:
	cd tests/$*; $(MAKE) clean

clean: $(foreach t,$(TESTS),clean-$t)
	rm -f $(KERNEL_OBJECTS) libmat.a

libmat.a: $(KERNEL_OBJECTS)
	ar rcs $@ $^

.PHONY: tests clean
