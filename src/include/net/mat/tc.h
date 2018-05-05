/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>
 *
 * The TC interface of MAT. Actually, the blocks are exported from inside MAT,
 * so there is no need to export functions to TC - the code can stay private to
 * MAT.
 */

#pragma once

#include "table.h"

int mat_tc_init(struct mat_table *tbl);
