#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) Ondřej Hlavatý <ohlavaty@redhat.com>

tmpdir=$(mktemp -d)
expected=expected.txt

cleanup() {
	rm -rf "$tmpdir"
}
trap cleanup EXIT

make tests

for td in tests/*; do
	echo "------------------------------"
	t=$(basename $td)
	outfile="$tmpdir/$t"
	if [ ! -f "$td/$expected" ]; then
		echo "   SKIP: $t"
		continue
	fi

	"$td/test" >"$outfile"
	if cmp -s "$outfile" "$td/$expected"; then
		echo "     OK: $t"
	else
		echo " FAILED: $t"
		diff -ds "$td/$expected" "$outfile"
	fi
done
