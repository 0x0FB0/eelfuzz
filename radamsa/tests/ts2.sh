#!/bin/sh

echo '(a) (b (c))' | $@ -m ts2 -p od -n 30 | sort 2>/dev/null | uniq | wc -l | grep -q 3 || exit 1

