#!/bin/sh

echo 'A (a) (b) (c) B' | $@ -m ts1 -p od -n 400 | sort 2>/dev/null | uniq | wc -l | grep -q 6 || exit 1 

