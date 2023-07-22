#!/bin/sh

SCRIPTDIR="$(dirname "$(readlink -f "$0")")"

for x in "$SCRIPTDIR"/config/*; do
	install -Dm644 $x "$DESTDIR"/etc/rrst/
done
