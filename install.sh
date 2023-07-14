#!/bin/sh

SCRIPTDIR="$(dirname "$(readlink -f "$0")")"

install -Dm644 "$SCRIPTDIR"/config/axolotl.ini "$DESTDIR"/etc/rrst/axolotl.ini
install -Dm644 "$SCRIPTDIR"/config/rb3.ini "$DESTDIR"/etc/rrst/rb3.ini
