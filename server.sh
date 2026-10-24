#!/usr/bin/env bash
. bash/shared/default.sh
exec bin/server "${1:-$SERVER_PORTV4}"
