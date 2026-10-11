#!/bin/sh
# Linker wrapper for the crt link line: rustc -C linker=tools/crt-ld.sh
exec bun "$(dirname "$0")/crt-ld.ts" "$@"
