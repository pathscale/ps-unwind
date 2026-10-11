#!/bin/sh
# Replace the @Q@ placeholder with a single quote in the named files. Files in
# this repository are written through a shell, where a literal single quote
# cannot appear inside a single-quoted argument.
set -e
for f in "$@"; do
    sed -i "" "s/@Q@/'/g" "$f"
done
