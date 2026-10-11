#!/bin/sh
# Builds the crt objects for one Linux triple into target/crt/<triple>:
# crtbegin.o crtbeginS.o crtend.o crtendS.o, all from crt/lib.rs.
set -eu
cd "$(dirname "$0")/.."
T="$1"
OUT="target/crt/$T"
mkdir -p "$OUT"
RUSTC="${PS_RUSTC:-rustc}"
b() {
  "$RUSTC" --edition 2024 --crate-type lib --crate-name crt --emit obj --target "$T" \
    -C panic=abort -C opt-level=s -C codegen-units=1 -C relocation-model=pic -C debuginfo=0 \
    --check-cfg "cfg(crt_begin,crt_end,crt_shared)" "$@"
}
b --cfg crt_begin crt/lib.rs -o "$OUT/crtbegin.o"
b --cfg crt_begin --cfg crt_shared crt/lib.rs -o "$OUT/crtbeginS.o"
b --cfg crt_end crt/lib.rs -o "$OUT/crtend.o"
b --cfg crt_end --cfg crt_shared crt/lib.rs -o "$OUT/crtendS.o"
echo "$OUT"
