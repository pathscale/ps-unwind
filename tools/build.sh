#!/bin/sh
# Builds the shipped artifacts into target/dist (or target/dist/<triple>):
#   ps_unwind.o       single fat-LTO object, only libc imports
#   libps_unwind.a    archive holding just that object
# compiler_builtins members of the cargo staticlib are dropped: the host
# program always links its own copy. llvm-ar from the rust toolchain is used
# because Apple ar cannot read the GNU long-name table of ELF archives.
set -eu
cd "$(dirname "$0")/.."
ROOT=$(pwd)
TARGET="${1:-}"
HOSTT=$(rustc --print host-tuple)
LLVM_AR="$(rustc --print sysroot)/lib/rustlib/$HOSTT/bin/llvm-ar"
if [ -n "$TARGET" ]; then
  cargo rustc --release --features staticlib --crate-type staticlib --target "$TARGET"
  OUT="$ROOT/target/$TARGET/release"
  DIST="$ROOT/target/dist/$TARGET"
  FORMAT=gnu
else
  cargo rustc --release --features staticlib --crate-type staticlib
  OUT="$ROOT/target/release"
  DIST="$ROOT/target/dist"
  FORMAT=darwin
fi
mkdir -p "$DIST/x"
rm -f "$DIST"/x/*
MEMBER=$("$LLVM_AR" t "$OUT/libps_unwind.a" | sed -n "/^ps_unwind-.*\.o$/p")
test -n "$MEMBER"
(cd "$DIST/x" && "$LLVM_AR" x "$OUT/libps_unwind.a" "$MEMBER")
mv "$DIST/x/$MEMBER" "$DIST/ps_unwind.o"
rm -rf "$DIST/x"
rm -f "$DIST/libps_unwind.a"
"$LLVM_AR" rcs --format=$FORMAT "$DIST/libps_unwind.a" "$DIST/ps_unwind.o"
echo "$DIST/libps_unwind.a"
