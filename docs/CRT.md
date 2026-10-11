# crt: crtbegin/crtend for Linux

Replaces gcc's `crtbegin.o`, `crtbeginS.o`, `crtend.o`, `crtendS.o` on aarch64 and
x86_64 Linux (gnu and musl), so a binary linked with ps-unwind carries no gcc
runtime. Written from the System V gABI, the AArch64 and x86-64 psABIs and the
Itanium C++ ABI section on `__cxa_atexit` / `__dso_handle`; no crt source was
read or adapted. macOS and Windows are out of scope.

## What step 1 measured (transcripts/crt-measure.txt)

A std program for both musl triples, linked with libc's `crt1.o`/`crti.o`/`crtn.o`
and no crtbegin/crtend at all, links with no error. The only crt-related names
std references (gnu and musl rlibs alike) are weak: `__dso_handle` and
`__cxa_thread_atexit_impl`.

| Job | Result |
| --- | --- |
| `__dso_handle` | Provided. std passes its address to glibc's `__cxa_thread_atexit_impl` for TLS destructors, so a shared object needs its own. Hidden, 0 in `crtbegin.o`, its own address in `crtbeginS.o`. The reference is weak, and rust-lld synthesizes a hidden `__dso_handle` at the image start when nobody defines one, so a missing definition never fails a link; C5 catches it by name instead. |
| `.eh_frame` zero terminator | Not provided. No consumer found: ps-unwind uses `.eh_frame_hdr`, and its linear fallback (`cfi::scan`) is bounded by the section length. `crtend*.o` are therefore empty and exist only to keep the link line shape. |
| `.ctors`/`.dtors`, `__do_global_dtors_aux` | Not provided: `.init_array`/`.fini_array` are run by the loader or libc. |
| `frame_dummy`, `__register_frame_info` calls | Absent by design; C3 enforces it. |
| `__TMC_END__`, TM clones | Not provided. |

## Layout

`crt/lib.rs` is a separate crate root, not a module of ps-unwind: the begin and
end objects must be separate inputs at fixed positions on the link line, while
`ps_unwind.o` is one LTO object placed anywhere. `tools/crt-build.sh <triple>`
builds the four objects into `target/crt/<triple>` from that one source with
`--cfg crt_begin|crt_end [--cfg crt_shared]`. Stable Rust has no
visibility attribute for statics, so one `global_asm!(".hidden __dso_handle")`
sets STV_HIDDEN; it emits no code.

## Link line

`tools/crt-ld.ts` (via `tools/crt-ld.sh`) is the linker for
`rustc -C linker=tools/crt-ld.sh -C linker-flavor=ld.lld -C link-self-contained=no`.
It builds:

    executable:     crt1.o|rcrt1.o|Scrt1.o crti.o crtbegin.o  <rustc args>  crtend.o crtn.o
    shared object:                         crti.o crtbeginS.o <rustc args>  crtendS.o crtn.o

- Kept from the C library: `crt1.o` (`rcrt1.o` for static PIE, `Scrt1.o` for
  dynamic PIE), `crti.o`, `crtn.o`. On musl they come from rust's self-contained
  directory; on gnu from the glibc sysroot.
- Gone: gcc's `crtbegin*.o`, `crtend*.o`, `crtfastmath.o`, and libgcc/libgcc_s.
  The driver refuses any foreign one (C1).
- Ours: `crtbegin.o`/`crtbeginS.o` right after `crti.o`, `crtend.o`/`crtendS.o`
  right before `crtn.o`. `crtbeginS.o` only for `-shared`; a PIE executable uses
  `crtbegin.o` (the value of `__dso_handle` is never read, only its address).
- Env: `PS_UNWIND_CRT_DIR` (our objects), `PS_UNWIND_CRT_LIBC_DIR` (crt1/crti/crtn),
  `PS_UNWIND_CRT_LLD` (rust-lld path). Add `-L native=<libc dir>` and ps-unwind as
  `-L native=target/dist/<triple> -l static:+whole-archive=ps_unwind`.

## Checks (bun tools/check-crt.ts)

| Check | aarch64 musl | x86_64 musl | aarch64 gnu | x86_64 gnu |
| --- | --- | --- | --- | --- |
| C1 no foreign crt object | pass, linked | pass, linked | not run | not run |
| C2 no libgcc/libgcc_s NEEDED | pass (shared probe; exe static) | pass | not run | not run |
| C3 no register_frame refs | pass | pass | not run | not run |
| C4 no duplicate definition | pass | pass | n/a (musl rule) | n/a |
| C5 objects (hidden, 0 / self reloc) | pass | pass | pass | pass |
| C5 linked images | pass | pass | not run | not run |
| C5 TLS destructor runs at thread exit | not run | not run | not run | not run |

Nothing was executed: there is no Linux host here. Every check has a planted
defect that fails it by name (transcripts/crt-plant-c1..c5.txt). There is no gcc
`crtbegin.o` on this machine, so the C1 and C4 plants use rust's self-contained
compiler-rt `crtbegin.o`, which does the same weak `__register_frame_info` calls
and defines `__dso_handle`.

## To run the gnu rows

Needs, for each gnu triple, a glibc link sysroot with `crt1.o`, `Scrt1.o`,
`crti.o`, `crtn.o`, `libc.so` (the linker script), `libc.so.6`,
`libc_nonshared.a`, `libm.so.6`, and the dynamic loader (`ld-linux-aarch64.so.1`
or `ld-linux-x86-64.so.2`), for example extracted from the distribution's glibc
development package (Debian `libc6-dev` and `libc6` for arm64 / amd64). Pass the
directory as `PS_UNWIND_CRT_LIBC_DIR` and `-L native=`. Not installed; the owner decides.
The TLS destructor row needs a Linux machine or VM to execute the binaries.
