# Targets

| Target | Tables | Built | Run here |
|---|---|---|---|
| aarch64-apple-darwin | `__eko_unwind`, `__unwind_info` (regular and compressed pages, FRAME, FRAMELESS, DWARF mode), `__eh_frame` (z P L R S B G, pointer encodings incl. 0x9b), `__gcc_except_tab` via std personality | yes | yes: tools/eh.ts, tools/mixed.ts, tools/defects.ts, tools/check-nostd.ts |
| aarch64-unknown-linux-gnu | EKO notes, `.eh_frame_hdr` (0x3b table), `.eh_frame` | yes | no, compiled only |
| aarch64-unknown-linux-musl | same | yes | no, compiled only |
| x86_64-unknown-linux-gnu | same | yes | no, compiled only |
| x86_64-unknown-linux-musl | same | yes | no, compiled only |
| arm64e, Windows, anything else | none | refused by `compile_error!` (arch/OS) or out of scope | no |

"Compiled only" means: `./tools/build.sh <triple>` builds the LTO object and
`bun tools/check-nostd.ts <triple>` passes (no std symbol, only the allowed
libc imports, exactly the 18 exports); see transcripts/linux-compile.txt.
A std program links with it on musl (tools/check-linux-link.ts L2), but
nothing for Linux has been executed, so the ELF finder and image cache, the x86_64 register layer, the
x86_64 trampolines and restore, and the Linux `_Unwind_GetCFA` are unverified.

Within aarch64-apple-darwin, these paths have no fixture yet:

- FRAMELESS compact frames as the interrupted frame (needs a signal fixture);
  the register layout used there is unverified against Apple libunwind.
- Signal frames in general (`ip_before_insn`, CIE augmentation S,
  `EkoAsyncFrame`).
- Compressed versus regular second-level pages are both parsed; which kinds
  the fixtures hit was not measured.

## L3 (glibc link) without installing anything: proposed, not built

`bun tools/check-linux-link.ts` L3 exits 2 (not run): rust-lld finds no
`-lc` for `*-linux-gnu`. Status: documented only; no stub tool exists yet and
L3 was not run. The route needs no install: the rustc
`aarch64-unknown-linux-gnu` std already present, its rust-lld, and a
link-only sysroot under `target/glibc-sysroot/` passed with
`-C link-arg=--sysroot=... -L native=.../lib`. L3 links and inspects
(`NEEDED`, no `libgcc_s`); it never runs the binary, so the sysroot only
has to satisfy the linker.

Files the sysroot needs, for the glibc 2.17 baseline std targets:

| File | Why | Content |
|---|---|---|
| `libc.so.6` | every libc symbol std and ps-unwind reference | stub DSO, SONAME `libc.so.6`, version nodes GLIBC_2.17 (and later ones a symbol needs) |
| `libc.so` | what `-lc` opens | linker script `GROUP ( libc.so.6 )`, no `libc_nonshared.a` (stubs define those symbols) |
| `ld-linux-aarch64.so.1` | `PT_INTERP` name and the few `ld.so` symbols (`__tls_get_addr`, `_dl_find_object` if referenced) | stub DSO with that SONAME |
| `libm.so.6`, `libm.so` | std links `-lm` | stub DSO + `GROUP` script |
| `libpthread.so`, `libdl.so`, `librt.so`, `libutil.so` | the libc crate passes `-lpthread -ldl -lrt -lutil` on gnu | empty stub DSOs (SONAME `libpthread.so.0` etc.) or linker scripts naming `libc.so.6`; with `--as-needed` none becomes `NEEDED` |
| `libgcc_s.so` | the `-lgcc_s` std passes must resolve to nothing | NOT included by design: an empty archive `libgcc_s.a` (`!<arch>` header only) so ps-unwind defines `_Unwind_*` and L3 can check no `libgcc_s` is `NEEDED` |
| `Scrt1.o`, `crt1.o`, `crti.o`, `crtn.o` | `_start`, `_init`/`_fini` prologue and epilogue rustc's gcc-flavour link line names | from the crt work (item 6, branch `crt`) or the .deb below |
| `crtbeginS.o`, `crtendS.o` (and non-S) | `__dso_handle`, init/fini array ends | item 6 (branch `crt`), written from the ABI documents |

Where the DSOs come from, two options:

1. Generated stubs (preferred). Symbol list = the undefined symbols
   `llvm-nm -u` reports for the std rlibs and `ps_unwind.o` (what
   check-linux-link.ts already derives), plus each one's kind and size:
   functions as `ret`, data objects (`environ`, `__libc_single_threaded`,
   `stdout` if referenced) as sized `.bss` objects so copy relocations get
   the right size. Build: `global_asm!` in a `#![no_std]` crate compiled
   with `rustc --target aarch64-unknown-linux-gnu --emit obj`, then
   `rust-lld -flavor gnu -shared -soname libc.so.6 --version-script V`.
   No glibc source or binary is read, so no licence question. Risk: a wrong
   symbol version or object size links fine and would be wrong at run time,
   which L3 never does; a missing symbol fails the link by name, which is
   the safe direction.
2. Extracted from Debian/Ubuntu arm64 `.deb`s without installing:
   download `libc6_*_arm64.deb` and `libc6-dev_*_arm64.deb` (and
   `libgcc-*-dev` only if the item 6 crt objects are not used), unpack with
   `ar x` and `tar xf data.tar.*` into `target/glibc-sysroot/`. Exact symbols,
   versions and sizes; real crt1/crti/crtn. Costs: a network download per
   machine, the version pinned to that release (must be >= the 2.17
   baseline and no newer than what is targeted, or symbols pick up newer
   versions), and the files are glibc (LGPL-2.1+; crt objects carry the
   linking exception), so they stay in `target/` and are never committed.
   GCC's crtbegin/libgcc from that package would reintroduce the GCC
   runtime the crt objects remove, so only the glibc files are taken.

Next step: implement option 1 as `tools/glibc-stubs.ts` writing
`target/glibc-sysroot/`, point L3 at it, keep L3 exit 2 when the sysroot is
absent.
