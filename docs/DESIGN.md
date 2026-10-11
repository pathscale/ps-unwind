# ps-unwind design

ps-unwind provides the `_Unwind_*` boundary that Rust `panic_unwind`, the
personality routine and `std::backtrace` call, for Rust programs, including
ones whose compiler emits the EKO table (docs/FORMAT.md). It is `#![no_std]`, allocates nothing, and reaches
the platform only through `libc`.

## Exports

Exactly these, and nothing else with a C name (checked by tools/check-nostd.ts
rule R5): `_Unwind_RaiseException`, `_Unwind_Resume`, `_Unwind_DeleteException`,
`_Unwind_GetIP`, `_Unwind_GetIPInfo`, `_Unwind_GetLanguageSpecificData`,
`_Unwind_GetRegionStart`, `_Unwind_SetGR`, `_Unwind_SetIP`,
`_Unwind_GetDataRelBase`, `_Unwind_GetTextRelBase`, `_Unwind_Backtrace`,
`_Unwind_GetCFA`, `_Unwind_FindEnclosingFunction`, and the crash-handler and
verifier API `ps_unwind_signal_enter`, `ps_unwind_signal_leave`,
`ps_unwind_backtrace_ucontext`, `ps_unwind_last_failure`,
`ps_unwind_cache_stats` (src/abi.rs).
`rust_eh_personality` stays the one in std and is called with the Itanium
convention (version 1, actions, class, exception, context).

## Code map

| File | Role |
|---|---|
| src/abi.rs | exports, `_Unwind_Context` (Cursor), phase one, phase two, backtrace |
| src/arch/aarch64.rs, src/arch/x86_64.rs | register file, DWARF register numbers, the three entry trampolines, context restore |
| src/cache.rs | lock-free image cache, signal-context flag, ps-reclaim retire queue |
| src/find/darwin.rs | cache fill from the dyld add/remove-image callbacks; EKO, then compact unwind, then `__eh_frame` |
| src/find/elf.rs | cache fill from AT_PHDR and `dl_iterate_phdr`, refresh on a miss outside signal context; EKO notes, then `.eh_frame_hdr` binary search, then `.eh_frame` scan |
| src/compact.rs | `__unwind_info` first level, regular and compressed second-level pages, LSDA index, personality array, FRAME and FRAMELESS steps, DWARF-mode hand-off |
| src/cfi.rs | CIE/FDE parsing (augmentations z P L R S B G), the CFA program, a DW_OP subset |
| src/eko.rs | EKO v1 and v2 reader (docs/FORMAT.md) and the built-in EKO personality |
| src/mem.rs | unaligned loads, LEB128, DW_EH_PE decoding including indirect (0x9b) |
| src/failure.rs | the named failures, last-failure record, the fatal path |

## Inline assembly (flagged)

Only register capture and register restore are assembly; everything else is
Rust.

- `trampoline!` (naked, one per entry: `_Unwind_RaiseException`,
  `_Unwind_Resume`, `_Unwind_Backtrace`). It stores the callee-saved
  registers, the caller stack pointer and the return address into a register
  file on its own stack, zeroes the caller-saved slots, and calls the Rust
  body with a pointer to it. The state captured is the caller state at the
  call, so the first frame walked is the caller and ps-unwind needs no unwind
  tables for itself.
- `restore` (aarch64: loads x0-x15, x19-x30, d8-d15, sp, then `br x17`; x16,
  x17 are scratch, x18 is the platform register and is left alone. x86_64:
  loads every register, switches the stack and returns to the target pc).

## Phases

`_Unwind_RaiseException` runs phase one (search) on a copy of the caller state,
records the stack pointer of the handler frame in `private_2`, then runs phase
two (cleanup) on the real state. `_Unwind_Resume` runs phase two only, using
`private_2`. Phase two passes `_UA_HANDLER_FRAME` when the frame stack pointer
equals `private_2` and stops with `HandlerFrameMissed` if the personality then
asks to continue. A personality result outside the protocol is
`BadPersonalityResult`.

Phase one is kept on purpose. Without it the cleanups of every frame would
run before the unwinder learned that nothing catches, which changes drop
output and the abort message; it is not a shortcut that can be taken while
staying observably identical.

## Platform behaviour mirrored

- A frame is reported or stepped only when tables describe it. Darwin compact
  encoding 0, a pc in no image, or a zero pc end the walk as
  `_URC_END_OF_STACK` (failures `NoUnwindInfo`, `NoImage`, `ZeroPc`). This is
  why `raise` on a raw pthread returns 5 and why a backtrace from main stops
  at `main` and not at dyld `start` (tools/mixed.ts B2 compares with the
  system unwinder).
- `_Unwind_Backtrace` reports its caller first and returns `_URC_END_OF_STACK`
  whenever it stops, including when the callback stops it.
- The lookup address is the return address minus one, except for a frame
  interrupted by a signal (CIE augmentation S), where it is the pc.
- `_Unwind_GetCFA`: Darwin returns the frame stack pointer (Apple libunwind);
  Linux returns the canonical frame address (libgcc, LLVM libunwind).
- Return addresses have bits above 48 cleared on aarch64 (no arm64e).
- `_Unwind_FindEnclosingFunction(pc)`: start of the function holding the
  address, or null. glibc targets look up pc - 1 (libgcc); musl and Darwin
  look up pc (LLVM libunwind). Only Linux std imports it (backtrace-rs); it is
  exported everywhere. tools/check-linux-link.ts derives the needed set from
  `nm -u` on what rustc links rather than from this list.

## Shortcuts, each with its proof

1. **EKO frames have no personality call and no LSDA.** The handler table
   carries the decision directly and src/eko.rs applies the exact decision
   table of `rust_eh_personality` (library/std/src/sys/personality/gcc.rs):
   search phase none or cleanup continues, catch is handler found, terminate
   is fatal phase one; cleanup phase none continues, cleanup or catch installs
   x0 = exception, x1 = 0, pc = pad; terminate is fatal phase two. Proof:
   tools/mixed.ts R1 and R2 land in the right EKO pad for a foreign exception
   and for a Rust panic, the catch row hands the exception back, and the
   planted defect `wrong-call-site` (pad of the neighbouring row) fails R1
   and R2 (transcripts/defects.txt).
2. **No DWARF CFI for EKO frames.** The frame word gives CFA, return address,
   caller FP and saved registers directly (docs/FORMAT.md). Proof: R1 checks
   x19 after the EKO cleanup pad and all 18 callee-saved registers after the
   EKO catch pad (mask 0x0); B1 matches lldb frame for frame through two EKO
   frames.
3. **`_Unwind_GetDataRelBase` and `_Unwind_GetTextRelBase` return 0.** Rust
   LSDAs never use datarel or textrel encodings, so std calls neither; libgcc
   returns 0 for both on aarch64 and x86_64; Apple libunwind aborts in both.
   Proof: tools/eh.ts (16 cases) and tools/mixed.ts are byte-identical to the system unwinder with neither being reached.
4. **No forced unwind.** `_Unwind_ForcedUnwind` is not in the export list and
   `private_1` is always 0, so `_UA_FORCE_UNWIND` is never passed. std does
   not call it on these targets.
5. **`__eh_frame` is scanned linearly when an image has no `__unwind_info`
   (Darwin) or no `.eh_frame_hdr` table (ELF).** It is correct but O(n).
   ld64 always writes `__unwind_info`, and a DWARF-mode entry in it carries
   the FDE offset, so on Darwin the scan only serves images built without
   one. Not a semantic shortcut: the same FDE is found either way.

## Failures

Every frame that cannot be handled is one of 26 named failures
(src/failure.rs), never a guess. The three end-of-stack failures become
`_URC_END_OF_STACK`. Every other failure writes `ps-unwind: <Name> pc=0x...`
to stderr with `write(2)` and returns the fatal phase code to the caller of
raise, so std then aborts exactly as it does for a platform unwinder error.
The last failure is also kept in two atomics for a crash handler.

## Cost on the unwind path

- No allocation on the unwind path. The `alloc` crate is in the build for
  the image cache writers and ps-reclaim only (the staticlib brings a
  malloc/free global allocator; the rlib uses the program one).
- No locks and no syscalls in ps-unwind code on the unwind path. The only
  syscall is `write` on the failure path, then `abort`. Image lookup is the
  lock-free cache below; a Linux miss outside signal context may refresh it
  (loader lock, allocation), never inside.
- Table reads are plain loads from mapped image memory, bounded by the
  section ends the image reports; saved registers are loads from the stack
  being unwound, as in every unwinder.

## Image cache

src/cache.rs holds a sorted array of loaded images (range plus the slid
addresses of the unwind sections) behind one `AtomicPtr`. Crash handlers
cannot lock or allocate, so:

- Readers: one SeqCst increment of a global reader count, one load of the
  pointer, a binary search, a copy of the entry, one Release decrement. No
  allocation, no lock, no call.
- Writers hold a spin lock, copy the array, change it, swap it in with
  SeqCst, and retire the old array into a ps-reclaim `Domain`. After the
  swap a writer runs `Domain::advance` only when it reads the reader count
  as 0: a reader that could hold an old array loaded it while counted, and
  a reader counted later loads the new one. Otherwise the old arrays stay
  queued for the next writer (bounded by unload frequency; tools/cache-check
  shows 1 to 18 queued after 6000 swaps under 3 busy readers).
- ps-reclaim access: crates.io ps-reclaim 0.1.4 (`^0.1`,
  `default-features = false`, features `spin-garbage` and `libc`, because
  0.1.4 without `std` does not enable the optional `spin` and `libc` it
  then needs and fails to compile). Readers do not pin: the first
  `Domain::pin` on a thread registers it, which takes the registry lock (a
  spin lock without std), creates a pthread key and allocates. A crash
  handler on a thread that never pinned would allocate, and one that
  interrupted its own thread inside registration would spin forever. So
  ps-reclaim provides the retire queue and its epoch scan on the writer
  side, and the reader count is the grace period. check-nostd R6 fails if
  any pthread import (the pin path) is linked. If ps-reclaim gains an
  explicit, allocation-free pin for pre-registered threads, readers could
  pin instead of counting.
- Darwin fill: a constructor in `__DATA,__mod_init_func` builds the cache
  before main by registering `_dyld_register_func_for_add_image` and
  `_dyld_register_func_for_remove_image`. dyld calls the add callback for
  every loaded image during registration (collected and published once)
  and before each `dlopen` returns; the remove callback runs before each
  unload. The cache is complete, so a miss is NoImage in any context.
- Linux fill: a constructor in `.init_array` records the executable from
  `getauxval(AT_PHDR)` (load bias from PT_PHDR) and every image from
  `dl_iterate_phdr`, with the `dlpi_adds + dlpi_subs` generation. A miss
  outside signal context makes one `dl_iterate_phdr` pass that stops at once
  when the generation is unchanged, and otherwise rebuilds the array. In
  signal context a miss is SignalContextMiss and `dl_iterate_phdr` is never
  called; before the cache exists only the executable is found there (from
  AT_PHDR, no allocation). COMPILED, NOT RUN.
- Signal context is a process-wide counter set by the crash-handler API
  `ps_unwind_signal_enter()` / `ps_unwind_signal_leave()`: one atomic load,
  allocation-free. `sigaltstack(2)` was not used: it is a syscall per query
  and misses handlers that run on the normal stack. Process-wide means every
  thread is treated as in signal context while any handler runs: more
  refusals, never an unsafe call.
- Open: on Linux an entry for a `dlclose`d image stays until the next miss
  refreshes the array, so a pc in a range reused by a later mapping can hit
  the stale entry (its table pointers are dangling). Darwin has no such
  window. On both, an image unloaded while another thread is unwinding
  through it is a use after unmap, as with the platform unwinders.
- Verified on Darwin by tools/cache-check.ts (C1 constructor-built and
  complete, C2 add-image, C3 remove-image, C4 grace period under
  MallocScribble), each with a planted defect.

### Reader counter: to be replaced

Readers use the global `READERS` counter because ps-reclaim 0.1.4 has no
signal-safe pin. ps-reclaim branch `no-std-and-reader-slot` (not released)
adds `ReaderSlot` / `Domain::pin_reader`: lock-free, allocation-free,
async-signal-safe, one `static` slot for every thread; and builds `no_std`
with `default-features = false` alone. Once that is released, the cache
registers one slot in its constructor, `lookup` pins through it instead of
`READERS`, writers drop their `READERS == 0` wait for `advance`, and the
`spin-garbage`/`libc` features in Cargo.toml go. Not switched now: no
released version has it.

## Signal frames

- Darwin `_sigtramp` (macOS on this machine) has compact unwind only, a
  FRAME entry that restores fp and lr from its own frame record; there is no
  CIE with augmentation S (lldb `image show-unwind -n _sigtramp`). Walking
  out of a handler with `_Unwind_Backtrace`, the system unwinder and
  ps-unwind both continue at the interrupted function lr and never report
  the interrupted frame itself. ps-unwind mirrors that exactly
  (tools/signal-check.ts SG1) instead of guessing at the private
  `_sigtramp` register usage.
- Crash handlers should walk from the interrupted state instead:
  `ps_unwind_backtrace_ucontext(uc, cb, arg)` takes the third argument of a
  SA_SIGINFO handler, reads x0..x30, sp, pc and d8..d15 from the
  mcontext, and starts with ip_before_insn = 1, so the interrupted
  instruction itself is looked up (not pc - 1), a frameless leaf takes its
  return address from lr (FL1, FL2), and an FP- or SP-kind EKO frame
  interrupted at an arbitrary instruction is refused by name with
  EkoAsyncFrame (EA1). On Darwin that EKO function still has its
  standard tables (docs/FORMAT.md), so falling back to them for an
  interrupted EKO frame is possible; it is not done: the refusal stays.
  A version 2 record describes every instruction and steps an
  interrupted frame anywhere in it (signal-check SG2, FL3).
- aarch64 Linux: the vDSO `__kernel_rt_sigreturn` is recognised by its code
  (`mov x8, #139; svc #0`, as libgcc and LLVM libunwind do), before any
  table lookup; the caller state is the ucontext at sp + 128 (after the
  siginfo), and the next frame has ip_before_insn = 1. x86_64 Linux
  `__restore_rt` is not recognised. COMPILED, NOT RUN (signal-check LX1).

## One unwinder per process: Linux only

On Linux ps-unwind is the only unwinder: every `_Unwind_*` that the program,
std and the crt objects import is defined by ps-unwind (derived with nm, not
listed: tools/check-linux-link.ts L1), musl links with no libunwind.a member
(L2), and a glibc link must show no libgcc_s in NEEDED (L3, needs a glibc
cross toolchain; not run here). crtbegin.o calls `__register_frame_info` /
`__deregister_frame_info` only through weak references; ps-unwind does not
define them, so they stay 0, crtbegin skips registration, and the weak
references do not make an `--as-needed` libgcc_s NEEDED. EKO functions on
Linux may therefore carry only the EKO table, version 2 (docs/FORMAT.md).

## Two unwinders on Darwin, accepted

libSystem always maps its own libunwind, and with the two-level namespace
each image binds `_Unwind_*` to the library it was linked against, so the
calls made inside libSystem, libc++abi and every other system dylib cannot
be interposed. What can be guaranteed is that every `_Unwind_*` reference of
the image itself binds to ps-unwind (tools/eh.ts G5 fails unless
`nm -m` shows the ps-unwind binary defining
`_Unwind_RaiseException` in `__TEXT,__text` and the system binary binding it
from libSystem). A Darwin process therefore has two unwinders, and this is
the documented design, not a defect:

- ps-unwind: Rust panics raised from the image, `std::backtrace`, crash
  handlers that call ps-unwind.
- the system unwinder: C++ exceptions thrown in system dylibs (libc++abi),
  and every external reader: crash reporters (ReportCrash), Instruments,
  lldb, `backtrace(3)`.

The system unwinder and the external readers know only `__unwind_info`,
`__eh_frame` and the LSDA. So on Darwin the compiler must keep them for
every EKO function. Dropping them would make a C++ exception from a system
dylib that unwinds through EKO frames hit `std::terminate`, and crash
reports, Instruments samples and lldb backtraces would stop at the first EKO
frame. The two unwinders share no state; each reads the same immutable
tables.

## No EKO table on Darwin

Rule: code that never unwinds pays nothing. With `__unwind_info`, `__eh_frame`
and the LSDA mandatory, the EKO table was +43% on top of them (docs/FORMAT.md,
Size). What it was said to buy, case by case:

- Lookup speed. `__unwind_info` is already a two-level sorted index, and the
  image cache finds the image without a syscall either way. The EKO search is
  not asymptotically better, and no measurement showed an unwind-time
  difference that matters next to the personality and landing-pad work.
- No personality call for frames without pads. `__unwind_info` entries with
  no personality and no LSDA already skip the personality; the D2 rule forces
  the LSDA to exist for every function with pads, so the handler table holds
  no information the LSDA lacks.
- `EkoAsyncFrame`. This is a refusal, not a capability: an FP/SP record cannot
  describe an interrupted frame, so the EKO path refuses it by name. The
  standard tables describe the same frame (FRAME, FRAMELESS or DWARF mode),
  and `ps_unwind_backtrace_ucontext` walks it from them when no EKO record
  shadows them. With the table present the EKO record wins the lookup
  (src/find/darwin.rs) and the crash walk stops at that frame
  (tools/signal-check.ts EA1: last_failure=25). The table makes Darwin crash
  traces worse, not better. A version 2 table has no such refusal, but adds
  nothing either: the standard tables it would duplicate stay mandatory.
- Frame kinds the standard formats cannot express. None: every EKO record
  kind (LEAF, FP, SP) maps onto a compact FRAMELESS or FRAME encoding or DWARF
  CFI, and D1 already requires one to exist for every EKO function.

So the compiler does not emit `__eko_unwind` on Darwin. Verifier:
`bun tools/check-darwin-tables.ts IMAGE --no-eko` fails with D3 when a Darwin
image carries the section (planted defect: fixtures/darwin-tables/both.rs,
which carries it; fixtures/darwin-tables/plain.rs passes).

The Darwin reader stays. It costs one more section-name compare in the
load-command walk the add-image callback does anyway for `__unwind_info` and
`__eh_frame`, and nothing per unwind for an image without the section. It is
kept because Darwin is the only place the EKO decoder runs at all
(tools/eh.ts, tools/mixed.ts, tools/defects.ts use EKO fixtures);
Linux, where the table does replace CFI + LSDA, is compiled only here.
Dropping the reader would leave the format with no executed reader.

Verifier: `bun tools/check-darwin-tables.ts IMAGE` fails by name when an EKO
function has no `__unwind_info` entry with a mode (D1) or has landing pads
but no LSDA descriptor (D2). fixtures/darwin-tables/both.s is an EKO
function emitted the required way and passes; with its `.cfi_*` lines
removed it fails D1 and D2. fixtures/mixed/fx.s keeps EKO-only functions
on purpose: it tests that ps-unwind walks them from the EKO table alone, and
it is not compiler output; check-darwin-tables fails on it, as it must.

## Linking

Build: `./tools/build.sh [triple]` writes `target/dist[/triple]/ps_unwind.o`
(one LTO object; imports only the dyld add/remove-image registration or
`getauxval` and `dl_iterate_phdr`, `malloc`, `posix_memalign`, `free`,
`abort`, `memcpy`, `memmove`, `write`, and on aarch64 Linux the outline
atomics of compiler_builtins; check-nostd R4) and `libps_unwind.a` holding
just that object. The cargo staticlib also carries compiler_builtins, which
the program brings anyway, and an rlib build (no `staticlib` feature, no panic
handler) is what `cargo build` produces.

The archive must be force-loaded: ld64 resolves a symbol from the first
library on the command line that has it, and rustc puts `-C link-arg` after
`-lSystem`, so a plain archive is never consulted (a smoke test with the
archive given plainly bound `_Unwind_RaiseException` to libSystem).

- Darwin:
  `rustc -C panic=unwind -C link-arg=-Wl,-force_load,<ps-unwind>/target/dist/libps_unwind.a ...`
  or `-C link-arg=<ps-unwind>/target/dist/ps_unwind.o`.
- Linux: `-L native=<ps-unwind>/target/dist/<triple> -l static:+whole-archive=ps_unwind`.
  rustc places a command-line `-l` ahead of the upstream rlibs and so ahead
  of `-lunwind` / `-lgcc_s`; `-C link-arg=.../ps_unwind.o` lands after
  them, and on musl rust-lld then reports 14 duplicate symbols because the
  libunwind.a members were already loaded. Linked and checked on musl by
  tools/check-linux-link.ts L2; not executed (no Linux machine).


## Windows is out of scope

Windows does not use the Itanium `_Unwind_*` protocol for Rust: on
`*-windows-msvc` panics are SEH exceptions raised with `RaiseException` and
dispatched by the OS (`RtlDispatchException`, `RtlVirtualUnwind`, language
handlers named in `.pdata`/`.xdata` UNWIND_INFO, see pe-unwind-info), and on
`*-windows-gnu` the libgcc unwinder itself is driven by that same OS
dispatcher through `_GCC_specific_handler`. Replacing the unwinder there
means replacing kernel32/ntdll exception dispatch, which a user-space library
linked ahead of the system cannot do.

## Prior art read (none is a dependency)

- unwinding 0.2.10 (crates.io copy; a vendored copy was
  not present at that path): phase structure, `_Unwind_*` signatures, CFI
  coverage.
- macho-unwind-info 0.5.0: compact unwind page formats and encodings.
- framehop 0.15.0: arm64 compact FRAME/FRAMELESS steps and the PAC mask.
- wasmtime-internal-unwinder 49.0.2: call sites keyed by return-address offset
  in a sorted, mmap-ready table, the same choice the EKO handler table makes.
- pe-unwind-info 0.6.1: Windows UNWIND_INFO, for the scope decision above.
