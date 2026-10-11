# ps-unwind

A `#![no_std]` stack unwinder in Rust used instead of the platform unwinder in
Rust programs. It exports the 14
`_Unwind_*` entry points Rust std uses plus a 5-call crash-handler API, reads Apple compact unwind, DWARF CFI
and the EKO compact table (docs/FORMAT.md), and needs nothing from the platform but `libc`.

- docs/DESIGN.md: how it works, shortcuts and their proofs, open problems, link lines
- docs/FORMAT.md: the EKO compact unwind table, versions 1 and 2
- docs/TARGETS.md: what runs, what only compiles

## Build

```
./tools/build.sh                    # target/dist/libps_unwind.a and ps_unwind.o
./tools/build.sh x86_64-unknown-linux-musl
cargo build                         # rlib, no panic handler
```

## Use

```
rustc -C panic=unwind -C link-arg=-Wl,-force_load,$PWD/target/dist/libps_unwind.a main.rs
```

## Crash handlers: `ps_unwind_backtrace_ucontext`

This is THE entry point for a crash handler.
It walks from the register state the signal interrupted, not from the
handler, so the faulting frame is the first frame reported.

```
typedef unsigned (*trace_fn)(struct _Unwind_Context *, void *arg);
unsigned ps_unwind_backtrace_ucontext(const void *uc, trace_fn trace, void *arg);
void     ps_unwind_signal_enter(void);
void     ps_unwind_signal_leave(void);
unsigned ps_unwind_last_failure(uintptr_t *pc);   /* pc may be NULL */
```

- `uc` is the third argument of an `SA_SIGINFO` handler (`ucontext_t *`):
  Darwin arm64 reads `uc_mcontext`, Linux aarch64 and x86_64 read the
  kernel sigcontext in `uc_mcontext`.
- `trace` is called once per frame, innermost first, starting with the
  interrupted instruction itself (`ip_before_insn` is 1 for it, so
  `_Unwind_GetIPInfo` gives the faulting pc and a frameless leaf or a fault
  at a function's first instruction is attributed correctly). Inside it use
  `_Unwind_GetIP`, `_Unwind_GetIPInfo`, `_Unwind_GetCFA`,
  `_Unwind_GetRegionStart`. Return 0 (`_URC_NO_REASON`) to continue, any
  other value to stop.
- Return value: always 5 (`_URC_END_OF_STACK`), as `_Unwind_Backtrace` does,
  whether the walk ran out of frames, the callback stopped it, or a table
  could not be read. It does not tell a complete trace from a truncated one.
- Why it stopped: `ps_unwind_last_failure(&pc)` returns the named failure
  code (src/failure.rs) and the pc it stopped at, 0 if none was recorded. A
  null `uc` records `ZeroPc` (3). In signal context a pc whose image is not
  in the cache records `SignalContextMiss` (26); a frame an EKO version 1
  call-site record cannot describe records `EkoAsyncFrame` (25); unreadable tables
  record `NoUnwindInfo`, `FdeRangeMiss`, `BadCieFde` and the rest of the
  list. The code is process-global and is not cleared when a walk starts, so
  a concurrent walk on another thread can overwrite it.

Async-signal-safety. Between `ps_unwind_signal_enter()` and
`ps_unwind_signal_leave()` the walk takes no lock, allocates nothing, makes
no syscall and never calls into the loader: image lookups read the
lock-free image cache (docs/DESIGN.md, "Image cache"), and a pc the cache
does not hold is refused with `SignalContextMiss` instead of filling it.
Failure recording is two atomic stores. What the callback does is the
caller's responsibility: write(2) and fixed buffers only.

The enter/leave contract:

- Call `ps_unwind_signal_enter()` first in the handler and
  `ps_unwind_signal_leave()` before it returns or re-raises. Without it a
  cache miss tries to refresh the cache (dl_iterate_phdr, malloc), which is
  not async-signal-safe.
- It is a counter: nested handlers may each enter and leave. Leave never
  takes it below 0.
- It is process-wide, not per thread: while any thread is between enter and
  leave, every thread's lookups refuse to refill the cache (they still read
  it). Keep the window to the walk.
- The cache is filled by a constructor at load time (Darwin also through
  dyld add-image callbacks, Linux on the next lookup outside signal context
  after a dlopen), so images loaded before the crash are present.

```rust
unsafe extern "C" fn on_crash(sig: i32, _info: *mut libc::siginfo_t, uc: *mut libc::c_void) {
    ps_unwind_signal_enter();
    ps_unwind_backtrace_ucontext(uc, print_frame, core::ptr::null_mut());
    let mut pc = 0usize;
    let why = ps_unwind_last_failure(&mut pc); // write(2) it, with pc
    ps_unwind_signal_leave();
    libc::signal(sig, libc::SIG_DFL);
    libc::raise(sig);
}

let mut sa: libc::sigaction = core::mem::zeroed();
sa.sa_sigaction = on_crash as usize;
sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK; // with sigaltstack for stack overflow
libc::sigaction(libc::SIGSEGV, &sa, core::ptr::null_mut());
```

Verified on Darwin by `bun tools/signal-check.ts` (SG1, FL1, FL2, EA1); the
Linux sigcontext readers are compiled only (docs/TARGETS.md).

## Verify

```
bun tools/check-nostd.ts            # no_std, imports, exact export list
bun tools/eh.ts                     # landing-pad fixtures, EKO from tools/eko-gen.ts: byte-identical to the system unwinder, lldb bt, sizes
bun tools/eh.ts --plant wrong-pad   # planted EKO defects must fail by name (also: no-restore)
bun tools/mixed.ts                  # EKO + DWARF 0x9b + libSystem + Rust frames, lldb bt
bun tools/defects.ts                # planted defects must each fail a named check
bun tools/sizes.ts lib
bun tools/check-linux-link.ts       # Linux import set by nm, musl link, glibc NEEDED
bun tools/cache-check.ts            # image cache: constructor, dlopen, dlclose, grace period
bun tools/eh.ts --format 2          # the same suite with EKO version 2 tables (plants: wrong-pad, no-restore)
bun tools/eko2.ts                   # v2 tables equal .eh_frame at every instruction (E1, E2), handler rows (H1), sizes (Z1, Z2)
bun tools/eko2.ts --plant wrong-cfa # must fail E1 naming the function and the instruction offset
bun tools/signal-check.ts           # _sigtramp, frameless frames, v1 EkoAsyncFrame refusal, v2 prologue and epilogue faults
bun tools/signal-check.ts --plant drop-state # must fail SG2 naming the fault offset
bun tools/check-darwin-tables.ts target/darwin-tables/both --build   # EKO supplements, never replaces
bun tools/check-darwin-tables.ts target/darwin-tables/plain --no-eko # shipped Darwin image: no EKO table (D3)
```

Everything builds with the public rustup toolchain on PATH (PS_RUSTC names
another rustc); nothing outside this repository is read.

MIT licensed.

## Linux start objects (crt)

On Linux, link with our `crtbegin.o`/`crtend.o` instead of gcc's, so no gcc runtime and no `__register_frame_info` registration comes along. Build them with `sh tools/crt-build.sh <triple>` and link through `tools/crt-ld.sh`:

    rustc --target <triple> -C linker=tools/crt-ld.sh -C linker-flavor=ld.lld \
      -C link-self-contained=no -L native=<libc dir> \
      -L native=target/dist/<triple> -l static:+whole-archive=ps_unwind main.rs

with `PS_UNWIND_CRT_DIR=target/crt/<triple>`, `PS_UNWIND_CRT_LIBC_DIR=<libc dir>` and `PS_UNWIND_CRT_LLD=<rust-lld>` set. The line becomes `crt1.o crti.o crtbegin.o ... crtend.o crtn.o` (`crti.o crtbeginS.o ... crtendS.o crtn.o` for `-shared`): `crt1.o`/`rcrt1.o`/`Scrt1.o`, `crti.o`, `crtn.o` stay from the C library (musl: rust's self-contained directory; gnu: the glibc sysroot); gcc's `crtbegin*.o`, `crtend*.o`, `crtfastmath.o` and libgcc_s are gone and the driver refuses them. Checks: `bun tools/check-crt.ts`. Details, measurement and what ran: docs/CRT.md.
