# EKO compact unwind table, versions 1 and 2

Version 1 is specified first; "Version 2" below describes what changes. A
compact unwind and landing-pad table a compiler can emit for the functions it compiles.
ps-unwind reads it (src/eko.rs); no other unwinder does.

What it may replace depends on the platform:

- Linux (gnu, musl): ps-unwind is the only unwinder in the process (checked
  by tools/check-linux-link.ts), so the compiler MAY drop `.eh_frame` CFI and
  the LSDA for EKO functions and emit only this table, in version 2. A
  version 1 table describes call sites only (an interrupted FP or SP frame
  is refused with `EkoAsyncFrame`), so dropping `.eh_frame` with it would
  lose crash backtraces from a signal in a prologue or epilogue; a version
  2 table describes every instruction. A compiler drops `.eh_frame` for a
  function only when its v2 state equals that `.eh_frame` at every
  instruction (tools/eko2.ts E1 is that check).
- Darwin: the table is NOT emitted. The compiler MUST keep the standard
  `__unwind_info` / `__eh_frame` entries and the LSDA for every EKO function:
  libSystem maps its own libunwind and, with the two-level namespace, its
  `_Unwind_*` calls cannot be interposed, so a C++ exception thrown in a
  system dylib unwinds through EKO frames with the system unwinder and,
  without standard tables, ends in `std::terminate`; crash reporters,
  Instruments and lldb read only the standard tables. See docs/DESIGN.md,
  "Two unwinders on Darwin". With those tables mandatory, the EKO table adds
  nothing ps-unwind needs (docs/DESIGN.md, "No EKO table on Darwin"), and
  code that never unwinds must pay nothing, so it is not emitted.
  `bun tools/check-darwin-tables.ts IMAGE --no-eko` fails by name (D3) on a
  Darwin image that carries one. ps-unwind still reads `__eko_unwind` if an
  image has it: the Darwin fixtures carry it on purpose, because Darwin is
  the only place the EKO reader is executed.
All fields are little-endian. Every offset below is in bytes.

## Where it lives

| Object format | Container | How the reader finds it |
|---|---|---|
| Mach-O (arm64) | section `__TEXT,__eko_unwind`, type `S_REGULAR`, attribute `S_ATTR_NO_DEAD_STRIP`, alignment 2^2 | the dyld add-image callback gives each image `mach_header`; the reader walks its `LC_SEGMENT_64 __TEXT` for the section, adds the slide and keeps it in the image cache |
| ELF (aarch64, x86_64) | `SHF_ALLOC` section of type `SHT_NOTE`, name `.note.eko_unwind`, alignment 4; one note per object: namesz 5, name `EKUW\0`, type 1, desc = one chunk | `dl_iterate_phdr`, every `PT_NOTE` of the image holding the pc; notes with another name or type are skipped |

The linker concatenates the per-object contributions. On Mach-O that gives a
run of chunks, possibly separated by zero padding words; on ELF it gives one
note per object. Each chunk is self-describing, so no link-time merging is
needed and a stripped or partial link stays readable.

## Chunk

One chunk per compiled object, 4-byte aligned.

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | u32 | magic | `0x57554B45` (`EKUW` in memory) |
| 4 | u8 | version | 1 |
| 5 | u8 | arch | 1 = aarch64, 2 = x86_64; must match the process |
| 6 | u16 | flags | bit 0 = handlers follow Rust personality rules; required in v1 and v2. Other bits 0 |
| 8 | u32 | count | number of function records |
| 12 | u32 | size | whole chunk in bytes, multiple of 4, at least 16 + 16 * count |
| 16 | 16 * count | records | sorted by start, non-overlapping |
| ... | ... | handler tables | referenced by records, 4-byte aligned |

A reader that sees a nonzero word that is not a valid header stops with
`BadEkoHeader`; it does not skip ahead and guess.

## Function record (16 bytes, version 1)

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | i32 | start | function start minus the address of this field |
| 4 | u32 | length | function length; the record covers [start, start + length) |
| 8 | u32 | frame | frame word, below |
| 12 | u32 | handlers | offset of the handler table from the chunk start; 0 = none |

Relocations for `start`: Mach-O arm64 `ARM64_RELOC_SUBTRACTOR` +
`ARM64_RELOC_UNSIGNED`, length 2 (what `.long sym - .` assembles to); ELF
`R_AARCH64_PREL32` or `R_X86_64_PC32`. `length` and `handlers` are
assemble-time constants and carry no relocation.

## Frame word

| Bits | Field |
|---|---|
| 0-1 | kind: 0 LEAF, 1 FP, 2 SP, 3 reserved (`BadEkoRecord`) |
| 2 | save order: 0 descending (first saved register in the lowest slot number), 1 ascending |
| 3-20 | register mask. aarch64: bits 0-9 = x19-x28, bits 10-17 = d8-d15. x86_64: bits 0-4 = rbx, r12, r13, r14, r15; higher bits must be 0 |
| 21-31 | param |

Slot s is the 8-byte word at CFA - 8 * s. Saved registers occupy consecutive
slots starting at the first save slot, in mask-bit order (or reversed when
bit 2 is set).

| Kind | CFA | Return address | Caller FP | First save slot |
|---|---|---|---|---|
| LEAF | aarch64: SP + 16 * param; x86_64: SP + 8 + 16 * param | aarch64: x30 (unchanged); x86_64: slot 1 | unchanged | none: mask must be 0 |
| FP | FP + 16 | slot 1 | slot 2 | param (at least 3 when the mask is not 0) |
| SP | SP + 16 * param | slot 1 | unchanged | 2 |

FP and SP records describe the frame at its call sites only, the only places
a caller frame can be. LEAF records describe a function that never calls and
therefore can only be the innermost, interrupted frame. A frame whose kind
does not fit how it was reached fails by name: an FP or SP record for an
interrupted frame is `EkoAsyncFrame`, a LEAF record for a caller frame is
`BadEkoRecord`. A v1 producer never signs return addresses; the reader
still strips bits above 48 from return addresses on aarch64.

## Handler table

Only functions with landing pads have one, so a function without landing
pads costs zero handler bytes and its record has handlers = 0.

| Offset | Size | Field |
|---|---|---|
| 0 | u32 | rows |
| 4 | 12 * rows | rows sorted by ret, each ret unique |

Row: `u32 ret` (return address of the call, minus function start), `u32 pad`
(landing pad minus function start), `u32 action`:

| action | pad | Meaning (matches `EHAction` in std personality/gcc.rs) |
|---|---|---|
| 0 cleanup | not 0 | run the pad in phase two, then `_Unwind_Resume` |
| 1 catch | not 0 | phase one stops here; phase two installs the pad |
| 2 terminate | 0 | phase one fails (`_URC_FATAL_PHASE1_ERROR`), as Rust `EHAction::Terminate` |

A call with no row continues unwinding. This is the opposite of an LSDA,
where a call missing from the call-site table means terminate: EKO lists
only calls that need something, so the common propagating call costs
nothing. Rows are keyed by return address offset, which needs no length and
no encoding. A duplicate ret is `EkoAmbiguousCallSite`; an invalid
action/pad pair is `BadEkoRecord`.

When the pad is installed: data register 0 (x0 / rax) = exception object,
data register 1 (x1 / rdx) = 0, pc = function start + pad, every other
register as unwound. This is what rust_eh_personality sets.

## PC lookup

1. The lookup address is the return address minus 1 for caller frames and
   the pc itself for the interrupted frame.
2. Find the image holding it (dyld / dl_iterate_phdr).
3. Walk the chunks of that image in order. Skip zero words. For a chunk whose
   first record start <= address < last record end, binary search the
   records for the last start <= address, check that the neighbours do not
   overlap it (`EkoUnsorted`), and accept it when address < start + length.
4. No chunk covers the address: fall back to the platform tables of the same
   image (compact unwind / `.eh_frame_hdr` / `__eh_frame`). This is how
   stacks that mix EKO, rustc and C frames are walked.
5. Handler lookup is a binary search of the rows for ret = return address -
   function start.

## Versioning

The version byte changes for any layout or meaning change. A reader rejects
versions it does not know (`BadEkoHeader`) rather than reading them as
version 1 or 2. Chunks of both versions may sit in one section; each is
read by its own rules, and the version 1 rules, results and refusals are
unchanged by version 2. Unknown flag bits are rejected the same way. arch is checked so
that a chunk for the wrong architecture is never used.

## Size

Per function: 16 bytes. Per function with landing pads: 4 bytes plus 12 per
call site with a pad. Per object: 16 bytes. No CIE, no personality pointer,
no GOT entry, no LSDA header.

Linux: the table replaces CFI + LSDA of EKO functions, so the size change is
EKO minus what it replaces. Darwin: the table would be an addition, since the
image keeps all of `__unwind_info`, `__eh_frame` and `__gcc_except_tab`; the
last column of the second table is what emitting it would cost, and is why
it is not emitted.

Two measurements, both on Darwin arm64 Mach-O images built with the public
rustc:

Exact, same functions: tools/eh.ts S1 derives an EKO record for each of the
23 eh_* fixture functions (tools/eko-gen.ts) and compares it with that
function's own `__eh_frame` FDE and its LSDA in `__gcc_except_tab` (to the
next LSDA). CIEs and `__unwind_info` are not counted. Per-function rows are
in transcripts/eh.txt.

| image | functions | `__eh_frame` FDEs | `__gcc_except_tab` | EKO v1 | ratio |
|---|---|---|---|---|---|
| target/eh/ps (fixtures/eh/eh.rs) | 23 | 1480 B | 696 B | 1624 B | 0.746 |

The EKO figure includes 24 terminate rows: calls the LSDA leaves out
(callees that cannot unwind, in functions that have an LSDA) must be listed
in EKO, where a missing row means "continue". These fixtures are small and
pad-heavy on purpose, so the ratio is worse than on ordinary code.

Estimate, whole image: `bun tools/sizes.ts image IMG` counts 16 B per
function in `__TEXT,__text` and 4 + 12 B per landing-pad call site, without
terminate rows (transcripts/sizes.txt):

| image | `__eh_frame` + `__gcc_except_tab` | `__unwind_info` | EKO v1 | Linux ratio | Darwin growth |
|---|---|---|---|---|---|
| target/mixed/mixed | 34512 B | 5816 B | 17364 B | 0.503 | +17364 B, +43.1% |

The Linux ratio is measured on the Mach-O tables as a proxy; no ELF image
is measured here.

## Version 2: the unwind state at every instruction

Version 2 keeps the chunk header (version byte 2, same magic, arch, flags,
count and size rules), the section and note containers, the PC lookup and
the meaning of every handler row. It replaces the 16-byte record and its
frame word with a 12-byte record and a state program that gives the unwind
state at every instruction of the function, so a frame interrupted anywhere
(prologue, body, epilogue, a frameless leaf) is stepped exactly and
`EkoAsyncFrame` does not exist for version 2 records. Nothing in it is
aarch64-only: registers are DWARF numbers, and the per-architecture part is
the table "Architecture" below.

### Record (12 bytes)

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | i32 | start | function start minus the address of this field (relocated as in v1) |
| 4 | u32 | length | function length; the record covers [start, start + length) |
| 8 | u32 | data | bits 0-30: offset of the description from the chunk start, 0 = none; bit 31: the description ends with a handler table |

Records are sorted by start and do not overlap; size is at least
16 + 12 * count. data = 0 means the entry state holds at every instruction
and there are no landing pads: a frameless leaf that never moves the stack
pointer costs its 12-byte record and nothing else. Bit 31 with offset 0 is
`BadEkoRecord`. Descriptions are byte-aligned and may be in any order; the
chunk is zero-padded to a multiple of 4.

A description is a state program, ended by END, then, when bit 31 is set,
the handler table.

### Architecture

| arch | code unit | SP | FP | return address column | entry state |
|---|---|---|---|---|---|
| 1 aarch64 | 4 bytes | 31 | 29 | 30 (x30) | CFA = SP + 0; the return address is in x30; nothing saved |
| 2 x86_64 | 1 byte | 7 | 6 | 16 | CFA = SP + 8; the return address in slot 1; nothing else saved |

These are the DWARF numbers and the initial CFI rows of both ABIs. A new
architecture is a new row: the program encoding does not change.

### State

A state is the CFI row of one instruction, restricted to what compilers
emit for code that unwinds:

- CFA = SP + 8 * n or FP + 8 * n.
- Each saved register (DWARF number, return address column included) is at
  slot s: the 8-byte word at CFA - 8 * s, s >= 1.
- Every other register, and the return address when its column is not
  saved, keeps its value (aarch64: the return address stays in x30).
- args_size: the DW_CFA_GNU_args_size in effect, bytes of outgoing
  arguments pushed at this instruction (x86 code that pushes arguments; 0
  otherwise). REMEMBER and RESTORE_STATE save and restore it with the rest
  of the state; ENTRY sets it to 0. It does not change the step (the CFA
  rule already counts the pushed bytes). When a landing pad is installed in
  the frame, the stack pointer moves up by the args_size in effect at the
  call (return address - 1), before the pc changes: installed SP = SP at
  the call + args_size, so the pad sees the arguments popped as after a
  normal return. This is what libgcc (uw_install_context) and LLVM
  libunwind (unw_set_reg of the ip) do. ps-unwind does it for both readers
  in Cursor::set_landing_ip_for (src/abi.rs), which `_Unwind_SetIP` and the
  EKO personality call, on every architecture whenever args_size is
  nonzero; version 1 records and compact entries have none. Checked at
  decode level on x86_64 musl (`bun tools/landing.ts`: 838 landing-pad
  sites, one with args_size 16, both readers equal to `.eh_frame`) and
  executed on aarch64 Darwin with a hand-written fixture
  (`bun tools/args-run.ts`: system unwinder, `.eh_frame` path and v2 path
  all hand the pad the popped stack pointer). Planted defects
  args-skip-dwarf and args-skip-v2 in tools/defects.ts fail by name.

Stepping a frame: CFA from its rule; every saved register loaded from its
slot; the caller stack pointer is the CFA; the caller pc is the return
address (high bits stripped on aarch64). This is the CFI step for the same
row (src/cfi.rs apply).

### State program

The program starts at offset 0 of the function in the entry state. Ops
change the state at the current offset; ADVANCE moves the offset forward.
The state at offset X is the state after the last op before the ADVANCE that
moves past X (DWARF CFA semantics). ULEB operands are at most 5 bytes and
fit in u32.

| byte | op | operands | effect |
|---|---|---|---|
| 0x00 | END | | end of the program |
| 0x01-0x3f | ADVANCE | | offset += n code units, n = byte |
| 0x40-0x7f | CFA_OFFSET | | CFA register unchanged, CFA = reg + 8 * (byte & 0x3f) |
| 0x80-0xbf | SAVE | uleb slot | register (byte & 0x3f) saved at slot |
| 0xc0 | CFA_SP | uleb n | CFA = SP + 8 * n |
| 0xc1 | CFA_FP | uleb n | CFA = FP + 8 * n |
| 0xc2 | CFA_OFFSET_LONG | uleb n | CFA = reg + 8 * n |
| 0xc3 | ADVANCE_LONG | uleb n | offset += n code units |
| 0xc4 | SAVE_LONG | uleb reg, uleb slot | register reg saved at slot |
| 0xc5 | RESTORE_LONG | uleb reg | reg back to its entry rule |
| 0xc6 | ENTRY | | the whole state back to the entry state |
| 0xc7 | REMEMBER | | push the whole state (CFA included); at most 4 deep, else `RememberStackOverflow` |
| 0xc8 | RESTORE_STATE | | pop it; an empty stack is `BadEkoRecord` |
| 0xc9 | FRAME | | the frame record both ABIs use: CFA = FP + 16, FP at slot 2, return address at slot 1 |
| 0xca | FRAME_REGS | | FP at slot 2, return address at slot 1; CFA unchanged |
| 0xcb | ARGS_SIZE | uleb n | args_size = n bytes (DW_CFA_GNU_args_size); 0 in the entry state |
| 0xcc-0xdf | reserved | | `BadEkoRecord` |
| 0xe0-0xff | RESTORE | | register (byte & 0x1f) back to its entry rule |

Prologue and epilogue states are written as they happen: one op group per
instruction that changes the state, after each callee-saved store and
before each restore. Example: sg_v2_leaf of fixtures/signal/sig.s, a
frameless aarch64 function that saves x19 (the udf instructions are the
fault points of tools/signal-check.ts FL3). Its program is 10 bytes:

    +0x00 udf #32                           entry state
    +0x04 sub sp, sp, #32
    +0x08 udf #33                 02 44     ADVANCE 2, CFA_OFFSET 4 (CFA = SP + 32)
    +0x0c str x19, [sp, #16]
    +0x10 udf #34                 02 93 02  ADVANCE 2, SAVE x19 slot 2
    +0x14 mov x19, #0x3333
    +0x18 udf #35
    +0x1c ldr x19, [sp, #16]
    +0x20 udf #36                 04 f3     ADVANCE 4, RESTORE x19
    +0x24 add sp, sp, #32
    +0x28 udf #37                 02 40     ADVANCE 2, CFA_OFFSET 0
    +0x2c ret                     00        END

Each op group takes effect at the instruction after the one that changed
the state. sg_v2_fp (frame record, x19, x20 and d8 saved one store at a
time, an epilogue restoring one load at a time, then the body state again
after ret) is 33 bytes: 02 46 9d 06 9e 05 02 93 03 94 04 02 c4 48 02 02 c1
06 06 c7 c0 06 02 c5 48 02 f3 f4 02 c6 02 c8 00.

An epilogue in the middle of a function is REMEMBER before it and
RESTORE_STATE after its return, as in CFI. A function whose state never
leaves the entry state has no program (data = 0, or END alone when it has
a handler table).

### Handler table (version 2)

Rows have the meaning of the version 1 rows (ret, pad, action; actions 0
cleanup, 1 catch, 2 terminate; a call with no row continues; landing pad
registers as in version 1), in a smaller encoding:

| Field | Encoding |
|---|---|
| rows | uleb |
| per row | uleb (ret - previous ret, the first relative to 0), uleb (pad * 4 + action) |

Rows are sorted by ret, so every delta is at least 1; a zero delta is a
second row for one return address, `EkoAmbiguousCallSite`. An invalid
action and pad pair is `BadEkoRecord`. The lookup reads the rows in order
and stops at the first ret at or past the one it looks for.

### What version 2 does not express

Rows with a CFA on another register or an expression, a register saved in
another register, `undefined` or expression rules, GNU ops other than
DW_CFA_GNU_args_size, DW_CFA_GNU_args_size in an FDE that also uses
DW_CFA_remember_state (no measured function has both; it is refused rather
than given a meaning), and aarch64 return address signing
(DW_CFA_AARCH64_negate_ra_state). A function that needs one keeps its
`.eh_frame` FDE and LSDA and gets no record; tools/eko2-gen.ts lists it by
name with the reason. Measured on the whole fixture images (tools/eko2.ts
E2): 435 of 435 functions on Darwin arm64, 787 of 787 on aarch64 musl, 692
of 692 on x86_64 musl (2 of them with DW_CFA_GNU_args_size, as ARGS_SIZE).
Planted defect: `bun tools/eko2.ts --plant wrong-args` adds 8 to the first
nonzero args_size and fails E2 x86_64-unknown-linux-musl naming the
function and offset.

### Version 2 checks and size

tools/eko2.ts generates v2 tables with tools/eko2-gen.ts from the
`.eh_frame` and LSDA of fixtures/eh/eh.rs built by the public rustc for
aarch64-apple-darwin, aarch64-unknown-linux-musl and
x86_64-unknown-linux-musl, links them into the image, reads them back
through the reader (tools/eko-dump.rs: eko::lookup_arch, eko::run and
eko::handler2) and compares the state with the `.eh_frame` of the same
function at every instruction (E1), the handler rows with the LSDA (H1),
and, table-only, every FDE of the whole image (E2). The Linux images are
decoded from the file and never run. tools/signal-check.ts SG2 and FL3
fault at every prologue and epilogue step of a v2 function on Darwin and
check the caller frame against the hardware state at entry; tools/eh.ts
--format 2 runs the landing-pad suite with v2 tables.

Bytes per function, version 2 against the `.eh_frame` FDE and the LSDA it
replaces (CIEs not counted; on Linux `.eh_frame_hdr` adds 8 more bytes per
function that version 2 also replaces), with version 1 for the same rows
(call sites only, so it cannot replace `.eh_frame`):

| image | functions | FDE + LSDA | per fn | v2 | per fn | v2 / (FDE + LSDA) | v1 per fn |
|---|---|---|---|---|---|---|---|
| eh_* functions, Darwin arm64 | 23 | 1480 + 696 B | 94.6 B | 967 B | 42.0 B | 0.444 | 69.9 B |
| eh_* functions, aarch64 musl | 23 | 1240 + 728 B | 85.6 B | 1026 B | 44.6 B | 0.521 | 67.3 B |
| eh_* functions, x86_64 musl | 23 | 1024 + 696 B | 74.8 B | 986 B | 42.9 B | 0.573 | 69.9 B |
| whole image, Darwin arm64 | 435 | 30404 + 6712 B | 85.3 B | 18489 B | 42.5 B | 0.498 | 50.0 B |
| whole image, aarch64 musl | 787 | 37380 + 15800 B | 67.6 B | 27201 B | 34.6 B | 0.511 | 34.2 B |
| whole image, x86_64 musl | 692 | 27744 + 14976 B | 61.7 B | 22948 B | 33.2 B | 0.537 | 37.3 B |

Version 2 is 43 to 56 percent smaller than what it replaces (per function,
not counting chunk headers: 16 bytes per object). On the whole aarch64 musl
image it is 0.4 bytes per function larger than version 1 for the same rows,
because version 1 says nothing about prologues and epilogues. Darwin is
unchanged: no table is emitted there (D3), whatever its version.
