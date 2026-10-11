# EKO compact unwind table, version 1

A compact unwind and landing-pad table a compiler can emit for the functions it compiles.
ps-unwind reads it (src/eko.rs); no other unwinder does.

What it may replace depends on the platform:

- Linux (gnu, musl): ps-unwind is the only unwinder in the process (checked
  by tools/check-linux-link.ts), so the compiler MAY drop `.eh_frame` CFI and
  the LSDA for EKO functions and emit only this table.
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
| 6 | u16 | flags | bit 0 = handlers follow Rust personality rules; required in v1. Other bits 0 |
| 8 | u32 | count | number of function records |
| 12 | u32 | size | whole chunk in bytes, multiple of 4, at least 16 + 16 * count |
| 16 | 16 * count | records | sorted by start, non-overlapping |
| ... | ... | handler tables | referenced by records, 4-byte aligned |

A reader that sees a nonzero word that is not a valid header stops with
`BadEkoHeader`; it does not skip ahead and guess.

## Function record (16 bytes)

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
version 1. Unknown flag bits are rejected the same way. arch is checked so
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
| target/mixed/mixed | 34512 B | 5808 B | 17284 B | 0.501 | +17284 B, +42.9% |

The Linux ratio is measured on the Mach-O tables as a proxy; no ELF image
is measured here.
