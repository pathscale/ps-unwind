// Hand-written frames for the mixed-stack fixture (aarch64 Mach-O).
//
// _fx_dwarf        DWARF-only frame: the frame record sits below the saved
//                  registers, which compact unwind cannot encode, so the
//                  linker emits a DWARF-mode entry. CIE augmentation zPLR,
//                  personality _rust_eh_personality through encoding 0x9b,
//                  hand-written LSDA. Its landing pad ends with a call to
//                  _Unwind_Resume as the last instruction of the function.
// _fx_sentinel     EKO frame placed directly after _fx_dwarf. Its only
//                  handler row is a terminate row at offset 0, so a lookup
//                  that uses the return address instead of return address
//                  minus one terminates the process.
// _fx_eko_cleanup  EKO frame (FP kind, x19 x20 saved) with two call sites
//                  and a different cleanup pad for each.
// _fx_compact      FRAME-mode compact unwind frame, see below.
// _fx_regcheck     EKO frame (FP kind, all 18 callee-saved registers) with a
//                  catch row. The pad compares x19-x28 and d8-d15 with the
//                  values it set before the call.

    .text
    .p2align 2
    .globl _fx_dwarf
_fx_dwarf:
Lfd_begin:
    .cfi_startproc
    .cfi_personality 155, _rust_eh_personality
    .cfi_lsda 16, Lfd_lsda
    sub sp, sp, #64
    .cfi_def_cfa_offset 64
    stp x29, x30, [sp, #16]
    .cfi_offset 30, -40
    .cfi_offset 29, -48
    stp x19, x20, [sp, #32]
    .cfi_offset 20, -24
    .cfi_offset 19, -32
    str d8, [sp, #48]
    .cfi_offset 72, -16
    add x29, sp, #16
    mov x19, x0
    mov x20, x1
    fmov d8, x1
    mov x0, x1
Lfd_call:
    blr x19
Lfd_ret:
    add x0, x20, #1
    ldr d8, [sp, #48]
    ldp x19, x20, [sp, #32]
    ldp x29, x30, [sp, #16]
    add sp, sp, #64
    ret
Lfd_pad:
    mov x19, x0
    mov x0, x20
    fmov x1, d8
    bl _fx_dwarf_landed
    mov x0, x19
    bl __Unwind_Resume
Lfd_end:
    .cfi_endproc

    .p2align 2
    .globl _fx_sentinel
_fx_sentinel:
    brk #2
Lsn_end:

    .p2align 2
    .globl _fx_eko_cleanup
_fx_eko_cleanup:
    sub sp, sp, #32
    stp x29, x30, [sp, #16]
    add x29, sp, #16
    stp x20, x19, [sp, #0]
    mov x19, x1
    mov x20, x0
    mov x0, x1
    bl _fx_noop
Lec_ret1:
    mov x0, x19
    blr x20
Lec_ret2:
    ldp x20, x19, [sp, #0]
    ldp x29, x30, [sp, #16]
    add sp, sp, #32
    ret
Lec_pad1:
    mov x20, x0
    mov x0, #1
    mov x1, x19
    bl _fx_eko_landed
    mov x0, x20
    bl __Unwind_Resume
    brk #1
Lec_pad2:
    mov x20, x0
    mov x0, #2
    mov x1, x19
    bl _fx_eko_landed
    mov x0, x20
    bl __Unwind_Resume
    brk #1
Lec_end:

    .p2align 2
    .globl _fx_regcheck
_fx_regcheck:
    sub sp, sp, #160
    stp x29, x30, [sp, #144]
    add x29, sp, #144
    stp x20, x19, [sp, #128]
    stp x22, x21, [sp, #112]
    stp x24, x23, [sp, #96]
    stp x26, x25, [sp, #80]
    stp x28, x27, [sp, #64]
    stp d9, d8, [sp, #48]
    stp d11, d10, [sp, #32]
    stp d13, d12, [sp, #16]
    stp d15, d14, [sp, #0]
    mov x16, x0
    mov x0, x1
    mov x9, #0xa500
    movk x9, #0x5a5a, lsl #48
    add x19, x9, #19
    add x20, x9, #20
    add x21, x9, #21
    add x22, x9, #22
    add x23, x9, #23
    add x24, x9, #24
    add x25, x9, #25
    add x26, x9, #26
    add x27, x9, #27
    add x28, x9, #28
    add x10, x9, #108
    fmov d8, x10
    add x10, x9, #109
    fmov d9, x10
    add x10, x9, #110
    fmov d10, x10
    add x10, x9, #111
    fmov d11, x10
    add x10, x9, #112
    fmov d12, x10
    add x10, x9, #113
    fmov d13, x10
    add x10, x9, #114
    fmov d14, x10
    add x10, x9, #115
    fmov d15, x10
    blr x16
Lrc_ret:
    mov x0, #0
    mov x1, #0
    b Lrc_out
Lrc_pad:
    mov x9, #0xa500
    movk x9, #0x5a5a, lsl #48
    mov x1, #0
    add x10, x9, #19
    cmp x19, x10
    cset x11, ne
    orr x1, x1, x11, lsl #0
    add x10, x9, #20
    cmp x20, x10
    cset x11, ne
    orr x1, x1, x11, lsl #1
    add x10, x9, #21
    cmp x21, x10
    cset x11, ne
    orr x1, x1, x11, lsl #2
    add x10, x9, #22
    cmp x22, x10
    cset x11, ne
    orr x1, x1, x11, lsl #3
    add x10, x9, #23
    cmp x23, x10
    cset x11, ne
    orr x1, x1, x11, lsl #4
    add x10, x9, #24
    cmp x24, x10
    cset x11, ne
    orr x1, x1, x11, lsl #5
    add x10, x9, #25
    cmp x25, x10
    cset x11, ne
    orr x1, x1, x11, lsl #6
    add x10, x9, #26
    cmp x26, x10
    cset x11, ne
    orr x1, x1, x11, lsl #7
    add x10, x9, #27
    cmp x27, x10
    cset x11, ne
    orr x1, x1, x11, lsl #8
    add x10, x9, #28
    cmp x28, x10
    cset x11, ne
    orr x1, x1, x11, lsl #9
    add x10, x9, #108
    fmov x12, d8
    cmp x12, x10
    cset x11, ne
    orr x1, x1, x11, lsl #10
    add x10, x9, #109
    fmov x12, d9
    cmp x12, x10
    cset x11, ne
    orr x1, x1, x11, lsl #11
    add x10, x9, #110
    fmov x12, d10
    cmp x12, x10
    cset x11, ne
    orr x1, x1, x11, lsl #12
    add x10, x9, #111
    fmov x12, d11
    cmp x12, x10
    cset x11, ne
    orr x1, x1, x11, lsl #13
    add x10, x9, #112
    fmov x12, d12
    cmp x12, x10
    cset x11, ne
    orr x1, x1, x11, lsl #14
    add x10, x9, #113
    fmov x12, d13
    cmp x12, x10
    cset x11, ne
    orr x1, x1, x11, lsl #15
    add x10, x9, #114
    fmov x12, d14
    cmp x12, x10
    cset x11, ne
    orr x1, x1, x11, lsl #16
    add x10, x9, #115
    fmov x12, d15
    cmp x12, x10
    cset x11, ne
    orr x1, x1, x11, lsl #17
Lrc_out:
    ldp d15, d14, [sp, #0]
    ldp d13, d12, [sp, #16]
    ldp d11, d10, [sp, #32]
    ldp d9, d8, [sp, #48]
    ldp x28, x27, [sp, #64]
    ldp x26, x25, [sp, #80]
    ldp x24, x23, [sp, #96]
    ldp x22, x21, [sp, #112]
    ldp x20, x19, [sp, #128]
    ldp x29, x30, [sp, #144]
    add sp, sp, #160
    ret
Lrc_end:

// _fx_compact: a standard frame that compact unwind encodes in FRAME mode
// (x19-x22 and d8/d9 in pairs below the frame record). It sits directly
// below _fx_regcheck, so the values regcheck compares for x19-x22, d8 and d9
// are the ones only this frame saved.
    .p2align 2
    .globl _fx_compact
_fx_compact:
    .cfi_startproc
    sub sp, sp, #64
    stp d9, d8, [sp, #0]
    stp x22, x21, [sp, #16]
    stp x20, x19, [sp, #32]
    stp x29, x30, [sp, #48]
    add x29, sp, #48
    .cfi_def_cfa 29, 16
    .cfi_offset 30, -8
    .cfi_offset 29, -16
    .cfi_offset 19, -24
    .cfi_offset 20, -32
    .cfi_offset 21, -40
    .cfi_offset 22, -48
    .cfi_offset 72, -56
    .cfi_offset 73, -64
    mov x9, #0x5555
    mov x19, x9
    mov x20, x9
    mov x21, x9
    mov x22, x9
    fmov d8, x9
    fmov d9, x9
    bl _fx_compact_next
    ldp x29, x30, [sp, #48]
    ldp x20, x19, [sp, #32]
    ldp x22, x21, [sp, #16]
    ldp d9, d8, [sp, #0]
    add sp, sp, #64
    ret
    .cfi_endproc

    .section __TEXT,__gcc_except_tab
    .p2align 2
Lfd_lsda:
    .byte 0xff
    .byte 0xff
    .byte 0x01
    .uleb128 Lfd_cs_end - Lfd_cs_begin
Lfd_cs_begin:
    .uleb128 0
    .uleb128 Lfd_call - Lfd_begin
    .uleb128 0
    .uleb128 0
    .uleb128 Lfd_call - Lfd_begin
    .uleb128 Lfd_ret - Lfd_call
    .uleb128 Lfd_pad - Lfd_begin
    .uleb128 0
    .uleb128 Lfd_ret - Lfd_begin
    .uleb128 Lfd_end - Lfd_ret
    .uleb128 0
    .uleb128 0
Lfd_cs_end:

// EKO chunk, format version 1 (docs/FORMAT.md). Frame words:
//   sentinel  0x00000000  LEAF, no saves
//   cleanup   0x00600019  FP, mask x19 x20, first slot 3, descending
//   regcheck  0x007ffff9  FP, mask x19-x28 d8-d15, first slot 3, descending
    .section __TEXT,__eko_unwind,regular,no_dead_strip
    .p2align 2
Leko_chunk:
    .long 0x57554b45
    .byte 1
    .byte 1
    .short 1
    .long 3
    .long Leko_chunk_end - Leko_chunk
Leko_r0:
    .long _fx_sentinel - Leko_r0
    .long Lsn_end - _fx_sentinel
    .long 0x00000000
    .long Leko_h0 - Leko_chunk
Leko_r1:
    .long _fx_eko_cleanup - Leko_r1
    .long Lec_end - _fx_eko_cleanup
    .long 0x00600019
    .long Leko_h1 - Leko_chunk
Leko_r2:
    .long _fx_regcheck - Leko_r2
    .long Lrc_end - _fx_regcheck
    .long 0x007ffff9
    .long Leko_h2 - Leko_chunk
Leko_h0:
    .long 1
    .long 0, 0, 2
Leko_h1:
    .long 2
    .long Lec_ret1 - _fx_eko_cleanup, Lec_pad1 - _fx_eko_cleanup, 0
    .long Lec_ret2 - _fx_eko_cleanup, Lec_pad2 - _fx_eko_cleanup, 0
Leko_h2:
    .long 1
    .long Lrc_ret - _fx_regcheck, Lrc_pad - _fx_regcheck, 1
Leko_chunk_end:
