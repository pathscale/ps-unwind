// Signal-frame fixtures (tools/signal-check.ts), aarch64 Darwin.
//
// _sg_before       FRAME function placed directly before _sg_fault_first, so
//                  a lookup at pc - 1 for the interrupted frame lands here
// _sg_fault_first  frameless leaf (compact FRAMELESS, stack 0) whose first
//                  instruction faults: pc = function start, RA in lr
// _sg_frameless32  frameless (compact FRAMELESS, stack 32) that faults after
//                  sub sp, sp, #32
// _sg_eko_fp       EKO record, FP kind, faults before its prologue; EKO only
//                  on purpose (a reader test, not compiler output)
// _sg_v2_fp        frame-pointer function that saves x19, x20 and d8; a udf
//                  before the prologue, after every prologue instruction,
//                  before and after every epilogue instruction. Its CFI
//                  states each step exactly (each store, each restore), and
//                  tools/eko2-gen.ts turns it into an EKO version 2 table
// _sg_v2_leaf      frameless function with 32 bytes of stack that saves
//                  x19, the same udf pattern
    .text
    .p2align 2
    .globl _sg_before
_sg_before:
    .cfi_startproc
    stp x29, x30, [sp, #-16]!
    .cfi_def_cfa_offset 16
    mov x29, sp
    .cfi_def_cfa w29, 16
    .cfi_offset w30, -8
    .cfi_offset w29, -16
    ldp x29, x30, [sp], #16
    ret
    .cfi_endproc

    .globl _sg_fault_first
_sg_fault_first:
    .cfi_startproc
    udf #0
    ret
    .cfi_endproc

    .p2align 2
    .globl _sg_frameless32
_sg_frameless32:
    .cfi_startproc
    sub sp, sp, #32
    .cfi_def_cfa_offset 32
    udf #1
    add sp, sp, #32
    ret
    .cfi_endproc

    .p2align 2
    .globl _sg_eko_fp
_sg_eko_fp:
    udf #2
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    ldp x29, x30, [sp], #16
    ret
Lsg_eko_end:

    .section __TEXT,__eko_unwind,regular,no_dead_strip
    .p2align 2
Lsg_chunk:
    .long 0x57554b45
    .byte 1
    .byte 1
    .short 1
    .long 1
    .long Lsg_chunk_end - Lsg_chunk
Lsg_r0:
    .long _sg_eko_fp - Lsg_r0
    .long Lsg_eko_end - _sg_eko_fp
    .long 0x00000001
    .long 0
Lsg_chunk_end:
    .text
    .p2align 2
    .globl _sg_v2_fp
_sg_v2_fp:
    .cfi_startproc
    udf #16
    stp x29, x30, [sp, #-48]!
    .cfi_def_cfa_offset 48
    .cfi_offset w30, -40
    .cfi_offset w29, -48
    udf #17
    stp x20, x19, [sp, #16]
    .cfi_offset w19, -24
    .cfi_offset w20, -32
    udf #18
    str d8, [sp, #32]
    .cfi_offset d8, -16
    udf #19
    mov x29, sp
    .cfi_def_cfa w29, 48
    udf #20
    mov x19, #0x1919
    mov x20, #0x2020
    fmov d8, x19
    udf #21
    .cfi_remember_state
    mov sp, x29
    .cfi_def_cfa wsp, 48
    udf #22
    ldr d8, [sp, #32]
    .cfi_restore d8
    udf #23
    ldp x20, x19, [sp, #16]
    .cfi_restore w19
    .cfi_restore w20
    udf #24
    ldp x29, x30, [sp], #48
    .cfi_def_cfa_offset 0
    .cfi_restore w29
    .cfi_restore w30
    udf #25
    ret
    .cfi_restore_state
    .cfi_endproc

    .p2align 2
    .globl _sg_v2_leaf
_sg_v2_leaf:
    .cfi_startproc
    udf #32
    sub sp, sp, #32
    .cfi_def_cfa_offset 32
    udf #33
    str x19, [sp, #16]
    .cfi_offset w19, -16
    udf #34
    mov x19, #0x3333
    udf #35
    ldr x19, [sp, #16]
    .cfi_restore w19
    udf #36
    add sp, sp, #32
    .cfi_def_cfa_offset 0
    udf #37
    ret
    .cfi_endproc
