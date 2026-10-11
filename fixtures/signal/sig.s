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
