// An EKO function the way a compiler must emit it on Darwin: the EKO record
// AND the standard CFI (compact unwind via .cfi) AND the LSDA.
// tools/check-darwin-tables.ts D1/D2 pass on it.
    .text
    .globl _dt_eko
    .p2align 2
_dt_eko:
    .cfi_startproc
    .cfi_personality 155, _rust_eh_personality
    .cfi_lsda 16, Ldt_lsda
    stp x29, x30, [sp, #-16]!
    .cfi_def_cfa_offset 16
    .cfi_offset w30, -8
    .cfi_offset w29, -16
    mov x29, sp
    .cfi_def_cfa w29, 16
Ldt_call:
    bl _dt_callee
Ldt_ret:
    ldp x29, x30, [sp], #16
    ret
Ldt_pad:
    ldp x29, x30, [sp], #16
    ret
Ldt_end:
    .cfi_endproc

    .globl _dt_callee
    .p2align 2
_dt_callee:
    .cfi_startproc
    ret
    .cfi_endproc

    .section __TEXT,__gcc_except_tab
    .p2align 2
Ldt_lsda:
    .byte 0xff
    .byte 0xff
    .byte 0x01
    .uleb128 Ldt_cs_end - Ldt_cs
Ldt_cs:
    .uleb128 Ldt_call - _dt_eko
    .uleb128 Ldt_ret - Ldt_call
    .uleb128 Ldt_pad - _dt_eko
    .byte 0
Ldt_cs_end:

// EKO chunk: one record, FP kind, no saves, one cleanup row.
    .section __TEXT,__eko_unwind,regular,no_dead_strip
    .p2align 2
Ldt_chunk:
    .long 0x57554b45
    .byte 1
    .byte 1
    .short 1
    .long 1
    .long Ldt_chunk_end - Ldt_chunk
Ldt_r0:
    .long _dt_eko - Ldt_r0
    .long Ldt_end - _dt_eko
    .long 0x00000001
    .long Ldt_h0 - Ldt_chunk
Ldt_h0:
    .long 1
    .long Ldt_ret - _dt_eko, Ldt_pad - _dt_eko, 0
Ldt_chunk_end:
