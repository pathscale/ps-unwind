// DW_CFA_GNU_args_size fixture (aarch64 Mach-O, tools/args-run.ts).
//
// _ax_args moves sp down by 32 bytes for an outgoing argument area before
// its call and records that with DW_CFA_GNU_args_size 32, the way an x86
// caller that pushes arguments does; the area is freed after the call
// returns. The CFA is x29 + 16, so stepping does not depend on sp. The
// escape is not a CFI op compact unwind can encode, so the assembler marks
// the function DWARF mode and the unwinder reads its FDE.
// The landing pad runs with sp as the unwinder installed it. It passes sp
// and x29 to _ax_landed: with args_size applied sp equals x29 (the area is
// popped, as after a normal return); without it sp is x29 - 32. Then it
// resumes the unwind with _Unwind_Resume.

    .text
    .p2align 2
    .globl _ax_args
_ax_args:
Lax_begin:
    .cfi_startproc
    .cfi_personality 155, _rust_eh_personality
    .cfi_lsda 16, Lax_lsda
    stp x29, x30, [sp, #-16]!
    .cfi_def_cfa_offset 16
    .cfi_offset 30, -8
    .cfi_offset 29, -16
    mov x29, sp
    .cfi_def_cfa w29, 16
    sub sp, sp, #32
    .cfi_escape 0x2e, 0x20
    mov x9, x0
    mov x0, sp
Lax_call:
    blr x9
Lax_ret:
    add sp, sp, #32
    .cfi_escape 0x2e, 0x00
    b Lax_out
Lax_pad:
    mov x1, sp
    mov x2, x29
    bl _ax_landed
    bl __Unwind_Resume
Lax_out:
    ldp x29, x30, [sp], #16
    .cfi_def_cfa sp, 0
    .cfi_restore 30
    .cfi_restore 29
    ret
Lax_end:
    .cfi_endproc

    .section __TEXT,__gcc_except_tab
    .p2align 2
Lax_lsda:
    .byte 0xff
    .byte 0xff
    .byte 0x01
    .uleb128 Lax_cs_end - Lax_cs_begin
Lax_cs_begin:
    .uleb128 0
    .uleb128 Lax_call - Lax_begin
    .uleb128 0
    .uleb128 0
    .uleb128 Lax_call - Lax_begin
    .uleb128 Lax_ret - Lax_call
    .uleb128 Lax_pad - Lax_begin
    .uleb128 0
    .uleb128 Lax_ret - Lax_begin
    .uleb128 Lax_end - Lax_ret
    .uleb128 0
    .uleb128 0
Lax_cs_end:
