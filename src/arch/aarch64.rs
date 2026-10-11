//! aarch64: Darwin (arm64, not arm64e) and Linux.
//!
//! Register file layout, shared with the assembly below (byte offsets):
//!   x0..x30   0..248
//!   sp        248
//!   pc        256
//!   d8..d15   264..328
//!   (pad)     328..336
//!
//! Only callee-saved state (x19..x29, sp, d8..d15) and the return address are
//! meaningful in a captured context; caller-saved slots are zeroed. x18 is the
//! Darwin platform register: it is never written by the restore sequence.

use crate::failure::{Failure, Result};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Regs {
    pub x: [usize; 31],
    pub sp: usize,
    pub pc: usize,
    pub d: [usize; 8],
    pad: usize,
}

pub const REGS_SIZE: usize = 336;
const _: () = assert!(core::mem::size_of::<Regs>() == REGS_SIZE);

/// DWARF column of the return address (x30, the link register).
pub const RA_COLUMN: u16 = 30;
/// DWARF number of the stack pointer.
pub const SP_COLUMN: u16 = 31;
/// DWARF number of the frame pointer.
pub const FP_COLUMN: u16 = 29;
/// The registers a personality routine passes to a landing pad.
pub const DATA_REG0: i32 = 0;
pub const DATA_REG1: i32 = 1;
/// Columns tracked by the CFI interpreter: x0..x30, sp, then d8..d15.
pub const COLUMNS: usize = 40;
/// Highest DWARF register a CFI program may name and still be parsed.
pub const MAX_DWARF_REG: u16 = 127;

/// The EKO table architecture code for this target.
pub const EKO_ARCH: u8 = 1;

/// Map a DWARF register number to a CFI column, or None when the register is
/// not tracked (caller-saved vector registers, which no unwind needs).
#[inline]
pub fn column(reg: u16) -> Option<usize> {
    match reg {
        0..=31 => Some(reg as usize),
        72..=79 => Some(32 + (reg as usize - 72)),
        _ => None,
    }
}

/// The DWARF register number of a column.
#[inline]
pub fn column_reg(col: usize) -> u16 {
    if col < 32 { col as u16 } else { 72 + (col as u16 - 32) }
}

impl Regs {
    pub const fn zeroed() -> Regs {
        Regs { x: [0; 31], sp: 0, pc: 0, d: [0; 8], pad: 0 }
    }

    pub fn get(&self, reg: u16) -> Result<usize> {
        match reg {
            0..=30 => Ok(self.x[reg as usize]),
            31 => Ok(self.sp),
            72..=79 => Ok(self.d[reg as usize - 72]),
            _ => Err(Failure::UnknownRegister),
        }
    }

    pub fn set(&mut self, reg: u16, value: usize) -> Result<()> {
        match reg {
            0..=30 => self.x[reg as usize] = value,
            31 => self.sp = value,
            72..=79 => self.d[reg as usize - 72] = value,
            _ => return Err(Failure::UnknownRegister),
        }
        Ok(())
    }

    #[inline]
    pub fn fp(&self) -> usize {
        self.x[29]
    }

    #[inline]
    pub fn lr(&self) -> usize {
        self.x[30]
    }

    /// Strip a pointer-authentication signature from a return address. On
    /// arm64 (not arm64e) and on Linux without PAC the high bits are already
    /// clear and this is the identity. User space addresses here fit in 48
    /// bits on both Darwin and Linux.
    #[inline]
    pub fn strip_pac(addr: usize) -> usize {
        addr & 0x0000_ffff_ffff_ffff
    }
}

/// Install a context: load the register file and branch to its pc. x16 and
/// x17 (the intra-procedure-call scratch registers) carry the context pointer
/// and the target; a landing pad does not read them.
#[inline(never)]
pub unsafe fn restore(regs: *const Regs) -> ! {
    unsafe {
        core::arch::asm!(
            "mov x16, x0",
            "ldp d8, d9, [x16, #264]",
            "ldp d10, d11, [x16, #280]",
            "ldp d12, d13, [x16, #296]",
            "ldp d14, d15, [x16, #312]",
            "ldr x17, [x16, #248]",
            "mov sp, x17",
            "ldp x2, x3, [x16, #16]",
            "ldp x4, x5, [x16, #32]",
            "ldp x6, x7, [x16, #48]",
            "ldp x8, x9, [x16, #64]",
            "ldp x10, x11, [x16, #80]",
            "ldp x12, x13, [x16, #96]",
            "ldp x14, x15, [x16, #112]",
            "ldp x19, x20, [x16, #152]",
            "ldp x21, x22, [x16, #168]",
            "ldp x23, x24, [x16, #184]",
            "ldp x25, x26, [x16, #200]",
            "ldp x27, x28, [x16, #216]",
            "ldp x29, x30, [x16, #232]",
            "ldr x17, [x16, #256]",
            "ldp x0, x1, [x16, #0]",
            "br x17",
            in("x0") regs,
            options(noreturn, nostack),
        )
    }
}

/// Capture the caller of a trampoline into a Regs block reserved on the
/// stack, then call `$impl` with the block address appended as the next
/// argument after `$nargs` original arguments. The captured pc is the return
/// address (x30) and the captured sp is the value the caller sees after the
/// call returns, so the first frame the walker sees is the caller itself:
/// the trampoline never needs unwind information of its own.
macro_rules! trampoline {
    ($name:ident, ($($arg:ident: $ty:ty),*) -> $ret:ty, $impl:path, $regs_reg:literal) => {
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C-unwind" fn $name($($arg: $ty),*) -> $ret {
            core::arch::naked_asm!(
                "sub sp, sp, #336",
                "stp xzr, xzr, [sp, #16]",
                "stp xzr, xzr, [sp, #32]",
                "stp xzr, xzr, [sp, #48]",
                "stp xzr, xzr, [sp, #64]",
                "stp xzr, xzr, [sp, #80]",
                "stp xzr, xzr, [sp, #96]",
                "stp xzr, xzr, [sp, #112]",
                "stp xzr, xzr, [sp, #128]",
                "stp xzr, xzr, [sp, #0]",
                "str x18, [sp, #144]",
                "stp x19, x20, [sp, #152]",
                "stp x21, x22, [sp, #168]",
                "stp x23, x24, [sp, #184]",
                "stp x25, x26, [sp, #200]",
                "stp x27, x28, [sp, #216]",
                "stp x29, x30, [sp, #232]",
                "add x9, sp, #336",
                "stp x9, x30, [sp, #248]",
                "stp d8, d9, [sp, #264]",
                "stp d10, d11, [sp, #280]",
                "stp d12, d13, [sp, #296]",
                "stp d14, d15, [sp, #312]",
                "str xzr, [sp, #328]",
                concat!("mov ", $regs_reg, ", sp"),
                "bl {f}",
                "ldr x30, [sp, #240]",
                "add sp, sp, #336",
                "ret",
                f = sym $impl,
            )
        }
    };
}

trampoline!(_Unwind_RaiseException, (exception: *mut crate::abi::UnwindException) -> crate::abi::Reason, crate::abi::raise_impl, "x1");
trampoline!(_Unwind_Resume, (exception: *mut crate::abi::UnwindException) -> (), crate::abi::resume_impl, "x1");
trampoline!(_Unwind_Backtrace, (trace: crate::abi::TraceFn, argument: *mut core::ffi::c_void) -> crate::abi::Reason, crate::abi::backtrace_impl, "x2");

impl Regs {
    #[inline]
    pub fn sp(&self) -> usize {
        self.sp
    }
    #[inline]
    pub fn set_sp(&mut self, v: usize) {
        self.sp = v;
    }
}

impl Regs {
    /// The interrupted state saved in the ucontext a SA_SIGINFO handler gets
    /// as its third argument. Callee-saved d8..d15 are the low halves of
    /// v8..v15.
    ///
    /// Darwin: `uc_mcontext` is a pointer at offset 48; the mcontext is
    /// `__es` (16 bytes), `__ss` (x0..x28, fp, lr, sp, pc, cpsr: 272 bytes),
    /// `__ns` (v0..v31, 16 bytes each) at 288.
    ///
    /// Linux: `uc_mcontext` (struct sigcontext) is inline at offset 176:
    /// fault_address, regs[31] at 8, sp at 256, pc at 264, pstate, then
    /// `__reserved` at 288 starting with the fpsimd_context (magic
    /// 0x46508001, size, fpsr, fpcr, vregs at +16). COMPILED, NOT RUN.
    pub unsafe fn from_ucontext(uc: usize) -> Regs {
        use crate::mem::load;
        let mut r = Regs { x: [0; 31], sp: 0, pc: 0, d: [0; 8], pad: 0 };
        #[cfg(target_vendor = "apple")]
        let (gp, sp, pc, v) = {
            let mc = unsafe { load::<usize>(uc + 48) };
            (mc + 16, mc + 16 + 31 * 8, mc + 16 + 32 * 8, Some(mc + 288))
        };
        #[cfg(target_os = "linux")]
        let (gp, sp, pc, v) = {
            let sc = uc + 176;
            let fpsimd = sc + 288;
            let v = (unsafe { load::<u32>(fpsimd) } == 0x4650_8001).then_some(fpsimd + 16);
            (sc + 8, sc + 256, sc + 264, v)
        };
        for i in 0..31 {
            r.x[i] = unsafe { load::<usize>(gp + 8 * i) };
        }
        r.sp = unsafe { load::<usize>(sp) };
        r.pc = Regs::strip_pac(unsafe { load::<usize>(pc) });
        if let Some(v) = v {
            for i in 0..8 {
                r.d[i] = unsafe { load::<usize>(v + 16 * (8 + i)) };
            }
        }
        r
    }

    /// Linux: `__kernel_rt_sigreturn` of the vDSO starts with
    /// `mov x8, #139; svc #0`. A frame whose pc is there is a signal frame:
    /// sp points at the rt_sigframe, siginfo (128 bytes) then the ucontext.
    /// libgcc (linux-unwind.h) and LLVM libunwind recognise it the same way.
    /// COMPILED, NOT RUN.
    #[cfg(target_os = "linux")]
    pub unsafe fn is_sigreturn(pc: usize) -> bool {
        use crate::mem::load;
        pc != 0
            && pc.is_multiple_of(4)
            && unsafe { load::<u32>(pc) } == 0xd280_1168
            && unsafe { load::<u32>(pc + 4) } == 0xd400_0001
    }

    #[cfg(target_os = "linux")]
    pub unsafe fn sigreturn_caller(&self) -> Regs {
        unsafe { Regs::from_ucontext(self.sp + 128) }
    }
}
