//! x86_64: Linux (System V). Compiled here, not run: see docs/TARGETS.md.
//!
//! Register file layout in DWARF order, shared with the assembly below:
//!   rax rdx rcx rbx rsi rdi rbp rsp r8..r15   0..128
//!   rip                                       128
//! DWARF numbers 0..15 are these registers, 16 is the return address column.

use crate::failure::{Failure, Result};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Regs {
    pub r: [usize; 16],
    pub pc: usize,
}

pub const REGS_SIZE: usize = 136;
const _: () = assert!(core::mem::size_of::<Regs>() == REGS_SIZE);

pub const RA_COLUMN: u16 = 16;
pub const SP_COLUMN: u16 = 7;
pub const FP_COLUMN: u16 = 6;
pub const DATA_REG0: i32 = 0;
pub const DATA_REG1: i32 = 1;
pub const COLUMNS: usize = 17;
pub const MAX_DWARF_REG: u16 = 127;
pub const EKO_ARCH: u8 = 2;

#[inline]
pub fn column(reg: u16) -> Option<usize> {
    if reg <= 16 { Some(reg as usize) } else { None }
}

#[inline]
pub fn column_reg(col: usize) -> u16 {
    col as u16
}

impl Regs {
    pub const fn zeroed() -> Regs {
        Regs { r: [0; 16], pc: 0 }
    }

    pub fn get(&self, reg: u16) -> Result<usize> {
        match reg {
            0..=15 => Ok(self.r[reg as usize]),
            16 => Ok(self.pc),
            _ => Err(Failure::UnknownRegister),
        }
    }

    pub fn set(&mut self, reg: u16, value: usize) -> Result<()> {
        match reg {
            0..=15 => self.r[reg as usize] = value,
            16 => self.pc = value,
            _ => return Err(Failure::UnknownRegister),
        }
        Ok(())
    }

    #[inline]
    pub fn fp(&self) -> usize {
        self.r[6]
    }

    #[inline]
    pub fn strip_pac(addr: usize) -> usize {
        addr
    }
}

impl Regs {
    #[inline]
    pub fn sp(&self) -> usize {
        self.r[7]
    }
    #[inline]
    pub fn set_sp(&mut self, v: usize) {
        self.r[7] = v;
    }
}

/// Install a context. rip is written just below the target rsp and popped
/// with ret, the same way the System V unwinders do it.
#[inline(never)]
pub unsafe fn restore(regs: *const Regs) -> ! {
    unsafe {
        core::arch::asm!(
            "mov rax, [rdi + 0]",
            "mov rdx, [rdi + 8]",
            "mov rcx, [rdi + 16]",
            "mov rbx, [rdi + 24]",
            "mov rsi, [rdi + 32]",
            "mov rbp, [rdi + 48]",
            "mov r8, [rdi + 64]",
            "mov r9, [rdi + 72]",
            "mov r10, [rdi + 80]",
            "mov r11, [rdi + 88]",
            "mov r12, [rdi + 96]",
            "mov r13, [rdi + 104]",
            "mov r14, [rdi + 112]",
            "mov r15, [rdi + 120]",
            "mov rsp, [rdi + 56]",
            "push qword ptr [rdi + 128]",
            "mov rdi, [rdi + 40]",
            "ret",
            in("rdi") regs,
            options(noreturn),
        )
    }
}

macro_rules! trampoline {
    ($name:ident, ($($arg:ident: $ty:ty),*) -> $ret:ty, $impl:path, $regs_reg:literal) => {
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C-unwind" fn $name($($arg: $ty),*) -> $ret {
            core::arch::naked_asm!(
                "sub rsp, 136",
                "mov qword ptr [rsp + 0], 0",
                "mov qword ptr [rsp + 8], 0",
                "mov qword ptr [rsp + 16], 0",
                "mov [rsp + 24], rbx",
                "mov qword ptr [rsp + 32], 0",
                "mov qword ptr [rsp + 40], 0",
                "mov [rsp + 48], rbp",
                "lea r11, [rsp + 144]",
                "mov [rsp + 56], r11",
                "mov qword ptr [rsp + 64], 0",
                "mov qword ptr [rsp + 72], 0",
                "mov qword ptr [rsp + 80], 0",
                "mov qword ptr [rsp + 88], 0",
                "mov [rsp + 96], r12",
                "mov [rsp + 104], r13",
                "mov [rsp + 112], r14",
                "mov [rsp + 120], r15",
                "mov r11, [rsp + 136]",
                "mov [rsp + 128], r11",
                concat!("mov ", $regs_reg, ", rsp"),
                "call {f}",
                "add rsp, 136",
                "ret",
                f = sym $impl,
            )
        }
    };
}

trampoline!(_Unwind_RaiseException, (exception: *mut crate::abi::UnwindException) -> crate::abi::Reason, crate::abi::raise_impl, "rsi");
trampoline!(_Unwind_Resume, (exception: *mut crate::abi::UnwindException) -> (), crate::abi::resume_impl, "rsi");
trampoline!(_Unwind_Backtrace, (trace: crate::abi::TraceFn, argument: *mut core::ffi::c_void) -> crate::abi::Reason, crate::abi::backtrace_impl, "rdx");

impl Regs {
    /// Linux: the interrupted state in a SA_SIGINFO ucontext. gregs start at
    /// offset 40 in the order r8..r15, rdi, rsi, rbp, rbx, rdx, rax, rcx,
    /// rsp, rip. COMPILED, NOT RUN.
    pub unsafe fn from_ucontext(uc: usize) -> Regs {
        use crate::mem::load;
        let g = |i: usize| unsafe { load::<usize>(uc + 40 + 8 * i) };
        let mut r = Regs { r: [0; 16], pc: g(16) };
        // DWARF order: rax rdx rcx rbx rsi rdi rbp rsp r8..r15
        let from = [13, 12, 14, 11, 9, 8, 10, 15];
        for (dw, &gi) in from.iter().enumerate() {
            r.r[dw] = g(gi);
        }
        for i in 0..8 {
            r.r[8 + i] = g(i);
        }
        r
    }
}
