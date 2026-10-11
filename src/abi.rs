//! The `_Unwind_*` boundary that Rust std (panic_unwind, the personality
//! routine and backtrace) is compiled against, and the two unwind phases.
//!
//! Exported: _Unwind_RaiseException, _Unwind_Resume, _Unwind_Backtrace (the
//! three entry trampolines in arch/), _Unwind_DeleteException, _Unwind_GetIP,
//! _Unwind_GetIPInfo, _Unwind_GetLanguageSpecificData, _Unwind_GetRegionStart,
//! _Unwind_SetGR, _Unwind_SetIP, _Unwind_GetDataRelBase,
//! _Unwind_GetTextRelBase, _Unwind_GetCFA and _Unwind_FindEnclosingFunction.

use core::ffi::{c_int, c_void};

use crate::arch::{self, Regs};
use crate::eko;
use crate::failure::{self, Failure, Result};
use crate::find;
use crate::frame::{FrameInfo, Kind};

pub type Reason = u32;
pub const URC_NO_REASON: Reason = 0;
pub const URC_FOREIGN_EXCEPTION_CAUGHT: Reason = 1;
pub const URC_FATAL_PHASE2_ERROR: Reason = 2;
pub const URC_FATAL_PHASE1_ERROR: Reason = 3;
pub const URC_END_OF_STACK: Reason = 5;
pub const URC_HANDLER_FOUND: Reason = 6;
pub const URC_INSTALL_CONTEXT: Reason = 7;
pub const URC_CONTINUE_UNWIND: Reason = 8;

pub type Action = u32;
pub const UA_SEARCH_PHASE: Action = 1;
pub const UA_CLEANUP_PHASE: Action = 2;
pub const UA_HANDLER_FRAME: Action = 4;

/// `struct _Unwind_Exception`: the class, the cleanup hook and two words
/// private to the unwinder. private_1 is 0 (no forced unwind is exported);
/// private_2 is the stack pointer of the frame phase one chose.
#[repr(C)]
pub struct UnwindException {
    pub exception_class: u64,
    pub exception_cleanup: Option<unsafe extern "C" fn(Reason, *mut UnwindException)>,
    pub private_1: usize,
    pub private_2: usize,
}

pub type Personality =
    unsafe extern "C" fn(c_int, Action, u64, *mut UnwindException, *mut Cursor) -> Reason;
pub type TraceFn = unsafe extern "C" fn(*mut Cursor, *mut c_void) -> Reason;

/// `struct _Unwind_Context`: the register state of one frame and what the
/// lookup found for it. Only ever lives on the stack of the thread unwinding.
#[repr(C)]
pub struct Cursor {
    pub regs: Regs,
    pub info: FrameInfo,
    /// The pc is the faulting instruction, not a return address: the frame
    /// below was a signal trampoline.
    pub ip_before_insn: bool,
}

impl Cursor {
    pub fn new(regs: Regs) -> Cursor {
        Cursor { regs, info: FrameInfo::EMPTY, ip_before_insn: false }
    }

    /// The address used to find the function: the return address minus one,
    /// so a call that is the last instruction of a function is attributed to
    /// that function and not to the next one.
    #[inline]
    pub fn lookup_pc(&self) -> usize {
        if self.ip_before_insn { self.regs.pc } else { self.regs.pc - 1 }
    }

    /// Find the tables for the current pc.
    pub fn lookup(&mut self) -> Result<()> {
        if self.regs.pc == 0 {
            return Err(Failure::ZeroPc);
        }
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        if unsafe { Regs::is_sigreturn(self.regs.pc) } {
            let pc = self.regs.pc;
            self.info = FrameInfo { start: pc, end: pc + 8, signal: true, kind: Kind::LinuxSigreturn, ..FrameInfo::EMPTY };
            return Ok(());
        }
        self.info = find::find(self.lookup_pc())?;
        Ok(())
    }

    /// Replace the register state with the caller state.
    pub fn step(&mut self) -> Result<()> {
        let async_frame = self.ip_before_insn;
        let next = match self.info.kind {
            #[cfg(target_vendor = "apple")]
            Kind::Compact(encoding) => crate::compact::step(encoding, &self.regs, async_frame)?,
            #[cfg(not(target_vendor = "apple"))]
            Kind::Compact(_) => return Err(Failure::BadCompactEncoding),
            Kind::Dwarf(fde) => {
                let row = crate::cfi::row_for(&fde, self.lookup_pc())?;
                crate::cfi::apply(&row, &self.regs, fde.cie.ra_reg)?
            }
            Kind::Eko(frame) => eko::step(frame, &self.regs, async_frame)?,
            Kind::Eko2 { program, limit } => eko::step2(program, limit, self.lookup_pc() - self.info.start, &self.regs)?,
            #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
            Kind::LinuxSigreturn => unsafe { self.regs.sigreturn_caller() },
        };
        if next.pc == 0 {
            return Err(Failure::ZeroPc);
        }
        let (old_sp, new_sp) = (self.regs.sp(), next.sp());
        if !self.info.signal && (new_sp < old_sp || (new_sp == old_sp && next.pc == self.regs.pc)) {
            return Err(Failure::StackNotAdvancing);
        }
        self.ip_before_insn = self.info.signal;
        self.regs = next;
        Ok(())
    }

    /// Run the frame personality, or the built-in EKO one.
    unsafe fn personality(&mut self, actions: Action, exception: *mut UnwindException) -> Result<Reason> {
        if self.info.eko_handlers != 0 {
            return eko::personality(actions, exception, self);
        }
        if self.info.personality == 0 {
            return Ok(URC_CONTINUE_UNWIND);
        }
        let f: Personality = unsafe { core::mem::transmute(self.info.personality) };
        let class = unsafe { (*exception).exception_class };
        Ok(unsafe { f(1, actions, class, exception, self) })
    }
}

fn fail(f: Failure, pc: usize, code: Reason) -> Reason {
    failure::record(f, pc);
    if f.is_end_of_stack() {
        URC_END_OF_STACK
    } else {
        failure::report(f, pc);
        code
    }
}

/// Phase one: walk a copy of the state to the frame that will catch.
unsafe fn search(exception: *mut UnwindException, regs: &Regs) -> Reason {
    let mut c = Cursor::new(*regs);
    loop {
        if let Err(f) = c.lookup() {
            return fail(f, c.regs.pc, URC_FATAL_PHASE1_ERROR);
        }
        if c.info.has_handler_logic() {
            match unsafe { c.personality(UA_SEARCH_PHASE, exception) } {
                Err(f) => return fail(f, c.regs.pc, URC_FATAL_PHASE1_ERROR),
                Ok(URC_HANDLER_FOUND) => {
                    unsafe {
                        (*exception).private_1 = 0;
                        (*exception).private_2 = c.regs.sp();
                    }
                    return URC_NO_REASON;
                }
                Ok(URC_CONTINUE_UNWIND) => {}
                Ok(_) => return URC_FATAL_PHASE1_ERROR,
            }
        }
        if let Err(f) = c.step() {
            return fail(f, c.regs.pc, URC_FATAL_PHASE1_ERROR);
        }
    }
}

/// Phase two: walk the real state, running cleanups, until a landing pad is
/// installed. Returns only on failure.
unsafe fn cleanup(exception: *mut UnwindException, regs: &Regs) -> Reason {
    let handler_sp = unsafe { (*exception).private_2 };
    let mut c = Cursor::new(*regs);
    loop {
        if let Err(f) = c.lookup() {
            return fail(f, c.regs.pc, URC_FATAL_PHASE2_ERROR);
        }
        let is_handler = c.regs.sp() == handler_sp;
        if c.info.has_handler_logic() {
            let actions = UA_CLEANUP_PHASE | if is_handler { UA_HANDLER_FRAME } else { 0 };
            match unsafe { c.personality(actions, exception) } {
                Err(f) => return fail(f, c.regs.pc, URC_FATAL_PHASE2_ERROR),
                Ok(URC_INSTALL_CONTEXT) => unsafe { arch::restore(&c.regs) },
                Ok(URC_CONTINUE_UNWIND) => {
                    if is_handler {
                        failure::report(Failure::HandlerFrameMissed, c.regs.pc);
                        failure::fatal(b"ps-unwind: phase two did not stop at the phase one handler\n");
                    }
                }
                Ok(_) => return URC_FATAL_PHASE2_ERROR,
            }
        } else if is_handler {
            failure::report(Failure::HandlerFrameMissed, c.regs.pc);
            failure::fatal(b"ps-unwind: the phase one handler frame has no personality\n");
        }
        if let Err(f) = c.step() {
            return fail(f, c.regs.pc, URC_FATAL_PHASE2_ERROR);
        }
    }
}

/// Body of `_Unwind_RaiseException`. `regs` is the state of its caller.
pub unsafe extern "C" fn raise_impl(exception: *mut UnwindException, regs: *mut Regs) -> Reason {
    let regs = unsafe { &*regs };
    let found = unsafe { search(exception, regs) };
    if found != URC_NO_REASON {
        return found;
    }
    unsafe { cleanup(exception, regs) }
}

/// Body of `_Unwind_Resume`, called at the end of a cleanup landing pad.
pub unsafe extern "C" fn resume_impl(exception: *mut UnwindException, regs: *mut Regs) {
    let regs = unsafe { &*regs };
    let _ = unsafe { cleanup(exception, regs) };
    failure::fatal(b"ps-unwind: _Unwind_Resume could not reach the handler\n")
}

/// Body of `_Unwind_Backtrace`. The first frame reported is the caller of
/// `_Unwind_Backtrace`, and a frame is reported only when tables describe it,
/// as in the platform unwinders. Any stop returns END_OF_STACK.
pub unsafe extern "C" fn backtrace_impl(trace: TraceFn, argument: *mut c_void, regs: *mut Regs) -> Reason {
    unsafe { walk(Cursor::new(*regs), trace, argument) }
}

/// Walk from the state a signal interrupted. `uc` is the third argument of
/// a SA_SIGINFO handler. The first frame is the interrupted instruction
/// itself (ip_before_insn = 1), so a frameless leaf and a fault at a
/// function first instruction are attributed correctly. Same callback and
/// result as `_Unwind_Backtrace`. Call ps_unwind_signal_enter first.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ps_unwind_backtrace_ucontext(uc: *const c_void, trace: TraceFn, argument: *mut c_void) -> Reason {
    if uc.is_null() {
        failure::record(Failure::ZeroPc, 0);
        return URC_END_OF_STACK;
    }
    let mut c = Cursor::new(unsafe { Regs::from_ucontext(uc as usize) });
    c.ip_before_insn = true;
    unsafe { walk(c, trace, argument) }
}

unsafe fn walk(mut c: Cursor, trace: TraceFn, argument: *mut c_void) -> Reason {
    loop {
        if let Err(f) = c.lookup() {
            failure::record(f, c.regs.pc);
            return URC_END_OF_STACK;
        }
        if unsafe { trace(&mut c, argument) } != URC_NO_REASON {
            return URC_END_OF_STACK;
        }
        if let Err(f) = c.step() {
            failure::record(f, c.regs.pc);
            return URC_END_OF_STACK;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _Unwind_DeleteException(exception: *mut UnwindException) {
    if let Some(cleanup) = unsafe { (*exception).exception_cleanup } {
        unsafe { cleanup(URC_FOREIGN_EXCEPTION_CAUGHT, exception) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _Unwind_GetIP(c: *mut Cursor) -> usize {
    unsafe { (*c).regs.pc }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _Unwind_GetIPInfo(c: *mut Cursor, ip_before_insn: *mut c_int) -> usize {
    unsafe {
        *ip_before_insn = c_int::from((*c).ip_before_insn);
        (*c).regs.pc
    }
}

/// The frame CFA as each platform unwinder defines it. Apple libunwind returns
/// the stack pointer of the frame; libgcc and LLVM libunwind on Linux return
/// the canonical frame address, which is the stack pointer of the caller at
/// the call. The Linux value is found by stepping a copy of the cursor; a frame
/// that cannot be stepped answers 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _Unwind_GetCFA(c: *mut Cursor) -> usize {
    #[cfg(target_vendor = "apple")]
    {
        unsafe { (*c).regs.sp() }
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        let c = unsafe { &*c };
        let mut copy = Cursor { regs: c.regs, info: c.info, ip_before_insn: c.ip_before_insn };
        match copy.step() {
            Ok(()) => copy.regs.sp(),
            Err(_) => 0,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _Unwind_GetLanguageSpecificData(c: *mut Cursor) -> *mut c_void {
    unsafe { (*c).info.lsda as *mut c_void }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _Unwind_GetRegionStart(c: *mut Cursor) -> usize {
    unsafe { (*c).info.start }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _Unwind_SetGR(c: *mut Cursor, index: c_int, value: usize) {
    if unsafe { (*c).regs.set(index as u16, value) }.is_err() {
        failure::report(Failure::UnknownRegister, index as usize);
        failure::fatal(b"ps-unwind: _Unwind_SetGR on an unknown register\n");
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _Unwind_SetIP(c: *mut Cursor, value: usize) {
    unsafe { (*c).regs.pc = value };
}

/// Start of the function containing `pc`, or null. Rust std imports this on
/// Linux (backtrace-rs symbol_address). libgcc looks up `pc - 1`; LLVM
/// libunwind (musl, Darwin) looks up `pc` itself; each target follows its
/// platform unwinder.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _Unwind_FindEnclosingFunction(pc: *mut c_void) -> *mut c_void {
    let pc = pc as usize;
    let target = if cfg!(all(target_os = "linux", target_env = "gnu")) { pc.wrapping_sub(1) } else { pc };
    match find::find(target) {
        Ok(info) => info.start as *mut c_void,
        Err(f) => {
            failure::record(f, pc);
            core::ptr::null_mut()
        }
    }
}

/// DW_EH_PE_datarel base. Zero on these targets, as in libgcc for aarch64 and
/// x86_64; Apple libunwind does not implement it at all. Rust LSDAs never use
/// datarel, so std never calls this in practice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _Unwind_GetDataRelBase(_c: *mut Cursor) -> usize {
    0
}

/// DW_EH_PE_textrel base. Zero, for the same reason as the datarel base.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _Unwind_GetTextRelBase(_c: *mut Cursor) -> usize {
    0
}

/// Crash handlers call this first. Until the matching
/// ps_unwind_signal_leave, image lookups never take the loader lock or
/// allocate: a pc the cache does not hold fails with SignalContextMiss.
#[unsafe(no_mangle)]
pub extern "C" fn ps_unwind_signal_enter() {
    crate::cache::signal_enter();
}

#[unsafe(no_mangle)]
pub extern "C" fn ps_unwind_signal_leave() {
    crate::cache::signal_leave();
}

/// The failure code (src/failure.rs) that ended the most recent walk, 0 for
/// none, and its pc through `pc` when not null. Lock-free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ps_unwind_last_failure(pc: *mut usize) -> u32 {
    match failure::last() {
        Some((f, at)) => {
            if !pc.is_null() {
                unsafe { *pc = at };
            }
            f as u32
        }
        None => 0,
    }
}

/// Cache counters for verifiers: entries, publishes, snapshots freed,
/// snapshots pending, readers now, signal depth. Writes six words to `out`.
/// Does not build the cache (so it shows what the constructor did). Takes
/// the writer lock: never from signal context.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ps_unwind_cache_stats(out: *mut usize) {
    let s = crate::cache::stats();
    for (i, v) in s.iter().enumerate() {
        unsafe { *out.add(i) = *v };
    }
}
