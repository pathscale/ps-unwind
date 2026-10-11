//! The record kinds a frame can be described by, and what a lookup returns.

use crate::cfi::Fde;

#[derive(Clone, Copy)]
pub enum Kind {
    /// An Apple compact encoding in FRAME or FRAMELESS mode.
    Compact(u32),
    /// A DWARF FDE (directly, or named by a compact DWARF-mode entry).
    Dwarf(Fde),
    /// An EKO record frame word.
    Eko(u32),
    /// aarch64 Linux `__kernel_rt_sigreturn`, recognised by its code: the
    /// caller state is the ucontext of the rt_sigframe at sp.
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    LinuxSigreturn,
}

/// Everything the unwinder knows about the function that owns a pc.
#[derive(Clone, Copy)]
pub struct FrameInfo {
    pub start: usize,
    pub end: usize,
    pub lsda: usize,
    pub personality: usize,
    /// Address of the EKO handler table, 0 when there is none.
    pub eko_handlers: usize,
    /// The CIE marks this function as a signal trampoline (augmentation S).
    pub signal: bool,
    pub kind: Kind,
    pub text_base: usize,
    pub data_base: usize,
}

impl FrameInfo {
    pub const EMPTY: FrameInfo = FrameInfo {
        start: 0,
        end: 0,
        lsda: 0,
        personality: 0,
        eko_handlers: 0,
        signal: false,
        kind: Kind::Eko(0),
        text_base: 0,
        data_base: 0,
    };

    /// True when this frame has something to call during an unwind phase:
    /// a personality routine, or an EKO handler table.
    pub fn has_handler_logic(&self) -> bool {
        self.personality != 0 || self.eko_handlers != 0
    }

    pub fn from_fde(fde: &Fde, text_base: usize, data_base: usize) -> FrameInfo {
        FrameInfo {
            start: fde.start,
            end: fde.end,
            lsda: fde.lsda,
            personality: fde.cie.personality,
            eko_handlers: 0,
            signal: fde.cie.signal,
            kind: Kind::Dwarf(*fde),
            text_base,
            data_base,
        }
    }
}
