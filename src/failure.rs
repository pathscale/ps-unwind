//! Named failures. Every frame the unwinder cannot step is one of these, never
//! a guess. The most recent one is kept in two atomics so a crash handler or a
//! fixture can read it back without allocating.

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// No loaded image contains the pc. On Darwin and Linux this is how the
    /// bottom of a stack looks, so it ends a walk as end-of-stack.
    NoImage = 1,
    /// The image has tables, but none covers the pc (compact encoding 0, no FDE).
    /// Also end-of-stack, matching the platform unwinders.
    NoUnwindInfo = 2,
    /// The pc of the next frame is zero.
    ZeroPc = 3,
    /// An FDE was selected but its [start, start + range) does not contain the pc.
    FdeRangeMiss = 4,
    /// A CIE or FDE header is malformed (bad id, length, version).
    BadCieFde = 5,
    /// A CIE augmentation string has a letter this reader does not know.
    UnknownAugmentation = 6,
    /// A DW_EH_PE pointer encoding this reader does not accept.
    BadPointerEncoding = 7,
    /// A DW_CFA opcode this reader does not implement.
    UnsupportedCfa = 8,
    /// A DW_OP opcode this reader does not implement, or a stack fault.
    UnsupportedDwarfOp = 9,
    /// DW_CFA_remember_state nested deeper than the fixed stack.
    RememberStackOverflow = 10,
    /// A register rule names a register the context does not carry.
    UnknownRegister = 11,
    /// The CFA rule is missing or not computable.
    BadCfaRule = 12,
    /// A compact unwind encoding this reader does not accept.
    BadCompactEncoding = 13,
    /// __unwind_info is malformed (version, page kind, bounds).
    BadUnwindInfo = 14,
    /// A frameless compact frame was reached as a caller (it cannot be one).
    FramelessCaller = 15,
    /// The decoded personality routine does not point into a loaded image.
    PersonalityNotCode = 16,
    /// An EKO table header has the wrong magic, version or architecture.
    BadEkoHeader = 17,
    /// An EKO record is malformed (reserved kind, overlapping save slots).
    BadEkoRecord = 18,
    /// EKO records are not sorted, or a handler table is not sorted.
    EkoUnsorted = 19,
    /// The new stack pointer did not move towards the stack base.
    StackNotAdvancing = 20,
    /// The personality routine returned a code the protocol does not allow.
    BadPersonalityResult = 21,
    /// Phase two passed the frame phase one chose without stopping there.
    HandlerFrameMissed = 22,
    /// A pointer that must be aligned is not.
    Misaligned = 23,
    /// An EKO handler lookup found more than one row for one return address.
    EkoAmbiguousCallSite = 24,
    /// An FP or SP kind EKO record was asked to step a frame interrupted at an
    /// arbitrary instruction. Those kinds describe call sites only.
    EkoAsyncFrame = 25,
    /// In signal context (between ps_unwind_signal_enter and
    /// ps_unwind_signal_leave) the image cache has no image for the pc, or
    /// has not been built yet. Filling it takes the loader lock and
    /// allocates, so it is refused instead (docs/DESIGN.md, "Image cache").
    SignalContextMiss = 26,
}

const NAMES: [&str; 27] = [
    "None",
    "NoImage",
    "NoUnwindInfo",
    "ZeroPc",
    "FdeRangeMiss",
    "BadCieFde",
    "UnknownAugmentation",
    "BadPointerEncoding",
    "UnsupportedCfa",
    "UnsupportedDwarfOp",
    "RememberStackOverflow",
    "UnknownRegister",
    "BadCfaRule",
    "BadCompactEncoding",
    "BadUnwindInfo",
    "FramelessCaller",
    "PersonalityNotCode",
    "BadEkoHeader",
    "BadEkoRecord",
    "EkoUnsorted",
    "StackNotAdvancing",
    "BadPersonalityResult",
    "HandlerFrameMissed",
    "Misaligned",
    "EkoAmbiguousCallSite",
    "EkoAsyncFrame",
    "SignalContextMiss",
];

const ALL: [Failure; 26] = [
    Failure::NoImage,
    Failure::NoUnwindInfo,
    Failure::ZeroPc,
    Failure::FdeRangeMiss,
    Failure::BadCieFde,
    Failure::UnknownAugmentation,
    Failure::BadPointerEncoding,
    Failure::UnsupportedCfa,
    Failure::UnsupportedDwarfOp,
    Failure::RememberStackOverflow,
    Failure::UnknownRegister,
    Failure::BadCfaRule,
    Failure::BadCompactEncoding,
    Failure::BadUnwindInfo,
    Failure::FramelessCaller,
    Failure::PersonalityNotCode,
    Failure::BadEkoHeader,
    Failure::BadEkoRecord,
    Failure::EkoUnsorted,
    Failure::StackNotAdvancing,
    Failure::BadPersonalityResult,
    Failure::HandlerFrameMissed,
    Failure::Misaligned,
    Failure::EkoAmbiguousCallSite,
    Failure::EkoAsyncFrame,
    Failure::SignalContextMiss,
];

impl Failure {
    pub fn name(self) -> &'static str {
        NAMES[self as usize]
    }

    /// Failures that mean "this is the bottom of the stack" to the platform
    /// unwinders. Everything else is a fatal, named error.
    pub const fn is_end_of_stack(self) -> bool {
        matches!(self, Failure::NoImage | Failure::NoUnwindInfo | Failure::ZeroPc)
    }

    pub fn from_code(code: u32) -> Option<Failure> {
        if code == 0 || code as usize > ALL.len() {
            None
        } else {
            Some(ALL[code as usize - 1])
        }
    }
}

pub type Result<T> = core::result::Result<T, Failure>;

static LAST_CODE: AtomicU32 = AtomicU32::new(0);
static LAST_PC: AtomicUsize = AtomicUsize::new(0);

/// Remember why the most recent walk stopped. Lock-free and signal-safe.
pub fn record(failure: Failure, pc: usize) {
    LAST_PC.store(pc, Ordering::Relaxed);
    LAST_CODE.store(failure as u32, Ordering::Release);
}

/// The reason the most recent walk stopped, and the pc it stopped at.
pub fn last() -> Option<(Failure, usize)> {
    let code = LAST_CODE.load(Ordering::Acquire);
    Failure::from_code(code).map(|f| (f, LAST_PC.load(Ordering::Relaxed)))
}

/// Write a named failure to stderr with write(2) only. Used when a failure is
/// about to be returned as a fatal reason code, so a run that dies says why.
pub fn report(failure: Failure, pc: usize) {
    let mut buf = [0u8; 96];
    let mut n = 0;
    for part in [b"ps-unwind: ".as_slice(), failure.name().as_bytes(), b" pc=0x".as_slice()] {
        for &b in part {
            buf[n] = b;
            n += 1;
        }
    }
    n += hex(pc, &mut buf[n..]);
    buf[n] = 10;
    n += 1;
    write_stderr(&buf[..n]);
}

/// Lower-case hex without leading zeros. Returns the number of bytes written.
pub fn hex(value: usize, out: &mut [u8]) -> usize {
    let mut n = 0;
    let mut shift = (usize::BITS - 4) as i32;
    let mut started = false;
    while shift >= 0 {
        let nib = (value >> shift) & 0xf;
        if nib != 0 || started || shift == 0 {
            started = true;
            out[n] = b"0123456789abcdef"[nib];
            n += 1;
        }
        shift -= 4;
    }
    n
}

pub fn write_stderr(bytes: &[u8]) {
    unsafe {
        libc::write(2, bytes.as_ptr().cast(), bytes.len());
    }
}

/// Print a fixed message and abort. Never unwinds.
pub fn fatal(message: &[u8]) -> ! {
    write_stderr(message);
    unsafe { libc::abort() }
}
