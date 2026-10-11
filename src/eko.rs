//! Reader for the EKO compact unwind table, version 1 (docs/FORMAT.md).
//!
//! A section holds one or more chunks. Each chunk is one compiled object: a
//! 16-byte header, a sorted array of 16-byte function records, and the
//! handler tables of the functions that have landing pads.

use crate::abi::{self, Cursor, Reason, UnwindException};
use crate::arch::{self, Regs};
use crate::failure::{Failure, Result};
use crate::mem::load;

pub const MAGIC: u32 = 0x5755_4b45; // "EKUW" in little-endian byte order
pub const VERSION: u8 = 1;
pub const FLAG_RUST_PERSONALITY: u16 = 1;
pub const HEADER: usize = 16;
pub const RECORD: usize = 16;
pub const ROW: usize = 12;

pub const KIND_LEAF: u32 = 0;
pub const KIND_FP: u32 = 1;
pub const KIND_SP: u32 = 2;

pub const ACTION_CLEANUP: u32 = 0;
pub const ACTION_CATCH: u32 = 1;
pub const ACTION_TERMINATE: u32 = 2;

/// One decoded function record.
#[derive(Clone, Copy)]
pub struct Record {
    pub start: usize,
    pub end: usize,
    pub frame: u32,
    /// Absolute address of the handler table, 0 when the function has none.
    pub handlers: usize,
}

fn record_at(at: usize, chunk: usize) -> Record {
    let rel = unsafe { load::<i32>(at) } as isize;
    let len = unsafe { load::<u32>(at + 4) } as usize;
    let frame = unsafe { load::<u32>(at + 8) };
    let h = unsafe { load::<u32>(at + 12) } as usize;
    let start = (at as isize).wrapping_add(rel) as usize;
    Record { start, end: start.wrapping_add(len), frame, handlers: if h == 0 { 0 } else { chunk + h } }
}

/// Find the record covering `pc` in the section [section, section + len).
/// Returns Ok(None) when no chunk covers the pc, so the caller falls back to
/// the platform tables of the same image.
pub fn lookup(section: usize, len: usize, pc: usize) -> Result<Option<Record>> {
    let end = section + len;
    let mut chunk = section;
    while chunk + HEADER <= end {
        let magic = unsafe { load::<u32>(chunk) };
        if magic == 0 {
            // Linker padding between chunks is zero-filled and 4-aligned.
            chunk += 4;
            continue;
        }
        let version = unsafe { load::<u8>(chunk + 4) };
        let arch_code = unsafe { load::<u8>(chunk + 5) };
        let flags = unsafe { load::<u16>(chunk + 6) };
        let count = unsafe { load::<u32>(chunk + 8) } as usize;
        let size = unsafe { load::<u32>(chunk + 12) } as usize;
        if magic != MAGIC
            || version != VERSION
            || arch_code != arch::EKO_ARCH
            || flags != FLAG_RUST_PERSONALITY
            || size < HEADER + count * RECORD
            || !size.is_multiple_of(4)
            || chunk + size > end
        {
            return Err(Failure::BadEkoHeader);
        }
        if count != 0 {
            let first = record_at(chunk + HEADER, chunk);
            let last = record_at(chunk + HEADER + (count - 1) * RECORD, chunk);
            if first.start <= pc && pc < last.end
                && let Some(r) = search(chunk, count, pc)? {
                    return Ok(Some(r));
                }
        }
        chunk += size;
    }
    Ok(None)
}

fn search(chunk: usize, count: usize, pc: usize) -> Result<Option<Record>> {
    let at = |i: usize| chunk + HEADER + i * RECORD;
    let (mut lo, mut hi) = (0usize, count);
    // Last record whose start is <= pc.
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if record_at(at(mid), chunk).start <= pc { lo = mid } else { hi = mid }
    }
    let r = record_at(at(lo), chunk);
    // Local order check: the records either side must not overlap this one.
    if lo > 0 && record_at(at(lo - 1), chunk).end > r.start {
        return Err(Failure::EkoUnsorted);
    }
    if lo + 1 < count && record_at(at(lo + 1), chunk).start < r.end {
        return Err(Failure::EkoUnsorted);
    }
    if r.start <= pc && pc < r.end { Ok(Some(r)) } else { Ok(None) }
}

pub fn kind(frame: u32) -> u32 {
    frame & 3
}

fn mask(frame: u32) -> u32 {
    (frame >> 3) & 0x3_ffff
}

fn param(frame: u32) -> usize {
    (frame >> 21) as usize
}

/// DWARF register numbers of the callee-saved set, in mask-bit order.
#[cfg(target_arch = "aarch64")]
const SAVED: [u16; 18] = [19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 72, 73, 74, 75, 76, 77, 78, 79];
#[cfg(target_arch = "x86_64")]
const SAVED: [u16; 5] = [3, 12, 13, 14, 15];

/// Step a frame described by an EKO record.
pub fn step(frame: u32, regs: &Regs, first: bool) -> Result<Regs> {
    let mut next = *regs;
    let m = mask(frame);
    if m >> SAVED.len() != 0 {
        return Err(Failure::BadEkoRecord);
    }
    let n = m.count_ones() as usize;
    let order_ascending = frame & 4 != 0;
    let (cfa, base) = match kind(frame) {
        KIND_LEAF => {
            if m != 0 || !first {
                return Err(Failure::BadEkoRecord);
            }
            let x86 = if cfg!(target_arch = "x86_64") { 8 } else { 0 };
            (regs.sp() + x86 + 16 * param(frame), 0)
        }
        KIND_FP if first => return Err(Failure::EkoAsyncFrame),
        KIND_SP if first => return Err(Failure::EkoAsyncFrame),
        KIND_FP => {
            if param(frame) < 3 && n != 0 {
                return Err(Failure::BadEkoRecord);
            }
            let fp = regs.fp();
            if fp == 0 || !fp.is_multiple_of(8) {
                return Err(Failure::Misaligned);
            }
            (fp + 16, param(frame))
        }
        KIND_SP => (regs.sp() + 16 * param(frame), 2),
        _ => return Err(Failure::BadEkoRecord),
    };
    let mut k = 0usize;
    for (bit, &reg) in SAVED.iter().enumerate() {
        if m & (1 << bit) != 0 {
            let slot = if order_ascending { base + n - 1 - k } else { base + k };
            let value = unsafe { load::<usize>(cfa - 8 * slot) };
            next.set(reg, value)?;
            k += 1;
        }
    }
    let ra = match kind(frame) {
        KIND_LEAF if cfg!(target_arch = "aarch64") => regs.get(arch::RA_COLUMN)?,
        _ => unsafe { load::<usize>(cfa - 8) },
    };
    if kind(frame) == KIND_FP {
        next.set(arch::FP_COLUMN, unsafe { load::<usize>(cfa - 16) })?;
    }
    if cfg!(target_arch = "aarch64") {
        next.set(arch::RA_COLUMN, ra)?;
    }
    next.set_sp(cfa);
    next.pc = Regs::strip_pac(ra);
    Ok(next)
}

/// Find the handler row for a return address offset. Rows are sorted by
/// return offset and unique.
pub fn handler(table: usize, ret: u32) -> Result<Option<(u32, u32)>> {
    let count = unsafe { load::<u32>(table) } as usize;
    let row = |i: usize| -> (u32, u32, u32) {
        let at = table + 4 + i * ROW;
        unsafe { (load::<u32>(at), load::<u32>(at + 4), load::<u32>(at + 8)) }
    };
    let (mut lo, mut hi) = (0usize, count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let (r, pad, action) = row(mid);
        if r == ret {
            if (mid > 0 && row(mid - 1).0 >= r) || (mid + 1 < count && row(mid + 1).0 <= r) {
                return Err(Failure::EkoAmbiguousCallSite);
            }
            let valid = match action {
                ACTION_CLEANUP | ACTION_CATCH => pad != 0,
                ACTION_TERMINATE => pad == 0,
                _ => false,
            };
            if !valid {
                return Err(Failure::BadEkoRecord);
            }
            return Ok(Some((pad, action)));
        }
        if r < ret { lo = mid + 1 } else { hi = mid }
    }
    Ok(None)
}

/// The built-in personality for EKO frames. It reproduces rust_eh_personality
/// decision for decision (library/std/src/sys/personality/gcc.rs):
///   search phase: no row or cleanup -> continue; catch -> handler found;
///                 terminate -> fatal phase 1 error.
///   cleanup phase: no row -> continue; cleanup or catch -> install with
///                 data reg 0 = exception, data reg 1 = 0, pc = landing pad;
///                 terminate -> fatal phase 2 error.
/// A frame interrupted by a signal has no call site, so it has no row.
pub fn personality(actions: u32, exception: *mut UnwindException, cursor: &mut Cursor) -> Result<Reason> {
    let table = cursor.info.eko_handlers;
    let pc = cursor.regs.pc;
    let row = if cursor.ip_before_insn || table == 0 || pc < cursor.info.start {
        None
    } else {
        handler(table, (pc - cursor.info.start) as u32)?
    };
    if actions & abi::UA_SEARCH_PHASE != 0 {
        return Ok(match row {
            None | Some((_, ACTION_CLEANUP)) => abi::URC_CONTINUE_UNWIND,
            Some((_, ACTION_CATCH)) => abi::URC_HANDLER_FOUND,
            _ => abi::URC_FATAL_PHASE1_ERROR,
        });
    }
    Ok(match row {
        None => abi::URC_CONTINUE_UNWIND,
        Some((pad, ACTION_CLEANUP | ACTION_CATCH)) => {
            cursor.regs.set(arch::DATA_REG0 as u16, exception as usize)?;
            cursor.regs.set(arch::DATA_REG1 as u16, 0)?;
            cursor.regs.pc = cursor.info.start + pad as usize;
            abi::URC_INSTALL_CONTEXT
        }
        _ => abi::URC_FATAL_PHASE2_ERROR,
    })
}
