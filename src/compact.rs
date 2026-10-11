//! Apple compact unwind (`__TEXT,__unwind_info`) for arm64: the two-level
//! lookup (first-level index, regular and compressed second-level pages, the
//! LSDA index and the personality array) and the FRAME / FRAMELESS steps.
//! DWARF-mode entries hand off to the FDE they name in `__eh_frame`.

use crate::arch::Regs;
use crate::failure::{Failure, Result};
use crate::mem::{load, Reader};

pub const UNWIND_HAS_LSDA: u32 = 0x4000_0000;
pub const UNWIND_PERSONALITY_MASK: u32 = 0x3000_0000;
pub const MODE_MASK: u32 = 0x0f00_0000;
pub const MODE_FRAMELESS: u32 = 0x0200_0000;
pub const MODE_DWARF: u32 = 0x0300_0000;
pub const MODE_FRAME: u32 = 0x0400_0000;
pub const FRAMELESS_STACK_MASK: u32 = 0x00ff_f000;
pub const DWARF_OFFSET_MASK: u32 = 0x00ff_ffff;

/// What the table says about one function.
#[derive(Clone, Copy)]
pub struct Entry {
    pub start: usize,
    pub end: usize,
    pub encoding: u32,
    pub lsda: usize,
    pub personality: usize,
}

/// Look up `pc` (already adjusted for return addresses) in an image whose
/// mach header is at `mh` and whose `__unwind_info` is [ui, ui + len).
/// Returns None when the table has no entry for the pc.
pub fn lookup(mh: usize, ui: usize, len: usize, pc: usize) -> Result<Option<Entry>> {
    if pc < mh {
        return Ok(None);
    }
    let target = pc - mh;
    if target > u32::MAX as usize {
        return Ok(None);
    }
    let target = target as u32;
    let end = ui + len;
    let mut h = Reader { pos: ui, end };
    let version = h.u32()?;
    if version != 1 {
        return Err(Failure::BadUnwindInfo);
    }
    let common_off = h.u32()? as usize;
    let common_count = h.u32()? as usize;
    let pers_off = h.u32()? as usize;
    let pers_count = h.u32()? as usize;
    let index_off = h.u32()? as usize;
    let index_count = h.u32()? as usize;
    if index_count < 2 || ui + index_off + index_count * 12 > end {
        return Err(Failure::BadUnwindInfo);
    }
    let index = |i: usize| -> (u32, u32, u32) {
        let at = ui + index_off + i * 12;
        unsafe { (load::<u32>(at), load::<u32>(at + 4), load::<u32>(at + 8)) }
    };
    // The last first-level entry is a sentinel whose offset ends the text.
    if target < index(0).0 || target >= index(index_count - 1).0 {
        return Ok(None);
    }
    let (mut lo, mut hi) = (0usize, index_count - 1);
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if index(mid).0 <= target { lo = mid } else { hi = mid }
    }
    let (first_func, page_off, lsda_first) = index(lo);
    let (next_func, _, lsda_last) = index(lo + 1);
    if page_off == 0 {
        return Ok(None);
    }
    let page = ui + page_off as usize;
    if page + 8 > end {
        return Err(Failure::BadUnwindInfo);
    }
    let kind = unsafe { load::<u32>(page) };
    let (func_off, func_end, encoding) = match kind {
        2 => {
            let entry_off = unsafe { load::<u16>(page + 4) } as usize;
            let count = unsafe { load::<u16>(page + 6) } as usize;
            if count == 0 || page + entry_off + count * 8 > end {
                return Err(Failure::BadUnwindInfo);
            }
            let entry = |i: usize| -> (u32, u32) {
                let at = page + entry_off + i * 8;
                unsafe { (load::<u32>(at), load::<u32>(at + 4)) }
            };
            let i = last_le(count, target, |i| entry(i).0)?;
            let Some(i) = i else { return Ok(None) };
            let fend = if i + 1 < count { entry(i + 1).0 } else { next_func };
            (entry(i).0, fend, entry(i).1)
        }
        3 => {
            let entry_off = unsafe { load::<u16>(page + 4) } as usize;
            let count = unsafe { load::<u16>(page + 6) } as usize;
            let enc_off = unsafe { load::<u16>(page + 8) } as usize;
            let enc_count = unsafe { load::<u16>(page + 10) } as usize;
            if count == 0 || page + entry_off + count * 4 > end || page + enc_off + enc_count * 4 > end {
                return Err(Failure::BadUnwindInfo);
            }
            let raw = |i: usize| -> u32 { unsafe { load::<u32>(page + entry_off + i * 4) } };
            let off = |i: usize| -> u32 { first_func.wrapping_add(raw(i) & 0x00ff_ffff) };
            let i = last_le(count, target, off)?;
            let Some(i) = i else { return Ok(None) };
            let fend = if i + 1 < count { off(i + 1) } else { next_func };
            let ei = (raw(i) >> 24) as usize;
            let encoding = if ei < common_count {
                if ui + common_off + ei * 4 + 4 > end {
                    return Err(Failure::BadUnwindInfo);
                }
                unsafe { load::<u32>(ui + common_off + ei * 4) }
            } else {
                let local = ei - common_count;
                if local >= enc_count {
                    return Err(Failure::BadUnwindInfo);
                }
                unsafe { load::<u32>(page + enc_off + local * 4) }
            };
            (off(i), fend, encoding)
        }
        _ => return Err(Failure::BadUnwindInfo),
    };
    if target < func_off || target >= func_end {
        return Ok(None);
    }
    let mut entry = Entry {
        start: mh + func_off as usize,
        end: mh + func_end as usize,
        encoding,
        lsda: 0,
        personality: 0,
    };
    if encoding & UNWIND_HAS_LSDA != 0 {
        // LSDA index rows are {function offset, lsda offset}, sorted, and the
        // first-level entries bracket the rows that belong to this page.
        let lo_at = ui + lsda_first as usize;
        let count = ((lsda_last - lsda_first) / 8) as usize;
        if lo_at + count * 8 > end {
            return Err(Failure::BadUnwindInfo);
        }
        let row = |i: usize| -> (u32, u32) {
            let at = lo_at + i * 8;
            unsafe { (load::<u32>(at), load::<u32>(at + 4)) }
        };
        let mut found = false;
        let (mut a, mut b) = (0usize, count);
        while a < b {
            let mid = a + (b - a) / 2;
            let (f, l) = row(mid);
            if f == func_off {
                entry.lsda = mh + l as usize;
                found = true;
                break;
            }
            if f < func_off { a = mid + 1 } else { b = mid }
        }
        if !found {
            return Err(Failure::BadUnwindInfo);
        }
    }
    let p = ((encoding & UNWIND_PERSONALITY_MASK) >> 28) as usize;
    if p != 0 {
        if p > pers_count || ui + pers_off + p * 4 > end {
            return Err(Failure::BadUnwindInfo);
        }
        let got = unsafe { load::<u32>(ui + pers_off + (p - 1) * 4) } as usize;
        entry.personality = unsafe { load::<usize>(mh + got) };
    }
    Ok(Some(entry))
}

/// Index of the last element whose key is <= target, checking the keys it
/// passes are ordered.
fn last_le(count: usize, target: u32, key: impl Fn(usize) -> u32) -> Result<Option<usize>> {
    if key(0) > target {
        return Ok(None);
    }
    let (mut lo, mut hi) = (0usize, count);
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if key(mid) <= target { lo = mid } else { hi = mid }
    }
    if lo + 1 < count && key(lo + 1) < key(lo) {
        return Err(Failure::BadUnwindInfo);
    }
    Ok(Some(lo))
}

/// Pairs of callee-saved registers named by the low bits of an arm64 FRAME or
/// FRAMELESS encoding, in the order the linker lays them out.
const X_PAIRS: [(u32, usize); 5] = [(0x1, 19), (0x2, 21), (0x4, 23), (0x8, 25), (0x10, 27)];
const D_PAIRS: [(u32, usize); 4] = [(0x100, 0), (0x200, 2), (0x400, 4), (0x800, 6)];

fn restore_pairs(encoding: u32, mut loc: usize, next: &mut Regs) {
    for (bit, reg) in X_PAIRS {
        if encoding & bit != 0 {
            next.x[reg] = unsafe { load::<usize>(loc) };
            loc -= 8;
            next.x[reg + 1] = unsafe { load::<usize>(loc) };
            loc -= 8;
        }
    }
    for (bit, reg) in D_PAIRS {
        if encoding & bit != 0 {
            next.d[reg] = unsafe { load::<usize>(loc) };
            loc -= 8;
            next.d[reg + 1] = unsafe { load::<usize>(loc) };
            loc -= 8;
        }
    }
}

/// Step an arm64 frame described by a FRAME or FRAMELESS encoding.
/// `first` is true for the frame the walk started in or a frame interrupted
/// by a signal: only such a frame may be frameless, because a frameless
/// function keeps its return address in the link register.
pub fn step(encoding: u32, regs: &Regs, first: bool) -> Result<Regs> {
    let mut next = *regs;
    match encoding & MODE_MASK {
        MODE_FRAME => {
            let fp = regs.fp();
            if fp == 0 || !fp.is_multiple_of(8) {
                return Err(Failure::Misaligned);
            }
            restore_pairs(encoding, fp - 8, &mut next);
            next.x[29] = unsafe { load::<usize>(fp) };
            let ra = unsafe { load::<usize>(fp + 8) };
            next.x[30] = ra;
            next.sp = fp + 16;
            next.pc = Regs::strip_pac(ra);
            Ok(next)
        }
        MODE_FRAMELESS => {
            if !first {
                return Err(Failure::FramelessCaller);
            }
            let size = 16 * ((encoding & FRAMELESS_STACK_MASK) >> 12) as usize;
            let top = regs.sp + size;
            restore_pairs(encoding, top - 8, &mut next);
            next.sp = top;
            next.pc = Regs::strip_pac(regs.lr());
            Ok(next)
        }
        _ => Err(Failure::BadCompactEncoding),
    }
}
