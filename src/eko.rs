//! Reader for the EKO compact unwind table, versions 1 and 2 (docs/FORMAT.md).
//!
//! A section holds one or more chunks. Each chunk is one compiled object: a
//! 16-byte header, a sorted array of function records, and per-function data.
//!
//! Version 1: 16-byte records with a frame word that describes the frame at
//! its call sites only, and handler tables of 12-byte rows.
//!
//! Version 2: 12-byte records pointing at a state program that gives the
//! unwind state (CFA, return address, saved registers) at every instruction,
//! followed by a compact handler table when the function has landing pads.

use crate::abi::{self, Cursor, Reason, UnwindException};
use crate::arch::{self, Regs};
use crate::failure::{Failure, Result};
use crate::frame::Kind;
use crate::mem::load;

pub const MAGIC: u32 = 0x5755_4b45; // "EKUW" in little-endian byte order
pub const VERSION: u8 = 1;
pub const FLAG_RUST_PERSONALITY: u16 = 1;
pub const HEADER: usize = 16;
pub const RECORD: usize = 16;
pub const ROW: usize = 12;
pub const VERSION2: u8 = 2;
pub const RECORD2: usize = 12;
/// Version 2 record data word, bit 31: a handler table follows the program.
pub const DATA_HANDLERS: u32 = 1 << 31;

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
    /// Version 2: the address of the state program the table follows.
    pub handlers: usize,
    /// Version 2: absolute address of the state program, 0 when the entry
    /// state holds at every instruction. Version 1: 0.
    pub program: usize,
    /// Version 2: end of the chunk; no program or table byte is read at or
    /// past it. Version 1: 0.
    pub limit: usize,
    pub version: u8,
}

impl Record {
    /// The frame kind a lookup reports for this record.
    pub fn kind(&self) -> Kind {
        if self.version == VERSION2 {
            Kind::Eko2 { program: self.program, limit: self.limit }
        } else {
            Kind::Eko(self.frame)
        }
    }
}

fn record_at(at: usize, chunk: usize) -> Record {
    let rel = unsafe { load::<i32>(at) } as isize;
    let len = unsafe { load::<u32>(at + 4) } as usize;
    let frame = unsafe { load::<u32>(at + 8) };
    let h = unsafe { load::<u32>(at + 12) } as usize;
    let start = (at as isize).wrapping_add(rel) as usize;
    Record { start, end: start.wrapping_add(len), frame, handlers: if h == 0 { 0 } else { chunk + h }, program: 0, limit: 0, version: VERSION }
}

/// Find the record covering `pc` in the section [section, section + len).
/// Returns Ok(None) when no chunk covers the pc, so the caller falls back to
/// the platform tables of the same image.
pub fn lookup(section: usize, len: usize, pc: usize) -> Result<Option<Record>> {
    lookup_arch(section, len, pc, arch::EKO_ARCH)
}

/// `lookup` for chunks of architecture code `want`. The unwinder only asks
/// for its own; tools/eko-dump.rs reads the tables of either architecture.
pub fn lookup_arch(section: usize, len: usize, pc: usize, want: u8) -> Result<Option<Record>> {
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
        let stride = match version {
            VERSION => RECORD,
            VERSION2 => RECORD2,
            _ => 0,
        };
        if magic != MAGIC
            || stride == 0
            || arch_code != want
            || flags != FLAG_RUST_PERSONALITY
            || size < HEADER + count * stride
            || !size.is_multiple_of(4)
            || chunk + size > end
        {
            return Err(Failure::BadEkoHeader);
        }
        if count != 0 {
            let limit = chunk + size;
            let rec = |i: usize| {
                let at = chunk + HEADER + i * stride;
                if version == VERSION { record_at(at, chunk) } else { record_at2(at, chunk, limit) }
            };
            let first = rec(0);
            let last = rec(count - 1);
            if first.start <= pc && pc < last.end
                && let Some(r) = search(&rec, count, pc)? {
                    if r.version == VERSION2 && ((r.handlers != 0 && r.program == 0) || r.program >= limit) {
                        return Err(Failure::BadEkoRecord);
                    }
                    return Ok(Some(r));
                }
        }
        chunk += size;
    }
    Ok(None)
}

fn search(rec: &impl Fn(usize) -> Record, count: usize, pc: usize) -> Result<Option<Record>> {
    let (mut lo, mut hi) = (0usize, count);
    // Last record whose start is <= pc.
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if rec(mid).start <= pc { lo = mid } else { hi = mid }
    }
    let r = rec(lo);
    // Local order check: the records either side must not overlap this one.
    if lo > 0 && rec(lo - 1).end > r.start {
        return Err(Failure::EkoUnsorted);
    }
    if lo + 1 < count && rec(lo + 1).start < r.end {
        return Err(Failure::EkoUnsorted);
    }
    if r.start <= pc && pc < r.end { Ok(Some(r)) } else { Ok(None) }
}

/// Version 2 record: i32 start (relative to the field), u32 length, u32 data
/// (bits 0-30 offset of the state program from the chunk start, 0 = none;
/// bit 31 = a handler table follows the program).
fn record_at2(at: usize, chunk: usize, limit: usize) -> Record {
    let rel = unsafe { load::<i32>(at) } as isize;
    let len = unsafe { load::<u32>(at + 4) } as usize;
    let data = unsafe { load::<u32>(at + 8) };
    let start = (at as isize).wrapping_add(rel) as usize;
    let off = (data & !DATA_HANDLERS) as usize;
    let program = if off == 0 { 0 } else { chunk + off };
    let handlers = if data & DATA_HANDLERS != 0 { chunk + off } else { 0 };
    Record { start, end: start.wrapping_add(len), frame: 0, handlers, program, limit, version: VERSION2 }
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
/// Installing a pad goes through Cursor::set_landing_ip_for, as
/// _Unwind_SetIP does: a version 2 frame pops its DW_CFA_GNU_args_size.
pub fn personality(actions: u32, exception: *mut UnwindException, cursor: &mut Cursor) -> Result<Reason> {
    personality_for(&HOST, actions, exception, cursor)
}

/// `personality` reading version 2 programs of architecture `a`
/// (tools/landing-sp.rs reads x86_64 tables on any host).
pub fn personality_for(a: &Arch2, actions: u32, exception: *mut UnwindException, cursor: &mut Cursor) -> Result<Reason> {
    let table = cursor.info.eko_handlers;
    let pc = cursor.regs.pc;
    let row = if cursor.ip_before_insn || table == 0 || pc < cursor.info.start {
        None
    } else if let Kind::Eko2 { program, limit } = cursor.info.kind {
        let (_, after) = run(a, program, limit, usize::MAX)?;
        handler2(after, limit, (pc - cursor.info.start) as u32)?
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
            cursor.set_landing_ip_for(a, cursor.info.start + pad as usize)?;
            abi::URC_INSTALL_CONTEXT
        }
        _ => abi::URC_FATAL_PHASE2_ERROR,
    })
}

// ---------------------------------------------------------------------------
// Version 2: the unwind state at every instruction.

/// What a version 2 program means on one architecture: the code unit an
/// ADVANCE counts in, the DWARF numbers of the stack pointer, frame pointer
/// and return address column, and the entry state (the state at the first
/// instruction, before the function has done anything). Both architectures
/// are defined on every target, so a host can read the tables of either.
#[derive(Clone, Copy)]
pub struct Arch2 {
    pub code: u8,
    pub unit: usize,
    pub sp: u16,
    pub fp: u16,
    pub ra: u16,
    /// CFA at entry = SP + 8 * entry_cfa.
    pub entry_cfa: u32,
    /// Return address at entry: 0 = still in register `ra`, else in that slot.
    pub entry_ra_slot: u16,
}

pub const AARCH64: Arch2 = Arch2 { code: 1, unit: 4, sp: 31, fp: 29, ra: 30, entry_cfa: 0, entry_ra_slot: 0 };
pub const X86_64: Arch2 = Arch2 { code: 2, unit: 1, sp: 7, fp: 6, ra: 16, entry_cfa: 1, entry_ra_slot: 1 };

#[cfg(target_arch = "aarch64")]
pub const HOST: Arch2 = AARCH64;
#[cfg(target_arch = "x86_64")]
pub const HOST: Arch2 = X86_64;

pub fn arch2(code: u8) -> Option<Arch2> {
    match code {
        1 => Some(AARCH64),
        2 => Some(X86_64),
        _ => None,
    }
}

/// Op codes of a version 2 state program (docs/FORMAT.md, "Version 2").
pub mod op {
    pub const END: u8 = 0x00;
    /// 0x01..=0x3f: ADVANCE n code units.
    pub const ADVANCE: u8 = 0x00;
    /// 0x40..=0x7f: CFA = current base + 8 * n.
    pub const CFA_OFFSET: u8 = 0x40;
    /// 0x80..=0xbf: register n (DWARF) is saved at CFA - 8 * uleb slot.
    pub const SAVE: u8 = 0x80;
    pub const CFA_SP: u8 = 0xc0;
    pub const CFA_FP: u8 = 0xc1;
    pub const CFA_OFFSET_LONG: u8 = 0xc2;
    pub const ADVANCE_LONG: u8 = 0xc3;
    pub const SAVE_LONG: u8 = 0xc4;
    pub const RESTORE_LONG: u8 = 0xc5;
    pub const ENTRY: u8 = 0xc6;
    pub const REMEMBER: u8 = 0xc7;
    pub const RESTORE_STATE: u8 = 0xc8;
    /// The frame record both ABIs use: CFA = FP + 16, FP in slot 2, the
    /// return address in slot 1.
    pub const FRAME: u8 = 0xc9;
    /// FP in slot 2 and the return address in slot 1; the CFA rule stays.
    pub const FRAME_REGS: u8 = 0xca;
    /// uleb n: DW_CFA_GNU_args_size, n bytes of outgoing arguments pushed
    /// at this offset. Part of the state; it does not change the step.
    pub const ARGS_SIZE: u8 = 0xcb;
    /// 0xe0..=0xff: register n (DWARF 0..31) back to its entry rule.
    pub const RESTORE: u8 = 0xe0;
}

pub const MAX_SAVED: usize = 32;
pub const MAX_REMEMBER: usize = 4;

/// The unwind state at one instruction: CFA = (SP or FP) + 8 * cfa_units;
/// each saved register is at CFA - 8 * slot; every other register, and the
/// return address when it is not saved, still holds its caller value.
/// `args_size` is DW_CFA_GNU_args_size (bytes of pushed outgoing arguments,
/// x86): carried as .eh_frame carries it. Stepping does not use it;
/// installing a landing pad adds it to the stack pointer
/// (abi::Cursor::set_landing_ip_for).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct State {
    pub cfa_fp: bool,
    pub cfa_units: u32,
    pub args_size: u32,
    pub count: usize,
    pub saved: [(u16, u16); MAX_SAVED],
}

impl State {
    pub const fn entry(a: &Arch2) -> State {
        let mut s = State { cfa_fp: false, cfa_units: a.entry_cfa, args_size: 0, count: 0, saved: [(0, 0); MAX_SAVED] };
        if a.entry_ra_slot != 0 {
            s.saved[0] = (a.ra, a.entry_ra_slot);
            s.count = 1;
        }
        s
    }

    /// Slot of `reg`, or None when the register is not saved.
    pub fn slot(&self, reg: u16) -> Option<u16> {
        self.saved[..self.count].iter().find(|x| x.0 == reg).map(|x| x.1)
    }

    fn save(&mut self, reg: usize, slot: usize) -> Result<()> {
        if slot == 0 || slot > u16::MAX as usize || reg > u16::MAX as usize {
            return Err(Failure::BadEkoRecord);
        }
        let (reg, slot) = (reg as u16, slot as u16);
        if let Some(x) = self.saved[..self.count].iter_mut().find(|x| x.0 == reg) {
            x.1 = slot;
            return Ok(());
        }
        if self.count == MAX_SAVED {
            return Err(Failure::BadEkoRecord);
        }
        self.saved[self.count] = (reg, slot);
        self.count += 1;
        Ok(())
    }

    fn restore(&mut self, a: &Arch2, reg: usize) -> Result<()> {
        if let Some(i) = self.saved[..self.count].iter().position(|x| x.0 as usize == reg) {
            self.saved.copy_within(i + 1..self.count, i);
            self.count -= 1;
        }
        if reg == a.ra as usize && a.entry_ra_slot != 0 {
            self.save(reg, a.entry_ra_slot as usize)?;
        }
        Ok(())
    }
}

/// Bounded byte reader over [pos, end). Running off the end is BadEkoRecord.
struct Bytes {
    pos: usize,
    end: usize,
}

impl Bytes {
    fn u8(&mut self) -> Result<u8> {
        if self.pos >= self.end {
            return Err(Failure::BadEkoRecord);
        }
        let b = unsafe { load::<u8>(self.pos) };
        self.pos += 1;
        Ok(b)
    }

    /// ULEB128 of at most 5 bytes (a u32).
    fn uleb(&mut self) -> Result<usize> {
        let mut v = 0usize;
        for i in 0..5 {
            let b = self.u8()?;
            v |= ((b & 0x7f) as usize) << (7 * i);
            if b & 0x80 == 0 {
                return if v > u32::MAX as usize { Err(Failure::BadEkoRecord) } else { Ok(v) };
            }
        }
        Err(Failure::BadEkoRecord)
    }
}

/// Run a version 2 state program up to byte offset `off` from the function
/// start. Returns the state in effect at `off` and, when the program was read
/// to its END, the address just past END (where a handler table starts),
/// else 0. `program` 0 means the entry state holds everywhere.
pub fn run(a: &Arch2, program: usize, limit: usize, off: usize) -> Result<(State, usize)> {
    let mut st = State::entry(a);
    if program == 0 {
        return Ok((st, 0));
    }
    let mut stack = [st; MAX_REMEMBER];
    let mut depth = 0usize;
    let mut at = 0usize;
    let mut b = Bytes { pos: program, end: limit };
    loop {
        let code = b.u8()?;
        let advance = match code {
            op::END => return Ok((st, b.pos)),
            0x01..=0x3f => code as usize,
            0x40..=0x7f => {
                st.cfa_units = (code & 0x3f) as u32;
                0
            }
            0x80..=0xbf => {
                let slot = b.uleb()?;
                st.save((code & 0x3f) as usize, slot)?;
                0
            }
            op::CFA_SP | op::CFA_FP => {
                st.cfa_fp = code == op::CFA_FP;
                st.cfa_units = b.uleb()? as u32;
                0
            }
            op::CFA_OFFSET_LONG => {
                st.cfa_units = b.uleb()? as u32;
                0
            }
            op::ADVANCE_LONG => b.uleb()?,
            op::SAVE_LONG => {
                let reg = b.uleb()?;
                let slot = b.uleb()?;
                st.save(reg, slot)?;
                0
            }
            op::RESTORE_LONG => {
                let reg = b.uleb()?;
                st.restore(a, reg)?;
                0
            }
            op::ENTRY => {
                st = State::entry(a);
                0
            }
            op::ARGS_SIZE => {
                st.args_size = b.uleb()? as u32;
                0
            }
            op::REMEMBER => {
                if depth == MAX_REMEMBER {
                    return Err(Failure::RememberStackOverflow);
                }
                stack[depth] = st;
                depth += 1;
                0
            }
            op::RESTORE_STATE => {
                if depth == 0 {
                    return Err(Failure::BadEkoRecord);
                }
                depth -= 1;
                st = stack[depth];
                0
            }
            op::FRAME | op::FRAME_REGS => {
                if code == op::FRAME {
                    st.cfa_fp = true;
                    st.cfa_units = 2;
                }
                st.save(a.fp as usize, 2)?;
                st.save(a.ra as usize, 1)?;
                0
            }
            0xe0..=0xff => {
                st.restore(a, (code & 0x1f) as usize)?;
                0
            }
            _ => return Err(Failure::BadEkoRecord),
        };
        if advance != 0 {
            let next = advance.checked_mul(a.unit).and_then(|n| at.checked_add(n)).ok_or(Failure::BadEkoRecord)?;
            if next > off {
                return Ok((st, 0));
            }
            at = next;
        }
    }
}

/// Apply a state to the registers of the frame it describes: the caller
/// state. Same result as a CFI row with the same rules (cfi::apply).
pub fn apply(a: &Arch2, st: &State, regs: &Regs) -> Result<Regs> {
    let base = regs.get(if st.cfa_fp { a.fp } else { a.sp })?;
    if st.cfa_fp && (base == 0 || !base.is_multiple_of(8)) {
        return Err(Failure::Misaligned);
    }
    let cfa = base.wrapping_add(8 * st.cfa_units as usize);
    if cfa == 0 {
        return Err(Failure::BadCfaRule);
    }
    let mut next = *regs;
    for &(reg, slot) in &st.saved[..st.count] {
        next.set(reg, unsafe { load::<usize>(cfa.wrapping_sub(8 * slot as usize)) })?;
    }
    let ra = next.get(a.ra)?;
    next.set_sp(cfa);
    next.pc = Regs::strip_pac(ra);
    Ok(next)
}

/// Step a frame described by a version 2 record. `off` is the lookup pc
/// minus the function start: the interrupted instruction, or the call.
/// Valid at every instruction, so there is no async refusal.
pub fn step2(program: usize, limit: usize, off: usize, regs: &Regs) -> Result<Regs> {
    let (st, _) = run(&HOST, program, limit, off)?;
    apply(&HOST, &st, regs)
}

/// Version 2 handler table: uleb rows, then per row uleb (ret - previous
/// ret, the first relative to 0) and uleb (pad << 2 | action). A zero delta
/// is a second row for one return address.
pub fn handler2(table: usize, limit: usize, ret: u32) -> Result<Option<(u32, u32)>> {
    let mut b = Bytes { pos: table, end: limit };
    let rows = b.uleb()?;
    let mut at = 0usize;
    let mut i = 0usize;
    while i < rows {
        let delta = b.uleb()?;
        let word = b.uleb()?;
        i += 1;
        if delta == 0 {
            return Err(Failure::EkoAmbiguousCallSite);
        }
        at += delta;
        if at > ret as usize {
            return Ok(None);
        }
        if at == ret as usize {
            if i < rows && b.uleb()? == 0 {
                return Err(Failure::EkoAmbiguousCallSite);
            }
            let (pad, action) = ((word >> 2) as u32, (word & 3) as u32);
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
    }
    Ok(None)
}
