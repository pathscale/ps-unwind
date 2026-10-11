//! Linux (glibc and musl): images in the lock-free cache (src/cache.rs),
//! FDEs through the PT_GNU_EH_FRAME binary-search table, EKO chunks through
//! PT_NOTE.
//!
//! COMPILED, NOT RUN: no Linux machine was available (docs/TARGETS.md).
//!
//! The cache is filled at init from the executable (AT_PHDR via getauxval,
//! no lock) and dl_iterate_phdr (loader lock). A pc it does not hold is
//! looked up again only outside signal context: one dl_iterate_phdr pass that
//! stops at once when dlpi_adds/dlpi_subs show no load or unload since the
//! last fill, and otherwise rebuilds the array. In signal context a miss is
//! SignalContextMiss and dl_iterate_phdr is never called; before the cache is
//! built only the executable is found there (from AT_PHDR, no allocation).

extern crate alloc;

use alloc::vec::Vec;
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::cache;
use crate::cfi;
use crate::eko;
use crate::failure::{Failure, Result};
use crate::frame::FrameInfo;
use crate::mem::{load, Bases, Reader};

const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const PT_PHDR: u32 = 6;
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
const PF_X: u32 = 1;
const NOTE_NAME: &[u8; 5] = b"EKUW\0";
const NOTE_TYPE: u32 = 1;
const MAX_NOTES: usize = 4;

/// One loaded image: the span of its PT_LOAD segments, its executable
/// segment, .eh_frame_hdr and up to MAX_NOTES PT_NOTE segments.
#[derive(Clone, Copy, Default)]
pub struct Entry {
    pub start: usize,
    pub end: usize,
    text_start: usize,
    text_end: usize,
    hdr: usize,
    hdr_seg_end: usize,
    notes: [(usize, usize); MAX_NOTES],
    note_count: usize,
}

fn entry_from_phdrs(base: usize, phdr: *const libc::Elf64_Phdr, n: usize) -> Option<Entry> {
    let mut e = Entry { start: usize::MAX, ..Entry::default() };
    let ph = |i: usize| unsafe { &*phdr.add(i) };
    for i in 0..n {
        let p = ph(i);
        let start = base.wrapping_add(p.p_vaddr as usize);
        let end = start.wrapping_add(p.p_memsz as usize);
        match p.p_type {
            PT_LOAD => {
                e.start = e.start.min(start);
                e.end = e.end.max(end);
                if p.p_flags & PF_X != 0 && e.text_start == 0 {
                    e.text_start = start;
                    e.text_end = end;
                }
            }
            PT_GNU_EH_FRAME => e.hdr = start,
            PT_NOTE if e.note_count < MAX_NOTES => {
                e.notes[e.note_count] = (start, p.p_memsz as usize);
                e.note_count += 1;
            }
            _ => {}
        }
    }
    if e.start >= e.end || e.text_start == 0 {
        return None;
    }
    if e.hdr != 0 {
        for i in 0..n {
            let p = ph(i);
            let start = base.wrapping_add(p.p_vaddr as usize);
            let end = start.wrapping_add(p.p_memsz as usize);
            if p.p_type == PT_LOAD && start <= e.hdr && e.hdr < end {
                e.hdr_seg_end = end;
            }
        }
    }
    Some(e)
}

/// The executable, from the auxiliary vector: no lock, no allocation, safe
/// in a signal handler. Needs PT_PHDR to know the load bias.
fn exe_entry() -> Option<Entry> {
    let phdr = unsafe { libc::getauxval(libc::AT_PHDR) } as usize;
    let n = unsafe { libc::getauxval(libc::AT_PHNUM) } as usize;
    if phdr == 0 || n == 0 {
        return None;
    }
    let ph = phdr as *const libc::Elf64_Phdr;
    let bias = (0..n).find_map(|i| {
        let p = unsafe { &*ph.add(i) };
        (p.p_type == PT_PHDR).then(|| phdr.wrapping_sub(p.p_vaddr as usize))
    })?;
    entry_from_phdrs(bias, ph, n)
}

/// dlpi_adds + dlpi_subs at the last fill; 0 before the first.
static GENERATION: AtomicU64 = AtomicU64::new(0);

struct Collect {
    entries: Vec<Entry>,
    generation: u64,
    /// Stop at the first image when the generation equals this.
    unchanged_if: u64,
    unchanged: bool,
}

const SUBS_END: usize = core::mem::offset_of!(libc::dl_phdr_info, dlpi_subs) + 8;

unsafe extern "C" fn collect(info: *mut libc::dl_phdr_info, size: libc::size_t, data: *mut c_void) -> c_int {
    unsafe {
        let c = &mut *(data as *mut Collect);
        let i = &*info;
        if size >= SUBS_END {
            c.generation = i.dlpi_adds.wrapping_add(i.dlpi_subs);
            if c.generation == c.unchanged_if && c.entries.is_empty() {
                c.unchanged = true;
                return 1;
            }
        }
        if let Some(e) = entry_from_phdrs(i.dlpi_addr as usize, i.dlpi_phdr, i.dlpi_phnum as usize) {
            c.entries.push(e);
        }
        0
    }
}

/// All images now loaded, or None when nothing changed since `unchanged_if`.
fn snapshot(unchanged_if: u64) -> Option<(Vec<Entry>, u64)> {
    let mut c = Collect { entries: Vec::with_capacity(16), generation: 0, unchanged_if, unchanged: false };
    if let Some(e) = exe_entry() {
        c.entries.push(e);
    }
    // Duplicates of the executable are dropped when the array is published.
    let mut probe = Collect { entries: Vec::new(), generation: 0, unchanged_if, unchanged: false };
    if unchanged_if != 0 {
        unsafe { libc::dl_iterate_phdr(Some(collect), (&mut probe as *mut Collect).cast()) };
        if probe.unchanged {
            return None;
        }
    }
    c.unchanged_if = u64::MAX;
    unsafe { libc::dl_iterate_phdr(Some(collect), (&mut c as *mut Collect).cast()) };

    Some((c.entries, c.generation))
}

/// Initial fill, from cache::ensure_ready.
pub fn fill() {
    if let Some((v, g)) = snapshot(0) {
        GENERATION.store(g, Ordering::Relaxed);
        cache::update(|s| s.extend_from_slice(&v));
    }
}

fn entry(addr: usize) -> Result<Entry> {
    let signal = cache::in_signal_context();
    if signal && !cache::is_ready() {
        return match exe_entry() {
            Some(e) if e.start <= addr && addr < e.end => Ok(e),
            _ => Err(Failure::SignalContextMiss),
        };
    }
    cache::ensure_ready()?;
    if let Some(e) = cache::lookup(addr) {
        return Ok(e);
    }
    if signal {
        return Err(Failure::SignalContextMiss);
    }
    if let Some((v, g)) = snapshot(GENERATION.load(Ordering::Relaxed)) {
        GENERATION.store(g, Ordering::Relaxed);
        cache::replace(v);
    }
    cache::lookup(addr).ok_or(Failure::NoImage)
}

pub fn is_code(addr: usize) -> bool {
    match entry(addr) {
        Ok(e) => e.text_start <= addr && addr < e.text_end,
        Err(_) => false,
    }
}

fn eko_in_notes(s: &Entry, target: usize) -> Result<Option<eko::Record>> {
    for &(start, len) in &s.notes[..s.note_count] {
        let end = start + len;
        let mut at = start;
        while at + 12 <= end {
            let namesz = unsafe { load::<u32>(at) } as usize;
            let descsz = unsafe { load::<u32>(at + 4) } as usize;
            let kind = unsafe { load::<u32>(at + 8) };
            let name = at + 12;
            let desc = name + ((namesz + 3) & !3);
            let next = desc + ((descsz + 3) & !3);
            if next > end {
                break;
            }
            let is_eko = namesz == 5
                && kind == NOTE_TYPE
                && (0..5).all(|i| unsafe { load::<u8>(name + i) } == NOTE_NAME[i]);
            if is_eko
                && let Some(r) = eko::lookup(desc, descsz, target)? {
                    return Ok(Some(r));
                }
            at = next;
        }
    }
    Ok(None)
}

pub fn find(target: usize) -> Result<FrameInfo> {
    let s = entry(target)?;
    if let Some(r) = eko_in_notes(&s, target)? {
        return Ok(FrameInfo {
            start: r.start,
            end: r.end,
            lsda: 0,
            personality: 0,
            eko_handlers: r.handlers,
            signal: false,
            kind: r.kind(),
            text_base: s.text_start,
            data_base: 0,
        });
    }
    if s.hdr == 0 {
        return Err(Failure::NoUnwindInfo);
    }
    let hdr = s.hdr;
    let mut r = Reader { pos: hdr, end: s.hdr_seg_end };
    let version = r.u8()?;
    let ptr_enc = r.u8()?;
    let count_enc = r.u8()?;
    let table_enc = r.u8()?;
    if version != 1 {
        return Err(Failure::BadCieFde);
    }
    let bases = Bases { text: s.text_start, data: hdr, func: 0 };
    let eh_frame = r.encoded(ptr_enc, &bases)?;
    let eh_end = s.hdr_seg_end;
    let fde = if count_enc != 0xff && table_enc == 0x3b {
        // datarel | sdata4: fixed 8-byte rows, binary search.
        let count = r.encoded(count_enc, &bases)?;
        let table = r.pos;
        if count == 0 || table + count * 8 > eh_end {
            return Err(Failure::NoUnwindInfo);
        }
        let row = |i: usize| -> (usize, usize) {
            let at = table + i * 8;
            let loc = (hdr as isize + unsafe { load::<i32>(at) } as isize) as usize;
            let fde = (hdr as isize + unsafe { load::<i32>(at + 4) } as isize) as usize;
            (loc, fde)
        };
        if row(0).0 > target {
            return Err(Failure::NoUnwindInfo);
        }
        let (mut lo, mut hi) = (0usize, count);
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if row(mid).0 <= target { lo = mid } else { hi = mid }
        }
        let fde = cfi::parse_fde(row(lo).1, eh_frame, eh_end, &bases)?;
        if fde.start != row(lo).0 {
            return Err(Failure::FdeRangeMiss);
        }
        if !(fde.start <= target && target < fde.end) {
            return Err(Failure::NoUnwindInfo);
        }
        fde
    } else {
        match cfi::scan(eh_frame, eh_end - eh_frame, target, &bases)? {
            Some(f) => f,
            None => return Err(Failure::NoUnwindInfo),
        }
    };
    let info = FrameInfo::from_fde(&fde, s.text_start, hdr);
    if info.personality != 0 && !is_code(info.personality) {
        return Err(Failure::PersonalityNotCode);
    }
    Ok(info)
}
