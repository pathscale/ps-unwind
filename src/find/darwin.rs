//! Darwin: images through the dyld add/remove-image callbacks, sections
//! through the mach header, both read once per image into the lock-free
//! cache (src/cache.rs). The unwind path itself makes no dyld call.
//!
//! `_dyld_register_func_for_add_image` calls back once for every image
//! already loaded, during registration, and then before each dlopen returns;
//! `_dyld_register_func_for_remove_image` before each unload. So the cache
//! is complete once built, and a pc it does not cover is in no image
//! (NoImage), in or out of signal context.

use core::ffi::c_void;

use crate::cache;
use crate::cfi;
use crate::compact;
use crate::eko;
use crate::failure::{Failure, Result};
use crate::frame::{FrameInfo, Kind};
use crate::mem::{load, Bases};

unsafe extern "C" {
    fn _dyld_register_func_for_add_image(f: extern "C" fn(mh: *const c_void, slide: isize));
    fn _dyld_register_func_for_remove_image(f: extern "C" fn(mh: *const c_void, slide: isize));
}

/// The EKO section name in the __TEXT segment.
pub const EKO_SECTION: &[u8] = b"__eko_unwind";

const MH_MAGIC_64: u32 = 0xfeed_facf;
const LC_SEGMENT_64: u32 = 0x19;

/// One loaded image: its __TEXT range and the slid addresses of the
/// sections the unwinder reads.
#[derive(Clone, Copy, Default)]
pub struct Entry {
    /// __TEXT start (the mach header) and end.
    pub start: usize,
    pub end: usize,
    pub eko: usize,
    pub eko_len: usize,
    pub unwind_info: usize,
    pub unwind_info_len: usize,
    pub eh_frame: usize,
    pub eh_frame_len: usize,
}

fn name_is(field: usize, name: &[u8]) -> bool {
    for i in 0..16 {
        let c = unsafe { load::<u8>(field + i) };
        let want = if i < name.len() { name[i] } else { 0 };
        if c != want {
            return false;
        }
        if c == 0 {
            return true;
        }
    }
    true
}

/// Walk the load commands of the image at `mh`.
pub fn image(mh: usize) -> Result<Entry> {
    if unsafe { load::<u32>(mh) } != MH_MAGIC_64 {
        return Err(Failure::NoImage);
    }
    let ncmds = unsafe { load::<u32>(mh + 16) } as usize;
    let sizeofcmds = unsafe { load::<u32>(mh + 20) } as usize;
    let mut cmd = mh + 32;
    let end = cmd + sizeofcmds;
    let mut out = Entry::default();
    let mut slide = None;
    let mut sections = [(0usize, 0usize); 3];
    for _ in 0..ncmds {
        if cmd + 8 > end {
            return Err(Failure::NoImage);
        }
        let kind = unsafe { load::<u32>(cmd) };
        let size = unsafe { load::<u32>(cmd + 4) } as usize;
        if size < 8 {
            return Err(Failure::NoImage);
        }
        if kind == LC_SEGMENT_64 {
            if name_is(cmd + 8, b"__TEXT") {
                let vmaddr = unsafe { load::<u64>(cmd + 24) } as usize;
                let vmsize = unsafe { load::<u64>(cmd + 32) } as usize;
                slide = Some(mh.wrapping_sub(vmaddr));
                out.start = mh;
                out.end = mh + vmsize;
            }
            let nsects = unsafe { load::<u32>(cmd + 64) } as usize;
            for i in 0..nsects {
                let sect = cmd + 72 + i * 80;
                let which = if name_is(sect, EKO_SECTION) {
                    0
                } else if name_is(sect, b"__unwind_info") {
                    1
                } else if name_is(sect, b"__eh_frame") {
                    2
                } else {
                    continue;
                };
                let addr = unsafe { load::<u64>(sect + 32) } as usize;
                let len = unsafe { load::<u64>(sect + 40) } as usize;
                sections[which] = (addr, len);
            }
        }
        cmd += size;
    }
    let Some(slide) = slide else { return Err(Failure::NoImage) };
    let slid = |(a, l): (usize, usize)| if l == 0 { (0, 0) } else { (a.wrapping_add(slide), l) };
    (out.eko, out.eko_len) = slid(sections[0]);
    (out.unwind_info, out.unwind_info_len) = slid(sections[1]);
    (out.eh_frame, out.eh_frame_len) = slid(sections[2]);
    Ok(out)
}

extern "C" fn on_add(mh: *const c_void, _slide: isize) {
    if let Ok(e) = image(mh as usize) {
        cache::update(|v| v.push(e));
    }
}

extern "C" fn on_remove(mh: *const c_void, _slide: isize) {
    let mh = mh as usize;
    cache::update(|v| v.retain(|e| e.start != mh));
}

/// Initial fill, from cache::ensure_ready. dyld calls on_add for every
/// loaded image before the first registration returns.
pub fn fill() {
    unsafe {
        _dyld_register_func_for_add_image(on_add);
        _dyld_register_func_for_remove_image(on_remove);
    }
}

fn entry(addr: usize) -> Result<Entry> {
    cache::ensure_ready()?;
    cache::lookup(addr).ok_or(Failure::NoImage)
}

/// True when `addr` lies in the __TEXT segment of a loaded image.
pub fn is_code(addr: usize) -> bool {
    entry(addr).is_ok()
}

/// Describe the function containing `target` (a pc already adjusted for a
/// return address).
pub fn find(target: usize) -> Result<FrameInfo> {
    let img = entry(target)?;
    let mh = img.start;
    let eh = img.eh_frame;
    let eh_len = img.eh_frame_len;
    let bases = Bases { text: mh, data: 0, func: 0 };

    if img.eko_len != 0
        && let Some(r) = eko::lookup(img.eko, img.eko_len, target)? {
            return Ok(FrameInfo {
                start: r.start,
                end: r.end,
                lsda: 0,
                personality: 0,
                eko_handlers: r.handlers,
                signal: false,
                kind: r.kind(),
                text_base: mh,
                data_base: 0,
            });
        }

    let info = if img.unwind_info_len != 0 {
        let ui = img.unwind_info;
        let Some(e) = compact::lookup(mh, ui, img.unwind_info_len, target)? else {
            return Err(Failure::NoUnwindInfo);
        };
        let mode = e.encoding & compact::MODE_MASK;
        if mode == 0 {
            return Err(Failure::NoUnwindInfo);
        }
        if mode == compact::MODE_DWARF {
            if eh_len == 0 {
                return Err(Failure::BadUnwindInfo);
            }
            let off = (e.encoding & compact::DWARF_OFFSET_MASK) as usize;
            if off >= eh_len {
                return Err(Failure::BadUnwindInfo);
            }
            let fde = cfi::parse_fde(eh + off, eh, eh + eh_len, &bases)?;
            if !(fde.start <= target && target < fde.end) {
                return Err(Failure::FdeRangeMiss);
            }
            FrameInfo::from_fde(&fde, mh, 0)
        } else {
            FrameInfo {
                start: e.start,
                end: e.end,
                lsda: e.lsda,
                personality: e.personality,
                eko_handlers: 0,
                signal: false,
                kind: Kind::Compact(e.encoding),
                text_base: mh,
                data_base: 0,
            }
        }
    } else if eh_len != 0 {
        match cfi::scan(eh, eh_len, target, &bases)? {
            Some(fde) => FrameInfo::from_fde(&fde, mh, 0),
            None => return Err(Failure::NoUnwindInfo),
        }
    } else {
        return Err(Failure::NoUnwindInfo);
    };
    if info.personality != 0 && !is_code(info.personality) {
        return Err(Failure::PersonalityNotCode);
    }
    Ok(info)
}
