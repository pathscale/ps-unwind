// Landing-pad install through the ps-unwind readers, for the decode-level
// args_size check (tools/landing.ts). Not part of the library.
//
// Usage: landing-sp ELF EHVM EHLEN V2FILE V2VM SITES
//   ELF     a 64-bit little-endian ELF image; its PT_LOAD segments are laid
//           out in one buffer at their link addresses, so .eh_frame and
//           what it points at (personality cells, LSDAs) read as mapped
//   EHVM    address of .eh_frame, hex; EHLEN its size, hex
//   V2FILE  an EKO version 2 table (raw chunks, x86_64), VM its address
//   SITES   lines "START RET PAD": function start (hex address), return
//           offset of a call and landing pad offset (hex)
//
// For every site it builds a Cursor stopped at the call (pc = START + RET)
// with a fixed stack pointer and installs the landing pad the way the
// unwinder does for that kind of frame, with the x86_64 v2 architecture in
// place of the host one:
//   dwarf  the frame cfi::scan finds in .eh_frame (Kind::Dwarf); a
//          personality routine calls _Unwind_SetIP, which runs
//          Cursor::set_landing_ip_for, called here directly
//   v2     the record eko::lookup_arch finds in the v2 table (Kind::Eko2);
//          eko::personality_for in the cleanup phase finds the handler row
//          of the call and installs its pad
// and prints how far the installed stack pointer moved:
//   site 0xSTART +0xRET +0xPAD dwarf=N v2=M
// A reader failure prints the failure name in place of the number; a v2
// personality result other than install prints reason-N.

use ps_unwind::abi::{self, Cursor};
use ps_unwind::arch::Regs;
use ps_unwind::cfi;
use ps_unwind::eko;
use ps_unwind::frame::FrameInfo;
use ps_unwind::mem::Bases;

const SP: usize = 0x10_0000;

fn u16_at(b: &[u8], o: usize) -> usize {
    u16::from_le_bytes([b[o], b[o + 1]]) as usize
}
fn u32_at(b: &[u8], o: usize) -> usize {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as usize
}
fn u64_at(b: &[u8], o: usize) -> usize {
    u32_at(b, o) | (u32_at(b, o + 4) << 32)
}
fn hex(s: &str) -> usize {
    usize::from_str_radix(s.trim_start_matches("0x"), 16).expect("hex")
}

/// The loadable segments of `elf` at their link addresses, 8-byte aligned.
fn layout(elf: &[u8]) -> Vec<u64> {
    let (phoff, phent, phnum) = (u64_at(elf, 0x20), u16_at(elf, 0x36), u16_at(elf, 0x38));
    let segs: Vec<(usize, usize, usize, usize)> = (0..phnum)
        .map(|i| phoff + i * phent)
        .filter(|&p| u32_at(elf, p) == 1)
        .map(|p| (u64_at(elf, p + 8), u64_at(elf, p + 16), u64_at(elf, p + 32), u64_at(elf, p + 40)))
        .collect();
    let top = segs.iter().map(|s| s.1 + s.3).max().unwrap_or(0);
    let mut mem = vec![0u64; top.div_ceil(8)];
    let base = mem.as_mut_ptr() as *mut u8;
    for (off, vaddr, filesz, _) in segs {
        unsafe { std::ptr::copy_nonoverlapping(elf[off..off + filesz].as_ptr(), base.add(vaddr), filesz) };
    }
    mem
}

fn install(mut c: Cursor, pad: usize) -> String {
    c.regs.set_sp(SP);
    match c.set_landing_ip_for(&eko::X86_64, pad) {
        Ok(()) if c.regs.pc == pad => format!("{}", c.regs.sp() as isize - SP as isize),
        Ok(()) => "pc-not-pad".to_string(),
        Err(f) => f.name().to_string(),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 {
        eprintln!("usage: landing-sp ELF EHVM EHLEN V2FILE V2VM SITES");
        std::process::exit(2);
    }
    let elf = std::fs::read(&args[1]).expect("read ELF");
    let (eh_vm, eh_len) = (hex(&args[2]), hex(&args[3]));
    let mem = layout(&elf);
    let img = mem.as_ptr() as usize;
    let v2raw = std::fs::read(&args[4]).expect("read V2FILE");
    let v2vm = hex(&args[5]);
    let mut words = vec![0u32; v2raw.len().div_ceil(4)];
    let v2 = words.as_mut_ptr() as usize;
    unsafe { std::ptr::copy_nonoverlapping(v2raw.as_ptr(), v2 as *mut u8, v2raw.len()) };
    let bases = Bases { text: 0, data: 0, func: 0 };
    let mut out = String::new();
    for line in std::fs::read_to_string(&args[6]).expect("read SITES").lines() {
        let f: Vec<usize> = line.split_whitespace().map(hex).collect();
        let (start, ret, pad) = (f[0], f[1], f[2]);

        let pc = img + start + ret;
        let dwarf = match cfi::scan(img + eh_vm, eh_len, pc - 1, &bases) {
            Ok(Some(fde)) if fde.start == img + start => {
                let mut c = Cursor::new(Regs::zeroed());
                c.regs.pc = pc;
                c.info = FrameInfo::from_fde(&fde, 0, 0);
                install(c, img + start + pad)
            }
            Ok(_) => "no-fde".to_string(),
            Err(e) => e.name().to_string(),
        };

        let at = v2 + (start - v2vm);
        let ekov2 = match eko::lookup_arch(v2, v2raw.len(), at + ret - 1, eko::X86_64.code) {
            Ok(Some(r)) if r.start == at && r.version == eko::VERSION2 => {
                let mut c = Cursor::new(Regs::zeroed());
                c.regs.pc = at + ret;
                c.info = FrameInfo { start: r.start, end: r.end, eko_handlers: r.handlers, kind: r.kind(), ..FrameInfo::EMPTY };
                c.regs.set_sp(SP);
                match eko::personality_for(&eko::X86_64, abi::UA_CLEANUP_PHASE, std::ptr::null_mut(), &mut c) {
                    Ok(abi::URC_INSTALL_CONTEXT) if c.regs.pc == at + pad => format!("{}", c.regs.sp() as isize - SP as isize),
                    Ok(abi::URC_INSTALL_CONTEXT) => "pc-not-pad".to_string(),
                    Ok(reason) => format!("reason-{}", reason),
                    Err(e) => e.name().to_string(),
                }
            }
            Ok(_) => "no-record".to_string(),
            Err(e) => e.name().to_string(),
        };
        out.push_str(&format!("site 0x{:x} +0x{:x} +0x{:x} dwarf={} v2={}\n", start, ret, pad, dwarf, ekov2));
    }
    drop(words);
    drop(mem);
    print!("{}", out);
}
