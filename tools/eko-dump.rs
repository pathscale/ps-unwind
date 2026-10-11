// EKO table dump through the ps-unwind reader (src/eko.rs), for the
// equivalence check (tools/eko2.ts). Not part of the library.
//
// Usage: eko-dump FILE VMADDR raw|note
//   FILE    bytes of an EKO section copied out of an image: a Mach-O
//           __eko_unwind section (raw: chunks) or an ELF .note.eko_unwind
//           section (note: ELF notes, the EKUW ones hold chunks)
//   VMADDR  the address of the first byte in the image, hex
//
// For every record of every chunk it asks the reader, at every code unit of
// the function: eko::lookup_arch must return this record, and eko::run gives
// the unwind state there. It prints the state where it changes:
//   fn 0xSTART LEN vVERSION
//   +0xOFF CFA=regN+K: regR=[CFA-S], ...
// then, for a version 2 record with handlers, every return offset that
// eko::handler2 finds a row for:
//   row RET PAD ACTION
// A reader failure prints "error +0xOFF NAME" and the dump goes on with the
// next record. Version 1 records print their frame word only.

use ps_unwind::eko;

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn state(st: &eko::State, a: &eko::Arch2) -> String {
    let base = if st.cfa_fp { a.fp } else { a.sp };
    let mut regs: Vec<(u16, u16)> = st.saved[..st.count].to_vec();
    regs.sort();
    let mut s = format!("CFA=reg{}+{}", base, 8 * st.cfa_units);
    if !regs.is_empty() {
        let list: Vec<String> = regs.iter().map(|(r, k)| format!("reg{}=[CFA-{}]", r, 8 * *k as u32)).collect();
        s.push_str(": ");
        s.push_str(&list.join(", "));
    }
    s
}

fn chunks(base: usize, len: usize, vm: usize, out: &mut String) {
    let bytes = unsafe { std::slice::from_raw_parts(base as *const u8, len) };
    let mut c = 0usize;
    while c + 16 <= len {
        let magic = u32_at(bytes, c);
        if magic == 0 {
            c += 4;
            continue;
        }
        let version = bytes[c + 4];
        let arch_code = bytes[c + 5];
        let count = u32_at(bytes, c + 8) as usize;
        let size = u32_at(bytes, c + 12) as usize;
        if magic != eko::MAGIC || size < 16 || c + size > len {
            out.push_str(&format!("error chunk +0x{:x} bad header\n", c));
            return;
        }
        let a = eko::arch2(arch_code);
        let stride = if version == eko::VERSION2 { eko::RECORD2 } else { eko::RECORD };
        for i in 0..count {
            let at = c + 16 + i * stride;
            let start = (base + at).wrapping_add(u32_at(bytes, at) as i32 as isize as usize);
            let length = u32_at(bytes, at + 4) as usize;
            let vstart = start.wrapping_sub(base).wrapping_add(vm);
            out.push_str(&format!("fn 0x{:x} {} v{}\n", vstart, length, version));
            if version != eko::VERSION2 {
                out.push_str(&format!("frame 0x{:08x}\n", u32_at(bytes, at + 8)));
                continue;
            }
            let Some(a) = a else {
                out.push_str("error +0x0 unknown arch\n");
                continue;
            };
            let mut last = String::new();
            let mut rec = None;
            let mut off = 0usize;
            while off < length {
                match eko::lookup_arch(base, len, start + off, arch_code) {
                    Ok(Some(r)) if r.start == start && r.end == start + length => {
                        match eko::run(&a, r.program, r.limit, off) {
                            Ok((st, _)) => {
                                let s = state(&st, &a);
                                if s != last {
                                    out.push_str(&format!("+0x{:x} {}\n", off, s));
                                    last = s;
                                }
                            }
                            Err(f) => {
                                out.push_str(&format!("error +0x{:x} {}\n", off, f.name()));
                                break;
                            }
                        }
                        rec = Some(r);
                    }
                    Ok(_) => {
                        out.push_str(&format!("error +0x{:x} lookup found another record or none\n", off));
                        break;
                    }
                    Err(f) => {
                        out.push_str(&format!("error +0x{:x} {}\n", off, f.name()));
                        break;
                    }
                }
                off += a.unit;
            }
            if let Some(r) = rec
                && r.handlers != 0
            {
                match eko::run(&a, r.program, r.limit, usize::MAX) {
                    Ok((_, table)) => {
                        for ret in 1..=length as u32 {
                            match eko::handler2(table, r.limit, ret) {
                                Ok(Some((pad, action))) => out.push_str(&format!("row {} {} {}\n", ret, pad, action)),
                                Ok(None) => {}
                                Err(f) => {
                                    out.push_str(&format!("error row {} {}\n", ret, f.name()));
                                    break;
                                }
                            }
                        }
                    }
                    Err(f) => out.push_str(&format!("error table {}\n", f.name())),
                }
            }
        }
        c += size;
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: eko-dump FILE VMADDR raw|note");
        std::process::exit(2);
    }
    let raw = std::fs::read(&args[1]).expect("read FILE");
    let vm = usize::from_str_radix(args[2].trim_start_matches("0x"), 16).expect("VMADDR hex");
    // 4-byte aligned copy, as in a mapped image.
    let mut words = vec![0u32; raw.len().div_ceil(4)];
    let base = words.as_mut_ptr() as usize;
    unsafe { std::ptr::copy_nonoverlapping(raw.as_ptr(), base as *mut u8, raw.len()) };
    let mut out = String::new();
    if args[3] == "note" {
        let mut at = 0usize;
        while at + 12 <= raw.len() {
            let namesz = u32_at(&raw, at) as usize;
            let descsz = u32_at(&raw, at + 4) as usize;
            let kind = u32_at(&raw, at + 8);
            let desc = at + 12 + namesz.div_ceil(4) * 4;
            if namesz == 5 && kind == 1 && &raw[at + 12..at + 17] == b"EKUW\0" {
                chunks(base + desc, descsz, vm + desc, &mut out);
            }
            at = desc + descsz.div_ceil(4) * 4;
        }
    } else {
        chunks(base, raw.len(), vm, &mut out);
    }
    drop(words);
    print!("{}", out);
}
