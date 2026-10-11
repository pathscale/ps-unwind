//! DWARF call frame information as found in `__eh_frame` / `.eh_frame`: CIE and
//! FDE parsing, the DW_CFA row interpreter and the small DW_OP evaluator that
//! CFI expressions need. Fixed-size state only: no allocation.

use crate::arch::{self, Regs, COLUMNS};
use crate::failure::{Failure, Result};
use crate::mem::{load, Bases, Reader, DW_EH_PE_OMIT};

/// A parsed CIE. Addresses are absolute.
#[derive(Clone, Copy)]
pub struct Cie {
    pub code_align: u64,
    pub data_align: i64,
    pub ra_reg: u16,
    pub fde_encoding: u8,
    pub lsda_encoding: u8,
    pub personality: usize,
    pub signal: bool,
    pub has_z: bool,
    pub instructions: usize,
    pub instructions_end: usize,
}

/// A parsed FDE together with its CIE.
#[derive(Clone, Copy)]
pub struct Fde {
    pub start: usize,
    pub end: usize,
    pub lsda: usize,
    pub instructions: usize,
    pub instructions_end: usize,
    pub cie: Cie,
}

/// Read an entry length. Returns (body start, entry end).
fn entry_bounds(addr: usize, section_end: usize) -> Result<(usize, usize)> {
    let mut r = Reader { pos: addr, end: section_end };
    let len32 = r.u32()?;
    let len = if len32 == 0xffff_ffff { r.u64()? as usize } else { len32 as usize };
    let body = r.pos;
    let end = body.checked_add(len).ok_or(Failure::BadCieFde)?;
    if end > section_end {
        return Err(Failure::BadCieFde);
    }
    Ok((body, end))
}

/// Parse the CIE at `addr`, inside a section ending at `section_end`.
pub fn parse_cie(addr: usize, section_end: usize, bases: &Bases) -> Result<Cie> {
    let (body, end) = entry_bounds(addr, section_end)?;
    let mut r = Reader { pos: body, end };
    if r.u32()? != 0 {
        return Err(Failure::BadCieFde);
    }
    let version = r.u8()?;
    if version != 1 && version != 3 && version != 4 {
        return Err(Failure::BadCieFde);
    }
    let aug = r.pos;
    let mut aug_len = 0usize;
    while r.u8()? != 0 {
        aug_len += 1;
        if aug_len > 16 {
            return Err(Failure::UnknownAugmentation);
        }
    }
    if version == 4 {
        // address_size and segment_selector_size
        r.skip(2)?;
    }
    let code_align = r.uleb()?;
    let data_align = r.sleb()?;
    let ra_reg = if version == 1 { u16::from(r.u8()?) } else { r.uleb()? as u16 };
    let mut cie = Cie {
        code_align,
        data_align,
        ra_reg,
        fde_encoding: 0,
        lsda_encoding: DW_EH_PE_OMIT,
        personality: 0,
        signal: false,
        has_z: false,
        instructions: 0,
        instructions_end: end,
    };
    let mut letters = Reader::new(aug, aug_len);
    let mut aug_end = 0usize;
    let mut first = true;
    while letters.pos < letters.end {
        let c = letters.u8()?;
        match c {
            0x7a if first => {
                // z: augmentation data length follows
                cie.has_z = true;
                let n = r.uleb()? as usize;
                aug_end = r.pos.checked_add(n).ok_or(Failure::BadCieFde)?;
                if aug_end > end {
                    return Err(Failure::BadCieFde);
                }
            }
            0x50 => {
                // P: personality encoding and pointer
                let enc = r.u8()?;
                cie.personality = r.encoded(enc, bases)?;
            }
            0x4c => cie.lsda_encoding = r.u8()?, // L
            0x52 => cie.fde_encoding = r.u8()?,  // R
            0x53 => cie.signal = true,           // S
            0x42 | 0x47 => {}                    // B (PAC B-key), G (MTE tagged)
            _ => return Err(Failure::UnknownAugmentation),
        }
        first = false;
    }
    if cie.has_z {
        if r.pos > aug_end {
            return Err(Failure::BadCieFde);
        }
        r.pos = aug_end;
    } else if aug_len != 0 {
        return Err(Failure::UnknownAugmentation);
    }
    cie.instructions = r.pos;
    Ok(cie)
}

/// Parse the FDE at `addr`. `section` is the start of the eh_frame section and
/// `section_end` its end; the CIE is located through the CIE pointer.
pub fn parse_fde(addr: usize, section: usize, section_end: usize, bases: &Bases) -> Result<Fde> {
    let (body, end) = entry_bounds(addr, section_end)?;
    let mut r = Reader { pos: body, end };
    let id_field = r.pos;
    let cie_delta = r.u32()? as usize;
    if cie_delta == 0 {
        return Err(Failure::BadCieFde);
    }
    let cie_addr = id_field.checked_sub(cie_delta).ok_or(Failure::BadCieFde)?;
    if cie_addr < section {
        return Err(Failure::BadCieFde);
    }
    let cie = parse_cie(cie_addr, section_end, bases)?;
    let start = r.encoded(cie.fde_encoding, bases)?;
    let range = crate::mem::encoded_range(&mut r, cie.fde_encoding)?;
    let mut lsda = 0usize;
    if cie.has_z {
        let n = r.uleb()? as usize;
        let aug_end = r.pos.checked_add(n).ok_or(Failure::BadCieFde)?;
        if cie.lsda_encoding != DW_EH_PE_OMIT {
            let mut a = Reader { pos: r.pos, end: aug_end };
            // A zero LSDA pointer (before relocation) means "none".
            let probe = a;
            lsda = a.encoded(cie.lsda_encoding, &Bases { func: start, ..*bases })?;
            let raw_zero = match cie.lsda_encoding & 0x0f {
                0x03 | 0x0b => (unsafe { load::<u32>(probe.pos) }) == 0,
                0x04 | 0x0c | 0x00 => (unsafe { load::<u64>(probe.pos) }) == 0,
                _ => false,
            };
            if raw_zero {
                lsda = 0;
            }
        }
        r.pos = aug_end;
    }
    Ok(Fde {
        start,
        end: start.wrapping_add(range),
        lsda,
        instructions: r.pos,
        instructions_end: end,
        cie,
    })
}

/// Linear search of a whole eh_frame section for the FDE covering `pc`. Used
/// only for images that carry `__eh_frame` without an index.
pub fn scan(section: usize, len: usize, pc: usize, bases: &Bases) -> Result<Option<Fde>> {
    let end = section + len;
    let mut at = section;
    while at + 4 <= end {
        let (body, entry_end) = entry_bounds(at, end)?;
        if body == entry_end || unsafe { load::<u32>(at) } == 0 {
            break; // zero terminator
        }
        let id = unsafe { load::<u32>(body) };
        if id != 0 {
            let fde = parse_fde(at, section, end, bases)?;
            if fde.start <= pc && pc < fde.end {
                return Ok(Some(fde));
            }
        }
        at = entry_end;
    }
    Ok(None)
}

#[derive(Clone, Copy, PartialEq)]
pub enum Rule {
    Same,
    Undefined,
    Offset(i64),
    ValOffset(i64),
    Register(u16),
    /// Address of a uleb128 length followed by a DWARF expression.
    Expr(usize),
    ValExpr(usize),
}

#[derive(Clone, Copy, PartialEq)]
pub enum Cfa {
    RegOffset(u16, i64),
    Expr(usize),
}

#[derive(Clone, Copy)]
pub struct Row {
    pub cfa: Cfa,
    pub rules: [Rule; COLUMNS],
    pub ra_signed: bool,
    /// DW_CFA_GNU_args_size: bytes of outgoing arguments pushed at this
    /// location. Stepping ignores it (the CFA rule already accounts for
    /// them); installing a landing pad adds it to the stack pointer.
    pub args_size: usize,
}

impl Row {
    const fn new() -> Row {
        Row { cfa: Cfa::RegOffset(0, 0), rules: [Rule::Same; COLUMNS], ra_signed: false, args_size: 0 }
    }
}

const REMEMBER_DEPTH: usize = 6;

/// Execute CIE initial instructions and then FDE instructions up to and
/// including the row that covers `target`.
pub fn row_for(fde: &Fde, target: usize) -> Result<Row> {
    let mut row = Row::new();

    let mut stack = [Row::new(); REMEMBER_DEPTH];
    let mut depth = 0usize;
    let mut loc = fde.start;
    run(&fde.cie, fde.cie.instructions, fde.cie.instructions_end, usize::MAX, &mut loc, &mut row, None, &mut stack, &mut depth)?;
    let initial = row;

    loc = fde.start;
    run(&fde.cie, fde.instructions, fde.instructions_end, target, &mut loc, &mut row, Some(&initial), &mut stack, &mut depth)?;
    Ok(row)
}

fn set_rule(row: &mut Row, reg: u64, rule: Rule) -> Result<()> {
    if reg > u64::from(arch::MAX_DWARF_REG) {
        return Err(Failure::UnknownRegister);
    }
    if let Some(col) = arch::column(reg as u16) {
        row.rules[col] = rule;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run(
    cie: &Cie,
    start: usize,
    end: usize,
    target: usize,
    loc: &mut usize,
    row: &mut Row,
    initial: Option<&Row>,
    stack: &mut [Row; REMEMBER_DEPTH],
    depth: &mut usize,
) -> Result<()> {
    let mut r = Reader { pos: start, end };
    let ca = cie.code_align as usize;
    let da = cie.data_align;
    while r.pos < r.end {
        let op = r.u8()?;
        let high = op & 0xc0;
        let low = op & 0x3f;
        if high == 0x40 {
            // DW_CFA_advance_loc
            let next = loc.wrapping_add(low as usize * ca);
            if next > target {
                return Ok(());
            }
            *loc = next;
            continue;
        }
        if high == 0x80 {
            let off = r.uleb()? as i64 * da;
            set_rule(row, u64::from(low), Rule::Offset(off))?;
            continue;
        }
        if high == 0xc0 {
            let rule = match initial {
                Some(i) => arch::column(u16::from(low)).map(|c| i.rules[c]).unwrap_or(Rule::Same),
                None => Rule::Same,
            };
            set_rule(row, u64::from(low), rule)?;
            continue;
        }
        match op {
            0x00 => {}
            0x01 => {
                // set_loc
                let next = r.encoded(cie.fde_encoding, &Bases::default())?;
                if next > target {
                    return Ok(());
                }
                *loc = next;
            }
            0x02..=0x04 => {
                let delta = match op {
                    0x02 => usize::from(r.u8()?),
                    0x03 => usize::from(r.u16()?),
                    _ => r.u32()? as usize,
                };
                let next = loc.wrapping_add(delta * ca);
                if next > target {
                    return Ok(());
                }
                *loc = next;
            }
            0x05 => {
                let reg = r.uleb()?;
                let off = r.uleb()? as i64 * da;
                set_rule(row, reg, Rule::Offset(off))?;
            }
            0x06 => {
                let reg = r.uleb()?;
                let rule = match initial {
                    Some(i) => arch::column(reg as u16).map(|c| i.rules[c]).unwrap_or(Rule::Same),
                    None => Rule::Same,
                };
                set_rule(row, reg, rule)?;
            }
            0x07 => {
                let reg = r.uleb()?;
                set_rule(row, reg, Rule::Undefined)?;
            }
            0x08 => {
                let reg = r.uleb()?;
                set_rule(row, reg, Rule::Same)?;
            }
            0x09 => {
                let reg = r.uleb()?;
                let other = r.uleb()?;
                set_rule(row, reg, Rule::Register(other as u16))?;
            }
            0x0a => {
                if *depth >= REMEMBER_DEPTH {
                    return Err(Failure::RememberStackOverflow);
                }
                stack[*depth] = *row;
                *depth += 1;
            }
            0x0b => {
                if *depth == 0 {
                    return Err(Failure::RememberStackOverflow);
                }
                *depth -= 1;
                // The CFA rule is part of the remembered state (DWARF 5, 6.4.2.4).
                *row = stack[*depth];
            }
            0x0c => {
                let reg = r.uleb()? as u16;
                let off = r.uleb()? as i64;
                row.cfa = Cfa::RegOffset(reg, off);
            }
            0x0d => {
                let reg = r.uleb()? as u16;
                match row.cfa {
                    Cfa::RegOffset(_, off) => row.cfa = Cfa::RegOffset(reg, off),
                    Cfa::Expr(_) => return Err(Failure::BadCfaRule),
                }
            }
            0x0e => {
                let off = r.uleb()? as i64;
                match row.cfa {
                    Cfa::RegOffset(reg, _) => row.cfa = Cfa::RegOffset(reg, off),
                    Cfa::Expr(_) => return Err(Failure::BadCfaRule),
                }
            }
            0x0f => {
                let at = r.pos;
                let n = r.uleb()? as usize;
                r.skip(n)?;
                row.cfa = Cfa::Expr(at);
            }
            0x10 | 0x16 => {
                let reg = r.uleb()?;
                let at = r.pos;
                let n = r.uleb()? as usize;
                r.skip(n)?;
                set_rule(row, reg, if op == 0x10 { Rule::Expr(at) } else { Rule::ValExpr(at) })?;
            }
            0x11 => {
                let reg = r.uleb()?;
                let off = r.sleb()? * da;
                set_rule(row, reg, Rule::Offset(off))?;
            }
            0x12 => {
                let reg = r.uleb()? as u16;
                let off = r.sleb()? * da;
                row.cfa = Cfa::RegOffset(reg, off);
            }
            0x13 => {
                let off = r.sleb()? * da;
                match row.cfa {
                    Cfa::RegOffset(reg, _) => row.cfa = Cfa::RegOffset(reg, off),
                    Cfa::Expr(_) => return Err(Failure::BadCfaRule),
                }
            }
            0x14 => {
                let reg = r.uleb()?;
                let off = r.uleb()? as i64 * da;
                set_rule(row, reg, Rule::ValOffset(off))?;
            }
            0x15 => {
                let reg = r.uleb()?;
                let off = r.sleb()? * da;
                set_rule(row, reg, Rule::ValOffset(off))?;
            }
            0x2d => {
                // DW_CFA_AARCH64_negate_ra_state (DW_CFA_GNU_window_save on SPARC).
                if cfg!(target_arch = "aarch64") {
                    row.ra_signed = !row.ra_signed;
                } else {
                    return Err(Failure::UnsupportedCfa);
                }
            }
            0x2e => {
                // DW_CFA_GNU_args_size. Part of the row, so remember_state and
                // restore_state carry it, as in LLVM libunwind.
                row.args_size = r.uleb()? as usize;
            }
            0x2f => {
                let reg = r.uleb()?;
                let off = -(r.uleb()? as i64) * da;
                set_rule(row, reg, Rule::Offset(off))?;
            }
            _ => return Err(Failure::UnsupportedCfa),
        }
    }
    Ok(())
}

/// Apply a row to `regs`, producing the caller state. Returns the new
/// register file; the caller pc is the value recovered for the RA column.
pub fn apply(row: &Row, regs: &Regs, ra_reg: u16) -> Result<Regs> {
    let cfa = match row.cfa {
        Cfa::RegOffset(reg, off) => (regs.get(reg)? as i64).wrapping_add(off) as usize,
        Cfa::Expr(at) => eval(at, regs, None)?,
    };
    if cfa == 0 {
        return Err(Failure::BadCfaRule);
    }
    let mut next = *regs;
    let mut ra_undefined = false;
    for col in 0..COLUMNS {
        let reg = arch::column_reg(col);
        let value = match row.rules[col] {
            Rule::Same => continue,
            Rule::Undefined => {
                if reg == ra_reg {
                    ra_undefined = true;
                }
                0
            }
            Rule::Offset(off) => unsafe { load::<usize>((cfa as i64).wrapping_add(off) as usize) },
            Rule::ValOffset(off) => (cfa as i64).wrapping_add(off) as usize,
            Rule::Register(other) => regs.get(other)?,
            Rule::Expr(at) => unsafe { load::<usize>(eval(at, regs, Some(cfa))?) },
            Rule::ValExpr(at) => eval(at, regs, Some(cfa))?,
        };
        next.set(reg, value)?;
    }
    // The CFA is by definition the stack pointer of the caller at the call.
    if !matches!(arch::column(arch::SP_COLUMN).map(|c| row.rules[c]), Some(Rule::Offset(_) | Rule::ValOffset(_) | Rule::Register(_) | Rule::Expr(_) | Rule::ValExpr(_))) {
        next.set_sp(cfa);
    }
    let ra = if ra_undefined { 0 } else { next.get(ra_reg)? };
    next.pc = Regs::strip_pac(ra);
    Ok(next)
}

const STACK: usize = 16;

/// Evaluate a CFI DWARF expression. `push` is the initial stack entry (the
/// CFA for register rules, nothing for a CFA expression).
pub fn eval(at: usize, regs: &Regs, push: Option<usize>) -> Result<usize> {
    let mut r = Reader { pos: at, end: usize::MAX };
    let n = r.uleb()? as usize;
    let mut r = Reader::new(r.pos, n);
    let mut stack = [0usize; STACK];
    let mut sp = 0usize;
    macro_rules! push {
        ($v:expr) => {{
            if sp >= STACK {
                return Err(Failure::UnsupportedDwarfOp);
            }
            stack[sp] = $v;
            sp += 1;
        }};
    }
    macro_rules! pop {
        () => {{
            if sp == 0 {
                return Err(Failure::UnsupportedDwarfOp);
            }
            sp -= 1;
            stack[sp]
        }};
    }
    if let Some(v) = push {
        push!(v);
    }
    while r.pos < r.end {
        let op = r.u8()?;
        match op {
            0x03 => push!(r.u64()? as usize),
            0x06 => {
                let a = pop!();
                push!(unsafe { load::<usize>(a) });
            }
            0x08 => push!(usize::from(r.u8()?)),
            0x09 => push!(r.u8()? as i8 as isize as usize),
            0x0a => push!(usize::from(r.u16()?)),
            0x0b => push!(r.u16()? as i16 as isize as usize),
            0x0c => push!(r.u32()? as usize),
            0x0d => push!(r.u32()? as i32 as isize as usize),
            0x0e => push!(r.u64()? as usize),
            0x0f => push!(r.u64()? as usize),
            0x10 => push!(r.uleb()? as usize),
            0x11 => push!(r.sleb()? as isize as usize),
            0x12 => {
                let a = pop!();
                push!(a);
                push!(a);
            }
            0x13 => {
                let _ = pop!();
            }
            0x14 => {
                if sp < 2 {
                    return Err(Failure::UnsupportedDwarfOp);
                }
                let a = stack[sp - 2];
                push!(a);
            }
            0x16 => {
                let a = pop!();
                let b = pop!();
                push!(a);
                push!(b);
            }
            0x1a | 0x1c | 0x1e | 0x21 | 0x22 | 0x24 | 0x25 | 0x27 => {
                let b = pop!();
                let a = pop!();
                push!(match op {
                    0x1a => a & b,
                    0x1c => a.wrapping_sub(b),
                    0x1e => a.wrapping_mul(b),
                    0x21 => a | b,
                    0x22 => a.wrapping_add(b),
                    0x24 => a.wrapping_shl(b as u32),
                    0x25 => a.wrapping_shr(b as u32),
                    _ => a ^ b,
                });
            }
            0x1f => {
                let a = pop!();
                push!((a as isize).wrapping_neg() as usize);
            }
            0x20 => {
                let a = pop!();
                push!(!a);
            }
            0x23 => {
                let a = pop!();
                push!(a.wrapping_add(r.uleb()? as usize));
            }
            0x30..=0x4f => push!(usize::from(op - 0x30)),
            0x70..=0x8f => {
                let off = r.sleb()?;
                let v = regs.get(u16::from(op - 0x70))?;
                push!((v as i64).wrapping_add(off) as usize);
            }
            0x92 => {
                let reg = r.uleb()? as u16;
                let off = r.sleb()?;
                let v = regs.get(reg)?;
                push!((v as i64).wrapping_add(off) as usize);
            }
            0x94 => {
                let size = r.u8()?;
                let a = pop!();
                push!(unsafe {
                    match size {
                        1 => usize::from(load::<u8>(a)),
                        2 => usize::from(load::<u16>(a)),
                        4 => load::<u32>(a) as usize,
                        8 => load::<u64>(a) as usize,
                        _ => return Err(Failure::UnsupportedDwarfOp),
                    }
                });
            }
            0x96 => {}
            _ => return Err(Failure::UnsupportedDwarfOp),
        }
    }
    let v = pop!();
    Ok(v)
}
