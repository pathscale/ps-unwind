//! Bounded reads of mapped image memory and the DW_EH_PE pointer decoder.
//!
//! Addresses are plain usize values: the tables live in loaded images, and the
//! reader never holds a reference into them, so there is no lifetime to get
//! wrong and nothing that could be freed underneath a walk.

use crate::failure::{Failure, Result};

/// Read a value of type T at an arbitrary (possibly unaligned) address.
#[inline(always)]
pub unsafe fn load<T: Copy>(addr: usize) -> T {
    unsafe { core::ptr::read_unaligned(addr as *const T) }
}

/// A cursor over [pos, end) in mapped memory.
#[derive(Clone, Copy)]
pub struct Reader {
    pub pos: usize,
    pub end: usize,
}

/// Bases for DW_EH_PE_textrel and DW_EH_PE_datarel. Zero means "not known",
/// and an encoding that needs an unknown base is a BadPointerEncoding.
#[derive(Clone, Copy, Default)]
pub struct Bases {
    pub text: usize,
    pub data: usize,
    pub func: usize,
}

pub const DW_EH_PE_OMIT: u8 = 0xff;
pub const DW_EH_PE_INDIRECT: u8 = 0x80;

impl Reader {
    pub fn new(pos: usize, len: usize) -> Reader {
        Reader { pos, end: pos.wrapping_add(len) }
    }

    #[inline]
    fn take(&mut self, n: usize) -> Result<usize> {
        let at = self.pos;
        let next = at.checked_add(n).ok_or(Failure::BadCieFde)?;
        if next > self.end {
            return Err(Failure::BadCieFde);
        }
        self.pos = next;
        Ok(at)
    }

    pub fn u8(&mut self) -> Result<u8> {
        let at = self.take(1)?;
        Ok(unsafe { load::<u8>(at) })
    }

    pub fn u16(&mut self) -> Result<u16> {
        let at = self.take(2)?;
        Ok(unsafe { load::<u16>(at) })
    }

    pub fn u32(&mut self) -> Result<u32> {
        let at = self.take(4)?;
        Ok(unsafe { load::<u32>(at) })
    }

    pub fn u64(&mut self) -> Result<u64> {
        let at = self.take(8)?;
        Ok(unsafe { load::<u64>(at) })
    }

    pub fn uleb(&mut self) -> Result<u64> {
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            if shift < 64 {
                result |= u64::from(byte & 0x7f) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
        }
    }

    pub fn sleb(&mut self) -> Result<i64> {
        let mut result = 0i64;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            if shift < 64 {
                result |= i64::from(byte & 0x7f) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 64 && byte & 0x40 != 0 {
                    result |= -1i64 << shift;
                }
                return Ok(result);
            }
        }
    }

    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.take(n).map(|_| ())
    }

    /// Decode one DW_EH_PE encoded pointer.
    ///
    /// The low nibble is the value format, bits 4..6 the application (what the
    /// value is relative to) and bit 7 says the result is the address of the
    /// pointer rather than the pointer. 0x9b, the form Darwin arm64 uses for a
    /// personality routine, is indirect | pcrel | sdata4: a 32-bit signed
    /// offset from the field to a GOT cell holding the routine address.
    pub fn encoded(&mut self, encoding: u8, bases: &Bases) -> Result<usize> {
        if encoding == DW_EH_PE_OMIT {
            return Err(Failure::BadPointerEncoding);
        }
        let field = self.pos;
        // DW_EH_PE_aligned: the value is pointer aligned and absolute.
        if encoding & 0x70 == 0x50 {
            let size = core::mem::size_of::<usize>();
            let aligned = (self.pos + size - 1) & !(size - 1);
            self.pos = aligned;
            let v = self.u64()? as usize;
            return Ok(v);
        }
        let raw: usize = match encoding & 0x0f {
            0x00 => {
                if core::mem::size_of::<usize>() == 8 {
                    self.u64()? as usize
                } else {
                    self.u32()? as usize
                }
            }
            0x01 => self.uleb()? as usize,
            0x02 => usize::from(self.u16()?),
            0x03 => self.u32()? as usize,
            0x04 => self.u64()? as usize,
            0x09 => self.sleb()? as isize as usize,
            0x0a => self.u16()? as i16 as isize as usize,
            0x0b => self.u32()? as i32 as isize as usize,
            0x0c => self.u64()? as i64 as isize as usize,
            _ => return Err(Failure::BadPointerEncoding),
        };
        let base = match encoding & 0x70 {
            0x00 => 0,
            0x10 => field,
            0x20 if bases.text != 0 => bases.text,
            0x30 if bases.data != 0 => bases.data,
            0x40 if bases.func != 0 => bases.func,
            _ => return Err(Failure::BadPointerEncoding),
        };
        let mut value = base.wrapping_add(raw);
        if encoding & DW_EH_PE_INDIRECT != 0 {
            if value == 0 || value % core::mem::align_of::<usize>() != 0 {
                return Err(Failure::BadPointerEncoding);
            }
            value = unsafe { load::<usize>(value) };
        }
        Ok(value)
    }
}

/// The size in bytes of an encoded value whose size does not depend on its
/// contents, used for the pc_range field of an FDE (format only, no base).
pub fn encoded_range(r: &mut Reader, encoding: u8) -> Result<usize> {
    let plain = encoding & 0x0f;
    r.encoded(plain, &Bases::default())
}
