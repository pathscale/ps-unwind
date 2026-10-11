//! Finding the unwind tables that cover a pc.

#[cfg(target_vendor = "apple")]
mod darwin;
#[cfg(target_vendor = "apple")]
pub use darwin::*;

#[cfg(target_os = "linux")]
mod elf;
#[cfg(target_os = "linux")]
pub use elf::*;
