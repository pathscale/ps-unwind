//! The only architecture-specific code: the register file, the DWARF register
//! numbering, the entry trampolines that capture the caller state, and the
//! jump that installs a landing-pad context.
//!
//! INLINE ASM: an unwinder cannot be written without it. Reading the caller
//! registers at the boundary and loading a whole register file before a jump
//! are not expressible in Rust. Each architecture keeps both pieces in one
//! file, and nothing else in the crate contains assembly.

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;
