//! crt: the start objects that replace gcc's crtbegin*.o and crtend*.o on
//! Linux (aarch64 and x86_64, gnu and musl). Written from the System V gABI,
//! the AArch64 and x86-64 psABIs and the Itanium C++ ABI (3.3.5, DSO object
//! destruction: __dso_handle and __cxa_atexit).
//!
//! One source, built by tools/crt-build.sh into four objects:
//!   --cfg crt_begin                    crtbegin.o   executable, __dso_handle = 0
//!   --cfg crt_begin --cfg crt_shared crtbeginS.o shared object, __dso_handle = &__dso_handle
//!   --cfg crt_end [--cfg crt_shared] crtend.o, crtendS.o: empty on purpose
//!
//! What is deliberately absent (docs/CRT.md has the measurement):
//!   frame_dummy and any __register_frame_info / __deregister_frame_info call:
//!     ps-unwind finds frames through PT_GNU_EH_FRAME.
//!   .ctors/.dtors sentinels and __do_global_dtors_aux: .init_array/.fini_array
//!     are run by the loader or libc.
//!   __TMC_END__ and transactional-memory clone registration.
//!   The zero terminator after .eh_frame: no consumer needs it. ps-unwind's
//!     linear scan (cfi::scan) is bounded by the section length it is given.
#![no_std]
#![allow(non_upper_case_globals)]

/// The handle's address identifies this image to __cxa_atexit and
/// __cxa_thread_atexit_impl; its value is never read by the C library.
#[cfg(crt_begin)]
#[repr(transparent)]
pub struct DsoHandle(*const DsoHandle);

#[cfg(crt_begin)]
unsafe impl Sync for DsoHandle {}

/// Executable: 0, so it needs no relocation.
#[cfg(all(crt_begin, not(crt_shared)))]
#[unsafe(no_mangle)]
#[used]
pub static __dso_handle: DsoHandle = DsoHandle(core::ptr::null());

/// Shared object: its own address, so every image carries a distinct value.
#[cfg(all(crt_begin, crt_shared))]
#[unsafe(no_mangle)]
#[used]
pub static __dso_handle: DsoHandle = DsoHandle(&__dso_handle);

// The gABI requires each image to bind its own __dso_handle, so it must not
// be exported or preempted: STV_HIDDEN. Stable Rust has no visibility
// attribute for a static, so this one assembler directive sets it on the
// symbol defined above (same object, same symbol table). It emits no code.
#[cfg(crt_begin)]
core::arch::global_asm!(".hidden __dso_handle");
