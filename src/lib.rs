//! ps-unwind: a no_std stack unwinder that provides the `_Unwind_*` boundary
//! used by Rust panic_unwind and std::backtrace.
//!
//! The crate reads the platform tables (Apple compact unwind, DWARF CFI in
//! `__eh_frame` / `.eh_frame`) and the versioned EKO compact table described in
//! docs/FORMAT.md. Nothing on the unwind path allocates, locks or makes a
//! syscall of its own; image lookup goes through a lock-free cache filled
//! outside the unwind path (src/cache.rs, docs/DESIGN.md "Image cache").

#![no_std]
#![allow(clippy::missing_safety_doc)]

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("ps-unwind supports aarch64 and x86_64 only");

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
compile_error!("ps-unwind supports Darwin and Linux only");

pub mod abi;
pub mod arch;
pub mod cache;
pub mod cfi;
#[cfg(target_vendor = "apple")]
pub mod compact;
pub mod eko;
pub mod failure;
pub mod find;
pub mod frame;
pub mod mem;

pub use failure::Failure;

/// The staticlib carries its own allocator for the image cache writers and
/// ps-reclaim: malloc, posix_memalign and free from libc. The rlib uses the
/// program allocator. Readers never allocate.
#[cfg(feature = "staticlib")]
mod malloc {
    use core::alloc::{GlobalAlloc, Layout};

    struct Malloc;

    unsafe impl GlobalAlloc for Malloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if layout.align() <= 16 {
                return unsafe { libc::malloc(layout.size()) }.cast();
            }
            let mut p = core::ptr::null_mut();
            let rc = unsafe { libc::posix_memalign(&mut p, layout.align(), layout.size()) };
            if rc == 0 { p.cast() } else { core::ptr::null_mut() }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
            unsafe { libc::free(ptr.cast()) }
        }
    }

    #[global_allocator]
    static ALLOCATOR: Malloc = Malloc;
}

#[cfg(feature = "staticlib")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // The unwinder never panics on purpose: every check returns a named
    // Failure. A panic here is a bug in ps-unwind, and unwinding out of the
    // unwinder is not an option.
    failure::fatal(b"ps-unwind: internal panic\n")
}
