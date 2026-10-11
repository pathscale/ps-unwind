// Mixed-stack fixture: Rust frames (compact unwind), a libSystem frame
// (qsort, compact unwind), a DWARF-only frame with a 0x9b personality and an
// LSDA, and EKO frames (fixtures/mixed/fx.s). Runs only on ps-unwind: the
// system unwinder has no tables for EKO frames.
//
// Modes: regcheck, panic, bt. Output is address-free except in bt.

use std::ffi::c_void;
use std::panic::catch_unwind;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

std::arch::global_asm!(include_str!("fx.s"), options(raw));

type Cb = extern "C-unwind" fn(u64) -> u64;

#[repr(C)]
struct Pair {
    ex: *mut Foreign,
    mask: u64,
}

#[repr(C)]
struct Foreign {
    class: u64,
    cleanup: Option<unsafe extern "C" fn(u32, *mut Foreign)>,
    private: [usize; 2],
}

unsafe extern "C-unwind" {
    fn fx_dwarf(cb: Cb, arg: u64) -> u64;
    fn fx_eko_cleanup(cb: Cb, arg: u64) -> u64;
    fn fx_regcheck(cb: Cb, arg: u64) -> Pair;
    safe fn fx_compact(arg: u64) -> u64;
    fn qsort(base: *mut c_void, n: usize, width: usize, cmp: extern "C-unwind" fn(*const c_void, *const c_void) -> i32);
    fn _Unwind_RaiseException(e: *mut Foreign) -> u32;
}

unsafe extern "C" {
    fn _Unwind_Backtrace(f: extern "C" fn(*mut c_void, *mut c_void) -> u32, arg: *mut c_void) -> u32;
    fn _Unwind_GetIP(ctx: *mut c_void) -> usize;
    fn _Unwind_GetCFA(ctx: *mut c_void) -> usize;
}

static PANIC: AtomicBool = AtomicBool::new(false);
static TRACE: AtomicBool = AtomicBool::new(false);
static NFRAMES: AtomicUsize = AtomicUsize::new(0);
static mut FRAMES: [(usize, usize); 128] = [(0, 0); 128];

struct Noisy(&'static str);

impl Drop for Noisy {
    fn drop(&mut self) {
        println!("drop {}", self.0);
    }
}

#[unsafe(no_mangle)]
extern "C" fn fx_dwarf_landed(x20: u64, d8: u64) {
    println!("dwarf pad: x20 {} d8 {}", if x20 == 0xd0 { "ok" } else { "WRONG" }, if d8 == 0xd0 { "ok" } else { "WRONG" });
}

#[unsafe(no_mangle)]
extern "C" fn fx_eko_landed(pad: u64, x19: u64) {
    println!("eko pad {pad}: x19 {}", if x19 == 0xe0 { "ok" } else { "WRONG" });
}

#[unsafe(no_mangle)]
extern "C" fn fx_noop(x: u64) -> u64 {
    std::hint::black_box(x)
}

extern "C" fn fx_trace_cb(ctx: *mut c_void, _: *mut c_void) -> u32 {
    let n = NFRAMES.load(Ordering::Relaxed);
    if n < 128 {
        unsafe { FRAMES[n] = (_Unwind_GetIP(ctx), _Unwind_GetCFA(ctx)) };
        NFRAMES.store(n + 1, Ordering::Relaxed);
    }
    0
}

/// Force the compiler to save every callee-saved register it lets inline asm
/// name (x19 and x29 are reserved by LLVM; x19 is covered by the asm frames).
#[inline(always)]
fn scramble(v: u64) {
    unsafe {
        std::arch::asm!(
            "mov x20, {v}", "mov x21, {v}", "mov x22, {v}", "mov x23, {v}", "mov x24, {v}",
            "mov x25, {v}", "mov x26, {v}", "mov x27, {v}", "mov x28, {v}",
            "fmov d8, {v}", "fmov d9, {v}", "fmov d10, {v}", "fmov d11, {v}",
            "fmov d12, {v}", "fmov d13, {v}", "fmov d14, {v}", "fmov d15, {v}",
            v = in(reg) v,
            out("x20") _, out("x21") _, out("x22") _, out("x23") _, out("x24") _,
            out("x25") _, out("x26") _, out("x27") _, out("x28") _,
            out("d8") _, out("d9") _, out("d10") _, out("d11") _,
            out("d12") _, out("d13") _, out("d14") _, out("d15") _,
        );
    }
}

#[inline(never)]
extern "C-unwind" fn rust_raise(_: u64) -> u64 {
    let _g = Noisy("rust_raise");
    scramble(0x1111);
    if TRACE.load(Ordering::Relaxed) {
        unsafe { _Unwind_Backtrace(fx_trace_cb, std::ptr::null_mut()) };
    }
    if PANIC.load(Ordering::Relaxed) {
        panic!("panic through mixed frames");
    }
    let e = Box::leak(Box::new(Foreign { class: u64::from_be_bytes(*b"PSUWFXT\0"), cleanup: None, private: [0; 2] }));
    let rc = unsafe { _Unwind_RaiseException(e) };
    println!("raise returned {rc}");
    0
}

#[inline(never)]
extern "C-unwind" fn rust_cmp(a: *const c_void, b: *const c_void) -> i32 {
    let _g = Noisy("rust_cmp");
    scramble(0x2222);
    let r = unsafe { fx_eko_cleanup(rust_raise, 0xe0) };
    std::hint::black_box(r) as i32 + unsafe { *(a as *const i32) - *(b as *const i32) }
}

#[inline(never)]
extern "C-unwind" fn rust_b(_: u64) -> u64 {
    let _g = Noisy("rust_b");
    scramble(0x3333);
    let mut v = [4i32, 3, 2, 1];
    unsafe { qsort(v.as_mut_ptr().cast(), v.len(), 4, rust_cmp) };
    v[0] as u64
}

#[inline(never)]
extern "C-unwind" fn rust_a(_: u64) -> u64 {
    let _g = Noisy("rust_a");
    scramble(0x4444);
    unsafe { fx_dwarf(rust_b, 0xd0) }
}

fn mode_regcheck() {
    let p = unsafe { fx_regcheck(fx_compact, 0) };
    if p.ex.is_null() {
        println!("regcheck: no exception caught");
        return;
    }
    let class = unsafe { (*p.ex).class };
    println!("regcheck: caught class {} mask {:#x}", if class == u64::from_be_bytes(*b"PSUWFXT\0") { "fixture" } else { "WRONG" }, p.mask);
}

#[unsafe(no_mangle)]
extern "C-unwind" fn fx_compact_next(arg: u64) -> u64 {
    rust_a(arg)
}

fn mode_panic() {
    PANIC.store(true, Ordering::Relaxed);
    std::panic::set_hook(Box::new(|i| eprintln!("panic: {}", i.payload_as_str().unwrap_or("?"))));
    let r = catch_unwind(|| rust_a(0));
    match r {
        Ok(v) => println!("panic: returned {v}"),
        Err(e) => println!("panic: caught {:?}", e.downcast_ref::<&str>()),
    }
}

fn mode_bt() {
    TRACE.store(true, Ordering::Relaxed);
    mode_regcheck();
    let n = NFRAMES.load(Ordering::Relaxed);
    for i in 0..n {
        let (ip, cfa) = unsafe { FRAMES[i] };
        println!("uw {i} ip {ip:#x} cfa {cfa:#x}");
    }
}

#[repr(C)]
struct DlInfo {
    fname: *const std::ffi::c_char,
    fbase: *mut c_void,
    sname: *const std::ffi::c_char,
    saddr: *mut c_void,
}

unsafe extern "C" {
    fn dladdr(addr: *const c_void, info: *mut DlInfo) -> i32;
}

/// A plain _Unwind_Backtrace from main with no fixture frames, printed as
/// symbol+offset so that a system-unwinder build and a ps-unwind build can be
/// compared byte for byte, including where each stops.
#[inline(never)]
fn mode_btplain() {
    unsafe { _Unwind_Backtrace(fx_trace_cb, std::ptr::null_mut()) };
    let n = NFRAMES.load(Ordering::Relaxed);
    for i in 0..n {
        let (ip, _) = unsafe { FRAMES[i] };
        let mut info = DlInfo { fname: std::ptr::null(), fbase: std::ptr::null_mut(), sname: std::ptr::null(), saddr: std::ptr::null_mut() };
        let name = if unsafe { dladdr((ip - 1) as *const c_void, &mut info) } != 0 && !info.sname.is_null() {
            let s = unsafe { std::ffi::CStr::from_ptr(info.sname) }.to_string_lossy().into_owned();
            format!("{s}+{:#x}", ip - info.saddr as usize)
        } else {
            "?".to_string()
        };
        println!("bt {i} {name}");
    }
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("regcheck") => mode_regcheck(),
        Some("panic") => mode_panic(),
        Some("bt") => mode_bt(),
        Some("btplain") => mode_btplain(),
        _ => std::process::exit(2),
    }
}
