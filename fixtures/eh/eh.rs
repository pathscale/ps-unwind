// Landing-pad fixture suite. Every frame named eh_* is a public symbol so that
// tools/eko-gen.ts can describe it with an EKO record (docs/FORMAT.md). The
// same program is linked twice, once on the system unwinder and once with
// ps-unwind force-loaded, and every case must print the same bytes and end
// with the same status (tools/eh.ts).
//
// Cases follow the Itanium two-phase model and Rust panic semantics: a call
// that propagates (no pad), cleanup pads that run drops and resume, catch
// pads (catch_unwind), a function that must not unwind (abort), a cleanup
// that panics (abort), and drop shapes that compile to different pads:
// enum variants, drop flags, shared ownership and niche-optimised options.
//
// The panic hook prints location and message only: the default hook prints
// the OS thread id, which differs between any two runs.

#[cfg(eko)]
std::arch::global_asm!(include_str!(env!("PS_EKO_S")), options(raw));

use std::cell::Cell;
use std::hint::black_box;
use std::panic::{self, AssertUnwindSafe, catch_unwind, panic_any, resume_unwind};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

static ABS: AtomicBool = AtomicBool::new(false);

pub struct Loud(&'static str);

impl Drop for Loud {
    fn drop(&mut self) {
        println!("drop {} panicking={}", self.0, std::thread::panicking());
    }
}

/// Panics in its destructor while the thread is already unwinding.
pub struct Bomb;

impl Drop for Bomb {
    fn drop(&mut self) {
        println!("bomb drop panicking={}", std::thread::panicking());
        panic!("bomb");
    }
}

/// Catches a panic inside its own destructor, during an unwind.
pub struct Absorber;

impl Drop for Absorber {
    fn drop(&mut self) {
        let r = catch_unwind(|| eh_throw("inside drop"));
        println!("absorber caught={} panicking={}", r.is_err(), std::thread::panicking());
    }
}

pub enum Shape {
    Empty,
    One(Loud),
    Two(Loud, Loud),
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_throw(what: &'static str) {
    if black_box(true) {
        panic!("{}", what);
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_step(fail: bool) {
    if black_box(fail) {
        eh_throw("step");
    }
    println!("step ok");
}

// pass-through: frames without pads between the panic and the catch.
#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_relay_2(n: u64) -> u64 {
    eh_throw("relay");
    black_box(n) + 1
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_relay_1(n: u64) -> u64 {
    eh_relay_2(black_box(n) * 3) + 7
}

// unwind-drops: a cleanup pad in each of two frames.
#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_guarded_inner() {
    let _g = Loud("inner");
    eh_throw("guarded");
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_guarded_outer() {
    let _g = Loud("outer");
    eh_guarded_inner();
    println!("not reached");
}

// two-sites: two calls in one frame whose pads differ (the second also
// drops `second`). The pad chosen for the wrong call site drops too little.
#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_two_sites() {
    let _a = Loud("first");
    eh_step(false);
    let _b = Loud("second");
    eh_step(true);
    println!("not reached");
}

// catch-local: the catch pad is in this frame, which then returns normally.
#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_catch_local() -> u32 {
    let _g = Loud("catch-local frame");
    let r = catch_unwind(|| {
        let _h = Loud("inside closure");
        eh_throw("caught locally");
        1u32
    });
    println!("local result err={}", r.is_err());
    if r.is_err() { 2 } else { 3 }
}

// rethrow: catch, then resume the same payload to the outer catch.
#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_rethrow() {
    let _g = Loud("rethrow frame");
    let r: Result<(), _> = catch_unwind(|| panic_any(41u32));
    if let Err(p) = r {
        println!("rethrowing");
        resume_unwind(p);
    }
}

// nounwind: a panic reaching an extern "C" frame must abort.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn eh_nounwind() {
    let _g = Loud("nounwind frame");
    eh_throw("into nounwind");
}

// cleanup-abort: a destructor that panics while unwinding must abort.
#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_bomb_frame() {
    let _l = Loud("before bomb");
    let _b = Bomb;
    eh_throw("lit fuse");
}

// drop-catches: a destructor that catches its own panic during an unwind.
#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_absorber_frame() {
    let _a = Absorber;
    eh_throw("outer of absorber");
}

// enum-shapes: the pad drops whichever variant is live.
#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_shapes(n: u32) {
    let s = match black_box(n) {
        0 => Shape::Empty,
        1 => Shape::One(Loud("one")),
        _ => Shape::Two(Loud("two-a"), Loud("two-b")),
    };
    eh_throw("shapes");
    drop(s);
}

// drop-flags: conditionally initialised locals; only the initialised one is
// dropped, which the pad decides from a runtime flag.
#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_flags(cond: bool) {
    let _x: Loud;
    let _y: Loud;
    if black_box(cond) {
        _x = Loud("x initialised");
    } else {
        _y = Loud("y initialised");
    }
    eh_throw("flags");
}

// shared: reference counts held in several frames; the last owner prints.
#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_shared_inner(r: Rc<Loud>, a: Arc<Loud>) {
    println!("inner rc={} arc={}", Rc::strong_count(&r), Arc::strong_count(&a));
    eh_throw("shared");
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_shared_outer() {
    let r = Rc::new(Loud("rc payload"));
    let a = Arc::new(Loud("arc payload"));
    eh_shared_inner(r.clone(), a.clone());
    drop((r, a));
}

// niche: options whose None is a niche of the payload.
#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_niche(some: bool) {
    let b: Option<Box<Loud>> = if black_box(some) { Some(Box::new(Loud("boxed"))) } else { None };
    let l: Option<Loud> = if black_box(!some) { Some(Loud("inline")) } else { None };
    let r: Option<&Cell<u32>> = None;
    eh_throw("niche");
    drop((b, l, r));
}

// callee-saved: values live in callee-saved registers across the unwind.
// eh_churn keeps its own values in the same registers, so its frame saves
// ours; a missing restore while unwinding it changes the checksum.
#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_churn_leaf(v: u64) -> u64 {
    if black_box(v) != 0 {
        eh_throw("churn");
    }
    v
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_churn(seed: u64) -> u64 {
    let v: [u64; 12] = core::array::from_fn(|i| black_box(seed.wrapping_mul(i as u64 + 13)));
    let mut acc = eh_churn_leaf(v[0]);
    for (i, x) in v.iter().enumerate() {
        acc = acc.rotate_left(i as u32 + 1) ^ x;
    }
    acc
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_keep(seed: u64) -> u64 {
    let v: [u64; 12] = core::array::from_fn(|i| black_box(seed.wrapping_add(i as u64 * 0x9e37)));
    let r = catch_unwind(|| eh_churn(seed ^ 0x55));
    let mut acc = r.is_err() as u64;
    for (i, x) in v.iter().enumerate() {
        acc = acc.rotate_left(i as u32 + 3) ^ x;
    }
    acc
}

// bt: a stack of eh_* frames walked with _Unwind_Backtrace (tools/eh.ts
// compares it with lldb).
unsafe extern "C" {
    fn _Unwind_Backtrace(f: extern "C" fn(*mut u8, *mut u8) -> u32, arg: *mut u8) -> u32;
    fn _Unwind_GetIP(ctx: *mut u8) -> usize;
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn eh_trace_cb(ctx: *mut u8, _arg: *mut u8) -> u32 {
    let ip = unsafe { _Unwind_GetIP(ctx) };
    // Relative to eh_throw, so two processes (two slides) print the same bytes;
    // bt-abs prints the address itself for the lldb comparison.
    if ABS.load(Ordering::Relaxed) {
        println!("uw ip 0x{:x}", ip);
    } else {
        println!("uw off {:+}", ip as isize - eh_throw as *const () as isize);
    }
    0
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_bt_leaf() -> u32 {
    let _g = Loud("bt leaf");
    unsafe { _Unwind_Backtrace(eh_trace_cb, core::ptr::null_mut()) }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn eh_bt_mid() -> u32 {
    let _g = Loud("bt mid");
    eh_bt_leaf() + black_box(1)
}

fn caught<F: FnOnce() -> R + panic::UnwindSafe, R>(f: F) {
    match catch_unwind(f) {
        Ok(_) => println!("returned"),
        Err(p) => {
            let what = p
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<u32>().map(|n| format!("u32 {}", n)))
                .unwrap_or_else(|| "?".into());
            println!("caught: {}", what);
        }
    }
}

pub const CASES: [&str; 16] = [
    "pass-through", "unwind-drops", "two-sites", "catch-local", "rethrow", "nounwind",
    "cleanup-abort", "drop-catches", "enum-shapes", "drop-flags", "shared", "niche-some",
    "niche-none", "callee-saved", "uncaught", "bt-run",
];

fn main() {
    panic::set_hook(Box::new(|info| {
        let msg = info
            .payload()
            .downcast_ref::<String>()
            .map(|s| s.as_str())
            .or_else(|| info.payload().downcast_ref::<&str>().copied())
            .unwrap_or("(non-string payload)");
        let at = info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
        eprintln!("panic at {}: {}", at, msg);
    }));
    let case = std::env::args().nth(1).unwrap_or_default();
    println!("case {}", case);
    match case.as_str() {
        "pass-through" => caught(|| eh_relay_1(5)),
        "unwind-drops" => caught(eh_guarded_outer),
        "two-sites" => caught(eh_two_sites),
        "catch-local" => caught(eh_catch_local),
        "rethrow" => caught(eh_rethrow),
        "nounwind" => caught(|| eh_nounwind()),
        "cleanup-abort" => caught(eh_bomb_frame),
        "drop-catches" => caught(eh_absorber_frame),
        "enum-shapes" => {
            for n in 0..3 {
                caught(move || eh_shapes(n));
            }
        }
        "drop-flags" => {
            caught(|| eh_flags(true));
            caught(|| eh_flags(false));
        }
        "shared" => caught(eh_shared_outer),
        "niche-some" => caught(|| eh_niche(true)),
        "niche-none" => caught(|| eh_niche(false)),
        "callee-saved" => {
            let mut out = 0u64;
            for s in 1..4u64 {
                out ^= eh_keep(black_box(s * 0x1234_5678_9abc));
            }
            println!("checksum 0x{:016x}", out);
        }
        "uncaught" => eh_guarded_outer(),
        "bt-abs" => {
            ABS.store(true, Ordering::Relaxed);
            let n = eh_bt_mid();
            println!("bt end {}", n);
        }
        "bt-run" => {
            let n = eh_bt_mid();
            println!("bt end {}", n);
        }
        "list" => println!("{}", CASES.join(" ")),
        _ => {
            eprintln!("unknown case");
            std::process::exit(2);
        }
    }
    let _ = AssertUnwindSafe(());
    println!("end");
}
