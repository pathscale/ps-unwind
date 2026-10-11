// Signal-frame fixture (tools/signal-check.ts). argv[1] picks the faulting
// function; the SIGILL handler walks with _Unwind_Backtrace and prints each
// frame as symbol+offset, the ip_before_insn flag and the frame stack
// pointer relative to the first frame, then _exit(0). Built twice: against
// the system unwinder and, with --cfg ps, against ps-unwind.
use std::ffi::{CStr, c_char, c_int, c_void};

std::arch::global_asm!(include_str!("sig.s"), options(raw));

unsafe extern "C" {
    fn sg_fault_first();
    fn sg_frameless32();
    fn sg_eko_fp();
    fn _Unwind_Backtrace(cb: extern "C" fn(*mut c_void, *mut c_void) -> c_int, arg: *mut c_void) -> c_int;
    fn _Unwind_GetIPInfo(ctx: *mut c_void, before: *mut c_int) -> usize;
    fn _Unwind_GetCFA(ctx: *mut c_void) -> usize;
    fn dladdr(addr: *const c_void, info: *mut DlInfo) -> c_int;
    fn sigaction(sig: c_int, act: *const SigAction, old: *mut SigAction) -> c_int;
    fn _exit(code: c_int) -> !;
}

#[cfg(ps)]
unsafe extern "C" {
    fn ps_unwind_signal_enter();
    fn ps_unwind_last_failure(pc: *mut usize) -> u32;
    fn ps_unwind_backtrace_ucontext(uc: *const c_void, cb: extern "C" fn(*mut c_void, *mut c_void) -> c_int, arg: *mut c_void) -> c_int;
}

#[repr(C)]
struct DlInfo {
    fname: *const c_char,
    fbase: *mut c_void,
    sname: *const c_char,
    saddr: *mut c_void,
}

#[repr(C)]
struct SigAction {
    handler: usize,
    mask: u32,
    flags: c_int,
}

const SIGILL: c_int = 4;
const SA_SIGINFO: c_int = 0x40;
const MAX: usize = 64;

static mut FRAMES: [(usize, c_int, usize); MAX] = [(0, 0, 0); MAX];
static mut COUNT: usize = 0;

extern "C" fn trace(ctx: *mut c_void, _arg: *mut c_void) -> c_int {
    unsafe {
        let n = COUNT;
        if n == MAX {
            return 9;
        }
        let mut before = 0;
        let ip = _Unwind_GetIPInfo(ctx, &mut before);
        FRAMES[n] = (ip, before, _Unwind_GetCFA(ctx));
        COUNT = n + 1;
    }
    0
}

fn name(ip: usize) -> String {
    let mut i = DlInfo { fname: std::ptr::null(), fbase: std::ptr::null_mut(), sname: std::ptr::null(), saddr: std::ptr::null_mut() };
    if unsafe { dladdr(ip as *const c_void, &mut i) } == 0 || i.sname.is_null() {
        return "?".into();
    }
    let s = unsafe { CStr::from_ptr(i.sname) }.to_string_lossy().into_owned();
    format!("{s}+{:#x}", ip - i.saddr as usize)
}

fn print(tag: &str, rel: usize) {
    let n = unsafe { COUNT };
    let frames = unsafe { &*std::ptr::addr_of!(FRAMES) };
    let base = if n > rel { frames[rel].2 } else { 0 };
    for (i, &(ip, before, sp)) in frames[..n].iter().enumerate() {
        println!("{tag} #{i} {} before_insn={before} sp={:+}", name(ip), sp as isize - base as isize);
    }
    unsafe { COUNT = 0 };
}

extern "C" fn on_sigill(_sig: c_int, _info: *mut c_void, uc: *mut c_void) {
    #[cfg(ps)]
    unsafe { ps_unwind_signal_enter() };
    let rc = unsafe { _Unwind_Backtrace(trace, std::ptr::null_mut()) };
    // Printing allocates; the walks are over and the process exits next.
    // Through _sigtramp: stack pointers relative to the _sigtramp frame (#1),
    // because frame #0 (this handler) differs between the two builds.
    print("tramp", 1);
    println!("tramp end rc={rc}");
    #[cfg(ps)]
    {
        let rc = unsafe { ps_unwind_backtrace_ucontext(uc, trace, std::ptr::null_mut()) };
        print("uc", 0);
        let mut pc = 0usize;
        let code = unsafe { ps_unwind_last_failure(&mut pc) };
        println!("uc end rc={rc} last_failure={code} at={}", if code == 0 { "-".into() } else { name(pc) });
    }
    let _ = uc;
    unsafe { _exit(0) }
}

#[inline(never)]
fn caller(mode: &str) {
    match mode {
        "first" => unsafe { sg_fault_first() },
        "frameless" => unsafe { sg_frameless32() },
        "eko" => unsafe { sg_eko_fp() },
        _ => panic!("mode"),
    }
    std::hint::black_box(());
}

fn main() {
    let mode = std::env::args().nth(1).expect("mode");
    let act = SigAction { handler: on_sigill as *const () as usize, mask: 0, flags: SA_SIGINFO };
    assert_eq!(unsafe { sigaction(SIGILL, &act, std::ptr::null_mut()) }, 0);
    caller(std::hint::black_box(&mode));
    println!("no fault");
}
