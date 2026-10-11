// Signal-frame fixture (tools/signal-check.ts). argv[1] picks the faulting
// function; the SIGILL handler walks with _Unwind_Backtrace and prints each
// frame as symbol+offset, the ip_before_insn flag and the frame stack
// pointer relative to the first frame, then _exit(0). Built twice: against
// the system unwinder and, with --cfg ps, against ps-unwind.
use std::ffi::{CStr, c_char, c_int, c_void};

std::arch::global_asm!(include_str!("sig.s"), options(raw));
// EKO version 2 table for sg_v2_* (tools/eko2-gen.ts output).
#[cfg(v2)]
std::arch::global_asm!(include_str!(env!("PS_EKO2_S")), options(raw));

unsafe extern "C" {
    fn sg_fault_first();
    fn sg_frameless32();
    fn sg_eko_fp();
    fn sg_v2_fp();
    fn sg_v2_leaf();
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
    fn ps_unwind_signal_leave();
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

// v2 modes: the handler records the walks of every fault, steps over the
// udf and returns, so one call of the fixture faults at every prologue and
// epilogue step. The truth is the hardware state at the first fault (the
// function entry): lr, sp, x19, x20, x29 and d8 are what the caller frame
// must get back at every later fault.
const FAULTS: usize = 16;
const DEPTH: usize = 12;
static mut V2_ON: bool = false;
static mut V2_COUNT: usize = 0;
// Per fault, per frame: ip, before_insn, CFA, x19, x20, x29, d8.
static mut V2_UC: [[[usize; 7]; DEPTH]; FAULTS] = [[[0; 7]; DEPTH]; FAULTS];
static mut V2_UCN: [usize; FAULTS] = [0; FAULTS];
static mut V2_END: [(c_int, u32); FAULTS] = [(0, 0); FAULTS];
static mut V2_TRUTH: [usize; 6] = [0; 6];

#[cfg(ps)]
extern "C" fn trace_v2(ctx: *mut c_void, arg: *mut c_void) -> c_int {
    unsafe {
        let k = arg as usize;
        let n = V2_UCN[k];
        if n == DEPTH {
            return 9;
        }
        let mut before = 0;
        let ip = _Unwind_GetIPInfo(ctx, &mut before);
        // The ps-unwind context starts with its register file
        // (src/arch/aarch64.rs): x0..x30 at 8 * i, d8 at byte 264.
        let r = ctx as *const usize;
        V2_UC[k][n] = [ip, before as usize, _Unwind_GetCFA(ctx), *r.add(19), *r.add(20), *r.add(29), *r.add(33)];
        V2_UCN[k] = n + 1;
    }
    0
}

unsafe fn v2_fault(uc: *mut c_void) {
    unsafe {
        // Darwin: uc_mcontext at 48; __ss after the 16-byte __es: x0..x28,
        // fp, lr, sp, pc; __ns (v0..v31, 16 bytes each) at 288.
        let mc = *((uc as usize + 48) as *const usize);
        let gp = mc + 16;
        let x = |i: usize| *((gp + 8 * i) as *const usize);
        let k = V2_COUNT;
        if k < FAULTS {
            if k == 0 {
                V2_TRUTH = [x(30), x(31), x(19), x(20), x(29), *((mc + 288 + 16 * 8) as *const usize)];
            }
            #[cfg(ps)]
            {
                let rc = ps_unwind_backtrace_ucontext(uc, trace_v2, k as *mut c_void);
                let mut pc = 0usize;
                V2_END[k] = (rc, ps_unwind_last_failure(&mut pc));
            }
            V2_COUNT = k + 1;
        }
        // Step over the udf and go on.
        *((gp + 32 * 8) as *mut usize) += 4;
        #[cfg(ps)]
        ps_unwind_signal_leave();
    }
}

fn v2_report(func: &str) {
    let (k, t) = unsafe { (V2_COUNT, V2_TRUTH) };
    let uc = unsafe { &*std::ptr::addr_of!(V2_UC) };
    let ucn = unsafe { &*std::ptr::addr_of!(V2_UCN) };
    let end = unsafe { &*std::ptr::addr_of!(V2_END) };
    println!("v2 {func} faults={k} truth ra={}", name(t[0]));
    let ok = |c: bool| if c { "ok" } else { "BAD" };
    let key = |f: &[[usize; 7]]| f.iter().map(|x| (x[0], x[2])).collect::<Vec<_>>();
    for i in 0..k {
        let f = &uc[i][..ucn[i]];
        let f0 = f.first().map_or("-".to_string(), |x| format!("{} b={}", name(x[0]), x[1]));
        let one = f.get(1).copied().unwrap_or([0; 7]);
        let ra = if one[0] == t[0] { "ok".to_string() } else { format!("BAD({})", name(one[0])) };
        let sp = if one[2] == t[1] { "ok".to_string() } else { format!("BAD({:+})", one[2] as isize - t[1] as isize) };
        let first = &uc[0][..ucn[0]];
        let callers = f.len() > 2 && f.len() == first.len() && key(&f[2..]) == key(&first[2..]);
        let fin = end[i] == end[0] && end[i].1 <= 3;
        println!(
            "v2 {func} #{i} {f0} ra={ra} sp={sp} x19={} x20={} x29={} d8={} callers={} end={} rc={} failure={}",
            ok(one[3] == t[2]), ok(one[4] == t[3]), ok(one[5] == t[4]), ok(one[6] == t[5]), ok(callers), ok(fin), end[i].0, end[i].1
        );
    }
    unsafe {
        V2_COUNT = 0;
        V2_UCN = [0; FAULTS];
    }
}

extern "C" fn on_sigill(_sig: c_int, _info: *mut c_void, uc: *mut c_void) {
    #[cfg(ps)]
    unsafe { ps_unwind_signal_enter() };
    if unsafe { V2_ON } {
        unsafe { v2_fault(uc) };
        return;
    }
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
        "v2fp" => {
            unsafe { V2_ON = true };
            unsafe { sg_v2_fp() };
            unsafe { V2_ON = false };
            v2_report("sg_v2_fp");
        }
        "v2leaf" => {
            unsafe { V2_ON = true };
            unsafe { sg_v2_leaf() };
            unsafe { V2_ON = false };
            v2_report("sg_v2_leaf");
        }
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
