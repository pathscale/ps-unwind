// DW_CFA_GNU_args_size at landing-pad install, executed (tools/args-run.ts).
// A panic unwinds through _ax_args (fixtures/args/args.s), whose call site
// has args_size 32 and a cleanup landing pad. The pad reports its sp
// relative to x29; the panic is then caught here. Prints one line:
//   caught=BOOL pad_sp=fpN
// Built against the system unwinder, against ps-unwind (--cfg ps), and
// against ps-unwind with an EKO version 2 table for _ax_args (--cfg v2).
use std::panic::catch_unwind;
use std::sync::atomic::{AtomicUsize, Ordering};

std::arch::global_asm!(include_str!("args.s"), options(raw));
// EKO version 2 table for _ax_args (tools/eko2-gen.ts output).
#[cfg(v2)]
std::arch::global_asm!(include_str!(env!("PS_EKO2_S")), options(raw));

unsafe extern "C-unwind" {
    fn ax_args(cb: extern "C-unwind" fn(usize)) -> usize;
}

static SP: AtomicUsize = AtomicUsize::new(0);
static FP: AtomicUsize = AtomicUsize::new(0);

#[unsafe(no_mangle)]
extern "C" fn ax_landed(exception: usize, sp: usize, fp: usize) -> usize {
    SP.store(sp, Ordering::Relaxed);
    FP.store(fp, Ordering::Relaxed);
    exception
}

extern "C-unwind" fn boom(_: usize) {
    panic!("args_size fixture");
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let caught = catch_unwind(|| unsafe { ax_args(boom) }).is_err();
    let d = SP.load(Ordering::Relaxed) as isize - FP.load(Ordering::Relaxed) as isize;
    println!("caught={} pad_sp=fp{:+}", caught, d);
}
