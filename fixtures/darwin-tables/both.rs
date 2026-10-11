// Linked only, never run: tools/check-darwin-tables.ts reads its tables.
std::arch::global_asm!(include_str!("both.s"), options(raw));

unsafe extern "C" {
    fn dt_eko();
}

fn main() {
    if std::env::args().count() > 99 {
        unsafe { dt_eko() }
    }
}
