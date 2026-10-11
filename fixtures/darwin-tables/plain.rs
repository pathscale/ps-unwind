// A Darwin image as a compiler ships it: standard tables only, no __eko_unwind.
// tools/check-darwin-tables.ts --no-eko passes on it and fails D3 on both.rs.
use std::hint::black_box;

#[inline(never)]
fn thrower(n: u32) -> u32 {
    if black_box(n) > 2 {
        panic!("plain");
    }
    n
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(|| thrower(black_box(3)));
    assert!(r.is_err());
    println!("plain: caught");
}
