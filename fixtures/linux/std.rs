fn main() { let r = std::panic::catch_unwind(|| panic!("x")); println!("{}", r.is_err()); println!("{}", std::backtrace::Backtrace::force_capture()); }
