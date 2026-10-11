// A dylib with no TLS and no std, so dlclose really unmaps it.
#![no_std]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn plug_fn() -> u32 {
    7
}
