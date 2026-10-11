// Shared-object probe for tools/check-crt.ts: one exported function.
#![no_std]
#[unsafe(no_mangle)]
pub extern "C" fn crt_probe() -> usize {
    1
}
