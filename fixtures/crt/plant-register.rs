// Plant for C3: an object that references __register_frame_info, as gcc's
// frame_dummy does.
#![no_std]
unsafe extern "C" {
    fn __register_frame_info(eh_frame: *const u8, object: *mut u8);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crt_plant() {
    unsafe { __register_frame_info(core::ptr::null(), core::ptr::null_mut()) }
}
