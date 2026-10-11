// Image cache fixture (tools/cache-check.ts). Linked with ps_unwind.o; prints
// raw counters, the runner judges. argv[1] is the plug dylib path.
use std::ffi::{CString, c_char, c_int, c_void};

unsafe extern "C" {
    fn ps_unwind_cache_stats(out: *mut usize);
    fn ps_unwind_last_failure(pc: *mut usize) -> u32;
    fn _Unwind_FindEnclosingFunction(pc: *mut c_void) -> *mut c_void;
    fn _dyld_image_count() -> u32;
    fn dlopen(path: *const c_char, mode: c_int) -> *mut c_void;
    fn dlsym(h: *mut c_void, name: *const c_char) -> *mut c_void;
    fn dlclose(h: *mut c_void) -> c_int;
}

fn stats(tag: &str) {
    let mut s = [0usize; 6];
    unsafe { ps_unwind_cache_stats(s.as_mut_ptr()) };
    let images = unsafe { _dyld_image_count() };
    println!("{tag} entries={} publishes={} freed={} pending={} slot={} signal={} dyld_images={images}", s[0], s[1], s[2], s[3], s[4], s[5]);
}

fn enclosing(tag: &str, f: *mut c_void) {
    let start = unsafe { _Unwind_FindEnclosingFunction(f) };
    let mut pc = 0usize;
    let code = unsafe { ps_unwind_last_failure(&mut pc) };
    println!("{tag} fn={f:p} enclosing={start:p} last_failure={code}");
}


// Readers look up a function of this image while the main thread loads and
// unloads the plug. Run with MallocScribble=1 so a snapshot freed under a
// reader reads as 0x55 bytes and the lookup goes wrong.
fn stress(path: &str, cycles: usize) {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    static STOP: AtomicBool = AtomicBool::new(false);
    static LOOKUPS: AtomicUsize = AtomicUsize::new(0);
    static WRONG: AtomicUsize = AtomicUsize::new(0);
    let target = stats as *mut c_void as usize;
    let readers: Vec<_> = (0..3)
        .map(|_| {
            std::thread::spawn(move || {
                while !STOP.load(Ordering::Relaxed) {
                    let s = unsafe { _Unwind_FindEnclosingFunction(target as *mut c_void) } as usize;
                    if s != target {
                        WRONG.fetch_add(1, Ordering::Relaxed);
                    }
                    LOOKUPS.fetch_add(1, Ordering::Relaxed);
                }
            })
        })
        .collect();
    let c = CString::new(path).unwrap();
    for _ in 0..cycles {
        let h = unsafe { dlopen(c.as_ptr(), 2) };
        assert!(!h.is_null(), "dlopen failed");
        unsafe { dlclose(h) };
    }
    STOP.store(true, Ordering::Relaxed);
    for r in readers {
        r.join().unwrap();
    }
    println!("stress cycles={cycles} lookups={} wrong={}", LOOKUPS.load(Ordering::Relaxed), WRONG.load(Ordering::Relaxed));
    stats("stressed");
}

fn main() {
    let path = std::env::args().nth(1).expect("plug path");
    if let Some(n) = std::env::args().nth(2) {
        return stress(&path, n.parse().unwrap());
    }
    stats("start");
    let c = CString::new(path).unwrap();
    let h = unsafe { dlopen(c.as_ptr(), 2) };
    assert!(!h.is_null(), "dlopen failed");
    let f = unsafe { dlsym(h, c"plug_fn".as_ptr()) };
    stats("opened");
    enclosing("opened", f);
    let rc = unsafe { dlclose(h) };
    println!("dlclose rc={rc}");
    stats("closed");
    enclosing("closed", f);

}
