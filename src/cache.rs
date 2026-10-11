//! Lock-free image cache: which loaded image holds a pc, and where its
//! unwind tables are. docs/DESIGN.md, "Image cache".
//!
//! Readers (every unwind step) pin the ps-reclaim Domain through one
//! ReaderSlot registered by the constructor (Domain::pin_reader: at most
//! MAX_NESTED_PINS compare-and-swaps or one fetch_add, and a fence), load
//! CURRENT, binary search, copy the entry and drop the guard (one store).
//! They allocate nothing, take no lock, touch no thread-local storage and
//! make no call, so a crash handler on any thread, or one that interrupted
//! a lookup on its own thread, can read the cache.
//!
//! Writers (dyld add/remove callbacks on Darwin; the init snapshot and the
//! refresh on a miss outside signal context on Linux) hold WRITER, build a
//! new sorted array, swap it in, and retire the old one into the Domain.
//! Domain::advance frees a retired snapshot only once no reader pinned
//! before the swap is still pinned.
//!
//! Readers never use Domain::pin: its first pin on a thread registers that
//! thread, which takes the registry lock and allocates (check-nostd R6).

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicUsize, Ordering};

use ps_reclaim::{Domain, ReaderSlot};

use crate::failure::{Failure, Result};
use crate::find::{self, Entry};

struct Snapshot {
    entries: Box<[Entry]>,
}

static CURRENT: AtomicPtr<Snapshot> = AtomicPtr::new(ptr::null_mut());
/// The one reader registration every lookup pins through, from any thread
/// or signal handler. Registered (may lock and allocate) before DOMAIN is
/// published, never in signal context.
static SLOT: AtomicPtr<ReaderSlot> = AtomicPtr::new(ptr::null_mut());
static SIGNAL: AtomicUsize = AtomicUsize::new(0);
static WRITER: AtomicBool = AtomicBool::new(false);
static DOMAIN: AtomicPtr<Domain> = AtomicPtr::new(ptr::null_mut());
static PUBLISHED: AtomicUsize = AtomicUsize::new(0);
static FREED: AtomicUsize = AtomicUsize::new(0);

const NONE: u8 = 0;
const BUILDING: u8 = 1;
const READY: u8 = 2;
static STATE: AtomicU8 = AtomicU8::new(NONE);

/// Entries collected while the initial fill runs (Darwin: dyld calls the
/// add-image callback once per loaded image during registration). Only
/// touched with WRITER held.
struct Staging(UnsafeCell<Option<Vec<Entry>>>);
unsafe impl Sync for Staging {}
static STAGING: Staging = Staging(UnsafeCell::new(None));

/// Process-wide signal-context flag. Set by a crash handler through
/// ps_unwind_signal_enter / ps_unwind_signal_leave. One atomic load per
/// query, no syscall (a sigaltstack(2) probe would be a syscall per step and
/// misses handlers that run on the normal stack). It is process-wide, so
/// while any thread is in a handler every thread is treated as being in one:
/// conservative, never unsafe.
pub fn in_signal_context() -> bool {
    SIGNAL.load(Ordering::SeqCst) != 0
}

pub fn signal_enter() {
    SIGNAL.fetch_add(1, Ordering::SeqCst);
}

pub fn signal_leave() {
    let _ = SIGNAL.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
}

/// The entry whose [start, end) holds `pc`, copied out of the current
/// snapshot. Lock-free, allocation-free, async-signal-safe.
pub fn lookup(pc: usize) -> Option<Entry> {
    // DOMAIN is stored after SLOT and before the first publish, so a null
    // DOMAIN means no snapshot exists yet.
    let d = DOMAIN.load(Ordering::Acquire);
    if d.is_null() {
        return None;
    }
    let (domain, slot) = unsafe { (&*d, &*SLOT.load(Ordering::Acquire)) };
    let _pin = domain.pin_reader(slot);
    let p = CURRENT.load(Ordering::SeqCst);
    if p.is_null() { None } else { search(&unsafe { &*p }.entries, pc) }
}

fn search(entries: &[Entry], pc: usize) -> Option<Entry> {
    let i = entries.partition_point(|e| e.start <= pc);
    if i == 0 {
        return None;
    }
    let e = entries[i - 1];
    if pc < e.end { Some(e) } else { None }
}

/// Build the cache if it is not built. Outside signal context this may
/// allocate and take the loader lock; in signal context it refuses.
pub fn ensure_ready() -> Result<()> {
    if STATE.load(Ordering::Acquire) == READY {
        return Ok(());
    }
    if in_signal_context() {
        return Err(Failure::SignalContextMiss);
    }
    if STATE.compare_exchange(NONE, BUILDING, Ordering::AcqRel, Ordering::Acquire).is_ok() {
        {
            let _w = lock();
            if DOMAIN.load(Ordering::Relaxed).is_null() {
                SLOT.store(Box::into_raw(Box::new(ReaderSlot::register())), Ordering::Release);
                DOMAIN.store(Box::into_raw(Box::new(Domain::new())), Ordering::Release);
            }
            unsafe { *STAGING.0.get() = Some(Vec::with_capacity(64)) };
        }
        find::fill();
        {
            let _w = lock();
            let v = unsafe { (*STAGING.0.get()).take() }.unwrap_or_default();
            publish(v);
        }
        STATE.store(READY, Ordering::Release);
    } else {
        while STATE.load(Ordering::Acquire) != READY {
            core::hint::spin_loop();
        }
    }
    Ok(())
}

pub fn is_ready() -> bool {
    STATE.load(Ordering::Acquire) == READY
}

struct WriterGuard;

impl Drop for WriterGuard {
    fn drop(&mut self) {
        WRITER.store(false, Ordering::Release);
    }
}

fn lock() -> WriterGuard {
    while WRITER.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
    WriterGuard
}

/// Apply a change. During the initial fill it goes to the staging list;
/// afterwards the current array is copied, changed and swapped in.
pub fn update(change: impl FnOnce(&mut Vec<Entry>)) {
    let _w = lock();
    if let Some(v) = unsafe { (*STAGING.0.get()).as_mut() } {
        change(v);
        return;
    }
    let p = CURRENT.load(Ordering::Acquire);
    let mut v = if p.is_null() { Vec::new() } else { unsafe { &*p }.entries.to_vec() };
    change(&mut v);
    publish(v);
}

/// Replace the whole array (Linux refresh).
pub fn replace(v: Vec<Entry>) {
    let _w = lock();
    publish(v);
}

struct Retired(usize);

fn publish(mut v: Vec<Entry>) {
    v.sort_unstable_by_key(|e| e.start);
    v.dedup_by_key(|e| e.start);
    let new = Box::into_raw(Box::new(Snapshot { entries: v.into_boxed_slice() }));
    let old = CURRENT.swap(new, Ordering::SeqCst);
    PUBLISHED.fetch_add(1, Ordering::Relaxed);
    let d = DOMAIN.load(Ordering::Relaxed);
    if d.is_null() {
        return;
    }
    let domain = unsafe { &*d };
    if !old.is_null() {
        let r = Retired(old as usize);
        domain.retire(move || {
            drop(unsafe { Box::from_raw(r.0 as *mut Snapshot) });
            FREED.fetch_add(1, Ordering::Relaxed);
        });
    }
    collect(domain);
}

/// Free retired snapshots no pinned reader can still hold. Called with
/// WRITER held, after a swap; advance skips what a pin still protects.
fn collect(domain: &Domain) {
    for _ in 0..4 {
        if domain.pending() == 0 {
            break;
        }
        domain.advance();
    }
}

/// entries, publishes, retired snapshots freed, retired snapshots pending,
/// 1 once the reader slot is registered, signal depth. Outside signal context only
/// (pending takes the ps-reclaim garbage lock).
pub fn stats() -> [usize; 6] {
    let _w = lock();
    let p = CURRENT.load(Ordering::Acquire);
    let n = if p.is_null() { 0 } else { unsafe { &*p }.entries.len() };
    let d = DOMAIN.load(Ordering::Relaxed);
    let pending = if d.is_null() { 0 } else { unsafe { (*d).pending() } };
    [
        n,
        PUBLISHED.load(Ordering::Relaxed),
        FREED.load(Ordering::Relaxed),
        pending,
        !SLOT.load(Ordering::Acquire).is_null() as usize,
        SIGNAL.load(Ordering::SeqCst),
    ]
}

extern "C" fn ctor() {
    let _ = ensure_ready();
}

// Build the cache before main, so that a crash handler finds it ready.
#[cfg(target_vendor = "apple")]
#[used]
#[unsafe(link_section = "__DATA,__mod_init_func,mod_init_funcs")]
static CTOR: extern "C" fn() = ctor;

#[cfg(target_os = "linux")]
#[used]
#[unsafe(link_section = ".init_array")]
static CTOR: extern "C" fn() = ctor;
