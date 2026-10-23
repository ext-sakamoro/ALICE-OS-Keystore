//! Test-only allocator that reports whether one chosen block was all zero when
//! freed (lets a test observe what a `Drop` left behind)
//!
//! It forwards every call to the system allocator. A test arms it with the
//! address of a heap block, drops the owner, and reads the verdict. Only the
//! lib's unit-test binary installs it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::Mutex;

/// The address being watched (0 = none)
static WATCH: AtomicUsize = AtomicUsize::new(0);
/// 0 = not freed yet, 1 = freed all zero, 2 = freed with a non-zero byte
static VERDICT: AtomicU8 = AtomicU8::new(0);
/// One watched drop at a time (the statics are process-wide)
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

pub(crate) struct WatchAlloc;

// SAFETY: every call is passed through to the system allocator unchanged. In
// `dealloc` the block at `ptr` is still owned by this call and valid for reads
// of `layout.size()` bytes until it is handed to `System.dealloc`.
unsafe impl GlobalAlloc for WatchAlloc {
    // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract; the call is forwarded unchanged
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as above
        unsafe { System.alloc(layout) }
    }

    // SAFETY: the caller upholds `GlobalAlloc::dealloc`'s contract (`ptr` came from `alloc` with `layout`)
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr as usize == WATCH.load(Ordering::SeqCst) {
            // SAFETY: as above
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            let verdict = if block.iter().all(|&b| b == 0) { 1 } else { 2 };
            VERDICT.store(verdict, Ordering::SeqCst);
            WATCH.store(0, Ordering::SeqCst);
        }
        // SAFETY: as above
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: WatchAlloc = WatchAlloc;

/// Drops `owned` (a box) and returns whether its heap block was all zero when freed
pub(crate) fn freed_all_zero<T>(owned: Box<T>) -> bool {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    VERDICT.store(0, Ordering::SeqCst);
    WATCH.store(core::ptr::from_ref::<T>(&*owned) as usize, Ordering::SeqCst);
    drop(owned);
    match VERDICT.load(Ordering::SeqCst) {
        1 => true,
        2 => false,
        _ => panic!("the watched block was not freed"),
    }
}
