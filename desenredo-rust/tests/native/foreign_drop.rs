//! Native fixture for a foreign C++ exception crossing a Rust cleanup frame.
//!
//! The C++ shim owns the thrown object and outer catch. Rust contributes only an
//! unwind-capable frame whose compiler-generated cleanup must run exactly once.

use core::sync::atomic::{AtomicUsize, Ordering};

static DROPS: AtomicUsize = AtomicUsize::new(0);

struct Guard;

impl Drop for Guard {
    fn drop(&mut self) {
        DROPS.fetch_add(1, Ordering::SeqCst);
    }
}

unsafe extern "C-unwind" {
    fn throw_int();

    fn cross_rust(callback: unsafe extern "C-unwind" fn()) -> i32;
}

unsafe extern "C-unwind" fn rust_frame() {
    let _guard = Guard;

    // SAFETY:
    // The linked C++ function throws through an `extern "C-unwind"` boundary.
    // The active Rust frame uses the same unwind-capable ABI and retains no C++
    // object reference after control transfers to the system unwinder.
    unsafe { throw_int() };
}

#[test]
fn foreign_exception_runs_rust_drop() {
    let before = DROPS.load(Ordering::SeqCst);
    // SAFETY:
    // The linked shim invokes rust_frame through `extern "C-unwind"` while a C++
    // catch remains active outside it. The callback signature and unwind behavior
    // agree on both sides of the boundary.
    let caught = unsafe { cross_rust(rust_frame) };

    assert_eq!(caught, 7);
    assert_eq!(DROPS.load(Ordering::SeqCst), before + 1);
}
