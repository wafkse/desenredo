//! Raises a Desenredo Rust panic object through a Rust cleanup frame.
//!
//! A native C++ catch-all exists only to give the Level I unwinder a phase-one
//! handler. The interesting frame is the Rust callback between the throw and that
//! handler. Its `Guard` must be destroyed by compiler-generated phase-two cleanup.
//!
//! ```text
//! C++ catch-all
//!      ^
//!      | phase two eventually installs handler
//!      |
//! +----+------------------+
//! | Rust callback         |
//! |                       |
//! | Guard lives here      |
//! |                       |
//! | desenredo_panic::start|
//! +-----------+-----------+
//!             |
//!             v
//!      MOZ\0RUST exception
//!             |
//!             v
//!   _Unwind_RaiseException
//!             |
//!       phase one search
//!             |
//!       phase two cleanup
//!             |
//!             +------> Guard::drop increments DROPS
//!             |
//!             v
//!        C++ catch-all
//!             |
//!             v
//!    exception cleanup hook
//! ```
//!
//! The [Itanium C++ ABI exception handling
//! specification](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html) defines
//! the language-neutral phase protocol used here. The Rust packet itself follows
//! rustc panic-runtime conventions rather than the C++ Level II object layout.

use core::sync::atomic::{AtomicUsize, Ordering};

use desenredo_panic::{
    object::start,
    runtime::{Hook, Runtime},
};

static DROPS: AtomicUsize = AtomicUsize::new(0);

struct Guard;

impl Drop for Guard {
    fn drop(&mut self) {
        DROPS.fetch_add(1, Ordering::SeqCst);
    }
}

struct TestRuntime;

unsafe extern "C" fn lost() -> ! {
    let code = match DROPS.load(Ordering::SeqCst) {
        1 => 0,
        _ => 9,
    };

    std::process::exit(code)
}

unsafe extern "C" fn foreign() -> ! {
    std::process::exit(10)
}
// SAFETY:
// Both hooks exit the process immediately. Neither hook returns or initiates another unwind through
// its C ABI boundary.
unsafe impl Runtime for TestRuntime {
    const FOREIGN: Hook = foreign;
    const LOST: Hook = lost;
}

unsafe extern "C" {
    fn catch_foreign(callback: unsafe extern "C-unwind" fn());
}

unsafe extern "C-unwind" fn throw_rust() {
    let _guard = Guard;
    let payload = Box::new("desenredo panic");

    start::<TestRuntime>(payload)
}

fn main() {
    // SAFETY:
    // The linked fixture invokes the callback through an unwind-capable ABI and keeps a native
    // catch-all handler active until the Rust panic transfers control to the system unwinder. The
    // callback signature agrees on both sides of the boundary.
    unsafe { catch_foreign(throw_rust) };

    std::process::exit(11)
}
