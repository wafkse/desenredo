#![no_std]
#![no_main]
#![cfg_attr(feature = "catch", feature(core_intrinsics, lang_items, panic_can_unwind))]
#![cfg_attr(feature = "catch", allow(internal_features))]

//! Freestanding Linux worker using Desenredo for recoverable Rust panics.
//!
//! This is an application-shaped example rather than an unwind test battery. It
//! starts directly at Linux `_start`, uses no libc or Rust `std`, obtains memory
//! with Talc backed by `rustix` mmap, discovers its own linked unwind metadata,
//! captures addr2line backtraces, and catches one Rust panic at each request boundary.
//!
//! Run it with a sequence of request arguments such as
//!
//! ```text
//! desenredo-no-std-worker work trace panic work
//! ```
//!
//! The middle request panics while owning an anonymous page mapping. Phase two
//! must run that resource's `Drop` implementation before the catch boundary
//! recovers the panic. The worker then continues with the final request.
//!
//! ```text
//! Linux _start
//!     |
//!     v
//! parse argc and argv
//!     |
//!     v
//! request boundary
//!     |
//!     +---- work ----> Mapping::drop ----> request complete
//!     |
//!     +---- panic ---> panic handler ----> Rust panic packet
//!                                      |
//!                                      v
//!                              _Unwind_RaiseException
//!                                      |
//!                              phase one search
//!                                      |
//!                              phase two cleanup
//!                                      |
//!                              Mapping::drop
//!                                      |
//!                                      v
//!                               catch boundary
//!                                      |
//!                                      v
//!                              next request continues
//! ```
//!
//! Deployment requirements are explicit in this example.
//!
//! - The target is static non-Windows x86_64 Linux with `panic = "unwind"`.
//! - The linker must retain `.eh_frame` and `.gcc_except_table` and publish their live bounds
//!   together with the executable text range.
//! - Unwind metadata is trusted because direct CFI memory reads may touch the live stack. Untrusted
//!   plugin CFI requires a stronger memory authority.
//! - The process is single threaded. A production multi-threaded runtime needs thread-local request
//!   identity rather than the global request scope used here.
//! - Catching Rust panics uses the nightly compiler catch intrinsic. The Cargo `catch` feature
//!   names that requirement and `runtime` depends on it.
//! - Talc is the process global allocator. Its lower-level source obtains whole mappings through
//!   rustix and must not allocate through Talc while Talc holds its lock.
//! - Backtrace capture is allocation free. Addr2line symbolization happens afterward from the
//!   matching ELF image exposed through `/proc/self/exe`.
//! - Only unwind-capable Rust boundaries may recover. A panic crossing a non-unwinding ABI such as
//!   `extern "C"` must terminate instead.
//!
//! The unwind protocol follows the [Itanium C++ ABI exception handling
//! specification](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html).
//! Caller recovery follows [DWARF Version 5](https://dwarfstd.org/doc/DWARF5.pdf)
//! section 6.4. GCC style language tables use the documented GNU and Linux
//! extension encodings rather than core DWARF alone.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("the no-std userspace example currently supports x86_64 Linux only");

extern crate alloc;

use core::num::NonZeroUsize;

use boundary::{BoundaryError, Outcome};
use linux::ExitCode;
use process::ProcessStack;
use service::{Command, Request};

mod allocator;
mod backtrace;
mod boundary;
mod image;
mod linux;
mod process;
mod runtime;
mod service;

core::arch::global_asm!(include_str!("start.S"), options(att_syntax));

/// Reports command line usage and terminates with an EX_USAGE-style status.
fn usage() -> ! {
    linux::stderr(b"usage: desenredo-no-std-worker [work|panic|trace]...\n");
    linux::exit(ExitCode::USAGE)
}

/// Converts one successful boundary outcome into an operational message.
fn report(outcome: Outcome) {
    match outcome {
        Outcome::Complete => linux::stdout(b"request completed\n"),
        Outcome::Recovered => linux::stdout(b"request panic recovered\n"),
        Outcome::Resource => linux::stderr(b"request resource allocation failed\n"),
        Outcome::Backtrace => linux::stderr(b"request backtrace failed\n"),
    }
}

/// Converts one catch-boundary invariant failure into terminal process policy.
fn boundary_failure(error: BoundaryError) -> ! {
    match error {
        BoundaryError::Busy => linux::terminate(b"nested recoverable request rejected\n", ExitCode::SOFTWARE),
        BoundaryError::Payload => linux::terminate(b"caught panic payload did not match request\n", ExitCode::SOFTWARE),
        BoundaryError::Cleanup => linux::terminate(b"request cleanup contract failed\n", ExitCode::SOFTWARE),
    }
}

/// Advances one nonzero request identifier without permitting wraparound.
fn next(id: NonZeroUsize) -> NonZeroUsize {
    match id.checked_add(1) {
        Some(next) => next,
        None => linux::terminate(b"request identifier exhausted\n", ExitCode::SOFTWARE),
    }
}

/// Rust process entry called directly from the assembly `_start` symbol.
///
/// # Safety
///
/// `stack` must be the exact initial stack pointer supplied by Linux at process
/// entry before the assembly shim realigns RSP for this call.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn desenredo_entry(stack: *mut usize) -> ! {
    linux::stdout(b"desenredo no_std worker ready\n");

    // SAFETY:
    // `_start` forwards the untouched Linux entry stack pointer in RDI.
    let stack = unsafe { ProcessStack::from_entry(stack) };
    let stack = match stack {
        Some(stack) => stack,
        None => linux::terminate(b"Linux process stack pointer was null\n", ExitCode::SOFTWARE),
    };
    let mut id = NonZeroUsize::MIN;
    let mut handled = false;

    for argument in stack.args() {
        let command = match Command::parse(argument) {
            Some(command) => command,
            None => usage(),
        };
        let request = Request::new(id, command);
        let outcome = boundary::run(&request);

        match outcome {
            Ok(outcome) => report(outcome),
            Err(error) => boundary_failure(error),
        }

        handled = true;
        id = next(id);
    }

    match handled {
        true => {
            linux::stdout(b"worker completed\n");
            linux::exit(ExitCode::SUCCESS)
        },
        false => usage(),
    }
}
