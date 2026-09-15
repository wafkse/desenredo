//! Rust panic and personality policy for the single-threaded worker.
//!
//! A request scope identifies the one panic the worker is prepared to recover.
//! Panics outside an active request are process failures. The example is
//! intentionally single threaded because the active request identity is global.

use alloc::boxed::Box;
use core::{
    ffi::c_int,
    intrinsics::abort,
    num::NonZeroUsize,
    panic::PanicInfo,
    sync::atomic::{AtomicUsize, Ordering},
};

use desenredo::{
    abi::{
        class::ExceptionClass,
        unwind::{Actions, Context, Exception, ReasonCode},
    },
    panic::{
        object,
        runtime::{Hook, Runtime},
    },
    personality::protocol,
    rust::personality::Policy,
};

use crate::{
    image::ProcessImage,
    linux::{self, ExitCode},
};

/// Request identifier visible to the panic handler before unwinding begins.
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

/// Structured panic payload produced by this process runtime.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Fault(NonZeroUsize);

impl Fault {
    /// Returns the request whose panic created this payload.
    #[inline]
    pub const fn request(self) -> NonZeroUsize {
        let Self(request) = self;

        request
    }
}

/// Failure to establish one exclusive recoverable request scope.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ScopeError;

/// Proof that one request owns the recoverable panic boundary.
// NOTE(invariant): ACTIVE equals the stored nonzero request identifier for the
// complete lifetime of this value. Drop clears that identity exactly once.
pub struct RequestScope(NonZeroUsize);

impl RequestScope {
    /// Acquires the process-wide recoverable panic slot for one request.
    #[inline]
    pub fn enter(request: NonZeroUsize) -> Result<Self, ScopeError> {
        let acquired = ACTIVE.compare_exchange(0, request.get(), Ordering::AcqRel, Ordering::Acquire);

        match acquired {
            Ok(_previous) => Ok(Self(request)),
            Err(_active) => Err(ScopeError),
        }
    }
}

impl Drop for RequestScope {
    #[inline]
    fn drop(&mut self) {
        let &mut Self(request) = self;
        let cleared = ACTIVE.compare_exchange(request.get(), 0, Ordering::AcqRel, Ordering::Acquire);

        match cleared {
            Ok(_active) => {},
            Err(_active) => linux::terminate(b"request scope invariant failed\n", ExitCode::SOFTWARE),
        }
    }
}

/// Runtime policy used by locally raised Rust panic packets.
pub struct LinuxRuntime;

/// Terminates when a raised panic returns from the unwinder without a handler.
unsafe extern "C" fn lost() -> ! {
    linux::terminate(b"unwinder returned without a request handler\n", ExitCode::LOST)
}

/// Terminates when a foreign exception reaches this Rust catch boundary.
unsafe extern "C" fn foreign() -> ! {
    linux::terminate(
        b"foreign exception reached the Rust request boundary\n",
        ExitCode::FOREIGN,
    )
}

// SAFETY:
// Both hooks terminate through Linux exit_group and cannot return or unwind
// through the C ABI boundary.
unsafe impl Runtime for LinuxRuntime {
    const FOREIGN: Hook = foreign;
    const LOST: Hook = lost;
}

/// Handles Rust language panics for the freestanding process.
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    let request = NonZeroUsize::new(ACTIVE.load(Ordering::Acquire));

    match (info.can_unwind(), request) {
        (true, Some(request)) => object::start::<LinuxRuntime>(Box::new(Fault(request))),
        (true, None) => linux::terminate(b"panic occurred outside a recoverable request\n", ExitCode::SOFTWARE),
        (false, _) => {
            linux::stderr(b"non-unwindable panic reached the process runtime\n");
            abort()
        },
    }
}

/// Rust personality entry used by compiler generated cleanup and catch pads.
#[lang = "eh_personality"]
unsafe extern "C" fn rust_eh_personality(
    version: c_int,
    actions: Actions,
    class: ExceptionClass,
    exception: *mut Exception,
    context: *mut Context,
) -> ReasonCode {
    // SAFETY:
    // The compiler and active Itanium unwinder supply one coherent callback
    // state. ProcessImage bounds metadata to this executable.
    unsafe { protocol::dispatch::<Policy<ProcessImage>>(version, actions, class, exception, context) }
}
