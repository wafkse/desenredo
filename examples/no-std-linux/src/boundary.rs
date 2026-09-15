//! Recoverable request boundary built on Rust's compiler catch intrinsic.
//!
//! This module is the only place that knows about the intrinsic callback ABI.
//! Application code sees request outcomes rather than raw exception pointers.

use core::{intrinsics::catch_unwind, mem::MaybeUninit, ptr::NonNull};

use desenredo::panic::object::{self, Payload};

use crate::{
    runtime::{Fault, LinuxRuntime, RequestScope, ScopeError},
    service::{self, Request, ServiceError},
};

/// Successful request boundary outcomes.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Outcome {
    /// The request returned normally.
    Complete,

    /// The request panicked and was recovered locally.
    Recovered,

    /// The request could not acquire its operating system resource.
    Resource,

    /// Backtrace capture or symbolization failed after request setup.
    Backtrace,
}

/// Failure of the catch boundary itself rather than the application request.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BoundaryError {
    /// Another recoverable request scope was already active.
    Busy,

    /// The caught panic payload did not belong to this request.
    Payload,

    /// Request resource cleanup did not occur exactly once.
    Cleanup,
}

/// Expected failure before a request begins unwinding.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum ExecutionError {
    /// The process already has one recoverable request in flight.
    Busy,

    /// Request-local resource acquisition failed.
    Service(ServiceError),
}

/// Intrinsic callback state shared by the invoke and catch callbacks.
// NOTE(invariant): request remains live for the intrinsic call. result is
// initialized only on normal return. payload is initialized only after a caught
// panic. The intrinsic boolean selects which slot may be read afterward.
struct State {
    /// Request executed by the invoke callback.
    request: NonNull<Request>,

    /// Normal execution result written only when invoke returns.
    result: MaybeUninit<Result<(), ExecutionError>>,

    /// Panic payload written only when the catch callback runs.
    payload: MaybeUninit<Payload>,
}

impl State {
    /// Creates empty callback state tied to one live request.
    #[inline]
    fn new(request: &Request) -> Self {
        let request = NonNull::from(request);
        let result = MaybeUninit::uninit();
        let payload = MaybeUninit::uninit();

        Self {
            request,
            result,
            payload,
        }
    }
}

/// Executes the request callback under one recoverable request scope.
unsafe fn invoke(state: *mut State) {
    // SAFETY:
    // The intrinsic forwards the exact live pointer created by run.
    let state = unsafe { &mut *state };
    let &mut State {
        request,
        ref mut result,
        ..
    } = state;
    // SAFETY:
    // State keeps the request live for the complete intrinsic call.
    let request = unsafe { request.as_ref() };
    let scope = RequestScope::enter(request.id());
    let executed = match scope {
        Ok(_scope) => service::execute(request).map_err(ExecutionError::Service),
        Err(ScopeError) => Err(ExecutionError::Busy),
    };

    result.write(executed);
}

/// Consumes one caught Rust panic into the callback payload slot.
unsafe fn catch(state: *mut State, exception: *mut u8) {
    // SAFETY:
    // The intrinsic forwards the exact live pointer created by run.
    let state = unsafe { &mut *state };
    let &mut State { ref mut payload, .. } = state;
    // SAFETY:
    // The intrinsic supplies the live exception selected by rust_eh_personality.
    let payload_value = unsafe { object::catch::<LinuxRuntime>(exception.cast()) };

    payload.write(payload_value);
}

/// Executes one request and converts the compiler catch protocol into an outcome.
///
/// # Errors
///
/// Returns a boundary error when request-scope ownership, panic identity, or
/// phase-two cleanup violates the example contract.
pub fn run(request: &Request) -> Result<Outcome, BoundaryError> {
    let before = service::cleanups();
    let expected = before.checked_add(1).ok_or(BoundaryError::Cleanup)?;
    let mut state = State::new(request);

    // SAFETY:
    // Both callbacks receive this exact live State pointer. catch never unwinds
    // and the intrinsic returns only after one callback path has completed.
    let caught = unsafe { catch_unwind(invoke, &mut state, catch) };
    let after = service::cleanups();

    match caught {
        false => {
            // SAFETY:
            // A false intrinsic result proves invoke returned and initialized result.
            let executed = unsafe { state.result.assume_init_read() };

            match (executed, after == expected, after == before) {
                (Ok(()), true, _) => Ok(Outcome::Complete),
                (Err(ExecutionError::Service(ServiceError::Resource)), _, true) => Ok(Outcome::Resource),
                (Err(ExecutionError::Service(ServiceError::Backtrace(_error))), true, _) => Ok(Outcome::Backtrace),
                (Err(ExecutionError::Busy), _, _) => Err(BoundaryError::Busy),
                _ => Err(BoundaryError::Cleanup),
            }
        },
        true => {
            // SAFETY:
            // A true intrinsic result proves catch initialized payload.
            let payload = unsafe { state.payload.assume_init_read() };
            let fault = payload.downcast::<Fault>();

            match (fault, after == expected) {
                (Ok(fault), true) if fault.request() == request.id() => Ok(Outcome::Recovered),
                (Ok(_fault), true) => Err(BoundaryError::Payload),
                (Err(_payload), true) => Err(BoundaryError::Payload),
                _ => Err(BoundaryError::Cleanup),
            }
        },
    }
}
