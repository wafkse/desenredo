//! Terminal behavior required by Rust panic transport.
//!
//! The panic object runtime cannot recover from every unwinder outcome. It also
//! must define what happens when a Rust catch boundary receives an exception it
//! cannot safely reinterpret as a locally allocated Rust panic packet.

/// Hook used for panic states which must terminate the current execution path.
pub type Hook = unsafe extern "C" fn() -> !;

/// Terminal policy used by Rust panic packet ownership transitions.
///
/// # Safety
///
/// Both hooks are called from contexts where unwinding through the hook's
/// `extern "C"` ABI would violate the ABI contract. Implementations must
/// terminate the thread, process, task, or equivalent execution domain without
/// returning and without initiating another unwind through that boundary.
pub unsafe trait Runtime {
    /// Handles an owned Rust panic packet that the unwinder gives back or deletes.
    const LOST: Hook;

    /// Handles a catch boundary which receives a foreign exception representation.
    const FOREIGN: Hook;
}
