//! Allocation and ownership transitions for Rust panic exception packets.
//!
//! The packet prefix intentionally matches Rust's `panic_unwind` representation.
//! Only the unwind header and canary are cross-runtime inspection points. Payload
//! access occurs only after the local canary proves that this crate instance owns
//! the complete packet representation.

use alloc::boxed::Box;
use core::{
    any::Any,
    convert::Infallible,
    mem::ManuallyDrop,
    ptr::{self, NonNull},
};

use desenredo_abi::unwind::{_Unwind_DeleteException, _Unwind_RaiseException, Exception, ReasonCode};
use desenredo_rust::class::CLASS;

use crate::runtime::{Hook, Runtime};

/// Boxed payload carried by one locally allocated Rust panic packet.
pub type Payload = Box<dyn Any + Send + 'static>;

/// Failure returned when the Level I unwinder gives a raised packet back.
#[derive(Debug, fack::prelude::Error)]
#[error("unwinder returned while raising Rust panic {reason:?}")]
// NOTE(invariant): packet uniquely owns one still-live Packet after _Unwind_RaiseException returns.
// Drop reconstructs exactly that Box unless ownership is deliberately abandoned by start.
pub struct Raise {
    /// Reason code returned by the unwinder.
    reason: ReasonCode,

    /// Unique ownership of the packet returned by the unwinder.
    packet: NonNull<Packet>,
}

impl Raise {
    /// Returns the reason reported by `_Unwind_RaiseException`.
    #[inline]
    pub const fn reason(&self) -> ReasonCode {
        let &Self { reason, .. } = self;

        reason
    }
}

impl Drop for Raise {
    #[inline]
    fn drop(&mut self) {
        let &mut Self { packet, .. } = self;

        // SAFETY:
        // The Raise invariant states that packet is the unique still-live Box
        // allocation returned to this owner by _Unwind_RaiseException. No other
        // path may free the packet while Raise exists.
        drop(unsafe { Box::from_raw(packet.as_ptr()) });
    }
}

/// Classification failure while extracting a caught Rust panic packet.
#[derive(Debug, Copy, Clone, Eq, PartialEq, fack::prelude::Error)]
pub enum CatchError {
    /// The exception class is not Rust's `MOZ\0RUST` class.
    #[error("foreign unwind exception")]
    Foreign,

    /// The exception is Rust-class but belongs to another panic runtime copy.
    #[error("foreign Rust panic runtime")]
    Rust,
}

/// Runtime-local identity byte used by the Rust panic packet prefix.
static CANARY: u8 = 0;

/// Heap object raised through the Itanium Level I unwinder.
#[repr(C)]
// NOTE(invariant): unwind and canary form the Rust panic prefix. payload and lost are accessible
// only after canary proves this runtime owns the complete Packet layout.
struct Packet {
    /// Language-neutral header consumed and mutated by the active unwinder.
    unwind: Exception,

    /// Address which identifies the crate instance that owns the packet layout.
    canary: *const u8,

    /// User panic payload owned until a local catch extracts it.
    payload: Payload,

    /// Terminal hook used if the unwinder deletes this still-owned panic packet.
    lost: Hook,
}

impl Packet {
    /// Constructs a packet before ownership transfers to the unwinder.
    #[inline]
    fn new<R>(payload: Payload) -> Self
    where
        R: Runtime,
    {
        let unwind = Exception::new(CLASS, Some(Self::cleanup));
        let canary = ptr::addr_of!(CANARY);
        let lost = R::LOST;

        Self {
            unwind,
            canary,
            payload,
            lost,
        }
    }

    /// Releases a packet deleted by the active unwinder.
    unsafe extern "C" fn cleanup(_reason: ReasonCode, exception: *mut Exception) {
        // SAFETY:
        // Packet::new installs this callback only into its own leading unwind
        // field. The Level I unwinder invokes the callback at most once after it
        // relinquishes the exception, so exception is the original Box pointer.
        let packet = unsafe { Box::from_raw(exception.cast::<Self>()) };

        let Self { lost, .. } = *packet;

        // SAFETY:
        // Runtime requires LOST to terminate without returning or unwinding
        // through this cleanup callback's C ABI boundary.
        unsafe { lost() }
    }
}

/// Raises one Rust-class exception with an owned payload.
///
/// On successful propagation control transfers into the system unwinder and the
/// function does not return through its normal Rust caller. If the unwinder
/// returns a reason code, the returned [`Raise`] regains ownership of the packet.
///
/// # Errors
///
/// Returns the owning packet error produced when `_Unwind_RaiseException`
/// returns instead of transferring control to a landing pad.
#[inline]
pub fn raise<R>(payload: Payload) -> Result<Infallible, Raise>
where
    R: Runtime,
{
    let packet = Box::new(Packet::new::<R>(payload));
    let packet = Box::into_raw(packet);

    // SAFETY:
    // Box::into_raw preserves the allocation and always returns its nonnull data
    // pointer. NonNull is only used to retain ownership if the unwinder returns.
    let packet = unsafe { NonNull::new_unchecked(packet) };
    let exception = packet.as_ptr().cast::<Exception>();

    // SAFETY:
    // Exception is the first field of Packet, so this pointer names the live
    // aligned Level I header. The Box remains allocated for the complete unwind.
    let reason = unsafe { _Unwind_RaiseException(exception) };

    Err(Raise { reason, packet })
}

/// Raises a Rust panic packet and applies the terminal runtime policy on return.
#[inline]
pub fn start<R>(payload: Payload) -> !
where
    R: Runtime,
{
    match raise::<R>(payload) {
        Ok(never) => match never {},
        Err(error) => {
            let _error = ManuallyDrop::new(error);

            // SAFETY:
            // ManuallyDrop keeps the still-live packet owned by the terminal
            // path without running Raise::drop. Runtime requires LOST never to return or
            // unwind through its C ABI boundary.
            unsafe { R::LOST() }
        },
    }
}

/// Extracts a payload from a locally produced Rust panic packet.
///
/// # Safety
///
/// `exception` must point to the live unwind header delivered to the active Rust
/// catch landing pad. The packet must not already have been deleted, extracted,
/// or resumed. The caller must transfer exclusive ownership of a local packet to
/// this function when the class and canary identify this runtime instance.
///
/// # Errors
///
/// Returns [`CatchError::Foreign`] without reading beyond the generic exception
/// header when the class differs. Returns [`CatchError::Rust`] after reading only the
/// stable Rust panic prefix when the class matches but the runtime canary differs.
#[inline]
pub unsafe fn take(exception: *mut Exception) -> Result<Payload, CatchError> {
    // SAFETY:
    // The caller contract proves exception is a live Level I header for this
    // catch transition. Reading its producer-owned class does not touch the
    // unwinder-private words.
    let class = unsafe { (*exception).class() };

    if class != CLASS {
        Err(CatchError::Foreign)
    } else {
        let packet = exception.cast::<Packet>();

        // SAFETY:
        // Every Rust panic runtime promises the unwind-header plus canary prefix.
        // Reading this single field does not assume our trailing Packet layout.
        let canary = unsafe { ptr::addr_of!((*packet).canary).read() };

        if !ptr::eq(canary, ptr::addr_of!(CANARY)) {
            Err(CatchError::Rust)
        } else {
            // SAFETY:
            // Matching the crate-local canary proves this exact Packet allocation
            // and representation. The caller transfers the caught packet
            // exclusively, so reconstructing the Box cannot alias another owner.
            let packet = unsafe { Box::from_raw(packet) };

            let Packet { payload, .. } = *packet;

            Ok(payload)
        }
    }
}

/// Extracts a local Rust panic or applies Rust's foreign-exception policy.
///
/// Non-Rust exceptions are deleted through their producer callback before the
/// foreign hook runs. Rust-class packets from another runtime copy are not
/// deleted because their cleanup callback may itself report a dropped Rust panic.
///
/// # Safety
///
/// `exception` must be the live exception object delivered to the active Rust
/// catch landing pad. It must not already have been consumed by another catch,
/// deletion, resume, or payload extraction path.
#[inline]
pub unsafe fn catch<R>(exception: *mut Exception) -> Payload
where
    R: Runtime,
{
    // SAFETY:
    // catch forwards the same exclusive live landing-pad exception contract to
    // take and immediately handles every classification outcome.
    let payload = unsafe { take(exception) };

    match payload {
        Ok(payload) => payload,
        Err(CatchError::Foreign) => {
            // SAFETY:
            // take read only the generic header and returned ownership unchanged.
            // The caller contract proves the foreign exception is still live, so
            // the producer cleanup callback may reclaim it exactly once.
            unsafe { _Unwind_DeleteException(exception) };

            // SAFETY:
            // Runtime requires FOREIGN to terminate without returning or
            // unwinding through this catch path's C ABI boundary.
            unsafe { R::FOREIGN() }
        },
        Err(CatchError::Rust) => {
            // SAFETY:
            // A foreign Rust runtime owns this packet and deleting it could call
            // that runtime's dropped-panic hook. Runtime requires FOREIGN to
            // terminate without touching the unknown representation further.
            unsafe { R::FOREIGN() }
        },
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::boxed::Box;
    use core::{
        mem::{offset_of, size_of},
        ptr,
    };
    use std::process::abort;

    use desenredo_abi::{
        class::{ExceptionClass, Language, Vendor},
        unwind::{Exception, ReasonCode},
    };
    use desenredo_rust::class::CLASS;

    use super::{CatchError, Packet, take};
    use crate::runtime::{Hook, Runtime};

    unsafe extern "C" fn terminate() -> ! {
        abort()
    }

    struct TestRuntime;

    // SAFETY:
    // Both test hooks terminate the process immediately and cannot return or
    // unwind through the C ABI boundary.
    unsafe impl Runtime for TestRuntime {
        const FOREIGN: Hook = terminate;
        const LOST: Hook = terminate;
    }

    unsafe extern "C" fn cleanup(_reason: ReasonCode, _exception: *mut Exception) {}

    #[repr(C)]
    // NOTE(invariant): unwind and canary form the foreign Rust panic prefix inspected by take
    // without assuming any trailing representation.
    struct ForeignRust {
        /// Rust-class unwind header from another runtime representation.
        unwind: Exception,

        /// Canary deliberately different from this runtime copy.
        canary: *const u8,
    }

    #[test]
    fn packet_prefix_matches_rust_runtime_contract() {
        assert_eq!(offset_of!(Packet, unwind), 0, "unwind header must lead the packet");
        assert_eq!(
            offset_of!(Packet, canary),
            size_of::<Exception>(),
            "canary must follow the unwind header"
        );
    }

    #[test]
    fn take_recovers_local_payload() {
        let packet = Box::new(Packet::new::<TestRuntime>(Box::new(42_u32)));
        let exception = Box::into_raw(packet).cast::<Exception>();

        // SAFETY:
        // exception is the leading header of one live local Packet and this call
        // transfers its unique Box ownership into take.
        let payload = unsafe { take(exception) }.expect("local panic payload");
        let value = payload.downcast::<u32>().expect("u32 payload");

        assert_eq!(*value, 42, "local payload must round trip");
    }

    #[test]
    fn take_rejects_non_rust_exception() {
        let class = ExceptionClass::join(Vendor::GNU, Language::CXX);
        let mut exception = Exception::new(class, Some(cleanup));

        // SAFETY:
        // exception is a live standalone unwind header and remains owned by this
        // stack frame because take rejects it before any representation transfer.
        let error = unsafe { take(ptr::from_mut(&mut exception)) }.expect_err("foreign class");

        assert_eq!(error, CatchError::Foreign, "foreign class must be rejected");
    }

    #[test]
    fn take_rejects_foreign_rust_canary() {
        let mut foreign = ForeignRust {
            unwind: Exception::new(CLASS, Some(cleanup)),
            canary: ptr::null(),
        };
        let exception = ptr::from_mut(&mut foreign.unwind);

        // SAFETY:
        // exception names the live Rust-compatible prefix in foreign. The null
        // canary forces rejection before take assumes the local trailing layout.
        let error = unsafe { take(exception) }.expect_err("foreign Rust runtime");

        assert_eq!(error, CatchError::Rust, "foreign Rust canary must be rejected");
    }
}
