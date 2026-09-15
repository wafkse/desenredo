//! Typed personality dispatch for the two-phase unwind protocol.
//!
//! Raw callback arguments are validated once and converted into phase-specific
//! capabilities so personality implementations cannot manufacture protocol states.

use core::{ffi::c_int, ptr::NonNull};

use super::context::{CleanupFrame, ExceptionRef, Frame, InstalledContext};
use crate::abi::{
    class::ExceptionClass,
    unwind::{Actions, Context, Exception, ReasonCode},
};

/// A malformed personality invocation from the unwinder.
#[derive(Debug, Copy, Clone, Eq, PartialEq, fack::prelude::Error)]
pub enum ProtocolError {
    /// The unwinder protocol version is unsupported.
    #[error("unsupported personality version")]
    UnsupportedVersion,
    /// The exception pointer was null.
    #[error("null exception pointer")]
    NullException,
    /// The context pointer was null.
    #[error("null unwind context")]
    NullContext,
    /// The action mask contained unknown bits.
    #[error("unknown personality action bits")]
    UnknownActions,
    /// Neither unwind phase was selected.
    #[error("missing unwind phase")]
    MissingPhase,
    /// The action mask requested an impossible state.
    #[error("invalid personality action combination")]
    InvalidCombination,
    /// The callback class disagreed with the exception header.
    #[error("exception class mismatch")]
    ClassMismatch,
}

/// A search-phase personality invocation.
// NOTE(invariant): Construction occurs only for a validated phase-one search callback with a live
// frame and exception.
pub struct Search<'a>(Frame<'a>, ExceptionRef<'a>, ExceptionClass);

impl Search<'_> {
    /// Returns the read-only frame view.
    #[inline]
    pub const fn frame(&self) -> &Frame<'_> {
        let &Self(ref frame, _, _) = self;

        frame
    }

    /// Returns the active exception.
    #[inline]
    pub const fn exception(&self) -> ExceptionRef<'_> {
        let &Self(_, exception, _) = self;

        exception
    }

    /// Returns the callback exception class.
    #[inline]
    pub const fn class(&self) -> ExceptionClass {
        let &Self(_, _, exception_class) = self;

        exception_class
    }
}

/// A non-handler cleanup-phase personality invocation.
// NOTE(invariant): Construction occurs only for a validated phase-two cleanup callback that is not
// the selected handler frame.
pub struct Cleanup<'a>(CleanupFrame<'a>, ExceptionRef<'a>, ExceptionClass, bool);

impl<'a> Cleanup<'a> {
    /// Returns a read-only view of the current frame.
    #[inline]
    pub const fn frame(&self) -> Frame<'_> {
        let &Self(ref frame, _, _, _) = self;

        frame.frame()
    }

    /// Returns the active exception.
    #[inline]
    pub const fn exception(&self) -> ExceptionRef<'_> {
        let &Self(_, exception, _, _) = self;

        exception
    }

    /// Returns the callback exception class.
    #[inline]
    pub const fn class(&self) -> ExceptionClass {
        let &Self(_, _, exception_class, _) = self;

        exception_class
    }

    /// Reports whether this is a forced unwind.
    #[inline]
    pub const fn forced(&self) -> bool {
        let &Self(_, _, _, forced) = self;

        forced
    }

    /// Consumes the invocation into its cleanup capabilities.
    #[inline]
    pub const fn split(self) -> (CleanupFrame<'a>, ExceptionRef<'a>, bool) {
        let Self(frame, exception, _, forced) = self;

        (frame, exception, forced)
    }
}

/// The cleanup invocation for the frame selected in phase one.
// NOTE(invariant): Construction occurs only for the non-forced handler frame selected during phase
// one.
pub struct Handler<'a>(CleanupFrame<'a>, ExceptionRef<'a>, ExceptionClass);

impl<'a> Handler<'a> {
    /// Returns a read-only view of the current frame.
    #[inline]
    pub const fn frame(&self) -> Frame<'_> {
        let &Self(ref frame, _, _) = self;

        frame.frame()
    }

    /// Returns the active exception.
    #[inline]
    pub const fn exception(&self) -> ExceptionRef<'_> {
        let &Self(_, exception, _) = self;

        exception
    }

    /// Returns the callback exception class.
    #[inline]
    pub const fn class(&self) -> ExceptionClass {
        let &Self(_, _, exception_class) = self;

        exception_class
    }

    /// Consumes the invocation into its handler capabilities.
    #[inline]
    pub const fn split(self) -> (CleanupFrame<'a>, ExceptionRef<'a>) {
        let Self(frame, exception, _) = self;

        (frame, exception)
    }
}

/// The only valid search-phase outcomes.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SearchDecision {
    /// Continue searching older frames.
    Continue,
    /// Mark this frame as the handler frame.
    HandlerFound,
    /// Stop phase one with a fatal result.
    Fatal,
}

/// The valid non-handler cleanup outcomes.
pub enum CleanupDecision<'a> {
    /// Continue unwinding to the next frame.
    Continue,
    /// Install a prepared landing pad context.
    Install(InstalledContext<'a>),
    /// Stop phase two with a fatal result.
    Fatal,
}

/// The valid selected-handler outcomes.
pub enum HandlerDecision<'a> {
    /// Install a prepared handler landing pad.
    Install(InstalledContext<'a>),
    /// Stop phase two with a fatal result.
    Fatal,
}

/// A language personality implemented with typed phase callbacks.
pub trait Personality {
    /// Processes the handler search phase.
    fn search(call: Search<'_>) -> SearchDecision;

    /// Processes cleanup for a frame that is not the selected handler.
    fn cleanup<'a>(call: Cleanup<'a>) -> CleanupDecision<'a>;

    /// Installs the landing pad for the handler selected during phase one.
    fn handler<'a>(call: Handler<'a>) -> HandlerDecision<'a>;
}

/// One validated personality invocation.
pub enum Invocation<'a> {
    /// A handler search request.
    Search(Search<'a>),
    /// A cleanup request that is not the selected handler frame.
    Cleanup(Cleanup<'a>),
    /// The handler frame selected during phase one.
    Handler(Handler<'a>),
}

/// Validates the raw unwind callback state.
///
/// # Safety
///
/// `exception` and `context` must be the exact pointers supplied together by the
/// active personality callback. Both pointed-to objects must remain live for all
/// of the caller-selected `'a`. The caller must not choose a lifetime longer
/// than that callback state remains valid.
///
/// `version`, `actions`, and `exception_class` must be the values from that same
/// callback. During cleanup phase the caller must not create another mutable Rust
/// capability for `context` while the returned invocation exists.
#[inline]
pub unsafe fn decode<'a>(
    version: c_int,
    actions: Actions,
    exception_class: ExceptionClass,
    exception: *mut Exception,
    context: *mut Context,
) -> Result<Invocation<'a>, ProtocolError> {
    const VERSION: c_int = 1;

    let exception = NonNull::new(exception);
    let context = NonNull::new(context);
    let header_class = exception.map(|exception| {
        // SAFETY:
        // The decode contract requires exception to be the live callback header
        // for all of the selected lifetime. This read accesses only the fixed
        // producer-owned class field before any phase capability is constructed.
        unsafe { exception.as_ref().class() }
    });
    let version_supported = version == VERSION;
    let class_matches = header_class == Some(exception_class);
    let actions_known = actions.known();
    let search = actions.has(Actions::SEARCH);
    let cleanup = actions.has(Actions::CLEANUP);
    let handler = actions.has(Actions::HANDLER);
    let forced = actions.has(Actions::FORCE);

    match (
        version_supported,
        exception,
        context,
        class_matches,
        actions_known,
        search,
        cleanup,
        handler,
        forced,
    ) {
        (false, _, _, _, _, _, _, _, _) => Err(ProtocolError::UnsupportedVersion),
        (_, None, _, _, _, _, _, _, _) => Err(ProtocolError::NullException),
        (_, _, None, _, _, _, _, _, _) => Err(ProtocolError::NullContext),
        (_, _, _, false, _, _, _, _, _) => Err(ProtocolError::ClassMismatch),
        (_, _, _, _, false, _, _, _, _) => Err(ProtocolError::UnknownActions),
        (_, _, _, _, _, false, false, _, _) => Err(ProtocolError::MissingPhase),
        (_, _, _, _, _, true, true, _, _) => Err(ProtocolError::InvalidCombination),
        (_, _, _, _, _, true, false, _, true) => Err(ProtocolError::InvalidCombination),
        (_, _, _, _, _, true, false, true, false) => Err(ProtocolError::InvalidCombination),
        (_, Some(exception), Some(context), _, _, true, false, false, false) => {
            // SAFETY:
            // The public decode contract keeps this nonnull exception alive for
            // all of `'a`. Search grants only shared exception access.
            let exception = unsafe { ExceptionRef::new(exception) };
            // SAFETY:
            // The same contract keeps the nonnull context alive for all of `'a`.
            // Search uses only read-only frame queries.
            let frame = unsafe { Frame::new(context) };

            Ok(Invocation::Search(Search(frame, exception, exception_class)))
        },
        (_, _, _, _, _, false, true, true, true) => Err(ProtocolError::InvalidCombination),
        (_, Some(exception), Some(context), _, _, false, true, true, false) => {
            // SAFETY:
            // The public decode contract keeps this nonnull exception alive for
            // all of `'a` while handler processing borrows it.
            let exception = unsafe { ExceptionRef::new(exception) };
            // SAFETY:
            // The exhaustive action classification proves cleanup plus handler
            // without force. The decode contract grants this invocation the sole
            // Rust mutation capability for the live context during `'a`.
            let frame = unsafe { CleanupFrame::new(context) };

            Ok(Invocation::Handler(Handler(frame, exception, exception_class)))
        },
        (_, Some(exception), Some(context), _, _, false, true, false, forced) => {
            // SAFETY:
            // The public decode contract keeps this nonnull exception alive for
            // all of `'a` while cleanup processing borrows it.
            let exception = unsafe { ExceptionRef::new(exception) };
            // SAFETY:
            // The exhaustive action classification proves a non-handler cleanup
            // callback. The decode contract grants this invocation the sole Rust
            // mutation capability for the live context during `'a`.
            let frame = unsafe { CleanupFrame::new(context) };

            Ok(Invocation::Cleanup(Cleanup(frame, exception, exception_class, forced)))
        },
    }
}

/// Dispatches one raw personality callback to a typed implementation.
///
/// # Safety
///
/// Every argument must come from one active personality callback and remain
/// valid until `dispatch` returns. In cleanup phase no other Rust value may
/// mutate the same unwind context during this call. The selected `P` must obey
/// the phase capabilities and must not retain borrowed callback state after its
/// method returns.
#[inline]
pub unsafe fn dispatch<P>(
    version: c_int,
    actions: Actions,
    exception_class: ExceptionClass,
    exception: *mut Exception,
    context: *mut Context,
) -> ReasonCode
where
    P: Personality,
{
    // SAFETY:
    // dispatch's contract supplies one coherent live callback state and bounds
    // every borrowed capability to this call. The invocation is consumed before
    // dispatch returns, so no callback lifetime can escape through this path.
    let invocation = unsafe { decode(version, actions, exception_class, exception, context) };

    match invocation {
        Ok(Invocation::Search(call)) => match P::search(call) {
            SearchDecision::Continue => ReasonCode::CONTINUE,
            SearchDecision::HandlerFound => ReasonCode::HANDLER,
            SearchDecision::Fatal => ReasonCode::FATAL1,
        },
        Ok(Invocation::Cleanup(call)) => match P::cleanup(call) {
            CleanupDecision::Continue => ReasonCode::CONTINUE,
            CleanupDecision::Install(context) => context.reason(),
            CleanupDecision::Fatal => ReasonCode::FATAL2,
        },
        Ok(Invocation::Handler(call)) => match P::handler(call) {
            HandlerDecision::Install(context) => context.reason(),
            HandlerDecision::Fatal => ReasonCode::FATAL2,
        },
        Err(_) => {
            if actions.has(Actions::CLEANUP) {
                ReasonCode::FATAL2
            } else {
                ReasonCode::FATAL1
            }
        },
    }
}

/// Exports a typed personality implementation under an ABI symbol.
#[macro_export]
macro_rules! export_personality {
    ($name:ident, $personality:ty) => {
        /// Exported Itanium personality entry point.
        /// # Safety
        ///
        /// This symbol must be called only by an Itanium-compatible unwinder
        /// with one coherent live callback state.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            version: core::ffi::c_int,
            actions: $crate::abi::unwind::Actions,
            exception_class: $crate::abi::class::ExceptionClass,
            exception: *mut $crate::abi::unwind::Exception,
            context: *mut $crate::abi::unwind::Context,
        ) -> $crate::abi::unwind::ReasonCode {
            // SAFETY:
            // The exported function's contract is exactly the raw callback
            // contract required by personality::protocol::dispatch.
            unsafe { $crate::protocol::dispatch::<$personality>(version, actions, exception_class, exception, context) }
        }
    };
}

#[cfg(test)]
mod export_tests {
    use super::{Cleanup, CleanupDecision, Handler, HandlerDecision, Personality, Search, SearchDecision};
    use crate::abi::unwind::PersonalityFn;

    struct TestPersonality;

    impl Personality for TestPersonality {
        fn search(_call: Search<'_>) -> SearchDecision {
            SearchDecision::Continue
        }

        fn cleanup<'a>(_call: Cleanup<'a>) -> CleanupDecision<'a> {
            CleanupDecision::Continue
        }

        fn handler<'a>(_call: Handler<'a>) -> HandlerDecision<'a> {
            HandlerDecision::Fatal
        }
    }

    crate::export_personality!(desenredo_test_personality, TestPersonality);

    #[test]
    fn exported_symbol_has_expected_function_type() {
        let _personality: PersonalityFn = desenredo_test_personality;
    }
}
