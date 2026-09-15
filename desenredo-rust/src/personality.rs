//! Personality policy implementing rustc's Itanium LSDA semantics.
//!
//! The policy requests cleanup landing pads for both Rust and foreign
//! exceptions. This is what lets compiler-generated `Drop::drop` code run when
//! any unwind-capable exception crosses a Rust frame. The exception language is
//! relevant to catch payload ownership, not to cleanup selection.

use core::marker::PhantomData;

use desenredo_lsda::{
    encoding::{Bases, Endian},
    table::Lsda,
};
use desenredo_personality::{
    context::{CleanupFrame, ExceptionRef, Frame, InstalledContext, LandingPad, Selector},
    protocol::{Cleanup, CleanupDecision, Handler, HandlerDecision, Personality, Search, SearchDecision},
    source::Source,
};

use super::action::{Action, Pad, scan};

/// Rust personality policy backed by one bounded live-LSDA source.
#[derive(Debug, Copy, Clone)]
// NOTE(invariant): The zero-sized marker selects one LSDA source policy and carries no runtime
// state.
pub struct Policy<S>(PhantomData<S>);

#[cfg(target_endian = "little")]
/// Native LSDA byte order on little endian targets.
const ENDIAN: Endian = Endian::Little;

#[cfg(target_endian = "big")]
/// Native LSDA byte order on big endian targets.
const ENDIAN: Endian = Endian::Big;

impl<S: Source> Policy<S> {
    /// Resolves the Rust LSDA action for one live unwind frame.
    fn action(frame: &Frame<'_>) -> Result<Action, ()> {
        let origin = frame.lsda();
        let bytes = S::bytes(frame);
        let are_aligned = match (origin, bytes.as_ref()) {
            (Some(origin), Ok(&Some(bytes))) => origin.as_ptr().addr() == bytes.as_ptr().addr(),
            _ => true,
        };

        match (origin, bytes, are_aligned) {
            (None, Ok(None), true) => Ok(Action::None),
            (Some(origin), Ok(Some(bytes)), true) => {
                let origin = origin.as_ptr().addr();
                let mut bases = Bases::new(origin, frame.start());

                if let Some(text) = S::text(frame) {
                    bases = bases.text(text);
                }
                if let Some(data) = S::data(frame) {
                    bases = bases.data(data);
                }

                let lsda = Lsda::new(bytes, bases, ENDIAN).map_err(|_error| ());

                match lsda {
                    Ok(lsda) => scan(&lsda, frame.ip().site()).map_err(|_error| ()),
                    Err(error) => Err(error),
                }
            },
            _ => Err(()),
        }
    }

    /// Prepares the phase two context for one validated Rust landing pad.
    fn install<'a>(frame: CleanupFrame<'a>, exception: ExceptionRef<'a>, pad: Pad) -> InstalledContext<'a> {
        let address = pad.nonzero();

        // SAFETY:
        // Source proves the LSDA bytes belong to the active image and scan only
        // constructs Pad from the landing address decoded for this frame. The
        // address is nonzero and the compiler emitted the landing pad using the
        // target's Itanium EH register convention.
        let landing = unsafe { LandingPad::new(address) };
        let selector = Selector::new(0);

        frame.install(landing, exception, selector)
    }
}

impl<S: Source> Personality for Policy<S> {
    #[inline]
    fn search(call: Search<'_>) -> SearchDecision {
        let action = Self::action(call.frame());

        match action {
            Ok(Action::None | Action::Cleanup(_)) => SearchDecision::Continue,
            Ok(Action::Catch(_) | Action::Filter(_)) => SearchDecision::HandlerFound,
            Ok(Action::Terminate) | Err(()) => SearchDecision::Fatal,
        }
    }

    #[inline]
    fn cleanup<'a>(call: Cleanup<'a>) -> CleanupDecision<'a> {
        let frame = call.frame();
        let action = Self::action(&frame);
        let forced = call.forced();

        match (action, forced) {
            (Ok(Action::None), _) => CleanupDecision::Continue,
            (Ok(Action::Filter(_)), true) => CleanupDecision::Continue,
            (Ok(Action::Cleanup(pad) | Action::Catch(pad) | Action::Filter(pad)), false)
            | (Ok(Action::Cleanup(pad) | Action::Catch(pad)), true) => {
                let (frame, exception, _) = call.split();

                let context = Self::install(frame, exception, pad);

                CleanupDecision::Install(context)
            },
            (Ok(Action::Terminate), _) | (Err(()), _) => CleanupDecision::Fatal,
        }
    }

    #[inline]
    fn handler<'a>(call: Handler<'a>) -> HandlerDecision<'a> {
        let frame = call.frame();
        let action = Self::action(&frame);

        match action {
            Ok(Action::Catch(pad) | Action::Filter(pad)) => {
                let (frame, exception) = call.split();

                let context = Self::install(frame, exception, pad);

                HandlerDecision::Install(context)
            },
            _ => HandlerDecision::Fatal,
        }
    }
}
