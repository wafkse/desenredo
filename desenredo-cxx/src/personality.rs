//! C++ personality policy over bounded Itanium LSDA metadata.
//!
//! The scanner follows the same phase split used by Rust and GNU personalities.
//! Cleanup discovery is independent from RTTI matching. Runtime-private C++
//! matching and handler persistence are delegated to an unsafe capability.

use core::{error::Error, marker::PhantomData, num::NonZeroUsize};

use desenredo_abi::class::ExceptionClass;
use desenredo_lsda::{
    encoding::{Bases, Endian, Target},
    error::LsdaError,
    table::{FilterIndex, Kind, Lsda, TypeIndex},
};
use desenredo_personality::{
    context::{CleanupFrame, ExceptionRef, Frame, InstalledContext, LandingPad, Selector},
    protocol::{Cleanup, CleanupDecision, Handler, HandlerDecision, Personality, Search, SearchDecision},
    source::Source,
};

/// Nonzero landing pad decoded from C++ LSDA metadata.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
// NOTE(invariant): The stored address is nonzero and was decoded as the landing pad for one
// validated C++ LSDA call site.
pub struct Pad(NonZeroUsize);

impl Pad {
    /// Returns the decoded code address.
    #[inline]
    pub const fn addr(self) -> usize {
        let Self(addr) = self;

        addr.get()
    }
}
/// One positive C++ catch clause and its decoded RTTI target.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
// NOTE(invariant): index is positive and target is the decoded RTTI entry selected by that exact
// index in the same bounded LSDA.
pub struct Catch {
    /// One-based RTTI table index used as the landing-pad selector.
    index: TypeIndex,

    /// Decoded RTTI address before optional ABI indirection.
    target: Target,
}

impl Catch {
    /// Returns the RTTI table index.
    #[inline]
    pub const fn index(self) -> TypeIndex {
        let Self { index, .. } = self;

        index
    }

    /// Returns the encoded RTTI target.
    #[inline]
    pub const fn target(self) -> Target {
        let Self { target, .. } = self;

        target
    }
}

/// One handler clause requiring runtime matching.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Clause {
    /// Positive RTTI catch clause.
    Catch(Catch),

    /// Negative dynamic exception specification clause.
    Filter(FilterIndex),
}

/// Matcher invocation stage.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Stage {
    /// Phase-one handler search.
    Search,

    /// Phase-two selected handler restoration.
    Handler,
}
/// C++ runtime capability for RTTI matching and private handler state.
///
/// # Safety
///
/// Implementations may inspect runtime-private exception state which Desenredo
/// deliberately keeps opaque. A domestic exception may be reinterpreted as that
/// private representation only when `class` proves it belongs to the matching
/// runtime domain and `exception` is the active object delivered by the unwinder.
///
/// A successful `Stage::Search` result must persist every private fact required
/// by the later selected-handler landing pad. This includes adjusted object
/// pointers, selector agreement, and any handler cache expected by the runtime.
/// `Stage::Handler` for that selected frame must reproduce the phase-one result.
///
/// Foreign exceptions must never be cast to a domestic private header. They may
/// match only clauses whose behavior the implementation can provide from the
/// generic unwind header and public metadata. Returning `true` promises that the
/// subsequent landing pad and catch runtime can safely consume the resulting
/// state.
pub unsafe trait Matcher {
    /// Structured matcher failure.
    type Error: Error;

    /// Tests one clause against the active exception.
    ///
    /// The matcher may inspect dynamic exception specification entries through
    /// `Lsda::filter` when `clause` is `Clause::Filter`. A `true` result is a
    /// runtime-state commitment under the unsafe trait contract rather than only
    /// an RTTI comparison result.
    fn test(
        stage: Stage,
        exception: ExceptionRef<'_>,
        class: ExceptionClass,
        lsda: &Lsda<'_>,
        clause: Clause,
        selector: Selector,
    ) -> Result<bool, Self::Error>;
}

/// C++ interpretation of one protected call site.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Action {
    /// No landing pad is required.
    None,

    /// Run compiler-generated cleanup code with selector zero.
    Cleanup(Pad),

    /// Transfer to the selected handler with its ABI selector.
    Handler(Pad, Selector),

    /// Treat the call site as non-unwinding.
    Terminate,
}
/// Failure while interpreting C++ exception metadata.
#[derive(Debug, Copy, Clone, Eq, PartialEq, fack::prelude::Error)]
pub enum CxxError {
    /// Generic LSDA structure is malformed.
    #[error("invalid C++ LSDA")]
    #[error(from)]
    Parse(LsdaError),

    /// A landing pad encoded as zero where code was required.
    #[error("zero C++ landing pad address")]
    Landing,

    /// A typed catch clause has no RTTI table.
    #[error("missing C++ RTTI table")]
    Types,

    /// A type index cannot be represented by the landing-pad selector width.
    #[error("C++ selector is out of range")]
    Selector,
}

/// Failure from metadata interpretation or runtime matching.
#[derive(Debug, fack::prelude::Error)]
pub enum Failure<E>
where
    E: Error,
{
    /// Metadata interpretation failed before runtime matching.
    #[error("invalid C++ exception metadata")]
    Metadata(CxxError),

    /// The selected runtime matcher failed.
    #[error("C++ runtime matcher failed")]
    Match(E),
}

impl Pad {
    /// Validates one executable landing pad decoded from C++ metadata.
    #[inline]
    fn new(addr: usize) -> Result<Self, CxxError> {
        NonZeroUsize::new(addr).map(Self).ok_or(CxxError::Landing)
    }
}

impl Clause {
    /// Resolves one positive RTTI catch clause from the reverse type table.
    #[inline]
    fn catch(lsda: &Lsda<'_>, index: TypeIndex) -> Result<Self, CxxError> {
        let types = lsda.types().ok_or(CxxError::Types)?;
        let target = types.get(lsda, index)?;

        Ok(Self::Catch(Catch { index, target }))
    }

    /// Converts one clause discriminator into the landing pad selector.
    #[inline]
    fn selector(self) -> Result<Selector, CxxError> {
        let value = match self {
            Self::Catch(catch) => isize::try_from(catch.index().raw()).map_err(|_error| CxxError::Selector)?,
            Self::Filter(index) => {
                let value = isize::try_from(index.raw()).map_err(|_error| CxxError::Selector)?;

                value.checked_neg().ok_or(CxxError::Selector)?
            },
        };

        Ok(Selector::new(value))
    }

    /// Tests one clause with the selected runtime matcher.
    fn test<M>(
        self,
        stage: Stage,
        exception: ExceptionRef<'_>,
        class: ExceptionClass,
        lsda: &Lsda<'_>,
    ) -> Result<Option<Selector>, Failure<M::Error>>
    where
        M: Matcher,
    {
        let selector = Self::selector(self).map_err(Failure::Metadata)?;
        let matched = M::test(stage, exception, class, lsda, self, selector).map_err(Failure::Match)?;

        if matched { Ok(Some(selector)) } else { Ok(None) }
    }
}

/// Finds cleanup work for one C++ call site without performing RTTI matching.
///
/// # Errors
///
/// Returns a structural metadata error for malformed bounded LSDA input.
#[inline]
pub fn clean(lsda: &Lsda<'_>, pc: usize) -> Result<Action, CxxError> {
    let site = lsda.site(pc)?;

    match site {
        None => Ok(Action::Terminate),
        Some(site) => match site.land() {
            None => Ok(Action::None),
            Some(addr) => {
                let pad = Pad::new(addr)?;

                match site.action() {
                    None => Ok(Action::Cleanup(pad)),
                    Some(action) => {
                        let mut cleanup = false;

                        for kind in lsda.chain(action)? {
                            match kind? {
                                Kind::Cleanup => cleanup = true,
                                Kind::Catch(_) | Kind::Filter(_) => {},
                            }
                        }

                        if cleanup {
                            Ok(Action::Cleanup(pad))
                        } else {
                            Ok(Action::None)
                        }
                    },
                }
            },
        },
    }
}
/// Scans one C++ call site for cleanup or handler work.
fn scan<M>(
    stage: Stage,
    lsda: &Lsda<'_>,
    pc: usize,
    exception: ExceptionRef<'_>,
    class: ExceptionClass,
) -> Result<Action, Failure<M::Error>>
where
    M: Matcher,
{
    let site = lsda.site(pc).map_err(CxxError::from).map_err(Failure::Metadata)?;

    match site {
        None => Ok(Action::Terminate),
        Some(site) => match site.land() {
            None => Ok(Action::None),
            Some(addr) => {
                let pad = Pad::new(addr).map_err(Failure::Metadata)?;

                match site.action() {
                    None => Ok(Action::Cleanup(pad)),
                    Some(action) => {
                        let chain = lsda.chain(action).map_err(CxxError::from).map_err(Failure::Metadata);

                        match chain {
                            Err(error) => Err(error),
                            Ok(chain) => {
                                let mut cleanup = false;
                                let mut selected = None;
                                let mut failure = None;

                                for kind in chain {
                                    let outcome = match kind {
                                        Err(error) => Err(Failure::Metadata(CxxError::from(error))),
                                        Ok(Kind::Cleanup) => {
                                            cleanup = true;
                                            Ok(None)
                                        },
                                        Ok(Kind::Catch(index)) => Clause::catch(lsda, index)
                                            .map_err(Failure::Metadata)
                                            .and_then(|clause| clause.test::<M>(stage, exception, class, lsda)),
                                        Ok(Kind::Filter(index)) => {
                                            Clause::Filter(index).test::<M>(stage, exception, class, lsda)
                                        },
                                    };

                                    match outcome {
                                        Ok(Some(selector)) => {
                                            selected = Some(selector);
                                            break;
                                        },
                                        Ok(None) => {},
                                        Err(error) => {
                                            failure = Some(error);
                                            break;
                                        },
                                    }
                                }

                                match (failure, selected, cleanup) {
                                    (Some(error), _, _) => Err(error),
                                    (None, Some(selector), _) => Ok(Action::Handler(pad, selector)),
                                    (None, None, true) => Ok(Action::Cleanup(pad)),
                                    (None, None, false) => Ok(Action::None),
                                }
                            },
                        }
                    },
                }
            },
        },
    }
}

/// Searches one C++ frame for a matching handler.
///
/// # Errors
///
/// Returns metadata or runtime matcher failures structurally.
#[inline]
pub fn search<M>(
    lsda: &Lsda<'_>,
    pc: usize,
    exception: ExceptionRef<'_>,
    class: ExceptionClass,
) -> Result<Action, Failure<M::Error>>
where
    M: Matcher,
{
    scan::<M>(Stage::Search, lsda, pc, exception, class)
}

/// Restores the handler selected for one C++ frame during phase two.
///
/// # Errors
///
/// Returns metadata or runtime matcher failures structurally.
#[inline]
pub fn handler<M>(
    lsda: &Lsda<'_>,
    pc: usize,
    exception: ExceptionRef<'_>,
    class: ExceptionClass,
) -> Result<Action, Failure<M::Error>>
where
    M: Matcher,
{
    scan::<M>(Stage::Handler, lsda, pc, exception, class)
}

/// C++ personality policy backed by one LSDA source and runtime matcher.
#[derive(Debug, Copy, Clone)]
// NOTE(invariant): The zero-sized marker fixes one LSDA source and one runtime matcher policy
// without runtime state.
pub struct Policy<S, M>(PhantomData<(S, M)>);

/// Short alias for the C++ personality policy.
pub type Cxx<S, M> = Policy<S, M>;

#[cfg(target_endian = "little")]
/// Native LSDA byte order on little endian targets.
const ENDIAN: Endian = Endian::Little;

#[cfg(target_endian = "big")]
/// Native LSDA byte order on big endian targets.
const ENDIAN: Endian = Endian::Big;
impl<S: Source, M: Matcher> Policy<S, M> {
    /// Bounds and parses the LSDA attached to one live frame.
    fn lsda<'a>(frame: &Frame<'a>) -> Result<Option<Lsda<'a>>, ()> {
        let origin = frame.lsda();
        let bytes = S::bytes(frame);
        let aligned = match (origin, bytes.as_ref()) {
            (Some(origin), Ok(&Some(bytes))) => origin.as_ptr().addr() == bytes.as_ptr().addr(),
            _ => true,
        };

        match (origin, bytes, aligned) {
            (None, Ok(None), true) => Ok(None),
            (Some(origin), Ok(Some(bytes)), true) => {
                let origin = origin.as_ptr().addr();
                let mut bases = Bases::new(origin, frame.start());

                if let Some(text) = S::text(frame) {
                    bases = bases.text(text);
                }
                if let Some(data) = S::data(frame) {
                    bases = bases.data(data);
                }

                let lsda = Lsda::new(bytes, bases, ENDIAN).map_err(|_error| ())?;

                Ok(Some(lsda))
            },
            _ => Err(()),
        }
    }

    /// Prepares one selected C++ landing pad for phase two installation.
    fn install<'a>(
        frame: CleanupFrame<'a>,
        exception: ExceptionRef<'a>,
        pad: Pad,
        selector: Selector,
    ) -> InstalledContext<'a> {
        let Pad(address) = pad;

        // SAFETY:
        // Source ties the bounded LSDA to this live frame image. Pad came from the
        // call-site entry selected for this frame and proves a nonzero decoded
        // address. The C++ compiler emitted that landing pad for the same target
        // EH data-register convention used by CleanupFrame::install.
        let landing = unsafe { LandingPad::new(address) };

        frame.install(landing, exception, selector)
    }
}

impl<S: Source, M: Matcher> Personality for Policy<S, M> {
    #[inline]
    fn search(call: Search<'_>) -> SearchDecision {
        let frame = call.frame();
        let lsda = Self::lsda(frame);

        match lsda {
            Ok(None) => SearchDecision::Continue,
            Err(()) => SearchDecision::Fatal,
            Ok(Some(lsda)) => {
                let action = search::<M>(&lsda, frame.ip().site(), call.exception(), call.class());

                match action {
                    Ok(Action::None | Action::Cleanup(_)) => SearchDecision::Continue,
                    Ok(Action::Handler(_, _)) => SearchDecision::HandlerFound,
                    Ok(Action::Terminate) | Err(_) => SearchDecision::Fatal,
                }
            },
        }
    }

    #[inline]
    fn cleanup<'a>(call: Cleanup<'a>) -> CleanupDecision<'a> {
        let frame = call.frame();
        let lsda = Self::lsda(&frame);

        match lsda {
            Ok(None) => CleanupDecision::Continue,
            Err(()) => CleanupDecision::Fatal,
            Ok(Some(lsda)) => {
                let action = clean(&lsda, frame.ip().site());

                match action {
                    Ok(Action::None) => CleanupDecision::Continue,
                    Ok(Action::Cleanup(pad)) => {
                        let (frame, exception, _) = call.split();

                        let selector = Selector::new(0);
                        let context = Self::install(frame, exception, pad, selector);

                        CleanupDecision::Install(context)
                    },
                    Ok(Action::Handler(_, _) | Action::Terminate) | Err(_) => CleanupDecision::Fatal,
                }
            },
        }
    }

    #[inline]
    fn handler<'a>(call: Handler<'a>) -> HandlerDecision<'a> {
        let class = call.class();

        let (frame, exception) = call.split();

        let view = frame.frame();
        let lsda = Self::lsda(&view);

        match lsda {
            Ok(Some(lsda)) => {
                let action = handler::<M>(&lsda, view.ip().site(), exception, class);

                match action {
                    Ok(Action::Handler(pad, selector)) => {
                        let context = Self::install(frame, exception, pad, selector);

                        HandlerDecision::Install(context)
                    },
                    _ => HandlerDecision::Fatal,
                }
            },
            Ok(None) | Err(()) => HandlerDecision::Fatal,
        }
    }
}
#[cfg(test)]
mod tests {
    use desenredo_lsda::{
        encoding::{Bases, Endian},
        table::{Kind, Lsda},
    };

    use super::{Action, Clause, clean};
    #[test]
    fn cleanup_scan_finds_cleanup_in_action_chain() {
        let bytes = [0xff, 0xff, 0x01, 0x04, 0x00, 0x05, 0x0a, 0x01, 0x00, 0x01, 0x01, 0x00];
        let bases = Bases::new(0x1000, 0x2000);
        let lsda = Lsda::new(&bytes, bases, Endian::Little).expect("valid cleanup fixture");
        let action = clean(&lsda, 0x2002).expect("valid cleanup scan");

        assert!(
            matches!(action, Action::Cleanup(_)),
            "cleanup action must be discovered"
        );
    }

    #[test]
    fn catch_clause_uses_positive_type_index_as_selector() {
        let bytes = [
            0xff, 0x00, 0x10, 0x01, 0x04, 0x00, 0x05, 0x0a, 0x01, 0x01, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ];
        let bases = Bases::new(0x1000, 0x2000);
        let lsda = Lsda::new(&bytes, bases, Endian::Little).expect("valid catch fixture");
        let site = lsda.site(0x2002).expect("valid site").expect("covered site");
        let action = site.action().expect("typed action");
        let mut chain = lsda.chain(action).expect("valid action chain");
        let kind = chain.next().expect("catch record").expect("valid record");
        let index = match kind {
            Kind::Catch(index) => Some(index),
            _ => None,
        }
        .expect("expected catch record");
        let clause = Clause::catch(&lsda, index).expect("valid catch clause");
        let selector = clause.selector().expect("selector fits isize");

        assert_eq!(selector.raw(), 1, "positive type index must become selector one");
    }
}
