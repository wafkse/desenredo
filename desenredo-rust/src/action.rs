//! Classification of one rustc GCC-style LSDA call site.
//!
//! Rust uses the generic GCC call-site and action tables with language-specific
//! meaning. Action zero is cleanup-only, positive entries identify Rust catch
//! landing pads, and negative entries identify filter landing pads. A program
//! counter outside every call-site range is treated as a terminate region.

use core::num::NonZeroUsize;

use desenredo_lsda::{
    error::LsdaError,
    table::{Kind, Lsda},
};

/// Nonzero landing-pad address decoded from Rust LSDA metadata.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
// NOTE(invariant): The stored address is nonzero and was decoded as the landing pad for one
// validated Rust LSDA call site.
pub struct Pad(NonZeroUsize);

impl Pad {
    /// Returns the decoded executable address.
    #[inline]
    pub const fn addr(self) -> usize {
        let Self(addr) = self;

        addr.get()
    }

    /// Returns the nonzero executable-address proof.
    #[inline]
    pub const fn nonzero(self) -> NonZeroUsize {
        let Self(addr) = self;

        addr
    }
}

/// Rust interpretation of one protected call site.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Action {
    /// No landing pad is required.
    None,

    /// Run compiler-generated cleanup code.
    Cleanup(Pad),

    /// Stop at a Rust panic catch boundary.
    Catch(Pad),

    /// Run a Rust exception filter landing pad.
    Filter(Pad),

    /// Treat the call site as non-unwinding.
    Terminate,
}

/// Failure while interpreting Rust exception metadata.
#[derive(Debug, Copy, Clone, Eq, PartialEq, fack::prelude::Error)]
pub enum ActionError {
    /// The generic LSDA structure is malformed.
    #[error("invalid Rust LSDA")]
    #[error(from)]
    Parse(LsdaError),

    /// A typed action entry resolved to an empty chain.
    #[error("empty Rust LSDA action chain")]
    Chain,

    /// A landing pad encoded as zero where executable code was required.
    #[error("zero Rust landing pad address")]
    Landing,
}

impl Pad {
    /// Validates one executable landing pad address decoded from LSDA metadata.
    #[inline]
    fn new(addr: usize) -> Result<Self, ActionError> {
        NonZeroUsize::new(addr).map(Self).ok_or(ActionError::Landing)
    }
}

/// Interprets one Rust call site using rustc's GCC-style LSDA policy.
///
/// # Errors
///
/// Returns a structural LSDA error, an empty action-chain error, or a zero
/// landing-pad error.
#[inline]
pub fn scan(lsda: &Lsda<'_>, pc: usize) -> Result<Action, ActionError> {
    match lsda.site(pc)? {
        None => Ok(Action::Terminate),
        Some(target_site) => match target_site.land() {
            None => Ok(Action::None),
            Some(addr) => {
                let pad = Pad::new(addr)?;

                match target_site.action() {
                    None => Ok(Action::Cleanup(pad)),
                    Some(action) => {
                        let mut chain = lsda.chain(action)?;
                        let kind = chain.next().transpose()?.ok_or(ActionError::Chain)?;

                        match kind {
                            Kind::Cleanup => Ok(Action::Cleanup(pad)),
                            Kind::Catch(_) => Ok(Action::Catch(pad)),
                            Kind::Filter(_) => Ok(Action::Filter(pad)),
                        }
                    },
                }
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use desenredo_lsda::{
        encoding::{Bases, Endian},
        table::Lsda,
    };

    use super::{Action, scan};

    #[test]
    fn cleanup_entry_selects_drop_landing_pad() {
        let bytes = [0xff, 0xff, 0x01, 0x04, 0x00, 0x05, 0x0a, 0x00];
        let bases = Bases::new(0x1000, 0x2000);
        let lsda = Lsda::new(&bytes, bases, Endian::Little).expect("valid fixture");
        let action = scan(&lsda, 0x2002).expect("valid Rust action");

        assert!(matches!(action, Action::Cleanup(_)));
    }

    #[test]
    fn positive_action_selects_rust_catch() {
        let bytes = [0xff, 0xff, 0x01, 0x04, 0x00, 0x05, 0x0a, 0x01, 0x01, 0x00];
        let bases = Bases::new(0x1000, 0x2000);
        let lsda = Lsda::new(&bytes, bases, Endian::Little).expect("valid fixture");
        let action = scan(&lsda, 0x2002).expect("valid Rust action");

        assert!(matches!(action, Action::Catch(_)));
    }

    #[test]
    fn rustc_cleanup_table_matches_policy() {
        let bytes = [
            0xff, 0x9b, 0x11, 0x01, 0x0c, 0x04, 0x09, 0x1f, 0x00, 0x0f, 0x0e, 0x3f, 0x01, 0x1d, 0x32, 0x00, 0x00, 0x7f,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let bases = Bases::new(0x1000, 0x2000);
        let lsda = Lsda::new(&bytes, bases, Endian::Little).expect("valid rustc fixture");
        let cleanup = scan(&lsda, 0x2005).expect("valid cleanup action");
        let filter = scan(&lsda, 0x2010).expect("valid filter action");
        let none = scan(&lsda, 0x201e).expect("valid no-action site");

        assert!(matches!(cleanup, Action::Cleanup(_)));
        assert!(matches!(filter, Action::Filter(_)));
        assert_eq!(none, Action::None);
    }

    #[test]
    fn uncovered_call_site_is_terminate() {
        let bytes = [0xff, 0xff, 0x01, 0x04, 0x00, 0x05, 0x0a, 0x00];
        let bases = Bases::new(0x1000, 0x2000);
        let lsda = Lsda::new(&bytes, bases, Endian::Little).expect("valid fixture");
        let action = scan(&lsda, 0x2008).expect("valid Rust action");

        assert_eq!(action, Action::Terminate);
    }
}
