//! Structured failures from physical unwind reconstruction.
//!
//! These errors are shared by machine register access, DWARF frame resolution,
//! expression evaluation, and cursor traversal. They describe recoverable unwind
//! failures rather than language personality outcomes.

use desenredo_dwarf::cfi::CfiError;
use gimli::Register;

/// Failure while reconstructing a physical stack.
#[derive(Debug, fack::prelude::Error)]
pub enum UnwindError {
    /// No trusted unwind image owns the current instruction address.
    #[error("no unwind image for instruction")]
    Image,

    /// The unwinder could not satisfy a CFI memory read.
    #[error("unwind memory read failed")]
    Memory,

    /// A DWARF register is not represented by the current machine state.
    #[error("unsupported unwind register")]
    Register(Register),

    /// A modeled register has no value established for the current activation.
    #[error("unavailable unwind register")]
    Unavailable(Register),

    /// The reconstructed state is incomplete for landing-pad installation.
    #[error("incomplete landing-pad register state")]
    Install,

    /// A DWARF expression requested an unavailable capability.
    #[error("unsupported unwind expression")]
    Expression,

    /// A decoded address cannot be represented by the target address width.
    #[error("unwind address is out of range")]
    Address,

    /// The DWARF parser or expression evaluator rejected the metadata.
    #[error("DWARF unwind operation failed")]
    Gimli(gimli::Error),

    /// Desenredo CFI row evaluation rejected the metadata.
    #[error("CFI row evaluation failed")]
    Cfi(CfiError),
}
