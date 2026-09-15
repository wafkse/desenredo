//! Structural failures reported while decoding bounded LSDA metadata.

/// A malformed or unsupported LSDA input.
#[derive(Debug, Copy, Clone, Eq, PartialEq, fack::prelude::Error)]
pub enum LsdaError {
    /// Input ended before the requested value was complete.
    #[error("truncated LSDA input")]
    Eof,

    /// A pointer encoding is unknown or unsupported here.
    #[error("invalid LSDA pointer encoding")]
    Encoding,

    /// A relative pointer requires a base that was not supplied.
    #[error("missing LSDA pointer base")]
    Base,

    /// Address or table arithmetic overflowed.
    #[error("LSDA arithmetic overflow")]
    Overflow,

    /// A table relation points outside the caller-bounded LSDA bytes.
    #[error("LSDA table relation is out of bounds")]
    Table,

    /// An action chain exceeded the bounded progress limit.
    #[error("LSDA action chain did not make bounded progress")]
    Loop,
}
