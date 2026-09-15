//! Instruction-pointer relation for physical frame lookup.

/// Relation between the stored instruction pointer and the active instruction.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Relation {
    /// The value is a return address after a call instruction.
    Return,

    /// The value denotes the interrupted instruction itself.
    Instruction,
}

impl Relation {
    /// Converts the stored instruction pointer into the CFI lookup address.
    #[inline]
    pub const fn site(self, address: usize) -> Option<usize> {
        match self {
            Self::Return => address.checked_sub(1),
            Self::Instruction => Some(address),
        }
    }

    /// Reports the Level I before instruction flag.
    #[inline]
    pub const fn before(self) -> bool {
        matches!(self, Self::Instruction)
    }
}
