//! Allocation free traversal of one physical stack.
//!
//! A cursor owns one reconstructed machine state. Each successful step resolves
//! one FDE, reports the current physical frame, and advances to its caller.
//!
//! Architecture-specific capture is completed before a cursor is created. The
//! cursor therefore owns semantic register state rather than raw ABI transport.

use core::marker::PhantomData;

use gimli::Register;

use crate::{arch::x86_64::state::State, error::UnwindError, relation::Relation, runtime::Unwinder, source::Info};

/// Internal identity used to match one physical frame across unwind phases.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
// NOTE(invariant): A key is produced from the active cursor stack identity and is
// compared only against keys produced by the same physical traversal model.
pub struct Key(usize);

impl Key {
    /// Creates a physical frame identity from a traversal stack key.
    ///
    /// # Safety
    ///
    /// `value` must have been produced by [`Cursor::key`] for the same physical
    /// traversal model or recovered unchanged from Desenredo-owned resume state.
    #[inline]
    pub const unsafe fn new(value: usize) -> Self {
        Self(value)
    }

    /// Returns the stored stack key.
    #[inline]
    pub const fn get(self) -> usize {
        let Self(value) = self;

        value
    }
}

/// Read only information about one reconstructed physical frame.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
// NOTE(invariant): ip and sp describe the same reconstructed physical activation before caller
// advancement.
pub struct Frame {
    /// Instruction address used to select the frame description entry.
    ip: usize,

    /// Stack pointer carried by the cursor before caller reconstruction.
    sp: usize,
}

impl Frame {
    /// Returns the instruction address represented by this frame.
    #[inline]
    pub const fn ip(self) -> usize {
        let Self { ip, .. } = self;

        ip
    }

    /// Returns the stack pointer represented by this frame.
    #[inline]
    pub const fn sp(self) -> usize {
        let Self { sp, .. } = self;

        sp
    }
}

/// Cursor over one currently live physical stack.
// NOTE(invariant): state and relation describe the same activation and every advance replaces both
// from one trusted FDE before another frame is observed.
pub struct Cursor<U: Unwinder> {
    /// Machine state for the frame currently being inspected.
    state: State,

    /// Instruction relation used for the next FDE lookup.
    relation: Relation,

    /// Compile time identity of the selected unwinder.
    marker: PhantomData<U>,
}

impl<U: Unwinder> Cursor<U> {
    /// Captures a cursor rooted at the current execution stack.
    #[inline(never)]
    pub fn capture() -> Self {
        let state = State::capture();

        Self::new(state)
    }

    /// Creates an ABI traversal cursor from one captured machine state.
    #[inline]
    pub const fn new(state: State) -> Self {
        let relation = Relation::Return;
        let marker = PhantomData;

        Self {
            state,
            relation,
            marker,
        }
    }

    /// Advances to the next physical frame.
    ///
    /// # Errors
    ///
    /// Returns a structured metadata, register, address, or memory failure when
    /// the caller frame cannot be reconstructed.
    #[inline]
    pub fn step(&mut self) -> Result<Option<Frame>, UnwindError> {
        let &mut Self {
            ref mut state,
            ref mut relation,
            ..
        } = self;

        let info = Info::new::<U>(state, *relation)?;

        match info {
            None => Ok(None),
            Some(info) => {
                let ip = info.ip();
                let sp = state.stack()?;
                let frame = Frame { ip, sp };
                let caller = info.caller::<U>(state)?;
                let next = if info.signal() {
                    Relation::Instruction
                } else {
                    Relation::Return
                };

                *state = caller;
                *relation = next;

                Ok(Some(frame))
            },
        }
    }

    /// Resolves the frame currently named by the cursor state.
    #[inline]
    pub fn current(&self) -> Result<Option<Info>, UnwindError> {
        let &Self {
            ref state, relation, ..
        } = self;

        Info::new::<U>(state, relation)
    }

    /// Replaces the cursor state with the caller reconstructed from `info`.
    #[inline]
    pub fn advance(&mut self, info: &Info) -> Result<(), UnwindError> {
        let &mut Self {
            ref mut state,
            ref mut relation,
            ..
        } = self;

        let caller = info.caller::<U>(state)?;
        let next = if info.signal() {
            Relation::Instruction
        } else {
            Relation::Return
        };

        *state = caller;
        *relation = next;

        Ok(())
    }

    /// Reads one DWARF register from the current reconstructed state.
    #[inline]
    pub const fn read(&self, register: Register) -> Result<usize, UnwindError> {
        let &Self { ref state, .. } = self;

        state.read(register)
    }

    /// Writes one DWARF register in the current reconstructed state.
    #[inline]
    pub fn write(&mut self, register: Register, value: usize) -> Result<(), UnwindError> {
        let &mut Self { ref mut state, .. } = self;

        state.write(register, value)
    }

    /// Returns the current stack pointer.
    #[inline]
    pub const fn stack(&self) -> Result<usize, UnwindError> {
        let &Self { ref state, .. } = self;

        state.stack()
    }

    /// Returns the current instruction pointer image.
    #[inline]
    pub const fn ip(&self) -> Option<usize> {
        let &Self { ref state, .. } = self;

        state.ip()
    }

    /// Returns the current instruction relation.
    #[inline]
    pub const fn relation(&self) -> Relation {
        let &Self { relation, .. } = self;

        relation
    }

    /// Returns the physical frame identity used by Level I phase matching.
    #[inline]
    pub fn key(&self) -> Result<Key, UnwindError> {
        let &Self {
            ref state, relation, ..
        } = self;

        let adjustment = usize::from(relation.before());
        let value = state.stack()?.wrapping_sub(adjustment);

        // SAFETY:
        // value is derived from this cursor's active physical frame identity.
        Ok(unsafe { Key::new(value) })
    }

    /// Applies the saved argument stack adjustment for landing pad installation.
    #[inline]
    pub fn adjust(&mut self, size: usize) -> Result<(), UnwindError> {
        let &mut Self { ref mut state, .. } = self;

        state.adjust(size)
    }

    /// Consumes the cursor and returns its installable machine state.
    #[inline]
    pub const fn take(self) -> State {
        let Self { state, .. } = self;

        state
    }
}
