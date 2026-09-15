//! DWARF CFI evaluation for implementations of the system unwinder.
//!
//! This module uses `gimli` only for `.eh_frame` CIE, FDE, and call-frame
//! instruction evaluation. C++ LSDA action tables remain a personality concern.
//! The selected `read-core` feature requires neither `std` nor `alloc`.

use gimli::{
    BaseAddresses, EhFrame, FrameDescriptionEntry, Reader, ReaderOffset, Register, RegisterRule, UnwindContext,
    UnwindContextStorage, UnwindSection, UnwindTableRow,
};

/// Failure while evaluating DWARF call-frame information.
#[derive(Debug, fack::prelude::Error)]
pub enum CfiError {
    /// The underlying DWARF evaluator rejected the frame metadata or storage.
    #[error("DWARF unwind evaluation failed")]
    #[error(from)]
    Gimli(gimli::Error),
}

/// Inline storage policy for `gimli` call-frame evaluation.
///
/// Exhausting either capacity is reported by `gimli` as an unwind error rather
/// than allocating dynamically.
#[derive(Debug, Copy, Clone)]
pub struct Storage<const RULES: usize, const STACK: usize>;

impl<const RULES: usize, const STACK: usize> Storage<RULES, STACK> {
    /// Maximum register rules retained in one unwind row.
    pub const RULES: usize = RULES;
    /// Maximum saved unwind-table rows retained by the evaluator.
    pub const STACK: usize = STACK;
}

impl<T, const RULES: usize, const STACK: usize> UnwindContextStorage<T> for Storage<RULES, STACK>
where
    T: ReaderOffset,
{
    type Rules = [(Register, RegisterRule<T>); RULES];
    type Stack = [UnwindTableRow<T, Self>; STACK];
}

/// Inline capacities matching the current `gimli` heap-backed defaults.
pub type Inline = Storage<192, 4>;

/// Evaluates one already selected frame description entry.
///
/// # Errors
///
/// Returns the parsing or storage-capacity error reported by `gimli`.
#[inline]
pub fn row<'ctx, R, S>(
    frame: &EhFrame<R>,
    bases: &BaseAddresses,
    fde: &FrameDescriptionEntry<R>,
    context: &'ctx mut UnwindContext<R::Offset, S>,
    address: u64,
) -> Result<&'ctx UnwindTableRow<R::Offset, S>, CfiError>
where
    R: Reader,
    S: UnwindContextStorage<R::Offset>,
{
    let row = fde.unwind_info_for_address(frame, bases, context, address)?;

    Ok(row)
}

/// Evaluates `.eh_frame` CFI for one program counter.
///
/// # Errors
///
/// Returns the parsing or storage-capacity error reported by `gimli`.
#[inline]
pub fn unwind<'ctx, R, S>(
    frame: &EhFrame<R>,
    bases: &BaseAddresses,
    context: &'ctx mut UnwindContext<R::Offset, S>,
    address: u64,
) -> Result<&'ctx UnwindTableRow<R::Offset, S>, CfiError>
where
    R: Reader,
    S: UnwindContextStorage<R::Offset>,
{
    let row = frame.unwind_info_for_address(bases, context, address, EhFrame::cie_from_offset)?;

    Ok(row)
}

#[cfg(test)]
mod tests {
    use gimli::UnwindContext;

    use super::Inline;

    #[test]
    fn inline() {
        let _: UnwindContext<usize, Inline> = UnwindContext::new_in();
    }
}
