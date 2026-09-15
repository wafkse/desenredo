//! Trusted unwind images and resolved DWARF frame metadata.
//!
//! [`crate::source::Image`] is the public bounded-image capability supplied by an
//! [`crate::runtime::Unwinder`]. [`crate::source::Info`] is the resolved frame capability consumed
//! by cursors and the Level I runtime. Its parser representation remains private behind semantic
//! accessors.

use core::{mem::size_of, ops::Range};

use desenredo_dwarf::cfi::{self, Inline};
use gimli::{
    BaseAddresses, CfaRule, EhFrame, EndianSlice, Evaluation, EvaluationResult, EvaluationStorage, Expression,
    FrameDescriptionEntry, Location, NativeEndian, Piece, Pointer, Reader, RegisterRule, UnwindContext,
    UnwindExpression, UnwindSection, UnwindTableRow, Value,
};

use crate::{arch::x86_64::state::State, error::UnwindError, relation::Relation, runtime::Unwinder};

/// Native-endian DWARF reader over one bounded byte slice.
type Bytes<'a> = EndianSlice<'a, NativeEndian>;
/// Static reader type retained by resolved frame metadata.
type Input = Bytes<'static>;
/// Inline-storage unwind table row used by resolved frame metadata.
type Row = UnwindTableRow<usize, Inline>;

/// A bounded live `.eh_frame` image and its relocation bases.
#[derive(Clone)]
// NOTE(invariant): `text` is nonempty. The EH frame base is derived from the exact borrowed
// section address and the text base is derived from `text.start`. `data` is `None` exactly until
// the builder installs the same data relative value into both the semantic field and DWARF bases.
pub struct Image<'a> {
    /// Bounded call frame information for the loaded image.
    eh_frame: EhFrame<Bytes<'a>>,

    /// Relocation bases used while interpreting encoded pointers.
    bases: BaseAddresses,

    /// Executable address range described by this image.
    text: Range<usize>,

    /// Optional data relative base configured for this image.
    data: Option<usize>,
}

impl<'a> Image<'a> {
    /// Creates an unwind image from bounded live section bytes and a nonempty text range.
    ///
    /// Returns `None` when the text range is empty or an address cannot be represented by
    /// the DWARF address width.
    #[inline]
    pub fn new(eh_frame: &'a [u8], text: Range<usize>) -> Option<Self> {
        let Range { start, end } = text;

        let valid = start < end;
        let section = u64::try_from(eh_frame.as_ptr().addr()).ok();
        let start64 = u64::try_from(start).ok();

        match (valid, section, start64) {
            (true, Some(section), Some(start64)) => {
                let bases = BaseAddresses::default().set_eh_frame(section).set_text(start64);
                let eh_frame = EhFrame::new(eh_frame, NativeEndian);
                let text = start..end;
                let data = None;

                Some(Self {
                    eh_frame,
                    bases,
                    text,
                    data,
                })
            },
            _ => None,
        }
    }

    /// Adds the data relative base used by this loaded image.
    #[inline]
    pub fn data(self, data: usize) -> Self {
        let Self {
            eh_frame, bases, text, ..
        } = self;

        match u64::try_from(data) {
            Ok(base) => {
                let bases = bases.set_got(base);
                let data = Some(data);

                Self {
                    eh_frame,
                    bases,
                    text,
                    data,
                }
            },
            Err(_) => unreachable!("the supported 64-bit target address must fit in u64"),
        }
    }

    /// Reports whether an instruction address belongs to this image.
    #[inline]
    pub fn contains(&self, address: usize) -> bool {
        let &Self { ref text, .. } = self;

        text.contains(&address)
    }
}

/// Fixed storage for one DWARF expression evaluation.
struct Storage;

impl<R: Reader> EvaluationStorage<R> for Storage {
    type ExpressionStack = [(R, R); 0];
    type Result = [Piece<R>; 1];
    type Stack = [Value; 64];
}

/// Resolved unwind metadata for one physical frame.
// NOTE(invariant): `fde` and `row` were resolved from `image` for `instruction` and remain
// tied to that same static live image while the frame exists.
// NOTE(rationale): Cursor traversal and the Level I adapter consume this resolved
// frame capability through its public semantic operations while its parser representation stays
// private.
pub struct Info {
    /// Loaded image containing this frame.
    image: Image<'static>,

    /// Frame description entry selected for the instruction address.
    fde: FrameDescriptionEntry<Input>,

    /// Evaluated call frame row for the instruction address.
    row: Row,

    /// Instruction address used to select this frame.
    instruction: usize,
}

impl Info {
    /// Resolves the current register state into one frame description.
    #[inline]
    pub fn new<U>(state: &State, relation: Relation) -> Result<Option<Self>, UnwindError>
    where
        U: Unwinder,
    {
        let site = match state.ip() {
            None | Some(0) => None,
            Some(ip) => relation.site(ip),
        };

        match site {
            None => Ok(None),
            Some(instruction) => {
                let image = U::image(instruction).ok_or(UnwindError::Image)?;

                let &Image {
                    ref eh_frame,
                    ref bases,
                    ..
                } = &image;

                let instruction64 = u64::try_from(instruction).map_err(|_error| UnwindError::Address)?;
                let fde = eh_frame
                    .fde_for_address(bases, instruction64, EhFrame::cie_from_offset)
                    .map_err(UnwindError::Gimli)?;
                let mut context = UnwindContext::<usize, Inline>::new_in();
                let row = cfi::row(eh_frame, bases, &fde, &mut context, instruction64)
                    .map_err(UnwindError::Cfi)?
                    .clone();

                Ok(Some(Self {
                    image,
                    fde,
                    row,
                    instruction,
                }))
            },
        }
    }

    /// Returns the instruction address represented by this frame.
    #[inline]
    pub const fn ip(&self) -> usize {
        let &Self { instruction, .. } = self;

        instruction
    }

    /// Reports whether this frame changes instruction pointer relation.
    #[inline]
    pub fn signal(&self) -> bool {
        let &Self { ref fde, .. } = self;

        fde.is_signal_trampoline()
    }

    /// Returns the function region start described by the FDE.
    #[inline]
    pub fn start(&self) -> Result<usize, UnwindError> {
        let &Self { ref fde, .. } = self;

        usize::try_from(fde.initial_address()).map_err(|_error| UnwindError::Address)
    }

    /// Returns the text relative base for this frame image.
    #[inline]
    pub const fn text(&self) -> usize {
        let &Self {
            image: Image {
                text: Range { start, .. },
                ..
            },
            ..
        } = self;

        start
    }

    /// Returns the data relative base for this frame image when configured.
    #[inline]
    pub const fn data(&self) -> Option<usize> {
        let &Self { ref image, .. } = self;

        let &Image { data, .. } = image;

        data
    }

    /// Resolves the LSDA pointer for this frame when present.
    #[inline]
    pub fn lsda<U>(&self) -> Result<Option<usize>, UnwindError>
    where
        U: Unwinder,
    {
        let &Self { ref fde, .. } = self;

        fde.lsda().map(Self::pointer::<U>).transpose()
    }

    /// Resolves the personality routine pointer for this frame when present.
    #[inline]
    pub fn personality<U>(&self) -> Result<Option<usize>, UnwindError>
    where
        U: Unwinder,
    {
        let &Self { ref fde, .. } = self;

        fde.personality().map(Self::pointer::<U>).transpose()
    }

    /// Returns the stack adjustment requested before landing-pad installation.
    #[inline]
    pub fn args(&self) -> Result<usize, UnwindError> {
        let &Self { ref row, .. } = self;

        usize::try_from(row.saved_args_size()).map_err(|_error| UnwindError::Address)
    }

    /// Reconstructs the caller register image from this frame row.
    #[inline]
    pub fn caller<U>(&self, registers: &State) -> Result<State, UnwindError>
    where
        U: Unwinder,
    {
        let &Self { ref row, .. } = self;

        let cfa = match *row.cfa() {
            CfaRule::RegisterAndOffset { register, offset } => {
                let base = registers.read(register)?;
                let offset = isize::try_from(offset).map_err(|_error| UnwindError::Address)?;

                base.wrapping_add_signed(offset)
            },
            CfaRule::Expression(expression) => Self::expr::<U>(self, registers, expression, None)?,
        };
        // GNU x86_64 .eh_frame consumers carry an unsaved register value forward
        // from the current context. Gimli yields explicit non-default rules,
        // including DW_CFA_undefined. Cloning therefore models that default while
        // the loop replaces or clears every register with an explicit rule.
        let mut caller = registers.clone();

        caller.write(gimli::X86_64::RSP, cfa)?;
        caller.clear(gimli::X86_64::RA)?;

        for &(register, ref rule) in row.registers() {
            match *rule {
                RegisterRule::Undefined => caller.clear(register)?,
                RegisterRule::SameValue => {
                    let value = registers.read(register)?;

                    caller.write(register, value)?;
                },
                RegisterRule::Offset(offset) => {
                    let offset = isize::try_from(offset).map_err(|_error| UnwindError::Address)?;
                    let address = cfa.wrapping_add_signed(offset);
                    let value = Self::register::<U>(register, address)?;

                    caller.write(register, value)?;
                },
                RegisterRule::ValOffset(offset) => {
                    let offset = isize::try_from(offset).map_err(|_error| UnwindError::Address)?;
                    let value = cfa.wrapping_add_signed(offset);

                    caller.write(register, value)?;
                },
                RegisterRule::Register(source) => {
                    let value = registers.read(source)?;

                    caller.write(register, value)?;
                },
                RegisterRule::Expression(expression) => {
                    let address = Self::expr::<U>(self, registers, expression, Some(cfa))?;
                    let value = Self::register::<U>(register, address)?;

                    caller.write(register, value)?;
                },
                RegisterRule::ValExpression(expression) => {
                    let value = Self::expr::<U>(self, registers, expression, Some(cfa))?;

                    caller.write(register, value)?;
                },
                RegisterRule::Architectural => return Err(UnwindError::Expression),
                RegisterRule::Constant(value) => {
                    let value = usize::try_from(value).map_err(|_error| UnwindError::Address)?;

                    caller.write(register, value)?;
                },
            }
        }

        Ok(caller)
    }

    /// Resolves one encoded pointer using the selected address-space authority.
    fn pointer<U>(pointer: Pointer) -> Result<usize, UnwindError>
    where
        U: Unwinder,
    {
        match pointer {
            Pointer::Direct(address) => usize::try_from(address).map_err(|_error| UnwindError::Address),
            Pointer::Indirect(address) => {
                let address = usize::try_from(address).map_err(|_error| UnwindError::Address)?;

                Self::word::<U>(address)
            },
        }
    }

    /// Reads one saved register through the address-space capability.
    fn register<U>(register: gimli::Register, address: usize) -> Result<usize, UnwindError>
    where
        U: Unwinder,
    {
        let size = State::width(register)?;
        let value = U::read(address, size).ok_or(UnwindError::Memory)?;

        usize::try_from(value).map_err(|_error| UnwindError::Address)
    }

    /// Reads one native word through the address-space capability.
    fn word<U>(target_address: usize) -> Result<usize, UnwindError>
    where
        U: Unwinder,
    {
        let target_size = u8::try_from(size_of::<usize>()).map_err(|_error| UnwindError::Address)?;
        let target_value = U::read(target_address, target_size).ok_or(UnwindError::Memory)?;

        usize::try_from(target_value).map_err(|_error| UnwindError::Address)
    }

    /// Evaluates one CFI expression against the current register image.
    fn expr<U>(
        &self,
        registers: &State,
        expression: UnwindExpression<usize>,
        cfa: Option<usize>,
    ) -> Result<usize, UnwindError>
    where
        U: Unwinder,
    {
        let &Self { ref image, ref fde, .. } = self;

        let &Image { ref eh_frame, .. } = image;

        let expression = expression.get(eh_frame).map_err(UnwindError::Gimli)?;

        let Expression(expression) = expression;

        let mut evaluation = Evaluation::<_, Storage>::new_in(expression, fde.cie().encoding());
        let mut result = evaluation.evaluate().map_err(UnwindError::Gimli)?;

        loop {
            let next = match result {
                EvaluationResult::Complete => break,
                EvaluationResult::RequiresMemory {
                    address,
                    size,
                    space: None,
                    ..
                } => {
                    let address = usize::try_from(address).map_err(|_error| UnwindError::Address)?;
                    let value = U::read(address, size).ok_or(UnwindError::Memory)?;

                    evaluation
                        .resume_with_memory(Value::Generic(value))
                        .map_err(UnwindError::Gimli)
                },
                EvaluationResult::RequiresRegister { register, .. } => {
                    let value = registers.read(register)?;
                    let value = u64::try_from(value).map_err(|_error| UnwindError::Address)?;

                    evaluation
                        .resume_with_register(Value::Generic(value))
                        .map_err(UnwindError::Gimli)
                },
                EvaluationResult::RequiresCallFrameCfa => match cfa {
                    Some(cfa) => {
                        let cfa = u64::try_from(cfa).map_err(|_error| UnwindError::Address)?;

                        evaluation.resume_with_call_frame_cfa(cfa).map_err(UnwindError::Gimli)
                    },
                    None => Err(UnwindError::Expression),
                },
                EvaluationResult::RequiresRelocatedAddress(address) => evaluation
                    .resume_with_relocated_address(address)
                    .map_err(UnwindError::Gimli),
                _ => Err(UnwindError::Expression),
            };

            result = next?;
        }

        let piece = evaluation.as_result().last().ok_or(UnwindError::Expression)?;
        let value = match piece.location {
            Location::Address { address } => Ok(address),
            Location::Register { register } => {
                let value = registers.read(register)?;

                u64::try_from(value).map_err(|_error| UnwindError::Address)
            },
            Location::Value { value } => value.to_u64(u64::MAX).map_err(UnwindError::Gimli),
            _ => Err(UnwindError::Expression),
        }?;

        usize::try_from(value).map_err(|_error| UnwindError::Address)
    }
}

#[cfg(test)]
mod tests {
    use super::Image;

    #[test]
    fn range() {
        let reversed_start = 0x2000;
        let reversed_end = 0x1000;

        assert!(
            Image::new(&[], 0x1000..0x2000).is_some(),
            "nonempty text range must construct"
        );
        assert!(
            Image::new(&[], 0x1000..0x1000).is_none(),
            "empty text range must be rejected"
        );
        assert!(
            Image::new(&[], reversed_start..reversed_end).is_none(),
            "reversed text range must be rejected"
        );
    }

    #[test]
    fn data() {
        let image = Image::new(&[], 0x1000..0x2000)
            .expect("the valid test image must construct")
            .data(0x3000);

        let &Image { ref bases, data, .. } = &image;

        assert_eq!(data, Some(0x3000), "semantic data base must be retained");
        assert_eq!(
            bases.eh_frame.data,
            Some(0x3000),
            "DWARF data base must match semantic data base"
        );
    }
}
