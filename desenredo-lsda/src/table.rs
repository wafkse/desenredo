//! GCC-style language specific data tables used by Itanium personalities.
//!
//! Parsing is zero-copy and allocation free. Every byte consumer is a `nom`
//! parser over a caller-bounded slice. Iteration carries the remaining slice
//! rather than a numeric cursor position.

use core::{mem::size_of, num::NonZeroUsize};

use gimli::constants::{
    DW_EH_PE_absptr, DW_EH_PE_aligned, DW_EH_PE_datarel, DW_EH_PE_funcrel, DW_EH_PE_pcrel, DW_EH_PE_sdata2,
    DW_EH_PE_sdata4, DW_EH_PE_sdata8, DW_EH_PE_sleb128, DW_EH_PE_textrel, DW_EH_PE_udata2, DW_EH_PE_udata4,
    DW_EH_PE_udata8, DW_EH_PE_uleb128, DwEhPe,
};
use nom::{
    bytes::complete::take,
    error::Error as NomError,
    number::complete::{
        be_i16, be_i32, be_i64, be_u8, be_u16, be_u32, be_u64, le_i16, le_i32, le_i64, le_u16, le_u32, le_u64,
    },
};

use crate::{
    encoding::{Bases, Endian, Target},
    error::LsdaError,
};

/// Absolute pointer encoding.
const ABS: DwEhPe = DW_EH_PE_absptr;
/// ABI aligned pointer encoding.
const ALIGN: DwEhPe = DW_EH_PE_aligned;
/// Data relative pointer encoding.
const DATA: DwEhPe = DW_EH_PE_datarel;
/// Function relative pointer encoding.
const FUNC: DwEhPe = DW_EH_PE_funcrel;
/// Program counter relative pointer encoding.
const PC: DwEhPe = DW_EH_PE_pcrel;
/// Signed two byte scalar encoding.
const S2: DwEhPe = DW_EH_PE_sdata2;
/// Signed four byte scalar encoding.
const S4: DwEhPe = DW_EH_PE_sdata4;
/// Signed eight byte scalar encoding.
const S8: DwEhPe = DW_EH_PE_sdata8;
/// Signed LEB128 scalar encoding.
const SLEB: DwEhPe = DW_EH_PE_sleb128;
/// Text relative pointer encoding.
const TEXT: DwEhPe = DW_EH_PE_textrel;
/// Unsigned two byte scalar encoding.
const U2: DwEhPe = DW_EH_PE_udata2;
/// Unsigned four byte scalar encoding.
const U4: DwEhPe = DW_EH_PE_udata4;
/// Unsigned eight byte scalar encoding.
const U8: DwEhPe = DW_EH_PE_udata8;
/// Unsigned LEB128 scalar encoding.
const ULEB: DwEhPe = DW_EH_PE_uleb128;

/// Positive one-based byte offset into the LSDA action table.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
// NOTE(invariant): The stored offset is nonzero and therefore names an ABI action-chain position
// rather than the cleanup-only zero sentinel.
pub struct Action(NonZeroUsize);

impl Action {
    /// Returns the one-based ABI offset.
    #[inline]
    pub const fn raw(self) -> usize {
        let Self(raw) = self;

        raw.get()
    }
}

/// One decoded call-site entry.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
// NOTE(invariant): The entry was decoded completely from the bounded call-site table and any stored
// action offset is nonzero.
pub struct Site {
    /// Function-relative beginning of the protected instruction range.
    start: usize,

    /// Length in bytes of the protected instruction range.
    length: usize,

    /// Absolute landing-pad address when one exists.
    landing: Option<usize>,

    /// Action-table chain when the site has typed actions.
    action: Option<Action>,
}

impl Site {
    /// Returns the function-relative range start.
    #[inline]
    pub const fn start(self) -> usize {
        let Self { start, .. } = self;

        start
    }

    /// Returns the range length.
    #[inline]
    pub const fn size(self) -> usize {
        let Self { length, .. } = self;

        length
    }

    /// Returns the landing-pad address when one exists.
    #[inline]
    pub const fn land(self) -> Option<usize> {
        let Self { landing, .. } = self;

        landing
    }

    /// Returns the action-table chain when one exists.
    #[inline]
    pub const fn action(self) -> Option<Action> {
        let Self { action, .. } = self;

        action
    }
}

/// Positive one-based index into the reverse RTTI table.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
// NOTE(invariant): The stored index is nonzero and therefore refers to one RTTI entry under the
// Itanium reverse-table convention.
pub struct TypeIndex(NonZeroUsize);

impl TypeIndex {
    /// Returns the one-based ABI index.
    #[inline]
    pub const fn raw(self) -> usize {
        let Self(raw) = self;

        raw.get()
    }
}

/// Positive index naming an exception specification list.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
// NOTE(invariant): The stored magnitude is nonzero and originated from one negative action-table
// discriminator.
pub struct FilterIndex(NonZeroUsize);

impl FilterIndex {
    /// Returns the positive magnitude of the ABI filter index.
    #[inline]
    pub const fn raw(self) -> usize {
        let Self(raw) = self;

        raw.get()
    }
}

/// Semantic action represented by one action-table record.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Kind {
    /// Runs a cleanup without selecting a C++ catch type.
    Cleanup,

    /// Tests one entry in the RTTI table.
    Catch(TypeIndex),

    /// Tests one exception specification list.
    Filter(FilterIndex),
}

/// Reverse RTTI table metadata.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
// NOTE(invariant): end is within the same bounded LSDA and encoding was validated before
// construction.
pub struct Types {
    /// Byte position immediately after the reverse RTTI entries.
    end: usize,

    /// Encoding used by each RTTI entry.
    encoding: DwEhPe,
}

/// Parsed bounded LSDA metadata.
#[derive(Copy, Clone)]
// NOTE(invariant): call_sites and every stored table relation are slices or offsets proven to lie
// within bytes during construction.
pub struct Lsda<'a> {
    /// Complete readable LSDA byte range supplied by the caller.
    bytes: &'a [u8],

    /// Logical bases used by encoded pointer evaluation.
    bases: Bases,

    /// Endianness used by fixed-width encoded values.
    endian: Endian,

    /// Absolute base used for landing-pad offsets.
    landing_base: usize,

    /// Optional reverse RTTI table metadata.
    types: Option<Types>,

    /// Encoding used by call-site range fields.
    call_encoding: DwEhPe,

    /// Exact bounded call-site table bytes.
    call_sites: &'a [u8],

    /// Beginning of the action table within `bytes`.
    action_offset: usize,
}

/// Iterator over bounded call-site entries.
// NOTE(invariant): input is always a suffix of the validated call_sites slice from lsda and
// advances only through successful nom parses.
pub struct Sites<'a> {
    /// Parsed LSDA shared by every yielded entry.
    lsda: Lsda<'a>,

    /// Remaining call-site table bytes.
    input: &'a [u8],

    /// Whether a parse error terminated iteration.
    done: bool,
}

/// Iterator over one bounded action chain.
// NOTE(invariant): next is either absent or a suffix of bytes beginning within the validated action
// table. fuel bounds traversal even for cyclic metadata.
pub struct Chain<'a> {
    /// Complete bounded LSDA bytes.
    bytes: &'a [u8],

    /// Remaining slice beginning at the next action record.
    next: Option<&'a [u8]>,

    /// Remaining progress budget used to reject cycles.
    fuel: usize,

    /// Byte position where the action table begins.
    floor: usize,
}

/// Iterator over one dynamic exception specification type list.
// NOTE(invariant): input begins at the validated filter-list address and remains a suffix of the
// same bounded LSDA until zero termination or error.
pub struct FilterTypes<'a> {
    /// Remaining filter-list bytes.
    input: &'a [u8],

    /// Whether the zero terminator or an error ended iteration.
    done: bool,
}

/// Integer decoded from one DWARF EH pointer field before base application.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Scalar {
    /// Unsigned encoded value.
    Unsigned(u64),

    /// Signed encoded value.
    Signed(i64),
}

impl Scalar {
    /// Applies one nonnegative logical base and converts to the native address width.
    fn add(self, base: usize) -> Result<usize, LsdaError> {
        let base = base as i128;
        let value = match self {
            Self::Unsigned(value) => i128::from(value),
            Self::Signed(value) => i128::from(value),
        };
        let value = base.checked_add(value).ok_or(LsdaError::Overflow)?;

        usize::try_from(value).map_err(|_error| LsdaError::Overflow)
    }
}

/// Nom error representation over one bounded input slice.
type ParseError<'a> = NomError<&'a [u8]>;

/// Parses one byte through `nom` complete-input semantics.
#[inline]
fn byte(input: &[u8]) -> Result<(&[u8], u8), LsdaError> {
    be_u8::<_, ParseError<'_>>(input).map_err(|_error| LsdaError::Eof)
}

/// Splits a bounded input after exactly `count` bytes through `nom`.
#[inline]
fn take_bytes(input: &[u8], count: usize) -> Result<(&[u8], &[u8]), LsdaError> {
    take::<_, _, ParseError<'_>>(count)(input).map_err(|_error| LsdaError::Eof)
}

/// Returns the number of bytes consumed from `whole` to reach `rest`.
#[inline]
fn position(whole: &[u8], rest: &[u8]) -> Result<usize, LsdaError> {
    whole.len().checked_sub(rest.len()).ok_or(LsdaError::Table)
}

/// Parses one fixed-width unsigned integer.
fn unsigned(input: &[u8], width: usize, endian: Endian) -> Result<(&[u8], u64), LsdaError> {
    match (width, endian) {
        (2, Endian::Little) => le_u16::<_, ParseError<'_>>(input)
            .map(|(rest, value)| (rest, u64::from(value)))
            .map_err(|_error| LsdaError::Eof),
        (2, Endian::Big) => be_u16::<_, ParseError<'_>>(input)
            .map(|(rest, value)| (rest, u64::from(value)))
            .map_err(|_error| LsdaError::Eof),
        (4, Endian::Little) => le_u32::<_, ParseError<'_>>(input)
            .map(|(rest, value)| (rest, u64::from(value)))
            .map_err(|_error| LsdaError::Eof),
        (4, Endian::Big) => be_u32::<_, ParseError<'_>>(input)
            .map(|(rest, value)| (rest, u64::from(value)))
            .map_err(|_error| LsdaError::Eof),
        (8, Endian::Little) => le_u64::<_, ParseError<'_>>(input).map_err(|_error| LsdaError::Eof),
        (8, Endian::Big) => be_u64::<_, ParseError<'_>>(input).map_err(|_error| LsdaError::Eof),
        _ => Err(LsdaError::Encoding),
    }
}

/// Parses one fixed-width signed integer.
fn signed(input: &[u8], width: usize, endian: Endian) -> Result<(&[u8], i64), LsdaError> {
    match (width, endian) {
        (2, Endian::Little) => le_i16::<_, ParseError<'_>>(input)
            .map(|(rest, value)| (rest, i64::from(value)))
            .map_err(|_error| LsdaError::Eof),
        (2, Endian::Big) => be_i16::<_, ParseError<'_>>(input)
            .map(|(rest, value)| (rest, i64::from(value)))
            .map_err(|_error| LsdaError::Eof),
        (4, Endian::Little) => le_i32::<_, ParseError<'_>>(input)
            .map(|(rest, value)| (rest, i64::from(value)))
            .map_err(|_error| LsdaError::Eof),
        (4, Endian::Big) => be_i32::<_, ParseError<'_>>(input)
            .map(|(rest, value)| (rest, i64::from(value)))
            .map_err(|_error| LsdaError::Eof),
        (8, Endian::Little) => le_i64::<_, ParseError<'_>>(input).map_err(|_error| LsdaError::Eof),
        (8, Endian::Big) => be_i64::<_, ParseError<'_>>(input).map_err(|_error| LsdaError::Eof),
        _ => Err(LsdaError::Encoding),
    }
}

/// Parses one bounded unsigned LEB128 value.
fn uleb(mut input: &[u8]) -> Result<(&[u8], u64), LsdaError> {
    let mut value = 0_u64;
    let mut shift = 0_u32;

    loop {
        let (rest, octet) = byte(input)?;

        let payload = u64::from(octet & 0x7f);
        let fits = match shift {
            63 => payload <= 1,
            0..=62 => true,
            _ => false,
        };

        if !fits {
            return Err(LsdaError::Overflow);
        }

        value |= payload << shift;
        input = rest;

        if octet & 0x80 == 0 {
            break Ok((input, value));
        }

        shift = shift.checked_add(7).ok_or(LsdaError::Overflow)?;
    }
}

/// Parses one bounded signed LEB128 value.
fn sleb(mut input: &[u8]) -> Result<(&[u8], i64), LsdaError> {
    let mut value = 0_u64;
    let mut shift = 0_u32;

    let terminal = loop {
        let (rest, octet) = byte(input)?;

        let payload = u64::from(octet & 0x7f);

        if shift >= 64 {
            return Err(LsdaError::Overflow);
        }

        value |= payload.checked_shl(shift).ok_or(LsdaError::Overflow)?;
        shift = shift.checked_add(7).ok_or(LsdaError::Overflow)?;
        input = rest;

        if octet & 0x80 == 0 {
            break octet;
        }
    };

    let signed = if shift < 64 && terminal & 0x40 != 0 {
        value | (!0_u64 << shift)
    } else {
        value
    };
    let value = i64::from_ne_bytes(signed.to_ne_bytes());

    Ok((input, value))
}

/// Parses one scalar form selected by a DWARF EH pointer encoding.
fn scalar(input: &[u8], format: DwEhPe, endian: Endian) -> Result<(&[u8], Scalar), LsdaError> {
    match format {
        ABS => unsigned(input, size_of::<usize>(), endian).map(|(rest, value)| (rest, Scalar::Unsigned(value))),
        ULEB => uleb(input).map(|(rest, value)| (rest, Scalar::Unsigned(value))),
        SLEB => sleb(input).map(|(rest, value)| (rest, Scalar::Signed(value))),
        U2 => unsigned(input, 2, endian).map(|(rest, value)| (rest, Scalar::Unsigned(value))),
        U4 => unsigned(input, 4, endian).map(|(rest, value)| (rest, Scalar::Unsigned(value))),
        U8 => unsigned(input, 8, endian).map(|(rest, value)| (rest, Scalar::Unsigned(value))),
        S2 => signed(input, 2, endian).map(|(rest, value)| (rest, Scalar::Signed(value))),
        S4 => signed(input, 4, endian).map(|(rest, value)| (rest, Scalar::Signed(value))),
        S8 => signed(input, 8, endian).map(|(rest, value)| (rest, Scalar::Signed(value))),
        _ => Err(LsdaError::Encoding),
    }
}

/// Applies ABI alignment to the remaining input without indexing the slice.
fn aligned<'a>(whole: &'a [u8], input: &'a [u8], bases: Bases) -> Result<&'a [u8], LsdaError> {
    let offset = position(whole, input)?;
    let address = bases.origin().checked_add(offset).ok_or(LsdaError::Overflow)?;
    let alignment = size_of::<usize>();
    let remainder = address % alignment;
    let padding = if remainder == 0 { 0 } else { alignment - remainder };

    let (rest, _) = take_bytes(input, padding)?;

    Ok(rest)
}

/// Parses one encoded target while retaining any requested indirection bit.
fn target<'a>(
    whole: &'a [u8],
    input: &'a [u8],
    encoding: DwEhPe,
    bases: Bases,
    endian: Endian,
) -> Result<(&'a [u8], Target), LsdaError> {
    let valid = encoding.is_valid_encoding() && !encoding.is_absent();

    if valid {
        let input = if encoding.application() == ALIGN {
            aligned(whole, input, bases)?
        } else {
            input
        };
        let field = bases
            .origin()
            .checked_add(position(whole, input)?)
            .ok_or(LsdaError::Overflow)?;

        let (rest, scalar) = scalar(input, encoding.format(), endian)?;

        let base = match encoding.application() {
            ABS | ALIGN => 0,
            PC => field,
            TEXT => bases.text_base().ok_or(LsdaError::Base)?,
            DATA => bases.data_base().ok_or(LsdaError::Base)?,
            FUNC => bases.function(),
            _ => return Err(LsdaError::Encoding),
        };
        let address = scalar.add(base)?;
        let indirect = encoding.is_indirect();
        let target = Target::new(address, indirect);

        Ok((rest, target))
    } else {
        Err(LsdaError::Encoding)
    }
}

/// Parses one plain call-site offset.
fn offset(input: &[u8], encoding: DwEhPe, endian: Endian) -> Result<(&[u8], usize), LsdaError> {
    let plain = encoding.application() == ABS && !encoding.is_indirect();

    let valid = encoding.is_valid_encoding() && !encoding.is_absent() && plain;

    if valid {
        scalar(input, encoding.format(), endian).and_then(|(rest, value)| value.add(0).map(|value| (rest, value)))
    } else {
        Err(LsdaError::Encoding)
    }
}

impl Kind {
    /// Converts the signed action discriminator into its semantic class.
    fn new(index: i64) -> Result<Self, LsdaError> {
        match index {
            0 => Ok(Self::Cleanup),
            1.. => {
                let index = usize::try_from(index).map_err(|_error| LsdaError::Overflow)?;
                let index = NonZeroUsize::new(index).ok_or(LsdaError::Table)?;

                Ok(Self::Catch(TypeIndex(index)))
            },
            ..0 => {
                let index = index.unsigned_abs();
                let index = usize::try_from(index).map_err(|_error| LsdaError::Overflow)?;
                let index = NonZeroUsize::new(index).ok_or(LsdaError::Table)?;

                Ok(Self::Filter(FilterIndex(index)))
            },
        }
    }
}

impl<'a> Lsda<'a> {
    /// Parses one complete bounded LSDA byte range.
    ///
    /// # Errors
    ///
    /// Returns a structural, encoding, base, or arithmetic error when the input
    /// cannot describe a bounded Itanium LSDA.
    #[inline]
    pub fn new(bytes: &'a [u8], bases: Bases, endian: Endian) -> Result<Self, LsdaError> {
        let (input, landing_encoding) = byte(bytes)?;

        let landing_encoding = DwEhPe(landing_encoding);

        let (input, landing_base) = if landing_encoding.is_absent() {
            (input, bases.function())
        } else {
            let (input, target) = target(bytes, input, landing_encoding, bases, endian)?;

            if target.indirect() {
                return Err(LsdaError::Encoding);
            }

            (input, target.addr())
        };

        let (input, type_encoding) = byte(input)?;

        let type_encoding = DwEhPe(type_encoding);

        let (input, types) = if type_encoding.is_absent() {
            (input, None)
        } else {
            let valid = type_encoding.is_valid_encoding();

            let (input, type_offset) = uleb(input)?;

            let type_offset = usize::try_from(type_offset).map_err(|_error| LsdaError::Overflow)?;
            let position = position(bytes, input)?;
            let end = position.checked_add(type_offset).ok_or(LsdaError::Overflow)?;
            let within_bounds = end <= bytes.len();

            match (valid, within_bounds) {
                (true, true) => {
                    let types = Types {
                        end,
                        encoding: type_encoding,
                    };

                    (input, Some(types))
                },
                (false, _) => return Err(LsdaError::Encoding),
                (_, false) => return Err(LsdaError::Table),
            }
        };

        let (input, call_encoding) = byte(input)?;

        let call_encoding = DwEhPe(call_encoding);
        let call_valid = call_encoding.is_valid_encoding() && !call_encoding.is_absent();

        let (input, call_length) = uleb(input)?;

        let call_length = usize::try_from(call_length).map_err(|_error| LsdaError::Overflow)?;

        let (actions, call_sites) = take_bytes(input, call_length)?;

        let action_offset = position(bytes, actions)?;

        if call_valid {
            Ok(Self {
                bytes,
                bases,
                endian,
                landing_base,
                types,
                call_encoding,
                call_sites,
                action_offset,
            })
        } else {
            Err(LsdaError::Encoding)
        }
    }

    /// Returns the reverse RTTI table metadata when one exists.
    #[inline]
    pub const fn types(&self) -> Option<Types> {
        let &Self { types, .. } = self;

        types
    }

    /// Iterates over validated call-site entries.
    #[inline]
    pub const fn sites(&self) -> Sites<'a> {
        let &Self { call_sites, .. } = self;

        Sites {
            lsda: *self,
            input: call_sites,
            done: false,
        }
    }

    /// Iterates one action chain.
    ///
    /// # Errors
    ///
    /// Returns an error when the one-based action offset lies outside the
    /// caller-bounded LSDA range.
    #[inline]
    pub fn chain(&self, action: Action) -> Result<Chain<'a>, LsdaError> {
        let &Self {
            bytes: whole,
            action_offset,
            ..
        } = self;

        let relative = action.raw().checked_sub(1).ok_or(LsdaError::Table)?;
        let next_offset = action_offset.checked_add(relative).ok_or(LsdaError::Overflow)?;
        let valid = next_offset < whole.len();

        if valid {
            let (next, _) = take_bytes(whole, next_offset)?;

            Ok(Chain {
                bytes: whole,
                next: Some(next),
                fuel: whole.len().saturating_add(1),
                floor: action_offset,
            })
        } else {
            Err(LsdaError::Table)
        }
    }

    /// Iterates the type indices in one dynamic exception specification.
    ///
    /// # Errors
    ///
    /// Returns an error when the specification relation lies outside the bounded LSDA.
    #[inline]
    pub fn filter(&self, index: FilterIndex) -> Result<FilterTypes<'a>, LsdaError> {
        let &Self {
            bytes: whole, types, ..
        } = self;

        let types = types.ok_or(LsdaError::Table)?;
        let relative = index.raw().checked_sub(1).ok_or(LsdaError::Table)?;
        let start = types.end.checked_add(relative).ok_or(LsdaError::Overflow)?;
        let within_bounds = start <= whole.len();

        if within_bounds {
            let (input, _) = take_bytes(whole, start)?;

            Ok(FilterTypes { input, done: false })
        } else {
            Err(LsdaError::Table)
        }
    }

    /// Finds the call-site entry covering one absolute program counter.
    ///
    /// # Errors
    ///
    /// Returns the first malformed table error encountered while scanning.
    #[inline]
    pub fn site(&self, pc: usize) -> Result<Option<Site>, LsdaError> {
        let &Self { bases, .. } = self;

        let pc = pc.checked_sub(bases.function()).ok_or(LsdaError::Table)?;
        let mut result = None;

        for site in Self::sites(self) {
            let site = site?;
            let end = site.start().checked_add(site.size()).ok_or(LsdaError::Overflow)?;
            let contains = site.start() <= pc && pc < end;
            let before = pc < site.start();

            match (contains, before) {
                (true, _) => {
                    result = Some(site);
                    break;
                },
                (false, true) => break,
                (false, false) => {},
            }
        }

        Ok(result)
    }
}

/// Parses one call-site record from the remaining exact table slice.
fn call_site<'a>(input: &'a [u8], lsda: Lsda<'a>) -> Result<(&'a [u8], Site), LsdaError> {
    let Lsda {
        endian,
        landing_base,
        call_encoding,
        ..
    } = lsda;

    let (input, start) = offset(input, call_encoding, endian)?;

    let (input, length) = offset(input, call_encoding, endian)?;

    let (input, landing) = offset(input, call_encoding, endian)?;

    let (input, action) = uleb(input)?;

    let action = usize::try_from(action).map_err(|_error| LsdaError::Overflow)?;
    let landing = match landing {
        0 => None,
        landing => Some(landing_base.checked_add(landing).ok_or(LsdaError::Overflow)?),
    };
    let action = NonZeroUsize::new(action).map(Action);
    let site = Site {
        start,
        length,
        landing,
        action,
    };

    Ok((input, site))
}

impl Iterator for Sites<'_> {
    type Item = Result<Site, LsdaError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let &mut Self {
            ref mut lsda,
            ref mut input,
            ref mut done,
        } = self;

        let finished = *done || input.is_empty();

        if finished {
            None
        } else {
            match call_site(input, *lsda) {
                Ok((rest, site)) => {
                    *input = rest;
                    Some(Ok(site))
                },
                Err(error) => {
                    *done = true;
                    Some(Err(error))
                },
            }
        }
    }
}

impl Types {
    /// Returns the encoding used by reverse RTTI entries.
    #[inline]
    pub const fn encoding(self) -> DwEhPe {
        let Self { encoding, .. } = self;

        encoding
    }

    /// Decodes one reverse RTTI table entry without following indirection.
    ///
    /// # Errors
    ///
    /// Returns an error for variable-width RTTI encodings, out-of-range indices,
    /// missing relative bases, or malformed pointer data.
    #[inline]
    pub fn get(self, lsda: &Lsda<'_>, index: TypeIndex) -> Result<Target, LsdaError> {
        let Self { end, encoding } = self;

        let width = Self::width(encoding)?;
        let offset = index.raw().checked_mul(width).ok_or(LsdaError::Overflow)?;
        let start = end.checked_sub(offset).ok_or(LsdaError::Table)?;

        let &Lsda {
            bytes: whole,
            bases,
            endian,
            ..
        } = lsda;

        let (input, _) = take_bytes(whole, start)?;

        let (rest, target) = target(whole, input, encoding, bases, endian)?;

        let consumed = position(whole, rest)?;

        if consumed <= end {
            Ok(target)
        } else {
            Err(LsdaError::Table)
        }
    }

    /// Returns the fixed byte width for one RTTI encoding.
    fn width(encoding: DwEhPe) -> Result<usize, LsdaError> {
        match encoding.format() {
            ABS => Ok(size_of::<usize>()),
            U2 | S2 => Ok(2),
            U4 | S4 => Ok(4),
            U8 | S8 => Ok(8),
            _ => Err(LsdaError::Encoding),
        }
    }
}

impl Iterator for Chain<'_> {
    type Item = Result<Kind, LsdaError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let &mut Self {
            bytes: whole,
            ref mut next,
            ref mut fuel,
            floor,
        } = self;

        let input = (*next)?;

        if *fuel == 0 {
            *next = None;
            Some(Err(LsdaError::Loop))
        } else {
            *fuel -= 1;

            let parsed = sleb(input).and_then(|(link, index)| {
                let (_rest, delta) = sleb(link)?;

                let kind = Kind::new(index)?;
                let next = match delta {
                    0 => Ok(None),
                    delta => {
                        let link = position(whole, link)?;
                        let link = i128::try_from(link).map_err(|_error| LsdaError::Overflow)?;
                        let target = link.checked_add(i128::from(delta)).ok_or(LsdaError::Overflow)?;
                        let target = usize::try_from(target).map_err(|_error| LsdaError::Table)?;
                        let valid = floor <= target && target < whole.len();

                        if valid {
                            let (next, _) = take_bytes(whole, target)?;

                            Ok(Some(next))
                        } else {
                            Err(LsdaError::Table)
                        }
                    },
                }?;

                Ok((kind, next))
            });

            match parsed {
                Ok((kind, next_input)) => {
                    *next = next_input;
                    Some(Ok(kind))
                },
                Err(error) => {
                    *next = None;
                    Some(Err(error))
                },
            }
        }
    }
}

impl Iterator for FilterTypes<'_> {
    type Item = Result<TypeIndex, LsdaError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let &mut Self {
            ref mut input,
            ref mut done,
        } = self;

        if *done {
            None
        } else {
            match uleb(input) {
                Ok((rest, 0)) => {
                    *input = rest;
                    *done = true;
                    None
                },
                Ok((rest, index)) => {
                    *input = rest;

                    let index = usize::try_from(index).map_err(|_error| LsdaError::Overflow);
                    let index = index.and_then(|index| NonZeroUsize::new(index).ok_or(LsdaError::Table));

                    Some(index.map(TypeIndex))
                },
                Err(error) => {
                    *done = true;
                    Some(Err(error))
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Kind, Lsda};
    use crate::{
        encoding::{Bases, Endian},
        error::LsdaError,
    };

    #[test]
    fn cleanup_site_decodes() {
        let bytes = [0xff, 0xff, 0x01, 0x04, 0x00, 0x05, 0x0a, 0x00];
        let bases = Bases::new(0x1000, 0x2000);
        let lsda = Lsda::new(&bytes, bases, Endian::Little).expect("valid cleanup fixture");
        let site = lsda.site(0x2002).expect("valid call-site table");
        let site = site.expect("covered program counter");

        assert_eq!(site.start(), 0);
        assert_eq!(site.size(), 5);
        assert_eq!(site.land(), Some(0x200a));
        assert_eq!(site.action(), None);
    }

    #[test]
    fn catch_type_decodes() {
        let bytes = [
            0xff, 0x00, 0x10, 0x01, 0x04, 0x00, 0x05, 0x0a, 0x01, 0x01, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ];
        let bases = Bases::new(0x1000, 0x2000);
        let lsda = Lsda::new(&bytes, bases, Endian::Little).expect("valid catch fixture");
        let site = lsda.site(0x2002).expect("valid table").expect("covered site");
        let action = site.action().expect("typed action");
        let mut chain = lsda.chain(action).expect("valid action chain");
        let kind = chain.next().expect("one action").expect("valid action");

        let index = match kind {
            Kind::Catch(index) => Some(index),
            _ => None,
        }
        .expect("expected catch action");
        let target = lsda
            .types()
            .expect("RTTI table")
            .get(&lsda, index)
            .expect("valid RTTI target");

        assert_eq!(target.addr(), 0x1234);
        assert!(!target.indirect());
        assert!(chain.next().is_none());
    }

    #[test]
    fn action_chain_advances_from_link_field() {
        let bytes = [0xff, 0xff, 0x01, 0x04, 0x00, 0x05, 0x0a, 0x01, 0x00, 0x01, 0x01, 0x00];
        let bases = Bases::new(0x1000, 0x2000);
        let lsda = Lsda::new(&bytes, bases, Endian::Little).expect("valid chain fixture");
        let site = lsda.site(0x2002).expect("valid table").expect("covered site");
        let mut chain = lsda.chain(site.action().expect("typed action")).expect("valid chain");

        assert_eq!(chain.next().expect("cleanup").expect("valid cleanup"), Kind::Cleanup);
        assert!(matches!(
            chain.next().expect("catch").expect("valid catch"),
            Kind::Catch(_)
        ));
        assert!(chain.next().is_none());
    }

    #[test]
    fn gcc_catch_all_shape_decodes() {
        let bytes = [
            0xff, 0x9b, 0x11, 0x01, 0x08, 0x09, 0x05, 0x17, 0x01, 0x24, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let bases = Bases::new(0x1000, 0x2000);
        let lsda = Lsda::new(&bytes, bases, Endian::Little).expect("valid catch-all fixture");
        let site = lsda.site(0x200a).expect("valid table").expect("covered site");
        let action = site.action().expect("typed action");
        let mut chain = lsda.chain(action).expect("valid action chain");
        let kind = chain.next().expect("catch").expect("valid catch");
        let index = match kind {
            Kind::Catch(index) => Some(index),
            _ => None,
        }
        .expect("expected catch action");
        let target = lsda
            .types()
            .expect("RTTI table")
            .get(&lsda, index)
            .expect("valid RTTI target");

        assert_eq!(site.land(), Some(0x2017));
        assert_eq!(target.addr(), 0x1010);
        assert!(target.indirect());
    }

    #[test]
    fn truncated_call_table_is_rejected() {
        let bytes = [0xff, 0xff, 0x01, 0x05, 0x00, 0x05, 0x0a, 0x00];
        let bases = Bases::new(0x1000, 0x2000);
        let result = Lsda::new(&bytes, bases, Endian::Little);

        assert_eq!(result.err(), Some(LsdaError::Eof));
    }

    #[test]
    fn filter_specification_indices_decode() {
        let bytes = [
            0xff, 0x00, 0x10, 0x01, 0x04, 0x00, 0x05, 0x0a, 0x01, 0x7f, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00,
        ];
        let bases = Bases::new(0x1000, 0x2000);
        let lsda = Lsda::new(&bytes, bases, Endian::Little).expect("valid filter fixture");
        let site = lsda.site(0x2002).expect("valid call table").expect("covered call site");
        let mut chain = lsda
            .chain(site.action().expect("filter action"))
            .expect("valid action chain");
        let kind = chain.next().expect("one action").expect("valid filter action");
        let index = match kind {
            Kind::Filter(index) => Some(index),
            _ => None,
        }
        .expect("expected filter action");
        let mut types = lsda.filter(index).expect("valid filter list");
        let first = types.next().expect("one filter type").expect("valid type index");

        assert_eq!(first.raw(), 1);
        assert!(types.next().is_none());
    }
}
