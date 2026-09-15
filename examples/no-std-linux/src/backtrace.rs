//! Allocation-free physical capture followed by `addr2line` symbolization.
//!
//! The unwind callback only records instruction pointers into fixed stack
//! storage. ELF mapping and DWARF parsing happen after `_Unwind_Backtrace`
//! returns, so capture never reenters the global allocator.

use alloc::format;
use core::{
    ffi::c_void,
    num::NonZeroUsize,
    ptr::{self, NonNull},
    slice::from_raw_parts,
};

use addr2line::{
    Context,
    gimli::{Dwarf, EndianSlice, RunTimeEndian, SectionId},
};
use desenredo::{
    abi::unwind::{_Unwind_Backtrace, _Unwind_GetIPInfo, Context as UnwindContext, ReasonCode},
    unwind::relation::Relation,
};
use object::{Object, ObjectSection};
use rustix::{
    fs::{Mode, OFlags, fstat, open},
    mm::{MapFlags, ProtFlags, mmap, munmap},
};

use crate::linux::{self, ExitCode};

/// Maximum number of physical frames captured without allocation.
const FRAME_LIMIT: usize = 64;

/// Backtrace capture or symbolization failure.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BacktraceError {
    /// Physical unwinding failed before reaching the terminal frame.
    Walk,

    /// `/proc/self/exe` could not be opened.
    Open,

    /// The executable file size was invalid for mapping.
    Size,

    /// The executable could not be mapped read-only.
    Map,

    /// The mapped executable was not a supported object file.
    Object,

    /// One required DWARF section could not be read.
    Section,

    /// DWARF parsing or address lookup failed.
    Dwarf,

    /// No captured interior return address resolved through DWARF.
    Interior,
}

/// One physical program counter and its ABI relation to the active instruction.
// NOTE(invariant): rip is nonzero. relation determines the exact address used
// for DWARF lookup without changing the raw RIP retained for diagnostics.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct ProgramCounter {
    /// Raw instruction pointer reported by `_Unwind_GetIPInfo`.
    rip: NonZeroUsize,

    /// Whether RIP names an instruction or the return address after one.
    relation: Relation,
}

impl ProgramCounter {
    /// Constructs one captured program counter from the Level I callback state.
    #[inline]
    fn new(rip: usize, before: bool) -> Option<Self> {
        let rip = NonZeroUsize::new(rip)?;
        let relation = match before {
            true => Relation::Instruction,
            false => Relation::Return,
        };

        Some(Self { rip, relation })
    }

    /// Returns the raw reported instruction pointer.
    #[inline]
    const fn rip(self) -> usize {
        let Self { rip, .. } = self;

        rip.get()
    }

    /// Returns the address that belongs to the active instruction.
    #[inline]
    const fn probe(self) -> Option<usize> {
        let Self { rip, relation } = self;

        relation.site(rip.get())
    }

    /// Reports whether this frame required return-address adjustment.
    #[inline]
    const fn interior(self) -> bool {
        let Self { relation, .. } = self;

        matches!(relation, Relation::Return)
    }
}

/// Fixed physical frame storage used by the unwind callback.
// NOTE(invariant): every slot before len is Some and every slot at or after len
// is None. truncated records that at least one additional frame was observed.
struct Trace {
    /// Captured physical frames.
    slots: [Option<ProgramCounter>; FRAME_LIMIT],

    /// Number of initialized frame slots.
    len: usize,

    /// Whether capture exceeded fixed storage.
    truncated: bool,
}

impl Trace {
    /// Creates empty allocation-free capture storage.
    #[inline]
    const fn new() -> Self {
        Self {
            slots: [None; FRAME_LIMIT],
            len: 0,
            truncated: false,
        }
    }

    /// Records one frame when fixed storage remains available.
    fn push(&mut self, frame: ProgramCounter) {
        let &mut Self {
            ref mut slots,
            ref mut len,
            ref mut truncated,
        } = self;
        let slot = slots.get_mut(*len);

        match slot {
            Some(slot) => {
                *slot = Some(frame);
                *len += 1;
            },
            None => *truncated = true,
        }
    }

    /// Iterates every captured physical frame in traversal order.
    fn frames(&self) -> impl Iterator<Item = ProgramCounter> + '_ {
        let &Self { ref slots, .. } = self;

        slots.iter().copied().flatten()
    }
}

/// Records one physical frame without allocating.
unsafe extern "C" fn visit(context: *mut UnwindContext, parameter: *mut c_void) -> ReasonCode {
    let mut before = 0;

    // SAFETY:
    // The trace callback receives the live context from `_Unwind_Backtrace`.
    let rip = unsafe { _Unwind_GetIPInfo(context, &mut before) };
    let frame = ProgramCounter::new(rip, before != 0);
    let trace = parameter.cast::<Trace>();

    // SAFETY:
    // capture forwards the unique live Trace pointer for the complete traversal.
    let trace = unsafe { &mut *trace };

    match frame {
        Some(frame) => Trace::push(trace, frame),
        None => {},
    }

    ReasonCode::NONE
}

/// Captures one physical backtrace into fixed stack storage.
fn capture() -> Result<Trace, BacktraceError> {
    let mut trace = Trace::new();
    let parameter = ptr::from_mut(&mut trace).cast();

    // SAFETY:
    // visit receives only the live Trace pointer and never stores the callback context.
    let reason = unsafe { _Unwind_Backtrace(visit, parameter) };

    match reason {
        ReasonCode::END => Ok(trace),
        _ => Err(BacktraceError::Walk),
    }
}

/// Read-only mapping of the process executable used for symbolization.
// NOTE(invariant): pointer names one live read-only mapping of exactly size
// bytes until Drop releases it. The mapping remains valid after closing its fd.
struct Executable {
    /// Base of the mapped ELF file.
    pointer: NonNull<c_void>,

    /// Exact mapped file size.
    size: NonZeroUsize,
}

impl Executable {
    /// Opens and maps `/proc/self/exe` without using the global allocator.
    fn open() -> Result<Self, BacktraceError> {
        let fd = open(c"/proc/self/exe", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .map_err(|_error| BacktraceError::Open)?;
        let stat = fstat(&fd).map_err(|_error| BacktraceError::Size)?;
        let size = usize::try_from(stat.st_size)
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or(BacktraceError::Size)?;

        // SAFETY:
        // A null hint requests a fresh private read-only file mapping. fd remains
        // live for this call and size comes from fstat on the same descriptor.
        let mapped = unsafe { mmap(ptr::null_mut(), size.get(), ProtFlags::READ, MapFlags::PRIVATE, &fd, 0) }
            .map_err(|_error| BacktraceError::Map)?;
        let pointer = NonNull::new(mapped).ok_or(BacktraceError::Map)?;

        Ok(Self { pointer, size })
    }

    /// Borrows the complete mapped ELF file.
    #[inline]
    const fn bytes(&self) -> &[u8] {
        let &Self { pointer, size } = self;
        let pointer = pointer.cast::<u8>().as_ptr();

        // SAFETY:
        // The Executable invariant keeps this exact read-only mapping live.
        unsafe { from_raw_parts(pointer, size.get()) }
    }
}

impl Drop for Executable {
    fn drop(&mut self) {
        let &mut Self { pointer, size } = self;

        // SAFETY:
        // The Executable invariant proves this exact mapping is live and unique.
        let released = unsafe { munmap(pointer.as_ptr(), size.get()) };

        match released {
            Ok(()) => {},
            Err(_error) => linux::terminate(b"self executable mapping release failed\n", ExitCode::SOFTWARE),
        }
    }
}

/// Reader type borrowed directly from the mapped ELF image.
type Reader<'a> = EndianSlice<'a, RunTimeEndian>;

/// Addr2line context borrowing one mapped executable image.
struct Symbols<'a> {
    /// Parsed DWARF address context.
    context: Context<Reader<'a>>,
}

impl<'a> Symbols<'a> {
    /// Builds one addr2line context from uncompressed DWARF sections in the ELF.
    fn new(bytes: &'a [u8]) -> Result<Self, BacktraceError> {
        let object = object::File::parse(bytes).map_err(|_error| BacktraceError::Object)?;
        let endian = match object.is_little_endian() {
            true => RunTimeEndian::Little,
            false => RunTimeEndian::Big,
        };
        let dwarf = Dwarf::load(|id: SectionId| {
            let data = Self::section(&object, id.name())?;
            let reader = EndianSlice::new(data, endian);

            Ok::<Reader<'a>, BacktraceError>(reader)
        })?;
        let context = Context::from_dwarf(dwarf).map_err(|_error| BacktraceError::Dwarf)?;

        Ok(Self { context })
    }

    /// Returns one raw section or an empty reader for an absent optional section.
    fn section(file: &object::File<'a>, name: &str) -> Result<&'a [u8], BacktraceError> {
        match file.section_by_name(name) {
            Some(section) => section.data().map_err(|_error| BacktraceError::Section),
            None => Ok(&[]),
        }
    }

    /// Prints every captured frame and reports whether an interior RIP resolved.
    fn print(&self, trace: &Trace) -> Result<bool, BacktraceError> {
        let &Self { ref context } = self;
        let mut interior = false;
        let mut number = 0_usize;

        for pc in Trace::frames(trace) {
            number = number.saturating_add(1);
            let rip = pc.rip();
            let probe = pc.probe().ok_or(BacktraceError::Dwarf)?;
            let probe64 = u64::try_from(probe).map_err(|_error| BacktraceError::Dwarf)?;
            let header = format!("  #{number} rip={rip:#018x} probe={probe:#018x}\n");

            linux::stdout(header.as_bytes());

            let mut frames = context
                .find_frames(probe64)
                .skip_all_loads()
                .map_err(|_error| BacktraceError::Dwarf)?;
            let mut resolved = false;

            loop {
                let frame = frames.next().map_err(|_error| BacktraceError::Dwarf)?;

                match frame {
                    Some(frame) => {
                        resolved = true;
                        Self::print_frame(frame)?;
                    },
                    None => break,
                }
            }

            match (pc.interior(), resolved) {
                (true, true) => interior = true,
                _ => {},
            }
        }

        let &Trace { truncated, .. } = trace;

        match truncated {
            true => linux::stdout(b"  <trace truncated>\n"),
            false => {},
        }

        Ok(interior)
    }

    /// Prints one inline or physical addr2line frame.
    fn print_frame(frame: addr2line::Frame<'_, Reader<'a>>) -> Result<(), BacktraceError> {
        linux::stdout(b"      ");

        match frame.function {
            Some(function) => {
                let name = function.demangle().map_err(|_error| BacktraceError::Dwarf)?;
                linux::stdout(name.as_bytes());
            },
            None => linux::stdout(b"<unknown function>"),
        }

        match frame.location {
            Some(location) => Self::print_location(location),
            None => {},
        }

        linux::stdout(b"\n");
        Ok(())
    }

    /// Prints source location details when DWARF provides them.
    fn print_location(location: addr2line::Location<'_>) {
        let addr2line::Location { file, line, column } = location;

        match file {
            Some(file) => {
                linux::stdout(b" at ");
                linux::stdout(file.as_bytes());
            },
            None => {},
        }

        match line {
            Some(line) => {
                let line = format!(":{line}");
                linux::stdout(line.as_bytes());
            },
            None => {},
        }

        match column {
            Some(column) => {
                let column = format!(":{column}");
                linux::stdout(column.as_bytes());
            },
            None => {},
        }
    }
}

/// Captures and symbolizes the current physical call stack.
///
/// # Errors
///
/// Returns a structured failure when unwinding, self-image mapping, DWARF
/// parsing, or the required interior-RIP lookup cannot be completed.
pub fn print() -> Result<(), BacktraceError> {
    let trace = capture()?;
    let executable = Executable::open()?;
    let symbols = Symbols::new(executable.bytes())?;
    let interior = Symbols::print(&symbols, &trace)?;

    match interior {
        true => Ok(()),
        false => Err(BacktraceError::Interior),
    }
}
