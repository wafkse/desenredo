//! Application request handling used by the userspace example.
//!
//! Each request owns one page mapping. The mapping is the resource whose Drop
//! path must run during phase two before a recovered panic reaches the boundary.

use core::{
    ffi::c_void,
    num::NonZeroUsize,
    ptr::{self, NonNull},
    sync::atomic::{AtomicUsize, Ordering},
};

use rustix::mm::{MapFlags, ProtFlags, mmap_anonymous, munmap};

use crate::{
    backtrace::{self, BacktraceError},
    linux::{self, ExitCode, PAGE_SIZE},
};

/// Number of request mappings released through Drop.
static CLEANUPS: AtomicUsize = AtomicUsize::new(0);

/// Work selected by one command line request.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Command {
    /// Complete normally after touching the request resource.
    Work,

    /// Panic after acquiring the request resource.
    Panic,

    /// Capture and symbolize the current physical call stack.
    Trace,
}

impl Command {
    /// Parses one application argument into a supported request command.
    #[inline]
    pub const fn parse(argument: &[u8]) -> Option<Self> {
        match argument {
            b"work" => Some(Self::Work),
            b"panic" => Some(Self::Panic),
            b"trace" => Some(Self::Trace),
            _ => None,
        }
    }
}

/// One application request with a stable nonzero identity.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Request {
    /// Monotonic request identity used by the panic runtime.
    id: NonZeroUsize,

    /// Operation selected for this request.
    command: Command,
}

impl Request {
    /// Constructs one validated request.
    #[inline]
    pub const fn new(id: NonZeroUsize, command: Command) -> Self {
        Self { id, command }
    }

    /// Returns the request identity.
    #[inline]
    pub const fn id(self) -> NonZeroUsize {
        let Self { id, .. } = self;

        id
    }
}

/// Expected request execution failure before panic propagation begins.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ServiceError {
    /// Linux could not allocate the per-request page mapping.
    Resource,

    /// Physical capture or addr2line symbolization failed.
    Backtrace(BacktraceError),
}

/// One page mapping owned by the active request.
// NOTE(invariant): pointer names one live private PAGE_SIZE mapping until Drop.
// No other path releases the mapping while this owner exists.
struct Mapping(NonNull<c_void>);

impl Mapping {
    /// Acquires one page of request-local scratch storage.
    fn new() -> Result<Self, ServiceError> {
        // SAFETY:
        // A null hint asks Linux for one fresh private page mapping.
        let mapped = unsafe {
            mmap_anonymous(
                ptr::null_mut(),
                PAGE_SIZE,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::PRIVATE,
            )
        };

        match mapped {
            Ok(mapped) => {
                // SAFETY:
                // A successful mmap result is a nonnull live mapping base.
                let pointer = unsafe { NonNull::new_unchecked(mapped) };

                Ok(Self(pointer))
            },
            Err(_error) => Err(ServiceError::Resource),
        }
    }

    /// Writes the request identity into owned scratch storage.
    const fn touch(&self, request: NonZeroUsize) {
        let &Self(pointer) = self;
        let word = pointer.cast::<usize>();

        // SAFETY:
        // Mapping owns at least one writable page and usize fits within it.
        unsafe { word.as_ptr().write(request.get()) };
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        let &mut Self(pointer) = self;

        // SAFETY:
        // The Mapping invariant proves this exact page is live and uniquely owned.
        let released = unsafe { munmap(pointer.as_ptr(), PAGE_SIZE) };

        match released {
            Ok(()) => {
                CLEANUPS.fetch_add(1, Ordering::AcqRel);
            },
            Err(_error) => linux::terminate(b"request mapping release failed\n", ExitCode::SOFTWARE),
        }
    }
}

/// Returns the number of request resources released through Drop.
#[inline]
pub fn cleanups() -> usize {
    CLEANUPS.load(Ordering::Acquire)
}

/// Executes one request while owning a resource that must unwind correctly.
///
/// # Errors
///
/// Returns [`ServiceError::Resource`] when Linux cannot create the request page.
pub fn execute(request: &Request) -> Result<(), ServiceError> {
    let resource = Mapping::new()?;
    let &Request { id, command } = request;

    resource.touch(id);

    match command {
        Command::Work => Ok(()),
        Command::Panic => simulated_panic(),
        Command::Trace => trace_outer().map_err(ServiceError::Backtrace),
    }
}

/// Outermost application frame retained in the backtrace demonstration.
#[inline(never)]
fn trace_outer() -> Result<(), BacktraceError> {
    trace_middle()
}

/// Middle application frame retained in the backtrace demonstration.
#[inline(never)]
fn trace_middle() -> Result<(), BacktraceError> {
    trace_inner()
}

/// Innermost application frame which captures the physical trace.
#[inline(never)]
fn trace_inner() -> Result<(), BacktraceError> {
    backtrace::print()
}

/// Produces the recoverable Rust panic demonstrated by the example.
#[expect(
    clippy::panic,
    reason = "the example intentionally demonstrates recovery from one Rust panic"
)]
fn simulated_panic() -> ! {
    panic!("simulated request failure")
}
