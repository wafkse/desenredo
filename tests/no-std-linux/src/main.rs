#![no_std]
#![no_main]
#![cfg_attr(feature = "catch", feature(core_intrinsics, lang_items, panic_can_unwind))]
#![cfg_attr(feature = "catch", allow(internal_features))]

//! Libc-free Linux userspace unwind integration for Desenredo.
//!
//! This executable proves that a `core + alloc` Linux process can unwind a real
//! Rust panic without Rust `std` or libc. `rustix` supplies raw Linux process and
//! memory operations. Desenredo supplies physical Level I unwinding, the Rust
//! exception object, and the personality policy.
//!
//! ```text
//!                  compiler generated Rust code
//!                            |
//!                            v
//!                         panic!
//!                            |
//!                            v
//!                  +-------------------+
//!                  | #[panic_handler]  |
//!                  +---------+---------+
//!                            |
//!                            v
//!                  +-------------------+
//!                  | desenredo-panic   |
//!                  | MOZ\0RUST packet |
//!                  +---------+---------+
//!                            |
//!                            v
//!                  _Unwind_RaiseException
//!                            |
//!             +--------------+--------------+
//!             |                             |
//!             v                             v
//!      Desenredo stack walk        rust_eh_personality
//!      over DWARF CFI              from Desenredo
//!             |                             |
//!             +--------------+--------------+
//!                            |
//!                     phase one search
//!                            |
//!                     handler selected
//!                            |
//!                     phase two cleanup
//!                            |
//!                            +------> Guard::drop
//!                            |
//!                            v
//!                     catch landing pad
//!                            |
//!                            v
//!                     payload recovered
//! ```
//!
//! The positive path places an `extern "C-unwind"` frame between the panic and
//! the compiler catch intrinsic. The frame owns a `Guard`, so successful recovery
//! requires phase two to execute its compiler-generated cleanup exactly once.
//!
//! The `ffi-c-abort` path replaces that frame with `extern "C"`. Rustc marks the
//! panic as non-unwindable before Desenredo raises an exception. The outer catch
//! remains a sentinel which must never receive control.
//!
//! The unwind protocol and personality phases come from the [Itanium C++ ABI
//! exception handling specification](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html).
//! The CIE, FDE, CFA, and register recovery model comes from [DWARF Version
//! 5](https://dwarfstd.org/doc/DWARF5.pdf), especially section 6.4.
//!
//! The executable intentionally separates those responsibilities. DWARF metadata
//! explains how to recover the next machine frame. LSDA explains what the active
//! language wants to do with that frame during exception propagation.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("the no-std userspace fixture currently validates x86_64 Linux");

extern crate alloc;

use alloc::boxed::Box;
#[cfg(not(feature = "ffi-c-abort"))]
use core::ffi::c_void;
#[cfg(not(feature = "ffi-c-abort"))]
use core::mem::MaybeUninit;
use core::{
    alloc::{GlobalAlloc, Layout},
    ffi::c_int,
    panic::PanicInfo,
    ptr,
    sync::atomic::{AtomicUsize, Ordering},
};

use desenredo::{
    abi::{
        class::ExceptionClass,
        unwind::{Actions, Context, Exception, ReasonCode},
    },
    personality::{context::Frame, protocol, source::Source},
    unwind::source::Image as Meta,
};
#[cfg(not(feature = "ffi-c-abort"))]
use desenredo_panic::object::Payload;
use desenredo_panic::runtime::{Hook, Runtime};
use rustix::mm::{MapFlags, ProtFlags};

core::arch::global_asm!(include_str!("catch.S"), options(att_syntax));
const PAGE: usize = 4096;
const MARKER: u64 = 0x4453_4e52_4544_4f21;

static DROPS: AtomicUsize = AtomicUsize::new(0);

/// First callback observation from a Level I traversal.
#[cfg(not(feature = "ffi-c-abort"))]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct First {
    /// Raw instruction pointer reported by the unwinder.
    ip: usize,

    /// Nonzero when the instruction pointer denotes the instruction itself.
    before: c_int,
}

/// State accumulated by the backtrace probe.
// NOTE(invariant): first is populated by the first callback and count records the
// complete number of callbacks delivered before the traversal returns.
#[cfg(not(feature = "ffi-c-abort"))]
struct Trace {
    /// First callback observation.
    first: Option<First>,

    /// Number of callbacks observed.
    count: usize,
}

#[cfg(not(feature = "ffi-c-abort"))]
impl Trace {
    /// Creates empty trace observation state.
    #[inline]
    const fn new() -> Self {
        Self { first: None, count: 0 }
    }
}

/// State accumulated by the forced-unwind stop callback.
// NOTE(invariant): first records the first physical frame exactly once and end is
// set only when the stop callback receives the explicit end-of-stack action.
#[cfg(not(feature = "ffi-c-abort"))]
struct Forced {
    /// First callback observation.
    first: Option<First>,

    /// Whether the final end-of-stack callback was observed.
    end: bool,
}

#[cfg(not(feature = "ffi-c-abort"))]
impl Forced {
    /// Creates empty forced-unwind observation state.
    #[inline]
    const fn new() -> Self {
        Self {
            first: None,
            end: false,
        }
    }
}

#[cfg(not(feature = "ffi-c-abort"))]
unsafe extern "C" {
    fn desenredo_trace_probe(state: *mut c_void) -> ReasonCode;

    static desenredo_trace_return: u8;

    fn desenredo_force_probe(exception: *mut Exception, state: *mut c_void) -> ReasonCode;

    static desenredo_force_return: u8;

    fn desenredo_register_probe(callback: extern "C-unwind" fn()) -> c_int;
}

struct LinuxAlloc;

#[global_allocator]
static ALLOCATOR: LinuxAlloc = LinuxAlloc;

#[inline]
fn pages(size: usize) -> Option<usize> {
    size.max(1).checked_add(PAGE - 1).map(|size| size & !(PAGE - 1))
}

#[inline]
fn map(size: usize) -> *mut u8 {
    // SAFETY:
    // A null hint asks Linux to choose a fresh private mapping.
    let mapped = unsafe {
        rustix::mm::mmap_anonymous(
            ptr::null_mut(),
            size,
            ProtFlags::READ | ProtFlags::WRITE,
            MapFlags::PRIVATE,
        )
    };

    match mapped {
        Ok(mapped) => mapped.cast(),
        Err(_) => ptr::null_mut(),
    }
}

// SAFETY:
// Every successful allocation is a private page mapping owned by the caller.
unsafe impl GlobalAlloc for LinuxAlloc {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = match (layout.align() <= PAGE, pages(layout.size())) {
            (true, Some(size)) => size,
            _ => return ptr::null_mut(),
        };

        map(size)
    }

    #[inline]
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let Some(size) = pages(layout.size()) else {
            return;
        };

        // SAFETY:
        // GlobalAlloc calls dealloc only for the live mapping returned by alloc.
        let _ = unsafe { rustix::mm::munmap(pointer.cast(), size) };
    }
}

#[derive(Debug, Copy, Clone, fack::prelude::Error)]
#[error("LSDA pointer lies outside the linked exception table")]
struct Bounds;

struct Image;

unsafe extern "C" {
    static __desenredo_text_start: u8;
    static __desenredo_text_end: u8;
    static __desenredo_eh_start: u8;
    static __desenredo_eh_end: u8;
    static __desenredo_lsda_start: u8;
    static __desenredo_lsda_end: u8;
}

// SAFETY:
// The linker script bounds every live GCC-style LSDA in this static image.
unsafe impl Source for Image {
    type Error = Bounds;

    #[inline]
    fn bytes<'a>(frame: &Frame<'a>) -> Result<Option<&'a [u8]>, Self::Error> {
        let origin = frame.lsda();
        let start = ptr::addr_of!(__desenredo_lsda_start).addr();
        let end = ptr::addr_of!(__desenredo_lsda_end).addr();

        match origin {
            None => Ok(None),
            Some(origin) => {
                // SAFETY:
                // Source proves origin is the live LSDA pointer for this frame.
                unsafe { bound(origin.as_ptr(), start, end) }.map(Some)
            },
        }
    }
}

// SAFETY:
// The linker symbols bound trusted compiler CFI for this static image. CFI memory
// reads address the same live image or live stack activation selected by that CFI.
#[desenredo::unwind]
unsafe impl desenredo::unwind::runtime::Unwinder for Image {
    fn image(address: usize) -> Option<Meta<'static>> {
        let text_start = ptr::addr_of!(__desenredo_text_start).addr();
        let text_end = ptr::addr_of!(__desenredo_text_end).addr();
        let eh_start = ptr::addr_of!(__desenredo_eh_start).addr();
        let eh_end = ptr::addr_of!(__desenredo_eh_end).addr();
        let text = text_start..text_end;
        let size = eh_end.checked_sub(eh_start);

        match (text.contains(&address), size) {
            (true, Some(size)) => {
                // SAFETY:
                // The linker symbols bound the complete live .eh_frame section.
                let bytes = unsafe { core::slice::from_raw_parts(ptr::with_exposed_provenance(eh_start), size) };

                Meta::new(bytes, text)
            },
            _ => None,
        }
    }

    fn read(address: usize, size: u8) -> Option<u64> {
        let pointer = ptr::with_exposed_provenance::<u8>(address);

        // SAFETY:
        // The Unwinder implementation contract restricts requests to trusted CFI
        // addresses in the current live image or stack activation.
        unsafe {
            match size {
                1 => Some(u64::from(pointer.read_unaligned())),
                2 => Some(u64::from(pointer.cast::<u16>().read_unaligned())),
                4 => Some(u64::from(pointer.cast::<u32>().read_unaligned())),
                8 => Some(pointer.cast::<u64>().read_unaligned()),
                _ => None,
            }
        }
    }
}

#[inline]
unsafe fn bound<'a>(origin: *const u8, start: usize, end: usize) -> Result<&'a [u8], Bounds> {
    let address = origin.addr();
    let valid = start <= address && address < end && start <= end;

    if !valid {
        Err(Bounds)
    } else {
        let size = end - address;
        // SAFETY:
        // The Source implementation proves this range is the linked LSDA section.
        Ok(unsafe { core::slice::from_raw_parts(origin, size) })
    }
}

#[lang = "eh_personality"]
unsafe extern "C" fn rust_eh_personality(
    version: c_int,
    actions: Actions,
    class: ExceptionClass,
    exception: *mut Exception,
    context: *mut Context,
) -> ReasonCode {
    // SAFETY:
    // The symbol is invoked only by the active Itanium unwinder.
    unsafe {
        protocol::dispatch::<desenredo::rust::personality::Policy<Image>>(version, actions, class, exception, context)
    }
}

struct LinuxRuntime;

unsafe extern "C" fn lost() -> ! {
    finish(b"unwinder returned without reaching the catch frame\n", 70)
}

unsafe extern "C" fn foreign() -> ! {
    finish(b"catch frame received a foreign exception\n", 71)
}

// SAFETY:
// Both hooks terminate through the raw Linux exit_group syscall.
unsafe impl Runtime for LinuxRuntime {
    const FOREIGN: Hook = foreign;
    const LOST: Hook = lost;
}

#[inline]
fn write_all(mut bytes: &[u8]) {
    while !bytes.is_empty() {
        // SAFETY:
        // This fixture never closes or repurposes the inherited stderr descriptor.
        let stderr = unsafe { rustix::stdio::stderr() };
        match rustix::io::write(stderr, bytes) {
            Ok(0) | Err(_) => break,
            Ok(written) => bytes = &bytes[written..],
        }
    }
}

#[inline]
fn finish(message: &[u8], status: i32) -> ! {
    write_all(message);
    rustix::runtime::exit_group(status)
}

struct Guard;

impl Drop for Guard {
    #[inline]
    fn drop(&mut self) {
        DROPS.fetch_add(1, Ordering::SeqCst);
    }
}

#[cfg(not(feature = "ffi-c-abort"))]
#[inline(never)]
extern "C-unwind" fn panic_source() {
    panic!("desenredo no-std panic=unwind fixture");
}

#[cfg(not(feature = "ffi-c-abort"))]
#[unsafe(no_mangle)]
unsafe extern "C" fn desenredo_register_landing(exception: *mut Exception, preserved: c_int) -> c_int {
    // SAFETY:
    // The authored handler receives the live Rust panic selected by this personality.
    let payload = unsafe { desenredo_panic::object::catch::<LinuxRuntime>(exception) };
    let payload = payload.downcast::<u64>();

    match payload {
        Ok(marker) if *marker == MARKER && preserved == 1 => 1,
        _ => 0,
    }
}

#[cfg(not(feature = "ffi-c-abort"))]
#[inline(never)]
fn registers() -> bool {
    // SAFETY:
    // The assembly probe keeps a Rust handler active and calls this unwind-capable callback.
    let preserved = unsafe { desenredo_register_probe(panic_source) };

    preserved == 1
}

#[cfg(not(feature = "ffi-c-abort"))]
#[inline(never)]
extern "C-unwind" fn ffi_unwind_boundary(callback: extern "C-unwind" fn()) {
    let _guard = Guard;

    callback();
}

#[cfg(feature = "ffi-c-abort")]
#[inline(never)]
extern "C" fn ffi_non_unwind_boundary() {
    let _guard = Guard;

    panic!("panic attempting to leave extern C");
}

#[cfg(feature = "ffi-c-abort")]
#[inline(never)]
extern "C-unwind" fn invoke_non_unwind() {
    ffi_non_unwind_boundary();
}

#[cfg(feature = "ffi-c-abort")]
unsafe extern "C-unwind" {
    fn desenredo_outer_catch(callback: extern "C-unwind" fn());
}

#[cfg(feature = "ffi-c-abort")]
#[unsafe(no_mangle)]
unsafe extern "C" fn unexpected_non_unwind_landing(_exception: *mut Exception) -> ! {
    finish(b"extern C unwind unexpectedly reached outer catch\n", 75)
}

#[cfg(not(feature = "ffi-c-abort"))]
#[unsafe(no_mangle)]
unsafe extern "C" fn desenredo_trace_visit(context: *mut Context, parameter: *mut c_void) -> ReasonCode {
    let state = parameter.cast::<Trace>();
    let mut before = 0;

    // SAFETY:
    // The trace ABI supplies a live Desenredo context and this writable output.
    let ip = unsafe { desenredo::abi::unwind::_Unwind_GetIPInfo(context, &mut before) };

    // SAFETY:
    // desenredo_trace_probe forwards the unique live Trace pointer for every callback.
    let state = unsafe { &mut *state };
    let Trace { first, count } = state;

    if first.is_none() {
        *first = Some(First { ip, before });
    }
    *count += 1;

    ReasonCode::NONE
}

#[cfg(not(feature = "ffi-c-abort"))]
#[unsafe(no_mangle)]
unsafe extern "C" fn desenredo_force_stop(
    _version: c_int,
    actions: Actions,
    _class: ExceptionClass,
    _exception: *mut Exception,
    context: *mut Context,
    parameter: *mut c_void,
) -> ReasonCode {
    let state = parameter.cast::<Forced>();

    // SAFETY:
    // desenredo_force_probe forwards the unique live Forced pointer for every callback.
    let state = unsafe { &mut *state };
    let Forced { first, end } = state;

    if actions.has(Actions::END) {
        *end = true;
    } else if first.is_none() {
        let mut before = 0;

        // SAFETY:
        // The stop ABI supplies a live context for every nonterminal physical frame.
        let ip = unsafe { desenredo::abi::unwind::_Unwind_GetIPInfo(context, &mut before) };
        *first = Some(First { ip, before });
    }

    ReasonCode::NONE
}

#[cfg(not(feature = "ffi-c-abort"))]
#[inline(never)]
extern "C-unwind" fn ending() -> bool {
    let class = ExceptionClass::new(u64::from_ne_bytes(*b"DSNRTEST"));
    let mut exception = Exception::new(class, None);

    // SAFETY:
    // exception is a live stack-owned Level I header whose private words are
    // exclusively available until this no-handler propagation returns.
    let reason = unsafe { desenredo::abi::unwind::_Unwind_RaiseException(&mut exception) };

    reason == ReasonCode::END
}

#[cfg(not(feature = "ffi-c-abort"))]
#[inline(never)]
fn trace() -> bool {
    let mut state = Trace::new();

    // SAFETY:
    // The assembly probe forwards this live state only to desenredo_trace_visit.
    let reason = unsafe { desenredo_trace_probe(ptr::from_mut(&mut state).cast()) };
    let expected = ptr::addr_of!(desenredo_trace_return).addr();
    let Trace { first, count } = state;

    matches!(
        (reason, first, count >= 3),
        (ReasonCode::END, Some(First { ip, before: 0 }), true) if ip == expected
    )
}

#[cfg(not(feature = "ffi-c-abort"))]
#[inline(never)]
fn forced() -> bool {
    let class = ExceptionClass::new(u64::from_ne_bytes(*b"DSNRTEST"));
    let mut exception = Exception::new(class, None);
    let mut state = Forced::new();

    // SAFETY:
    // The stack exception and callback state remain live until forced traversal
    // reaches the explicit root or reports failure.
    let reason = unsafe { desenredo_force_probe(ptr::from_mut(&mut exception), ptr::from_mut(&mut state).cast()) };
    let expected = ptr::addr_of!(desenredo_force_return).addr();
    let Forced { first, end } = state;

    matches!(
        (reason, first, end),
        (ReasonCode::END, Some(First { ip, before: 0 }), true) if ip == expected
    )
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    if info.can_unwind() {
        desenredo_panic::object::start::<LinuxRuntime>(Box::new(MARKER))
    } else {
        write_all(b"terminating non-unwinding panic\n");
        core::intrinsics::abort()
    }
}

// NOTE(invariant): payload is initialized exactly when the catch callback consumes a local Rust
// panic object.
#[cfg(not(feature = "ffi-c-abort"))]
struct CatchState {
    /// Panic payload initialized by the intrinsic catch callback.
    payload: MaybeUninit<Payload>,
}

#[cfg(not(feature = "ffi-c-abort"))]
impl CatchState {
    #[inline]
    const fn new() -> Self {
        Self {
            payload: MaybeUninit::uninit(),
        }
    }
}

#[cfg(not(feature = "ffi-c-abort"))]
unsafe fn invoke_c_unwind(_state: *mut CatchState) {
    ffi_unwind_boundary(panic_source);
}

#[cfg(not(feature = "ffi-c-abort"))]
unsafe fn catch_panic(state: *mut CatchState, exception: *mut u8) {
    // SAFETY:
    // The intrinsic supplies the live runtime exception object selected by rust_eh_personality.
    let payload = unsafe { desenredo_panic::object::catch::<LinuxRuntime>(exception.cast::<Exception>()) };

    // SAFETY:
    // The intrinsic passes back the same valid state pointer supplied by run_catch_unwind.
    unsafe { (*state).payload.write(payload) };
}

#[cfg(not(feature = "ffi-c-abort"))]
#[inline]
fn run_catch_unwind() -> bool {
    let mut state = CatchState::new();

    // SAFETY:
    // Both callbacks accept this live state pointer and catch_panic never unwinds.
    let caught = unsafe { core::intrinsics::catch_unwind(invoke_c_unwind, ptr::from_mut(&mut state), catch_panic) };

    if caught {
        // SAFETY:
        // A true result proves catch_panic ran and initialized the payload slot.
        let payload = unsafe { state.payload.assume_init_read() };
        let payload = payload.downcast::<u64>();
        let drops = DROPS.load(Ordering::SeqCst);

        matches!(payload, Ok(marker) if *marker == MARKER && drops == 1)
    } else {
        false
    }
}

#[unsafe(no_mangle)]
extern "C-unwind" fn desenredo_entry() -> ! {
    write_all(b"starting no_std rustix linux_raw unwind fixture\n");

    #[cfg(feature = "ffi-c-abort")]
    {
        write_all(b"attempting panic across extern C boundary\n");
        // SAFETY:
        // The assembly frame is an outer sentinel which must remain unreachable because rustc marks
        // the inner C panic non-unwindable.
        unsafe { desenredo_outer_catch(invoke_non_unwind) };
        finish(b"extern C boundary unexpectedly returned\n", 74)
    }

    #[cfg(not(feature = "ffi-c-abort"))]
    {
        if !ending() {
            finish(b"no-handler propagation did not reach END\n", 76)
        }
        if !trace() {
            finish(b"backtrace did not start at its ABI caller or reach END\n", 77)
        }
        if !forced() {
            finish(b"forced unwind caller or END callback mismatch\n", 78)
        }
        if !registers() {
            finish(b"callee-saved register reconstruction mismatch\n", 79)
        }

        if run_catch_unwind() {
            finish(b"no_std unwind batteries passed\n", 0)
        } else {
            finish(b"catch_unwind payload or Drop cleanup mismatch\n", 72)
        }
    }
}
