#![expect(
    clippy::missing_inline_in_public_items,
    reason = "public naked ABI trampolines cannot carry inline attributes"
)]

//! x86_64 Level I ABI entry trampolines.
//!
//! These functions own the raw SysV entry stack and the transition from naked
//! assembly into Desenredo semantic unwind state. Generic traversal never reads
//! raw register transport directly.

use core::{ffi::c_void, mem::size_of};

use desenredo_abi::unwind::{Exception, ReasonCode, StopFn, TraceFn};

use crate::{
    arch::x86_64::{registers::Registers, state::State},
    runtime::{self, Unwinder},
};

/// Offset of the first preserved ABI argument after the raw register image.
const FIRST: usize = size_of::<Registers>();

/// Offset of the second preserved ABI argument.
const SECOND: usize = FIRST + size_of::<usize>();

/// Offset of the third preserved ABI argument.
const THIRD: usize = SECOND + size_of::<usize>();

/// Start of alignment storage after preserved arguments.
const PAD: usize = THIRD + size_of::<usize>();

/// Stack storage used by every x86_64 Level I entry trampoline.
// STACK contains one Registers transport, three native argument words, and one
// padding word. Its size is eight modulo sixteen so subtraction from the SysV
// entry stack establishes sixteen-byte alignment before calls.
const STACK: usize = PAD + size_of::<usize>();

/// Converts one captured raw register image into semantic unwind state.
///
/// # Safety
///
/// `registers` must point to one live initialized image written by
/// [`Registers::entry`] and must be consumed exactly once.
const unsafe fn state(registers: *const Registers) -> State {
    // SAFETY:
    // The function contract establishes initialized storage and single consumption.
    let registers = unsafe { Registers::take(registers) };

    State::captured(registers)
}

/// Continues normal propagation after architecture entry capture.
unsafe extern "C-unwind" fn dispatch_raise<U>(registers: *const Registers, exception: *mut Exception) -> ReasonCode
where
    U: Unwinder,
{
    // SAFETY:
    // The naked caller provides exactly one initialized capture image.
    let state = unsafe { state(registers) };

    // SAFETY:
    // The Level I entry contract transfers the live exception to this propagation.
    unsafe { runtime::raise::<U>(state, exception) }
}

/// Continues forced propagation after architecture entry capture.
unsafe extern "C-unwind" fn dispatch_force<U>(
    registers: *const Registers,
    exception: *mut Exception,
    stop: StopFn,
    parameter: *mut c_void,
) -> ReasonCode
where
    U: Unwinder,
{
    // SAFETY:
    // The naked caller provides exactly one initialized capture image.
    let state = unsafe { state(registers) };

    // SAFETY:
    // The Level I entry contract supplies the complete forced-unwind capability.
    unsafe { runtime::force::<U>(state, exception, stop, parameter) }
}

/// Continues cleanup resume after architecture entry capture.
unsafe extern "C-unwind" fn dispatch_resume<U>(registers: *const Registers, exception: *mut Exception) -> !
where
    U: Unwinder,
{
    // SAFETY:
    // The naked caller provides exactly one initialized capture image.
    let state = unsafe { state(registers) };

    // SAFETY:
    // The active exception carries Desenredo resume state from phase two.
    unsafe { runtime::resume::<U>(state, exception) }
}

/// Continues rethrow handling after architecture entry capture.
unsafe extern "C-unwind" fn dispatch_rethrow<U>(registers: *const Registers, exception: *mut Exception) -> ReasonCode
where
    U: Unwinder,
{
    // SAFETY:
    // The naked caller provides exactly one initialized capture image.
    let state = unsafe { state(registers) };

    // SAFETY:
    // The active exception is owned by the current handler or forced traversal.
    unsafe { runtime::rethrow::<U>(state, exception) }
}

/// Continues backtrace traversal after architecture entry capture.
unsafe extern "C" fn dispatch_trace<U>(
    registers: *const Registers,
    visit: TraceFn,
    parameter: *mut c_void,
) -> ReasonCode
where
    U: Unwinder,
{
    // SAFETY:
    // The naked caller provides exactly one initialized capture image.
    let state = unsafe { state(registers) };

    // SAFETY:
    // The ABI caller keeps the trace callback pair live for the complete walk.
    unsafe { runtime::trace::<U>(state, visit, parameter) }
}

/// Starts normal two-phase propagation from the x86_64 Level I caller.
///
/// # Safety
///
/// `exception` must satisfy the Level I live exception ownership contract. The
/// selected `U` must satisfy [`Unwinder`] for every reached frame.
#[doc(hidden)]
#[unsafe(naked)]
pub unsafe extern "C-unwind" fn raise<U>(_exception: *mut Exception) -> ReasonCode
where
    U: Unwinder,
{
    core::arch::naked_asm!(
        "subq ${stack}, %rsp",
        "movq %rdi, {first}(%rsp)",
        "leaq {stack}(%rsp), %rsi",
        "movq %rsp, %rdi",
        "callq {capture}",
        "movq {first}(%rsp), %rsi",
        "movq %rsp, %rdi",
        "callq {next}",
        "addq ${stack}, %rsp",
        "retq",
        stack = const STACK,
        first = const FIRST,
        capture = sym Registers::entry,
        next = sym dispatch_raise::<U>,
        options(att_syntax),
    );
}

/// Starts forced propagation from the x86_64 Level I caller.
///
/// # Safety
///
/// The exception, stop callback, and parameter must remain valid for the complete
/// forced traversal. The selected `U` must satisfy [`Unwinder`] for every frame.
#[doc(hidden)]
#[unsafe(naked)]
pub unsafe extern "C-unwind" fn force<U>(
    _exception: *mut Exception,
    _stop: StopFn,
    _parameter: *mut c_void,
) -> ReasonCode
where
    U: Unwinder,
{
    core::arch::naked_asm!(
        "subq ${stack}, %rsp",
        "movq %rdi, {first}(%rsp)",
        "movq %rsi, {second}(%rsp)",
        "movq %rdx, {third}(%rsp)",
        "leaq {stack}(%rsp), %rsi",
        "movq %rsp, %rdi",
        "callq {capture}",
        "movq {third}(%rsp), %rcx",
        "movq {second}(%rsp), %rdx",
        "movq {first}(%rsp), %rsi",
        "movq %rsp, %rdi",
        "callq {next}",
        "addq ${stack}, %rsp",
        "retq",
        stack = const STACK,
        first = const FIRST,
        second = const SECOND,
        third = const THIRD,
        capture = sym Registers::entry,
        next = sym dispatch_force::<U>,
        options(att_syntax),
    );
}

/// Resumes propagation from an x86_64 cleanup landing pad.
///
/// # Safety
///
/// `exception` must carry resume state written by the selected Desenredo unwinder.
#[doc(hidden)]
#[unsafe(naked)]
pub unsafe extern "C-unwind" fn resume<U>(_exception: *mut Exception) -> !
where
    U: Unwinder,
{
    core::arch::naked_asm!(
        "subq ${stack}, %rsp",
        "movq %rdi, {first}(%rsp)",
        "leaq {stack}(%rsp), %rsi",
        "movq %rsp, %rdi",
        "callq {capture}",
        "movq {first}(%rsp), %rsi",
        "movq %rsp, %rdi",
        "callq {next}",
        "ud2",
        stack = const STACK,
        first = const FIRST,
        capture = sym Registers::entry,
        next = sym dispatch_resume::<U>,
        options(att_syntax),
    );
}

/// Resumes forced propagation or reraises from the x86_64 Level I caller.
///
/// # Safety
///
/// `exception` must be the active object owned by the current handler or forced
/// traversal and must carry private state written by the selected unwinder.
#[doc(hidden)]
#[unsafe(naked)]
pub unsafe extern "C-unwind" fn rethrow<U>(_exception: *mut Exception) -> ReasonCode
where
    U: Unwinder,
{
    core::arch::naked_asm!(
        "subq ${stack}, %rsp",
        "movq %rdi, {first}(%rsp)",
        "leaq {stack}(%rsp), %rsi",
        "movq %rsp, %rdi",
        "callq {capture}",
        "movq {first}(%rsp), %rsi",
        "movq %rsp, %rdi",
        "callq {next}",
        "addq ${stack}, %rsp",
        "retq",
        stack = const STACK,
        first = const FIRST,
        capture = sym Registers::entry,
        next = sym dispatch_rethrow::<U>,
        options(att_syntax),
    );
}

/// Walks physical frames starting at the x86_64 `_Unwind_Backtrace` caller.
///
/// # Safety
///
/// `visit` and `parameter` must remain valid for the complete callback sequence.
#[doc(hidden)]
#[unsafe(naked)]
pub unsafe extern "C" fn trace<U>(_visit: TraceFn, _parameter: *mut c_void) -> ReasonCode
where
    U: Unwinder,
{
    core::arch::naked_asm!(
        "subq ${stack}, %rsp",
        "movq %rdi, {first}(%rsp)",
        "movq %rsi, {second}(%rsp)",
        "leaq {stack}(%rsp), %rsi",
        "movq %rsp, %rdi",
        "callq {capture}",
        "movq {second}(%rsp), %rdx",
        "movq {first}(%rsp), %rsi",
        "movq %rsp, %rdi",
        "callq {next}",
        "addq ${stack}, %rsp",
        "retq",
        stack = const STACK,
        first = const FIRST,
        second = const SECOND,
        capture = sym Registers::entry,
        next = sym dispatch_trace::<U>,
        options(att_syntax),
    );
}

#[cfg(test)]
mod tests {
    use super::STACK;

    #[test]
    fn alignment() {
        assert_eq!(STACK % 16, 8);
    }
}
