//! Level I Itanium unwind ABI declarations and exception header.
//!
//! These definitions mirror the language-neutral `_Unwind_*` interface. The
//! module owns raw reason values, action bits, the opaque unwind context, and the
//! exception header passed between a language runtime and an unwinder. It does
//! not allocate and does not assume libc or a hosted process runtime.

use core::{
    ffi::{c_int, c_void},
    ops::BitOr,
};

use super::class::ExceptionClass;

bitflags::bitflags! {
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    struct ActionBits: c_int {
        const SEARCH = 1;
        const CLEANUP = 2;
        const HANDLER = 4;
        const FORCE = 8;
        const END = 16;
    }
}

/// A reason code returned by the unwinder or a personality routine.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
// NOTE(invariant): The stored integer preserves the complete Itanium reason-code value supplied at
// the ABI boundary.
pub struct ReasonCode(c_int);

impl ReasonCode {
    /// Unwinding should continue with the next frame.
    pub const CONTINUE: Self = Self(8);
    /// The unwinder reached the end of the stack.
    pub const END: Self = Self(5);
    /// The search phase encountered a fatal error.
    pub const FATAL1: Self = Self(3);
    /// The cleanup phase encountered a fatal error.
    pub const FATAL2: Self = Self(2);
    /// A foreign runtime caught the exception.
    pub const FOREIGN: Self = Self(1);
    /// The personality routine found a handler.
    pub const HANDLER: Self = Self(6);
    /// The unwinder must install the modified context.
    pub const INSTALL: Self = Self(7);
    /// No exceptional condition was reported.
    pub const NONE: Self = Self(0);
    /// A forced unwind stopped normally.
    pub const STOP: Self = Self(4);

    /// Creates a reason code from its ABI integer representation.
    #[inline]
    pub const fn new(value: c_int) -> Self {
        Self(value)
    }

    /// Returns the underlying ABI integer.
    #[inline]
    pub const fn raw(self) -> c_int {
        let Self(value) = self;

        value
    }
}

/// Personality action bits supplied by the unwinder.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
// NOTE(invariant): The stored integer preserves the complete action-bit value supplied at the ABI
// boundary.
pub struct Actions(c_int);

impl Actions {
    /// Every action bit recognized by this ABI surface.
    pub const ALL: Self = Self(ActionBits::all().bits());
    /// The cleanup phase bit.
    pub const CLEANUP: Self = Self(ActionBits::CLEANUP.bits());
    /// The GNU end of stack extension bit.
    pub const END: Self = Self(ActionBits::END.bits());
    /// The forced unwind bit.
    pub const FORCE: Self = Self(ActionBits::FORCE.bits());
    /// The frame selected as the handler bit.
    pub const HANDLER: Self = Self(ActionBits::HANDLER.bits());
    /// No action bits are set.
    pub const NONE: Self = Self(ActionBits::empty().bits());
    /// The handler search phase bit.
    pub const SEARCH: Self = Self(ActionBits::SEARCH.bits());

    /// Creates action bits from their ABI integer representation.
    #[inline]
    pub const fn new(value: c_int) -> Self {
        Self(value)
    }

    /// Returns the ABI integer representation.
    #[inline]
    pub const fn raw(self) -> c_int {
        let Self(value) = self;

        value
    }

    /// Reports whether every action bit is recognized.
    #[inline]
    pub const fn known(self) -> bool {
        ActionBits::from_bits(Self::raw(self)).is_some()
    }

    /// Reports whether all requested bits are present.
    #[inline]
    pub const fn has(self, other: Self) -> bool {
        let current = ActionBits::from_bits_retain(Self::raw(self));
        let other = ActionBits::from_bits_retain(Self::raw(other));

        current.contains(other)
    }
}

impl BitOr for Actions {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        let lhs = ActionBits::from_bits_retain(Self::raw(self));
        let rhs = ActionBits::from_bits_retain(Self::raw(rhs));
        let bits = lhs.union(rhs).bits();

        Self(bits)
    }
}

/// Opaque frame state owned and mutated by the active unwinder.
///
/// Safe code never constructs or dereferences this type. Personality wrappers
/// only retain a nonnull pointer for the duration of one callback.
#[repr(C)]
// NOTE(invariant): The zero-sized private field keeps the system-owned unwind context opaque to
// safe Rust code.
pub struct Context {
    /// Prevents callers from depending on the system-owned representation.
    _private: [u8; 0],
}

/// Cleanup callback stored in an unwind exception header.
///
/// The unwinder invokes this callback after it has stopped using the exception.
/// The producer remains responsible for interpreting the enclosing allocation
/// and releasing it exactly once.
pub type Cleanup = unsafe extern "C" fn(ReasonCode, *mut Exception);

/// Optional cleanup callback stored in an unwind exception header.
pub type CleanupFn = Option<Cleanup>;

/// The ABI exception header used by the GNU DWARF unwinder.
#[repr(C, align(16))]
// NOTE(invariant): Layout, field order, and alignment match the x86_64 Itanium header. Fresh
// construction zeroes both private words and only the active unwinder may mutate them after raise.
pub struct Exception {
    /// Identifies the producer runtime and source language.
    exception_class: ExceptionClass,

    /// Releases producer-owned exception storage after deletion.
    exception_cleanup: CleanupFn,

    /// First machine word reserved for the active unwinder.
    private_1: usize,

    /// Second machine word reserved for the active unwinder.
    private_2: usize,
}

/// Exclusive access to the two words reserved for the active unwinder.
// NOTE(invariant): Both references name the private words of one live Exception and remain
// exclusively borrowed for the complete capability lifetime.
pub struct Private<'a>(&'a mut usize, &'a mut usize);

impl Private<'_> {
    /// Returns both private words without changing ownership.
    #[inline]
    pub const fn words(&self) -> [usize; 2] {
        let &Self(ref first, ref second) = self;

        [**first, **second]
    }

    /// Replaces both private words through the exclusive borrow.
    #[inline]
    pub const fn write(&mut self, words: [usize; 2]) {
        let &mut Self(ref mut first, ref mut second) = self;

        let [new_first, new_second] = words;

        **first = new_first;
        **second = new_second;
    }
}

impl Exception {
    /// Creates a producer-owned exception header before unwinding begins.
    ///
    /// Both unwinder-private words start at zero as required for a fresh raise.
    /// The producer may initialize its surrounding allocation after construction
    /// but must stop accessing the private words once the header is raised.
    #[inline]
    pub const fn new(exception_class: ExceptionClass, exception_cleanup: CleanupFn) -> Self {
        Self {
            exception_class,
            exception_cleanup,
            private_1: 0,
            private_2: 0,
        }
    }

    /// Returns the exception class configured by the producer runtime.
    #[inline]
    pub const fn class(&self) -> ExceptionClass {
        let &Self { exception_class, .. } = self;

        exception_class
    }

    /// Returns the producer cleanup callback stored in this header.
    #[inline]
    pub const fn cleanup(&self) -> CleanupFn {
        let &Self { exception_cleanup, .. } = self;

        exception_cleanup
    }

    /// Borrows the words reserved for the active unwinder.
    ///
    /// # Safety
    ///
    /// The caller must be the active unwinder for this live exception. No other
    /// code may read or modify the private words until the returned capability is
    /// dropped. Producer code must not use this operation to inspect unwinder
    /// state.
    #[inline]
    pub const unsafe fn private(&mut self) -> Private<'_> {
        let &mut Self {
            ref mut private_1,
            ref mut private_2,
            ..
        } = self;

        Private(private_1, private_2)
    }
}

/// Stop callback used by forced unwinding.
pub type StopFn =
    unsafe extern "C" fn(c_int, Actions, ExceptionClass, *mut Exception, *mut Context, *mut c_void) -> ReasonCode;

/// Trace callback used by the GNU backtrace extension.
pub type TraceFn = unsafe extern "C" fn(*mut Context, *mut c_void) -> ReasonCode;

/// Personality callback installed in unwind metadata.
pub type PersonalityFn =
    unsafe extern "C" fn(c_int, Actions, ExceptionClass, *mut Exception, *mut Context) -> ReasonCode;

unsafe extern "C-unwind" {
    /// Starts a normal two-phase unwind.
    ///
    /// # Safety
    ///
    /// `exception` must point to a live aligned header whose producer-owned fields
    /// remain valid until the unwinder transfers or returns ownership. Its private
    /// words must be available exclusively to this unwinder invocation.
    pub fn _Unwind_RaiseException(exception: *mut Exception) -> ReasonCode;

    /// Starts a forced single-phase unwind.
    ///
    /// # Safety
    ///
    /// `exception` must satisfy the live-header ownership contract used by a
    /// normal raise. `stop` and `stop_parameter` must remain valid for every stop
    /// callback until the forced unwind finishes or returns.
    pub fn _Unwind_ForcedUnwind(exception: *mut Exception, stop: StopFn, stop_parameter: *mut c_void) -> ReasonCode;

    /// Resumes propagation after a cleanup landing pad.
    ///
    /// # Safety
    ///
    /// `exception` must be the still-active object delivered to the cleanup
    /// landing pad. The landing pad must not have consumed, deleted, or replaced
    /// the exception before resuming it.
    pub fn _Unwind_Resume(exception: *mut Exception);

    /// Resumes a forced unwind or rethrows a handled exception.
    ///
    /// # Safety
    ///
    /// `exception` must be the active object in the state expected by the current
    /// unwinder. The caller must still own the corresponding resume or rethrow
    /// transition and must not have deleted the object.
    pub fn _Unwind_Resume_or_Rethrow(exception: *mut Exception) -> ReasonCode;
}

unsafe extern "C" {
    /// Deletes an exception through its producer cleanup callback.
    ///
    /// # Safety
    ///
    /// `exception` must be a live object which the caller currently owns and may
    /// delete. No reference, landing pad, or unwinder operation may continue to
    /// use the exception after this call transfers it to the cleanup callback.
    pub fn _Unwind_DeleteException(exception: *mut Exception);

    /// Reads one DWARF-numbered general register from an unwind context.
    ///
    /// # Safety
    ///
    /// `context` must be the live context supplied by the active unwinder callback
    /// and `index` must be a DWARF register number supported by the target.
    pub fn _Unwind_GetGR(context: *mut Context, index: c_int) -> usize;

    /// Writes one DWARF-numbered general register in an installable context.
    ///
    /// # Safety
    ///
    /// `context` must be the live mutable phase-two context. The caller must have
    /// exclusive authority to prepare that context and `index` must name a target
    /// register which the landing-pad ABI permits the personality to replace.
    pub fn _Unwind_SetGR(context: *mut Context, index: c_int, value: usize);

    /// Reads the instruction pointer from the unwind context.
    ///
    /// # Safety
    ///
    /// `context` must be the live context for the active unwinder callback.
    pub fn _Unwind_GetIP(context: *mut Context) -> usize;

    /// Reads the instruction pointer and reports its instruction relation.
    ///
    /// # Safety
    ///
    /// `context` must be live for the active callback. `before_instruction` must
    /// point to writable `c_int` storage for the duration of the call.
    pub fn _Unwind_GetIPInfo(context: *mut Context, before_instruction: *mut c_int) -> usize;

    /// Writes the instruction pointer in an installable context.
    ///
    /// # Safety
    ///
    /// `context` must be the exclusively prepared phase-two context and `value`
    /// must name executable landing-pad code valid for the target EH convention.
    pub fn _Unwind_SetIP(context: *mut Context, value: usize);

    /// Reads the canonical frame address.
    ///
    /// # Safety
    ///
    /// `context` must be the live context for the active unwinder callback.
    pub fn _Unwind_GetCFA(context: *mut Context) -> usize;

    /// Returns the language specific data address for the frame.
    ///
    /// # Safety
    ///
    /// `context` must be live for the active callback. The returned pointer is not
    /// a Rust slice and carries no length or dereference permission by itself.
    pub fn _Unwind_GetLanguageSpecificData(context: *mut Context) -> *const u8;

    /// Returns the code region start for the frame.
    ///
    /// # Safety
    ///
    /// `context` must be the live context for the active unwinder callback.
    pub fn _Unwind_GetRegionStart(context: *mut Context) -> usize;

    /// Returns the text-relative pointer base for the frame.
    ///
    /// # Safety
    ///
    /// `context` must be live and the linked unwinder implementation must support
    /// this optional base query for the current frame. Callers should query it
    /// lazily only when an encoding requires a text-relative base.
    pub fn _Unwind_GetTextRelBase(context: *mut Context) -> usize;

    /// Returns the data-relative pointer base for the frame.
    ///
    /// # Safety
    ///
    /// `context` must be live and the linked unwinder implementation must support
    /// this optional base query for the current frame. Callers should query it
    /// lazily only when an encoding requires a data-relative base.
    pub fn _Unwind_GetDataRelBase(context: *mut Context) -> usize;

    /// Walks frames without running cleanup actions.
    ///
    /// # Safety
    ///
    /// `trace` must remain callable for every visited frame and `parameter` must
    /// remain valid according to the callback's own contract until walking stops.
    pub fn _Unwind_Backtrace(trace: TraceFn, parameter: *mut c_void) -> ReasonCode;
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, offset_of, size_of};

    use super::{Actions, Exception};

    #[test]
    fn layout() {
        assert_eq!(size_of::<Exception>(), 32);
        assert_eq!(align_of::<Exception>(), 16);
        assert_eq!(offset_of!(Exception, exception_class), 0);
        assert_eq!(offset_of!(Exception, exception_cleanup), 8);
        assert_eq!(offset_of!(Exception, private_1), 16);
        assert_eq!(offset_of!(Exception, private_2), 24);
    }

    #[test]
    fn actions() {
        assert!(Actions::ALL.known());
        assert!(Actions::NONE.known());
        assert!(!Actions::new(32).known());
    }
}
