//! Strong wrappers for unwind contexts and exception references.
//!
//! The wrappers carry callback lifetimes and phase capabilities without owning
//! storage. They do not require an allocator or a hosted C runtime.
//!
//! Constructors which establish callback provenance are public unsafe ABI
//! boundaries. Safe code can inspect validated capabilities but cannot manufacture
//! a callback lifetime or phase-two mutation token without satisfying those contracts.

use core::{ffi::c_int, marker::PhantomData, num::NonZeroUsize, ptr::NonNull};

use gimli::{Register, X86_64};

use crate::abi::{
    class::ExceptionClass,
    unwind::{self as raw, Context, Exception},
};

/// A borrowed exception header supplied by the unwinder.
#[derive(Copy, Clone)]
// NOTE(invariant): raw is nonnull and names the active exception header for all of 'a. The wrapper
// grants shared access only and never owns or releases the header.
pub struct ExceptionRef<'a>(NonNull<Exception>, PhantomData<&'a Exception>);

impl<'a> ExceptionRef<'a> {
    /// Creates a borrowed exception from a callback pointer.
    ///
    /// # Safety
    ///
    /// `raw` must be the exception pointer supplied by the active unwinder. The
    /// pointed-to header must remain live for all of `'a`, and no producer or
    /// unwinder operation may release the header while the returned reference
    /// exists. Construction does not transfer ownership.
    #[inline]
    pub const unsafe fn new(raw: NonNull<Exception>) -> Self {
        Self(raw, PhantomData)
    }

    /// Returns the exception class stored in the header.
    #[inline]
    pub const fn class(self) -> ExceptionClass {
        let Self(raw, _) = self;

        // SAFETY:
        // The ExceptionRef invariant guarantees raw is nonnull and the complete
        // Exception header remains live for the represented shared lifetime.
        // class reads only producer-owned header state and does not touch the
        // unwinder-private words.
        unsafe { raw.as_ref().class() }
    }

    /// Returns the raw exception pointer.
    #[inline]
    pub const fn ptr(self) -> *mut Exception {
        let Self(raw, _) = self;

        raw.as_ptr()
    }
}

/// The instruction pointer state reported by the unwinder.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
// NOTE(invariant): address and before_instruction are the paired instruction-pointer facts returned
// by one unwind context query.
pub struct InstructionPointer {
    /// The raw instruction pointer value.
    address: usize,

    /// Whether the pointer denotes the instruction itself.
    before_instruction: bool,
}

impl InstructionPointer {
    /// Returns the raw instruction pointer value.
    #[inline]
    pub const fn address(self) -> usize {
        let Self { address, .. } = self;

        address
    }

    /// Returns the address used for call-site table matching.
    #[inline]
    pub const fn site(self) -> usize {
        let Self {
            address,
            before_instruction,
        } = self;

        match (address, before_instruction) {
            (0, _) | (_, true) => address,
            (_, false) => address - 1,
        }
    }
}

/// A read-only view of one unwind frame.
// NOTE(invariant): raw is nonnull and names the system-owned context for all of 'a. Frame grants
// read-only ABI queries and does not permit context mutation.
pub struct Frame<'a>(NonNull<Context>, PhantomData<&'a Context>);

impl<'a> Frame<'a> {
    /// Creates a frame view from a callback context.
    ///
    /// # Safety
    ///
    /// `raw` must be the context pointer supplied for the active personality
    /// callback and must remain valid for all of `'a`. No operation may destroy
    /// or recycle the unwinder-owned context while the returned frame exists.
    #[inline]
    pub const unsafe fn new(raw: NonNull<Context>) -> Self {
        Self(raw, PhantomData)
    }

    /// Returns the current instruction pointer state.
    #[inline]
    pub fn ip(&self) -> InstructionPointer {
        let &Self(raw, _) = self;

        let mut before_instruction = 0;
        // SAFETY:
        // Frame proves raw is the live context from the active unwinder callback.
        // before_instruction is valid writable storage for the complete call and
        // no mutable Rust reference aliases the opaque context.
        let address = unsafe { raw::_Unwind_GetIPInfo(raw.as_ptr(), &mut before_instruction) };
        let before_instruction = before_instruction != 0;

        InstructionPointer {
            address,
            before_instruction,
        }
    }

    /// Returns the start address for the current code region.
    #[inline]
    pub fn start(&self) -> usize {
        let &Self(raw, _) = self;

        // SAFETY:
        // Frame proves raw remains the live system-owned context for this callback.
        // The query does not transfer ownership or expose context storage.
        unsafe { raw::_Unwind_GetRegionStart(raw.as_ptr()) }
    }

    /// Returns the text relative base.
    #[inline]
    pub fn text(&self) -> usize {
        let &Self(raw, _) = self;

        // SAFETY:
        // Frame proves raw remains the live system-owned context for this callback.
        // This method only invokes the ABI base query and retains no returned pointer.
        unsafe { raw::_Unwind_GetTextRelBase(raw.as_ptr()) }
    }

    /// Returns the data relative base.
    #[inline]
    pub fn data(&self) -> usize {
        let &Self(raw, _) = self;

        // SAFETY:
        // Frame proves raw remains the live system-owned context for this callback.
        // This method only invokes the ABI base query and retains no returned pointer.
        unsafe { raw::_Unwind_GetDataRelBase(raw.as_ptr()) }
    }

    /// Returns the canonical frame address.
    #[inline]
    pub fn cfa(&self) -> usize {
        let &Self(raw, _) = self;

        // SAFETY:
        // Frame proves raw remains the live system-owned context for this callback.
        // The canonical frame address is returned as an integer and is not dereferenced.
        unsafe { raw::_Unwind_GetCFA(raw.as_ptr()) }
    }

    /// Returns the language specific data pointer when one exists.
    #[inline]
    pub fn lsda(&self) -> Option<NonNull<u8>> {
        let &Self(raw, _) = self;

        // SAFETY:
        // Frame proves raw remains the live system-owned context for this callback.
        // The ABI returns only an image pointer here. No slice is created until an
        // unsafe Source implementation proves a complete readable range.
        let data = unsafe { raw::_Unwind_GetLanguageSpecificData(raw.as_ptr()) };

        NonNull::new(data.cast_mut())
    }
}

/// A validated landing pad address for this target ABI.
#[derive(Copy, Clone)]
// NOTE(invariant): address is nonzero and names executable landing-pad code emitted for the active
// target EH convention. Installation may transfer control to this address with the target EH data
// registers populated.
pub struct LandingPad(NonZeroUsize);

impl LandingPad {
    /// Creates a landing pad capability from an executable address.
    ///
    /// # Safety
    ///
    /// `address` must identify executable landing-pad code in the same live image
    /// as the active unwind frame. That code must accept the target Itanium EH
    /// data-register convention and remain executable until the unwinder installs
    /// the prepared context.
    #[inline]
    pub const unsafe fn new(address: NonZeroUsize) -> Self {
        Self(address)
    }

    /// Returns the executable landing pad address.
    #[inline]
    pub const fn address(self) -> usize {
        let Self(address) = self;

        address.get()
    }
}

/// The selector value passed to a C++ landing pad.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
// NOTE(invariant): The stored value is the exact signed selector delivered to the target landing
// pad.
pub struct Selector(isize);

impl Selector {
    /// Creates a selector from the personality scan result.
    #[inline]
    pub const fn new(value: isize) -> Self {
        Self(value)
    }

    /// Returns the raw selector value.
    #[inline]
    pub const fn raw(self) -> isize {
        let Self(value) = self;

        value
    }
}

/// Mutable context access available only during the cleanup phase.
// NOTE(invariant): raw is nonnull and names the active phase-two context for all of 'a. This value
// is the unique Rust capability permitted to mutate that context before installation.
pub struct CleanupFrame<'a>(NonNull<Context>, PhantomData<&'a mut Context>);

impl<'a> CleanupFrame<'a> {
    /// Creates cleanup-phase context access from a callback pointer.
    ///
    /// # Safety
    ///
    /// `raw` must be the live context supplied for a phase-two personality
    /// callback and must remain valid for all of `'a`. While the returned value
    /// exists, no other Rust value may hold a mutable capability for the same
    /// context. The system unwinder remains the storage owner.
    #[inline]
    pub const unsafe fn new(raw: NonNull<Context>) -> Self {
        Self(raw, PhantomData)
    }

    /// Borrows the context through the read-only frame API.
    #[inline]
    pub const fn frame(&self) -> Frame<'_> {
        let &Self(raw, _) = self;

        Frame(raw, PhantomData)
    }

    /// Installs the x86_64 Itanium landing-pad register state.
    ///
    /// The System V x86_64 unwind convention uses DWARF register `0`, physical
    /// `RAX`, for the active exception object and DWARF register `1`, physical
    /// `RDX`, for the language selector. The instruction pointer is replaced
    /// with the validated landing-pad address before the install proof is
    /// returned.
    #[inline]
    pub fn install(
        self,
        landing_pad: LandingPad,
        exception: ExceptionRef<'a>,
        selector: Selector,
    ) -> InstalledContext<'a> {
        let Self(raw, _) = self;

        let exception = exception.ptr().addr();
        let selector = selector.raw().cast_unsigned();
        let instruction_pointer = landing_pad.address();

        let Register(exception_register) = X86_64::RAX;

        let Register(selector_register) = X86_64::RDX;

        let exception_register = c_int::from(exception_register);
        let selector_register = c_int::from(selector_register);

        // SAFETY:
        // CleanupFrame is the unique mutation capability for the active phase-two
        // context. X86_64::RAX and X86_64::RDX are gimli's psABI DWARF register
        // definitions for the two x86_64 EH data registers. LandingPad proves the
        // replacement instruction pointer is nonzero and uses that convention.
        unsafe {
            raw::_Unwind_SetGR(raw.as_ptr(), exception_register, exception);
            raw::_Unwind_SetGR(raw.as_ptr(), selector_register, selector);
            raw::_Unwind_SetIP(raw.as_ptr(), instruction_pointer);
        }

        InstalledContext(PhantomData)
    }
}

/// Proof that a cleanup context is ready for installation.
// NOTE(invariant): the active phase-two context has already received the exception register,
// selector register, and landing-pad instruction pointer. Returning this proof permits only the ABI
// INSTALL result and carries the exclusive context lifetime until callback return.
pub struct InstalledContext<'a>(PhantomData<&'a mut Context>);

impl InstalledContext<'_> {
    /// Converts the proof into the ABI reason code.
    #[inline]
    pub const fn reason(self) -> raw::ReasonCode {
        let Self(_) = self;

        raw::ReasonCode::INSTALL
    }
}
