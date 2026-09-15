//! Availability-aware register state used by DWARF reconstruction.

use gimli::{Register, X86_64};

use crate::{arch::x86_64::registers::Registers, error::UnwindError};

/// Semantic register state used by DWARF reconstruction.
#[derive(Clone)]
// NOTE(invariant): A Some value is available because the ABI, CFI, or personality
// established it. None means that using the register as an input is invalid. RSP
// and RA describe the current physical activation when available.
pub struct State {
    /// Availability and value for RAX.
    rax: Option<usize>,

    /// Availability and value for RDX.
    rdx: Option<usize>,

    /// Availability and value for RCX.
    rcx: Option<usize>,

    /// Availability and value for RBX.
    rbx: Option<usize>,

    /// Availability and value for RSI.
    rsi: Option<usize>,

    /// Availability and value for RDI.
    rdi: Option<usize>,

    /// Availability and value for RBP.
    rbp: Option<usize>,

    /// Availability and value for RSP.
    rsp: Option<usize>,

    /// Availability and value for R8.
    r8: Option<usize>,

    /// Availability and value for R9.
    r9: Option<usize>,

    /// Availability and value for R10.
    r10: Option<usize>,

    /// Availability and value for R11.
    r11: Option<usize>,

    /// Availability and value for R12.
    r12: Option<usize>,

    /// Availability and value for R13.
    r13: Option<usize>,

    /// Availability and value for R14.
    r14: Option<usize>,

    /// Availability and value for R15.
    r15: Option<usize>,

    /// Availability and value for the DWARF return-address pseudo register.
    ra: Option<usize>,

    /// Availability and value for MXCSR.
    mxcsr: Option<usize>,

    /// Availability and value for the x87 control word.
    fcw: Option<usize>,
}

impl State {
    /// Captures a semantic state rooted at the current ABI call boundary.
    #[inline(never)]
    pub fn capture() -> Self {
        Self::captured(Registers::capture())
    }

    /// Converts one ABI capture into semantic unwind state.
    ///
    /// Only values preserved by the SysV call boundary become available. The
    /// volatile general registers remain unavailable until CFI or personality
    /// code establishes them.
    #[inline]
    pub const fn captured(registers: Registers) -> Self {
        let Registers {
            rbx,
            rbp,
            rsp,
            r12,
            r13,
            r14,
            r15,
            ra,
            mxcsr,
            fcw,
            ..
        } = registers;

        Self {
            rax: None,
            rdx: None,
            rcx: None,
            rbx: Some(rbx),
            rsi: None,
            rdi: None,
            rbp: Some(rbp),
            rsp: Some(rsp),
            r8: None,
            r9: None,
            r10: None,
            r11: None,
            r12: Some(r12),
            r13: Some(r13),
            r14: Some(r14),
            r15: Some(r15),
            ra: Some(ra),
            mxcsr: Some(mxcsr),
            fcw: Some(fcw),
        }
    }

    /// Returns the storage width for one modeled DWARF register.
    #[inline]
    pub const fn width(register: Register) -> Result<u8, UnwindError> {
        match register {
            X86_64::RAX
            | X86_64::RDX
            | X86_64::RCX
            | X86_64::RBX
            | X86_64::RSI
            | X86_64::RDI
            | X86_64::RBP
            | X86_64::RSP
            | X86_64::R8
            | X86_64::R9
            | X86_64::R10
            | X86_64::R11
            | X86_64::R12
            | X86_64::R13
            | X86_64::R14
            | X86_64::R15
            | X86_64::RA => Ok(8),
            X86_64::MXCSR => Ok(4),
            X86_64::FCW => Ok(2),
            _ => Err(UnwindError::Register(register)),
        }
    }

    /// Reads one available DWARF register.
    #[inline]
    pub const fn read(&self, register: Register) -> Result<usize, UnwindError> {
        let &Self {
            ref rax,
            ref rdx,
            ref rcx,
            ref rbx,
            ref rsi,
            ref rdi,
            ref rbp,
            ref rsp,
            ref r8,
            ref r9,
            ref r10,
            ref r11,
            ref r12,
            ref r13,
            ref r14,
            ref r15,
            ref ra,
            ref mxcsr,
            ref fcw,
        } = self;

        let value = match register {
            X86_64::RAX => *rax,
            X86_64::RDX => *rdx,
            X86_64::RCX => *rcx,
            X86_64::RBX => *rbx,
            X86_64::RSI => *rsi,
            X86_64::RDI => *rdi,
            X86_64::RBP => *rbp,
            X86_64::RSP => *rsp,
            X86_64::R8 => *r8,
            X86_64::R9 => *r9,
            X86_64::R10 => *r10,
            X86_64::R11 => *r11,
            X86_64::R12 => *r12,
            X86_64::R13 => *r13,
            X86_64::R14 => *r14,
            X86_64::R15 => *r15,
            X86_64::RA => *ra,
            X86_64::MXCSR => *mxcsr,
            X86_64::FCW => *fcw,
            _ => return Err(UnwindError::Register(register)),
        };

        match value {
            Some(value) => Ok(value),
            None => Err(UnwindError::Unavailable(register)),
        }
    }

    /// Makes one modeled register available with `value`.
    #[inline]
    pub fn write(&mut self, register: Register, value: usize) -> Result<(), UnwindError> {
        let slot = Self::slot(self, register)?;

        *slot = Some(value);

        Ok(())
    }

    /// Marks one modeled register unavailable.
    #[inline]
    pub fn clear(&mut self, register: Register) -> Result<(), UnwindError> {
        let slot = Self::slot(self, register)?;

        *slot = None;

        Ok(())
    }

    /// Returns the current stack pointer when available.
    #[inline]
    pub const fn stack(&self) -> Result<usize, UnwindError> {
        Self::read(self, X86_64::RSP)
    }

    /// Returns the current instruction pointer image when available.
    #[inline]
    pub const fn ip(&self) -> Option<usize> {
        let &Self { ra, .. } = self;

        ra
    }

    /// Adjusts the current stack pointer by a DWARF argument size.
    #[inline]
    pub fn adjust(&mut self, size: usize) -> Result<(), UnwindError> {
        let rsp = Self::read(self, X86_64::RSP)?;

        Self::write(self, X86_64::RSP, rsp.wrapping_add(size))
    }

    /// Validates this state for landing-pad installation.
    #[inline]
    pub fn install(self) -> Result<Install, UnwindError> {
        let Self {
            rax,
            rdx,
            rcx,
            rbx,
            rsi,
            rdi,
            rbp,
            rsp,
            r8,
            r9,
            r10,
            r11,
            r12,
            r13,
            r14,
            r15,
            ra,
            mxcsr,
            fcw,
        } = self;

        match (rax, rdx, rbx, rbp, rsp, r12, r13, r14, r15, ra, mxcsr, fcw) {
            (
                Some(rax),
                Some(rdx),
                Some(rbx),
                Some(rbp),
                Some(rsp),
                Some(r12),
                Some(r13),
                Some(r14),
                Some(r15),
                Some(ra),
                Some(mxcsr),
                Some(fcw),
            ) => {
                let registers = Registers {
                    rax,
                    rdx,
                    rcx: rcx.unwrap_or_default(),
                    rbx,
                    rsi: rsi.unwrap_or_default(),
                    rdi: rdi.unwrap_or_default(),
                    rbp,
                    rsp,
                    r8: r8.unwrap_or_default(),
                    r9: r9.unwrap_or_default(),
                    r10: r10.unwrap_or_default(),
                    r11: r11.unwrap_or_default(),
                    r12,
                    r13,
                    r14,
                    r15,
                    ra,
                    mxcsr,
                    fcw,
                };

                Ok(Install { registers })
            },
            _ => Err(UnwindError::Install),
        }
    }

    /// Returns mutable access to one modeled register availability slot.
    const fn slot(&mut self, register: Register) -> Result<&mut Option<usize>, UnwindError> {
        let &mut Self {
            ref mut rax,
            ref mut rdx,
            ref mut rcx,
            ref mut rbx,
            ref mut rsi,
            ref mut rdi,
            ref mut rbp,
            ref mut rsp,
            ref mut r8,
            ref mut r9,
            ref mut r10,
            ref mut r11,
            ref mut r12,
            ref mut r13,
            ref mut r14,
            ref mut r15,
            ref mut ra,
            ref mut mxcsr,
            ref mut fcw,
        } = self;

        match register {
            X86_64::RAX => Ok(rax),
            X86_64::RDX => Ok(rdx),
            X86_64::RCX => Ok(rcx),
            X86_64::RBX => Ok(rbx),
            X86_64::RSI => Ok(rsi),
            X86_64::RDI => Ok(rdi),
            X86_64::RBP => Ok(rbp),
            X86_64::RSP => Ok(rsp),
            X86_64::R8 => Ok(r8),
            X86_64::R9 => Ok(r9),
            X86_64::R10 => Ok(r10),
            X86_64::R11 => Ok(r11),
            X86_64::R12 => Ok(r12),
            X86_64::R13 => Ok(r13),
            X86_64::R14 => Ok(r14),
            X86_64::R15 => Ok(r15),
            X86_64::RA => Ok(ra),
            X86_64::MXCSR => Ok(mxcsr),
            X86_64::FCW => Ok(fcw),
            _ => Err(UnwindError::Register(register)),
        }
    }
}

/// Validated landing-pad machine image.
// NOTE(invariant): The contained register image has available values for RAX,
// RDX, every SysV nonvolatile GPR, RSP, RA, MXCSR, and FCW. Construction occurs
// only through State::install.
pub struct Install {
    /// Raw machine image consumed by the transfer primitive.
    registers: Registers,
}

impl Install {
    /// Restores this validated image and transfers control to its landing pad.
    ///
    /// # Safety
    ///
    /// The stack pointer and return address must still name the live activation
    /// from which this install proof was derived.
    #[inline]
    pub unsafe fn restore(self) -> ! {
        let Self { registers } = self;

        // SAFETY:
        // Install construction proves the required register availability. The
        // caller contract proves the retained control transfer remains live.
        unsafe { Registers::jump(&registers) }
    }
}

#[cfg(test)]
mod tests {
    use gimli::X86_64;

    use super::State;
    use crate::{arch::x86_64::registers::Registers, error::UnwindError};

    #[test]
    fn volatile_capture_is_unavailable() {
        let state = State::captured(Registers::zeroed());

        assert!(matches!(
            state.read(X86_64::RAX),
            Err(UnwindError::Unavailable(X86_64::RAX))
        ));
        assert_eq!(state.read(X86_64::RBX).expect("RBX is ABI preserved"), 0);
    }

    #[test]
    fn explicit_undefined_clears_availability() {
        let mut state = State::captured(Registers::zeroed());

        state.clear(X86_64::RBX).expect("RBX is modeled");

        assert!(matches!(
            state.read(X86_64::RBX),
            Err(UnwindError::Unavailable(X86_64::RBX))
        ));
    }

    #[test]
    fn install_requires_landing_data() {
        let mut state = State::captured(Registers::zeroed());

        assert!(matches!(state.clone().install(), Err(UnwindError::Install)));

        state.write(X86_64::RAX, 0x1234_5678).expect("RAX is modeled");
        state.write(X86_64::RDX, 0x2345_6789).expect("RDX is modeled");

        assert!(state.install().is_ok());
    }

    #[test]
    fn widths() {
        assert_eq!(State::width(X86_64::RAX).expect("RAX width"), 8);
        assert_eq!(State::width(X86_64::RA).expect("RA width"), 8);
        assert_eq!(State::width(X86_64::MXCSR).expect("MXCSR width"), 4);
        assert_eq!(State::width(X86_64::FCW).expect("FCW width"), 2);
    }
}
