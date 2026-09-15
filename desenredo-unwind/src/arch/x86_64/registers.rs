#![expect(
    clippy::missing_inline_in_public_items,
    reason = "public naked register transfers cannot carry inline attributes"
)]

//! Raw x86_64 register transport used by naked assembly boundaries.

use core::mem::{offset_of, size_of};

/// Raw x86_64 register image used at assembly boundaries.
///
/// This type is an ABI transport rather than a semantic unwind state. Volatile
/// fields may contain arbitrary scratch values unless another operation gives
/// them meaning. Field order follows the modeled DWARF register image. Naked
/// assembly derives every field displacement through `offset_of!`, making this
/// Rust representation the source of layout truth.
#[repr(C)]
#[derive(Clone)]
pub struct Registers {
    /// General register RAX.
    pub rax: usize,

    /// General register RDX.
    pub rdx: usize,

    /// General register RCX.
    pub rcx: usize,

    /// General register RBX.
    pub rbx: usize,

    /// General register RSI.
    pub rsi: usize,

    /// General register RDI.
    pub rdi: usize,

    /// General register RBP.
    pub rbp: usize,

    /// Stack pointer RSP.
    pub rsp: usize,

    /// General register R8.
    pub r8: usize,

    /// General register R9.
    pub r9: usize,

    /// General register R10.
    pub r10: usize,

    /// General register R11.
    pub r11: usize,

    /// General register R12.
    pub r12: usize,

    /// General register R13.
    pub r13: usize,

    /// General register R14.
    pub r14: usize,

    /// General register R15.
    pub r15: usize,

    /// DWARF pseudo register RA.
    pub ra: usize,

    /// MXCSR control state in the low 32 bits.
    pub mxcsr: usize,

    /// x87 control word in the low 16 bits.
    pub fcw: usize,
}

impl Registers {
    /// Moves one initialized raw register image out of caller-owned storage.
    ///
    /// # Safety
    ///
    /// `registers` must point to one live initialized `Registers` value. The
    /// pointed-to value must not be read again after this operation.
    #[inline]
    pub const unsafe fn take(registers: *const Self) -> Self {
        // SAFETY:
        // The method contract proves one initialized live value and single consumption.
        unsafe { registers.read() }
    }

    /// Captures the ABI-preserved state of the caller of this function.
    ///
    /// Volatile registers in the returned transport have no semantic meaning.
    #[inline(never)]
    pub fn capture() -> Self {
        let mut registers = Self::zeroed();

        // SAFETY:
        // registers names writable storage with the exact repr(C) layout used
        // by the naked capture primitive.
        unsafe { Self::save(&mut registers) };

        registers
    }

    /// Returns an all-zero transport used as writable capture storage.
    #[inline]
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            rax: 0,
            rdx: 0,
            rcx: 0,
            rbx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            ra: 0,
            mxcsr: 0,
            fcw: 0,
        }
    }

    /// Captures one Level I ABI caller before a Rust frame exists.
    ///
    /// # Safety
    ///
    /// `output` must point to writable aligned [`Registers`] storage. `stack`
    /// must be the exact stack pointer observed at entry to the Level I ABI
    /// function and its top native word must be the live return address.
    #[unsafe(naked)]
    pub unsafe extern "C" fn entry(_output: *mut Self, _stack: *const usize) {
        core::arch::naked_asm!(
            "movq $0, {rax}(%rdi)",
            "movq $0, {rdx}(%rdi)",
            "movq $0, {rcx}(%rdi)",
            "movq $0, {rsi}(%rdi)",
            "movq $0, {rdi_slot}(%rdi)",
            "movq $0, {r8}(%rdi)",
            "movq $0, {r9}(%rdi)",
            "movq $0, {r10}(%rdi)",
            "movq $0, {r11}(%rdi)",
            "movq %rbx, {rbx}(%rdi)",
            "movq %rbp, {rbp}(%rdi)",
            "movq %r12, {r12}(%rdi)",
            "movq %r13, {r13}(%rdi)",
            "movq %r14, {r14}(%rdi)",
            "movq %r15, {r15}(%rdi)",
            "leaq {word}(%rsi), %rax",
            "movq %rax, {rsp}(%rdi)",
            "movq (%rsi), %rax",
            "movq %rax, {ra}(%rdi)",
            "movq $0, {mxcsr}(%rdi)",
            "movq $0, {fcw}(%rdi)",
            "stmxcsr {mxcsr}(%rdi)",
            "fnstcw {fcw}(%rdi)",
            "retq",
            rax = const offset_of!(Registers, rax),
            rdx = const offset_of!(Registers, rdx),
            rcx = const offset_of!(Registers, rcx),
            rbx = const offset_of!(Registers, rbx),
            rsi = const offset_of!(Registers, rsi),
            rdi_slot = const offset_of!(Registers, rdi),
            rbp = const offset_of!(Registers, rbp),
            rsp = const offset_of!(Registers, rsp),
            r8 = const offset_of!(Registers, r8),
            r9 = const offset_of!(Registers, r9),
            r10 = const offset_of!(Registers, r10),
            r11 = const offset_of!(Registers, r11),
            r12 = const offset_of!(Registers, r12),
            r13 = const offset_of!(Registers, r13),
            r14 = const offset_of!(Registers, r14),
            r15 = const offset_of!(Registers, r15),
            ra = const offset_of!(Registers, ra),
            mxcsr = const offset_of!(Registers, mxcsr),
            fcw = const offset_of!(Registers, fcw),
            word = const size_of::<usize>(),
            options(att_syntax),
        );
    }

    /// Saves the ABI-preserved caller state into one register transport.
    ///
    /// # Safety
    ///
    /// `registers` must point to one live writable [`Registers`] value.
    #[unsafe(naked)]
    unsafe extern "C" fn save(_registers: *mut Self) {
        core::arch::naked_asm!(
            "movq %rbx, {rbx}(%rdi)",
            "movq %rbp, {rbp}(%rdi)",
            "movq %r12, {r12}(%rdi)",
            "movq %r13, {r13}(%rdi)",
            "movq %r14, {r14}(%rdi)",
            "movq %r15, {r15}(%rdi)",
            "leaq {word}(%rsp), %rax",
            "movq %rax, {rsp}(%rdi)",
            "movq (%rsp), %rax",
            "movq %rax, {ra}(%rdi)",
            "stmxcsr {mxcsr}(%rdi)",
            "fnstcw {fcw}(%rdi)",
            "retq",
            rbx = const offset_of!(Registers, rbx),
            rbp = const offset_of!(Registers, rbp),
            rsp = const offset_of!(Registers, rsp),
            r12 = const offset_of!(Registers, r12),
            r13 = const offset_of!(Registers, r13),
            r14 = const offset_of!(Registers, r14),
            r15 = const offset_of!(Registers, r15),
            ra = const offset_of!(Registers, ra),
            mxcsr = const offset_of!(Registers, mxcsr),
            fcw = const offset_of!(Registers, fcw),
            word = const size_of::<usize>(),
            options(att_syntax),
        );
    }

    /// Installs this raw transport and never returns.
    ///
    /// # Safety
    ///
    /// The nonvolatile registers, RSP, RA, MXCSR, and FCW must describe one live
    /// activation. RAX and RDX must contain the landing-pad data selected by the
    /// active personality.
    #[unsafe(naked)]
    pub unsafe extern "C" fn jump(_registers: *const Self) -> ! {
        core::arch::naked_asm!(
            "movq {rsp}(%rdi), %rsp",
            "ldmxcsr {mxcsr}(%rdi)",
            "fldcw {fcw}(%rdi)",
            "movq {ra}(%rdi), %rax",
            "pushq %rax",
            "movq {rax}(%rdi), %rax",
            "movq {rdx}(%rdi), %rdx",
            "movq {rcx}(%rdi), %rcx",
            "movq {rbx}(%rdi), %rbx",
            "movq {rsi}(%rdi), %rsi",
            "movq {rbp}(%rdi), %rbp",
            "movq {r8}(%rdi), %r8",
            "movq {r9}(%rdi), %r9",
            "movq {r10}(%rdi), %r10",
            "movq {r11}(%rdi), %r11",
            "movq {r12}(%rdi), %r12",
            "movq {r13}(%rdi), %r13",
            "movq {r14}(%rdi), %r14",
            "movq {r15}(%rdi), %r15",
            "movq {rdi_slot}(%rdi), %rdi",
            "cld",
            "retq",
            rax = const offset_of!(Registers, rax),
            rdx = const offset_of!(Registers, rdx),
            rcx = const offset_of!(Registers, rcx),
            rbx = const offset_of!(Registers, rbx),
            rsi = const offset_of!(Registers, rsi),
            rdi_slot = const offset_of!(Registers, rdi),
            rbp = const offset_of!(Registers, rbp),
            rsp = const offset_of!(Registers, rsp),
            r8 = const offset_of!(Registers, r8),
            r9 = const offset_of!(Registers, r9),
            r10 = const offset_of!(Registers, r10),
            r11 = const offset_of!(Registers, r11),
            r12 = const offset_of!(Registers, r12),
            r13 = const offset_of!(Registers, r13),
            r14 = const offset_of!(Registers, r14),
            r15 = const offset_of!(Registers, r15),
            ra = const offset_of!(Registers, ra),
            mxcsr = const offset_of!(Registers, mxcsr),
            fcw = const offset_of!(Registers, fcw),
            options(att_syntax),
        );
    }
}

#[cfg(test)]
mod tests {
    use core::mem::{offset_of, size_of};

    use super::Registers;

    /// Sentinel installed in RBX by the machine probes.
    const RBX: usize = 0x1111_1111;

    /// Sentinel installed in RBP by the machine probes.
    const RBP: usize = 0x2222_2222;

    /// Sentinel installed in R12 by the machine probes.
    const R12: usize = 0x3333_3333;

    /// Sentinel installed in R13 by the machine probes.
    const R13: usize = 0x4444_4444;

    /// Sentinel installed in R14 by the machine probes.
    const R14: usize = 0x5555_5555;

    /// Sentinel installed in R15 by the machine probes.
    const R15: usize = 0x6666_6666;

    /// Sentinel installed in landing-pad RAX.
    const RAX: usize = 0x1234_5678;

    /// Sentinel installed in landing-pad RDX.
    const RDX: usize = 0x2345_6789;

    /// Synthetic return address consumed by the ABI entry capture probe.
    const ENTRY_MARKER: usize = 0x3456_789a;

    /// Native stack word width used by probe frame layouts.
    const WORD: usize = size_of::<usize>();

    /// First saved caller register after the raw transport.
    const SAVED_RBX: usize = size_of::<Registers>();

    /// Saved caller RBP slot.
    const SAVED_RBP: usize = SAVED_RBX + WORD;

    /// Saved caller R12 slot.
    const SAVED_R12: usize = SAVED_RBP + WORD;

    /// Saved caller R13 slot.
    const SAVED_R13: usize = SAVED_R12 + WORD;

    /// Saved caller R14 slot.
    const SAVED_R14: usize = SAVED_R13 + WORD;

    /// Saved caller R15 slot.
    const SAVED_R15: usize = SAVED_R14 + WORD;

    /// Saved caller stack pointer slot.
    const SAVED_RSP: usize = SAVED_R15 + WORD;

    /// Scratch return slot consumed by the synthetic landing transfer.
    const LANDING_SLOT: usize = SAVED_RSP + WORD;

    /// Stack pointer observed after the synthetic landing return.
    const TARGET_RSP: usize = LANDING_SLOT + WORD;

    /// Complete restore probe frame size.
    const RESTORE_FRAME: usize = TARGET_RSP + WORD;

    /// Calls the raw capture primitive with nonvolatile sentinels.
    #[unsafe(naked)]
    unsafe extern "C" fn probe_capture() -> usize {
        core::arch::naked_asm!(
            "pushq %rbx",
            "pushq %rbp",
            "pushq %r12",
            "pushq %r13",
            "pushq %r14",
            "pushq %r15",
            "subq ${registers}, %rsp",
            "movq ${rbx_value}, %rbx",
            "movq ${rbp_value}, %rbp",
            "movq ${r12_value}, %r12",
            "movq ${r13_value}, %r13",
            "movq ${r14_value}, %r14",
            "movq ${r15_value}, %r15",
            "movq %rsp, %rdi",
            "callq {capture}",
            ".Lcapture_return:",
            "cmpq ${rbx_value}, %rbx",
            "jne .Lcapture_fail",
            "cmpq ${rbp_value}, %rbp",
            "jne .Lcapture_fail",
            "cmpq ${r12_value}, %r12",
            "jne .Lcapture_fail",
            "cmpq ${r13_value}, %r13",
            "jne .Lcapture_fail",
            "cmpq ${r14_value}, %r14",
            "jne .Lcapture_fail",
            "cmpq ${r15_value}, %r15",
            "jne .Lcapture_fail",
            "cmpq ${rbx_value}, {rbx}(%rsp)",
            "jne .Lcapture_fail",
            "cmpq ${rbp_value}, {rbp}(%rsp)",
            "jne .Lcapture_fail",
            "cmpq ${r12_value}, {r12}(%rsp)",
            "jne .Lcapture_fail",
            "cmpq ${r13_value}, {r13}(%rsp)",
            "jne .Lcapture_fail",
            "cmpq ${r14_value}, {r14}(%rsp)",
            "jne .Lcapture_fail",
            "cmpq ${r15_value}, {r15}(%rsp)",
            "jne .Lcapture_fail",
            "cmpq %rsp, {rsp}(%rsp)",
            "jne .Lcapture_fail",
            "leaq .Lcapture_return(%rip), %rdx",
            "cmpq %rdx, {ra}(%rsp)",
            "jne .Lcapture_fail",
            "movl $1, %eax",
            "jmp .Lcapture_done",
            ".Lcapture_fail:",
            "xorl %eax, %eax",
            ".Lcapture_done:",
            "addq ${registers}, %rsp",
            "popq %r15",
            "popq %r14",
            "popq %r13",
            "popq %r12",
            "popq %rbp",
            "popq %rbx",
            "retq",
            registers = const size_of::<Registers>(),
            rbx = const offset_of!(Registers, rbx),
            rbp = const offset_of!(Registers, rbp),
            rsp = const offset_of!(Registers, rsp),
            r12 = const offset_of!(Registers, r12),
            r13 = const offset_of!(Registers, r13),
            r14 = const offset_of!(Registers, r14),
            r15 = const offset_of!(Registers, r15),
            ra = const offset_of!(Registers, ra),
            rbx_value = const RBX,
            rbp_value = const RBP,
            r12_value = const R12,
            r13_value = const R13,
            r14_value = const R14,
            r15_value = const R15,
            capture = sym Registers::save,
            options(att_syntax),
        );
    }

    /// Calls the raw ABI entry capture with nonvolatile sentinels.
    #[unsafe(naked)]
    unsafe extern "C" fn probe_entry() -> usize {
        core::arch::naked_asm!(
            "pushq %rbx",
            "pushq %rbp",
            "pushq %r12",
            "pushq %r13",
            "pushq %r14",
            "pushq %r15",
            "subq ${frame}, %rsp",
            "movq ${marker}, {registers}(%rsp)",
            "movq ${rbx_value}, %rbx",
            "movq ${rbp_value}, %rbp",
            "movq ${r12_value}, %r12",
            "movq ${r13_value}, %r13",
            "movq ${r14_value}, %r14",
            "movq ${r15_value}, %r15",
            "leaq {registers}(%rsp), %rsi",
            "movq %rsp, %rdi",
            "callq {capture}",
            "cmpq ${rbx_value}, %rbx",
            "jne .Lentry_fail",
            "cmpq ${rbp_value}, %rbp",
            "jne .Lentry_fail",
            "cmpq ${r12_value}, %r12",
            "jne .Lentry_fail",
            "cmpq ${r13_value}, %r13",
            "jne .Lentry_fail",
            "cmpq ${r14_value}, %r14",
            "jne .Lentry_fail",
            "cmpq ${r15_value}, %r15",
            "jne .Lentry_fail",
            "cmpq ${rbx_value}, {rbx}(%rsp)",
            "jne .Lentry_fail",
            "cmpq ${rbp_value}, {rbp}(%rsp)",
            "jne .Lentry_fail",
            "cmpq ${r12_value}, {r12}(%rsp)",
            "jne .Lentry_fail",
            "cmpq ${r13_value}, {r13}(%rsp)",
            "jne .Lentry_fail",
            "cmpq ${r14_value}, {r14}(%rsp)",
            "jne .Lentry_fail",
            "cmpq ${r15_value}, {r15}(%rsp)",
            "jne .Lentry_fail",
            "leaq {frame}(%rsp), %rdx",
            "cmpq %rdx, {rsp}(%rsp)",
            "jne .Lentry_fail",
            "cmpq ${marker}, {ra}(%rsp)",
            "jne .Lentry_fail",
            "movl $1, %eax",
            "jmp .Lentry_done",
            ".Lentry_fail:",
            "xorl %eax, %eax",
            ".Lentry_done:",
            "addq ${frame}, %rsp",
            "popq %r15",
            "popq %r14",
            "popq %r13",
            "popq %r12",
            "popq %rbp",
            "popq %rbx",
            "retq",
            frame = const size_of::<Registers>() + WORD,
            registers = const size_of::<Registers>(),
            rbx = const offset_of!(Registers, rbx),
            rbp = const offset_of!(Registers, rbp),
            rsp = const offset_of!(Registers, rsp),
            r12 = const offset_of!(Registers, r12),
            r13 = const offset_of!(Registers, r13),
            r14 = const offset_of!(Registers, r14),
            r15 = const offset_of!(Registers, r15),
            ra = const offset_of!(Registers, ra),
            marker = const ENTRY_MARKER,
            rbx_value = const RBX,
            rbp_value = const RBP,
            r12_value = const R12,
            r13_value = const R13,
            r14_value = const R14,
            r15_value = const R15,
            capture = sym Registers::entry,
            options(att_syntax),
        );
    }

    /// Installs a raw transport and verifies the landing values.
    #[unsafe(naked)]
    unsafe extern "C" fn probe_restore() -> usize {
        core::arch::naked_asm!(
            "subq ${frame}, %rsp",
            "movq %rbx, {saved_rbx}(%rsp)",
            "movq %rbp, {saved_rbp}(%rsp)",
            "movq %r12, {saved_r12}(%rsp)",
            "movq %r13, {saved_r13}(%rsp)",
            "movq %r14, {saved_r14}(%rsp)",
            "movq %r15, {saved_r15}(%rsp)",
            "leaq {frame}(%rsp), %rax",
            "movq %rax, {saved_rsp}(%rsp)",
            "cld",
            "movq %rsp, %rdi",
            "xorl %eax, %eax",
            "movl ${register_words}, %ecx",
            "rep stosq",
            "movq ${rax_value}, {rax}(%rsp)",
            "movq ${rdx_value}, {rdx}(%rsp)",
            "movq ${rbx_value}, {rbx}(%rsp)",
            "movq ${rbp_value}, {rbp}(%rsp)",
            "movq ${r12_value}, {r12}(%rsp)",
            "movq ${r13_value}, {r13}(%rsp)",
            "movq ${r14_value}, {r14}(%rsp)",
            "movq ${r15_value}, {r15}(%rsp)",
            "movq %rsp, {r11}(%rsp)",
            "leaq {target_rsp}(%rsp), %rax",
            "movq %rax, {rsp}(%rsp)",
            "leaq .Lrestore_landing(%rip), %rax",
            "movq %rax, {ra}(%rsp)",
            "stmxcsr {mxcsr}(%rsp)",
            "fnstcw {fcw}(%rsp)",
            "movq %rsp, %rdi",
            "jmp {restore}",
            ".Lrestore_landing:",
            "pushfq",
            "popq %rcx",
            "testq $0x400, %rcx",
            "jne .Lrestore_fail",
            "cmpq ${rax_value}, %rax",
            "jne .Lrestore_fail",
            "cmpq ${rdx_value}, %rdx",
            "jne .Lrestore_fail",
            "cmpq ${rbx_value}, %rbx",
            "jne .Lrestore_fail",
            "cmpq ${rbp_value}, %rbp",
            "jne .Lrestore_fail",
            "cmpq ${r12_value}, %r12",
            "jne .Lrestore_fail",
            "cmpq ${r13_value}, %r13",
            "jne .Lrestore_fail",
            "cmpq ${r14_value}, %r14",
            "jne .Lrestore_fail",
            "cmpq ${r15_value}, %r15",
            "jne .Lrestore_fail",
            "leaq {target_rsp}(%r11), %rcx",
            "cmpq %rcx, %rsp",
            "jne .Lrestore_fail",
            "movl $1, %eax",
            "jmp .Lrestore_done",
            ".Lrestore_fail:",
            "xorl %eax, %eax",
            ".Lrestore_done:",
            "movq {saved_rbx}(%r11), %rbx",
            "movq {saved_rbp}(%r11), %rbp",
            "movq {saved_r12}(%r11), %r12",
            "movq {saved_r13}(%r11), %r13",
            "movq {saved_r14}(%r11), %r14",
            "movq {saved_r15}(%r11), %r15",
            "movq {saved_rsp}(%r11), %rsp",
            "retq",
            frame = const RESTORE_FRAME,
            register_words = const size_of::<Registers>() / WORD,
            target_rsp = const TARGET_RSP,
            saved_rbx = const SAVED_RBX,
            saved_rbp = const SAVED_RBP,
            saved_r12 = const SAVED_R12,
            saved_r13 = const SAVED_R13,
            saved_r14 = const SAVED_R14,
            saved_r15 = const SAVED_R15,
            saved_rsp = const SAVED_RSP,
            rax = const offset_of!(Registers, rax),
            rdx = const offset_of!(Registers, rdx),
            rbx = const offset_of!(Registers, rbx),
            rbp = const offset_of!(Registers, rbp),
            rsp = const offset_of!(Registers, rsp),
            r11 = const offset_of!(Registers, r11),
            r12 = const offset_of!(Registers, r12),
            r13 = const offset_of!(Registers, r13),
            r14 = const offset_of!(Registers, r14),
            r15 = const offset_of!(Registers, r15),
            ra = const offset_of!(Registers, ra),
            mxcsr = const offset_of!(Registers, mxcsr),
            fcw = const offset_of!(Registers, fcw),
            rax_value = const RAX,
            rdx_value = const RDX,
            rbx_value = const RBX,
            rbp_value = const RBP,
            r12_value = const R12,
            r13_value = const R13,
            r14_value = const R14,
            r15_value = const R15,
            restore = sym Registers::jump,
            options(att_syntax),
        );
    }

    #[test]
    fn capture_preserves_sysv_state() {
        // SAFETY:
        // The probe allocates a complete Registers transport and restores its
        // own caller state before returning.
        let preserved = unsafe { probe_capture() };

        assert_eq!(preserved, 1);
    }

    #[test]
    fn entry_capture_preserves_sysv_state() {
        // SAFETY:
        // The probe supplies writable Registers storage and one readable
        // synthetic ABI return-address word.
        let preserved = unsafe { probe_entry() };

        assert_eq!(preserved, 1);
    }

    #[test]
    fn restore_installs_selected_state() {
        // SAFETY:
        // The probe materializes a complete raw transport and valid synthetic
        // landing stack before invoking the transfer primitive.
        let restored = unsafe { probe_restore() };

        assert_eq!(restored, 1);
    }
}
