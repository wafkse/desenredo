#![no_std]

//! Desenredo physical stack unwinding.
//!
//! This crate owns machine context capture, DWARF frame reconstruction, physical
//! stack traversal, and the Level I operations used by final image ABI adapters.
//! Language personality policy remains in separate crates.
//!
//! ```text
//! compiler `_Unwind_*` symbol
//!            |
//!            v
//! `arch::x86_64::entry`
//!            |
//!            v
//! `registers::Registers`
//!       raw ABI image
//!            |
//!            v
//!    `state::State`
//!  availability proof
//!            |
//!            v
//!       `Cursor<U>`
//!            |
//!      +-----+-----+
//!      |           |
//!      v           v
//!  `Image` CFI   `U::read`
//!      |           |
//!      +-----+-----+
//!            |
//!            v
//!      caller `State`
//!            |
//!            v
//! personality callback or validated `Install`
//! ```
//!
//! The Level I traversal and callback contract comes from the [Itanium C++ ABI
//! exception handling specification](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html).
//! Caller reconstruction uses the CIE, FDE, CFA, register-rule, and expression
//! model from [DWARF Version 5](https://dwarfstd.org/doc/DWARF5.pdf), especially
//! section 6.4. GNU `.eh_frame` is the runtime representation consumed here.

#[cfg(not(all(target_arch = "x86_64", target_pointer_width = "64", not(target_os = "windows"),)))]
compile_error!("the native unwinder currently supports non-Windows x86_64 targets only");

/// Architecture-specific physical unwind mechanisms.
pub mod arch;

/// Compiler Level I runtime adapter and unwinder policy.
pub mod runtime;

/// Physical stack cursor.
pub mod cursor;

/// Structured physical unwind failures.
pub mod error;

/// Instruction-pointer relation used by frame lookup.
pub mod relation;

/// Bounded unwind images and resolved frame metadata.
pub mod source;
