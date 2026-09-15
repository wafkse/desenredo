#![no_std]

//! Itanium Level I exception handling ABI definitions.
//!
//! The crate preserves the raw ABI value space while separating exception class
//! identity from the language-neutral unwind interface. It has no allocator or
//! operating-system dependency.
//!
//! The normative provenance for `_Unwind_*`, `_Unwind_Exception`,
//! `_Unwind_Context`, reason codes, action bits, and personality callbacks is the
//! [Itanium C++ ABI exception handling specification](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html).
//! Level I of that document is language neutral even though the document belongs
//! to the C++ ABI family.

#[cfg(not(all(target_arch = "x86_64", target_pointer_width = "64", not(target_os = "windows"),)))]
compile_error!("the validated unwind layout currently supports non-Windows x86_64 targets only");

/// Exception producer and language identity.
pub mod class;

/// Language-neutral Level I unwind types and symbols.
pub mod unwind;
