#![no_std]

//! Rust panic object transport for Desenredo.
//!
//! This crate is separate from the facade because panic payload ownership uses
//! `alloc`. The [`object`] module owns the `MOZ\0RUST` exception packet and its
//! payload transitions. The [`runtime`] module defines terminal hooks used when
//! unwinding cannot continue or a catch receives a foreign exception.
//!
//! The packet enters the language-neutral `_Unwind_*` protocol defined by the
//! [Itanium C++ ABI exception handling specification](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html).
//! Rust-specific packet layout and canary behavior intentionally follow rustc's
//! panic runtime rather than the C++ Level II object model.

extern crate alloc;

/// Panic packet ownership and unwind transfer.
pub mod object;

/// Terminal policy required by the panic packet runtime.
pub mod runtime;
