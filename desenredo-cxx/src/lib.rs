#![no_std]

//! C++ Itanium exception ABI support.
//!
//! Raw Level II symbols, RTTI identity, allocation ownership, and personality
//! policy remain separate public modules. Runtime-private exception header
//! layouts are intentionally not exposed.
//!
//! The primary provenance is the [Itanium C++ ABI exception handling
//! specification](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html).
//! Level II describes the interoperable C++ runtime surface including primary
//! exception allocation, throwing, catch entry, catch exit, and rethrow.
//! Desenredo intentionally does not treat incomplete Level III implementation
//! details as a stable cross-runtime representation.

/// Raw Itanium C++ Level II symbols.
pub mod abi;

/// C++ personality scanning and handler matching.
pub mod personality;

/// Opaque C++ RTTI references.
pub mod rtti;

/// C++ exception allocation ownership and throw transfer.
pub mod runtime;
