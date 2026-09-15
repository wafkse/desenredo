#![no_std]

//! Facade for the Desenredo exception and unwinding components.
//!
//! Each subsystem remains an independent crate with its own dependency boundary.
//! This crate provides one stable namespace for applications which intentionally
//! consume the complete Desenredo stack.

/// Itanium Level I ABI definitions.
pub use desenredo_abi as abi;
/// C++ Level II runtime and personality support.
pub use desenredo_cxx as cxx;
/// DWARF call-frame evaluation.
pub use desenredo_dwarf as dwarf;
/// Bounded language specific data parsing.
pub use desenredo_lsda as lsda;
/// Selects one concrete unwinder implementation for the final image ABI.
pub use desenredo_macro::unwind;
/// Rust panic object transport.
pub use desenredo_panic as panic;
/// Typed personality callback protocol.
pub use desenredo_personality as personality;
/// Rust language unwind policy.
pub use desenredo_rust as rust;
/// Desenredo physical stack unwinding.
pub use desenredo_unwind as unwind;
