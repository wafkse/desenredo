#![no_std]

//! Rust language policy for the Itanium unwind ABI.
//!
//! Compiler-generated landing pads own destructor execution. This crate
//! interprets rustc LSDA metadata and selects those landing pads without owning
//! panic payload allocation.
//!
//! Rust uses the language-neutral Level I protocol described by the [Itanium C++
//! ABI exception handling specification](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html).
//! The Rust-specific action interpretation follows rustc behavior while keeping
//! the underlying call-site and action-table parsing in `desenredo-lsda`.

/// Rust LSDA call-site classification.
pub mod action;

/// Rust panic exception class identity.
pub mod class;

/// Rust personality policy over bounded live LSDA bytes.
pub mod personality;
