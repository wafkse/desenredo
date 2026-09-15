//! x86_64 physical unwind mechanisms.
//!
//! This module follows the same raw transport versus semantic state split used
//! by Nekor's low-level architecture crates. Naked assembly operates only on
//! [`registers::Registers`]. DWARF reconstruction operates on [`state::State`].
//!
//! The preserved register set, control-state requirements, and stack discipline
//! come from the x86-64 System V ABI.

/// Level I ABI entry trampolines for x86_64.
pub mod entry;

/// Raw register transport used by naked assembly boundaries.
pub mod registers;

/// Availability-aware DWARF register state and landing installation.
pub mod state;
