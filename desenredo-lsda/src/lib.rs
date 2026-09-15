#![no_std]

//! Allocation-free parsing for bounded Itanium language specific data areas.
//!
//! The parser consumes caller-bounded slices through `nom` with default features
//! disabled. Encoded address policy and table semantics remain separate public
//! modules so language personalities can depend on the concepts they use.
//!
//! The surrounding two-phase personality protocol comes from the [Itanium C++
//! ABI exception handling specification](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html).
//! LEB128 is defined by DWARF. The `DW_EH_PE_*` pointer encodings used by GNU
//! exception tables are platform extensions documented by the [Linux Standard
//! Base DWARF extensions](https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html).
//! They are not part of core DWARF call-frame information.

/// Address bases and encoded-pointer results.
pub mod encoding;

/// Structural LSDA decoding failures.
pub mod error;

/// GCC-style call-site, action, filter, and RTTI tables.
pub mod table;
