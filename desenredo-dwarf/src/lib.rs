#![no_std]

//! DWARF mechanisms used by system unwind implementations.
//!
//! The crate delegates call-frame instruction evaluation to `gimli` while
//! retaining caller-selected fixed storage for allocation-free use.
//!
//! The provenance for CIEs, FDEs, CFA rules, register recovery rules, and
//! call-frame instructions is [DWARF Version 5](https://dwarfstd.org/doc/DWARF5.pdf).
//! Section 6.4 describes call-frame information. GNU `.eh_frame` carries a
//! closely related runtime form of those rules.

/// `.eh_frame` call-frame evaluation.
pub mod cfi;
