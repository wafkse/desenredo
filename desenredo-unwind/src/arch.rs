//! Architecture-specific physical unwind mechanisms.
//!
//! Architecture modules own raw register transport, naked ABI entry points,
//! and control-transfer machinery. Generic traversal consumes their public
//! semantic state rather than sharing raw representation.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
