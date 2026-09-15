#![no_std]

//! Typed Itanium personality protocol and frame capabilities.
//!
//! Raw callbacks are validated once and converted into phase-specific values.
//! Language runtimes consume those values without reinterpreting raw unwind
//! pointers or action combinations.
//!
//! Personality callback arguments, the phase-one search, the phase-two cleanup,
//! landing-pad installation, and `_Unwind_SetGR` or `_Unwind_SetIP` behavior are
//! specified by the [Itanium C++ ABI exception handling
//! specification](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html).

/// ABI types used by exported personality shims.
pub use desenredo_abi as abi;

/// Borrowed unwind frame and landing-pad capabilities.
pub mod context;

/// Personality callback validation and phase dispatch.
pub mod protocol;

/// Bounded live LSDA source capability.
pub mod source;
