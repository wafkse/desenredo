//! Opaque C++ runtime type information.
//!
//! C++ runtimes expose pointers to `std::type_info` objects, but the Itanium ABI
//! does not require Rust code to depend on their concrete C++ object layout.
//! This module therefore carries only pointer identity and lifetime.

use core::{marker::PhantomData, ptr::NonNull};

/// Opaque storage representing one C++ `std::type_info` object.
#[repr(C)]
// NOTE(invariant): The private zero-sized field keeps the foreign std::type_info representation
// opaque to Rust.
pub struct TypeInfo {
    /// Prevents Rust code from constructing or inspecting the C++ representation.
    _private: [u8; 0],
}

/// Borrowed capability for one live C++ RTTI object.
#[derive(Copy, Clone)]
// NOTE(invariant): raw is nonnull and names one live TypeInfo object for the complete represented
// lifetime. Construction is unsafe because Rust cannot verify that lifetime or the foreign object
// identity.
pub struct TypeInfoRef<'a>(NonNull<TypeInfo>, PhantomData<&'a TypeInfo>);

impl<'a> TypeInfoRef<'a> {
    /// Creates an RTTI reference from a foreign runtime pointer.
    ///
    /// # Safety
    ///
    /// `raw` must point to a C++ `std::type_info` object whose storage remains
    /// alive and immutable for `'a`. The pointer must originate from the same
    /// C++ ABI domain that will consume the reference.
    #[inline]
    pub const unsafe fn new(raw: NonNull<TypeInfo>) -> Self {
        Self(raw, PhantomData)
    }

    /// Returns the underlying C++ RTTI pointer.
    #[inline]
    pub const fn ptr(self) -> *mut TypeInfo {
        let Self(raw, _) = self;

        raw.as_ptr()
    }
}
