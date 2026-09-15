//! Ownership-safe access to primary C++ exception storage.
//!
//! [`crate::runtime::Allocation`] binds one raw object buffer to the runtime that allocated it.
//! Dropping the value releases that buffer through the same runtime. Calling
//! [`crate::runtime::Allocation::throw`] consumes the owner and transfers storage to C++.

use core::{ffi::c_void, hint::unreachable_unchecked, marker::PhantomData, mem::ManuallyDrop, ptr::NonNull};

use super::{
    abi::{__cxa_allocate_exception, __cxa_free_exception, __cxa_throw, Destructor},
    rtti::TypeInfoRef,
};

/// Runtime capability that owns C++ exception allocation and propagation.
///
/// # Safety
///
/// One implementation must describe one coherent C++ exception runtime. A
/// pointer returned by `alloc` must remain valid until that same implementation
/// receives it through `free` or `throw`. `free` must accept each owned pointer
/// at most once. `throw` must take ownership of the pointer, must interpret the
/// supplied RTTI and destructor consistently with the initialized object, and
/// must not return normally after ownership transfer.
pub unsafe trait ExceptionRuntime {
    /// Allocates storage for one primary thrown object.
    ///
    /// # Safety
    ///
    /// The returned pointer must satisfy this trait's ownership and lifetime
    /// contract and must be suitably aligned for any object the requested size
    /// can represent under the selected C++ runtime.
    unsafe fn alloc(size: usize) -> NonNull<c_void>;

    /// Releases one still-owned primary exception allocation.
    ///
    /// # Safety
    ///
    /// `exception` must be a live pointer produced by this exact runtime
    /// implementation and must not already have been freed or thrown.
    unsafe fn free(exception: NonNull<c_void>);

    /// Transfers one initialized object to the exception runtime and throws it.
    ///
    /// # Safety
    ///
    /// `exception` must be live storage from this exact runtime and contain a
    /// fully initialized C++ object described by `type_info`. `destructor`, when
    /// present, must accept that object pointer using the linked ABI.
    unsafe fn throw(exception: NonNull<c_void>, type_info: TypeInfoRef<'_>, destructor: Option<Destructor>) -> !;
}

/// Runtime backed by the C++ Level II symbols linked into the final image.
#[derive(Debug, Copy, Clone)]
pub struct LinkedRuntime;

// SAFETY:
// This implementation delegates every transition to one set of linked Level II
// symbols. The trait caller still proves that allocations, RTTI, and destructors
// belong to that same runtime domain.
unsafe impl ExceptionRuntime for LinkedRuntime {
    #[inline]
    unsafe fn alloc(size: usize) -> NonNull<c_void> {
        // SAFETY:
        // The ABI allocator accepts an object byte size and returns storage owned
        // by the linked C++ runtime. The Itanium contract terminates rather than
        // reporting allocation failure through a null pointer.
        let raw = unsafe { __cxa_allocate_exception(size) };

        // SAFETY:
        // The Level II allocation contract above guarantees a nonnull result on
        // normal return.
        unsafe { NonNull::new_unchecked(raw) }
    }

    #[inline]
    unsafe fn free(exception: NonNull<c_void>) {
        // SAFETY:
        // The ExceptionRuntime caller proves this pointer is a live allocation
        // produced by this same LinkedRuntime and has not transferred to throw.
        unsafe { __cxa_free_exception(exception.as_ptr()) };
    }

    #[inline]
    unsafe fn throw(exception: NonNull<c_void>, type_info: TypeInfoRef<'_>, destructor: Option<Destructor>) -> ! {
        // SAFETY:
        // The trait caller proves the allocation, initialized object, RTTI, and
        // optional destructor all belong to the linked C++ runtime. The Level II
        // ABI transfers ownership and does not return normally.
        unsafe {
            __cxa_throw(exception.as_ptr(), type_info.ptr(), destructor);
            unreachable_unchecked()
        }
    }
}

/// Owned primary-object storage allocated by one C++ exception runtime.
// NOTE(invariant): raw is one live allocation owned by R. Allocation is the unique Rust owner and
// Drop frees raw exactly once unless throw consumes the owner and transfers raw to R.
pub struct Allocation<R: ExceptionRuntime>(NonNull<c_void>, PhantomData<R>);

impl<R: ExceptionRuntime> Allocation<R> {
    /// Allocates storage for one future thrown object.
    #[inline]
    pub fn new(size: usize) -> Self {
        // SAFETY:
        // The unsafe runtime trait guarantees that a normal return produces one
        // live allocation which this newly constructed owner may hold uniquely.
        let raw = unsafe { R::alloc(size) };

        Self(raw, PhantomData)
    }

    /// Returns the object storage pointer without transferring ownership.
    #[inline]
    pub const fn ptr(&self) -> *mut c_void {
        let &Self(raw, _) = self;

        raw.as_ptr()
    }

    /// Transfers the initialized object to the selected runtime and throws it.
    ///
    /// # Safety
    ///
    /// The allocation must contain a fully initialized C++ object described by
    /// `type_info`. `destructor`, when present, must be valid for that exact
    /// object. After this call begins, callers must not retain references that
    /// assume Rust still owns the allocation.
    #[inline]
    pub unsafe fn throw(self, type_info: TypeInfoRef<'_>, destructor: Option<Destructor>) -> ! {
        let owner = ManuallyDrop::new(self);

        let &Self(raw, _) = &*owner;

        // SAFETY:
        // ManuallyDrop prevents Rust from freeing the allocation after ownership
        // transfers to R. Consuming Allocation proves unique ownership of raw. The method caller
        // proves the object and metadata agreement required by R::throw.
        unsafe { R::throw(raw, type_info, destructor) }
    }
}

impl<R: ExceptionRuntime> Drop for Allocation<R> {
    #[inline]
    fn drop(&mut self) {
        let &mut Self(ref mut raw, _) = self;

        // SAFETY:
        // The Allocation invariant proves raw is still uniquely owned by this
        // value and was allocated by R because throw consumes and forgets self.
        unsafe { R::free(*raw) };
    }
}

/// Exception allocation backed by linked C++ runtime symbols.
pub type LinkedAlloc = Allocation<LinkedRuntime>;

#[cfg(test)]
mod tests {
    extern crate std;
    use core::{
        ffi::c_void,
        ptr::{NonNull, addr_of_mut},
        sync::atomic::{AtomicUsize, Ordering},
    };
    use std::process::abort;

    use super::{Allocation, ExceptionRuntime};
    use crate::{abi::Destructor, rtti::TypeInfoRef};

    struct MockRuntime;

    static FREES: AtomicUsize = AtomicUsize::new(0);
    static mut BUFFER: [u128; 4] = [0; 4];

    // SAFETY:
    // The test runtime has one static allocation domain. The test creates only
    // one owner at a time and never exercises the throwing transition.
    unsafe impl ExceptionRuntime for MockRuntime {
        unsafe fn alloc(size: usize) -> NonNull<c_void> {
            assert!(size <= 64, "fixture allocation must fit static storage");
            let raw = addr_of_mut!(BUFFER).cast::<c_void>();

            // SAFETY:
            // addr_of_mut returns the address of static storage and therefore
            // cannot be null.
            unsafe { NonNull::new_unchecked(raw) }
        }

        unsafe fn free(_: NonNull<c_void>) {
            FREES.fetch_add(1, Ordering::SeqCst);
        }

        unsafe fn throw(_: NonNull<c_void>, _: TypeInfoRef<'_>, _: Option<Destructor>) -> ! {
            abort()
        }
    }

    #[test]
    fn allocation_uses_selected_runtime_for_release() {
        let before = FREES.load(Ordering::SeqCst);

        {
            let allocation = Allocation::<MockRuntime>::new(8);
            assert!(!allocation.ptr().is_null(), "runtime allocation must be nonnull");
        }

        let after = FREES.load(Ordering::SeqCst);
        assert_eq!(after, before + 1, "dropping the owner must release through its runtime");
    }
}
