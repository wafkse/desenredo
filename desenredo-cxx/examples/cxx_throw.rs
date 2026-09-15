//! Throws a native C++ `int` from Rust-owned exception storage.
//!
//! The example exercises the C++ Level II allocation and throw interface while
//! leaving stack traversal to the language-neutral Level I unwinder.
//!
//! ```text
//! Rust                         C++ runtime                    unwinder
//!  |                               |                            |
//!  | LinkedAlloc::new              |                            |
//!  +------------------------------>| __cxa_allocate_exception   |
//!  |                               |                            |
//!  | write 42 into object storage  |                            |
//!  | borrow type_info for int      |                            |
//!  |                               |                            |
//!  | Allocation::throw             |                            |
//!  +------------------------------>| __cxa_throw                |
//!  |                               +--------------------------->|
//!  |                               |  _Unwind_RaiseException    |
//!  |                               |                            |
//!  |                         phase one searches                |
//!  |                         phase two installs catch          |
//!  |                               |                            |
//!  |<------------------------------+ catch receives int = 42    |
//! ```
//!
//! The ownership boundary is `Allocation::throw`. Before that call the Rust
//! value uniquely owns the storage returned by `__cxa_allocate_exception`.
//! After the call the C++ runtime owns the storage and Rust cannot free it.
//!
//! Provenance is defined by the [Itanium C++ ABI exception handling
//! specification](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html).
//! Level I defines `_Unwind_*` and the personality protocol. Level II defines
//! `__cxa_allocate_exception`, `__cxa_throw`, and C++ catch processing.

use core::{ffi::c_int, mem::size_of, ptr::NonNull};

use desenredo_cxx::{
    rtti::{TypeInfo, TypeInfoRef},
    runtime::LinkedAlloc,
};
unsafe extern "C" {
    fn int_type_info() -> *mut TypeInfo;

    fn catch_from_rust(callback: unsafe extern "C-unwind" fn()) -> c_int;
}

unsafe extern "C-unwind" fn throw_int() {
    let allocation = LinkedAlloc::new(size_of::<c_int>());
    let object = allocation.ptr().cast::<c_int>();

    // SAFETY:
    // LinkedAlloc owns writable storage of the requested object size. The linked
    // C++ allocator supplies suitable object alignment and no Rust reference
    // aliases this raw write.
    unsafe { object.write(42) };

    // SAFETY:
    // The shim returns the linked C++ runtime RTTI object for int. The call
    // borrows that process-lifetime object and transfers no ownership.
    let info = unsafe { int_type_info() };
    let info = NonNull::new(info).expect("C++ RTTI pointer must be nonnull");

    // SAFETY:
    // The nonnull pointer names the same runtime's live std::type_info object for
    // int and remains valid through the following throw ownership transfer.
    let info = unsafe { TypeInfoRef::new(info) };

    // SAFETY:
    // The allocation contains one initialized c_int whose dynamic type agrees
    // with info. Consuming Allocation transfers unique ownership into the C++
    // runtime and this callback does not return normally.
    unsafe { allocation.throw(info, None) }
}
fn main() {
    // SAFETY:
    // The linked shim invokes throw_int through an unwind-capable ABI while a
    // native C++ catch for int remains active. Both sides agree on the callback
    // signature and the C++ handler owns catch processing after phase two.
    let caught = unsafe { catch_from_rust(throw_int) };

    assert_eq!(caught, 42);
}
