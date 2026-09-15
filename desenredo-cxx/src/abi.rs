//! Raw Itanium C++ Level II ABI bindings.
//!
//! These declarations are intentionally thin. They do not model ownership or
//! catch-state transitions. Callers that need primary exception storage should
//! prefer [`crate::runtime`], which ties allocation and release to one runtime.

use core::ffi::c_void;

use super::rtti::TypeInfo;

/// Destructor callback stored for one primary C++ exception object.
pub type Destructor = unsafe extern "C-unwind" fn(*mut c_void);

unsafe extern "C" {
    /// Allocates storage for one primary thrown object.
    ///
    /// # Safety
    ///
    /// The returned storage belongs to the linked C++ runtime and must either be
    /// released with `__cxa_free_exception` or transferred to `__cxa_throw`.
    pub fn __cxa_allocate_exception(thrown_size: usize) -> *mut c_void;

    /// Releases primary exception storage that has not been thrown.
    ///
    /// # Safety
    ///
    /// `thrown_exception` must be a still-owned pointer returned by this linked
    /// runtime's `__cxa_allocate_exception`.
    pub fn __cxa_free_exception(thrown_exception: *mut c_void);

    /// Returns the adjusted thrown-object pointer for a live exception header.
    ///
    /// # Safety
    ///
    /// `exception_object` must be the active C++ unwind exception expected by
    /// the linked C++ runtime.
    pub fn __cxa_get_exception_ptr(exception_object: *mut c_void) -> *mut c_void;

    /// Begins a catch scope and returns the adjusted thrown-object pointer.
    ///
    /// # Safety
    ///
    /// `exception_object` must be the live exception supplied to the selected
    /// C++ landing pad. Catch nesting and later `__cxa_end_catch` calls must obey
    /// the linked runtime's state machine.
    pub fn __cxa_begin_catch(exception_object: *mut c_void) -> *mut c_void;

    /// Returns RTTI for the innermost currently handled C++ exception.
    ///
    /// # Safety
    ///
    /// The calling thread must have a C++ exception catch state compatible with
    /// the linked runtime. A null result means no current typed exception.
    pub fn __cxa_current_exception_type() -> *mut TypeInfo;
}

unsafe extern "C-unwind" {
    /// Transfers an initialized object to the C++ runtime and starts unwinding.
    ///
    /// # Safety
    ///
    /// `thrown_exception` must be live primary storage from the linked runtime.
    /// `type_info` must describe the initialized object and `destructor` must be
    /// valid for that object when present. A conforming implementation does not
    /// return normally.
    pub fn __cxa_throw(thrown_exception: *mut c_void, type_info: *mut TypeInfo, destructor: Option<Destructor>);

    /// Ends the innermost active C++ catch scope.
    ///
    /// # Safety
    ///
    /// The current thread must have a matching active `__cxa_begin_catch` scope.
    pub fn __cxa_end_catch();

    /// Rethrows the innermost active C++ exception.
    ///
    /// # Safety
    ///
    /// The current thread must be inside a rethrowable C++ catch scope. A
    /// conforming implementation transfers control to the unwinder.
    pub fn __cxa_rethrow();
}
