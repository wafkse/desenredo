//! Linux initial process stack parsing.
//!
//! The kernel enters `_start` with `argc` followed by the `argv` pointer array.
//! The assembly entry point forwards that original stack pointer before aligning
//! the Rust call stack.

use core::{marker::PhantomData, ptr::NonNull, slice::from_raw_parts};

/// Native words occupied by the initial argument count.
const ARGC_WORDS: usize = 1;

/// Pointer words occupied by the executable name.
const PROGRAM_WORDS: usize = 1;

/// Pointer words advanced for each argument.
const ARGUMENT_WORDS: usize = 1;

/// Validated view of the Linux process entry stack.
// NOTE(invariant): base is the original nonnull stack pointer supplied by Linux
// at process entry. The argc and argv storage remains live for the process.
pub struct ProcessStack(NonNull<usize>);

impl ProcessStack {
    /// Validates the raw stack pointer forwarded by `_start`.
    ///
    /// # Safety
    ///
    /// `raw` must be the exact initial stack pointer supplied by Linux before
    /// any stack adjustment or ordinary Rust call frame is created.
    #[inline]
    pub unsafe fn from_entry(raw: *mut usize) -> Option<Self> {
        NonNull::new(raw).map(Self)
    }

    /// Iterates application arguments while skipping the executable name.
    #[inline]
    pub const fn args(&self) -> Args<'_> {
        let &Self(base) = self;

        // SAFETY:
        // ProcessStack proves base names the live Linux argc word.
        let argc = unsafe { base.as_ptr().read() };
        // SAFETY:
        // Linux places argv immediately after argc on the initial stack.
        let argv = unsafe { base.as_ptr().add(ARGC_WORDS).cast::<*const u8>() };
        // SAFETY:
        // argv points at the executable name followed by application arguments.
        let first = unsafe { argv.add(PROGRAM_WORDS) };
        // SAFETY:
        // Pointer arithmetic from one live initial stack base cannot produce null.
        let cursor = unsafe { NonNull::new_unchecked(first.cast_mut()) };
        let remaining = argc.saturating_sub(PROGRAM_WORDS);
        let marker = PhantomData;

        Args {
            cursor,
            remaining,
            marker,
        }
    }
}

/// Iterator over NUL-terminated Linux application arguments.
// NOTE(invariant): cursor names the next argv pointer and remaining bounds every
// read to the argc count captured from the same initial process stack.
pub struct Args<'a> {
    /// Pointer to the next argv pointer slot.
    cursor: NonNull<*const u8>,

    /// Number of application arguments not yet yielded.
    remaining: usize,

    /// Lifetime tie to the process stack that owns argv storage.
    marker: PhantomData<&'a ProcessStack>,
}

impl<'a> Iterator for Args<'a> {
    type Item = &'a [u8];

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let &mut Self {
            ref mut cursor,
            ref mut remaining,
            ..
        } = self;

        match *remaining {
            0 => None,
            _ => {
                // SAFETY:
                // Args guarantees cursor names the next live argv pointer slot.
                let argument = unsafe { cursor.as_ptr().read() };
                // SAFETY:
                // remaining proves another pointer slot belongs to argv.
                let next = unsafe { cursor.as_ptr().add(ARGUMENT_WORDS) };
                // SAFETY:
                // Advancing within the live argv array cannot produce null.
                *cursor = unsafe { NonNull::new_unchecked(next) };
                *remaining -= 1;

                let mut length = 0_usize;
                loop {
                    // SAFETY:
                    // Linux guarantees this argv pointer reaches one terminating
                    // zero byte before leaving the process-owned argument string.
                    let byte = unsafe { argument.add(length).read() };

                    match byte {
                        0 => break,
                        _ => length = length.saturating_add(1),
                    }
                }

                // SAFETY:
                // The scan above proves exactly length initialized bytes precede
                // the terminating zero in this process-owned argument string.
                Some(unsafe { from_raw_parts(argument, length) })
            },
        }
    }
}
