//! Verifies compiler-generated Rust cleanup during panic unwinding.

extern crate alloc;

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::panic::{catch_unwind, resume_unwind};

    /// Number of cleanup guards dropped by completed unwinds.
    static DROPS: AtomicUsize = AtomicUsize::new(0);

    /// Cleanup sentinel whose destructor records phase two execution.
    struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn rust_panic_runs_drop_cleanup() {
        let before = DROPS.load(Ordering::SeqCst);
        let result = catch_unwind(|| {
            let _guard = Guard;

            resume_unwind(Box::new("desenredo Rust unwind fixture"));
        });

        assert!(result.is_err(), "the fixture panic must be caught");
        assert_eq!(
            DROPS.load(Ordering::SeqCst),
            before + 1,
            "phase two must run the cleanup guard"
        );
    }
}
