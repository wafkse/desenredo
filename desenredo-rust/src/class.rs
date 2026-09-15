//! Rust panic exception class identity.

use desenredo_abi::class::ExceptionClass;

/// Rust panic exception class identity.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
// NOTE(invariant): Construction is private and the only public value is RUST, so every externally
// obtainable Tag identifies Rust panic exceptions.
pub struct Tag(ExceptionClass);

impl Tag {
    /// Exception class emitted by Rust's Itanium panic runtime.
    pub const RUST: Self = Self(ExceptionClass::new(u64::from_ne_bytes(*b"MOZ\0RUST")));

    /// Returns the underlying Itanium exception class.
    #[inline]
    pub const fn class(self) -> ExceptionClass {
        let Self(class) = self;

        class
    }
}

/// Raw Rust panic exception class.
pub const CLASS: ExceptionClass = Tag::RUST.class();

#[cfg(test)]
mod tests {
    use super::CLASS;

    #[test]
    fn rust_class_matches_std_runtime() {
        assert_eq!(CLASS.bits(), u64::from_ne_bytes(*b"MOZ\0RUST"));
    }
}
