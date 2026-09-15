//! Exception-class identifiers carried in `_Unwind_Exception`.
//!
//! An Itanium exception class is an opaque eight-byte language-runtime tag.
//! Desenredo preserves its ABI integer representation while exposing the vendor
//! and language halves as distinct four-byte newtypes. No matching policy is
//! implied by the vendor value alone.

/// The producer identifier portion of an exception class.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
// NOTE(invariant): The four stored bytes are the complete producer half of one Itanium exception
// class.
pub struct Vendor([u8; 4]);

impl Vendor {
    /// The vendor identifier used by libc++abi.
    pub const CLANG: Self = Self(*b"CLNG");
    /// The vendor identifier used by the GNU C++ runtime.
    pub const GNU: Self = Self(*b"GNUC");

    /// Creates a vendor identifier from ABI bytes.
    #[inline]
    pub const fn new(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    /// Returns the ABI bytes.
    #[inline]
    pub const fn bytes(self) -> [u8; 4] {
        let Self(bytes) = self;

        bytes
    }
}

/// The language identifier portion of an exception class.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
// NOTE(invariant): The four stored bytes are the complete language half of one Itanium exception
// class.
pub struct Language([u8; 4]);

impl Language {
    /// The common C++ language identifier.
    pub const CXX: Self = Self(*b"C++\0");

    /// Creates a language identifier from ABI bytes.
    #[inline]
    pub const fn new(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    /// Returns the ABI bytes.
    #[inline]
    pub const fn bytes(self) -> [u8; 4] {
        let Self(bytes) = self;

        bytes
    }
}

/// The eight byte producer and language identifier.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
// NOTE(invariant): The stored value preserves the exact eight ABI bytes of one exception class.
pub struct ExceptionClass(u64);

impl ExceptionClass {
    /// Creates an exception class from its semantic components.
    #[inline]
    pub const fn join(except_vendor: Vendor, except_language: Language) -> Self {
        let [b0, b1, b2, b3, ..] = except_vendor.bytes();

        let [.., b4, b5, b6, b7] = except_language.bytes();

        Self(u64::from_be_bytes([b0, b1, b2, b3, b4, b5, b6, b7]))
    }

    /// Creates an exception class from its ABI integer representation.
    #[inline]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the ABI integer representation.
    #[inline]
    pub const fn bits(self) -> u64 {
        let Self(value) = self;

        value
    }

    /// Returns the producer identifier.
    #[inline]
    pub const fn vendor(self) -> Vendor {
        let [b0, b1, b2, b3, ..] = Self::bits(self).to_be_bytes();

        Vendor::new([b0, b1, b2, b3])
    }

    /// Returns the language identifier.
    #[inline]
    pub const fn language(self) -> Language {
        let [.., b4, b5, b6, b7] = Self::bits(self).to_be_bytes();

        Language::new([b4, b5, b6, b7])
    }

    /// Reports whether the class uses the common C++ language identifier.
    #[inline]
    pub const fn cxx(self) -> bool {
        matches!(Language::bytes(Self::language(self)), [b'C', b'+', b'+', 0])
    }
}

#[cfg(test)]
mod tests {
    use super::{ExceptionClass, Language, Vendor};

    #[test]
    fn parts_round_trip() {
        let class = ExceptionClass::join(Vendor::new(*b"TEST"), Language::CXX);

        assert_eq!(class.vendor(), Vendor::new(*b"TEST"));
        assert_eq!(class.language(), Language::CXX);
        assert!(class.cxx());
    }

    #[test]
    fn known_cxx_classes_match_runtime_tags() {
        let clang = ExceptionClass::join(Vendor::CLANG, Language::CXX);
        let gnu = ExceptionClass::join(Vendor::GNU, Language::CXX);

        assert_eq!(clang.bits(), 0x434c_4e47_432b_2b00);
        assert_eq!(gnu.bits(), 0x474e_5543_432b_2b00);
    }
}
