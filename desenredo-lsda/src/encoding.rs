//! Address bases and encoded-pointer results used by LSDA tables.

/// Endianness used by fixed-width LSDA encodings.
pub type Endian = gimli::RunTimeEndian;

/// Logical addresses used by LSDA relative pointer encodings.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
// NOTE(invariant): origin and function are mandatory image addresses while text and data are
// optional bases for the same live image.
pub struct Bases {
    /// Address corresponding to the first byte of the bounded LSDA slice.
    origin: usize,

    /// Beginning of the function described by the current unwind region.
    function: usize,

    /// Beginning of the text image when text-relative encoding is used.
    text: Option<usize>,

    /// Data-relative base when data-relative encoding is used.
    data: Option<usize>,
}

impl Bases {
    /// Creates the mandatory LSDA and function bases.
    #[inline]
    pub const fn new(origin: usize, function: usize) -> Self {
        Self {
            origin,
            function,
            text: None,
            data: None,
        }
    }

    /// Adds the text-relative base.
    #[inline]
    pub const fn text(self, text: usize) -> Self {
        let Self {
            origin, function, data, ..
        } = self;

        Self {
            origin,
            function,
            text: Some(text),
            data,
        }
    }

    /// Adds the data-relative base.
    #[inline]
    pub const fn data(self, data: usize) -> Self {
        let Self {
            origin, function, text, ..
        } = self;

        Self {
            origin,
            function,
            text,
            data: Some(data),
        }
    }

    /// Returns the logical address of the first bounded LSDA byte.
    #[inline]
    pub const fn origin(self) -> usize {
        let Self { origin, .. } = self;

        origin
    }

    /// Returns the current function base.
    #[inline]
    pub const fn function(self) -> usize {
        let Self { function, .. } = self;

        function
    }

    /// Returns the optional text-relative base.
    #[inline]
    pub const fn text_base(self) -> Option<usize> {
        let Self { text, .. } = self;

        text
    }

    /// Returns the optional data-relative base.
    #[inline]
    pub const fn data_base(self) -> Option<usize> {
        let Self { data, .. } = self;

        data
    }
}

/// One decoded pointer value before optional ABI indirection.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
// NOTE(invariant): address is the decoded pointer value before optional indirection and indirect
// records whether the ABI requests that dereference.
pub struct Target {
    /// Decoded address before any optional indirection is followed.
    address: usize,

    /// Whether the ABI requests one pointer-sized dereference.
    indirect: bool,
}

impl Target {
    /// Constructs one decoded target.
    #[inline]
    pub const fn new(address: usize, indirect: bool) -> Self {
        Self { address, indirect }
    }

    /// Returns the decoded address.
    #[inline]
    pub const fn addr(self) -> usize {
        let Self { address, .. } = self;

        address
    }

    /// Reports whether the target is indirect.
    #[inline]
    pub const fn indirect(self) -> bool {
        let Self { indirect, .. } = self;

        indirect
    }
}
