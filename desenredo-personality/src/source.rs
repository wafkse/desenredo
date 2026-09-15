//! Live language specific data supplied to personality implementations.
//!
//! The system unwind API exposes only an LSDA pointer. This capability lets a
//! platform or image loader prove the complete readable range once and pass a
//! bounded slice to language-specific parsers.

use core::error::Error;

use super::context::Frame;

/// Provider of a complete live LSDA byte range for one unwind frame.
///
/// # Safety
///
/// When [`Source::bytes`] returns `Some`, the slice must begin at exactly the
/// address returned by [`Frame::lsda`] for that same frame. The complete slice
/// must remain readable for the frame lifetime and must cover every call-site,
/// action, type, and filter byte which can be reached from that LSDA.
///
/// The slice must refer to the live image represented by `frame`. A copied LSDA
/// buffer is not sufficient when an encoding is relative to its in-image field
/// address. Any address returned by [`Source::text`] or [`Source::data`] must be
/// the corresponding base for that same image and frame. Implementations must
/// not create a Rust slice across unmapped or concurrently mutable storage.
pub unsafe trait Source {
    /// Error reported while bounding the live LSDA range.
    type Error: Error;

    /// Returns a bounded view beginning at the frame's live LSDA pointer.
    ///
    /// `None` is valid only when the frame has no LSDA. `Some` must satisfy the
    /// complete range and provenance contract stated on [`Source`].
    fn bytes<'a>(frame: &Frame<'a>) -> Result<Option<&'a [u8]>, Self::Error>;

    /// Returns the text-relative pointer base for this exact live image.
    ///
    /// Leaving this as `None` is preferred when no parsed encoding requires a
    /// text-relative base. This keeps optional unwinder queries lazy.
    #[inline]
    fn text(_frame: &Frame<'_>) -> Option<usize> {
        None
    }

    /// Returns the data-relative pointer base for this exact live image.
    ///
    /// Leaving this as `None` is preferred when no parsed encoding requires a
    /// data-relative base. This keeps optional unwinder queries lazy.
    #[inline]
    fn data(_frame: &Frame<'_>) -> Option<usize> {
        None
    }
}
