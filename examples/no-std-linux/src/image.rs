//! Static image discovery for DWARF CFI and Rust LSDA metadata.
//!
//! This example trusts only metadata linked into its own executable. The linker
//! script publishes exact text, `.eh_frame`, and `.gcc_except_table` bounds.

use core::{error::Error, fmt, ops::Range, ptr, slice::from_raw_parts};

use desenredo::{
    personality::{context::Frame, source::Source},
    unwind::source::Image as UnwindImage,
};

/// Failure to bound one compiler supplied LSDA pointer.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Bounds;

impl fmt::Display for Bounds {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LSDA pointer lies outside the linked exception table")
    }
}

impl Error for Bounds {}

/// Unwind authority for the one statically linked executable image.
pub struct ProcessImage;

unsafe extern "C" {
    /// First executable byte in the linked text segment.
    static __desenredo_text_start: u8;

    /// One-past-the-end executable byte in the linked text segment.
    static __desenredo_text_end: u8;

    /// First byte in the linked `.eh_frame` section.
    static __desenredo_eh_start: u8;

    /// One-past-the-end byte in the linked `.eh_frame` section.
    static __desenredo_eh_end: u8;

    /// First byte in the linked GCC exception table section.
    static __desenredo_lsda_start: u8;

    /// One-past-the-end byte in the linked GCC exception table section.
    static __desenredo_lsda_end: u8;
}

/// Returns the executable text range exported by the linker script.
#[inline]
fn text() -> Range<usize> {
    let start = ptr::addr_of!(__desenredo_text_start).addr();
    let end = ptr::addr_of!(__desenredo_text_end).addr();

    start..end
}

/// Bounds a live pointer to the remainder of one linker-owned byte range.
///
/// # Safety
///
/// `origin` must be a live pointer into the allocation described by `start` and
/// `end` when the numeric bounds validation succeeds.
unsafe fn bound<'a>(origin: *const u8, start: usize, end: usize) -> Result<&'a [u8], Bounds> {
    let address = origin.addr();
    let valid = start <= address && address < end && start <= end;

    match valid {
        true => {
            let size = end - address;

            // SAFETY:
            // The checked numeric range and caller contract prove a live suffix.
            Ok(unsafe { from_raw_parts(origin, size) })
        },
        false => Err(Bounds),
    }
}

// SAFETY:
// The linker script bounds every live Rust LSDA in this static executable. The
// returned slice starts at the frame LSDA pointer and remains live with the image.
unsafe impl Source for ProcessImage {
    type Error = Bounds;

    #[inline]
    fn bytes<'a>(frame: &Frame<'a>) -> Result<Option<&'a [u8]>, Self::Error> {
        let origin = frame.lsda();
        let start = ptr::addr_of!(__desenredo_lsda_start).addr();
        let end = ptr::addr_of!(__desenredo_lsda_end).addr();

        match origin {
            None => Ok(None),
            Some(origin) => {
                // SAFETY:
                // Source provenance proves origin belongs to this live image.
                unsafe { bound(origin.as_ptr(), start, end) }.map(Some)
            },
        }
    }
}

#[desenredo::unwind]
#[expect(
    clippy::absolute_paths,
    reason = "the unwind macro requires the canonical facade trait path"
)]
// SAFETY:
// image returns only this executable's trusted compiler-generated CFI. read is
// used only for addresses derived from that CFI and the live stack activations
// reconstructed from it. This example does not accept untrusted unwind metadata.
unsafe impl desenredo::unwind::runtime::Unwinder for ProcessImage {
    fn image(address: usize) -> Option<UnwindImage<'static>> {
        let text = text();
        let eh_start = ptr::addr_of!(__desenredo_eh_start).addr();
        let eh_end = ptr::addr_of!(__desenredo_eh_end).addr();
        let size = eh_end.checked_sub(eh_start);
        let owned = text.contains(&address);

        match (owned, size) {
            (true, Some(size)) => {
                // SAFETY:
                // Linker symbols bound the complete live `.eh_frame` section.
                let pointer = ptr::with_exposed_provenance(eh_start);
                // SAFETY:
                // The linker symbols bound the complete live `.eh_frame` section.
                let bytes = unsafe { from_raw_parts(pointer, size) };

                UnwindImage::new(bytes, text)
            },
            _ => None,
        }
    }

    fn read(address: usize, size: u8) -> Option<u64> {
        let pointer = ptr::with_exposed_provenance::<u8>(address);

        // SAFETY:
        // The unsafe Unwinder contract above restricts every read to trusted CFI
        // derived addresses in this image or one live stack activation.
        unsafe {
            match size {
                1 => Some(u64::from(pointer.read_unaligned())),
                2 => Some(u64::from(pointer.cast::<u16>().read_unaligned())),
                4 => Some(u64::from(pointer.cast::<u32>().read_unaligned())),
                8 => Some(pointer.cast::<u64>().read_unaligned()),
                _ => None,
            }
        }
    }
}
