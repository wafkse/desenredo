//! Talc global allocation backed directly by Linux anonymous mappings.
//!
//! Talc owns suballocation and heap reuse. The backing allocator below owns
//! only complete Linux mappings and never allocates through the global allocator.

use core::{
    alloc::{GlobalAlloc, Layout},
    ffi::c_void,
    ptr,
};

use rustix::mm::{MapFlags, ProtFlags, mmap_anonymous, munmap};
use spinning_top::RawSpinlock;
use talc::{TalcLock, source::GlobalAllocSource};

use crate::linux::PAGE_SIZE;

/// Minimum heap block requested from Linux for Talc growth.
const HEAP_BLOCK: usize = 1024 * 1024;

/// Allocation-free Linux mapping provider used only beneath Talc.
#[derive(Debug, Copy, Clone)]
struct MmapAlloc;

/// Talc source which pools Linux mappings into reusable heaps.
type Source = GlobalAllocSource<MmapAlloc>;

/// Locked allocator installed as the process-wide Rust allocator.
type Allocator = TalcLock<RawSpinlock, Source>;

#[global_allocator]
/// Process-wide Talc allocator backed by anonymous Linux mappings.
static ALLOCATOR: Allocator = TalcLock::new(GlobalAllocSource::with_block_size(MmapAlloc, HEAP_BLOCK));
/// Rounds one allocation size to complete Linux pages.
#[inline]
fn mapped_size(size: usize) -> Option<usize> {
    let size = size.max(1);
    let extra = PAGE_SIZE - 1;

    size.checked_add(extra).map(|size| size / PAGE_SIZE * PAGE_SIZE)
}

// SAFETY:
// Successful allocations are page-aligned private mappings. Layouts requiring
// stronger alignment fail. Deallocation reconstructs the exact rounded mapping
// size from the original Layout and releases that mapping exactly once.
unsafe impl GlobalAlloc for MmapAlloc {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = match (layout.align() <= PAGE_SIZE, mapped_size(layout.size())) {
            (true, Some(size)) => size,
            _ => return ptr::null_mut(),
        };

        // SAFETY:
        // A null address asks Linux for one fresh mapping with page alignment.
        let mapped = unsafe {
            mmap_anonymous(
                ptr::null_mut(),
                size,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::PRIVATE,
            )
        };

        match mapped {
            Ok(mapped) => mapped.cast(),
            Err(_error) => ptr::null_mut(),
        }
    }

    #[inline]
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let size = mapped_size(layout.size());

        match size {
            Some(size) => {
                // SAFETY:
                // GlobalAlloc supplies the live mapping and original Layout.
                let _released = unsafe { munmap(pointer.cast::<c_void>(), size) };
            },
            None => {},
        }
    }
}
