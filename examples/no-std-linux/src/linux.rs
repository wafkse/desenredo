//! Linux process output and termination mechanisms.
//!
//! Allocation lives in the separate `allocator` module so the Talc policy and
//! its rustix backing source remain distinct from ordinary process I/O.

use rustix::{
    fd::BorrowedFd,
    io::write,
    runtime::exit_group,
    stdio::{stderr as stderr_fd, stdout as stdout_fd},
};

/// Native page size assumed by this x86_64 Linux example.
pub const PAGE_SIZE: usize = 4096;

/// Process exit status used by terminal example policies.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ExitCode(i32);

impl ExitCode {
    /// Foreign exception reached the Rust catch boundary.
    pub const FOREIGN: Self = Self(71);
    /// Raised panic returned from the unwinder without a handler.
    pub const LOST: Self = Self(72);
    /// Internal runtime or invariant failure.
    pub const SOFTWARE: Self = Self(70);
    /// Successful completion.
    pub const SUCCESS: Self = Self(0);
    /// Invalid command line usage.
    pub const USAGE: Self = Self(64);

    /// Returns the Linux process status.
    #[inline]
    pub const fn get(self) -> i32 {
        let Self(value) = self;

        value
    }
}

/// Writes a complete byte sequence to one inherited descriptor when possible.
fn write_all(fd: BorrowedFd<'_>, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        match write(fd, bytes) {
            Ok(0) => break,
            Err(_error) => break,
            Ok(written) => {
                let (_, rest) = bytes.split_at(written);
                bytes = rest;
            },
        }
    }
}

/// Writes an operational message to standard output.
#[inline]
pub fn stdout(bytes: &[u8]) {
    // SAFETY:
    // The process inherits descriptor one from Linux process creation.
    let stdout = unsafe { stdout_fd() };

    write_all(stdout, bytes);
}

/// Writes a diagnostic message to standard error.
#[inline]
pub fn stderr(bytes: &[u8]) {
    // SAFETY:
    // The process inherits descriptor two from Linux process creation.
    let stderr = unsafe { stderr_fd() };

    write_all(stderr, bytes);
}

/// Terminates every thread in the process with one status.
#[inline]
pub fn exit(status: ExitCode) -> ! {
    exit_group(status.get())
}

/// Reports one terminal diagnostic and exits the process.
#[inline]
pub fn terminate(message: &[u8], status: ExitCode) -> ! {
    stderr(message);
    exit(status)
}
