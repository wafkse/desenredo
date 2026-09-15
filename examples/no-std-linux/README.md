# `no_std` Linux userspace worker

This example is a static x86_64 Linux process built without Rust `std` and without libc. It uses Desenredo as the process unwind runtime and recovers selected Rust panics at an application request boundary.

The program accepts `work`, `trace`, and `panic` requests from Linux `argv`.

```text
$ ./target/release/desenredo-no-std-worker work trace panic work

desenredo no_std worker ready
request completed
  #1 rip=... probe=...
      desenredo_no_std_worker::backtrace::capture at ...
      ...
request completed
request panic recovered
request completed
worker completed
```

The `trace` request captures and symbolizes the current physical stack. The `panic` request allocates a real private Linux mapping and then panics. Phase two unwinding runs its `Drop` implementation, releases the mapping with `munmap`, reaches the request catch boundary, validates the typed panic payload, and continues with the next request.

```text
Linux _start
    |
    v
argc and argv
    |
    v
request boundary
    |
    +---- work ----> mapped request resource ----> Drop ----> complete
    |
    +---- panic ---> mapped request resource
                       |
                       v
                   Rust panic
                       |
                       v
                 panic packet
                       |
                       v
              _Unwind_RaiseException
                       |
                 phase one search
                       |
                 phase two cleanup
                       |
                       +----> munmap in Drop
                       |
                       v
                  catch boundary
                       |
                       v
                  next request
```

## Build and run

Nightly Rust is required because the current Rust panic catch boundary uses compiler intrinsics.

```text
cd examples/no-std-linux

cargo +nightly build \
  --features runtime \
  --release

../../target/release/desenredo-no-std-worker work trace panic work
```

The `catch` Cargo feature names the nightly catch capability and is enabled by default. The `runtime` feature depends on `catch`, so the executable target cannot be selected without the required compiler support.

The example-local `.cargo/config.toml` also enables Cargo `build-std` for `core`, `alloc`, and the active toolchain's `compiler_builtins`. The `compiler-builtins-mem` feature supplies freestanding `memcpy`, `memset`, `memmove`, `memcmp`, and related compiler runtime symbols. `start.S` therefore owns only Linux process entry rather than reimplementing compiler builtins.

## Runtime responsibilities

A real `no_std` Linux process must supply the runtime services that `std` and libc normally hide.

This example owns those responsibilities explicitly.

- `start.S` provides `_start` and the compiler-required memory primitives.
- `process.rs` interprets the kernel supplied initial stack and yields bounded argument byte slices without calling libc `strlen`.
- `allocator.rs` installs Talc as the global allocator. Talc obtains whole heaps from a non-allocating `rustix` mmap backend.
- `linux.rs` provides output, process exit, and terminal failure behavior through `rustix` Linux syscalls.
- `image.rs` binds Desenredo to the executable text, `.eh_frame`, and `.gcc_except_table` ranges published by the linker script.
- `backtrace.rs` captures physical frames without allocation, maps `/proc/self/exe`, and resolves arbitrary instruction addresses with `addr2line`.
- `runtime.rs` owns panic payload creation, terminal hooks, the Rust personality symbol, and the active recoverable request capability.
- `service.rs` represents application work and owns a real per-request Linux mapping whose `Drop` path must run during phase two.
- `boundary.rs` is the only module that knows the compiler catch intrinsic callback ABI.

The application layer therefore sees ordinary request outcomes rather than raw exception pointers or `_Unwind_*` state.

## Deployment requirements

The example is intentionally explicit about the assumptions that make unwinding sound.

The executable must be built for non-Windows x86_64 Linux with `panic = "unwind"`. The final image must retain compiler CFI and language-specific data. The linker script publishes exact bounds for executable text, `.eh_frame`, and `.gcc_except_table`.

`ProcessImage` trusts only compiler-generated metadata linked into this executable. Its memory authority may read addresses derived from that CFI and from live reconstructed stack activations. Do not reuse this policy for arbitrary plugin or attacker-controlled unwind metadata. Such a system needs a stricter memory authority and image-validation policy.

Recovery is intentionally request scoped. The panic handler raises a Desenredo panic only when one `RequestScope` capability is active. A panic outside that scope terminates the process. Nested request scopes are rejected.

Foreign exceptions are not converted into Rust request failures. The panic runtime terminates if the catch boundary receives one. An unwinder that loses the panic before the selected handler is also terminal.

A panic must not cross a non-unwinding ABI such as `extern "C"`. Use an unwind-capable boundary when propagation is part of the contract. The separate `tests/no-std-linux` regression package contains the fatal `extern "C"` case.

The process is single threaded. `RequestScope` uses one process-global atomic request identity. A multi-threaded service must replace that policy with thread-local or task-local ownership so one thread cannot claim another thread's panic.

The global allocator is Talc behind `TalcLock<RawSpinlock, _>`. Its `GlobalAllocSource` obtains larger heap mappings from a small `MmapAlloc` backed by `rustix`. The backing allocator never calls the global allocator, so Talc cannot recursively reenter itself while holding its lock. The configured minimum heap block is 1 MiB. Production systems should choose the block policy and synchronization strategy for their workload.

## Backtraces and arbitrary RIP symbolization

The `trace` request deliberately separates physical capture from symbolization. `_Unwind_Backtrace` records raw instruction pointers into fixed stack storage and performs no heap allocation. Only after traversal returns does the example open and map `/proc/self/exe`, parse the ELF with `object`, and build an `addr2line::Context`.

The raw RIP is retained for diagnostics. Source attribution uses the Itanium IP relation reported by `_Unwind_GetIPInfo`.

```text
instruction RIP      -> probe = RIP
return-address RIP   -> probe = RIP - 1
                          |
                          v
                 addr2line::find_frames
```

This matters because normal unwound frames contain return addresses that usually point inside a function rather than at its entry symbol. The example requires at least one adjusted return-address frame to resolve through DWARF before it accepts the trace as successful. The `trace_outer`, `trace_middle`, and `trace_inner` functions are retained as explicit frames in debug builds, while optimized release builds may represent them as inline frames.

The checked release profile keeps DWARF for this example with `debug = 2`. A stripped production binary should not depend on `/proc/self/exe` containing its complete debug information. Use a separate debug file, build-id indexed symbol store, or an external symbolization service while preserving the same raw RIP and probe-address relation.

`/proc/self/exe` is a Linux policy choice for this example. Sandboxed deployments that hide procfs need another trusted way to obtain the matching image bytes.

## Why the cleanup check matters

Catching a payload is not enough to demonstrate correct unwinding. A usable exception runtime must execute compiler-generated cleanup landing pads on the way to the handler.

Every request in this example acquires one private mapping. The boundary records the cleanup count before execution and verifies that exactly one mapping was released before it accepts either normal completion or a recovered panic.

```text
resource acquired
      |
      v
request body
      |
   panic
      |
      v
phase two
      |
      v
Mapping::drop
      |
      v
munmap
      |
      v
catch accepted
```

This gives the example an observable ownership invariant rather than merely proving that control eventually reaches a catch callback.

## Specification provenance

The two-phase exception protocol, unwind reason codes, personality invocation, landing-pad installation, and `_Unwind_*` interface follow the Itanium C++ ABI exception handling specification.

Caller reconstruction uses DWARF call-frame information. CIEs, FDEs, CFA rules, register recovery, and call-frame instructions are described in DWARF Version 5 section 6.4.

The relevant references are

- [Itanium C++ ABI exception handling](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html)
- [DWARF Version 5](https://dwarfstd.org/doc/DWARF5.pdf)

## Static image verification

A release build should remain a standalone executable with no dynamic loader or shared-library dependency.

```text
file target/release/desenredo-no-std-worker
readelf -l target/release/desenredo-no-std-worker | grep INTERP
readelf -d target/release/desenredo-no-std-worker | grep NEEDED
nm -u target/release/desenredo-no-std-worker
```

For the checked example, `file` reports a statically linked x86_64 ELF. The other three commands produce no dependency or undefined-symbol output.
