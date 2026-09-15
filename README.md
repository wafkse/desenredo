# desenredo

`desenredo` is a `no_std` Rust implementation of the Itanium exception-handling ABI for x86_64. It provides DWARF CFI stack unwinding, GCC-style LSDA parsing, personality dispatch, Rust panic transport, and C++ exception interoperability.

The workspace is split along those boundaries:

| crate | purpose |
| --- | --- |
| `desenredo-abi` | Level I `_Unwind_*` ABI types and exception headers |
| `desenredo-dwarf` | `.eh_frame` CFI evaluation |
| `desenredo-unwind` | x86_64 register recovery and physical stack traversal |
| `desenredo-lsda` | bounded GCC-style LSDA parsing |
| `desenredo-personality` | typed personality callback protocol |
| `desenredo-rust` | rustc LSDA and personality policy |
| `desenredo-panic` | owned Rust panic packets and unwind transport |
| `desenredo-cxx` | C++ Level II bindings, RTTI, and exception ownership |
| `desenredo-macro` | process-global `_Unwind_*` symbol generation |
| `desenredo` | facade over the workspace |

## Embedding

Desenredo does physical unwinding. The embedding runtime still owns image discovery, mapped-memory authority, relocation, and linker placement. A concrete `desenredo::unwind::Unwinder` supplies the live image and memory access used during traversal; `#[desenredo::unwind]` binds that implementation to the compiler-facing `_Unwind_*` symbols.

The library is intended to be used by the Nekor unikernel as its generic physical unwinding layer, with Nekor supplying the kernel-specific image and memory policy around it.

The final image must retain the unwind metadata used by the runtime, in particular `.eh_frame` and the language-specific exception tables required by its personalities.

## `no_std` Linux example

`examples/no-std-linux` is a static x86_64 Linux program built without Rust `std` or libc. It demonstrates process startup, allocation, image bounds, physical backtracing, Rust panic cleanup, catch recovery, and continued execution.

```text
./target/release/desenredo-no-std-worker work trace panic work
```

`tests/no-std-linux` contains the lower-level regression cases for unwinding across ABI boundaries, forced unwind, register reconstruction, cleanup execution, and non-unwind FFI termination.

See [`examples/no-std-linux/README.md`](examples/no-std-linux/README.md) for the build and linker setup.

## References

- [Itanium C++ ABI: Exception Handling](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html)
- [Itanium C++ ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi.html)
- [DWARF Version 5](https://dwarfstd.org/doc/DWARF5.pdf)
- [Linux Standard Base DWARF extensions](https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html)

## License

GNU General Public License v3.0 only. See [`LICENSE`](LICENSE).
