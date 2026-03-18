# Whistler 0.3.0

## New features

- **Array fields in defstruct** — `(field-name (array type count))` declares
  fixed-size array fields with C-compatible layout. Generates indexed
  accessors `(name-field ptr idx)` with `setf` support, and pointer
  accessors `(name-field-ptr ptr)` for passing array addresses to BPF
  helpers. Constant indices fold to fixed offsets at compile time; runtime
  indices skip the multiply for byte-sized elements.

- **sizeof** — `(sizeof struct-name)` expands to the struct's byte size at
  compile time. Replaces magic numbers in `probe-read-user`,
  `ringbuf-reserve`, etc.

- **memset** — `(memset ptr offset value nbytes)` fills memory with widened
  stores. 16 bytes of `#xFF` compiles to 2 u64 immediate stores instead of
  16 u8 stores. Values representable as signed 32-bit (like -1 for 0xFF
  fill) use `mov` instead of `ld_imm64`, saving 2 instructions per store.

- **memcpy** — `(memcpy dst dst-off src src-off nbytes)` copies memory using
  the widest possible load/store pairs.

- **pt-regs-parm1 through parm6, pt-regs-ret** — x86-64 `struct pt_regs`
  access macros matching C's `PT_REGS_PARM1()` etc. from `bpf_tracing.h`.
  Eliminates raw register offset constants in uprobe/kprobe programs.

- **BTF array support** — Array fields emit proper `BTF_KIND_ARRAY` entries
  in the `.BTF` section.

- **Codegen for array fields** — Shared header generation (C, Go, Rust,
  Python, Common Lisp) emits correct array syntax for each language:
  `uint8_t field[16]`, `[16]uint8`, `[u8; 16]`, `ctypes.c_uint8 * 16`.

## Bug fixes

- **Fixed ELF output tests** — Updated `write-minimal-elf` and
  `write-elf-with-maps` tests to use the multi-program `write-bpf-elf` API
  introduced in 0.2.0. All 14 tests now pass.
