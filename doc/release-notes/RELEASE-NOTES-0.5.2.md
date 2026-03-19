# Whistler 0.5.2 Release Notes

## Bug fixes

- **Fix BTF encoding for structs with array fields.** Array field types
  (`BTF_KIND_ARRAY`) were interleaved with struct member entries, producing
  malformed BTF that libbpf and bpftool rejected. (Fixes #1)

- **Fix ELF map symbols: emit `STT_OBJECT` with size.** Map symbols were
  emitted as `NOTYPE` with size 0, causing libbpf's `bpf_object__open()` to
  fail matching BTF `VAR` entries to ELF symbols. (Fixes #2)

- **Stop emitting CO-RE relocations for user-defined structs.** All struct
  field accesses generated CO-RE relocations, causing libbpf to search kernel
  BTF, fail, and replace every access with an invalid instruction. User-defined
  structs now emit direct loads/stores with compile-time offsets. (Fixes #3)

- **Convert BTF struct field names from hyphens to underscores.** Field names
  retained Lisp-style hyphens which the kernel BTF validator rejected as
  invalid C identifiers. (Fixes #4)

- **Use defprog name for FUNC symbols instead of section name.** FUNC symbols
  used the ELF section path (e.g. `kprobe/__x64_sys_execve`) which contains
  slashes that the kernel rejects. Now uses the defprog name. (Fixes #5)
