# Whistler 0.4.0 Release Notes

## Bug Fixes

### BTF / ELF Compatibility (cilium/ebpf, libbpf)

- **Emit proper BTF line_info section.** The kernel requires at least
  one `bpf_line_info` entry per function when `func_info` is present.
  Previously the section was empty, causing cilium/ebpf to fail with
  "can't read record size: EOF".

- **Sanitize BTF FUNC names.** Section names containing slashes (e.g.
  `tracepoint/sock/inet_sock_set_state`) are now stripped to the last
  path component for the BTF FUNC type name, since slashes are invalid
  in BTF identifiers.

- **Consistent naming between ELF symbols and BTF VARs.** Map names
  now use `lisp-to-c-name` (lowercase, hyphens→underscores)
  consistently in both ELF symbol table entries and BTF VAR/DATASEC
  types. Previously a mix of uppercase/hyphens vs lowercase/underscores
  caused cilium/ebpf to report symbol/VAR count mismatches.

- **Case-insensitive kernel struct field lookup.** CO-RE field index
  resolution for kernel structs (e.g. `xdp_md`) now uses
  case-insensitive comparison, fixing incorrect relocations for fields
  like `data_end`.

### Register Allocation

- **Spill across ring buffer helper calls.** `ringbuf-reserve`,
  `ringbuf-submit`, and `ringbuf-discard` are now recognized as
  call-like operations, so the register allocator correctly spills
  caller-saved registers (R1-R5) across these BPF helper calls.

### Code Generation

- **Forward-only jumps for return statements.** When a program has
  multiple `return` statements, their exit blocks are now placed at the
  end of the instruction stream. This prevents backward jumps that
  trigger the BPF verifier's infinite loop detection.

- **Disable cross-block map FD caching.** Map file descriptor caching
  in callee-saved registers did not account for control flow, causing
  "R9 !read_ok" verifier errors when a cached register was
  uninitialized on some paths. Caching is disabled until a
  control-flow-aware implementation is added.

### Peephole Optimizer

- **Fix tail-merge direction.** Duplicate `mov r0, IMM; exit`
  epilogues are now replaced with forward jumps to the *last*
  occurrence (previously the first), ensuring all exit jumps go
  forward as required by the BPF verifier.

- **Preserve jump-target `goto` instructions.** `goto pc+0`
  elimination now checks whether the instruction is itself a jump
  target before deleting it, preventing conditional branches from
  targeting past-the-end positions.

- **Fix redundant mask elimination.** `AND rX, MASK` was incorrectly
  deleted when the register's known bit-width equaled the mask's
  container size (e.g. a byte-loaded value ANDed with `0x0f` was
  treated as a no-op because both were classified as "8-bit"). Mask
  width is now computed using `integer-length`, so `0x0f` is correctly
  identified as 4 bits.
