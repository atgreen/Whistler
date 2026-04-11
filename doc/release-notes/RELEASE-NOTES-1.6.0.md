# Whistler 1.6.0 Release Notes

## New Features

- Torture test suite (`tests/test-torture.lisp`): 161 programs stress-testing
  ALU, comparisons, control flow, register pressure, maps, helpers, loops,
  packet parsing, and complex combinations. When run with `CAP_BPF`
  (`make test-torture`), output is validated against the real kernel BPF
  verifier. Codegen validation tests check constant folding, helper IDs,
  branch structure, callee-saved register usage, and stack allocation.

- Compile-time context access validation: `ctx-load` now checks access
  widths against the known context struct layout for XDP (`xdp_md`) and TC
  (`__sk_buff`) programs. Invalid widths produce a clear error with a fix
  suggestion.

## Bug Fixes

- **Wrong helper in map-lookup-delete fusion.** The SSA optimizer fused
  `map-lookup` + `map-delete` into BPF helper 46, which is
  `bpf_get_socket_cookie` -- not `bpf_map_lookup_and_delete_elem` (a
  userspace syscall, not an in-kernel helper). The fusion is disabled and
  the bogus constant removed.

- **Missing SSA phis for `setf` in loops.** `setf` inside `dotimes`
  updated the environment but did not create phi nodes at the loop header.
  `lower-dotimes` now pre-inserts phis for all in-scope variables; DCE
  removes unused ones.

- **Missing SSA phis for `setf` in branches.** `setf` in one arm of
  `if`/`when`/`unless` created a new vreg without merging at the join
  point. `lower-if` now inserts phis for variables whose vregs differ
  between branches.

- **Missing phi moves on `br-cond` edges.** `emit-br-cond-insn` emitted
  plain conditional + unconditional jumps without phi resolution copies.
  Phi-move emission is factored into a shared helper called by both `:br`
  and `:br-cond`, with trampoline blocks when needed.

- **Nested loop phi predecessor.** Inner `dotimes` referenced the program
  entry block instead of the block where the counter init was emitted.

- **R0 in caller-free pool.** The register allocator documented R0 as
  reserved but still included it in the allocatable pool.

## Documentation

- Fixed stale `ctx`-passing API across 7 book pages (`xdp-data ctx` etc.).
- Updated `defprog` syntax from `(&key ...)` to `(:type ... :section ...)`.
- Updated examples to use zero-argument accessor macros and `with-ringbuf`.
- `book/book/` added to `.gitignore`.
