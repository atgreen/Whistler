# Whistler 1.1.0

## New features

- **`kernel-load` form** — Safely read from kernel pointers via
  `probe-read-kernel`. `(kernel-load u32 task 2772)` expands to a
  stack-alloc + probe-read-kernel + load sequence.

- **`import-kernel-struct` uses `kernel-load`** — Generated accessors
  now use `kernel-load` instead of direct `load`, making them safe for
  kernel pointers (e.g., from `get-current-task`) by default.

- **Anonymous struct/union flattening in `import-kernel-struct`** — The
  BTF parser now recursively descends into anonymous struct/union members,
  surfacing their fields as direct members. Fields like `skc_daddr` and
  `skc_dport` inside `sock_common`'s anonymous unions are now accessible.

- **`get-current-task` and `probe-read-kernel` helpers** — BPF helpers
  #35 and #113 for kernel struct traversal.

- **`reset-compilation-state`** — Exported function to clear accumulated
  maps/programs/structs between `compile-to-elf` calls in the REPL.

- **Stack usage breakdown in error messages** — When the 512-byte BPF
  stack limit is exceeded, the error now includes a per-category breakdown
  (struct-alloc, register spills, map key temporaries, etc.).

- **`:value-type` for `defmap`** — Explicit struct-valued map declarations.

- **aarch64 support for `pt-regs-parm1..6`** — Architecture-specific
  pt_regs offsets with compile-time error on unsupported platforms.

## Bug fixes

- **Fix phi-threading dropping vreg definitions (issue #12)** —
  `phi-branch-threading` redirected predecessor branches but left stale
  inputs in phi instructions. After `simplify-cfg` merged blocks, the phi
  destination vreg lost its definition, causing the emitter to assign it
  to a callee-saved register that collided with prior helper call results
  (e.g., `ktime-get-ns` in R7). Fixed by removing the threaded input from
  the phi when redirecting the predecessor.

- **Fix nil call-dst crash in `hoist-loads-before-calls`** — Void helper
  calls (unused result after dead-destination-elimination) caused a type
  error in the `/=` comparison.
