# Whistler Optimization Results

Comparison of compiled eBPF output: Whistler (SSA pipeline) vs Clang at
various optimization levels.

## Benchmark results

### Static instruction counts

| Program | Legacy | Clang -O2 | Clang -Os | Whistler SSA |
|---------|--------|-----------|-----------|--------------|
| count-xdp | 24 | 23 | 23 | **23** |
| drop-port | 11 | — | — | **7** |
| synflood-xdp | 126 | 82 | 77 | **76** |
| runqlat | 79 | 55 | — | **55** |

Whistler matches or beats `clang -O2` on every benchmark where a C
equivalent exists.

### Dynamic instruction counts (synflood-xdp hot path)

The hot path is: SYN packet from a known IP under the threshold (the
common case during an attack). Dynamic instruction count measures actual
instructions executed per packet.

| Build | Static insns | Dynamic insns (hot path) |
|-------|-------------|--------------------------|
| clang -O2 | 82 | 49 |
| clang -Os | 77 | 50 |
| **Whistler** | **76** | **35** |

Whistler is **28% faster** than `clang -O2` on the hot path. The primary
advantage is that Whistler loads `ip->saddr` with a single `ldxw` instruction,
while clang's byte-by-byte reconstruction from `__attribute__((packed))` structs
costs 10 instructions for the same 32-bit field.

clang -Os is actually 1 dynamic instruction *slower* than -O2 on the hot path:
its shared-exit pattern (`w0 = w6; exit`) saves 5 static instructions but costs
an extra register move on every packet.

## Optimization passes

The SSA pipeline applies 10 optimization passes:

### 1. Copy propagation
Replaces `%b = mov %a` with direct use of `%a`. Eliminates post-helper-call
register copies and register-to-register moves from `let` bindings.

### 2. Constant propagation
Folds constant-valued virtual registers into their use sites. `%x = mov 42;
%y = add %x, 1` becomes `%y = add 42, 1`.

### 3. Constant offset folding
Folds chains of `add %base, C` pointer arithmetic into load/ctx-load
instruction offsets. The pattern `%p = add %base, 14; %v = load %p, 0`
becomes `%v = load %base, 14`. This pass chains through multiple additions,
accumulating offsets, and triggers dead code elimination to remove the now-unused
`add` instructions.

**Impact:** synflood-xdp 81 → 76 (−5 instructions).

### 4. Tracepoint return elision
Removes unnecessary return value setup for tracepoint programs where the
return value is ignored by the kernel.

### 5. Dead code elimination
Mark-sweep from side-effecting instructions (calls, stores, branches, returns).
Removes instructions that produce unused values.

### 6. Dead destination elimination
Removes destination registers from instructions whose results are never used,
converting them to side-effect-only operations.

### 7. Lookup-delete fusion
Fuses `map-lookup` + `map-delete` on the same map/key into a single
`map-lookup-delete` helper call. Uses dominance analysis to safely fuse
across basic block boundaries — the lookup's block must dominate the delete's
block. Stops after the first match per lookup to avoid multi-delete erasure
bugs.

### 8. Load hoisting
Moves memory loads above helper calls when safe. This allows values to be
loaded before a call clobbers R0-R5, reducing the need for callee-saved
register pressure. Uses a blocklist of helpers that invalidate pointers
(e.g., `bpf_map_update_elem`, `bpf_ringbuf_output`).

### 9. PHI-branch threading
When a conditional branch tests a φ-function whose value is known along a
specific incoming edge, threads the branch to skip the test entirely. Eliminates
redundant branches in `if`/`cond` chains.

### 10. Bitmask-check fusion
Combines `%masked = and %val, MASK; br-cond (test %masked, 0)` into a single
`br-cond (test-and %val, MASK)` when safe (no side-effecting instructions
between the mask and the branch).

## Post-regalloc peephole passes

After register allocation and BPF emission, the peephole optimizer runs:

- **Redundant mov elimination** — Removes `mov rX, rX` and back-to-back
  duplicate moves.
- **Unreachable code elimination** — Removes instructions after unconditional
  jumps or exits that cannot be reached.
- **Tail merging** — Identifies common instruction sequences at the end of
  basic blocks and merges them.

## Register allocator

The linear-scan register allocator operates on SSA liveness intervals with:

- **Two register pools:** Callee-saved (R6-R9) for values live across helper
  calls; caller-saved (R0-R5) for short-lived values.
- **Sorted register return:** Freed registers are returned to pools in sorted
  order, ensuring deterministic allocation regardless of interval expiry timing.
- **Context-aware R6/R1 handling:** R6 is reserved for the context pointer when
  needed across calls; R1 is excluded when the context pointer stays in its
  entry register (ctx-early mode).
- **Spill heuristic:** When a pool is exhausted, the interval with the farthest
  end point is spilled to the stack.

## Why Whistler beats clang on packet programs

1. **Direct multi-byte loads.** Whistler uses `ldxh`/`ldxw` to load packet
   fields directly. Clang generates byte-by-byte reconstruction due to
   `__attribute__((packed))` struct semantics — 4 byte loads + shifts + ORs
   for a 32-bit field vs Whistler's single instruction.

2. **No struct overhead.** Whistler's protocol macros expand to direct
   `(load TYPE ptr OFFSET)` calls at compile time. There are no struct
   definitions, no packed attribute semantics, and no alignment concerns.

3. **Aggressive fusion.** Lookup-delete fusion eliminates a helper call.
   Bitmask-check fusion eliminates an instruction per flag test. Offset
   folding eliminates pointer arithmetic.

4. **Minimal control flow.** PHI-branch threading and dead code elimination
   produce tight control flow with no redundant tests.

## Where clang still has advantages

- **Loop optimization:** Clang's loop unroller and strength reduction can
  transform loops more aggressively. Whistler relies on the `log2` intrinsic
  for the most common case.
- **BTF/CO-RE:** Clang generates BTF and CO-RE relocations for struct
  portability across kernel versions. Whistler uses explicit offsets.
- **DWARF debuginfo:** Clang generates source-level debug information.
  Whistler does not (which is why its ELF output is much smaller).

## Test programs

- `examples/count-xdp.lisp` — Minimal XDP packet counter
- `examples/synflood-xdp.lisp` — SYN flood mitigation with per-IP tracking
- `examples/runqlat.lisp` — Run queue latency histogram (tracepoint)
- `examples/drop-port.lisp` — Port-based packet filtering

Compiled on Linux 6.18.16, Clang 22.1.0, SBCL 2.6.1.
