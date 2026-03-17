# Whistler Optimization Results

Comparison of compiled eBPF output: Whistler vs Clang -O2.

## Benchmark results

### Instruction counts (disasm lines, ld_imm64 = 1 instruction)

| Program | Whistler | clang -O2 | Delta |
|---------|----------|-----------|-------|
| count-xdp | 11 | 11 | tied |
| drop-port | 25 | 26 | **Whistler wins** |
| synflood-xdp | 62 | 62 | tied |
| ct4-basic | 97 | 97 | tied |
| nodeport-lb4 | 73 | 74 | **Whistler wins** |

Whistler matches or beats `clang -O2` on every benchmark.

## SSA optimization passes

### 1. Copy propagation
Replaces `%b = mov %a` with direct use of `%a`. Eliminates post-helper-call
register copies and register-to-register moves from `let` bindings.

### 2. Constant propagation
Folds constant-valued virtual registers into their use sites. `%x = mov 42;
%y = add %x, 1` becomes `%y = add 42, 1`.

### 3. Byte-swap comparison folding
When a bswap result is compared against a constant, folds the swap into the
constant and eliminates the runtime bswap instruction:
`%y = bswap16 %x; br-cond (jeq %y 9999)` → `br-cond (jeq %x 0x0F27)`

### 4. Constant offset folding
Folds chains of `add %base, C` pointer arithmetic into load/ctx-load
instruction offsets. The pattern `%p = add %base, 14; %v = load %p, 0`
becomes `%v = load %base, 14`.

### 5. Tracepoint return elision
Removes unnecessary return value setup for tracepoint programs where the
return value is ignored by the kernel.

### 6. Dead code elimination
Mark-sweep from side-effecting instructions (calls, stores, branches, returns).
Removes instructions that produce unused values.

### 7. Dead destination elimination
Removes destination registers from instructions whose results are never used.

### 8. Dead store elimination
Byte-level coverage tracking per pointer. Multiple smaller stores can kill a
larger zero-init store. Lowering emits explicit zero stores after struct-alloc,
making them visible to DSE.

### 9. Lookup-delete fusion
Fuses `map-lookup` + `map-delete` on the same map/key into a single
`map-lookup-delete` helper call. Uses dominance analysis to safely fuse
across basic block boundaries.

### 10. Load hoisting
Moves memory loads above helper calls when safe. Uses a blocklist of helpers
that invalidate pointers (e.g., `bpf_map_update_elem`).

### 11. PHI-branch threading
When a conditional branch tests a φ-function whose value is known along a
specific incoming edge, threads the branch to skip the test entirely.

### 12. Bitmask-check fusion
Combines `%masked = and %val, MASK; br-cond (test %masked, 0)` into a single
`br-cond (test-and %val, MASK)`.

### 13. ALU type narrowing
Promotes 64-bit ALU operations to 32-bit when operand types are ≤32 bits
(u8, u16, u32). Enables ALU32 emission, reducing instruction encoding size.

### 14. Live-range splitting
Splits live ranges at call boundaries for rematerializable values. Constants,
loads from stable pointers, and ctx-loads can be recomputed after helper calls
instead of occupying callee-saved registers.

## Register allocator

The linear-scan register allocator operates on SSA liveness intervals with:

- **Two register pools:** Callee-saved (R6-R9) for values live across helper
  calls; caller-saved (R0-R5) for short-lived values.
- **Value classification:** Values are classified as `:packet-ptr`, `:hot-scalar`,
  `:recomputable`, `:helper-setup`, or `:temporary`. Classification drives
  spill-cost decisions.
- **Spill-cost heuristic:** Prefers spilling rematerializable and helper-setup
  values over hot scalars or packet pointers.
- **Preferred registers:** Binary ALU results prefer the lhs operand's register
  (or either operand for commutative ops) to reduce copies.
- **Context-aware R6/R1 handling:** R6 is reserved for the context pointer when
  needed across calls; R1 is excluded when ctx-loads happen early.
- **Backend portfolio:** Multiple allocation policies are tried (varying
  reserve counts and ctx-save strategy); the best result is kept.

## Emission-level optimizations

### Map-fd caching
Caches frequently used map file descriptors in callee-saved registers. Each
cached use saves one `ld_imm64` (2 BPF slots) → `mov` (1 slot). Triggered
when a map has 3+ references and a free callee-saved register is available.

### Struct base elimination
Struct-alloc vregs map directly to R10-relative offsets. Load/store through
struct pointers use `R10 + combined_offset` directly, skipping pointer
register loads.

### Struct key pointer caching
When a struct key is used for 3+ map-ptr operations, the computed R10+offset
pointer is cached on the stack at allocation time. Subsequent map calls reload
in 1 instruction instead of recomputing in 2.

### Immediate stores
Detects constant values in store instructions and uses BPF `st-mem` (1 insn)
instead of `mov + stx-mem` (2 insns).

### Canonical key reuse
Canonicalizes constant map keys by size+value so repeated lookups with the
same key value reuse one stack slot.

## Peephole passes

After register allocation and BPF emission, the peephole optimizer runs:

- **Redundant mov elimination** — Removes `mov rX, rX` and back-to-back
  duplicate moves.
- **Unreachable code elimination** — Removes instructions after unconditional
  jumps or exits.
- **Tail merging** — Identifies common instruction sequences at the end of
  basic blocks and merges them.
- **Branch inversion** — Inverts branch conditions to eliminate unnecessary
  unconditional jumps.
- **Dead jump elimination** — Removes jumps to the immediately following
  instruction.

## Why Whistler matches or beats clang

1. **Map-fd caching.** Clang emits `ld_imm64` (2 slots) for every map
   reference. Whistler caches the fd in a callee-saved register after the
   first use, emitting `mov r1, r_cached` (1 slot) subsequently. This is the
   single biggest advantage on map-heavy programs.

2. **Bswap constant folding.** Whistler folds byte-swap operations into
   comparison constants at compile time, just like clang. EtherType and port
   comparisons use no runtime byte swap.

3. **Direct field loads.** Protocol macros expand to `(load TYPE ptr OFFSET)`
   at compile time. No packed-struct reconstruction overhead.

4. **Aggressive fusion.** Lookup-delete fusion eliminates a helper call.
   Bitmask-check fusion eliminates an instruction per flag test. Offset
   folding eliminates pointer arithmetic.

## Test programs

- `examples/count-xdp.lisp` — Minimal XDP packet counter (11 insns)
- `examples/drop-port.lisp` — Port-based packet filtering (25 insns)
- `examples/synflood-xdp.lisp` — SYN flood mitigation (65 insns)
- `examples/runqlat.lisp` — Run queue latency histogram (57 insns)
- `examples/tc-classifier.lisp` — TC packet classifier (68 insns)
- `examples/ringbuf-events.lisp` — Ring buffer events (53 insns)
