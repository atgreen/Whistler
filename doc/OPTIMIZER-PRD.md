# Whistler Optimizer: Design and Implementation

## Status: Implemented

All planned optimization phases have been implemented and are the default
compilation pipeline. The SSA optimizer matches or beats `clang -O2` on all
benchmarks.

### Results vs original targets

| Program | Original | Target | Achieved |
|---------|----------|--------|----------|
| runqlat | 86 insns | ≤53 (match clang) | **55** (matches clang) |
| synflood-xdp | 133 insns | — | **76** (beats clang's 82) |
| count-xdp | 28 insns | — | **23** (matches clang) |

## Why we can beat C

Clang must respect C semantics: aliasing rules, integer promotion, volatile,
sequence points. Its BPF backend is a port of a general-purpose backend with
limited BPF-specific optimization. Whistler has advantages clang doesn't:

1. **S-expression source is already an AST.** No parsing phase. Macros expand
   to data structures we can walk, rewrite, and analyze trivially.

2. **We own the language semantics.** No C standard to comply with. We can
   define `let` bindings as SSA-like single-assignment values, make mutation
   explicit via `setf`, and guarantee no aliasing between named variables.

3. **eBPF is a tiny target.** 11 registers, no memory allocator, no calling
   convention to conform to (all calls are to numbered helpers with fixed
   signatures), max 1 million instructions, no hardware branch predictor to
   worry about. The verifier already enforces safety, so we can be aggressive.

4. **No pointers-to-local-vars in general.** The only time a local's address
   escapes is when passed to `map-lookup`/`map-update` (which require `&key`).
   We know exactly where this happens. All other variables are pure values —
   perfect for SSA.

5. **Programs are small.** O(n²) algorithms are fine for n≤1000. We can afford
   expensive analysis that would be impractical for C/LLVM.

6. **Direct multi-byte packet loads.** BPF's `ldxh`/`ldxw` handle unaligned
   packet memory correctly. Clang uses byte-by-byte reconstruction due to
   `__attribute__((packed))`, costing 10 instructions for a 32-bit field vs
   Whistler's 1. This is the single largest source of Whistler's advantage on
   XDP programs.

## Architecture (implemented)

```
Source (.lisp)
  │
  ├─ CL macroexpand (user macros, protocol macros)
  │
  ├─ Lowering to SSA IR                               lower.lisp
  │   ├─ Named, typed virtual registers (infinite supply)
  │   ├─ Basic blocks with explicit control flow edges
  │   └─ φ-functions at join points
  │
  ├─ SSA optimization passes                           ssa-opt.lisp
  │   ├─ Copy propagation
  │   ├─ Constant propagation
  │   ├─ Constant offset folding
  │   ├─ Tracepoint return elision
  │   ├─ Dead code elimination
  │   ├─ Dead destination elimination
  │   ├─ Lookup-delete fusion (dominance-based)
  │   ├─ Load hoisting (helper-aware)
  │   ├─ PHI-branch threading
  │   └─ Bitmask-check fusion
  │
  ├─ Register allocation (linear scan on SSA)          regalloc.lisp
  │   ├─ Liveness intervals from SSA
  │   ├─ Two pools: callee-saved (R6-R9), caller-saved (R0-R5)
  │   ├─ Context-aware R6/R1 handling
  │   ├─ Sorted register return for determinism
  │   └─ Spill to stack with furthest-end heuristic
  │
  ├─ BPF instruction emission                          emit.lisp
  │
  ├─ Post-regalloc peephole                            peephole.lisp
  │   ├─ Redundant mov elimination
  │   ├─ Unreachable code elimination
  │   └─ Tail merging
  │
  └─ ELF emission                                      elf.lisp
```

## Implementation history

### Sprint 1: Foundation
- `log2` intrinsic (unrolled binary search, no loop)
- Map-key lookahead for stack allocation preference
- Constant folding at the s-expression level

### Sprint 2: SSA IR + basic passes
- IR data structures (`ir.lisp`): `ir-insn`, `basic-block`, `ir-program`
- S-expression → SSA IR lowering (`lower.lisp`)
- Copy propagation
- Dead code elimination

### Sprint 3: Register allocator
- Linear-scan allocator with callee/caller-saved pools
- Liveness interval computation
- Spill/reload insertion

### Sprint 4: Advanced optimizations
- PHI-branch threading
- Bitmask-check fusion
- Tail merging in peephole
- Lookup-delete fusion with dominance analysis
- Load hoisting before helper calls
- Constant offset folding

### Correctness fixes
- R1 aliasing: when ctx-early, R1 excluded from caller-saved pool and ctx
  interval added to active set
- Sorted register return: `expire-intervals` returns freed registers in sorted
  order for deterministic allocation
- Lookup-delete fusion: dominance-based with single-match-per-lookup guard
- Bitmask-check fusion: side-effect guard prevents fusing across effectful insns
- Load hoisting: helper blocklist instead of pointer provenance tracking
- PHI-branch threading: defensive label normalization (`ensure-label-form`)

## Remaining opportunities

- **Register coalescing:** Merge virtual registers connected by moves or
  φ-functions with non-overlapping live ranges.
- **Helper argument pre-positioning:** Allocate values destined for R1-R5
  directly into those registers when their intervals allow.
- **Common subexpression elimination:** Hash-based CSE for repeated ctx-loads
  or address computations.
- **Loop strength reduction:** Keep dotimes counters in registers instead of
  stack slots.

## Non-goals

- **CO-RE / BTF support.** Whistler's advantage is not needing these.
- **Multiple compilation targets.** eBPF only.
- **Link-time optimization.** BPF programs are single compilation units.
- **DWARF debuginfo.** Keeps ELF output small. Can be added later if needed.
