# Optimization TODO: Register Allocation and PHI Resolution

## Current State

The cgroup-firewall example (555 instructions across 3 programs) passes
the BPF verifier with two workarounds in `src/emit.lisp`:

1. **Ringbuf pointer spill** (lines 1091-1104): After `bpf_ringbuf_reserve`,
   the returned pointer is forced to a stack slot and reloaded before every
   field store. This adds ~8 load instructions per `with-ringbuf` block.

2. **Store emission order** (lines 769-778): The value operand is
   materialized into R2 before the pointer into R1, preventing the value
   computation from clobbering the pointer register.

Both workarounds compensate for the register allocator and emitter not
coordinating properly on register lifetimes during store instructions.

## What Needs to Change

### 1. Ringbuf pointers in callee-saved registers

**Goal:** Assign ringbuf reserve results to callee-saved registers (R7-R9)
so they survive across field store computations. Remove the stack spill
workaround.

**Approach:** In `src/regalloc.lisp`, function `compute-liveness` (line
~128), force `spans-call-p` to true for vregs defined by
`:ringbuf-reserve`:

```lisp
(let ((force-callee (and insn (eq (ir-insn-op insn) :ringbuf-reserve))))
  (make-live-interval ... :spans-call-p (or spans force-callee) ...))
```

Then in `src/emit.lisp`, revert the spill workaround to a simple
`store-to-vreg`:

```lisp
(when dst (store-to-vreg ctx dst whistler/bpf:+bpf-reg-0+))
```

**What happened when we tried it:** This works in isolation. Ringbuf
pointers land in R7/R8 and field stores use them correctly. The
instruction count drops from 578 to 549. But it exposes a second bug
(below) because it shifts which variables get which registers.

### 2. PHI resolution for displaced PHI nodes

**Root cause:** Several optimization passes (`simplify-cfg` block merging,
`hoist-loads-before-calls`, `split-live-ranges`) can insert non-PHI
instructions before PHI nodes within a basic block. The emitter's
`phi-moves-for-edge` function (line ~1302) stops scanning at the first
non-PHI instruction:

```lisp
(dolist (insn (basic-block-insns block))
  (unless (eq (ir-insn-op insn) :phi)
    (return))  ;; <-- misses PHIs after this point
  ...)
```

This silently drops PHI resolution moves for any PHI that appears after
a non-PHI instruction, leaving registers uninitialized.

**Symptom:** BPF verifier error `Rn !read_ok` on variables initialized
to 0 in `let` and conditionally modified in `when`/`cond`:

```lisp
(let ((port u16 0))
  (when (= protocol +ipproto-udp+)
    (setf port (udp-hdr-dst-port pkt)))
  ;; port used here -- R7 never written on non-UDP path
```

**Fix attempt:** Change `phi-moves-for-edge` to scan ALL instructions
(not just the prefix):

```lisp
(dolist (insn (basic-block-insns block))
  (when (eq (ir-insn-op insn) :phi)  ;; scan all, not stop at first non-phi
    ...))
```

**What happened:** This fixes the displaced PHI scanning but introduces
a new problem: PHI resolution moves are now emitted for edges where the
source register was clobbered by a helper call between the PHI's
definition and the move emission point. Specifically:

```
44: call bpf_map_lookup_elem  ;; clobbers R1-R5
45: r1 = r0
46: if r1 != 0 goto +2
47: *(u64*)(r10 -24) = r2    ;; R2 !read_ok -- clobbered by call at 44
```

The PHI move at instruction 47 tries to copy R2 (a PHI input from before
the call), but R2 was destroyed by the helper call. The register
allocator assigned the PHI source to a caller-saved register, not knowing
it would need to survive past a call.

### 3. Fallthrough PHI resolution

**Related issue:** When a basic block falls through to the next block
(no explicit `:br` terminator), the emitter never calls
`emit-phi-moves` for that edge. PHI resolution is only triggered by
`:br` and `:br-cond` instruction handlers.

**Fix attempt:** After emitting each block, check if it lacks a
terminator and the next block has PHIs, then call `emit-phi-moves`:

```lisp
(unless terminated
  (emit-phi-moves ctx (basic-block-label (first block-list))))
```

**What happened:** Same problem as #2 -- the emitted moves can reference
registers clobbered by intervening helper calls.

## Proper Fix Strategy

The underlying issue is that PHI resolution in the emitter assumes:
1. PHI nodes are always at the start of their block
2. PHI source vregs are always live at the branch point

Neither assumption holds after optimization. A correct fix needs to
address both:

**Option A: Enforce PHI-first invariant in the optimizer.** After every
optimization pass that moves instructions, re-sort each block to put
PHIs first. This is the simplest fix and preserves the emitter's
existing logic. The pass should be added at the end of `optimize-ir`
(or within `canonicalize-ir`).

**Option B: Make the emitter robust to displaced PHIs.** Fix
`phi-moves-for-edge` to scan all instructions AND check that each PHI
source vreg is still available (not clobbered by intervening calls). If
a source vreg was clobbered, reload it from its spill slot or
rematerialize it.

**Option C: Move PHI resolution into the register allocator.** Instead
of emitting PHI copies during code emission, resolve PHIs during
register allocation by inserting explicit copy instructions into the IR.
This is the most principled fix (used by LLVM and most production
compilers) but requires significant restructuring.

**Recommendation:** Start with Option A. Add a
`ensure-phis-first` pass that sorts each block's instructions so PHIs
precede all other instructions. Run it as the last step before
`split-live-ranges` in `optimize-ir`. This preserves the emitter's
existing PHI resolution logic and fixes the displaced-PHI bug without
introducing new clobbering issues.

## Files Involved

| File | What to change |
|------|---------------|
| `src/regalloc.lisp:128` | Force `spans-call-p` for `:ringbuf-reserve` vregs |
| `src/emit.lisp:1091-1104` | Remove ringbuf spill workaround |
| `src/emit.lisp:1302` | Fix `phi-moves-for-edge` scanning (after Option A) |
| `src/ssa-opt.lisp:2030` | Add `ensure-phis-first` pass before `split-live-ranges` |

## Verification

The cgroup-firewall example exercises all the problem patterns:
- Multiple `with-ringbuf` blocks with complex field expressions (ntohl, ntohs)
- Mutable variables across conditional branches (`port`, `dest-allowed`)
- Nested `when`/`cond` with early `return`
- Multiple `map-lookup` calls between variable definition and use

Run `./examples/verify-cgroup-firewall.sh` to verify all 3 programs
pass the kernel BPF verifier. The test suite (`make test`, 545 checks)
covers the existing examples but does not currently test verifier
acceptance.
