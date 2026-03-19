# Whistler 0.5.0 Release Notes

## Bug Fixes

- **Value-size-aware map macros.** `getmap`, `setmap`, `incf-map`, and
  `atomic-add` now derive the correct BPF operation width (u8/u16/u32/u64)
  from the map's declared `:value-size`. Previously these were hard-wired
  to 64-bit, emitting invalid `ldxdw`/64-bit atomics for maps with smaller
  value sizes.

- **Reject conflicting licenses in multi-program builds.** `compile-to-elf`
  now signals an error when programs declare different licenses instead of
  silently using the first program's license for all.

## New Optimization Passes

- **CFG simplification.** Folds constant branches, merges jump-only blocks
  and linear chains, removes unreachable blocks. Runs in a fixed-point
  loop to catch cascading opportunities.

- **Common subexpression elimination.** Intra-block CSE for pure ALU ops,
  byte-swaps, casts, and memory loads (invalidated on stores/calls).

- **Store-to-load forwarding.** Replaces loads from just-stored locations
  with the stored value, eliminating memory round-trips.

- **Loop-invariant code motion.** Detects natural loops, hoists invariant
  instructions (constants, ctx-loads, pure ALU) to the loop preheader.

- **Trivial phi elimination.** Collapses PHI nodes where all inputs
  converge to the same value.

- **Fixpoint canonicalization.** Copy-prop, const-prop, phi elimination,
  CFG simplification, and DCE now iterate to a fixed point, catching
  multi-step optimization chains that single-pass missed.

## Code Size Improvements

| Example          | 0.4.1 | 0.5.0 | Saved |
|------------------|-------|-------|-------|
| synflood-xdp     |    71 |    68 |    -3 |
| ratelimit-xdp    |    62 |    55 |    -7 |
| runqlat           |    57 |    37 |   -20 |
| multi-prog        |    45 |    44 |    -1 |

## Test Suite

- New FiveAM-based test suite with 138 checks across 11 test files,
  covering opcode-level instruction verification, all optimization
  passes, protocol parsing, map operations, tail calls, ring buffers,
  multi-program builds, and ELF output validation. Run with `make test`.

## New Example

- `percpu-counter.lisp` — demonstrates LICM hoisting ctx-loads out of
  a loop.
