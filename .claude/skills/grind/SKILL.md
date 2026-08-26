---
name: grind
description: Whistler-local autonomous work loop. Survey the Beads queue, pick the highest-value next task (prioritizing correctness of generated eBPF and progress toward the Lisp→eBPF compiler goal), reprioritize the queue accordingly, then execute it end-to-end with the project's validation discipline (verifier-correct codegen, instruction-count/disassembly parity, test + kernel-load suites). Trigger when the user says "/grind", "grind", "pick the next thing and do it", "keep making progress", or wants an autonomous session that decides and works without hand-holding.
---

# grind — the Whistler progress loop

You are advancing **Whistler**: a Lisp that compiles to eBPF, written in Common
Lisp (SBCL). The pipeline is **source → macro expansion → lowering → SSA IR →
optimization (ssa-opt, sccp) → register allocation → BPF emission → peephole →
ELF**, with a pure-CL userspace loader (no libbpf/CFFI), a bpftrace frontend, and
a standalone symbolizer. The north star: **correct, verifier-passing eBPF that
holds its own against `clang -O2`** on instruction count, across every program
type and frontend.

`/grind` = **decide what to work on next, reprioritize the queue so that
decision is legible, then do the work to completion.** One good increment,
committed and closed, beats a half-finished heroic epic. Prefer correctness and
demonstrable progress toward the goal over breadth.

## 0. Orient (every run)

```bash
bd prime            # workflow + memories (if context is stale)
bd ready            # claimable work
bd stats            # open/blocked/in-progress shape
```

Skim `CLAUDE.md` (Architecture + Conventions) for the subsystem you're about to
touch — do **not** re-read all of `src/`. The pass ordering and the "must include
this op" invariants (`ir-insn-side-effect-p`, regalloc call-positions,
shared-definition single-source-of-truth in `compiler.lisp`) are where correctness
bugs hide; re-read the relevant Conventions bullet before editing that pass.

Build the system:

```bash
make                # loads/compiles the whistler ASDF system
```

Compile a program the standard way (state is auto-isolated by `compile-file*` /
`with-bpf-session`; in the REPL call `(reset-compilation-state)` between separate
`compile-to-elf` runs):

```bash
sbcl --noinform --non-interactive \
  --eval '(require :asdf)' \
  --eval '(push #P"/home/green/git/whistler/" asdf:*central-registry*)' \
  --eval '(asdf:load-system "whistler")' \
  --eval '(whistler::compile-file* "examples/synflood-xdp.lisp" "output.bpf.o")'
```

## 1. Choose the next task — selection rubric

Score candidates in this order and pick the highest that is **tractable now**:

1. **Correctness first.** A bug that produces *wrong eBPF* — a miscompile, a
   verifier rejection, a wrong runtime value, a broken relocation (map, kfunc,
   CO-RE), a bad ELF section — outranks any feature or perf work. Wrong code
   poisons everything built on it, and the verifier is unforgiving.
2. **On the critical path to the goal.** Prefer work that widens
   verifier-correct coverage (program types, helpers/kfuncs, protocol/context
   accessors) or closes the gap to `clang -O2` on real benchmarks
   (e.g. nodeport-lb4: Whistler 76 vs clang 75 instructions).
3. **Serves the compiler goal.** Codegen quality (optimization passes, peephole,
   regalloc/spilling), shared single-source-of-truth correctness across the two
   frontends + loader (helpers/kfuncs/constants in `compiler.lisp`), loader/
   session parity (both paths must patch the same relocations). Value work that
   makes the *compiler* better, not incidental surface.
4. **Tractable and verifiable.** A clear done-signal and a way to *observe* it
   end-to-end — a test that flips, an instruction count that drops, a program
   that now loads into the kernel. Favor a well-scoped bug or a decomposable
   slice over an open-ended epic.

Deprioritize: cosmetic cleanups, speculative features, anything with no line to
the goal, and **tracking/rollup epics** — don't "work" a rollup; decompose it
into a concrete child and do that.

When the top candidate is a large epic, carve off the smallest child that
delivers real, verifiable value and do *that* this run.

## 2. Anti-rat-hole guardrails

- **Time-box the investigation.** If after a bounded dig the task reveals itself
  as an architecture epic (multi-subsystem, no clear done-signal), **stop**:
  write findings + a decomposition as Beads, pick a smaller adjacent win, and
  proceed. Don't sink the session into a bottomless path.
- **Chase a done-signal, not a rabbit.** Every task needs an observable "it
  works now" (a form that compiles to the right instructions, a test that flips,
  a program that loads and attaches). If you can't state it, you're rat-holing.
- **Commit validated increments.** Don't stockpile a giant uncommitted change.
  Land each proven step; the next session/agent benefits.
- **A decision that's genuinely the maintainer's** (a language-semantics policy,
  a big irreversible direction) — surface it briefly and pick the safe default
  or ask, rather than guessing and building the wrong thing at length.

## 3. Codegen-correctness mandate (non-negotiable)

Whistler emits code the **BPF verifier** must accept and the kernel must run
correctly. Two disciplines protect that:

1. **Preserve the pass invariants.** Any op that modifies state must be in
   `ir-insn-side-effect-p` (stores, calls, tail-call, struct-alloc, branches) or
   DCE will silently delete it. Any call-like op (map-lookup, map-lookup-ptr,
   tail-call, …) must be in regalloc's call-positions list or R1–R5 clobbering
   corrupts live values. Peephole passes are order-dependent. A violation here is
   exactly a silent miscompile — treat it as the top-priority failure mode.
2. **Keep the shared definitions single-source.** Helpers, constants, builtins,
   and the kfunc registry live in `compiler.lisp`; `lower.lisp`, the bpftrace
   frontend, and the loader *reference* them, never copy. When you change a
   kfunc/helper/reloc, update the one registry and confirm **both** load paths
   still patch it (ELF loader `patch-kfunc-relocations`, session
   `session-load-progs`).

**Prove it before committing** on any codegen path you touched:

- **Compile and inspect the output.** Regenerate the affected example and read
  the disassembly (`whistler::disassemble-cu` on the compilation-unit from
  `compile-to-elf`). For codegen changes, **compare instruction counts and
  disassembly** against the prior output — a count that went *up* unexpectedly,
  or a changed instruction you can't explain, is a regression until proven
  otherwise.
- **Run the suites** (§5). A green `make test` plus a clean disassembly diff is
  the cheapest evidence a codegen change is correct.
- **Load it into the kernel when the change can affect what the verifier sees**
  — `make test-torture` actually loads compiled programs (needs CAP_BPF). Use
  `/usr/bin/sbcl` (it carries the BPF caps), **not** the Homebrew SBCL, for any
  kernel-load test.

An unexplained instruction-count change, a verifier rejection under torture, or
a relocation the loader no longer patches means you broke something — find it
before committing.

## 4. Reprioritize the queue

Make the decision legible by aligning priorities with the rubric — *before* you
start coding:

- Raise correctness/miscompile bugs and critical-path/goal work that are
  currently underranked; lower speculative or off-goal items.
  `bd update <id> --priority N`.
- Leave a one-line `bd comment` on anything you re-rank, saying why (e.g.
  "raise: verifier-reject on the tail-call path" / "lower: cosmetic, off
  critical path"). Keep churn minimal — reprioritize to *reflect* the plan, not
  to reshuffle the whole board.
- File newly discovered work as Beads immediately (never a `// TODO` or a mental
  note): `bd create "…" -t bug|task -p N`. Model blockers with `bd dep add`.

## 5. Execute end-to-end

```bash
bd update <id> --claim
```

1. Implement the smallest correct change. Match surrounding code idiom; keep the
   shared definitions in `compiler.lisp` authoritative (§3).
2. Rebuild (`make`); **drive the affected flow** and observe the result (the
   /verify discipline) — compile the relevant example and read its disassembly,
   don't trust tests alone. Wrong-code bugs demand you *see* the right
   instructions now.
3. Run the suites:
   ```bash
   make test               # FiveAM (whistler/tests)
   make bpftrace-parse-test # when the bpftrace frontend is touched
   make test-torture       # kernel-load, needs CAP_BPF (use /usr/bin/sbcl)
   ```
   For codegen changes, also compare instruction counts and disassembly against
   the pre-change output (§3).
4. Commit with an imperative subject citing the bead id and a note on what
   codegen/verifier behavior you confirmed; end the message with:
   `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
5. `bd close <id>` with the commit hash and what was verified (tests green,
   disassembly diff, kernel-load result); `bd sync`. `git push` only when the
   user asks. If not on a branch and about to commit, branch first.

## 6. Loop or hand off

Report: what you picked and **why** (the rubric line it satisfied), the change,
how you verified it (tests, instruction-count/disassembly diff, and any
kernel-load evidence), what you re-ranked, and any new Beads filed. Then pick the
next task (repeat) until told to stop or the queue has no tractable
correctness/goal work left — at which point say so plainly rather than inventing
busywork.
