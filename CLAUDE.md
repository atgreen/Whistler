# Whistler

A Lisp that compiles to eBPF. Written in Common Lisp (SBCL).

## Build & Run

```bash
# Load and compile a program
sbcl --noinform --non-interactive \
  --eval '(require :asdf)' \
  --eval '(push #P"/home/green/git/whistler/" asdf:*central-registry*)' \
  --eval '(asdf:load-system "whistler")' \
  --eval '(whistler::compile-file* "examples/synflood-xdp.lisp" "output.bpf.o")'

# Disassemble (inspect instruction output)
# Use whistler::disassemble-cu on the compilation-unit returned by compile-to-elf
```

`compile-file*` and `with-bpf-session` automatically isolate compilation state. When using `compile-to-elf` directly in the REPL, call `(reset-compilation-state)` between separate compilations to clear accumulated maps/programs/structs.

No test suite. Verify correctness by checking instruction counts and comparing disassembly output.

## Architecture

Pipeline: **source** → macro expansion → **lowering** (lower.lisp) → SSA IR → **optimization** (ssa-opt.lisp) → **register allocation** (regalloc.lisp) → **BPF emission** (emit.lisp) → **peephole** (peephole.lisp) → **ELF output** (elf.lisp)

### Key files

| File | Purpose |
|------|---------|
| `packages.lisp` | Package definitions and exports |
| `bpf.lisp` | BPF instruction encoding, constants, opcodes |
| `compiler.lisp` | Legacy direct compiler, macro expansion (`whistler-macroexpand`), constant folding, **shared definitions** (helpers, constants, builtins — single source of truth for both pipelines) |
| `ir.lisp` | SSA IR data structures (`ir-insn`, `basic-block`, `ir-program`) |
| `lower.lisp` | Lowering from surface language to SSA IR |
| `ssa-opt.lisp` | SSA optimizations (copy prop, DCE, constant folding, phi threading) |
| `regalloc.lisp` | Linear-scan register allocator with spilling |
| `emit.lisp` | IR → BPF instruction emission, stack allocation, map operations, tail calls |
| `peephole.lisp` | Post-regalloc BPF peephole optimizer (15+ passes) |
| `btf.lisp` | BTF type encoding and BTF.ext (CO-RE relocations, func_info) |
| `elf.lisp` | ELF object file writer (multi-program support) |
| `protocols.lisp` | Protocol header macros (Ethernet, IPv4, TCP, UDP), map/struct surface macros |
| `whistler.lisp` | Top-level interface: `defmap`, `defprog`, `defstruct`, `compile-to-elf` |

### Packages

- `whistler/bpf` — BPF constants and instruction constructors
- `whistler/compiler` — Legacy compiler, macro expansion, **shared definitions** (`*builtin-helpers*`, `*builtin-constants*`, `*whistler-builtins*`, `sym=`, `bpf-type-p`)
- `whistler/ir` — IR, lowering, optimization, regalloc, emission, peephole
- `whistler/elf` — ELF output
- `whistler/btf` — BTF and BTF.ext encoding
- `whistler` — User-facing surface language (programs use `(in-package #:whistler)`)

## Surface Language

Programs are defined with `defprog`, maps with `defmap`, structs with `defstruct`. Standard CL `let` bindings with optional type inference:

```lisp
(let ((x (load u32 ptr 0))       ; type inferred from load → u32
      (y (tcp-flags tcp)))        ; inferred → u8
  (store u32 ptr 4 x))           ; memory store
```

Use `(declare (type ...))` for narrowing when inference can't determine the type (integer literals, arithmetic results).

Key forms: `let` (parallel bindings, standard CL), `let*` (sequential bindings), `if`, `when`, `unless`, `when-let`, `if-let`, `return`, `load`, `store`, `logand`, `logxor`, `>>`, `ash`, `cast`, `map-lookup`, `map-update`, `map-delete`, `map-lookup-ptr`, `struct-alloc`, `stack-addr`, `tail-call`, `get-prandom-u32`, `sizeof`, `memset`, `memcpy`, `do-user-ptrs`, `do-user-array`, `with-ringbuf`, `fill-process-info`, `pt-regs-parm1`..`parm6`, `pt-regs-ret`, protocol accessors.

`setf` supports CL-style multi-pair: `(setf place1 val1 place2 val2 ...)`. `defmap` defaults `:key-size` and `:value-size` to 0 (omit for ringbuf maps).

`defstruct` generates BPF accessors `(name-field ptr)`, `setf` expanders, indexed array access, and pointer accessors `(name-field-ptr ptr)`. Also generates CL-side: `name` struct with `(name-field instance)` accessors, `decode-name` (bytes→struct), `encode-name` (struct→bytes). The CL accessors use the same names as the BPF accessors. `(sizeof name)` returns compile-time struct size. Maps support `(getmap m k)` / `(setf (getmap m k) v)` / `(remmap m k)` — matching CL's gethash/remhash pattern.

`with-ringbuf` handles reserve/null-check/submit: `(with-ringbuf (var map size) body...)`. `fill-process-info` fills pid/uid/timestamp/comm from BPF helpers using struct accessor names.

Memory ops: `(memset ptr off val n)` with widened stores, `(memcpy dst doff src soff n)` with wide load/store pairs. `(pt-regs-parm1)` through `(pt-regs-parm6)` and `(pt-regs-ret)` for uprobe/kprobe context access (x86-64 and aarch64; compile-time error on unsupported architectures).

## Userspace Loader (whistler/loader)

Pure CL BPF loader — no libbpf, no CFFI. ASDF system `whistler/loader`. Key APIs: `with-bpf-object` (load .bpf.o), `with-bpf-session` (inline compile+load), `map-lookup`/`map-update`/`map-get-next-key`, `attach-kprobe`/`attach-uprobe`/`attach-tracepoint`/`attach-xdp`/`attach-tc`/`attach-cgroup`, `open-ring-consumer`/`ring-poll`. Cgroup programs (`cgroup_skb`, `cgroup/sock_*`, `cgroup/connect*`, `cgroup/sendmsg*`) are supported — the loader sets `expected_attach_type` automatically from the ELF section name and uses `BPF_PROG_ATTACH`/`BPF_PROG_DETACH` for cgroup attachment. `with-bpf-session` compiles BPF at macroexpand time using `bpf:map`, `bpf:prog`, `bpf:attach`, `bpf:map-ref`. The `bpf:` prefix separates kernel-side from userspace code. See `examples/ffi-call-tracker.lisp` for a complete inline example, or `examples/cgroup-skb-session.lisp` for cgroup usage.

## Kernel Integration

`deftracepoint` reads tracepoint format files from tracefs at macroexpand time: `(deftracepoint sched/sched-switch prev-pid prev-state next-pid)` → generates `(tp-prev-pid)` etc. `import-kernel-struct` reads `/sys/kernel/btf/vmlinux`: `(import-kernel-struct task_struct pid tgid)` → generates `(task-struct-pid ptr)` etc.

Permissions: `CAP_BPF` + `CAP_PERFMON` for loading/attaching. Use `sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/sbcl` instead of root. Tracepoint format files need `chmod a+r`.

Protocol headers: Ethernet, IPv4, IPv6, TCP, UDP, ICMP with constants and `with-packet`/`with-tcp`/`with-udp` parsing macros. TC (sched_cls) programs use `with-tc-packet`/`with-tc-tcp`/`with-tc-udp` (same API, `__sk_buff` offsets, `TC_ACT_OK`/`TC_ACT_SHOT` return codes).

Types: `u8`, `u16`, `u32`, `u64`. The `whistler` package shadows `case`, `defstruct`, `incf`, and `decf` from CL. Standalone BPF source files use `(in-package #:whistler)` which avoids conflicts. To use Whistler from another package, add `:shadowing-import-from`:

```lisp
(defpackage #:my-bpf
  (:use #:cl #:whistler)
  (:shadowing-import-from #:whistler #:case #:defstruct #:incf #:decf))
```

## Multi-program and tail calls

Multiple `defprog` forms compile into a single ELF with separate sections. Tail calls use `:prog-array` maps:

```lisp
(defmap jt :type :prog-array :key-size 4 :value-size 4 :max-entries 8)
(tail-call jt index)   ; transfer execution to program at index, falls through on failure
```

## Conventions

- BPF registers: R0 = return, R1-R5 = args/caller-saved, R6-R9 = callee-saved, R10 = frame pointer
- Stack offsets are negative from R10, max 512 bytes
- Register allocator spills in 8-byte slots; `ectx-alloc-stack` handles sub-8-byte allocations with natural alignment
- Peephole passes are order-dependent; final cleanup iterates branch inversion + dead-jump removal
- `ir-insn-side-effect-p` must include any op that modifies state (stores, calls, tail-call, struct-alloc, branches)
- Call-like ops (map-lookup, map-lookup-ptr, tail-call, etc.) must be in regalloc's call-positions list
- Shared definitions (helpers, constants, builtins) live in `compiler.lisp` — `lower.lisp` references them, not copies

## Benchmarks (nodeport-lb4)

Whistler: 76 instructions, clang -O2: 75 instructions.
