# Compilation Model

Whistler compiles Lisp s-expressions to eBPF bytecode through a 9-phase
pipeline. Full Common Lisp is available at compile time -- user-defined
macros, defconstant, defstruct, and import-kernel-struct all run during
the macroexpansion phase.

## Pipeline

```mermaid
graph LR
    A[Source] --> B[Load]
    B --> C[Macroexpand]
    C --> D[Constant Fold]
    D --> E[Lower to SSA IR]
    E --> F[SSA Optimize]
    F --> G[Register Alloc]
    G --> H[BPF Emit]
    H --> I[Peephole]
    I --> J[ELF Output]

    style A fill:#4a9eff,color:#fff
    style J fill:#2ecc71,color:#fff
```

### 1. Load

Read the source file. `defmap`, `defprog`, `defstruct`, `defconstant`,
and `deftracepoint` forms are evaluated, populating the compiler's map
and program tables.

### 2. Macroexpand

Recursively expand all macros in program bodies. Whistler built-in forms
(if, let, setf, load, store, etc.) and BPF helpers are recognized and
left intact. Everything else is expanded via `macroexpand-1`. This is
what makes Whistler a real Lisp -- user macros compose freely with
built-in forms.

### 3. Constant fold

Walk the expanded s-expression tree, replacing `defconstant` symbols with
their integer values and folding arithmetic on constant arguments
(+, -, *, /, <<, >>, &, |).

### 4. Lower to SSA IR

Translate surface-language forms into SSA (Static Single Assignment)
intermediate representation with virtual registers and basic blocks.
Each variable binding creates a fresh virtual register. Control flow
(if, when, cond, dotimes) creates basic blocks with branch/jump
instructions. Phi nodes are inserted at join points.

### 5. SSA optimize

Multiple optimization passes, run in sequence:

**Canonicalization (to fixed point):**
- Copy propagation
- Constant propagation
- Dead code elimination
- Dead destination elimination
- Eliminate trivial phis
- Simplify CFG
- Eliminate unreachable blocks

**Domain-specific folds:**
- Byte-swap comparison fusion (fold ntohs/ntohl into comparisons)
- Constant offset folding
- Tracepoint return elision

**Loop and memory:**
- Loop-invariant code motion
- Common subexpression elimination
- Forward stores to loads

**SCCP** (Sparse Conditional Constant Propagation):
- Propagate constants through phi nodes and fold unreachable branches

**Cleanup:**
- Dead code elimination
- Dead destination elimination
- Dead store elimination

**Cross-block fusions:**
- Lookup-delete fusion (merge map lookup + delete into single path)
- Hoist loads before helper calls
- Phi branch threading
- Bitmask check fusion
- Redundant branch cleanup

**Final:**
- Re-canonicalize after fusions
- Narrow ALU types (use 32-bit ops where safe)
- Split live ranges (improve register allocation)

### 6. Register allocation

Linear-scan register allocation with two pools:

| Pool          | Registers | Usage                          |
|---------------|-----------|--------------------------------|
| Callee-saved  | R6-R9     | Values live across helper calls |
| Caller-saved  | R1-R5     | Temporaries, helper arguments   |

R0 is reserved for helper return values and program exit code.
R10 is the read-only frame pointer.
R6 is reserved for the context pointer when needed.

When registers are exhausted, values spill to the 512-byte stack frame.
Spill decisions consider value classification (packet pointers are
expensive to spill; constants can be rematerialized).

### 7. BPF emission

Map allocated physical registers to BPF instructions. Handle stack
layout, map FD placeholder loading (for later relocation), and CO-RE
relocation tracking.

### 8. Peephole optimization

Post-emission cleanup on the BPF instruction list:

- Redundant mov elimination (`mov rX, rX`)
- Branch inversion (`jCC +1; ja +N` becomes `j!CC +N`)
- Jump-to-next elimination (`ja +0`)
- Jump threading (chains of unconditional jumps)
- Dead code after exit/unconditional jump
- Return value folding (`mov rX, IMM; mov r0, rX; exit` becomes
  `mov r0, IMM; exit`)
- Stack address folding
- Tail merge (identical exit sequences)

### 9. ELF emit

Write the final BPF instructions and metadata into an ELF64 relocatable
object file. See [ELF Output](./elf.md) for section details.

## BPF register table

| Register | Role                                    |
|----------|-----------------------------------------|
| R0       | Return value / helper return             |
| R1       | Argument 1 / context pointer on entry    |
| R2-R5    | Arguments 2-5 / caller-saved temporaries |
| R6-R9    | Callee-saved (preserved across calls)    |
| R10      | Frame pointer (read-only)                |

## eBPF constraints

```admonish warning title="Verifier Constraints"
The BPF verifier enforces these constraints on loaded programs:

- **No unbounded loops** -- all loops must have a provable upper bound
  (use `dotimes`).
- **No recursion** -- tail calls are the only inter-program control flow.
- **512-byte stack** -- total stack frame cannot exceed 512 bytes.
- **Pointer safety** -- all memory accesses must be bounds-checked.
  Packet data requires explicit bounds guards before the verifier
  allows access.
- **Helper restrictions** -- each program type has a specific set of
  allowed helpers. The verifier rejects calls to disallowed helpers.
```
