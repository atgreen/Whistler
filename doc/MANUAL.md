# Whistler Language Manual

## Overview

Whistler is a Lisp that compiles to eBPF bytecode. Programs are written as
Common Lisp s-expressions and compiled to ELF object files containing eBPF
instructions. The full power of Common Lisp is available at compile time
(macros, code generation, the REPL); at runtime, only eBPF bytecode executes
in the kernel.

This document covers every form the compiler accepts, the compilation model,
and the constraints imposed by the eBPF virtual machine.

## Compilation model

### Phases

1. **Load** — The source file is loaded as Common Lisp. `defmap` and `defprog`
   macros register map and program definitions.
2. **Macroexpand** — The compiler walks the program body and expands all CL
   macros (user-defined macros, protocol macros from `protocols.lisp`).
   Whistler built-in forms (`let`, `if`, `when`, `map-lookup`, etc.) are NOT
   expanded — they are compiled directly.
3. **Constant fold** — `defconstant` symbols are resolved to integer values
   and arithmetic on constants is evaluated at compile time.
4. **Lower to SSA IR** — The macro-expanded s-expression tree is lowered to an
   intermediate representation with virtual registers, basic blocks, explicit
   control flow edges, and φ-functions at join points.
5. **SSA optimize** — Optimization passes run in sequence:
   - Copy propagation
   - Constant propagation
   - Byte-swap comparison folding (eliminates runtime bswap when comparing
     against constants)
   - Constant offset folding (folds pointer arithmetic into load offsets)
   - Tracepoint return elision
   - Dead code elimination
   - Dead destination elimination
   - Dead store elimination (byte-level coverage tracking)
   - Lookup-delete fusion (dominance-based, merges map-lookup + map-delete)
   - Load hoisting (moves loads before helper calls when safe)
   - PHI-branch threading (eliminates redundant branches via φ-function analysis)
   - Bitmask-check fusion (combines mask + compare into single test)
   - ALU type narrowing (promotes 32-bit ALU when operands are ≤32 bits)
   - Live-range splitting (rematerialization of constants and reloadable values)
6. **Register allocation** — Linear-scan allocator over SSA liveness intervals
   with two register pools (callee-saved R6-R9 for values live across helper
   calls, caller-saved R0-R5 for short-lived values), stack spilling, value
   classification, and spill-cost heuristics. A backend portfolio tries
   multiple allocation policies and keeps the best result.
7. **BPF emission** — SSA IR with physical register assignments is emitted as
   eBPF instructions. Includes map-fd caching (reuses callee-saved registers
   for frequently referenced maps), struct key pointer caching, and CO-RE
   relocation tracking.
8. **Peephole optimization** — Post-emission pass eliminates redundant moves,
   unreachable code, and merges common tail sequences.
9. **ELF emit** — Instructions, map definitions, relocations, BTF, BTF.ext,
   and metadata are written to an ELF object file. Supports multiple programs
   per ELF.

### Register allocation

eBPF has 11 registers:

| Register | Purpose | Lifetime |
|----------|---------|----------|
| R0 | Return value, helper call results | Clobbered by calls |
| R1–R5 | Helper call arguments, temporaries | Clobbered by calls |
| R6–R9 | Callee-saved registers | Preserved across calls |
| R10 | Frame pointer (read-only) | Immutable |

The linear-scan register allocator manages two pools:

- **Callee-saved pool (R6–R9):** Assigned to virtual registers whose liveness
  intervals span helper calls. R6 is reserved for the context pointer when the
  program uses `ctx-load` after a helper call; otherwise R6 is available for
  general allocation.
- **Caller-saved pool (R0–R5):** Assigned to short-lived virtual registers that
  don't survive across calls. When this pool is exhausted, the allocator
  overflows into the callee-saved pool before spilling.

When all registers are exhausted, values are spilled to the stack frame. The
allocator classifies values (packet pointer, hot scalar, recomputable,
helper-setup, temporary) and uses spill-cost heuristics to choose candidates.
Rematerializable values (constants, loads from stable pointers) are preferred
for spilling since they can be recomputed instead of reloaded. The eBPF stack
is limited to 512 bytes.

### eBPF constraints

The kernel's BPF verifier enforces:

- **No unbounded loops.** `dotimes` requires a compile-time constant bound.
- **No recursion.** Programs are straight-line or branching, not recursive.
- **512-byte stack limit.** The compiler tracks stack usage and errors if
  exceeded.
- **Pointer safety.** All memory accesses must be within bounds. Use
  `with-packet` / `with-ipv4` / etc. to satisfy the verifier's bounds checks.
- **Helper restrictions.** Some helpers are only available to certain program
  types. The kernel verifier enforces this at load time.

## Top-level declarations

### defmap

```lisp
(defmap name :type TYPE [:key-size N] [:value-size N] :max-entries N
        [:map-flags FLAGS])
```

Declares a BPF map. Emitted as a map definition in the ELF `maps` section.

**Parameters:**
- `:type` — One of `:hash`, `:array`, `:percpu-hash`, `:percpu-array`,
  `:ringbuf`, `:prog-array`, `:lpm-trie`
- `:key-size` — Key size in bytes (default 0, omit for ringbuf)
- `:value-size` — Value size in bytes (default 0, omit for ringbuf)
- `:max-entries` — Maximum number of entries
- `:map-flags` — Optional flags (e.g., `1` for `BPF_F_NO_PREALLOC` with LPM trie)

Ring buffer maps only need type and max-entries:
```lisp
(defmap events :type :ringbuf :max-entries 262144)
```

### defprog

```lisp
(defprog name (&key (type :xdp) (section nil) (license "GPL"))
  body...)
```

Declares a BPF program. The body consists of Whistler forms that are compiled
to eBPF instructions. The last expression is implicitly returned — no need
for `(return ...)` unless returning early.

Multiple `defprog` forms compile into a single ELF with separate sections.

**Parameters:**
- `:type` — Program type: `:xdp`, `:socket-filter`, `:tracepoint`, `:kprobe`
- `:section` — ELF section name (defaults to lowercase type name)
- `:license` — License string (must be `"GPL"` for GPL-only helpers)

### defstruct

```lisp
(defstruct name
  (field1 type1)
  (field2 type2)
  (field3 (array elem-type count))
  ...)
```

Defines a BPF struct with C-compatible layout (natural alignment, padding).
Field types can be scalar (`u8`, `u16`, `u32`, `u64`) or fixed-size arrays
(`(array type count)`).

Generates for BPF:

- `(make-NAME)` — Allocates the struct on the stack, returns a pointer.
- `(NAME-FIELD ptr)` — Reads a scalar field.
- `(setf (NAME-FIELD ptr) val)` — Writes a scalar field (auto-truncates to field width).
- `(NAME-FIELD ptr idx)` — Reads an array element. Constant indices fold to
  fixed offsets; runtime indices compute the offset dynamically.
- `(setf (NAME-FIELD ptr idx) val)` — Writes an array element.
- `(NAME-FIELD-PTR ptr)` — Returns a pointer to the array field start.
  Useful for passing to BPF helpers.

Generates for CL userspace:

- `NAME-RECORD` — CL `defstruct` with matching slots.
- `(decode-NAME bytes)` — Decode a byte array into a `NAME-RECORD` struct.
- `(encode-NAME record)` — Encode a `NAME-RECORD` back to bytes.
- `(NAME-RECORD-FIELD record)` — Standard CL struct accessors.

This lets both BPF code and userspace decode the same struct layout from
a single definition.

Example:

```lisp
(defstruct my-event
  (pid       u32)
  (comm      (array u8 16))
  (data      (array u8 32)))

(let ((evt (make-my-event)))
  (setf (my-event-pid evt) (cast u32 (get-current-pid-tgid)))
  ;; Pass array pointer to helper
  (get-current-comm (my-event-comm-ptr evt) 16)
  ;; Indexed array access
  (setf (my-event-data evt 0) 42))
```

### sizeof

```lisp
(sizeof struct-name)
```

Returns the byte size of a struct at compile time. Replaces magic numbers
in `probe-read-user`, `ringbuf-reserve`, etc.

```lisp
(probe-read-user buf (sizeof my-struct) ptr)
(ringbuf-reserve events (sizeof my-event) 0)
```

## Forms

### Literals

- **Integers** — Decimal or hex (`42`, `0xff`). 32-bit values use `MOV64_IMM`,
  larger values use `LD_IMM64` (2-instruction sequence).
- **nil** — Compiles to `MOV64_IMM reg, 0`.
- **Symbols** — Looked up as: (1) built-in constants (`XDP_PASS`, etc.),
  (2) `defconstant` values (inlined at compile time), (3) bound variables.

### Variable binding

```lisp
;; Types are optional — default to u64 when omitted.
(let ((data (xdp-data))
      (count (load u32 ptr 0))
      (flags (tcp-flags tcp)))
  body...)

;; Use (declare (type ...)) for sub-64-bit narrowing when needed.
(let ((port (load u16 ptr 2))
      (proto (ipv4-protocol ip)))
  (declare (type u16 port))
  body...)
```

Types are inferred from initializers when possible: `(load u32 ...)` → u32,
`(ctx-load u32 ...)` → u32, `(cast u16 ...)` → u16, `(ntohs ...)` → u16,
`(ntohl ...)` → u32, `(get-prandom-u32)` → u32. Everything else defaults
to u64. Use `(declare (type TYPE var ...))` at the start of the let body
when the type cannot be inferred (integer literals, arithmetic results).

`let` evaluates all init forms before binding any variables (standard CL
semantics). Use `let*` when each initializer needs to reference prior
bindings in the same form.

### Mutation

```lisp
(setf var expr)
(setf place1 val1 place2 val2 ...)   ; multi-pair, like CL
```

Updates bound variables or struct fields. Multi-pair `setf` evaluates and
assigns each pair left to right. Works with accessor places:

```lisp
(setf (my-struct-field ptr) 42
      (my-struct-other ptr) 0)
```

### Control flow

```lisp
(if test then-form else-form)
```

When `test` is a comparison form (`>`, `=`, etc.), the compiler emits a single
conditional jump. Otherwise, the test is evaluated and compared against zero.

```lisp
(when test body...)         ; if test is truthy, execute body
(unless test body...)       ; if test is falsy, execute body
```

```lisp
(when-let ((var init) ...) body...)
```

Binds variables and executes body only if all values are non-nil. Accepts
both `(var init)` and `(var type init)` bindings.

```lisp
(if-let (var init) then else)
```

Binds a variable and branches on its value. Accepts both `(var init)`
and `(var type init)`.

```lisp
(cond
  (test1 body1...)
  (test2 body2...)
  ...
  (t default-body...))
```

Multi-way conditional. Compiles to a chain of conditional jumps.

```lisp
(case key-expr
  (value1 body1...)
  ((v2 v3) body2...)      ; multiple values
  (t default...))
```

Multi-way dispatch on a value. Shadows CL's `case`.

```lisp
(and expr1 expr2 ...)      ; short-circuit: returns 0 on first falsy
(or  expr1 expr2 ...)      ; short-circuit: returns first truthy value
```

```lisp
(progn expr1 expr2 ...)    ; evaluate sequentially, return last
(return expr)              ; set R0 to expr value and exit
(return)                   ; set R0 to 0 and exit
```

### Arithmetic

All arithmetic is 64-bit (`BPF_ALU64`). The SSA optimizer narrows to 32-bit
ALU when operand types allow.

```lisp
(+ a b)        ; add (n-ary)
(- a b)        ; subtract
(- a)          ; negate
(* a b)        ; multiply
(/ a b)        ; unsigned divide
(mod a b)      ; unsigned modulo
(incf var)     ; increment variable by 1
(incf var n)   ; increment variable by n
(decf var)     ; decrement variable by 1
```

### Bitwise operations

```lisp
(logand a b)   ; AND
(logior a b)   ; OR
(logxor a b)   ; XOR
(<< a n)       ; left shift
(>> a n)       ; logical right shift (unsigned)
(>>> a n)      ; arithmetic right shift (signed)
```

### Comparison

Returns 1 if true, 0 if false. When used as the test in `if` / `when` /
`unless`, the compiler emits a direct conditional jump instead.

```lisp
;; Unsigned
(= a b)   (/= a b)   (> a b)   (>= a b)   (< a b)   (<= a b)

;; Signed
(s> a b)  (s>= a b)  (s< a b)  (s<= a b)
```

### Logic

```lisp
(not expr)     ; 0 → 1, nonzero → 0
```

### Memory access

```lisp
(load type ptr offset)       ; *(type *)(ptr + offset)
(store type ptr offset val)  ; *(type *)(ptr + offset) = val
(ctx-load type offset)       ; load from context (R1/R6 + offset)
(stack-addr var)             ; pointer to var's stack slot (&var)
(atomic-add ptr offset val)  ; lock *(u64 *)(ptr + offset) += val
```

`type` is one of: `u8`, `u16`, `u32`, `u64`, `i8`, `i16`, `i32`, `i64`.

### Memory operations

```lisp
(memset ptr offset value nbytes)
```

Fill NBYTES bytes at PTR+OFFSET with VALUE. OFFSET and NBYTES must be
compile-time constants. When VALUE is a compile-time integer, the macro uses
widened stores for efficiency (e.g., 16 bytes of `#xFF` becomes 2 u64 stores
instead of 16 u8 stores). Values like `#xFF` (widened to -1) use `mov`
instead of `ld_imm64` for optimal codegen.

```lisp
(memcpy dst dst-offset src src-offset nbytes)
```

Copy NBYTES bytes from SRC+SRC-OFFSET to DST+DST-OFFSET. All offsets and
NBYTES must be compile-time constants. Uses the widest possible loads/stores.

### pt_regs access (x86-64)

Portable access to function arguments in uprobe/kprobe programs:

```lisp
(pt-regs-parm1)   ; first function arg (rdi, offset 112)
(pt-regs-parm2)   ; second function arg (rsi, offset 104)
(pt-regs-parm3)   ; third function arg (rdx, offset 96)
(pt-regs-parm4)   ; fourth function arg (rcx, offset 88)
(pt-regs-parm5)   ; fifth function arg (r8, offset 72)
(pt-regs-parm6)   ; sixth function arg (r9, offset 64)
(pt-regs-ret)     ; return value (rax, offset 80)
```

These match the C macros `PT_REGS_PARM1()` etc. from `bpf_tracing.h`,
using x86-64 System V ABI register offsets into `struct pt_regs`.

### Type operations

```lisp
(cast u8 expr)     ; AND with 0xff
(cast u16 expr)    ; AND with 0xffff
(cast u32 expr)    ; 32-bit MOV (zero-extends)
(cast u64 expr)    ; no-op
```

### Byte-order conversion

```lisp
(ntohs expr)   (htons expr)     ; 16-bit byte swap
(ntohl expr)   (htonl expr)     ; 32-bit byte swap
(ntohll expr)  (htonll expr)    ; 64-bit byte swap
```

Emits the BPF `END` instruction with the appropriate width. When a byte-swap
result is compared against a constant, the compiler folds the swap into the
constant at compile time, eliminating the runtime instruction.

### Map operations

#### Low-level interface

```lisp
(map-lookup map-name key-expr)     ; → pointer or 0 (NULL)
(map-update map-name key val flags) ; insert/update
(map-delete map-name key-expr)     ; delete entry
```

Calls `bpf_map_lookup_elem`, `bpf_map_update_elem`, `bpf_map_delete_elem`.
Key and value expressions must be variables (the compiler takes their stack
address). Flags: `BPF_ANY` (0), `BPF_NOEXIST` (1), `BPF_EXIST` (2).

For struct keys already on the stack, use the pointer variants:

```lisp
(map-lookup-ptr map-name key-ptr)
(map-update-ptr map-name key-ptr val-ptr flags)
(map-delete-ptr map-name key-ptr)
```

#### High-level interface

```lisp
(getmap map-name key)                 ; lookup + deref, 0 if not found
(setf (getmap map-name key) val)      ; insert or update (BPF_ANY)
(remmap map-name key)                 ; delete entry
(incf (getmap map-name key))          ; atomic increment
(incf (getmap map-name key) delta)    ; atomic increment by delta
```

These mirror CL's `gethash` / `(setf (gethash ...))` / `remhash` pattern.
`incf` on a getmap place uses `map-lookup` + `atomic-add` for existing
entries, and `map-update` to initialize new entries in hash maps.

**Struct keys:** When a map's `:key-size` exceeds 8 bytes, all high-level
macros (`getmap`, `setmap`, `incf`, `remmap`, `delmap`) automatically use the
`-ptr` variants at compile time — no source changes needed. The key expression
should be a struct pointer (from `make-*`).

#### Ring buffer operations

```lisp
(ringbuf-reserve map-name size flags) ; → pointer or NULL
(ringbuf-submit ptr flags)            ; submit reserved data
(ringbuf-discard ptr flags)           ; discard reserved data
```

```lisp
(with-ringbuf (var map-name size [:flags 0])
  body...)
```

Reserve a ring buffer entry, execute `body`, and auto-submit on normal exit.
`var` is bound to the reserved pointer (guaranteed non-null inside `body`).
If reserve fails, `body` is skipped. Use `(ringbuf-discard var 0)` before
`(return ...)` if you need to abort inside `body`.

#### Process metadata

```lisp
(fill-process-info event
  :pid-field STRUCT-PID
  :uid-field STRUCT-UID
  :timestamp-field STRUCT-TIMESTAMP
  :comm-field STRUCT-COMM-PTR
  :comm-size 16)
```

Fill common process metadata fields in a struct. Each keyword names the
struct accessor to use. All fields are optional. Expands to
`get-current-pid-tgid`, `get-current-uid-gid`, `ktime-get-ns`, and
`get-current-comm` calls as needed.

### Tail calls

```lisp
(tail-call prog-array-map index)
```

Transfers execution to the program at `index` in a `:prog-array` map. If the
index is out of range or no program is loaded at that slot, execution
continues normally (falls through). The target program receives the same
context as the caller.

```lisp
(defmap jt :type :prog-array :key-size 4 :value-size 4 :max-entries 256)

(defprog dispatcher (:section "xdp")
  (tail-call jt (ipv4-protocol ip))
  XDP_PASS)
```

### BPF helper calls

```lisp
(helper-name arg1 arg2 ...)
```

BPF helpers are called directly by name in function position (Lisp-2 style).
Arguments are loaded into R1–R5 (max 5). The return value is in R0.

```lisp
(let ((ts (ktime-get-ns)))         ; get current timestamp
  (trace-printk fmt fmt-len ts))   ; print to trace pipe
(redirect ifindex 0)               ; redirect packet
```

**Available helpers:**

| Name | ID | Description |
|------|----|-------------|
| `map-lookup-elem` | 1 | Map lookup |
| `map-update-elem` | 2 | Map update |
| `map-delete-elem` | 3 | Map delete |
| `probe-read` | 4 | Read kernel memory |
| `ktime-get-ns` | 5 | Monotonic clock (nanoseconds) |
| `trace-printk` | 6 | Debug printf to trace pipe |
| `get-prandom-u32` | 7 | Pseudo-random u32 |
| `get-smp-processor-id` | 8 | Current CPU ID |
| `tail-call` | 12 | Tail call to program in prog-array |
| `get-current-pid-tgid` | 14 | Current PID/TGID |
| `get-current-uid-gid` | 15 | Current UID/GID |
| `get-current-comm` | 16 | Current process name |
| `redirect` | 23 | Redirect packet to interface |
| `perf-event-output` | 25 | Send data to userspace perf ring |
| `probe-read-str` | 45 | Read kernel string |
| `get-current-cgroup-id` | 80 | Current cgroup ID |
| `probe-read-user` | 112 | Read user memory |
| `probe-read-user-str` | 114 | Read user string |
| `ringbuf-output` | 130 | Output to ring buffer |
| `ringbuf-reserve` | 131 | Reserve ring buffer space |
| `ringbuf-submit` | 132 | Submit ring buffer reservation |
| `ringbuf-discard` | 133 | Discard ring buffer reservation |

### Bounded loops

```lisp
(dotimes (var count)
  body...)
```

Iterates `count` times with `var` bound as a `u32` counting from 0 to
`count - 1`. The count MUST be a compile-time constant (integer literal or
`defconstant` value) — this is required for the BPF verifier to prove
termination.

### User-space iteration

```lisp
(do-user-ptrs (ptr-var base-ptr count max-count [:index i]) body...)
```

Iterate over a user-space array of pointers (e.g. `ffi_type **`). For each
non-null pointer within `count` elements (up to the compile-time constant
`max-count`), binds `ptr-var` to the pointer value and executes `body`.
Supply `:index name` to bind the loop index.

Expands to a bounded `dotimes` with `probe-read-user` for each 8-byte
pointer, a runtime count guard, and a null check.

```lisp
(do-user-ptrs (atype-ptr arg-types-ptr nargs +max-args+ :index i)
  (probe-read-user buf (sizeof ffi-type) atype-ptr)
  (setf (my-key-field key i) (cast u8 (ffi-type-code buf))))
```

```lisp
(do-user-array (var type base-ptr count max-count [:index i]) body...)
```

Iterate over a user-space array of `type` elements, where `type` is a scalar
(`u8`, `u16`, `u32`, `u64`) or a struct name. For scalar types, `var` is
bound to the loaded value. For struct types, `var` is bound to a stack buffer
pointer that is overwritten each iteration.

```lisp
;; Array of structs
(do-user-array (entry my-struct entries-ptr count +max+ :index i)
  (my-struct-field entry))

;; Array of scalars
(do-user-array (val u32 array-ptr count +max+)
  (when (> val threshold) ...))
```

### Inline assembly

```lisp
(asm opcode dst-reg src-reg offset immediate)
```

Emits a single raw BPF instruction. All arguments are integer constants. Use
the BPF opcode encoding from the kernel headers. This is an escape hatch for
instructions the compiler does not directly support.

## Kernel integration

### deftracepoint

```lisp
(deftracepoint category/event-name [field1 field2 ...])
```

Reads the tracepoint format file from tracefs at macroexpand time and generates
`ctx-load` accessor macros named `tp-FIELD`. If no field names are given, all
non-common fields are imported.

```lisp
(deftracepoint sched/sched-switch prev-pid prev-state next-pid)
;; Generates: (tp-prev-pid), (tp-prev-state), (tp-next-pid)
```

The format file path is
`/sys/kernel/tracing/events/{category}/{event}/format`. Requires read
permission on the file (default is root-only; use `chmod a+r` to allow
non-root compilation).

Array fields generate a `-ptr` accessor instead of a value accessor.

### import-kernel-struct

```lisp
(import-kernel-struct struct-name [field1 field2 ...])
```

Reads `/sys/kernel/btf/vmlinux` at macroexpand time and generates `load`
accessor macros for the specified kernel struct fields. If no field names are
given, all scalar fields are imported.

```lisp
(import-kernel-struct task_struct pid tgid flags)
;; Generates: (task-struct-pid ptr), (task-struct-tgid ptr),
;;            (task-struct-flags ptr), +task-struct-size+
```

BTF types are resolved through typedefs, const, volatile, etc. to the
underlying scalar type. Pointer fields become `u64`. The struct's total size
is available as `+NAME-SIZE+`.

### Permissions

BPF operations require Linux capabilities:

- **`CAP_BPF`** — load programs, create maps
- **`CAP_PERFMON`** — attach to perf events (kprobes, uprobes, tracepoints)

Grant them to SBCL instead of running as root:

```sh
sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/sbcl
```

Tracepoint format files and vmlinux BTF are readable by root by default.
To allow non-root compilation:

```sh
sudo chmod a+r /sys/kernel/tracing/events/sched/sched_switch/format
# vmlinux BTF is typically world-readable already
```

## Protocol library

The protocol library (`protocols.lisp`) provides compile-time macros for
parsing network packet headers. All accessors expand to `(load ...)` at compile
time — there is no runtime overhead.

### defheader

```lisp
(defheader name
  (field-name :offset N :type TYPE [:net-order BOOL])
  ...)
```

Defines a protocol header. For each field, generates a macro `(NAME-FIELD-NAME ptr)`
that expands to `(load TYPE ptr OFFSET)`. If `:net-order t` is specified, the
accessor wraps the load in `ntohs` or `ntohl` as appropriate.

### Built-in headers

**Ethernet** — `eth-type`, `eth-dst-mac-hi`, `eth-dst-mac-lo`,
`eth-src-mac-hi`, `eth-src-mac-lo`

**IPv4** — `ipv4-ver-ihl`, `ipv4-tos`, `ipv4-total-len`, `ipv4-id`,
`ipv4-frag-off`, `ipv4-ttl`, `ipv4-protocol`, `ipv4-checksum`,
`ipv4-src-addr`, `ipv4-dst-addr`

**TCP** — `tcp-src-port`, `tcp-dst-port`, `tcp-seq`, `tcp-ack-seq`,
`tcp-data-off`, `tcp-flags`, `tcp-window`, `tcp-checksum`, `tcp-urgent`

**UDP** — `udp-src-port`, `udp-dst-port`, `udp-length`, `udp-checksum`

**IPv6** — `ipv6-ver-tc-flow`, `ipv6-payload-len`, `ipv6-nexthdr`,
`ipv6-hop-limit`, `ipv6-src-addr-hi`, `ipv6-src-addr-lo`,
`ipv6-dst-addr-hi`, `ipv6-dst-addr-lo`

**ICMP** — `icmp-type`, `icmp-code`, `icmp-checksum`, `icmp-rest`

### XDP context accessors

```lisp
(xdp-data)         ; load ctx->data (with CO-RE relocation for xdp_md)
(xdp-data-end)     ; load ctx->data_end (with CO-RE relocation)
```

These emit CO-RE relocations for the kernel's `xdp_md` struct, so field
offsets are patched automatically by libbpf at load time.

### Parsing macros (statement-oriented)

These macros parse headers with automatic bounds checking and early return
on failure. They produce flat guard control flow (each check jumps directly
to the exit), which is optimal for the BPF verifier.

```lisp
(with-packet (data data-end :min-len N) body...)
(with-eth (data data-end) body...)
(with-ipv4 (data data-end ip-var) body...)
(with-tcp (data data-end tcp-var) body...)
(with-udp (data data-end udp-var) body...)
```

### Parsing macros (expression-oriented)

These return a pointer (or 0 on failure) and can be used in `when-let`:

```lisp
(parse-eth data data-end)     ; → data or 0
(parse-ipv4 data data-end)    ; → ip-ptr or 0
(parse-tcp data data-end)     ; → tcp-ptr or 0
(parse-udp data data-end)     ; → udp-ptr or 0
```

Note: the `with-*` macros produce better code because they generate flat
guard control flow. The `parse-*` macros create intermediate phi nodes.

### Protocol constants

```lisp
;; EtherTypes
+ethertype-ipv4+    ; 0x0800
+ethertype-ipv6+    ; 0x86dd
+ethertype-arp+     ; 0x0806

;; Header lengths (bytes)
+eth-hdr-len+       ; 14
+ipv4-hdr-len+      ; 20 (minimum, without options)
+tcp-hdr-len+       ; 20 (minimum)
+udp-hdr-len+       ; 8

;; IP protocols
+ip-proto-icmp+     ; 1
+ip-proto-tcp+      ; 6
+ip-proto-udp+      ; 17

;; TCP flags
+tcp-fin+  +tcp-syn+  +tcp-rst+  +tcp-psh+  +tcp-ack+  +tcp-urg+
```

## Macros

Whistler macros are standard Common Lisp macros defined with `defmacro`. They
are expanded at compile time before eBPF code generation.

The macro expander walks the program body tree. It expands any macro that is
NOT a Whistler built-in form. This means:

- `when`, `unless`, `and`, `or` etc. are compiler primitives — they are NOT
  CL macros, even though CL has macros with the same names.
- User-defined macros expand normally.
- Protocol library macros (`with-tcp`, `ipv4-src-addr`, etc.) expand normally.
- `(setf (accessor ...))` forms are expanded via CL's `defsetf` machinery
  before the Whistler compiler sees them.

### Defining macros

```lisp
(defmacro with-map-value ((var map key) &body body)
  `(let ((,var (map-lookup ,map ,key)))
     (when ,var ,@body)))

(with-map-value (ptr my-map key)
  (atomic-add ptr 0 1))
```

Since the full CL runtime is available at macro-expansion time, macros can
perform arbitrary computation:

```lisp
(defmacro define-port-checker (name &rest ports)
  `(defmacro ,name (tcp-ptr)
     `(or ,,@(mapcar (lambda (p) ``(= (tcp-dst-port ,,tcp-ptr) ,,p)) ports))))
```

## ELF output

The compiler produces standard ELF64 relocatable objects with `EM_BPF` (247)
machine type. Multiple programs compile into a single ELF with separate
sections.

| Section | Content |
|---------|---------|
| Program sections (e.g. `xdp`, `xdp/handler`) | BPF instruction bytecode |
| `maps` | Map definitions (32 bytes each, shared across programs) |
| `license` | Null-terminated license string |
| `.BTF` | BTF type information (base types, structs, xdp_md, FUNC) |
| `.BTF.ext` | BTF extensions (func_info per program, CO-RE relocations) |
| `.symtab` | Symbol table (section syms, map syms, FUNC syms per program) |
| `.strtab` | String table |
| `.rel<section>` | Relocations per program section for map fd references |
| `.shstrtab` | Section name strings |

Relocations use `R_BPF_64_64` type for map fd fixups. The loader (bpftool,
libbpf, etc.) creates the maps, obtains their file descriptors, and patches
the `LD_IMM64` instructions.

## Shared header generation

The `--gen` CLI flag generates matching type definitions for userland code:

```
whistler compile prog.lisp --gen c          # → prog.h
whistler compile prog.lisp --gen go         # → prog_types.go
whistler compile prog.lisp --gen rust       # → prog_types.rs
whistler compile prog.lisp --gen python     # → prog_types.py
whistler compile prog.lisp --gen lisp       # → prog_types.lisp
whistler compile prog.lisp --gen all        # → all of the above
```

Generated headers contain struct definitions (including array fields) and
`defconstant` values from the source file, translated to the target
language's idiom. Array fields map to native array syntax in each language:
`uint8_t field[16]` (C), `[16]uint8` (Go), `[u8; 16]` (Rust),
`ctypes.c_uint8 * 16` (Python). Struct layouts are guaranteed to match the
BPF side because they are derived from the same `defstruct` definitions.

## CLI reference

```
whistler --version                          # version info
whistler --help                             # usage
whistler compile INPUT [-o OUTPUT] [--gen LANG...]
whistler disasm INPUT                       # disassemble to stdout
```

When `-o` is omitted, the output path is derived from the input file
(`.lisp` → `.bpf.o`).

## Userspace loader (`whistler/loader`)

A pure Common Lisp BPF loader. No libbpf, no CFFI — uses SBCL's `sb-alien`
for direct syscall access.

### Loading `.bpf.o` files

```lisp
(asdf:load-system "whistler/loader")

;; Load and auto-close
(whistler/loader:with-bpf-object (obj "my-prog.bpf.o")
  ;; obj has maps created, programs loaded
  ...)

;; Or manual lifecycle
(let ((obj (whistler/loader:open-bpf-object "my-prog.bpf.o")))
  (whistler/loader:load-bpf-object obj)
  ...
  (whistler/loader:close-bpf-object obj))
```

### Attachment

```lisp
(whistler/loader:attach-kprobe prog-fd function-name)
(whistler/loader:attach-uprobe prog-fd binary-path symbol-name)
(whistler/loader:attach-xdp prog-fd interface-name)
```

### Map operations

```lisp
(whistler/loader:map-lookup map-info key-bytes)    ; → value-bytes or nil
(whistler/loader:map-update map-info key val)
(whistler/loader:map-delete map-info key)
(whistler/loader:map-get-next-key map-info key)    ; → next-key or nil
```

### Ring buffer

```lisp
(let ((consumer (whistler/loader:open-ring-consumer map-info callback)))
  (loop (whistler/loader:ring-poll consumer :timeout-ms 1000))
  (whistler/loader:close-ring-consumer consumer))
```

### Inline BPF sessions

Compile BPF code at macroexpand time and load at runtime — no files:

```lisp
(whistler/loader:with-bpf-session ()
  ;; BPF side (compiled at macroexpand time, bytecode embedded as literal)
  (bpf:map stats :type :hash :key-size 4 :value-size 8 :max-entries 1024)
  (bpf:prog counter (:type :kprobe :section "kprobe/..." :license "GPL")
    (incf (getmap stats 0)) 0)

  ;; CL side (normal runtime code)
  (bpf:attach counter "__x64_sys_execve")
  (loop (sleep 1) (format t "~d~%" (bpf:map-ref stats 0))))
```

The `bpf:` prefix separates kernel-side forms from userspace code. The
compiler runs during macroexpansion; the expanded code contains the raw
bytecode as a literal array. `unwind-protect` closes all resources on exit.

## Cookbook

Worked examples showing how Whistler forms compose into complete programs.

### Tracepoint with ring buffer events

The most common pattern: attach to a kernel tracepoint, build a struct,
send it to userspace via a ring buffer.

```lisp
(in-package #:whistler)

;; 1. Define the event struct. This generates both BPF accessors
;;    (make-conn-event, conn-event-src-addr, setf expanders) and
;;    CL-side codec (decode-conn-event → conn-event-record struct).
(defstruct conn-event
  (src-addr u32)
  (dst-addr u32)
  (dst-port u16)
  (proto    u8)
  (pad      u8))    ; align to 12 bytes

;; 2. Declare maps. Ring buffers need :max-entries (buffer size in bytes)
;;    but not :key-size or :value-size.
(defmap events :type :ringbuf :max-entries 4096)

;; 3. Write the program. with-tcp does bounds + EtherType + protocol
;;    checks automatically. with-ringbuf handles reserve/null-check/submit.
(defprog event-logger (:type :xdp :section "xdp" :license "GPL")
  (with-tcp (data data-end tcp)
    (let ((flags (tcp-flags tcp)))
      ;; Only new connections: SYN set, ACK not set
      (when (and (logand flags +tcp-syn+)
                 (not (logand flags +tcp-ack+)))
        (let ((ip (+ data +eth-hdr-len+)))
          (with-ringbuf (event events (sizeof conn-event))
            (setf (conn-event-src-addr event) (ipv4-src-addr ip)
                  (conn-event-dst-addr event) (ipv4-dst-addr ip)
                  (conn-event-dst-port event) (tcp-dst-port tcp)
                  (conn-event-proto event) +ip-proto-tcp+))))))
  XDP_PASS)

(compile-to-elf "events.bpf.o")
```

Key points:
- `with-tcp` expands to bounds check → EtherType check → protocol check,
  all as flat guards with early return. Zero overhead beyond what you'd
  write by hand.
- `with-ringbuf` reserves space, executes the body, and submits on normal
  exit. If the reserve fails (buffer full), the body is skipped.
- `sizeof` is a compile-time constant — no runtime cost.
- The same `defstruct` drives both the BPF accessors and the CL-side
  `decode-conn-event` for reading events in userspace.

### Kernel struct traversal

Reading kernel data structures from kprobes/tracepoints. This is the
get-current-task → import-kernel-struct → kernel-load chain.

```lisp
(in-package #:whistler)

;; 1. Import kernel struct fields from vmlinux BTF. This reads
;;    /sys/kernel/btf/vmlinux at compile time and generates accessors
;;    that use kernel-load (probe-read-kernel under the hood).
(import-kernel-struct task_struct pid tgid real_parent)

;; 2. Define the event we'll send to userspace.
(defstruct exec-event
  (pid  u32)
  (ppid u32)
  (comm (array u8 16)))

(defmap events :type :ringbuf :max-entries 16384)

;; 3. Attach to execve. get-current-task returns a kernel pointer;
;;    the imported accessors use probe-read-kernel automatically.
(defprog trace-exec (:type :kprobe
                     :section "kprobe/__x64_sys_execve"
                     :license "GPL")
  (let* ((task   (get-current-task))
         (pid    (task-struct-tgid task))       ; safe: uses kernel-load
         (parent (task-struct-real-parent task)) ; pointer to parent task
         (ppid   (task-struct-tgid parent)))    ; read parent's tgid
    (with-ringbuf (event events (sizeof exec-event))
      (setf (exec-event-pid event) pid
            (exec-event-ppid event) ppid)
      (get-current-comm (exec-event-comm-ptr event) 16)))
  0)

(compile-to-elf "exec-trace.bpf.o")
```

Key points:
- `import-kernel-struct` reads offsets from your running kernel's BTF,
  so the program is portable across kernel versions (CO-RE).
- The generated accessors (`task-struct-pid`, etc.) use `kernel-load`,
  which expands to `probe-read-kernel` into a stack buffer. This is
  required because the BPF verifier won't allow direct loads from
  kernel pointers.
- Pointer chasing works naturally: `task-struct-real-parent` returns a
  kernel pointer, and you can pass it directly to another accessor.
- `get-current-comm` writes the process name into an array field via
  the `-ptr` accessor (`exec-event-comm-ptr`).

### XDP with tail call dispatch

Split packet processing across multiple programs using tail calls.
A dispatcher reads the protocol and jumps into the appropriate handler.

```lisp
(in-package #:whistler)

;; Jump table: IP protocol number → handler program FD.
;; Populated at load time by bpftool or libbpf.
(defmap jt :type :prog-array
  :key-size 4 :value-size 4 :max-entries 256)

;; Per-protocol counters (shared across all programs in the ELF).
(defmap stats :type :array
  :key-size 4 :value-size 8 :max-entries 3)

(defconstant +stat-dispatched+ 0)
(defconstant +stat-tcp+        1)
(defconstant +stat-udp+        2)

;; Dispatcher — the XDP entry point.
(defprog xdp-dispatch (:type :xdp :section "xdp" :license "GPL")
  (let ((data     (xdp-data))
        (data-end (xdp-data-end)))
    (when (> (+ data 34) data-end)
      (return XDP_PASS))
    (when (/= (eth-type data) +ethertype-ipv4+)
      (return XDP_PASS))
    (let ((proto (ipv4-protocol (+ data +eth-hdr-len+))))
      (declare (type u32 proto))
      (incf (getmap stats +stat-dispatched+))
      ;; Tail call into the handler. If no program is loaded for
      ;; this protocol number, execution falls through to XDP_PASS.
      (tail-call jt proto)))
  XDP_PASS)

;; TCP handler — loaded into jt[6] at runtime.
(defprog tcp-handler (:type :xdp :section "xdp/tcp" :license "GPL")
  (incf (getmap stats +stat-tcp+))
  ;; ... TCP-specific processing ...
  XDP_PASS)

;; UDP handler — loaded into jt[17] at runtime.
(defprog udp-handler (:type :xdp :section "xdp/udp" :license "GPL")
  (incf (getmap stats +stat-udp+))
  ;; ... UDP-specific processing ...
  XDP_PASS)

;; All three programs compile into one ELF, sharing maps.
(compile-to-elf "dispatch.bpf.o")
```

Key points:
- Multiple `defprog` forms compile into a single ELF with separate
  sections. Maps are shared.
- `tail-call` transfers execution to the program at the given index
  in the prog-array map. It's a zero-cost jump — no new stack frame.
- If the index is out of range or no program is loaded there,
  execution continues normally. This makes tail calls safe as a
  dispatch mechanism.
- At load time, populate the jump table:
  ```sh
  bpftool prog load dispatch.bpf.o /sys/fs/bpf/dispatch
  bpftool map update name jt key 6 0 0 0 \
    value pinned /sys/fs/bpf/dispatch/tcp_handler
  bpftool map update name jt key 17 0 0 0 \
    value pinned /sys/fs/bpf/dispatch/udp_handler
  ```

### Inline session: compile, load, and trace from one file

No intermediate `.bpf.o` file. The BPF program compiles at macroexpand
time and loads at runtime, all from one Lisp form.

```lisp
(asdf:load-system "whistler/loader")

(defpackage #:my-tracer
  (:use #:cl #:whistler #:whistler/loader)
  (:shadowing-import-from #:whistler #:incf #:decf)
  (:shadowing-import-from #:cl #:case #:defstruct))

(in-package #:my-tracer)

(whistler:defstruct call-event
  (pid u32) (comm (array u8 16)))

(defun run ()
  (with-bpf-session ()
    ;; BPF side — compiled at macroexpand time
    (bpf:map events :type :ringbuf :max-entries 16384)
    (bpf:prog trace (:type :kprobe
                      :section "kprobe/__x64_sys_execve"
                      :license "GPL")
      (with-ringbuf (evt events (sizeof call-event))
        (fill-process-info evt
          :pid-field call-event-pid
          :comm-field call-event-comm-ptr))
      0)

    ;; CL side — runs at runtime
    (bpf:attach trace "__x64_sys_execve")
    (format t "Tracing execve. Ctrl-C to stop.~%")
    (let ((ring (bpf:map-ref events)))
      (handler-case
          (loop (ring-poll ring :timeout-ms 1000))
        (sb-sys:interactive-interrupt ()
          (format t "~&Done.~%"))))))

(run)
```

Key points:
- `with-bpf-session` scopes the entire lifecycle: compile, load,
  attach, and auto-cleanup on exit.
- The `bpf:` prefix marks kernel-side declarations. Everything else
  is normal CL that runs at runtime.
- `(:shadowing-import-from #:whistler #:incf #:decf)` resolves the
  CL/Whistler symbol conflict when embedding in your own package.
- `fill-process-info` fills pid/uid/timestamp/comm from BPF helpers
  in one form, using your struct's accessor names.
