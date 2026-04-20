# Design: BTF-Driven Context Access

## Problem

Context struct fields are accessed via raw numeric offsets:

```lisp
(let ((ip   (ctx u32 4))    ; what is offset 4?
      (port (ctx u32 24)))  ; what is offset 24?
  (setf (ctx u32 4) +localhost-nbo+))
```

This is error-prone, unreadable, and breaks if the kernel changes
struct layouts across versions. The programmer must manually look up
offsets for each program type's context struct.

## Current State

- `(ctx TYPE OFFSET)` reads a context field, `(setf (ctx ...) ...)`
  writes. Both emit verifier-aware context loads/stores (not regular
  memory access).
- The `ctx` read path lowers positionally as `(ctx TYPE OFFSET)` in
  `src/lower.lisp:303`. The write path uses a fixed-arity
  `define-setf-expander` for `(ctx type offset)` in
  `src/whistler.lisp:372`. Both must be extended for field-name access.
- Context struct layouts (`bpf_sock_addr`, `__sk_buff`, `xdp_md`, etc.)
  are hardcoded as offset constants in each example.
- There is already partial context-layout knowledge in
  `src/lower.lisp` via `section-to-ctx-fields`, used for validation.
  This should be unified with the new lookup, not duplicated.
- Whistler already has BTF parsing (`src/btf.lisp`, `src/vmlinux.lisp`)
  and `import-kernel-struct` for kprobe/tracepoint field access.
  BTF is read from `/sys/kernel/btf/vmlinux` (not kernel headers).
- The program type (`:xdp`, `:cgroup-sock-addr`, etc.) determines
  which context struct the kernel expects, but `defprog` currently
  drops `:type` — only `:section`, `:license`, and `:body` are passed
  to `compile-program` and `lower-program`. Plumbing the program type
  through is a prerequisite.

## Proposed Design

### Field-name context access

`(ctx field-name)` looks up the field in the program type's context
struct, determines the type and offset, and emits the appropriate
context load:

```lisp
(defprog connect4 (:type :cgroup-sock-addr ...)
  ;; compiler knows ctx is bpf_sock_addr from program type
  (let ((ip   (ctx user-ip4))      ; -> (ctx u32 4)
        (port (ctx user-port)))    ; -> (ctx u32 24)
    (setf (ctx user-ip4) +localhost-nbo+)))
```

No offset constants, no type annotations.

**Portability caveat:** Until Phase 3 (CO-RE), offsets are resolved at
compile time from either the static table (Phase 1) or the build
host's BTF (Phase 2). The compiled program is tied to the kernel it
was built on. True compile-once portability requires CO-RE relocations.

### How it works

1. **Program type plumbing**: `defprog` must pass `:type` through
   `compile-program` → `lower-program` so the lowering phase knows
   which context struct to use. Currently these functions only receive
   `section`, `license`, `maps`, and `body`.

2. **Program type -> struct name mapping** (compile-time table):

   | Program type | Context struct |
   |-------------|---------------|
   | `:xdp` | `xdp_md` |
   | `:cgroup-skb` | `__sk_buff` |
   | `:cgroup-sock-addr` | `bpf_sock_addr` |
   | `:cgroup-sock` | `bpf_sock_ops` |
   | `:tc` | `__sk_buff` |
   | `:tracepoint` | (per-tracepoint, already handled separately) |

   Note: `:kprobe` maps to `pt_regs` which is architecture-specific
   (x86-64 vs aarch64 have different layouts). Kprobe context is
   already handled specially via `pt-regs-parm1` etc. Do not fold it
   into the generic field-name UX without explicitly deciding how
   architecture variants are represented.

3. **`ctx` form dispatch**: when the compiler sees `(ctx user-ip4)`,
   it checks whether the argument is a symbol (field name) or a type
   keyword (legacy numeric access):
   - Symbol: look up field in the context struct, lower to a
     context access **annotated with struct+field metadata**, not a
     bare offset. The IR carries `(:core struct-name field-name)`
     alongside the resolved type and offset, so Phase 3 CO-RE can
     emit relocations without re-deriving field identity. This
     matches how `core-ctx-load` already works in the pipeline
     (`src/lower.lisp:921`, `src/emit.lisp:745`).
   - Type keyword (`u32`, `u16`, ...): existing behavior, raw offset
     (no CO-RE metadata — the programmer chose explicit offsets)

   **Field type handling.** Context structs are flat — they contain
   scalars, fixed-size arrays of scalars, and pointer-to-struct fields.
   No nested struct traversal is needed. The three categories:

   - **Scalar fields** (`u8`, `u16`, `u32`, `u64`): `(ctx field-name)`
     emits a single context load. This covers the vast majority of
     fields.

   - **Array fields** (`__u32[4]` for IPv6 addresses, `__u32[5]` for
     `cb`, etc.): `(ctx field-name index)` emits an indexed context
     load at `base-offset + index * elem-size`. The index must be a
     compile-time constant (required by the verifier). Without an
     index, `(ctx field-name)` on an array field is a compile error.

     ```lisp
     (ctx user-ip6 0)   ; → (ctx u32 8)   — user_ip6[0]
     (ctx user-ip6 3)   ; → (ctx u32 20)  — user_ip6[3]
     (setf (ctx user-ip6 2) val)  ; write works the same way
     ```

   - **Pointer fields** (`struct bpf_sock *sk`, `void *skb_data`,
     etc.): `(ctx field-name)` loads the pointer as a raw `u64`
     scalar. The context access itself is just a u64 load — Whistler
     does not automatically attach pointee type information to the
     loaded value. To chase the pointer into a kernel struct, the
     programmer must use `import-kernel-struct` accessors with
     explicit type annotation, same as loading any other kernel
     pointer today. A future extension could add syntactic sugar
     (e.g., `(ctx-typed sk)` returning a value the macro system
     can track), but that is out of scope for this plan.

4. **`setf` expansion**: the `define-setf-expander` for `ctx`
   (`src/whistler.lisp:372`) must handle three shapes:
   - `(setf (ctx type offset) val)` — existing two-argument form
   - `(setf (ctx field-name) val)` — new single-argument scalar field
   - `(setf (ctx field-name index) val)` — new two-argument array field

   The expander must distinguish field-name forms (symbol first arg)
   from legacy forms (type keyword first arg), then resolve type and
   offset from the context struct table. For array fields, the index
   must be a compile-time constant.

5. **Unify with existing validation**: `section-to-ctx-fields` in
   `src/lower.lisp` already knows context layouts for validation.
   Replace it with a lookup into the same table used for field-name
   resolution, eliminating duplicate layout sources.

### Implementation plan

#### Phase 1: Static context struct definitions

Define the common context structs in Whistler as a compile-time table
(no BTF dependency). This is enough to eliminate magic offsets:

```lisp
;; In src/whistler.lisp or src/ctx-structs.lisp
(defparameter *ctx-struct-layouts*
  ;; Each field: (name type offset)
  ;; Array fields: (name (:array elem-type count) offset)
  ;; Pointer fields: (name :ptr offset)
  '(("bpf_sock_addr" . ((user-family u32 0)
                         (user-ip4    u32 4)
                         (user-ip6    (:array u32 4) 8)
                         (user-port   u32 24)
                         (family      u32 28)
                         (type        u32 32)
                         (protocol    u32 36)
                         (msg-src-ip4 u32 40)
                         (msg-src-ip6 (:array u32 4) 44)
                         (sk          :ptr 60)))
    ("__sk_buff"     . ((len       u32 0)
                         ...))
    ("xdp_md"        . ((data      u32 0)
                         (data-end  u32 4)
                         (data-meta u32 8)
                         ...))))
```

Required plumbing changes:
- `defprog` (`src/whistler.lisp:502`): pass `:type` to `compile-program`
- `compile-program` (`src/whistler.lisp:625`): forward to `lower-program`
- `lower-program` (`src/lower.lisp:114`): accept program type, store in
  lowering context
- `ctx` read lowering (`src/lower.lisp:303`): currently a fixed
  2-argument form `(ctx TYPE OFFSET)`. Must now handle three shapes:
  - `(ctx TYPE OFFSET)` — legacy, unchanged
  - `(ctx field-name)` — scalar field, resolve type+offset from table
  - `(ctx field-name index)` — array field, validate index is a
    compile-time constant, compute `base-offset + index * elem-size`,
    resolve element type from the array's element type
- `ctx` setf expander (`src/whistler.lisp:372`): handle all three
  setf shapes (see item 4 above)
- `section-to-ctx-fields` (`src/lower.lisp`): replace with unified lookup

**Portability:** Offsets are hardcoded in the compiler. The compiled
program only works on kernels where the struct layout matches. This is
the same as writing raw offsets today, just more readable.

#### Phase 2: BTF-driven resolution *(implemented)*

Context field resolution now uses BTF from `/sys/kernel/btf/vmlinux`
at compile time when available, via a resolver hook
(`*ctx-btf-resolver*`) installed by `src/vmlinux.lisp`. The resolver
calls `btf-ctx-struct-fields` which looks up the struct in the
kernel's BTF, resolves field types (scalars, arrays, pointers),
and flattens anonymous struct/union members.

Implementation:
- `btf-ctx-struct-fields` in `src/vmlinux.lisp` — BTF struct lookup
  returning fields in `*ctx-struct-fields*` format
- `btf-resolve-array` — resolves BTF array types to element type + count
- `btf-member-raw-type-id` — follows typedef chains without collapsing
- `*ctx-btf-resolver*` in `src/compiler.lisp` — callback hook, set at
  load time by `src/vmlinux.lisp`
- `*vmlinux-btf-path*` — override BTF path for cross-compilation
- `vmlinux-btf` struct now caches `type-data`, eliminating the
  redundant re-read in `btf-struct-fields`

**Resolution order:** BTF first, static table fallback. When BTF is
available, offsets reflect the build host's actual kernel layout.

**Portability:** Offsets are resolved from the build host's kernel BTF
and baked into the program. Compiled programs work only on the kernel
they were built on (or compatible ones). This is not compile-once
portability.

**Cross-compilation:** Set `*vmlinux-btf-path*` to point to the
target kernel's BTF blob. When BTF is unavailable (no vmlinux, no
override), the static table provides a fallback with standard offsets.

#### Phase 3: CO-RE relocation

For true compile-once portability, emit BPF CO-RE (Compile Once, Run
Everywhere) relocations instead of hardcoded offsets. The loader
(libbpf or Whistler's loader) patches offsets at load time based on
the target kernel's BTF.

Whistler has partial CO-RE infrastructure for **reads only**:
`lower-core-ctx-load` (`src/lower.lisp:921`) lowers to IR with
`(:core struct-name field-name)` metadata, and the emit path
(`src/emit.lisp:745`) consumes it to produce relocations. This
provides a model to follow for field-name context reads.

**Writes need new end-to-end support.** There is no `core-ctx-store`
in lowering, and `emit-ctx-store-insn` (`src/emit.lisp:767`) does not
consume `(:core ...)` metadata. Phase 3 must add the full write-side
CO-RE path: lowering with metadata, IR representation, and emission
with relocation records.

This is the target state. Once Phase 3 is done, `(ctx field-name)`
compiles to a relocatable access that works across kernel versions.

### Backward compatibility

- `(ctx u32 4)` continues to work (type keyword triggers legacy path)
- `(ctx user-ip4)` is the new form (symbol triggers field lookup)
- Existing code with `defconstant` offsets keeps working unchanged

### Files to modify

| File | Change |
|------|--------|
| `src/whistler.lisp` | Context struct table, prog-type plumbing in `defprog`/`compile-program`, `define-setf-expander` arity |
| `src/lower.lisp` | `ctx` form: detect symbol vs type keyword, unify `section-to-ctx-fields`, accept prog type in `lower-program` |
| `src/vmlinux.lisp` | BTF lookup for context structs (Phase 2) *(done)* |
| `src/emit.lisp` | CO-RE relocation emission (Phase 3) |
| `book/src/language/memory.md` | Document `(ctx field-name)` form |

### Open questions

- **Kprobe context**: `pt_regs` is architecture-specific. The existing
  `pt-regs-parm1` etc. accessors handle this with arch-conditional
  expansion. Should `(ctx field-name)` for kprobes use the same
  mechanism, or remain separate?

- **Tracepoint context**: already handled by `deftracepoint` which
  reads format files. Keep this separate or unify?

- **Nested field access**: BPF context structs can contain pointers
  to other kernel structs (e.g., `__sk_buff->sk`). Field-name access
  for the top-level struct is straightforward; chasing pointers into
  nested structs is a CO-RE concern and should wait for Phase 3.

### Example: cgroup-firewall after this change

```lisp
(defprog connect4 (:type :cgroup-sock-addr
                   :section "cgroup/connect4"
                   :license "GPL")
  (let* ((socket-cookie (get-socket-cookie (ctx-ptr)))
         (pid (cast u32 (>> (get-current-pid-tgid) 32)))
         (pid-key u64 socket-cookie))
    (map-update socket-pid-map pid-key pid 0)

    (let* ((user-ip4  (ctx user-ip4))
           (user-port (ctx user-port))
           (original-ip user-ip4)
           (original-port (ntohs (cast u16 user-port))))
      (cond
        ((or (= user-port (htons 80))
             (= user-port (htons 443)))
         (setf (ctx user-ip4) +localhost-nbo+)
         (when (= user-port (htons 80))
           (setf (ctx user-port) (htons 8080)))
         ...)))))
```

No `+sock-addr-user-ip4+` constants. No offset math. The compiler
resolves fields from the program type's context struct.
