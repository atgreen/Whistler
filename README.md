# Whistler

A Lisp that compiles to eBPF.

Whistler is a Common Lisp dialect for writing eBPF programs. It compiles
s-expressions directly to eBPF bytecode and emits valid ELF object files
loadable by the kernel — no C compiler, no clang, no LLVM in the pipeline.

```lisp
(defmap pkt-count :type :array
  :key-size 4 :value-size 8 :max-entries 1)

(defprog count-packets (:type :xdp :license "GPL")
  (incf (getmap pkt-count 0))
  XDP_PASS)
```

This compiles to 11 eBPF instructions and a valid BPF ELF object file.

## Why Whistler?

### Why use Whistler instead of `clang -target bpf`?

Whistler is built for the actual shape of eBPF programs: small,
verifier-constrained, repetitive, and highly pattern-driven.

- **Smaller toolchain, tighter feedback loop.** eBPF programs are usually tens
  to hundreds of instructions. Whistler compiles them directly without pulling
  in the full C/LLVM pipeline.
- **A language matched to the domain.** eBPF is full of explicit bounds checks,
  map lookups, helper calls, stack shaping, and verifier-visible control flow.
  Whistler exposes those concepts directly instead of encoding them indirectly
  through C.
- **Real metaprogramming.** eBPF code is full of recurring patterns: parse
  headers, validate packet bounds, look up state, fast-path success, bail out
  early. In Whistler, those become hygienic macros and compile-time
  abstractions instead of preprocessor tricks.
- **Compiler-aware abstractions.** Struct accessors, protocol helpers, and map
  operations are part of the language surface, so the compiler can optimize
  them intentionally rather than recovering patterns after C lowering.
- **Automatic CO-RE support.** Whistler preserves struct identity through the
  compiler pipeline and emits CO-RE relocations automatically, so portable
  struct access does not require extra ceremony in user code.
If you already have a C/libbpf workflow, Whistler is not trying to replace that
ecosystem wholesale. It is for cases where you want a language and compiler
designed around eBPF itself.

### What Whistler does differently

**The compiler is the language runtime.** Whistler source files are valid Common
Lisp. When you compile a Whistler program, the full power of Common Lisp is
available at compile time — real macros with hygiene, a REPL for interactive
development, and an actual language for code generation. At runtime, the output
is pure eBPF bytecode, indistinguishable from clang's output.

**The surface language is declarative.** Built-in macros erase BPF ceremony:

```lisp
;; incf on a map handles lookup, null check, atomic increment,
;; and initialization for new keys — all in one form.
(incf (getmap pkt-count 0))

;; with-tcp does bounds check, EtherType, and protocol check
;; as flat guards. No parse overhead.
(with-tcp (data data-end tcp)
  (when (= (tcp-dst-port tcp) 8080)
    (return XDP_DROP)))

;; if-let binds a map lookup result and branches on it.
(if-let (val (map-lookup my-map key))
  (atomic-add val 0 1)              ; key exists
  (setf (getmap my-map key) 1))     ; key is new
```

The last expression in a `defprog` body is implicitly returned — no need
for `(return XDP_PASS)` at the end.

**Zero dependencies for compilation.** The compiler is self-contained Common
Lisp. The ELF writer is hand-rolled (~400 lines). No libelf, no libbpf, no
kernel headers needed to compile. The output is a standard BPF ELF object that
any loader (bpftool, libbpf, ip link) can load.

**Polyglot header generation.** `--gen c`, `--gen go`, `--gen rust`, `--gen python`,
`--gen lisp` generate matching struct definitions from your `defstruct`
declarations — one source of truth for BPF and userspace.

**Pure CL userspace loader.** `whistler/loader` loads `.bpf.o` into the kernel,
attaches probes, reads maps, and consumes ring buffers — no libbpf, no C.
Or use `with-bpf-session` to compile and load BPF inline, in one Lisp form.

**The whole project is ~7,000 lines.** Compiler, loader, and session runtime.
You can read it in an afternoon. When the verifier rejects your program, you
can read the compiler to understand exactly what bytecode was generated and why.

### Compared to alternatives

| | Whistler | C + clang | BCC (Python) | Aya (Rust) | bpftrace |
|---|---|---|---|---|---|
| Toolchain size | ~3 MB (SBCL) | ~200 MB | ~100 MB | ~500 MB | ~50 MB |
| Compile-time metaprogramming | Full CL macros | `#define` | Python strings | `proc_macro` | none |
| Output | ELF .o | ELF .o | JIT loaded | ELF .o | JIT loaded |
| Compile-time language | Common Lisp | cpp | Python | Rust | n/a |
| Self-contained compiler | yes | no (needs LLVM) | no (needs kernel headers) | no (needs LLVM) | no |
| Interactive development | REPL | no | yes | no | yes |
| Code quality vs clang -O2 | **matches or beats** | baseline | n/a | comparable | n/a |
| Lines of compiler code | ~5,500 | ~50,000+ | n/a | ~20,000+ | n/a |

## Getting started

### Requirements

- [SBCL](http://www.sbcl.org/) (Steel Bank Common Lisp) 2.0+
- Linux with kernel 5.3+ (for bounded loop support)
- [FiveAM](https://github.com/lispci/fiveam) (for tests only)
- `readelf` / `llvm-objdump` (optional, for inspecting output)

### Build

```sh
make        # build standalone binary
make test   # run test suite (requires FiveAM)
make repl   # interactive REPL with Whistler loaded
```

### Compile an example

```sh
# Using the REPL:
make repl
* (load "examples/synflood-xdp.lisp")
* (compile-to-elf "synflood.bpf.o")
Compiled 1 program (74 instructions total), 2 maps → synflood.bpf.o

# Or from the command line:
./whistler compile examples/count-xdp.lisp -o count.bpf.o
```

### Load into the kernel

```sh
# Attach an XDP program to an interface
ip link set dev eth0 xdp obj count.bpf.o sec xdp

# Or load with bpftool
bpftool prog load count.bpf.o /sys/fs/bpf/count

# Monitor maps
bpftool map dump name pkt_count

# Detach
ip link set dev eth0 xdp off
```

### Permissions

BPF programs require elevated privileges to load. Instead of running as
root, grant capabilities to your SBCL binary:

```sh
# Allow BPF program loading and perf event attachment
sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/sbcl

# Allow reading tracepoint format files (for deftracepoint)
sudo chmod a+r /sys/kernel/tracing/events/sched/sched_switch/format
```

### Generate userspace headers

Whistler can generate matching struct definitions for your userland code from
the same `defstruct` definitions used in the BPF program — one source of truth
for both sides:

```sh
# Generate C header
./whistler compile probes.lisp --gen c        # → probes.h

# Generate for multiple languages at once
./whistler compile probes.lisp --gen c go rust python lisp

# Generate all supported languages
./whistler compile probes.lisp --gen all
```

Supported: **C**, **Go**, **Rust**, **Python**, **Common Lisp** (`--gen lisp`). Array fields
map to native syntax (`uint8_t field[16]` in C, `[16]uint8` in Go,
`[u8; 16]` in Rust). Struct layouts are guaranteed to match because they're
derived from the same `defstruct`.

## Language reference

### Program structure

Every Whistler source file is a Common Lisp file. Programs use two top-level
macros:

```lisp
(in-package #:whistler)

;; Declare BPF maps
(defmap my-map :type :hash
  :key-size 4 :value-size 8 :max-entries 1024)

;; Declare BPF programs
(defprog my-prog (:type :xdp :section "xdp" :license "GPL")
  ;; program body — Whistler forms
  (return XDP_PASS))
```

**Map types:** `:hash`, `:array`, `:percpu-hash`, `:percpu-array`, `:ringbuf`,
`:prog-array` (for tail calls), `:lpm-trie` (for CIDR matching)

**Program types:** `:xdp`, `:socket-filter`, `:tracepoint`, `:kprobe`

### Types

Types determine memory access width. Variables default to `u64` when no type
is specified:

| Type | Width | BPF size |
|------|-------|----------|
| `u8` / `i8` | 1 byte | `BPF_B` |
| `u16` / `i16` | 2 bytes | `BPF_H` |
| `u32` / `i32` | 4 bytes | `BPF_W` |
| `u64` / `i64` | 8 bytes | `BPF_DW` |

### Variable bindings

```lisp
;; let evaluates all inits before binding (standard CL semantics).
(let ((x (load u32 ptr 0))
      (y (load u32 ptr 4)))
  body...)

;; let* binds sequentially — each init can reference prior bindings.
(let* ((x 42)
       (y (+ x 1))
       (ptr (map-lookup my-map x)))
  body...)

;; Use (declare (type ...)) for sub-64-bit narrowing, just like CL.
(let ((port (load u16 tcp-ptr 2))
      (flags (tcp-flags tcp-ptr)))
  (declare (type u16 port) (type u8 flags))
  ...)

;; setf mutates a bound variable — supports multi-pair like CL
(setf x (+ x 1))
(setf (my-struct-a ptr) 1
      (my-struct-b ptr) 2)
```

Types default to `u64` when omitted. Use `(declare (type ...))` for sub-64-bit
narrowing where it matters (map keys, struct fields, protocol fields) — the
same form CL uses. The SSA pipeline's type narrowing pass will further optimize
ALU operations to 32-bit when safe.

### Control flow

```lisp
(if (> x 10) then-expr else-expr)

(when (= flags +tcp-syn+)
  body...)

(unless packet-valid
  (return XDP_DROP))

(cond
  ((= proto +ip-proto-tcp+) (handle-tcp))
  ((= proto +ip-proto-udp+) (handle-udp))
  (t (return XDP_PASS)))

;; Short-circuit boolean operators
(and (> x 0) (< x 100))   ; returns 0 or last truthy value
(or  cached (map-lookup m key))

(progn expr1 expr2 ...)    ; sequential execution, returns last
(return value)             ; set R0 and exit
```

### Arithmetic and logic

```lisp
;; Arithmetic (64-bit ALU, n-ary)
(+ a b c)  (- a b)  (* a b)  (/ a b)  (mod a b)

;; Bitwise
(logand a b)  (logior a b)  (logxor a b)
(<< val shift)  (>> val shift)  (>>> val shift)  ; arithmetic right shift

;; Comparison (returns 0 or 1)
(= a b)  (/= a b)  (> a b)  (>= a b)  (< a b)  (<= a b)
(s> a b) (s>= a b) (s< a b) (s<= a b)  ; signed comparison

(not expr)  ; 0→1, nonzero→0
```

### Memory access

```lisp
;; Load from pointer
(load u32 ptr offset)        ; *(u32 *)(ptr + offset)

;; Store to pointer
(store u32 ptr offset val)   ; *(u32 *)(ptr + offset) = val

;; Load from XDP context (struct xdp_md)
(ctx-load u32 0)             ; ctx->data
(ctx-load u32 4)             ; ctx->data_end

;; Atomic operations
(atomic-add ptr offset val)  ; lock *(u64 *)(ptr + offset) += val

;; Get pointer to stack variable (for passing to helpers)
(stack-addr var)

;; Type narrowing
(cast u16 expr)              ; mask to 0xffff
(cast u32 expr)              ; zero-extend 32-bit
```

### Structs and CO-RE

Define structs with C-compatible layout. `defstruct` generates CL-style
accessor functions and `setf` expanders. Scalar field accesses emit CO-RE
relocations, enabling cross-kernel portability.

```lisp
;; Define a struct — generates accessors and setf expanders
(defstruct ct-key
  (src-addr u32)
  (dst-addr u32)
  (src-port u16)
  (dst-port u16))

;; Allocate on stack, set fields with setf
(let ((key (make-ct-key)))
  (setf (ct-key-src-addr key) src-ip)
  (setf (ct-key-dst-addr key) dst-ip)
  ;; Read a field
  (ct-key-src-port key))
```

#### Array fields

Structs support fixed-size array fields with indexed access:

```lisp
(defstruct my-event
  (pid     u32)
  (data    (array u8 16)))

;; Indexed read/write — constant indices fold to fixed offsets
(my-event-data evt 5)                         ; read element 5
(setf (my-event-data evt 5) (cast u8 val))    ; write element 5

;; Pointer accessor — for passing array field addresses to BPF helpers
(get-current-comm (my-event-data-ptr evt) 16)
```

#### sizeof

```lisp
(sizeof my-event)                             ; → struct byte size (constant)
(probe-read-user buf (sizeof ffi-cif) ptr)    ; no more magic numbers
(ringbuf-reserve events (sizeof my-event) 0)
```

### Memory operations

```lisp
;; Fill memory (widened stores: 16 bytes of 0xFF = 2 u64 stores, not 16 u8)
(memset ptr offset value nbytes)

;; Copy memory (wide load/store pairs)
(memcpy dst dst-offset src src-offset nbytes)
```

All offsets and sizes must be compile-time constants.

### User-Space Iteration

Iterate over user-space arrays without manual pointer arithmetic:

```lisp
;; Array of pointers (e.g. ffi_type **): null-checked, each ptr bound
(do-user-ptrs (atype-ptr arg-types-ptr nargs +max-args+ :index i)
  (probe-read-user buf (sizeof ffi-type) atype-ptr)
  (use-field buf i))

;; Array of structs (e.g. struct event[]): each element read into buffer
(do-user-array (entry my-struct entries-ptr count +max-entries+ :index i)
  (my-struct-field entry))

;; Array of scalars (e.g. u32[]): each value bound directly
(do-user-array (val u32 array-ptr count +max-count+)
  (when (> val threshold) ...))
```

Both require a compile-time `max-count` for the BPF verifier and a runtime
`count` for the actual bound. Supply `:index name` to use the loop index.

### Ring Buffer

```lisp
;; Reserve, execute body, auto-submit on normal exit
(with-ringbuf (event events (sizeof my-event))
  (setf (my-event-type event) 1)
  ...)
;; No manual ringbuf-reserve / ringbuf-submit needed
```

### Process Metadata

```lisp
;; Fill pid, uid, timestamp, and comm in one form
(fill-process-info event
  :pid-field my-event-pid
  :uid-field my-event-uid
  :timestamp-field my-event-timestamp
  :comm-field my-event-comm-ptr)
```

### pt_regs access (x86-64)

Portable access to function arguments in uprobe/kprobe programs, matching
C's `PT_REGS_PARM1()` etc.:

```lisp
(pt-regs-parm1)    ; first arg (rdi)
(pt-regs-parm2)    ; second arg (rsi)
(pt-regs-parm3)    ; third arg (rdx)
(pt-regs-parm4)    ; fourth arg (rcx)
(pt-regs-parm5)    ; fifth arg (r8)
(pt-regs-parm6)    ; sixth arg (r9)
(pt-regs-ret)      ; return value (rax)
```

### Tracepoints

Auto-resolve tracepoint field offsets from the running kernel at compile time:

```lisp
;; Reads /sys/kernel/tracing/events/sched/sched_switch/format
(deftracepoint sched/sched-switch prev-pid prev-state next-pid)

;; Generates: (tp-prev-pid) → (ctx-load u32 24)
;;            (tp-prev-state) → (ctx-load u64 32)
;;            (tp-next-pid) → (ctx-load u32 56)
```

No hardcoded offsets — field positions come from your kernel's tracefs.

### Kernel struct import

Import kernel struct definitions from vmlinux BTF at compile time:

```lisp
;; Reads /sys/kernel/btf/vmlinux
(import-kernel-struct task_struct pid tgid flags)

;; Generates: (task-struct-pid ptr) → (load u32 ptr 2768)
;;            (task-struct-tgid ptr) → (load u32 ptr 2772)
;;            +task-struct-size+ → 9856
```

No kernel headers, no vmlinux.h — field offsets come from your kernel's BTF.

### Map operations

```lisp
;; High-level interface (like gethash / (setf (gethash ...)) / remhash)
(getmap map-name key)                     ; lookup + deref, 0 if not found
(setf (getmap map-name key) val)          ; insert or update (BPF_ANY)
(remmap map-name key)                     ; delete

;; Atomic increment (handles both array and hash maps)
(incf (getmap map-name key))
(incf (getmap map-name key) delta)    ; increment by delta

;; Low-level interface (returns raw pointers, supports flags)
(map-lookup map-name key-var)             ; → pointer or 0 (NULL)
(map-update map-name key-var val-var flags)
(map-delete map-name key-var)
```

Key and value arguments must be variables (the compiler takes their stack
address to pass to the BPF helper).

### Byte order

Network protocols use big-endian. eBPF runs on the host (usually little-endian).

```lisp
(ntohs expr)   ; network-to-host 16-bit byte swap
(ntohl expr)   ; network-to-host 32-bit byte swap
(htons expr)   ; host-to-network 16-bit (same operation)
(htonl expr)   ; host-to-network 32-bit
```

### Bounded loops

eBPF requires provably bounded iteration. The count must be a compile-time
constant.

```lisp
(dotimes (i 16)
  ;; i is bound as u32, counts from 0 to 15
  body...)
```

### BPF helper calls

BPF helpers are called directly by name in function position (Lisp-2 style):

```lisp
;; Call any BPF helper by name (up to 5 arguments)
(ktime-get-ns)
(trace-printk fmt-ptr fmt-len arg1)
(redirect ifindex flags)
(get-smp-processor-id)
```

### Inline assembly

Escape hatch for instructions the compiler doesn't cover:

```lisp
(asm opcode dst-reg src-reg offset immediate)
```

### Tail calls

BPF tail calls transfer execution to another program in a program array map.
If the target index is invalid or no program is loaded, execution continues
normally (no crash).

```lisp
(defmap jump-table :type :prog-array
  :key-size 4 :value-size 4 :max-entries 256)

;; Dispatch to protocol-specific handler
(tail-call jump-table protocol-index)
;; Falls through here if no handler loaded for that index
XDP_PASS
```

### Multi-program ELF

Multiple `defprog` forms compile into a single ELF object with separate
sections. All programs share the same maps.

```lisp
(defmap stats :type :array :key-size 4 :value-size 8 :max-entries 2)

(defprog dispatcher (:section "xdp" :license "GPL")
  (tail-call jump-table 0)
  XDP_PASS)

(defprog handler (:section "xdp/handler" :license "GPL")
  (incf (getmap stats 0))
  XDP_PASS)

(compile-to-elf "output.bpf.o")  ; both programs in one ELF
```

### Protocol headers

Whistler includes compile-time protocol header definitions. These expand to
`(load TYPE ptr OFFSET)` with automatic byte-order conversion — zero runtime
cost.

```lisp
;; Named field access (all compile-time macros)
(eth-type data)              ; EtherType with ntohs
(ipv4-src-addr ip-ptr)       ; source IP (network order, for map keys)
(ipv4-protocol ip-ptr)       ; IP protocol number
(tcp-dst-port tcp-ptr)       ; destination port with ntohs
(tcp-flags tcp-ptr)          ; TCP flags byte
(udp-src-port udp-ptr)       ; source port with ntohs

;; Parsing macros with automatic bounds checking
(with-packet (data data-end :min-len 64)
  body...)

(with-ipv4 (data data-end ip)
  ;; ip is bound to the start of the IPv4 header
  ;; bounds check and EtherType check done automatically
  body...)

(with-tcp (data data-end tcp)
  ;; tcp is bound to the start of the TCP header
  ;; bounds check + EtherType + protocol check done automatically
  body...)
```

Define your own protocol headers:

```lisp
(defheader my-proto
  (field-a :offset 0 :type u32)
  (field-b :offset 4 :type u16 :net-order t))
;; Generates: (my-proto-field-a ptr) and (my-proto-field-b ptr)
```

### Macros

Since Whistler source files are Common Lisp, you can define macros with
`defmacro`. They are expanded at compile time before eBPF code generation.

```lisp
;; Define reusable patterns
(defmacro bump-counter (map idx)
  `(incf (getmap ,map ,idx)))

;; Use them — expands to the same code you'd write by hand
(bump-counter stats 0)

;; Generate code programmatically
(defmacro check-ports (tcp &rest ports)
  `(or ,@(mapcar (lambda (p) `(= (tcp-dst-port ,tcp) ,p)) ports)))

(when (check-ports tcp 80 443 8080)
  (return XDP_DROP))
```

### Constants

Use `defconstant` for compile-time constants. They are inlined as immediates
in the generated bytecode.

```lisp
(defconstant +threshold+ 1000)

;; In the program body, +threshold+ becomes: mov64 reg, 1000
(if (> count +threshold+) ...)
```

Built-in constants: `XDP_ABORTED`, `XDP_DROP`, `XDP_PASS`, `XDP_TX`,
`XDP_REDIRECT`, `BPF_ANY`, `BPF_NOEXIST`, `BPF_EXIST`, `NULL`.

## Examples

### Packet counter

Whistler: **11 instructions** · clang -O2: **11 instructions**

<table>
<tr><th>Whistler</th><th>C + clang</th></tr>
<tr><td valign="top">

```lisp
(defmap pkt-count :type :array
  :key-size 4 :value-size 8
  :max-entries 1)

(defprog count-packets
    (:type :xdp :license "GPL")
  (incf (getmap pkt-count 0))
  XDP_PASS)
```

</td><td valign="top">

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1);
} pkt_count SEC(".maps");

SEC("xdp")
int count_packets(struct xdp_md *ctx) {
  __u32 key = 0;
  __u64 *val = bpf_map_lookup_elem(
                 &pkt_count, &key);
  if (val)
    __sync_fetch_and_add(val, 1);
  return XDP_PASS;
}
```

</td></tr>
</table>

### Port blocker

Whistler: **25 instructions** · clang -O2: **26 instructions**

<table>
<tr><th>Whistler</th><th>C + clang</th></tr>
<tr><td valign="top">

```lisp
(defmap drop-count :type :array
  :key-size 4 :value-size 8
  :max-entries 1)

(defprog drop-port
    (:type :xdp :license "GPL")
  (with-tcp (data data-end tcp)
    (when (= (tcp-dst-port tcp) 9999)
      (incf (getmap drop-count 0))
      (return XDP_DROP)))
  XDP_PASS)
```

</td><td valign="top">

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1);
} drop_count SEC(".maps");

SEC("xdp")
int drop_port(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *end  = (void *)(long)ctx->data_end;
  if (data + sizeof(struct ethhdr)
      + sizeof(struct iphdr)
      + sizeof(struct tcphdr) > end)
    return XDP_PASS;
  struct ethhdr *eth = data;
  if (eth->h_proto != htons(ETH_P_IP))
    return XDP_PASS;
  struct iphdr *ip = data + sizeof(*eth);
  if (ip->protocol != IPPROTO_TCP)
    return XDP_PASS;
  struct tcphdr *tcp = (void *)ip
                       + sizeof(*ip);
  if (ntohs(tcp->dest) == 9999) {
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(
                   &drop_count, &key);
    if (val)
      __sync_fetch_and_add(val, 1);
    return XDP_DROP;
  }
  return XDP_PASS;
}
```

</td></tr>
</table>

### SYN flood mitigation

Whistler: **65 instructions** · clang -O2: **68 instructions**

<table>
<tr><th>Whistler</th><th>C + clang</th></tr>
<tr><td valign="top">

```lisp
(defmap syn-counter :type :hash
  :key-size 4 :value-size 8
  :max-entries 32768)
(defmap syn-stats :type :array
  :key-size 4 :value-size 8
  :max-entries 3)

(defconstant +syn-threshold+ 100)

(defprog synflood
    (:type :xdp :license "GPL")
  (with-tcp (data data-end tcp)
    (when (= (logand (tcp-flags tcp)
                     #x12)
             +tcp-syn+)
      (incf (getmap syn-stats 0))
      (let ((src (ipv4-src-addr
                   (+ data
                      +eth-hdr-len+))))
        (if-let (p (map-lookup
                     syn-counter src))
          (if (> (load u64 p 0)
                 +syn-threshold+)
            (progn
              (incf (getmap syn-stats 1))
              (return XDP_DROP))
            (atomic-add p 0 1))
          (progn
            (incf (getmap syn-stats 2))
            (setf (getmap syn-counter
                          src) 1))))))
  XDP_PASS)
```

</td><td valign="top">

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 32768);
} syn_counter SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 3);
} syn_stats SEC(".maps");

static void bump_stat(void *map, __u32 idx) {
  __u64 *val = bpf_map_lookup_elem(
                 map, &idx);
  if (val)
    __sync_fetch_and_add(val, 1);
}

#define SYN_THRESHOLD 100
#define TCP_SYN 0x02
#define TCP_ACK 0x10

SEC("xdp")
int synflood(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *end  = (void *)(long)ctx->data_end;
  if (data + sizeof(struct ethhdr)
      + sizeof(struct iphdr)
      + sizeof(struct tcphdr) > end)
    return XDP_PASS;
  struct ethhdr *eth = data;
  if (eth->h_proto != htons(ETH_P_IP))
    return XDP_PASS;
  struct iphdr *ip = data + sizeof(*eth);
  if (ip->protocol != IPPROTO_TCP)
    return XDP_PASS;
  struct tcphdr *tcp = (void *)ip
                       + sizeof(*ip);
  __u8 flags = ((__u8 *)tcp)[13];
  if (!(flags & TCP_SYN)
      || (flags & TCP_ACK))
    return XDP_PASS;

  bump_stat(&syn_stats, 0);

  __u32 src = ip->saddr;
  __u64 *count = bpf_map_lookup_elem(
                   &syn_counter, &src);
  if (count) {
    if (*count > SYN_THRESHOLD) {
      bump_stat(&syn_stats, 1);
      return XDP_DROP;
    }
    __sync_fetch_and_add(count, 1);
  } else {
    bump_stat(&syn_stats, 2);
    __u64 init = 1;
    bpf_map_update_elem(&syn_counter,
      &src, &init, BPF_ANY);
  }
  return XDP_PASS;
}
```

</td></tr>
</table>

## Userspace loader (`whistler/loader`)

A pure Common Lisp BPF loader — no libbpf, no CFFI, no C dependencies.
Load `.bpf.o` files, create maps, attach probes, and consume ring buffers
from SBCL:

```lisp
(asdf:load-system "whistler/loader")

(whistler/loader:with-bpf-object (obj "my-probes.bpf.o")
  (whistler/loader:attach-obj-kprobe obj "trace_execve" "__x64_sys_execve")
  (let* ((map (whistler/loader:bpf-object-map obj "stats"))
         (val (whistler/loader:map-lookup map #(0 0 0 0))))
    (when val
      (format t "count: ~d~%" (whistler/loader:decode-int-value val)))))
```

### Inline BPF sessions

Write BPF programs and userspace code in the same Lisp form. The BPF code
compiles at macroexpand time; the bytecode is embedded as a literal:

```lisp
(whistler/loader:with-bpf-session ()
  ;; Kernel side — compiled to eBPF at macroexpand time
  (bpf:map counter :type :hash :key-size 4 :value-size 8 :max-entries 1024)
  (bpf:prog trace (:type :kprobe :section "kprobe/__x64_sys_execve" :license "GPL")
    (incf (getmap counter 0))
    0)

  ;; Userspace side — normal CL at runtime
  (bpf:attach trace "__x64_sys_execve")
  (loop (sleep 1)
        (format t "count: ~d~%" (bpf:map-ref counter 0))))
```

No `.bpf.o` files, no build step, no separate loader binary. One file, one language.

### Struct decode/encode

`whistler:defstruct` generates both BPF macros and a CL struct with
byte-level codec — one definition serves both kernel and userspace:

```lisp
(whistler:defstruct my-event
  (pid u32) (comm (array u8 16)) (data u64))

;; BPF side: (make-my-event), (my-event-pid ptr), (setf (my-event-pid ptr) val)
;; CL side:  (decode-my-event bytes) → my-event-record struct
;;           (my-event-record-pid rec), (my-event-record-comm rec)
;;           (encode-my-event rec) → bytes (round-trips perfectly)
```

See `examples/ffi-call-tracker.lisp` for a complete standalone example.

## Author

Whistler was created by [Anthony Green](https://github.com/atgreen).

## License

MIT

Note: The compiler itself is MIT-licensed. BPF programs compiled by Whistler
typically use `license "GPL"` in their `defprog` because the kernel requires
GPL for BPF programs that call GPL-only helpers.
