# Whistler

A Lisp that compiles to eBPF.

Whistler is a Common Lisp dialect for writing eBPF programs. It compiles
s-expressions directly to eBPF bytecode and emits valid ELF object files
loadable by the kernel — no C compiler, no clang, no LLVM in the pipeline.

```lisp
(in-package #:whistler)

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
- **Optimization for eBPF specifically.** The backend is tuned around eBPF
  realities like helper clobbers, stack-slot reuse, map-fd caching, and
  instruction-count pressure, rather than being a general optimizer retargeted
  to BPF.

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

**The whole compiler is ~5,500 lines.** You can read it in an afternoon. Compare
with the clang/LLVM BPF backend. When the verifier rejects your program, you
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
- `readelf` / `llvm-objdump` (optional, for inspecting output)

### Build

```sh
make        # build standalone binary
make test   # run test suite (14 tests)
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
;; Standard CL let bindings — types default to u64.
(let ((x 42)
      (y (+ x 1))
      (ptr (map-lookup my-map x)))
  body...)

;; Use (declare (type ...)) for sub-64-bit narrowing, just like CL.
(let ((port (load u16 tcp-ptr 2))
      (flags (tcp-flags tcp-ptr)))
  (declare (type u16 port) (type u8 flags))
  ...)

;; setf mutates a bound variable
(setf x (+ x 1))
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
accessor functions and `setf` expanders. All field accesses emit CO-RE
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

XDP context accessors (`xdp-data`, `xdp-data-end`) also emit CO-RE relocations
for the kernel's `xdp_md` struct, so field offsets are patched automatically by
libbpf at load time.

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

## Internals

### Architecture

The SSA-based optimizing pipeline matches or beats `clang -O2` on instruction
count.

```
Whistler source (.lisp)
  → CL macroexpand (user macros, protocol macros)
  → Lowering to SSA IR (virtual registers, basic blocks, φ-functions)
  → SSA optimization passes:
      copy propagation → constant propagation → offset folding →
      dead code elimination → lookup-delete fusion → load hoisting →
      PHI-branch threading → bitmask-check fusion
  → Linear-scan register allocation (callee-saved / caller-saved pools)
  → BPF instruction emission from SSA IR
  → Peephole optimization (redundant mov/jump elimination, tail merging)
  → CO-RE relocation tracking (struct field access → .BTF.ext records)
  → ELF emission (sections, symbols, relocations, .BTF, .BTF.ext)
  → .bpf.o (loadable by bpftool / ip link / libbpf)
```

### Project structure

```
whistler/
├── whistler.asd       ASDF system definition
├── src/
│   ├── packages.lisp      Package definitions
│   ├── bpf.lisp           eBPF instruction encoding and constants
│   ├── btf.lisp           BTF and BTF.ext (CO-RE) encoder
│   ├── elf.lisp           ELF object file writer (no dependencies)
│   ├── compiler.lisp      Shared definitions, macro expansion, constant folding
│   ├── ir.lisp            SSA IR data structures (basic blocks, instructions)
│   ├── lower.lisp         S-expression → SSA IR lowering
│   ├── ssa-opt.lisp       SSA optimization passes
│   ├── regalloc.lisp      Linear-scan register allocator
│   ├── emit.lisp          SSA IR → BPF instruction emission
│   ├── peephole.lisp      Post-regalloc peephole optimizer
│   ├── whistler.lisp      Top-level API (defmap, defprog, CLI)
│   ├── protocols.lisp     Surface language macros + protocol headers
│   └── codegen.lisp       Shared header generation (C, Go, Rust, Python, CL)
├── examples/
│   ├── count-xdp.lisp              Packet counter (11 insns)
│   ├── drop-port.lisp              Port blocker (37 insns)
│   ├── ratelimit-xdp.lisp          Per-IP rate limiter (62 insns)
│   ├── synflood-xdp.lisp           SYN flood filter (74 insns)
│   ├── runqlat.lisp                 Run queue latency histogram (57 insns)
│   ├── tail-call-dispatch.lisp      Protocol dispatch via tail calls (26 insns)
│   └── multi-prog.lisp             Multi-program ELF (2 programs, 44 insns)
└── tests/
    ├── test.lisp             14 tests
    └── test-ssa.lisp         SSA pipeline integration test
```

## License

MIT

Note: The compiler itself is MIT-licensed. BPF programs compiled by Whistler
typically use `license "GPL"` in their `defprog` because the kernel requires
GPL for BPF programs that call GPL-only helpers.
