# Whistler

Whistler is a Common Lisp compiler that produces eBPF bytecode. You write
s-expressions, the compiler emits valid ELF object files, and your kernel loads
them directly. There is no LLVM, no kernel headers, no CFFI. The entire
compiler is self-contained SBCL code.

```lisp
(defmap pkt-count :type :array
  :key-size 4 :value-size 8 :max-entries 1)

(defprog count-packets (:type :xdp :license "GPL")
  (incf (getmap pkt-count 0))
  XDP_PASS)
```

This compiles to 11 eBPF instructions and a valid BPF ELF object file.

## Why Whistler

eBPF programs are small, verifier-constrained, and pattern-driven. They parse
headers, validate bounds, look up state in maps, and emit events. These
recurring patterns make eBPF a natural fit for a high-level language with real
metaprogramming -- not string concatenation or preprocessor macros, but a
compiler that understands the domain.

### Real metaprogramming

Whistler programs are Common Lisp. CL macros are hygienic, composable, and
operate on the AST at compile time. A `with-tcp` macro that parses Ethernet,
IP, and TCP headers with bounds checks is not a preprocessor trick -- it is a
function that generates verified code and participates in the compiler pipeline.

### No C toolchain

The compiler is approximately 7,000 lines of SBCL. It includes its own ELF
writer, BTF encoder, and peephole optimizer. You do not need clang, LLVM,
libelf, or kernel headers installed.

### Compiler-aware abstractions

Struct accessors, protocol helpers, and map operations are part of the
language. The compiler optimizes them intentionally rather than recovering
patterns after C lowering. `(incf (getmap m k))` compiles to an atomic
add on the map value -- the compiler knows the idiom.

### Automatic CO-RE

Struct identity is preserved through the compilation pipeline. When you use
`import-kernel-struct` to access kernel data structures, the compiler emits
CO-RE relocations automatically. No manual `BPF_CORE_READ` calls.

### Interactive REPL development

Compile, load, attach, inspect maps, iterate -- all from one Lisp image.
Change a BPF program, recompile, and reload without leaving your REPL session.

## Comparison

| | Whistler | C + clang | BCC (Python) | Aya (Rust) | bpftrace |
|---|---|---|---|---|---|
| Toolchain size | ~3 MB (SBCL) | ~200 MB | ~100 MB | ~500 MB | ~50 MB |
| Metaprogramming | Full CL macros | `#define` | Python strings | `proc_macro` | none |
| Output format | ELF .o | ELF .o | JIT loaded | ELF .o | JIT loaded |
| Self-contained compiler | yes | no (needs LLVM) | no (needs kernel headers) | no (needs LLVM) | no |
| Interactive development | REPL | no | yes | no | yes |
| Code quality vs clang -O2 | matches or beats | baseline | n/a | comparable | n/a |

Whistler matches clang -O2 instruction counts on real programs. On the
Cilium `nodeport-lb4` load balancer (a complex production BPF program),
Whistler produces 76 instructions to clang's 75.

## The userspace loader

`whistler/loader` is a pure Common Lisp BPF loader. No libbpf, no CFFI.
It parses `.bpf.o` files, creates maps via `bpf()` syscalls, loads programs
into the kernel, attaches them (kprobe, uprobe, tracepoint, XDP, TC, cgroup),
and consumes ring buffers -- all from SBCL.

You can also use inline BPF sessions that compile and load in the same form:

```lisp
(whistler/loader:with-bpf-session ()
  ;; Kernel side -- compiled to eBPF at macroexpand time
  (bpf:map counter :type :hash
    :key-size 4 :value-size 8 :max-entries 1024)
  (bpf:prog trace (:type :kprobe
                    :section "kprobe/__x64_sys_execve"
                    :license "GPL")
    (incf (getmap counter 0))
    0)

  ;; Userspace side -- normal CL at runtime
  (bpf:attach trace "__x64_sys_execve")
  (loop (sleep 1)
        (format t "count: ~d~%" (bpf:map-ref counter 0))))
```

One file, one language, no intermediate artifacts.
