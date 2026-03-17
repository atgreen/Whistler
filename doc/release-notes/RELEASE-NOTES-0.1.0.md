# Whistler 0.1.0

Initial release. A Lisp that compiles to eBPF.

## Features

### Compiler
- SSA-based optimizing compiler producing code that matches or beats `clang -O2`
- 14 optimization passes: copy/constant propagation, bswap folding, dead code/store elimination, lookup-delete fusion, load hoisting, PHI-branch threading, bitmask fusion, ALU narrowing, live-range splitting
- Linear-scan register allocator with value classification, rematerialization, and backend portfolio search
- Peephole optimizer with tail merging, branch inversion, dead jump elimination
- Map-fd caching, struct key pointer caching, immediate store optimization

### Surface Language
- Standard CL `let` bindings with optional types (inferred from initializers)
- `(declare (type ...))` for sub-64-bit narrowing
- CL-style `defstruct` with accessor functions and `setf` expanders
- CL-style map interface: `getmap`, `(setf (getmap ...))`, `remmap`, `incf`
- `when-let`, `if-let`, `case`, `with-tcp`, `with-ipv4`, protocol accessors
- Full CL macros at compile time

### BPF Features
- XDP, TC, tracepoint, kprobe program types
- Multi-program ELF (multiple `defprog` in one file)
- Tail calls via `:prog-array` maps
- Ring buffer support (`ringbuf-reserve`, `ringbuf-submit`)
- CO-RE relocations via `.BTF.ext` for cross-kernel portability
- BTF type information for all structs and programs

### Tooling
- CLI with `compile`, `disasm`, `--version`, `--help`
- `--gen` flag for shared type headers: C, Go, Rust, Python, Common Lisp
- Version strings via `cl-version-string` with git hash

## Examples

14 examples included:
- Packet counter, port blocker, SYN flood filter, rate limiter
- Run queue latency histogram (tracepoint)
- Tail call dispatcher, multi-program ELF
- TC classifier, ring buffer events
- 5 Cilium-style programs: connection tracker, load balancer, policy enforcer, CIDR prefilter, health ping responder

## Benchmarks

| Program | Whistler | clang -O2 |
|---------|----------|-----------|
| count-xdp | 11 | 11 |
| drop-port | 25 | 26 |
| synflood | 65 | 68 |
| ct4-basic | 101 | 97 |
| nodeport-lb4 | 75 | 75 |
