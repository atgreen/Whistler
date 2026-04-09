# Top-Level Declarations

A Whistler source file consists of three kinds of top-level declarations:
`defmap`, `defprog`, and `defstruct`. Every other construct lives inside
the body of a `defprog`.

## defmap

[defmap](./defmap.md) declares a BPF map -- a kernel-side data structure
shared between BPF programs and userspace. You choose a map type (hash
table, array, ring buffer, etc.), specify key and value sizes, and set
capacity. The compiler emits the corresponding ELF map section and
generates accessor forms you can use inside `defprog` bodies.

## defprog

[defprog](./defprog.md) defines a BPF program. Each `defprog` produces one
program section in the output ELF. You specify the program type (XDP,
kprobe, tracepoint, and so on), write the body using Whistler forms, and
the compiler handles register allocation, stack layout, and bytecode
emission. Multiple `defprog` forms in the same source file compile into a
single ELF object.

## defstruct

[defstruct](./defstruct.md) declares a C-compatible struct layout used on
both the BPF side and the Common Lisp userspace side. On the BPF side the
compiler generates constructors, field accessors, and `sizeof`. On the CL
side it generates a corresponding record struct with `encode` and `decode`
functions, so you can pack and unpack data exchanged through maps or ring
buffers without manual byte wrangling.
