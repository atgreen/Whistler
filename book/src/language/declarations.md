# Top-Level Declarations

A Whistler source file consists of top-level declarations:
`defmap`, `defprog`, `defstruct`, and `defunion`. Every other construct
lives inside the body of a `defprog`.

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
side it generates a corresponding CL struct with `encode` and `decode`
functions, so you can pack and unpack data exchanged through maps or ring
buffers without manual byte wrangling.

## defunion

`defunion` declares a union of existing struct types. It allocates the
size of the largest member; the returned pointer can be used with any
member's field accessors (all members share offset 0). This is useful
for packet parsing where the same stack buffer is reused for different
header types:

```lisp
(defstruct ip-hdr  ...)
(defstruct udp-hdr ...)
(defunion packet-buf ip-hdr udp-hdr)

(let ((pkt (make-packet-buf)))
  (skb-load-bytes (ctx-ptr) 0 pkt (sizeof ip-hdr))
  (ip-hdr-protocol pkt))    ; access through any member's accessors
```
