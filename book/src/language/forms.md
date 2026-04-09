# Forms

The body of a `defprog` consists of Whistler forms that the compiler
translates to eBPF bytecode. These forms look like Common Lisp but target
a restricted execution model: 64-bit registers, no heap, no closures, no
general recursion.

Standard CL is fully available at **compile time**. You can write
`defmacro`, `defconstant`, helper functions, and arbitrary Lisp code that
runs during compilation. The compiler expands all macros before lowering
to eBPF. Only the primitive Whistler forms survive into the final
bytecode.

```lisp
;; CL macro -- runs at compile time, gone before bytecode emission
(defmacro drop-if (test)
  `(when ,test (return XDP_DROP)))

(defprog my-filter (:type :xdp :section "xdp" :license "GPL")
  ;; These are Whistler forms compiled to eBPF:
  (let ((data (xdp-data))
        (data-end (xdp-data-end)))
    (when (> (+ data 34) data-end)
      (return XDP_PASS))
    (drop-if (= (eth-type data) +ethertype-ipv4+)))
  XDP_PASS)
```

The following chapters document each category of form:

- [Variables and Types](./variables.md) -- `let`, `let*`, `setf`, type inference
- [Control Flow](./control-flow.md) -- `if`, `when`, `unless`, `cond`, `case`, `and`, `or`
- [Arithmetic and Bitwise](./arithmetic.md) -- math, shifts, comparisons, casts, byte order
- [Memory Access](./memory.md) -- `load`, `store`, `ctx-load`, `stack-addr`, `atomic-add`, `memset`, `memcpy`
- [Map Operations](./maps.md) -- low-level and high-level map access
- [Ring Buffers](./ringbuf.md) -- `ringbuf-reserve`, `with-ringbuf`
- [BPF Helpers](./helpers.md) -- kernel helper function calls
- [Loops](./loops.md) -- `dotimes`, `do-user-ptrs`, `do-user-array`
- [Tail Calls](./tail-calls.md) -- program chaining via `tail-call`
- [Inline Assembly](./asm.md) -- raw BPF instruction emission
