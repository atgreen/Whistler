# Memory Access

## load

Read a value of a given type from a pointer at a byte offset:

```lisp
(load type ptr offset)
(load type ptr)          ; offset defaults to 0
```

Types: `u8`, `u16`, `u32`, `u64`. The result type matches the load type.

```lisp
(let ((ethertype (load u16 data 12))
      (protocol  (load u8  ip   9)))
  ...)
```

## store

Write a value to memory:

```lisp
(store type ptr offset value)
```

```lisp
(store u32 event 0 src-addr)
(store u8  event 10 proto)
```

## ctx-load

Read from the BPF program context (the `ctx` pointer passed by the
kernel). The context structure varies by program type -- for XDP it
contains `data`, `data_end`, and `data_meta` as `u32` offsets.

```lisp
(ctx-load type offset)
```

```lisp
(let ((data     (ctx-load u32 0))    ; xdp_md->data
      (data-end (ctx-load u32 4)))   ; xdp_md->data_end
  ...)
```

## stack-addr

Take the address of a stack-allocated variable (analogous to `&var` in
C). Useful for passing pointers to BPF helpers that expect pointer
arguments.

```lisp
(let ((key u32 0))
  (map-lookup my-map (stack-addr key)))
```

## atomic-add

Atomically add a value to memory at a given offset:

```lisp
(atomic-add ptr offset value)
(atomic-add ptr offset value type)   ; type defaults to u64
```

```lisp
(when-let ((p (map-lookup counters key)))
  (atomic-add p 0 1))
```

The offset must be aligned to the type width.

## memset

Fill a region of memory with a byte value. Both `offset` and `nbytes`
must be compile-time constants. When the value is a compile-time
constant, the compiler emits widened stores (u64/u32/u16) for efficiency.

```lisp
(memset ptr offset value nbytes)
```

```lisp
;; Zero 32 bytes starting at offset 0
(memset buf 0 0 32)

;; Fill 16 bytes with 0xFF
(memset key 16 #xFF 16)
```

## memcpy

Copy bytes between memory regions. All offsets and `nbytes` must be
compile-time constants. The compiler uses the widest possible
loads/stores (u64, then u32, u16, u8) for efficiency.

```lisp
(memcpy dst dst-offset src src-offset nbytes)
```

```lisp
(memcpy event 0 data 14 20)   ; copy 20 bytes of IP header
```

## pt_regs access

For kprobe and uprobe programs, function arguments are available through
`pt_regs` accessors. These are compile-time macros that expand to
`ctx-load` with architecture-specific offsets (x86-64 and aarch64
supported).

| Macro | Description |
|-------|-------------|
| `(pt-regs-parm1)` | First argument |
| `(pt-regs-parm2)` | Second argument |
| `(pt-regs-parm3)` | Third argument |
| `(pt-regs-parm4)` | Fourth argument |
| `(pt-regs-parm5)` | Fifth argument |
| `(pt-regs-parm6)` | Sixth argument |
| `(pt-regs-ret)` | Return value |

```lisp
(defprog trace-open (:type :kprobe :section "kprobe/do_sys_open" :license "GPL")
  (let ((filename-ptr (pt-regs-parm2)))
    (probe-read-user-str buf 256 filename-ptr)
    ...))
```

Compiling on an unsupported architecture produces a compile-time error.
