# Arithmetic and Bitwise

All arithmetic operates on 64-bit registers. The optimizer narrows to
32-bit instructions when it can prove the operands fit.

## Arithmetic operators

| Form | Description |
|------|-------------|
| `(+ a b ...)` | Addition (n-ary, left-fold) |
| `(- a b)` | Subtraction |
| `(- a)` | Negation |
| `(* a b ...)` | Multiplication |
| `(/ a b)` | Unsigned division |
| `(mod a b)` | Unsigned modulo |
| `(incf var)` | Increment variable by 1 (or by delta: `(incf var 5)`) |
| `(decf var)` | Decrement variable by 1 (or by delta: `(decf var 5)`) |

Division or modulo by a compile-time zero is a compile error. `incf` and
`decf` are macros that expand to `setf` for variables and to
atomic-increment for map places (see [Map Operations](./maps.md)).

```lisp
(let ((total (+ a b c)))       ; n-ary addition
  (setf total (* total 2))
  (incf total)                 ; total = total + 1
  total)
```

## Bitwise operators

| Form | Description |
|------|-------------|
| `(logand a b)` | Bitwise AND |
| `(logior a b)` | Bitwise OR |
| `(logxor a b)` | Bitwise XOR |
| `(<< a n)` | Left shift |
| `(>> a n)` | Logical right shift (zero-fill) |
| `(>>> a n)` | Arithmetic right shift (sign-extending) |

Shift amounts must be 0--63; shifting by 64 or more is a compile error.

```lisp
;; Extract PID from tgid (upper 32 bits)
(let ((pid (cast u32 (>> (get-current-pid-tgid) 32))))
  ...)

;; Check TCP SYN flag
(when (logand flags +tcp-syn+)
  ...)
```

## Comparison operators

Comparisons return 1 (true) or 0 (false). When used directly as the
test of `if`, `when`, or `unless`, the compiler emits a conditional jump
without materializing the value.

### Unsigned (default)

| Form | Description |
|------|-------------|
| `(= a b)` | Equal |
| `(/= a b)` | Not equal |
| `(> a b)` | Greater than |
| `(>= a b)` | Greater than or equal |
| `(< a b)` | Less than |
| `(<= a b)` | Less than or equal |

### Signed

| Form | Description |
|------|-------------|
| `(s> a b)` | Signed greater than |
| `(s>= a b)` | Signed greater than or equal |
| `(s< a b)` | Signed less than |
| `(s<= a b)` | Signed less than or equal |

```lisp
(when (s< offset 0)
  (return XDP_DROP))
```

## Logic

```lisp
(not expr)   ; returns 1 if expr is 0, else 0
```

## Type cast

Truncate or zero-extend a value to a specific width:

```lisp
(cast u8 val)    ; keep low 8 bits
(cast u16 val)   ; keep low 16 bits
(cast u32 val)   ; keep low 32 bits
(cast u64 val)   ; no-op (identity)
```

## Byte-order conversion

Network-to-host and host-to-network byte swaps:

| Form | Width | Description |
|------|-------|-------------|
| `(ntohs x)` | 16-bit | Network to host short |
| `(htons x)` | 16-bit | Host to network short |
| `(ntohl x)` | 32-bit | Network to host long |
| `(htonl x)` | 32-bit | Host to network long |
| `(ntohll x)` | 64-bit | Network to host long long |
| `(htonll x)` | 64-bit | Host to network long long |

The return type reflects the width: `ntohs` returns `u16`, `ntohl`
returns `u32`, `ntohll` returns `u64`.

When a byte-swapped value is compared against a compile-time constant,
the compiler folds the swap into the constant rather than emitting a
runtime swap instruction.

```lisp
;; Compiler folds: instead of swapping at runtime, it compares
;; against the byte-swapped constant directly
(when (= (ntohs (load u16 data 12)) +ethertype-ipv4+)
  ...)
```
