# Variables and Types

## let and let*

`let` binds variables with **parallel** semantics -- all initializers are
evaluated before any variable becomes visible. `let*` binds
**sequentially**, so each initializer can reference variables bound
earlier in the same form.

```lisp
;; Parallel: b does not see the new a
(let ((a 10)
      (b (+ a 1)))   ; a here refers to an outer binding
  ...)

;; Sequential: b sees the new a
(let* ((a 10)
       (b (+ a 1)))  ; a is 10
  ...)
```

Each binding has one of these shapes:

```lisp
(var init)            ; type inferred from init
(var type init)       ; explicit type
(var type)            ; explicit type, zero-initialized
```

## Type inference

Variables default to `u64`. The compiler infers narrower types from
certain initializer forms:

| Initializer | Inferred type |
|-------------|---------------|
| `(load u32 ...)` | `u32` |
| `(ctx u32 ...)` | `u32` |
| `(cast u16 ...)` | `u16` |
| `(ntohs ...)` | `u16` |
| `(ntohl ...)` | `u32` |
| `(get-prandom-u32)` | `u32` |
| `(get-smp-processor-id)` | `u32` |
| anything else | `u64` |

## Type declarations

Use `declare` after the binding list to explicitly narrow variables.
This follows the CL convention:

```lisp
(let ((proto (ipv4-protocol ip)))
  (declare (type u32 proto))
  (tail-call jt proto))
```

Multiple variables can share a declaration:

```lisp
(let ((a (load u32 ptr 0))
      (b (load u32 ptr 4)))
  (declare (type u32 a b))
  (+ a b))
```

## setf

`setf` assigns to a variable or a struct field accessor:

```lisp
(setf count (+ count 1))
```

Multi-pair `setf` assigns several places in sequence:

```lisp
(setf (conn-event-src-addr event) (ipv4-src-addr ip)
      (conn-event-dst-addr event) (ipv4-dst-addr ip)
      (conn-event-dst-port event) (tcp-dst-port tcp))
```

Struct field `setf` works because `defstruct` generates `defsetf`
expanders. The compiler expands multi-pair `setf` into a `progn` of
single assignments.
