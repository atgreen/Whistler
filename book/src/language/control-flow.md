# Control Flow

## if

Two-way conditional. Returns the value of the taken branch.

```lisp
(if (> data-end (+ data 34))
    (process-packet data)
    XDP_DROP)
```

When the test is a comparison form (`=`, `>`, `<`, etc.), the compiler
emits a direct conditional jump instead of materializing a 0/1 value.

## when, unless

One-armed conditionals with implicit `progn` body. Return 0 when the
body is skipped.

```lisp
(when (= proto +ip-proto-tcp+)
  (incf (getmap tcp-count 0))
  (process-tcp data))

(unless (> (+ data 34) data-end)
  (return XDP_PASS))
```

## when-let

Bind variables and execute the body only if **all** bound values are
non-zero. If any initializer evaluates to 0, the remaining bindings and
the body are skipped. Returns 0 when skipped.

```lisp
;; Null-check a map lookup and use the pointer
(when-let ((p (map-lookup my-map key)))
  (atomic-add p 0 1))

;; Typed binding
(when-let ((p u64 (map-lookup my-map key)))
  (load u32 p 0))

;; Multiple bindings -- all must be non-zero
(when-let ((a (map-lookup m1 k1))
           (b (map-lookup m2 k2)))
  (+ (load u64 a 0) (load u64 b 0)))
```

## if-let

Bind a variable and branch on its value. If the initializer is non-zero,
execute the *then* branch with the variable in scope. Otherwise execute
the *else* branch.

```lisp
(if-let (p (map-lookup my-map key))
  (load u64 p 0)   ; then: p is bound and non-zero
  0)                ; else: key not found

;; Typed binding
(if-let (p u64 (map-lookup my-map key))
  (load u32 p 0)
  0)
```

## cond

Multi-way conditional. Clauses are tested in order; the body of the
first matching clause executes. A final `t` clause is the default.

```lisp
(cond
  ((= proto +ip-proto-tcp+)  (handle-tcp data))
  ((= proto +ip-proto-udp+)  (handle-udp data))
  (t                          XDP_PASS))
```

## case

Multi-way dispatch on a value. Shadows CL's `case`. Each clause is
`(value body...)` or `((v1 v2 ...) body...)`. The final clause may use
`t` or `otherwise` as a catch-all. Compiles to a `cond` chain.

```lisp
(case (ipv4-protocol ip)
  (+ip-proto-tcp+  (handle-tcp))
  (+ip-proto-udp+  (handle-udp))
  ((41 47)         (handle-tunnel))   ; match multiple values
  (t               XDP_PASS))
```

## and, or

Short-circuit logical operators. `and` returns 0 as soon as any operand
is zero; `or` returns the first non-zero operand. These are compiler
primitives, not CL macros.

```lisp
(when (and (= proto +ip-proto-tcp+)
           (logand flags +tcp-syn+)
           (not (logand flags +tcp-ack+)))
  (log-syn-packet data))

(let ((port (or (tcp-dst-port tcp) (tcp-src-port tcp))))
  ...)
```

## progn

Evaluate forms in sequence, return the value of the last one.

```lisp
(progn
  (incf (getmap pkt-count 0))
  XDP_PASS)
```

## return

Exit the BPF program early with a return value. If no value is given,
returns 0.

```lisp
(when (> (+ data 34) data-end)
  (return XDP_PASS))
```
