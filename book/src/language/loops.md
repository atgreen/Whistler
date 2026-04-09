# Loops

The BPF verifier requires that all loops have a provably bounded
iteration count. Whistler enforces this at compile time.

## dotimes

Iterate a fixed number of times. The bound must be a compile-time
constant (an integer literal or a `defconstant` symbol).

```lisp
(dotimes (var count)
  body...)
```

The loop variable is bound as a `u32` starting at 0.

```lisp
(defconstant +max-headers+ 8)

(dotimes (i +max-headers+)
  (when (= (load u8 ptr i) 0)
    (return i)))
```

A non-constant or negative bound is a compile error.

## do-user-ptrs

Iterate over a user-space array of pointers (e.g., `ffi_type **`). For
each element within `count` (up to the compile-time constant
`max-count`), reads the pointer via `probe-read-user` and binds it if
non-null.

```lisp
(do-user-ptrs (ptr-var base-ptr count max-count [:index idx])
  body...)
```

The `:index` keyword optionally names the loop index variable. If
omitted, a gensym is used.

```lisp
(defconstant +max-args+ 16)

(do-user-ptrs (atype-ptr (ffi-cif-arg-types cif)
                          (ffi-cif-nargs cif)
                          +max-args+
                          :index i)
  (probe-read-user ft (sizeof ffi-type) atype-ptr)
  (setf (stats-key-arg-types key i) (ffi-type-type-code ft)))
```

Expands to a `dotimes` with a bounds-guarded `probe-read-user` and a
`when-let` null check on each pointer.

## do-user-array

Iterate over a user-space array of typed elements (scalar or struct).
Similar to `do-user-ptrs` but reads the elements themselves rather than
pointers to them.

```lisp
(do-user-array (var type base-ptr count max-count [:index idx])
  body...)
```

`type` is a scalar type (`u8`, `u16`, `u32`, `u64`) or a struct name.
For scalars, `var` is bound to the loaded value. For structs, `var` is
bound to a reusable stack buffer pointer that is overwritten each
iteration.

```lisp
(do-user-array (val u32 array-ptr nelems 64 :index i)
  (incf (getmap histogram val)))
```
