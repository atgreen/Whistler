# Map Operations

Whistler provides both low-level primitives and high-level macros for
BPF map access. The high-level macros mirror CL's `gethash` pattern.

## Low-level primitives

These compile directly to BPF helper calls with the map file descriptor
in R1 and a pointer to the key on the stack in R2.

### map-lookup

```lisp
(map-lookup map-name key)
```

Returns a pointer to the value, or 0 (null) if the key is not found.
**You must null-check this pointer** before dereferencing it -- the BPF
verifier enforces this.

```lisp
(when-let ((p (map-lookup counters key)))
  (load u64 p 0))
```

### map-update

```lisp
(map-update map-name key value flags)
```

Flags: `BPF_ANY` (0), `BPF_NOEXIST` (1), `BPF_EXIST` (2).

### map-delete

```lisp
(map-delete map-name key)
```

### Pointer-key variants

When a map has a struct key (key-size > 8 bytes), use the `-ptr`
variants. These take pointers to data on the stack instead of
scalar values:

```lisp
(map-lookup-ptr map-name key-ptr)
(map-update-ptr map-name key-ptr val-ptr flags)
(map-delete-ptr map-name key-ptr)
```

The high-level macros auto-select the `-ptr` variants when the map's
key-size exceeds 8 bytes.

## High-level macros

### getmap

Look up a map value. For scalar values (value-size <= 8), dereferences
the pointer and returns the value directly. For struct values, returns
the pointer. Returns 0 if the key is not found.

```lisp
(getmap map-name key)
```

```lisp
(let ((count (getmap pkt-count 0)))
  (when (> count 1000)
    (return XDP_DROP)))
```

### (setf (getmap ...))

Update a map entry:

```lisp
(setf (getmap my-map key) new-value)
```

### remmap

Delete a map entry (mirrors CL's `remhash`):

```lisp
(remmap my-map key)
```

### (incf (getmap ...))

Atomically increment a map value. For array maps, this is a lookup
followed by `atomic-add`. For hash maps, it initializes the entry to the
delta if the key does not exist.

```lisp
(incf (getmap pkt-count 0))       ; increment by 1
(incf (getmap pkt-count 0) 5)     ; increment by 5
```

## Struct keys

When a map is declared with a key-size greater than 8 bytes, the
high-level macros (`getmap`, `setf`, `remmap`, `incf`) automatically
switch to the `-ptr` variants, passing a pointer to the struct key on
the stack. No user code changes needed.

```lisp
(defstruct stats-key
  (comm (array u8 16))
  (nargs u16) (rtype u8) (abi u8) (pad u32))

(defmap stats :type :hash :key-size 40 :value-size 8 :max-entries 10240)

;; incf auto-uses map-lookup-ptr / map-update-ptr for the 40-byte key
(incf (getmap stats key))
```
