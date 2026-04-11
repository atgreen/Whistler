# defstruct

`defstruct` declares a C-compatible struct layout. The compiler generates
accessors for both the BPF side (inside `defprog`) and the Common Lisp
userspace side (for packing and unpacking data exchanged through maps and
ring buffers).

## Syntax

```lisp
(defstruct name
  (field-name type)
  ...)
```

## Field Types

| Type | Size | Description |
|------|------|-------------|
| `u8` | 1 byte | Unsigned 8-bit integer |
| `u16` | 2 bytes | Unsigned 16-bit integer |
| `u32` | 4 bytes | Unsigned 32-bit integer |
| `u64` | 8 bytes | Unsigned 64-bit integer |
| `(array type count)` | `sizeof(type) * count` | Fixed-size array of a scalar type |

## Layout and Alignment

Fields are laid out with C-compatible natural alignment. Each field is
aligned to its own size: `u16` fields align to 2 bytes, `u32` to 4 bytes,
`u64` to 8 bytes. The compiler inserts padding bytes between fields as
needed. The overall struct size is padded to a multiple of the largest field
alignment.

For example:

```lisp
(defstruct sample
  (flags u8)
  (id u32)
  (value u64))
```

This produces a 16-byte struct: 1 byte for `flags`, 3 bytes of padding,
4 bytes for `id`, and 8 bytes for `value`.

## BPF-Side API

Inside a `defprog` body, `defstruct` generates the following forms:

### Constructor

```lisp
(make-NAME)
```

Allocates the struct on the BPF stack with all fields zeroed.

```lisp
(let ((e (make-sample)))
  (setf (sample-id e) 42)
  ...)
```

### Field Accessor

```lisp
(NAME-FIELD ptr)
```

Reads a field value from a struct pointer.

```lisp
(let ((pid (sample-id e)))
  ...)
```

### Field Setter

```lisp
(setf (NAME-FIELD ptr) value)
```

Writes a value to a field.

```lisp
(setf (sample-value e) 100)
```

### Field Pointer

```lisp
(NAME-FIELD-PTR ptr)
```

Returns a pointer to the field within the struct. This is useful for
passing field addresses to BPF helpers like `bpf_probe_read` or
`bpf_get_current_comm`:

```lisp
(get-current-comm (my-event-comm-ptr e) 16)
```

### Sizeof

```lisp
(sizeof NAME)
```

Returns the total size of the struct in bytes, including padding. This is
typically used with `ringbuf-reserve`:

```lisp
(ringbuf-reserve events (sizeof my-event))
```

## CL-Side API

On the Common Lisp userspace side, `defstruct` generates:

### Record Struct

```lisp
NAME-RECORD
```

A standard CL `defstruct` with a slot for each field. Array fields become
CL vectors.

### Decoder

```lisp
(decode-NAME byte-vector &optional offset)
```

Parses a byte vector (or a subrange starting at `offset`) into a
`NAME-RECORD` instance. This is used when reading data from maps or ring
buffers.

### Encoder

```lisp
(encode-NAME record)
```

Serializes a `NAME-RECORD` instance into a byte vector suitable for writing
to a map.

## Full Example

Consider a struct for reporting process events:

```lisp
(defstruct my-event
  (pid u32)
  (comm (array u8 16))
  (data (array u8 64)))
```

This defines a struct with a 32-bit PID, a 16-byte command name buffer, and
a 64-byte data buffer. The total size is 84 bytes (4 + 16 + 64, no padding
needed since the largest field alignment is 4).

### BPF side

```lisp
(defmap events :type :ringbuf
  :max-entries (* 256 1024))

(defprog trace-exec (:type :tracepoint
                     :section "tracepoint/sched/sched_process_exec")
  (with-ringbuf (e events (sizeof my-event))
    (setf (my-event-pid e) (get-current-pid-tgid))
    (get-current-comm (my-event-comm-ptr e) 16)
    (probe-read (my-event-data-ptr e) 64 some-source))
  0)
```

### CL side

```lisp
;; Reading events from the ring buffer
(with-ringbuf-consumer (buf events)
  (lambda (data size)
    (let ((evt (decode-my-event data)))
      (format t "pid=~A comm=~A~%"
              (my-event-record-pid evt)
              (map 'string #'code-char
                   (my-event-record-comm evt))))))

;; Creating and encoding a record manually
(let ((rec (make-my-event-record :pid 1234
                                  :comm (make-array 16 :element-type '(unsigned-byte 8))
                                  :data (make-array 64 :element-type '(unsigned-byte 8)))))
  (encode-my-event rec))
```
