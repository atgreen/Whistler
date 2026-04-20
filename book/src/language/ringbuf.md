# Ring Buffers

Ring buffers send variable-sized records from BPF programs to userspace
without per-event syscalls. Whistler provides both raw primitives and a
convenience macro.

## Primitives

### ringbuf-reserve

Reserve space in a ring buffer map. Returns a pointer to the reserved
region, or 0 if the buffer is full.

```lisp
(ringbuf-reserve map-name size flags)
```

`size` should be a compile-time constant or `(sizeof struct-name)`.
`flags` is typically 0.

### ringbuf-submit

Submit a previously reserved record to the ring buffer, making it
visible to the userspace consumer.

```lisp
(ringbuf-submit ptr flags)
```

### ringbuf-discard

Discard a reserved record without submitting it.

```lisp
(ringbuf-discard ptr flags)
```

### ringbuf-output

Copy a stack-allocated struct directly into the ring buffer. This is a
single helper call -- more compact than the reserve/submit pattern when
you build the entire record before sending.

```lisp
(ringbuf-output map-name data-ptr size flags)
```

`data-ptr` must point to a stack-allocated struct (e.g., from
`make-event`). The BPF verifier requires the pointer to be fp-derived.

```lisp
(let ((evt (make-conn-event)))
  (setf (conn-event-src-addr evt) src
        (conn-event-dst-addr evt) dst
        (conn-event-dst-port evt) port
        (conn-event-proto evt)    proto)
  (ringbuf-output events evt (sizeof conn-event) 0))
```

Use `ringbuf-output` when filling all fields before sending. Use
`with-ringbuf` (below) when you need conditional field logic or want
to avoid the stack copy.

## with-ringbuf

The `with-ringbuf` macro handles reserve, body execution, and submit in
one form. If `ringbuf-reserve` returns null, the body is skipped
entirely.

```lisp
(with-ringbuf (var map-name size [:flags 0])
  body...)
```

The variable is bound to the reserved pointer inside the body. On normal
exit, `ringbuf-submit` is called automatically. The buffer is **not**
zeroed -- set fields explicitly or use `memset`.

```lisp
(defstruct conn-event
  (src-addr u32)
  (dst-addr u32)
  (dst-port u16)
  (proto    u8)
  (pad      u8))

(defmap events :type :ringbuf :max-entries 4096)

(with-ringbuf (event events (sizeof conn-event))
  (setf (conn-event-src-addr event) (ipv4-src-addr ip)
        (conn-event-dst-addr event) (ipv4-dst-addr ip)
        (conn-event-dst-port event) (tcp-dst-port tcp)
        (conn-event-proto event)    proto))
```

If the body executes `(return ...)`, the reservation is **not**
auto-submitted. Call `(ringbuf-discard var 0)` before returning if
needed.

## fill-process-info

A convenience macro for filling common process metadata fields in a
struct. Each keyword names a struct field setter:

```lisp
(fill-process-info event
  :pid-field       my-event-pid
  :uid-field       my-event-uid
  :timestamp-field my-event-timestamp
  :comm-field      my-event-comm-ptr
  :comm-size       16)
```

This expands to calls to `get-current-pid-tgid`, `get-current-uid-gid`,
`ktime-get-ns`, and `get-current-comm` with the appropriate field
setters.
