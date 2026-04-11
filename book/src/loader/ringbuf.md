# Ring Buffer Consumer

The loader includes a pure-CL ring buffer consumer for
`BPF_MAP_TYPE_RINGBUF` maps. It uses mmap for zero-copy access and
epoll for efficient waiting.

## Usage

```lisp
(let ((consumer (open-ring-consumer map-info
                  (lambda (sap len)
                    ;; sap is a system-area-pointer to the event data
                    ;; len is the event length in bytes
                    (let ((buf (make-array len :element-type '(unsigned-byte 8))))
                      (dotimes (i len)
                        (setf (aref buf i) (sb-sys:sap-ref-8 sap i)))
                      (process-event buf))))))
  (unwind-protect
       (loop
         (ring-poll consumer :timeout-ms 1000))
    (close-ring-consumer consumer)))
```

## API

### open-decoding-ring-consumer

```lisp
(open-decoding-ring-consumer map-info decoder callback) -> ring-consumer
```

Creates a ring buffer consumer that copies each event into an octet vector,
decodes it with `decoder`, and passes the decoded object to `callback`.
Use this when your ring buffer holds `defstruct`-defined records.

### with-decoding-ring-consumer

```lisp
(with-decoding-ring-consumer (consumer map-info decoder callback)
  body...)
```

Convenience macro that opens a decoding ring consumer, binds it to
`consumer`, and guarantees cleanup with `unwind-protect`.

### open-ring-consumer

```lisp
(open-ring-consumer map-info callback) -> ring-consumer
```

Creates a ring buffer consumer. `callback` is called with `(sap len)` for
each event -- a system-area-pointer and the event byte length. The
callback runs synchronously during `ring-poll`.

Internally, this mmaps the consumer page (read-write) and the producer +
data pages (read-only), then sets up an epoll instance on the map FD.

### ring-poll

```lisp
(ring-poll consumer :timeout-ms 100) -> event-count
```

Waits for ring buffer events via epoll, then consumes all available events.
Returns the number of events processed. A timeout of 0 makes it
non-blocking.

### close-ring-consumer

```lisp
(close-ring-consumer consumer)
```

Unmaps memory and closes the epoll FD. Always call this on cleanup.

## Reading structured events

When your BPF program writes a `defstruct`-defined struct to the ring
buffer, use the higher-level decoding helper:

```lisp
;; Given: (defstruct conn-event (src-addr u32) (dst-addr u32) (port u16))
;; Whistler generates: decode-conn-event, conn-event-record-src-addr, etc.

(open-decoding-ring-consumer
 map-info
 #'decode-conn-event
 (lambda (ev)
   (format t "~a:~d~%" (conn-event-record-src-addr ev)
                        (conn-event-record-port ev))))
```
