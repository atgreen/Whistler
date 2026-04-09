# Tracepoint with Ring Buffer

Capture new TCP connection events (SYN packets) via XDP and send them to
userspace through a ring buffer.

## BPF program

```lisp
(in-package #:whistler)

;;; Event struct -- shared between BPF and userspace.
;;; defstruct generates both BPF accessor macros and CL-side codec
;;; (decode-conn-event -> conn-event-record struct).
(defstruct conn-event
  (src-addr  u32)
  (dst-addr  u32)
  (dst-port  u16)
  (proto     u8)
  (pad       u8))    ; align to 12 bytes

;;; Maps
(defmap events :type :ringbuf :max-entries 4096)

(defmap rb-stats :type :array
  :key-size 4 :value-size 8 :max-entries 2)

(defconstant +stat-events-sent+    0)
(defconstant +stat-events-dropped+ 1)

;;; Program
(defprog event-logger (:type :xdp :section "xdp" :license "GPL")
  (with-packet (data data-end :min-len 38)    ; Eth + IPv4 + TCP ports
    (when (= (eth-type data) +ethertype-ipv4+)
      (let* ((ip    (+ data +eth-hdr-len+))
             (proto (ipv4-protocol ip)))
        ;; TCP SYN packets only
        (when (and (= proto +ip-proto-tcp+)
                   (> (+ data 54) data-end))
          (return XDP_PASS))
        (when (= proto +ip-proto-tcp+)
          (let* ((tcp   (+ ip +ipv4-hdr-len+))
                 (flags (tcp-flags tcp)))
            ;; Only log new connections (SYN set, ACK not set)
            (when (and (logand flags +tcp-syn+)
                       (not (logand flags +tcp-ack+)))
              (with-ringbuf (event events (sizeof conn-event))
                (setf (conn-event-src-addr event) (ipv4-src-addr ip)
                      (conn-event-dst-addr event) (ipv4-dst-addr ip)
                      (conn-event-dst-port event) (tcp-dst-port tcp)
                      (conn-event-proto event) proto)
                (incf (getmap rb-stats +stat-events-sent+)))))))))
  XDP_PASS)

(compile-to-elf "ringbuf-events.bpf.o")
```

## Key points

- **Flat guards**: `with-packet` does a single bounds check and
  early-returns `XDP_PASS` on failure. The nested `when` forms are flat
  guard checks, not deeply nested success paths. This structure is
  optimal for the BPF verifier, which tracks packet bounds along each
  code path.

- **sizeof**: `(sizeof conn-event)` resolves at compile time to the
  struct's total byte size (12 in this case). It works anywhere an
  integer constant is expected.

- **with-ringbuf**: Reserves space in the ring buffer, executes the body,
  and auto-submits on normal exit. If the ring buffer is full, the
  reservation returns 0 and the body is skipped entirely (guarded by an
  internal `when`).

- **Dual struct**: `defstruct` generates both BPF accessor macros for
  the kernel side (`conn-event-src-addr`, etc.) and a CL struct plus
  `decode-conn-event` function for the userspace side. With `--gen c`,
  you also get a matching C struct for non-Lisp consumers.
