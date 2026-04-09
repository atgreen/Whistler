# Tracepoint with Ring Buffer

The most common pattern: attach to a kernel tracepoint, build a struct,
send it to userspace via a ring buffer.

```lisp
(in-package #:whistler)

;; 1. Define the event struct. Generates both BPF accessors and
;;    CL-side codec (decode-conn-event -> conn-event-record struct).
(defstruct conn-event
  (src-addr u32)
  (dst-addr u32)
  (dst-port u16)
  (proto    u8)
  (pad      u8))    ; align to 12 bytes

;; 2. Declare maps.
(defmap events :type :ringbuf :max-entries 4096)

;; 3. Write the program.
(defprog event-logger (:type :xdp :section "xdp" :license "GPL")
  (with-tcp (data data-end tcp)
    (let ((flags (tcp-flags tcp)))
      ;; Only new connections: SYN set, ACK not set
      (when (and (logand flags +tcp-syn+)
                 (not (logand flags +tcp-ack+)))
        (let ((ip (+ data +eth-hdr-len+)))
          (with-ringbuf (event events (sizeof conn-event))
            (setf (conn-event-src-addr event) (ipv4-src-addr ip)
                  (conn-event-dst-addr event) (ipv4-dst-addr ip)
                  (conn-event-dst-port event) (tcp-dst-port tcp)
                  (conn-event-proto event) +ip-proto-tcp+))))))
  XDP_PASS)

(compile-to-elf "events.bpf.o")
```

## Key points

- `with-tcp` expands to bounds check, EtherType check, protocol check --
  all as flat guards with early return. Zero overhead.
- `with-ringbuf` reserves space, executes the body, and submits on normal
  exit. If the reserve fails (buffer full), the body is skipped.
- `sizeof` is a compile-time constant.
- The same `defstruct` drives both the BPF accessors and the CL-side
  `decode-conn-event` for reading events in userspace.
