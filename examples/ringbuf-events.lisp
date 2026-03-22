;;; ringbuf-events.lisp — Event logging via ring buffer
;;;
;;; Demonstrates BPF ring buffer output: captures connection events
;;; (new TCP SYN packets) and sends them to userspace via a ring
;;; buffer. Userspace can read events with bpftool or libbpf.
;;;
;;; Each event is a 12-byte struct: (src-ip dst-ip dst-port proto).
;;;
;;; Attach with:
;;;   bpftool prog load ringbuf-events.bpf.o /sys/fs/bpf/ringbuf_events
;;;   ip link set dev eth0 xdp pinned /sys/fs/bpf/ringbuf_events
;;;
;;; Read events:
;;;   bpftool map dump name events

(in-package #:whistler)

;;; Event struct sent to userspace

(defstruct conn-event
  (src-addr  u32)    ; source IP
  (dst-addr  u32)    ; destination IP
  (dst-port  u16)    ; destination port
  (proto     u8)     ; IP protocol
  (pad       u8))    ; padding (total: 12 bytes)

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
