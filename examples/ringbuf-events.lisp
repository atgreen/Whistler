;;; ringbuf-events.lisp — Event logging via ring buffer
;;;
;;; Demonstrates BPF ring buffer output: captures connection events
;;; (new TCP SYN packets) and sends them to userspace via a ring
;;; buffer. Userspace can read events with bpftool or libbpf.
;;;
;;; Each event is a 16-byte struct: (src-ip dst-ip dst-port proto).
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

;; Ring buffer for sending events to userspace
(defmap events :type :ringbuf
  :key-size 0 :value-size 0 :max-entries 4096)

;; Statistics
(defmap rb-stats :type :array
  :key-size 4 :value-size 8 :max-entries 2)

(defconstant +stat-events-sent+    0)
(defconstant +stat-events-dropped+ 1)

;;; Program

(defprog event-logger (:type :xdp :section "xdp" :license "GPL")
  (let ((data     (xdp-data))
        (data-end (xdp-data-end)))
    ;; Need Eth + IPv4 + at least TCP header start (ports)
    (when (> (+ data 38) data-end)
      (return XDP_PASS))
    (when (/= (eth-type data) +ethertype-ipv4+)
      (return XDP_PASS))
    (let ((ip    (+ data +eth-hdr-len+))
          (proto (ipv4-protocol (+ data +eth-hdr-len+))))
      ;; TCP SYN packets only
      (when (/= proto +ip-proto-tcp+)
        (return XDP_PASS))
      ;; Need TCP header for flags
      (when (> (+ data 54) data-end)         ; 14 + 20 + 20 = 54
        (return XDP_PASS))
      (let ((tcp   (+ ip +ipv4-hdr-len+))
            (flags (tcp-flags (+ ip +ipv4-hdr-len+))))
        ;; Only log new connections (SYN set, ACK not set)
        (when (and (logand flags +tcp-syn+)
                   (not (logand flags +tcp-ack+)))
          ;; Reserve space in ring buffer
          (let ((event (ringbuf-reserve events 12 0)))
            (if event
                ;; Fill event struct and submit
                (progn
                  (setf (conn-event-src-addr event) (ipv4-src-addr ip))
                  (setf (conn-event-dst-addr event) (ipv4-dst-addr ip))
                  (setf (conn-event-dst-port event) (tcp-dst-port tcp))
                  (setf (conn-event-proto event) proto)
                  (ringbuf-submit event 0)
                  (incf (getmap rb-stats +stat-events-sent+)))
                ;; Ring buffer full
                (incf (getmap rb-stats +stat-events-dropped+))))))))
  XDP_PASS)
