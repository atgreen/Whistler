;;; tail-call-dispatch.lisp — Protocol dispatch via tail calls
;;;
;;; Demonstrates BPF tail calls for splitting packet processing into
;;; separate programs per protocol. A dispatcher reads the IP protocol
;;; field and tail-calls into the appropriate handler.
;;;
;;; At load time, populate the jump table:
;;;   bpftool map update name jt key 6 0 0 0 value pinned /sys/fs/bpf/tcp_handler
;;;   bpftool map update name jt key 17 0 0 0 value pinned /sys/fs/bpf/udp_handler

(in-package #:whistler)

;;; Maps

;; Jump table: protocol number → program FD
(defmap jt :type :prog-array
  :key-size 4 :value-size 4 :max-entries 256)

;; Per-protocol packet counters
(defmap proto-stats :type :array
  :key-size 4 :value-size 8 :max-entries 3)

;;; Constants
(defconstant +stat-dispatched+ 0)
(defconstant +stat-tcp+ 1)
(defconstant +stat-udp+ 2)

;;; Dispatcher — entry point
(defprog xdp-dispatch (:type :xdp :section "xdp" :license "GPL")
  (let ((data     (xdp-data))
        (data-end (xdp-data-end)))
    (when (> (+ data 34) data-end)              ; Eth(14) + IPv4(20)
      (return XDP_PASS))
    (when (/= (eth-type data) +ethertype-ipv4+)
      (return XDP_PASS))
    (let ((proto (ipv4-protocol (+ data +eth-hdr-len+))))
      (declare (type u32 proto))
      (incf (getmap proto-stats +stat-dispatched+))
      ;; Tail call into protocol-specific handler
      ;; If no handler loaded for this protocol, fall through to XDP_PASS
      (tail-call jt proto)))
  XDP_PASS)
