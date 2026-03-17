;;; multi-prog.lisp — Multiple programs in one ELF object
;;;
;;; Demonstrates multi-program compilation: a dispatcher and handler
;;; share maps and compile into one .bpf.o with separate ELF sections.

(in-package #:whistler)

;;; Shared maps
(defmap pkt-stats :type :array
  :key-size 4 :value-size 8 :max-entries 4)

(defmap jt :type :prog-array
  :key-size 4 :value-size 4 :max-entries 8)

(defconstant +stat-total+   0)
(defconstant +stat-ipv4+    1)
(defconstant +stat-other+   2)

;;; Program 1: dispatcher
(defprog xdp-main (:type :xdp :section "xdp" :license "GPL")
  (let ((data     (xdp-data))
        (data-end (xdp-data-end)))
    (incf (getmap pkt-stats +stat-total+))
    (when (> (+ data 14) data-end)
      (return XDP_PASS))
    (when (= (eth-type data) +ethertype-ipv4+)
      (tail-call jt 0))   ; jump to IPv4 handler
    (incf (getmap pkt-stats +stat-other+)))
  XDP_PASS)

;;; Program 2: IPv4 handler
(defprog ipv4-handler (:type :xdp :section "xdp/ipv4" :license "GPL")
  (incf (getmap pkt-stats +stat-ipv4+))
  XDP_PASS)
