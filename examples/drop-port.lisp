;;; drop-port.lisp — Drop packets on a specific port
;;;
;;; XDP program that drops TCP packets destined for port 9999.
;;; Uses with-tcp for flat guard-style parsing (bounds + ethertype +
;;; protocol checks as early returns, no intermediate phi nodes).

(in-package #:whistler)

(defmap drop-count :type :array
  :key-size 4 :value-size 8 :max-entries 1)

(defconstant +blocked-port+ 9999)

(defprog drop-port (:type :xdp :section "xdp" :license "GPL")
  (with-tcp (data data-end tcp)
    (when (= (tcp-dst-port tcp) +blocked-port+)
      (incf (getmap drop-count 0))
      (return XDP_DROP)))
  XDP_PASS)
