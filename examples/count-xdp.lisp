;;; count-xdp.lisp — Count packets with XDP
;;;
;;; A minimal XDP program that counts every packet passing through
;;; an interface using a BPF array map.

(in-package #:whistler)

(defmap pkt-count :type :array
  :key-size 4 :value-size 8 :max-entries 1)

(defprog count-packets (:type :xdp :section "xdp" :license "GPL")
  (incf (getmap pkt-count 0))
  XDP_PASS)
