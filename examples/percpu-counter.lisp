;;; percpu-counter.lisp — Per-CPU packet counter with XDP
;;;
;;; A minimal XDP program that counts every packet using a BPF
;;; per-CPU array map. Unlike a plain :array map, a :percpu-array gives
;;; each CPU its own copy of the value, so increments on different cores
;;; never touch the same cache line. Userspace reads one slot per CPU and
;;; sums them (see the loader's percpu-value-size handling).

(in-package #:whistler)

(defmap pkt-count :type :percpu-array
  :key-size 4 :value-size 8 :max-entries 1)

(defprog count-packets (:type :xdp :section "xdp" :license "GPL")
  ;; getmap on a percpu map returns this CPU's slot.
  (incf (getmap pkt-count 0))
  XDP_PASS)
