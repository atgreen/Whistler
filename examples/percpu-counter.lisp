;;; percpu-counter.lisp — Per-iteration context access in a loop
;;;
;;; XDP program that checks packet bounds in each iteration of a loop,
;;; using ctx field access that is loop-invariant. LICM hoists the loads
;;; (data and data-end pointers) out of the loop, saving 2 memory reads
;;; per iteration.

(in-package #:whistler)

(defmap counters :type :array
  :key-size 4 :value-size 8 :max-entries 4)

(defprog count-with-bounds-check (:type :xdp :section "xdp" :license "GPL")
  (let ((total u64 0))
    (dotimes (i 4)
      ;; These two ctx reads produce the same value every iteration.
      ;; LICM hoists them to the preheader.
      (let ((data     u64 (ctx data))
            (data-end u64 (ctx data-end)))
        (when (> data-end data)
          (setf total (+ total 1)))))
    (return total)))
