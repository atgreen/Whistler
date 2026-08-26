;;; licm-loop.lisp — Loop-invariant code motion over context loads
;;;
;;; XDP program that reads loop-invariant ctx fields (data and data-end
;;; pointers) inside a loop. The two reads produce the same value on every
;;; iteration, so LICM hoists them into the loop preheader — saving 2 memory
;;; reads per iteration. Inspect the disassembly to see the loads emitted
;;; once, before the loop, rather than four times inside it.

(in-package #:whistler)

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
