;;; runqlat.lisp — Run queue latency histogram
;;;
;;; Measures time tasks spend waiting on the CPU run queue.
;;; Produces a log2 histogram of latencies in microseconds.
;;;
;;; Whistler port of iovisor/bcc libbpf-tools/runqlat.
;;;
;;; This implements the sched_switch tracepoint handler which:
;;;   1. Records enqueue timestamps for preempted (still-runnable) tasks
;;;   2. Computes run-queue latency when tasks get scheduled

(in-package #:whistler)

;;; ---- Maps ----

;; pid → enqueue timestamp (nanoseconds)
(defmap start :type :hash
  :key-size 4 :value-size 8 :max-entries 10240)

;; Log2 histogram: 26 buckets (index → count)
(defmap hist :type :array
  :key-size 4 :value-size 8 :max-entries 26)

;;; ---- Constants ----

(defconstant +task-running+ 0)
(defconstant +max-slots+ 26)

;;; ---- Tracepoint field accessors ----

(defmacro tp-prev-pid ()   `(ctx-load u32 24))
(defmacro tp-prev-state () `(ctx-load u64 32))
(defmacro tp-next-pid ()   `(ctx-load u32 56))

;;; ---- Program ----

(defprog runqlat (:type :tracepoint
                  :section "tracepoint/sched/sched_switch"
                  :license "GPL")

  (let ((prev-pid   (tp-prev-pid))
        (prev-state (tp-prev-state))
        (next-pid   (tp-next-pid)))

    ;; If previous task is still runnable (preempted, not blocking),
    ;; record its enqueue time.
    (when (and (= prev-state +task-running+) prev-pid)
      (setf (getmap start prev-pid) (ktime-get-ns)))

    ;; Look up when the incoming task was enqueued.
    (when-let ((tsp (map-lookup start next-pid)))
      ;; Compute latency: (now - enqueue_time), convert ns → µs
      (let ((delta (- (ktime-get-ns) (load u64 tsp 0))))
        (setf delta (/ delta 1000))

        ;; Map to log2 histogram bucket
        (let ((slot (log2 delta)))
          (when (>= slot +max-slots+)
            (setf slot (- +max-slots+ 1)))

          ;; Increment the bucket counter
          (when-let ((countp (map-lookup hist slot)))
            (atomic-add countp 0 1))))

      ;; Clean up: remove the timestamp entry
      (remmap start next-pid)))

  0)
