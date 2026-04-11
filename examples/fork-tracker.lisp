;;; fork-tracker.lisp — Track process forks via tracepoint (inline BPF session)
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Attaches to sched/sched_process_fork and records parent→child PID
;;; mappings in a hash map.  Dumps the map on Ctrl-C.
;;;
;;; This example exercises the tracepoint attachment path in the loader,
;;; based on the test case from issue #32.
;;;
;;; Prerequisites:
;;;   sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/sbcl
;;;   sudo chmod a+r /sys/kernel/tracing/events/sched/sched_process_fork/format
;;;   sudo chmod a+r /sys/kernel/tracing/events/sched/sched_process_fork/id
;;;
;;; Usage:
;;;   sbcl --load examples/fork-tracker.lisp

(asdf:load-system "whistler/loader")

(in-package #:whistler-loader-user)

(whistler:deftracepoint sched/sched-process-fork parent-pid child-pid)

(defun run ()
  (format *error-output* "Compiling and loading BPF program...~%")
  (with-bpf-session ()
    (bpf:map ppid-map :type :hash :key-size 4 :value-size 4 :max-entries 100000)

    (bpf:prog trace (:type :tracepoint
                     :section "tracepoint/sched/sched_process_fork"
                     :license "GPL")
      (setf (whistler:getmap ppid-map (tp-child-pid)) (tp-parent-pid))
      0)

    (format *error-output* "Attaching to tracepoint/sched/sched_process_fork...~%")
    (bpf:attach trace "tracepoint/sched/sched_process_fork")
    (format *error-output* "Tracing process forks. Press Ctrl-C to dump map.~%")

    (handler-case
        (loop (sleep 1))
      (sb-sys:interactive-interrupt ()
        (let ((m (bpf-session-map 'ppid-map))
              (count 0))
          (format t "~&~%~10a  ~10a~%" "CHILD PID" "PARENT PID")
          (format t "~10a  ~10a~%" "---------" "----------")
          (when m
            (let ((key nil))
              (loop
                (let ((next-key (map-get-next-key m key)))
                  (unless next-key (return))
                  (let ((value (map-lookup m next-key)))
                    (when value
                      (format t "~10d  ~10d~%"
                              (decode-int-value next-key)
                              (decode-int-value value))
                      (cl:incf count)))
                  (setf key next-key)))))
          (format t "~%~d forks recorded.~%" count))))))

(run)
