;;; syscall.lisp — Linux syscall wrappers for BPF operations
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Uses SBCL's sb-alien for direct syscall access. No CFFI dependency.

(in-package #:whistler/loader)

;;; ========== Conditions ==========

(define-condition bpf-error (error)
  ((context :initarg :context :reader bpf-error-context)
   (errno :initarg :errno :reader bpf-error-errno))
  (:report (lambda (c s)
             (format s "BPF error in ~a: errno ~d (~a)"
                     (bpf-error-context c)
                     (bpf-error-errno c)
                     (sb-int:strerror (bpf-error-errno c))))))

(define-condition bpf-verifier-error (bpf-error)
  ((log :initarg :log :reader bpf-verifier-error-log))
  (:report (lambda (c s)
             (format s "BPF verifier rejected program~%~a"
                     (bpf-verifier-error-log c)))))

;;; ========== Syscall numbers (x86-64) ==========

(defconstant +sys-bpf+ 321)
(defconstant +sys-perf-event-open+ 298)
(defconstant +sys-ioctl+ 16)

;;; ========== BPF commands ==========

(defconstant +bpf-map-create+ 0)
(defconstant +bpf-map-lookup-elem+ 1)
(defconstant +bpf-map-update-elem+ 2)
(defconstant +bpf-map-delete-elem+ 3)
(defconstant +bpf-map-get-next-key+ 4)
(defconstant +bpf-prog-load+ 5)
(defconstant +bpf-obj-pin+ 6)
(defconstant +bpf-obj-get+ 7)

;;; ========== BPF map types ==========

(defconstant +bpf-map-type-hash+ 1)
(defconstant +bpf-map-type-array+ 2)
(defconstant +bpf-map-type-percpu-hash+ 5)
(defconstant +bpf-map-type-percpu-array+ 6)
(defconstant +bpf-map-type-lru-hash+ 9)
(defconstant +bpf-map-type-ringbuf+ 27)

;;; ========== BPF program types ==========

(defconstant +bpf-prog-type-socket-filter+ 1)
(defconstant +bpf-prog-type-kprobe+ 2)
(defconstant +bpf-prog-type-sched-cls+ 3)
(defconstant +bpf-prog-type-tracepoint+ 5)
(defconstant +bpf-prog-type-xdp+ 6)

;;; ========== Perf event constants ==========

(defconstant +perf-type-tracepoint+ 2)
(defconstant +perf-sample-raw+ 1024)
(defconstant +perf-flag-fd-cloexec+ 8)
(defconstant +perf-event-ioc-set-bpf+ #x40042408)
(defconstant +perf-event-ioc-enable+ #x2400)

;;; ========== Ring buffer constants ==========

(defconstant +bpf-ringbuf-busy-bit+ (ash 1 31))
(defconstant +bpf-ringbuf-discard-bit+ (ash 1 30))
(defconstant +bpf-ringbuf-hdr-size+ 8)

;;; ========== Low-level syscall ==========

(declaim (inline %raw-syscall))
(defun %raw-syscall (number &rest args)
  "Raw syscall via sb-alien. Handles up to 6 args."
  (apply #'sb-alien:alien-funcall
         (sb-alien:extern-alien "syscall"
                                (sb-alien:function sb-alien:long
                                                   sb-alien:long
                                                   sb-alien:long sb-alien:long
                                                   sb-alien:long sb-alien:long
                                                   sb-alien:long sb-alien:long))
         number
         (loop for i below 6
               collect (if (< i (length args))
                           (let ((a (nth i args)))
                             (etypecase a
                               (integer a)
                               (sb-sys:system-area-pointer (sb-sys:sap-int a))))
                           0))))

(defun syscall (number &rest args)
  (apply #'%raw-syscall number args))

;;; ========== Byte array helpers ==========

(defun make-attr-buf (&optional (size 256))
  "Create a zeroed bpf_attr buffer."
  (make-array size :element-type '(unsigned-byte 8) :initial-element 0))

(defun put-u32 (buf offset val)
  (setf (aref buf offset) (logand val #xff))
  (setf (aref buf (+ offset 1)) (logand (ash val -8) #xff))
  (setf (aref buf (+ offset 2)) (logand (ash val -16) #xff))
  (setf (aref buf (+ offset 3)) (logand (ash val -24) #xff)))

(defun put-u64 (buf offset val)
  (put-u32 buf offset (logand val #xffffffff))
  (put-u32 buf (+ offset 4) (logand (ash val -32) #xffffffff)))

(defun get-u32 (buf offset)
  (logior (aref buf offset)
          (ash (aref buf (+ offset 1)) 8)
          (ash (aref buf (+ offset 2)) 16)
          (ash (aref buf (+ offset 3)) 24)))

(defun get-u64 (buf offset)
  (logior (get-u32 buf offset)
          (ash (get-u32 buf (+ offset 4)) 32)))

(defun put-ptr (buf offset sap)
  "Store a SAP (system area pointer) as a u64 in the buffer."
  (put-u64 buf offset (sb-sys:sap-int sap)))

;;; ========== BPF syscall wrapper ==========

(defun %bpf (cmd attr-buf attr-size context)
  "Call bpf() syscall. Returns the fd/result on success, signals bpf-error on failure."
  (sb-sys:with-pinned-objects (attr-buf)
    (let ((ret (syscall +sys-bpf+ cmd
                        (sb-sys:vector-sap attr-buf)
                        attr-size)))
      (when (< ret 0)
        (error 'bpf-error :context context
                           :errno (sb-alien:get-errno)))
      ret)))

;;; ========== Perf event open ==========

(defun %perf-event-open (attr-buf pid cpu group-fd flags)
  "Call perf_event_open() syscall."
  (sb-sys:with-pinned-objects (attr-buf)
    (let ((ret (syscall +sys-perf-event-open+
                        (sb-sys:vector-sap attr-buf)
                        pid cpu group-fd flags)))
      (when (< ret 0)
        (error 'bpf-error :context "perf_event_open"
                           :errno (sb-alien:get-errno)))
      ret)))

;;; ========== Ioctl ==========

(defun %ioctl (fd request arg)
  "Call ioctl()."
  (let ((ret (syscall +sys-ioctl+ fd request arg)))
    (when (< ret 0)
      (error 'bpf-error :context (format nil "ioctl ~x" request)
                         :errno (sb-alien:get-errno)))
    ret))

;;; ========== File helpers ==========

(defun read-file-string (path)
  "Read a file as a trimmed string. Returns nil if file doesn't exist."
  (handler-case
      (string-trim '(#\Space #\Newline #\Return #\Tab)
                   (with-open-file (f path) (read-line f)))
    (error () nil)))

(defun read-file-int (path)
  "Read an integer from a file. Returns nil if file doesn't exist."
  (let ((s (read-file-string path)))
    (when s (parse-integer s :junk-allowed t))))
