;;; ringbuf.lisp — BPF ring buffer consumer
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Consumes events from BPF_MAP_TYPE_RINGBUF maps via mmap + epoll.

(in-package #:whistler/loader)

;;; ========== Epoll constants ==========

(defconstant +sys-epoll-create1+ 291)
(defconstant +sys-epoll-ctl+ 233)
(defconstant +sys-epoll-wait+ 232)
(defconstant +epoll-ctl-add+ 1)
(defconstant +epollin+ 1)
(defconstant +epoll-cloexec+ #x80000)

;;; ========== Ring buffer consumer ==========

(defstruct ring-consumer
  map-fd ring-size mmap-ptr consumer-ptr producer-ptr data-ptr
  epoll-fd callback closed)

(defun page-size ()
  4096)

(defun open-ring-consumer (map-info callback)
  "Create a ring buffer consumer for a ringbuf map.
   CALLBACK is called with (sap length) for each event."
  (let* ((map-fd (map-info-fd map-info))
         (ring-size (map-info-max-entries map-info))
         (pgsz (page-size))
         ;; mmap in two parts:
         ;; 1. Consumer page (rw) — page 0, offset 0
         ;; 2. Producer page + data (ro) — pages 1+, offset page-size
         (consumer-ptr (sb-posix:mmap nil pgsz
                                      (logior sb-posix:prot-read sb-posix:prot-write)
                                      sb-posix:map-shared
                                      map-fd 0))
         (ro-size (+ pgsz (* 2 ring-size)))
         (ro-ptr (sb-posix:mmap nil ro-size
                                sb-posix:prot-read
                                sb-posix:map-shared
                                map-fd pgsz))
         (mmap-ptr consumer-ptr)
         (producer-ptr ro-ptr)
         (data-ptr (sb-sys:sap+ ro-ptr pgsz))
         ;; Create epoll
         (epoll-fd (syscall +sys-epoll-create1+ +epoll-cloexec+)))

    (when (< epoll-fd 0)
      (error 'bpf-error :context "epoll_create1" :errno (sb-alien:get-errno)))

    ;; Add map fd to epoll
    (let ((event-buf (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0)))
      (put-u32 event-buf 0 +epollin+)  ; events
      (put-u32 event-buf 4 map-fd)     ; data.fd
      (sb-sys:with-pinned-objects (event-buf)
        (let ((ret (syscall +sys-epoll-ctl+ epoll-fd +epoll-ctl-add+
                            map-fd (sb-sys:vector-sap event-buf))))
          (when (< ret 0)
            (error 'bpf-error :context "epoll_ctl" :errno (sb-alien:get-errno))))))

    (make-ring-consumer
     :map-fd map-fd :ring-size ring-size :mmap-ptr mmap-ptr
     :consumer-ptr consumer-ptr :producer-ptr producer-ptr
     :data-ptr data-ptr :epoll-fd epoll-fd :callback callback)))

(defun open-decoding-ring-consumer (map-info decoder callback)
  "Create a ring buffer consumer that decodes each event before CALLBACK.
   DECODER receives an octet vector and returns a decoded event object.
   CALLBACK receives the decoded event."
  (open-ring-consumer
   map-info
   (lambda (sap len)
     (let ((buf (make-array len :element-type '(unsigned-byte 8))))
       (dotimes (i len)
         (setf (aref buf i) (sb-sys:sap-ref-8 sap i)))
       (funcall callback (funcall decoder buf))))))

(defmacro with-decoding-ring-consumer ((var map-info decoder callback) &body body)
  "Bind VAR to a decoding ring consumer and ensure it is closed on exit."
  `(let ((,var (open-decoding-ring-consumer ,map-info ,decoder ,callback)))
     (unwind-protect
          (progn ,@body)
       (close-ring-consumer ,var))))

(defun check-ring-consumer-open (consumer context)
  "Refuse CONTEXT on a closed consumer. The mmapped pages are gone and the
   epoll fd may have been reissued, and neither a raw SAP read nor a syscall
   on a recycled descriptor reports the mistake on its own."
  (when (ring-consumer-closed consumer)
    (error 'bpf-error
           :context (format nil "~a on a closed ring consumer" context)
           :errno 9)))  ; EBADF

(defun ring-poll (consumer &key (timeout-ms 100))
  "Wait for ring buffer events, then consume them. Returns event count."
  (check-ring-consumer-open consumer "ring-poll")
  (let ((event-buf (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0)))
    (sb-sys:with-pinned-objects (event-buf)
      (let ((ret (syscall +sys-epoll-wait+
                          (ring-consumer-epoll-fd consumer)
                          (sb-sys:vector-sap event-buf)
                          1 timeout-ms)))
        (cond
          ((> ret 0) (ring-consume consumer))
          ((= ret 0) 0)  ; timeout
          (t 0))))))      ; error (EINTR etc)

(defun ring-consume (consumer)
  "Process all available events in the ring buffer. Returns event count."
  (check-ring-consumer-open consumer "ring-consume")
  (let* ((ring-size (ring-consumer-ring-size consumer))
         (mask (1- ring-size))
         (data-ptr (ring-consumer-data-ptr consumer))
         (callback (ring-consumer-callback consumer))
         (count 0))
    ;; Read producer position
    (sb-thread:barrier (:read))
    (let ((prod-pos (sb-sys:sap-ref-64 (ring-consumer-producer-ptr consumer) 0))
          (cons-pos (sb-sys:sap-ref-64 (ring-consumer-consumer-ptr consumer) 0)))
      (loop while (< cons-pos prod-pos) do
        (let* ((hdr-off (logand cons-pos mask))
               (hdr (sb-sys:sap-ref-32 data-ptr hdr-off))
               (len (logand hdr #x3fffffff))  ; low 30 bits = length
               (aligned-len (logand (+ len +bpf-ringbuf-hdr-size+ 7) (lognot 7))))
          ;; Check flags
          (cond
            ((logtest hdr +bpf-ringbuf-busy-bit+)
             ;; Not yet committed — stop
             (return))
            ((logtest hdr +bpf-ringbuf-discard-bit+)
             ;; Discarded — skip
             nil)
            (t
             ;; Valid event — call callback with data pointer and length
             (let ((event-off (logand (+ cons-pos +bpf-ringbuf-hdr-size+) mask)))
               (funcall callback (sb-sys:sap+ data-ptr event-off) len)
               (incf count))))
          (incf cons-pos aligned-len)))
      ;; Update consumer position
      (setf (sb-sys:sap-ref-64 (ring-consumer-consumer-ptr consumer) 0) cons-pos)
      (sb-thread:barrier (:write)))
    count))

(defun close-ring-consumer (consumer)
  "Close a ring buffer consumer, unmapping memory and closing epoll.
   Idempotent: a second close is a no-op, so it can never unmap a region
   or close a descriptor the process has since handed to something else."
  (unless (ring-consumer-closed consumer)
    (let ((pgsz (page-size))
          (ring-size (ring-consumer-ring-size consumer))
          (rw-ptr (ring-consumer-mmap-ptr consumer))
          (ro-ptr (ring-consumer-producer-ptr consumer))
          (epoll-fd (ring-consumer-epoll-fd consumer)))
      ;; Drop every handle first. Whatever the syscalls below do, this
      ;; consumer is finished with these resources and must not name them
      ;; again — nor let ring-poll or ring-consume read through them.
      (setf (ring-consumer-closed consumer) t
            (ring-consumer-mmap-ptr consumer) nil
            (ring-consumer-consumer-ptr consumer) nil
            (ring-consumer-producer-ptr consumer) nil
            (ring-consumer-data-ptr consumer) nil
            (ring-consumer-epoll-fd consumer) nil)
      ;; Unmap consumer page (rw)
      (sb-posix:munmap rw-ptr pgsz)
      ;; Unmap producer + data pages (ro)
      (sb-posix:munmap ro-ptr (+ pgsz (* 2 ring-size)))
      (sb-posix:close epoll-fd)))
  nil)
