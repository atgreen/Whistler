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
  epoll-fd callback)

(defun page-size ()
  4096)

(defun open-ring-consumer (map-info callback)
  "Create a ring buffer consumer for a ringbuf map.
   CALLBACK is called with (sap length) for each event."
  (let* ((map-fd (map-info-fd map-info))
         (ring-size (map-info-max-entries map-info))
         (pgsz (page-size))
         ;; mmap: consumer page (rw) + producer page + 2*data (ro)
         (mmap-size (+ pgsz pgsz (* 2 ring-size)))
         (mmap-ptr (sb-posix:mmap nil mmap-size
                                  (logior sb-posix:prot-read sb-posix:prot-write)
                                  sb-posix:map-shared
                                  map-fd 0))
         ;; Consumer position at mmap-ptr + 0
         ;; Producer position at mmap-ptr + page-size
         ;; Data at mmap-ptr + 2*page-size
         (consumer-ptr mmap-ptr)
         (producer-ptr (sb-sys:sap+ mmap-ptr pgsz))
         (data-ptr (sb-sys:sap+ mmap-ptr (* 2 pgsz)))
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

(defun ring-poll (consumer &key (timeout-ms 100))
  "Wait for ring buffer events, then consume them. Returns event count."
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
  "Close a ring buffer consumer, unmapping memory and closing epoll."
  (let ((pgsz (page-size))
        (ring-size (ring-consumer-ring-size consumer)))
    (sb-posix:munmap (ring-consumer-mmap-ptr consumer)
                     (+ pgsz pgsz (* 2 ring-size))))
  (sb-posix:close (ring-consumer-epoll-fd consumer)))
