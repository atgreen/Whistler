(in-package #:whistler/tests)

(def-suite loader-suite
  :description "whistler/loader: ring buffer consumer lifetime"
  :in whistler-suite)

(in-suite loader-suite)

;;; A ring consumer owns two mmapped regions and an epoll fd, and close is
;;; the interesting path. It can be exercised without CAP_BPF and without a
;;; real ringbuf map: build the consumer over anonymous pages and a bare
;;; epoll fd, both of which an unprivileged process can create. Close then
;;; unmaps memory this process really owns and closes an fd it really holds,
;;; so nothing here can fault the image.

(defconstant +ring-test-page-size+ 4096)
(defconstant +ring-test-ring-size+ 4096)

;;; MAP_FIXED_NOREPLACE — take an address back only if it is still free,
;;; rather than evicting whatever the runtime may have put there.
(defconstant +map-fixed-noreplace+ #x100000)

(defun ring-test-ro-size ()
  (+ +ring-test-page-size+ (* 2 +ring-test-ring-size+)))

(defun map-anon-pages (size &optional addr)
  "Map SIZE bytes of private anonymous memory. With ADDR, map at that exact
   address, so a region a close has unmapped becomes valid memory again."
  (sb-posix:mmap addr size
                 (logior sb-posix:prot-read sb-posix:prot-write)
                 (logior sb-posix:map-private sb-posix:map-anon
                         (if addr +map-fixed-noreplace+ 0))
                 -1 0))

(defun make-test-ring-consumer ()
  "Build a ring-consumer over anonymous pages and a real epoll fd."
  (let* ((rw (map-anon-pages +ring-test-page-size+))
         (ro (map-anon-pages (ring-test-ro-size)))
         (epoll-fd (whistler/loader::syscall
                    whistler/loader::+sys-epoll-create1+
                    whistler/loader::+epoll-cloexec+)))
    (whistler/loader::make-ring-consumer
     :map-fd -1
     :ring-size +ring-test-ring-size+
     :mmap-ptr rw
     :consumer-ptr rw
     :producer-ptr ro
     :data-ptr (sb-sys:sap+ ro +ring-test-page-size+)
     :epoll-fd epoll-fd
     :callback (lambda (sap len) (declare (ignore sap len))))))

(defun stage-one-event (consumer-ptr producer-ptr data-ptr)
  "Lay one committed 4-byte event into the pages a ring consumer reads, so
   that a consumer which does read them reports an event rather than zero."
  (setf (sb-sys:sap-ref-64 consumer-ptr 0) 0)
  (setf (sb-sys:sap-ref-32 data-ptr 0) 4)
  (setf (sb-sys:sap-ref-64 producer-ptr 0)
        (logand (+ 4 whistler/loader::+bpf-ringbuf-hdr-size+ 7) (lognot 7))))

(defun fd-open-p (fd)
  (handler-case (progn (sb-posix:fcntl fd sb-posix:f-getfd) t)
    (sb-posix:syscall-error () nil)))

(defun signals-bpf-error-p (thunk)
  (handler-case (progn (funcall thunk) nil)
    (whistler/loader:bpf-error () t)))

;;; ========== Close is a one-shot operation ==========

(test closing-a-ring-consumer-twice-spares-the-reissued-fd
  (let* ((consumer (make-test-ring-consumer))
         (rw (whistler/loader::ring-consumer-mmap-ptr consumer))
         (ro (whistler/loader::ring-consumer-producer-ptr consumer))
         (epoll-fd (whistler/loader::ring-consumer-epoll-fd consumer)))
    (whistler/loader:close-ring-consumer consumer)
    ;; Take the addresses back so a second close unmaps memory we own.
    (map-anon-pages +ring-test-page-size+ rw)
    (map-anon-pages (ring-test-ro-size) ro)
    ;; The kernel hands out the lowest free descriptor, so this lands on the
    ;; number the consumer just gave up.
    (let ((reused-fd (whistler/loader::syscall
                      whistler/loader::+sys-epoll-create1+
                      whistler/loader::+epoll-cloexec+)))
      (unwind-protect
           (progn
             (is (= reused-fd epoll-fd)
                 "the test needs the descriptor reissued: got ~D, wanted ~D"
                 reused-fd epoll-fd)
             (whistler/loader:close-ring-consumer consumer)
             (is (fd-open-p reused-fd)
                 "the second close closed descriptor ~D, which now belongs to something else"
                 reused-fd))
        (when (fd-open-p reused-fd)
          (sb-posix:close reused-fd))
        (sb-posix:munmap rw +ring-test-page-size+)
        (sb-posix:munmap ro (ring-test-ro-size))))))

;;; ========== Reading after close ==========

(test ring-consume-refuses-a-closed-consumer
  (let* ((consumer (make-test-ring-consumer))
         (rw (whistler/loader::ring-consumer-mmap-ptr consumer))
         (ro (whistler/loader::ring-consumer-producer-ptr consumer))
         (data (whistler/loader::ring-consumer-data-ptr consumer)))
    (whistler/loader:close-ring-consumer consumer)
    ;; Make the surrendered addresses valid and event-shaped again. This is
    ;; what an unlucky reallocation looks like from the outside, and it is
    ;; what the consumer's stale pointers would read.
    (map-anon-pages +ring-test-page-size+ rw)
    (map-anon-pages (ring-test-ro-size) ro)
    (stage-one-event rw ro data)
    (unwind-protect
         (is (signals-bpf-error-p
              (lambda () (whistler/loader:ring-consume consumer)))
             "ring-consume read the recycled pages instead of signalling")
      (sb-posix:munmap rw +ring-test-page-size+)
      (sb-posix:munmap ro (ring-test-ro-size)))))

(test ring-poll-refuses-a-closed-consumer
  (let* ((consumer (make-test-ring-consumer))
         (rw (whistler/loader::ring-consumer-mmap-ptr consumer))
         (ro (whistler/loader::ring-consumer-producer-ptr consumer))
         (data (whistler/loader::ring-consumer-data-ptr consumer)))
    (whistler/loader:close-ring-consumer consumer)
    (map-anon-pages +ring-test-page-size+ rw)
    (map-anon-pages (ring-test-ro-size) ro)
    (stage-one-event rw ro data)
    (unwind-protect
         (is (signals-bpf-error-p
              (lambda () (whistler/loader:ring-poll consumer :timeout-ms 0)))
             "ring-poll waited on a descriptor the consumer no longer owns")
      (sb-posix:munmap rw +ring-test-page-size+)
      (sb-posix:munmap ro (ring-test-ro-size)))))
