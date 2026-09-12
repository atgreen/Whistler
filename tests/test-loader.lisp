(in-package #:whistler/tests)

(def-suite loader-suite
  :description "whistler/loader: ring buffer consumer lifetime, ELF header validation"
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

;;; ========== ELF header validation ==========
;;;
;;; A caller who hands the loader something that is not a BPF object should be
;;; told exactly that. The header fields only mean anything once the file has
;;; been shown to be long enough to carry them, so each read has to sit behind
;;; the check that justifies it.

(defun octets (sequence)
  (coerce sequence '(vector (unsigned-byte 8))))

(defun ascii-octets (string)
  (map '(vector (unsigned-byte 8)) #'char-code string))

(defun elf-ident-octets ()
  "The four identification bytes at the head of every ELF file."
  (octets (list #x7f (char-code #\E) (char-code #\L) (char-code #\F))))

(defun elf64-header-octets (&key (class 2) (data 1)
                                 (machine whistler/binary:+em-bpf+))
  "Build a 64-byte ELF64 header carrying the fields the loader inspects.
   Every other byte is left zero."
  (let ((header (make-array 64 :element-type '(unsigned-byte 8)
                               :initial-element 0)))
    (replace header (elf-ident-octets))
    (setf (aref header 4) class
          (aref header 5) data
          (aref header 18) (ldb (byte 8 0) machine)
          (aref header 19) (ldb (byte 8 8) machine))
    header))

(defun elf-parse-condition (bytes)
  "Write BYTES to a temp file and parse it as a BPF ELF. Returns the condition
   the parse signalled, or NIL when it parsed without complaint."
  (uiop:with-temporary-file (:stream out :pathname path
                             :element-type '(unsigned-byte 8))
    (write-sequence bytes out)
    (finish-output out)
    (handler-case (progn (whistler/loader::read-bpf-elf path) nil)
      (error (e) e))))

(defun reports-p (condition text)
  (and condition (search text (princ-to-string condition)) t))

(test a-short-non-elf-file-is-reported-as-not-an-elf
  (let ((condition (elf-parse-condition (ascii-octets "not an elf!!!"))))
    (is (not (typep condition 'sb-int:invalid-array-index-error))
        "the parser indexed past the end of the file instead of checking it: ~a"
        condition)
    (is (reports-p condition "Not an ELF file")
        "wanted a report that the file is not an ELF, got: ~a" condition)))

(test a-file-too-short-for-the-magic-is-reported-as-not-an-elf
  (dolist (length '(0 1 2 3))
    (let ((condition (elf-parse-condition (subseq (elf-ident-octets) 0 length))))
      (is (not (typep condition 'sb-int:invalid-array-index-error))
          "a ~D-byte file was indexed rather than measured: ~a" length condition)
      (is (reports-p condition "Not an ELF file")
          "wanted a report that a ~D-byte file is not an ELF, got: ~a"
          length condition))))

(test a-truncated-elf-header-is-reported-as-truncated
  (let ((condition (elf-parse-condition (subseq (elf64-header-octets) 0 32))))
    (is (not (typep condition 'sb-int:invalid-array-index-error))
        "the section-header geometry was read out of a half-length header: ~a"
        condition)
    (is (reports-p condition "Truncated ELF header")
        "wanted a report that the header is short, got: ~a" condition)))

(test a-non-bpf-elf-keeps-its-own-report
  ;; EM_X86_64 — a genuine ELF, just not one this loader can use.
  (let ((condition (elf-parse-condition (elf64-header-octets :machine 62))))
    (is (not (typep condition 'sb-int:invalid-array-index-error))
        "a well-formed header failed on an index rather than on its machine: ~a"
        condition)
    (is (reports-p condition "Not a 64-bit LE BPF ELF")
        "wanted the machine-mismatch report, got: ~a" condition)))

(test a-compiled-bpf-object-still-parses
  (uiop:with-temporary-file (:stream source :pathname source-path :type "lisp")
    (write-string "(in-package #:whistler)
                   (defprog elf-header-probe
                       (:type :xdp :section \"xdp\" :license \"GPL\")
                     (return 2))"
                  source)
    (finish-output source)
    (let ((object-path (make-pathname :type "bpf.o" :defaults source-path)))
      (unwind-protect
           (progn
             (whistler::compile-file* source-path object-path)
             (let ((elf (whistler/loader::read-bpf-elf object-path)))
               (is (string= "GPL" (whistler/loader::bpf-elf-license elf))
                   "license section did not survive the round trip")
               (is (= 1 (length (whistler/loader::bpf-elf-prog-sections elf)))
                   "wanted one program section, got ~D"
                   (length (whistler/loader::bpf-elf-prog-sections elf)))))
        (when (probe-file object-path) (delete-file object-path))))))
