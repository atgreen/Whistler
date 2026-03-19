(in-package #:whistler/tests)

(in-suite programs-suite)

;;; ========== Tail calls ==========

(test tail-call-compiles
  "tail-call should compile to a BPF tail call sequence"
  (let ((n (w-count "(tail-call jt 0)
                     (return 0)"
                    :maps '((jt :type :prog-array :key-size 4
                                :value-size 4 :max-entries 8)))))
    ;; tail-call emits: key store + map fd load + call helper 12 + fallthrough
    (is (> n 3) "tail-call should produce several instructions")))

(test tail-call-fallthrough
  "tail-call fallthrough should reach the return"
  ;; tail-call can fail silently; code after it is the fallthrough path
  (let ((bytes (w-body "(tail-call jt 0)
                        (return 42)"
                       :maps '((jt :type :prog-array :key-size 4
                                    :value-size 4 :max-entries 8)))))
    ;; Should still end with exit
    (let ((n (/ (length bytes) 8)))
      (is (= +jmp-exit+ (nth-insn-opcode bytes (1- n)))
          "Should end with exit (fallthrough path)"))))

;;; ========== Ring buffer ==========

(test ringbuf-reserve-compiles
  "ringbuf-reserve should compile"
  (let ((n (w-count "(let ((ptr (ringbuf-reserve rb 64 0)))
                       (declare (type u64 ptr))
                       (if ptr (return 1) (return 0)))"
                    :maps '((rb :type :ringbuf :key-size 0
                                :value-size 0 :max-entries 4096)))))
    (is (> n 4) "ringbuf-reserve should produce instructions")))

;;; ========== Multi-program ==========

(test multi-program-compiles
  "Multiple defprog in one ELF should compile"
  (let ((whistler::*maps* nil)
        (whistler::*programs* nil)
        (whistler::*struct-defs* (make-hash-table :test 'equal)))
    (finishes
      (load (merge-pathnames "examples/multi-prog.lisp"
                             (asdf:system-source-directory :whistler))))))

(test tail-call-dispatch-compiles
  "tail-call-dispatch example should compile"
  (let ((whistler::*maps* nil)
        (whistler::*programs* nil)
        (whistler::*struct-defs* (make-hash-table :test 'equal)))
    (finishes
      (load (merge-pathnames "examples/tail-call-dispatch.lisp"
                             (asdf:system-source-directory :whistler))))))

(test ringbuf-events-compiles
  "ringbuf-events example should compile"
  (let ((whistler::*maps* nil)
        (whistler::*programs* nil)
        (whistler::*struct-defs* (make-hash-table :test 'equal)))
    (finishes
      (load (merge-pathnames "examples/ringbuf-events.lisp"
                             (asdf:system-source-directory :whistler))))))

(test tc-classifier-compiles
  "tc-classifier example should compile"
  (let ((whistler::*maps* nil)
        (whistler::*programs* nil)
        (whistler::*struct-defs* (make-hash-table :test 'equal)))
    (finishes
      (load (merge-pathnames "examples/tc-classifier.lisp"
                             (asdf:system-source-directory :whistler))))))

(test runqlat-compiles
  "runqlat example should compile"
  (let ((whistler::*maps* nil)
        (whistler::*programs* nil)
        (whistler::*struct-defs* (make-hash-table :test 'equal)))
    (finishes
      (load (merge-pathnames "examples/runqlat.lisp"
                             (asdf:system-source-directory :whistler))))))

;;; ========== ELF structure validation ==========

(test elf-has-license-section
  "Generated ELF should have a license section"
  (let* ((cu (compile-single (read-whistler-forms "(return 0)")))
         (path "/tmp/whistler-5am-license-sect.bpf.o"))
    (unwind-protect
         (progn
           (whistler/elf:write-bpf-elf
            path
            :prog-sections (list (list "xdp"
                                       (whistler/bpf:insn-bytes
                                        (whistler/compiler:cu-insns cu))
                                       nil nil))
            :maps nil
            :license "GPL")
           (let ((output (with-output-to-string (s)
                           (uiop:run-program (list "readelf" "-S" path)
                                             :output s :ignore-error-status t))))
             (is (not (null (search "license" output)))
                 "ELF should have a license section")))
      (when (probe-file path)
        (delete-file path)))))

(test elf-has-maps-section
  "ELF with maps should have a maps section"
  (let* ((cu (compile-single
              (read-whistler-forms
               "(let ((key 0))
                  (declare (type u32 key))
                  (let ((val (map-lookup m key)))
                    (declare (type u64 val))
                    (if val (return 1) (return 0))))")
              :maps '((m :type :array :key-size 4
                         :value-size 8 :max-entries 1))))
         (path "/tmp/whistler-5am-maps-sect.bpf.o"))
    (unwind-protect
         (progn
           (let ((map-specs (loop for m in (whistler/compiler:cu-maps cu)
                                  collect (list (whistler/compiler:bpf-map-name m)
                                                (whistler/compiler:bpf-map-type m)
                                                (whistler/compiler:bpf-map-key-size m)
                                                (whistler/compiler:bpf-map-value-size m)
                                                (whistler/compiler:bpf-map-max-entries m)))))
             (whistler/elf:write-bpf-elf
              path
              :prog-sections (list (list "xdp"
                                         (whistler/bpf:insn-bytes
                                          (whistler/compiler:cu-insns cu))
                                         (reverse (whistler/compiler:cu-map-relocs cu))
                                         nil))
              :maps map-specs
              :license "GPL"))
           (let ((output (with-output-to-string (s)
                           (uiop:run-program (list "readelf" "-S" path)
                                             :output s :ignore-error-status t))))
             (is (not (null (search "maps" output)))
                 "ELF should have a maps section")))
      (when (probe-file path)
        (delete-file path)))))
