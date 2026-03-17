;;; Test SSA pipeline

(in-package #:whistler)

(format t "~%=== SSA Pipeline Tests ===~%")

;; Simple return
(let ((cu (compile-program-ssa "xdp" "GPL" nil '((return 2)))))
  (format t "  return 2: ~d insns~%" (length (cu-insns cu))))

;; Arithmetic
(let ((cu (compile-program-ssa "xdp" "GPL" nil '((return (+ 1 2))))))
  (format t "  return (+ 1 2): ~d insns~%" (length (cu-insns cu))))

;; Let + if
(let ((cu (compile-program-ssa "xdp" "GPL" nil
            '((let ((x u32 10))
                (if (> x 5) (return 2) (return 1)))))))
  (format t "  let+if: ~d insns~%" (length (cu-insns cu))))

;; Map lookup
(let ((cu (compile-program-ssa "xdp" "GPL"
            '((my-map :type :array :key-size 4 :value-size 8 :max-entries 1))
            '((let ((key u32 0))
                (let ((val u64 (map-lookup my-map key)))
                  (return 2)))))))
  (format t "  map-lookup: ~d insns~%" (length (cu-insns cu))))

;; Count-xdp
(let ((*maps* nil) (*programs* nil))
  (defmap test-pkt-count :type :array
    :key-size 4 :value-size 8 :max-entries 1)
  (defprog test-count-packets (:type :xdp :section "xdp" :license "GPL")
    (let ((key u32 0))
      (let ((val u64 (map-lookup test-pkt-count key)))
        (if val
            (atomic-add val 0 1)
            (let ((init u64 1))
              (map-update test-pkt-count key init 0)))))
    (return XDP_PASS))
  (let* ((maps (reverse *maps*))
         (progs (reverse *programs*)))
    (destructuring-bind (name &key section license body) (first progs)
      (declare (ignore name))
      (let ((cu-old (compile-program section license maps body))
            (cu-new (compile-program-ssa section license maps body)))
        (format t "  count-xdp: old=~d SSA=~d~%"
                (length (cu-insns cu-old)) (length (cu-insns cu-new))))))
  ;; Also write ELF from SSA to verify
  (let* ((maps (reverse *maps*))
         (progs (reverse *programs*)))
    (destructuring-bind (name &key section license body) (first progs)
      (declare (ignore name))
      (let ((cu (compile-program-ssa section license maps body)))
        (let ((path "/tmp/whistler-ssa-test.bpf.o")
              (insn-bytes (insn-bytes (cu-insns cu)))
              (map-specs (loop for m in (cu-maps cu)
                               collect (list (bpf-map-name m)
                                             (bpf-map-type m)
                                             (bpf-map-key-size m)
                                             (bpf-map-value-size m)
                                             (bpf-map-max-entries m))))
              (relocs (reverse (cu-map-relocs cu))))
          (write-bpf-elf path
                         :prog-section-name "xdp"
                         :prog-bytes insn-bytes
                         :maps map-specs
                         :relocations relocs
                         :license "GPL")
          (let ((output (with-output-to-string (s)
                          (uiop:run-program (list "readelf" "-S" path)
                                            :output s :ignore-error-status t))))
            (if (search "xdp" output)
                (format t "  SSA ELF: valid~%")
                (format t "  SSA ELF: INVALID~%")))
          (delete-file path))))))

;; Runqlat
(let ((*maps* nil) (*programs* nil))
  (load "examples/runqlat.lisp")
  (let* ((maps (reverse *maps*))
         (progs (reverse *programs*)))
    (destructuring-bind (name &key section license body) (first progs)
      (declare (ignore name))
      (let ((cu-old (compile-program section license maps body))
            (cu-new (compile-program-ssa section license maps body)))
        (format t "  runqlat: old=~d SSA=~d~%"
                (length (cu-insns cu-old)) (length (cu-insns cu-new)))))))
