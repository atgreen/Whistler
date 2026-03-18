;;; Whistler test suite

(in-package #:whistler)

(defvar *test-count* 0)
(defvar *pass-count* 0)
(defvar *fail-count* 0)

(defmacro deftest (name &body body)
  `(progn
     (incf *test-count*)
     (handler-case
         (progn ,@body
                (incf *pass-count*)
                (format t "  PASS: ~a~%" ',name))
       (error (e)
         (incf *fail-count*)
         (format t "  FAIL: ~a — ~a~%" ',name e)))))

(defmacro assert-eq (expected actual)
  `(let ((e ,expected) (a ,actual))
     (unless (equal e a)
       (error "Expected ~s, got ~s" e a))))

(defmacro assert-true (expr)
  `(unless ,expr
     (error "Expected true: ~s" ',expr)))

;;; BPF instruction encoding tests

(format t "~%=== BPF Instruction Encoding ===~%")

(deftest encode-mov64-imm
  (let* ((insns (whistler/bpf:emit-mov64-imm 1 42))
         (insn (first insns))
         (bytes (whistler/bpf:encode-insn insn)))
    (assert-eq 8 (length bytes))
    ;; code = ALU64 | K | MOV = 0x07 | 0x00 | 0xb0 = 0xb7
    (assert-eq #xb7 (aref bytes 0))
    ;; dst=1, src=0 → byte = 0x01
    (assert-eq #x01 (aref bytes 1))
    ;; imm=42 LE
    (assert-eq 42 (aref bytes 4))))

(deftest encode-exit
  (let* ((insns (whistler/bpf:emit-exit))
         (insn (first insns))
         (bytes (whistler/bpf:encode-insn insn)))
    ;; code = JMP | EXIT = 0x05 | 0x90 = 0x95
    (assert-eq #x95 (aref bytes 0))))

(deftest encode-call
  (let* ((insns (whistler/bpf:emit-call 1))
         (insn (first insns))
         (bytes (whistler/bpf:encode-insn insn)))
    ;; code = JMP | CALL = 0x05 | 0x80 = 0x85
    (assert-eq #x85 (aref bytes 0))
    ;; imm = 1 (map_lookup_elem)
    (assert-eq 1 (aref bytes 4))))

(deftest encode-ld-imm64
  (let ((insns (whistler/bpf:emit-ld-imm64 1 #xdeadbeef)))
    (assert-eq 2 (length insns))
    (let ((bytes (whistler/bpf:encode-insn (first insns))))
      ;; code = LD | DW | IMM = 0x00 | 0x18 | 0x00 = 0x18
      (assert-eq #x18 (aref bytes 0)))))

;;; Compiler tests

(format t "~%=== Compiler ===~%")

(deftest compile-return-constant
  (let ((cu (compile-program "xdp" "GPL" nil '((return 2)))))
    ;; Should have: mov64 r0,2 ; exit (ctx save elided — R6 unused)
    (assert-eq 2 (length (cu-insns cu)))))

(deftest compile-arithmetic
  ;; (+ 1 2) is constant-folded to 3, so this becomes (return 3):
  ;; mov r0,3 ; exit — 2 instructions (ctx save elided)
  (let ((cu (compile-program "xdp" "GPL" nil
              '((return (+ 1 2))))))
    (assert-eq 2 (length (cu-insns cu)))))

(deftest compile-let-binding
  (let ((cu (compile-program "xdp" "GPL" nil
              '((let ((x u32 42))
                  (return x))))))
    ;; The let-bound constant is fully folded away.
    (assert-eq 2 (length (cu-insns cu)))))

(deftest compile-if-cmp
  (let ((cu (compile-program "xdp" "GPL" nil
              '((let ((x u32 10))
                  (if (> x 5)
                      (return 2)
                      (return 1)))))))
    (assert-true (> (length (cu-insns cu)) 4))))

(deftest compile-log2-intrinsic
  ;; log2 intrinsic emits unrolled binary search: 15 instructions
  ;; (1 mov-imm for result + 4 × (jlt + rsh + add) + 1 jlt + 1 add)
  ;; Plus: mov r0,0 + let binding + exit = total should include 15 log2 insns
  (let ((cu (compile-program "xdp" "GPL" nil
              '((let ((x u64 1024))
                  (return (log2 x)))))))
    ;; Should have: mov r7,1024 ; mov r0,0 ; (15 log2 insns) ; exit = 18
    ;; ctx save elided since R6 unused
    (assert-eq 18 (length (cu-insns cu)))))

(deftest compile-constant-folding
  ;; (+ 10 (* 3 4)) should fold to 22
  (let ((cu (compile-program "xdp" "GPL" nil
              '((return (+ 10 (* 3 4)))))))
    ;; Folds to (return 22): mov r0,22 ; exit = 2 instructions
    (assert-eq 2 (length (cu-insns cu)))))

(deftest compile-map-lookup
  (let ((cu (compile-program "xdp" "GPL"
              '((my-map :type :array :key-size 4 :value-size 8 :max-entries 1))
              '((let ((key u32 0))
                  (let ((val u64 (map-lookup my-map key)))
                    (if val
                        (return 2)
                        (return 1))))))))
    (assert-true (> (length (cu-insns cu)) 5))
    (assert-eq 1 (length (cu-maps cu)))
    (assert-true (> (length (cu-map-relocs cu)) 0))))

;;; ELF output test

(format t "~%=== ELF Output ===~%")

(deftest write-minimal-elf
  (let ((cu (compile-program "xdp" "GPL" nil '((return 2)))))
    (let ((path "/tmp/whistler-test.bpf.o"))
      (let ((insn-bytes (whistler/bpf:insn-bytes (cu-insns cu))))
        (whistler/elf:write-bpf-elf path
                                    :prog-sections (list (list "xdp" insn-bytes nil nil))
                                    :maps nil
                                    :license "GPL"))
      ;; Check file exists and has ELF magic
      (with-open-file (in path :element-type '(unsigned-byte 8))
        (let ((magic (make-array 4 :element-type '(unsigned-byte 8))))
          (read-sequence magic in)
          (assert-eq #x7f (aref magic 0))
          (assert-eq (char-code #\E) (aref magic 1))
          (assert-eq (char-code #\L) (aref magic 2))
          (assert-eq (char-code #\F) (aref magic 3))))
      (delete-file path))))

(deftest write-elf-with-maps
  (let ((cu (compile-program "xdp" "GPL"
              '((pkt-count :type :array :key-size 4 :value-size 8 :max-entries 1))
              '((let ((key u32 0))
                  (let ((val u64 (map-lookup pkt-count key)))
                    (return 2)))))))
    (let ((path "/tmp/whistler-test-maps.bpf.o"))
      (let ((insn-bytes (whistler/bpf:insn-bytes (cu-insns cu)))
            (map-specs (loop for m in (cu-maps cu)
                             collect (list (bpf-map-name m)
                                           (bpf-map-type m)
                                           (bpf-map-key-size m)
                                           (bpf-map-value-size m)
                                           (bpf-map-max-entries m))))
            (relocs (reverse (cu-map-relocs cu))))
        (whistler/elf:write-bpf-elf path
                                    :prog-sections (list (list "xdp" insn-bytes relocs nil))
                                    :maps map-specs
                                    :license "GPL"))
      ;; Verify with readelf if available
      (let ((output (with-output-to-string (s)
                      (uiop:run-program (list "readelf" "-h" path)
                                        :output s :ignore-error-status t))))
        ;; readelf shows machine as "Linux BPF" or "<unknown>: 0xf7"
        (assert-true (or (search "BPF" output)
                         (search "0xf7" output)
                         (search "ELF" output))))
      (delete-file path))))

;;; Full integration test

(format t "~%=== Integration ===~%")

(deftest compile-count-xdp-program
  (let ((*maps* nil)
        (*programs* nil))
    ;; Define the program inline
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
    (let ((path "/tmp/whistler-integration.bpf.o"))
      (compile-to-elf path)
      ;; Verify ELF
      (let ((output (with-output-to-string (s)
                      (uiop:run-program (list "readelf" "-S" path)
                                        :output s :ignore-error-status t))))
        (assert-true (search "xdp" output))
        (assert-true (search "maps" output))
        (assert-true (search "license" output)))
      (delete-file path))))

;;; Summary

(format t "~%=== Results ===~%")
(format t "~d tests: ~d passed, ~d failed~%"
        *test-count* *pass-count* *fail-count*)
(when (> *fail-count* 0)
  (uiop:quit 1))
