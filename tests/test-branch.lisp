(in-package #:whistler/tests)

(in-suite branch-suite)

;;; ========== Comparison / conditional branch tests ==========
;;;
;;; Adapted from LLVM test/CodeGen/BPF/cmp.ll
;;; Each test verifies that a comparison operator emits the correct
;;; BPF jump instruction (or its branch-inverted equivalent).

(test branch-eq-imm
  "(= x 0) should emit jeq or jne (branch may be inverted)"
  (let ((bytes (w-body "(let ((x (get-prandom-u32)))
                          (declare (type u32 x))
                          (if (= x 0) (return 1) (return 0)))")))
    (is (or (has-opcode-p bytes +jmp-jeq-imm+)
            (has-opcode-p bytes +jmp-jne-imm+))
        "Expected jeq imm (0x15) or jne imm (0x55)")))

(test branch-neq-imm
  "(/= x 0) should emit jne or jeq (branch may be inverted)"
  (let ((bytes (w-body "(let ((x (get-prandom-u32)))
                          (declare (type u32 x))
                          (if (/= x 0) (return 1) (return 0)))")))
    (is (or (has-opcode-p bytes +jmp-jne-imm+)
            (has-opcode-p bytes +jmp-jeq-imm+))
        "Expected jne imm (0x55) or inverted jeq imm (0x15)")))

(test branch-gt-unsigned
  "(> x 10) should emit unsigned jgt or jle"
  (let ((bytes (w-body "(let ((x (get-prandom-u32)))
                          (declare (type u32 x))
                          (if (> x 10) (return 1) (return 0)))")))
    (is (or (has-opcode-p bytes +jmp-jgt-imm+)
            (has-opcode-p bytes +jmp-jle-imm+))
        "Expected unsigned jgt (0x25) or jle (0xb5)")))

(test branch-ge-unsigned
  "(>= x 10) should emit unsigned jge or jlt"
  (let ((bytes (w-body "(let ((x (get-prandom-u32)))
                          (declare (type u32 x))
                          (if (>= x 10) (return 1) (return 0)))")))
    (is (or (has-opcode-p bytes +jmp-jge-imm+)
            (has-opcode-p bytes +jmp-jlt-imm+))
        "Expected unsigned jge (0x35) or jlt (0xa5)")))

(test branch-lt-unsigned
  "(< x 10) should emit unsigned jlt or jge"
  (let ((bytes (w-body "(let ((x (get-prandom-u32)))
                          (declare (type u32 x))
                          (if (< x 10) (return 1) (return 0)))")))
    (is (or (has-opcode-p bytes +jmp-jlt-imm+)
            (has-opcode-p bytes +jmp-jge-imm+))
        "Expected unsigned jlt (0xa5) or jge (0x35)")))

(test branch-le-unsigned
  "(<= x 10) should emit unsigned jle or jgt"
  (let ((bytes (w-body "(let ((x (get-prandom-u32)))
                          (declare (type u32 x))
                          (if (<= x 10) (return 1) (return 0)))")))
    (is (or (has-opcode-p bytes +jmp-jle-imm+)
            (has-opcode-p bytes +jmp-jgt-imm+))
        "Expected unsigned jle (0xb5) or jgt (0x25)")))

;;; ========== Signed comparison tests ==========

(test branch-sgt
  "(s> x 10) should emit signed jsgt or jsle"
  (let ((bytes (w-body "(let ((x (get-prandom-u32)))
                          (declare (type u32 x))
                          (if (s> x 10) (return 1) (return 0)))")))
    (is (or (has-opcode-p bytes +jmp-jsgt-imm+)
            (has-opcode-p bytes +jmp-jsle-imm+))
        "Expected signed jsgt (0x65) or jsle (0xd5)")))

(test branch-sge
  "(s>= x 10) should emit signed jsge or jslt"
  (let ((bytes (w-body "(let ((x (get-prandom-u32)))
                          (declare (type u32 x))
                          (if (s>= x 10) (return 1) (return 0)))")))
    (is (or (has-opcode-p bytes +jmp-jsge-imm+)
            (has-opcode-p bytes +jmp-jslt-imm+))
        "Expected signed jsge (0x75) or jslt (0xc5)")))

(test branch-slt
  "(s< x 10) should emit signed jslt or jsge"
  (let ((bytes (w-body "(let ((x (get-prandom-u32)))
                          (declare (type u32 x))
                          (if (s< x 10) (return 1) (return 0)))")))
    (is (or (has-opcode-p bytes +jmp-jslt-imm+)
            (has-opcode-p bytes +jmp-jsge-imm+))
        "Expected signed jslt (0xc5) or jsge (0x75)")))

(test branch-sle
  "(s<= x 10) should emit signed jsle or jsgt"
  (let ((bytes (w-body "(let ((x (get-prandom-u32)))
                          (declare (type u32 x))
                          (if (s<= x 10) (return 1) (return 0)))")))
    (is (or (has-opcode-p bytes +jmp-jsle-imm+)
            (has-opcode-p bytes +jmp-jsgt-imm+))
        "Expected signed jsle (0xd5) or jsgt (0x65)")))

;;; ========== Control flow structure tests ==========

(test when-compiles
  "(when cond body) should compile without error"
  (let ((n (w-count "(let ((x (get-prandom-u32)))
                       (declare (type u32 x))
                       (when (> x 0)
                         (return 1)))
                     (return 0)")))
    (is (> n 3) "when should produce at least a load + cmp + branch + returns")))

(test unless-compiles
  "(unless cond body) should compile without error"
  (let ((n (w-count "(let ((x (get-prandom-u32)))
                       (declare (type u32 x))
                       (unless (= x 0)
                         (return 1)))
                     (return 0)")))
    (is (> n 3) "unless should produce multiple instructions")))

(test nested-if
  "Nested if/else should compile without error"
  (let ((n (w-count "(let ((x (get-prandom-u32)))
                       (declare (type u32 x))
                       (if (> x 100)
                           (if (> x 200)
                               (return 3)
                               (return 2))
                           (return 1)))")))
    (is (> n 5) "Nested if should produce multiple branches")))

;;; ========== Call instruction tests ==========
;;;
;;; Adapted from LLVM test/CodeGen/BPF/cc_args.ll

(test helper-call-emits-call-insn
  "map-lookup should emit a BPF call instruction"
  (let ((bytes (w-body "(let ((key 0))
                          (declare (type u32 key))
                          (let ((val (map-lookup m key)))
                            (declare (type u64 val))
                            (if val (return 1) (return 0))))"
                       :maps '((m :type :array :key-size 4
                                   :value-size 8 :max-entries 1)))))
    (is (has-opcode-p bytes +jmp-call+)
        "Expected call instruction (0x85)")
    ;; The call should be to helper 1 (map_lookup_elem)
    (let ((idx (find-opcode bytes +jmp-call+)))
      (when idx
        (is (= 1 (nth-insn-imm bytes idx))
            "Expected call to helper 1 (map_lookup_elem)")))))

(test exit-insn-present
  "Every program should end with an exit instruction"
  (let ((bytes (w-body "(return 42)")))
    (let ((n (/ (length bytes) 8)))
      (is (= +jmp-exit+ (nth-insn-opcode bytes (1- n)))
          "Last instruction should be exit (0x95)"))))
