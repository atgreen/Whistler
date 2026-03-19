(in-package #:whistler/tests)

(in-suite alu-suite)

;;; ========== Arithmetic operation tests ==========
;;;
;;; Adapted from LLVM test/CodeGen/BPF/32-bit-subreg-alu.ll

(test add-imm
  "Addition with immediate should emit alu64 add imm"
  (let ((bytes (w-body "(let ((x u64 (ctx-load u64 0)))
                          (return (+ x 42)))")))
    (is (has-opcode-p bytes +alu64-add-imm+)
        "Expected alu64 add imm (0x07)")))

(test add-reg
  "Addition of two registers should emit alu64 add reg"
  (let ((bytes (w-body "(let ((x u64 (ctx-load u64 0))
                              (y u64 (ctx-load u64 8)))
                          (return (+ x y)))")))
    (is (has-opcode-p bytes +alu64-add-reg+)
        "Expected alu64 add reg (0x0f)")))

(test sub-imm
  "Subtraction with immediate should emit alu64 sub imm"
  (let ((bytes (w-body "(let ((x u64 (ctx-load u64 0)))
                          (return (- x 10)))")))
    (is (has-opcode-p bytes +alu64-sub-imm+)
        "Expected alu64 sub imm (0x17)")))

(test mul-imm
  "Multiplication with immediate should emit alu64 mul imm"
  (let ((bytes (w-body "(let ((x u64 (ctx-load u64 0)))
                          (return (* x 3)))")))
    (is (has-opcode-p bytes +alu64-mul-imm+)
        "Expected alu64 mul imm (0x27)")))

(test div-imm
  "Division with immediate should emit alu64 div imm or rsh"
  (let ((bytes (w-body "(let ((x u64 (ctx-load u64 0)))
                          (return (/ x 4)))")))
    ;; Division by power of 2 might optimize to right shift
    (is (or (has-opcode-p bytes +alu64-div-imm+)
            (has-opcode-p bytes +alu64-rsh-imm+))
        "Expected alu64 div imm (0x37) or rsh imm (0x77)")))

(test mod-imm
  "Modulo with immediate should emit alu64 mod imm"
  (let ((bytes (w-body "(let ((x u64 (ctx-load u64 0)))
                          (return (mod x 7)))")))
    (is (has-opcode-p bytes +alu64-mod-imm+)
        "Expected alu64 mod imm (0x97)")))

;;; ========== Bitwise operation tests ==========

(test logand-imm
  "Bitwise AND with immediate should emit alu and imm (32 or 64 bit)"
  (let ((bytes (w-body "(let ((x u64 (ctx-load u64 0)))
                          (return (logand x #xff)))")))
    ;; Compiler may narrow to alu32 (0x54) when mask fits 32 bits
    (is (or (has-opcode-p bytes +alu64-and-imm+)
            (has-opcode-p bytes #x54))
        "Expected alu and imm (0x57 or 0x54)")))

(test logior-imm
  "Bitwise OR with immediate should emit alu or imm (32 or 64 bit)"
  (let ((bytes (w-body "(let ((x u64 (ctx-load u64 0)))
                          (return (logior x #x80)))")))
    (is (or (has-opcode-p bytes +alu64-or-imm+)
            (has-opcode-p bytes #x44))
        "Expected alu or imm (0x47 or 0x44)")))

(test logxor-imm
  "Bitwise XOR with immediate should emit alu xor imm (32 or 64 bit)"
  (let ((bytes (w-body "(let ((x u64 (ctx-load u64 0)))
                          (return (logxor x #xaa)))")))
    (is (or (has-opcode-p bytes +alu64-xor-imm+)
            (has-opcode-p bytes #xa4))
        "Expected alu xor imm (0xa7 or 0xa4)")))

;;; ========== Shift operation tests ==========
;;;
;;; Adapted from LLVM test/CodeGen/BPF/shifts.ll

(test lshift-imm
  "Left shift with immediate should emit alu lsh imm"
  (let ((bytes (w-body "(let ((x u64 (ctx-load u64 0)))
                          (return (<< x 4)))")))
    (is (or (has-opcode-p bytes +alu64-lsh-imm+)
            (has-opcode-p bytes #x64))
        "Expected alu lsh imm (0x67 or 0x64)")))

(test rshift-imm
  "Right shift with immediate should emit alu rsh imm"
  (let ((bytes (w-body "(let ((x u64 (ctx-load u64 0)))
                          (return (>> x 4)))")))
    (is (or (has-opcode-p bytes +alu64-rsh-imm+)
            (has-opcode-p bytes #x74))
        "Expected alu rsh imm (0x77 or 0x74)")))

(test arshift-imm
  "Arithmetic right shift with immediate should emit alu arsh imm"
  (let ((bytes (w-body "(let ((x u64 (ctx-load u64 0)))
                          (return (>>> x 4)))")))
    (is (or (has-opcode-p bytes +alu64-arsh-imm+)
            (has-opcode-p bytes #xc4))
        "Expected alu arsh imm (0xc7 or 0xc4)")))

;;; ========== Constant folding tests ==========

(test constant-fold-add
  "(+ 10 32) should fold to 42 at compile time — 2 instructions"
  (is (= 2 (w-count "(return (+ 10 32))"))))

(test constant-fold-nested
  "(+ 10 (* 3 4)) should fold to 22 at compile time"
  (is (= 2 (w-count "(return (+ 10 (* 3 4)))"))))

(test constant-fold-arithmetic
  "(+ 100 (* 5 10)) should fold to 150"
  (let ((bytes (w-body "(return (+ 100 (* 5 10)))")))
    (is (= 150 (nth-insn-imm bytes 0))
        "Expected folded immediate 150")))
