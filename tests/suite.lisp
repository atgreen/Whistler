(in-package #:whistler/tests)

;;; ========== Top-level suite ==========

(def-suite whistler-suite
  :description "Whistler compiler test suite")

(def-suite memory-suite
  :description "Load/store width correctness"
  :in whistler-suite)

(def-suite atomics-suite
  :description "Atomic operation width correctness"
  :in whistler-suite)

(def-suite alu-suite
  :description "ALU and arithmetic operations"
  :in whistler-suite)

(def-suite branch-suite
  :description "Comparison and control flow"
  :in whistler-suite)

(def-suite compile-suite
  :description "End-to-end compilation and error handling"
  :in whistler-suite)

(def-suite byteswap-suite
  :description "Byte swap (endian conversion) operations"
  :in whistler-suite)

(def-suite controlflow-suite
  :description "Advanced control flow: loops, casts, logical ops"
  :in whistler-suite)

(def-suite protocol-suite
  :description "Protocol header parsing and packet access"
  :in whistler-suite)

(def-suite optimization-suite
  :description "SSA optimization and peephole pass correctness"
  :in whistler-suite)

(def-suite maps-suite
  :description "Map operations: lookup, update, delete"
  :in whistler-suite)

(def-suite programs-suite
  :description "Multi-program, tail calls, ring buffers, examples"
  :in whistler-suite)

;;; ========== Test helpers ==========

(defun read-whistler-forms (string)
  "Read Lisp forms from STRING in the whistler package, so symbols like
   getmap, when-let, ctx-load etc. resolve correctly."
  (let ((*package* (find-package '#:whistler)))
    (with-input-from-string (s string)
      (loop for form = (read s nil s)
            until (eq form s)
            collect form))))

(defun compile-single (body &key maps)
  "Compile a minimal XDP program from BODY forms, return the compilation unit.
   Binds *maps* so that surface macros (getmap, incf-map, etc.) can look up
   map specs during macro expansion."
  (let ((whistler::*maps* (or maps whistler::*maps*)))
    (whistler::compile-program "xdp" "GPL" maps body)))

(defun compile-insn-bytes (body &key maps)
  "Compile BODY and return the raw instruction byte vector."
  (let ((cu (compile-single body :maps maps)))
    (whistler/bpf:insn-bytes (whistler/compiler:cu-insns cu))))

(defun insn-count (body &key maps)
  "Compile BODY and return the instruction count."
  (length (whistler/compiler:cu-insns (compile-single body :maps maps))))

(defmacro w-body (string &key maps)
  "Parse STRING as whistler forms and compile them, returning insn bytes.
   Convenience macro for test assertions."
  `(compile-insn-bytes (read-whistler-forms ,string) :maps ,maps))

(defmacro w-count (string &key maps)
  "Parse STRING as whistler forms and return instruction count."
  `(insn-count (read-whistler-forms ,string) :maps ,maps))

(defun nth-insn-opcode (bytes n)
  "Extract the opcode byte from the Nth BPF instruction (8 bytes each)."
  (aref bytes (* n 8)))

(defun nth-insn-regs (bytes n)
  "Extract the dst/src register nibble byte from the Nth instruction."
  (aref bytes (+ (* n 8) 1)))

(defun nth-insn-off (bytes n)
  "Extract the 16-bit offset from the Nth instruction (little-endian, signed)."
  (let ((lo (aref bytes (+ (* n 8) 2)))
        (hi (aref bytes (+ (* n 8) 3))))
    (let ((val (logior lo (ash hi 8))))
      (if (logbitp 15 val)
          (- val #x10000)
          val))))

(defun nth-insn-imm (bytes n)
  "Extract the 32-bit immediate from the Nth instruction (little-endian, signed)."
  (let ((b0 (aref bytes (+ (* n 8) 4)))
        (b1 (aref bytes (+ (* n 8) 5)))
        (b2 (aref bytes (+ (* n 8) 6)))
        (b3 (aref bytes (+ (* n 8) 7))))
    (let ((val (logior b0 (ash b1 8) (ash b2 16) (ash b3 24))))
      (if (logbitp 31 val)
          (- val #x100000000)
          val))))

(defun find-opcode (bytes opcode)
  "Find the instruction index of the first instruction with OPCODE, or nil."
  (let ((n (/ (length bytes) 8)))
    (loop for i below n
          when (= (nth-insn-opcode bytes i) opcode)
            return i)))

(defun count-opcode (bytes opcode)
  "Count how many instructions have OPCODE."
  (let ((n (/ (length bytes) 8)))
    (loop for i below n
          count (= (nth-insn-opcode bytes i) opcode))))

(defun has-opcode-p (bytes opcode)
  "Does the instruction stream contain OPCODE?"
  (not (null (find-opcode bytes opcode))))

;;; ========== BPF opcode constants for test assertions ==========
;;; These encode the full opcode byte (class | size | mode/source).

(defconstant +ldxb+  #x71)  ; ldx mem u8
(defconstant +ldxh+  #x69)  ; ldx mem u16
(defconstant +ldxw+  #x61)  ; ldx mem u32
(defconstant +ldxdw+ #x79)  ; ldx mem u64

(defconstant +stxb+  #x73)  ; stx mem u8
(defconstant +stxh+  #x6b)  ; stx mem u16
(defconstant +stxw+  #x63)  ; stx mem u32
(defconstant +stxdw+ #x7b)  ; stx mem u64

(defconstant +stb+   #x72)  ; st imm u8
(defconstant +sth+   #x6a)  ; st imm u16
(defconstant +stw+   #x62)  ; st imm u32
(defconstant +stdw+  #x7a)  ; st imm u64

(defconstant +atomic-w+  #xc3)  ; stx atomic u32
(defconstant +atomic-dw+ #xdb)  ; stx atomic u64

(defconstant +alu64-add-reg+ #x0f)  ; alu64 x add
(defconstant +alu64-add-imm+ #x07)  ; alu64 k add
(defconstant +alu64-sub-reg+ #x1f)  ; alu64 x sub
(defconstant +alu64-sub-imm+ #x17)  ; alu64 k sub
(defconstant +alu64-mul-reg+ #x2f)  ; alu64 x mul
(defconstant +alu64-mul-imm+ #x27)  ; alu64 k mul
(defconstant +alu64-div-reg+ #x3f)  ; alu64 x div
(defconstant +alu64-div-imm+ #x37)  ; alu64 k div
(defconstant +alu64-or-reg+  #x4f)  ; alu64 x or
(defconstant +alu64-or-imm+  #x47)  ; alu64 k or
(defconstant +alu64-and-reg+ #x5f)  ; alu64 x and
(defconstant +alu64-and-imm+ #x57)  ; alu64 k and
(defconstant +alu64-lsh-reg+ #x6f)  ; alu64 x lsh
(defconstant +alu64-lsh-imm+ #x67)  ; alu64 k lsh
(defconstant +alu64-rsh-reg+ #x7f)  ; alu64 x rsh
(defconstant +alu64-rsh-imm+ #x77)  ; alu64 k rsh
(defconstant +alu64-xor-reg+ #xaf)  ; alu64 x xor
(defconstant +alu64-xor-imm+ #xa7)  ; alu64 k xor
(defconstant +alu64-mov-reg+ #xbf)  ; alu64 x mov
(defconstant +alu64-mov-imm+ #xb7)  ; alu64 k mov
(defconstant +alu64-arsh-reg+ #xcf) ; alu64 x arsh
(defconstant +alu64-arsh-imm+ #xc7) ; alu64 k arsh
(defconstant +alu64-mod-reg+ #x9f)  ; alu64 x mod
(defconstant +alu64-mod-imm+ #x97)  ; alu64 k mod

(defconstant +alu32-add-reg+ #x0c)  ; alu32 x add
(defconstant +alu32-add-imm+ #x04)  ; alu32 k add
(defconstant +alu32-mov-reg+ #xbc)  ; alu32 x mov
(defconstant +alu32-mov-imm+ #xb4)  ; alu32 k mov

(defconstant +jmp-jeq-reg+  #x1d)  ; jmp x jeq
(defconstant +jmp-jeq-imm+  #x15)  ; jmp k jeq
(defconstant +jmp-jne-reg+  #x5d)  ; jmp x jne
(defconstant +jmp-jne-imm+  #x55)  ; jmp k jne
(defconstant +jmp-jgt-reg+  #x2d)  ; jmp x jgt
(defconstant +jmp-jgt-imm+  #x25)  ; jmp k jgt
(defconstant +jmp-jge-reg+  #x3d)  ; jmp x jge
(defconstant +jmp-jge-imm+  #x35)  ; jmp k jge
(defconstant +jmp-jlt-reg+  #xad)  ; jmp x jlt
(defconstant +jmp-jlt-imm+  #xa5)  ; jmp k jlt
(defconstant +jmp-jle-reg+  #xbd)  ; jmp x jle
(defconstant +jmp-jle-imm+  #xb5)  ; jmp k jle
(defconstant +jmp-jsgt-reg+ #x6d)  ; jmp x jsgt
(defconstant +jmp-jsgt-imm+ #x65)  ; jmp k jsgt
(defconstant +jmp-jsge-reg+ #x7d)  ; jmp x jsge
(defconstant +jmp-jsge-imm+ #x75)  ; jmp k jsge
(defconstant +jmp-jslt-reg+ #xcd)  ; jmp x jslt
(defconstant +jmp-jslt-imm+ #xc5)  ; jmp k jslt
(defconstant +jmp-jsle-reg+ #xdd)  ; jmp x jsle
(defconstant +jmp-jsle-imm+ #xd5)  ; jmp k jsle
(defconstant +jmp-ja+       #x05)  ; jmp ja (unconditional)
(defconstant +jmp-call+     #x85)  ; jmp call
(defconstant +jmp-exit+     #x95)  ; jmp exit

(defconstant +ld-imm64+ #x18)  ; ld imm dw (2-insn wide)

;;; ========== Entry point ==========

(defun run-tests ()
  "Run all Whistler tests. Returns T on success."
  (run! 'whistler-suite))
