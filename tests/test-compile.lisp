(in-package #:whistler/tests)

(in-suite compile-suite)

;;; ========== End-to-end compilation tests ==========

(test return-constant
  "Returning a constant should produce 2 instructions (mov + exit)"
  (is (= 2 (w-count "(return 2)"))))

(test return-constant-value
  "Return 42 should emit mov r0, 42"
  (let ((bytes (w-body "(return 42)")))
    (is (= +alu64-mov-imm+ (nth-insn-opcode bytes 0))
        "First instruction should be mov64 imm")
    (is (= 42 (nth-insn-imm bytes 0))
        "Immediate value should be 42")))

(test let-constant-folded
  "Let binding with constant should fold away"
  (is (= 2 (w-count "(let ((x u32 42)) (return x))"))))

(test cfg-constant-branch-folded
  "If with constant operands should fold to the taken branch"
  (is (= 2 (w-count "(let ((x u32 10))
                        (if (> x 5) (return 2) (return 1)))"))))

(test cfg-constant-branch-false-path
  "If with false constant condition should take else branch"
  (let ((bytes (w-body "(let ((x u32 3))
                          (if (> x 5) (return 99) (return 42)))")))
    (is (= 42 (nth-insn-imm bytes 0))
        "Should return 42 (else branch)")))

(test map-lookup-has-relocs
  "Program with map-lookup should produce map relocations"
  (let ((cu (compile-single
             (read-whistler-forms
              "(let ((key u32 0))
                 (let ((val u64 (map-lookup m key)))
                   (if val (return 1) (return 0))))")
             :maps '((m :type :array :key-size 4
                        :value-size 8 :max-entries 1)))))
    (is (= 1 (length (whistler/compiler:cu-maps cu)))
        "Should have 1 map")
    (is (> (length (whistler/compiler:cu-map-relocs cu)) 0)
        "Should have map relocations")))

;;; ========== ELF output tests ==========

(test elf-has-magic
  "Generated ELF should have correct magic bytes"
  (let* ((cu (compile-single (read-whistler-forms "(return 0)")))
         (path "/tmp/whistler-5am-elf-test.bpf.o"))
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
           (with-open-file (in path :element-type '(unsigned-byte 8))
             (let ((magic (make-array 4 :element-type '(unsigned-byte 8))))
               (read-sequence magic in)
               (is (= #x7f (aref magic 0)))
               (is (= (char-code #\E) (aref magic 1)))
               (is (= (char-code #\L) (aref magic 2)))
               (is (= (char-code #\F) (aref magic 3))))))
      (when (probe-file path)
        (delete-file path)))))

;;; ========== Multi-program and license tests ==========

(defun eval-whistler (string)
  "Read and eval each form in STRING in the whistler package."
  (dolist (form (read-whistler-forms string))
    (eval form)))

(test conflicting-licenses-rejected
  "compile-to-elf should reject programs with different licenses"
  (let ((whistler::*maps* nil)
        (whistler::*programs* nil))
    (eval-whistler "(defmap test-m :type :array :key-size 4 :value-size 8 :max-entries 1)")
    (eval-whistler "(defprog p1 (:type :xdp :section \"xdp/p1\" :license \"GPL\")
                      (return 1))")
    (eval-whistler "(defprog p2 (:type :xdp :section \"xdp/p2\" :license \"MIT\")
                      (return 2))")
    (signals error
      (whistler::compile-to-elf "/tmp/whistler-5am-license-test.bpf.o"))))

(test matching-licenses-accepted
  "compile-to-elf should accept programs with the same license"
  (let ((whistler::*maps* nil)
        (whistler::*programs* nil))
    (eval-whistler "(defmap test-m :type :array :key-size 4 :value-size 8 :max-entries 1)")
    (eval-whistler "(defprog p1 (:type :xdp :section \"xdp/p1\" :license \"GPL\")
                      (return 1))")
    (eval-whistler "(defprog p2 (:type :xdp :section \"xdp/p2\" :license \"GPL\")
                      (return 2))")
    (let ((path "/tmp/whistler-5am-multi-test.bpf.o"))
      (unwind-protect
           (progn
             (whistler::compile-to-elf path)
             (is (not (null (probe-file path))) "ELF file should be created"))
        (when (probe-file path)
          (delete-file path))))))

;;; ========== Integration: full program compilation ==========

(test count-xdp-compiles
  "The count-xdp pattern should compile to a valid program"
  (let ((cu (compile-single
             (read-whistler-forms
              "(let ((key u32 0))
                 (let ((val u64 (map-lookup pkt-count key)))
                   (if val
                       (atomic-add val 0 1)
                       (let ((init u64 1))
                         (map-update pkt-count key init 0)))))
               (return 2)")
             :maps '((pkt-count :type :array :key-size 4
                                :value-size 8 :max-entries 1)))))
    (is (> (length (whistler/compiler:cu-insns cu)) 5)
        "count-xdp should produce several instructions")
    (is (= 1 (length (whistler/compiler:cu-maps cu)))
        "Should have 1 map")))

(test synflood-example-compiles
  "The synflood-xdp example should compile without error"
  (let ((whistler::*maps* nil)
        (whistler::*programs* nil)
        (whistler::*struct-defs* (make-hash-table :test 'equal)))
    (finishes
      (load (merge-pathnames "examples/synflood-xdp.lisp"
                             (asdf:system-source-directory :whistler))))))
