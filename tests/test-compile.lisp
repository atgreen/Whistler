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
  (is (= 2 (w-count "(let ((x 42)) (declare (type u32 x)) (return x))"))))

(test cfg-constant-branch-folded
  "If with constant operands should fold to the taken branch"
  (is (= 2 (w-count "(let ((x 10))
                        (declare (type u32 x))
                        (if (> x 5) (return 2) (return 1)))"))))

(test cfg-constant-branch-false-path
  "If with false constant condition should take else branch"
  (let ((bytes (w-body "(let ((x 3))
                          (declare (type u32 x))
                          (if (> x 5) (return 99) (return 42)))")))
    (is (= 42 (nth-insn-imm bytes 0))
        "Should return 42 (else branch)")))

(test map-lookup-has-relocs
  "Program with map-lookup should produce map relocations"
  (let ((cu (compile-single
             (read-whistler-forms
              "(let ((key 0))
                 (declare (type u32 key))
                 (let ((val (map-lookup m key)))
                   (declare (type u64 val))
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

(test defstruct-generates-distinct-host-record
  "defstruct should keep host-side record accessors distinct from BPF accessors"
  (let ((whistler::*struct-defs* (make-hash-table :test 'equal)))
    (eval-whistler "(defstruct sample-event
                      (pid u32)
                      (port u16)
                      (comm (array u8 4)))")
    (is (not (null (macro-function 'whistler::sample-event-pid)))
        "BPF accessor should remain a macro")
    (is (fboundp 'whistler::decode-sample-event)
        "Decoder should be defined")
    (is (fboundp 'whistler::make-sample-event-record)
        "Host-side record constructor should be defined")
    (let* ((bytes #(42 0 0 0 57 48 65 66 67 68 0 0))
           (decode (symbol-function 'whistler::decode-sample-event))
           (encode (symbol-function 'whistler::encode-sample-event))
           (pid (symbol-function 'whistler::sample-event-record-pid))
           (port (symbol-function 'whistler::sample-event-record-port))
           (comm (symbol-function 'whistler::sample-event-record-comm))
           (rec (funcall decode bytes)))
      (is (typep rec 'whistler::sample-event-record)
          "Decoder should return the host-side record type")
      (is (= 42 (funcall pid rec)))
      (is (= 12345 (funcall port rec)))
      (is (equalp #(65 66 67 68) (funcall comm rec)))
      (is (equalp bytes (funcall encode rec))
          "encode/decode should round-trip"))))

;;; ========== Integration: full program compilation ==========

(test count-xdp-compiles
  "The count-xdp pattern should compile to a valid program"
  (let ((cu (compile-single
             (read-whistler-forms
              "(let ((key 0))
                 (declare (type u32 key))
                 (let ((val (map-lookup pkt-count key)))
                   (declare (type u64 val))
                   (if val
                       (atomic-add val 0 1)
                       (let ((init 1))
                         (declare (type u64 init))
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

(test doctor-prints-report
  "doctor should emit a recognizable report."
  (let ((out (with-output-to-string (s)
               (let ((*standard-output* s))
                 (whistler::doctor)))))
    (is (not (null (search "Whistler doctor" out))))
    (is (not (null (search "doctor checks completed" out))))))

(test typed-struct-map-helpers
  "Struct-valued map helpers should use generated encode/decode functions."
  (let ((whistler::*struct-defs* (make-hash-table :test 'equal)))
    (eval-whistler "(defstruct stat-entry
                      (packets u64)
                      (drops u64))")
    (let* ((map-info (whistler/loader::make-map-info
                      :name "stats" :key-size 4 :value-size 16))
           (record (whistler::make-stat-entry-record :packets 10 :drops 2))
           (encoded (whistler::encode-stat-entry record))
           (orig-update (symbol-function 'whistler/loader:map-update))
           (orig-lookup (symbol-function 'whistler/loader:map-lookup)))
      (unwind-protect
           (progn
             (setf (symbol-function 'whistler/loader:map-update)
                   (lambda (info key-bytes value-bytes &key (flags 0))
                     (declare (ignore flags))
                     (is (eq map-info info))
                     (is (equalp #(0 0 0 0) key-bytes))
                     (is (equalp encoded value-bytes))
                     :ok))
             (is (eq :ok (whistler/loader:map-update-struct-int
                          map-info 0 record 'whistler::stat-entry)))
             (setf (symbol-function 'whistler/loader:map-lookup)
                   (lambda (info key-bytes)
                     (is (eq map-info info))
                     (is (equalp #(0 0 0 0) key-bytes))
                     encoded))
             (let ((decoded (whistler/loader:map-lookup-struct-int
                             map-info 0 'whistler::stat-entry)))
               (is (= 10 (whistler::stat-entry-record-packets decoded)))
               (is (= 2 (whistler::stat-entry-record-drops decoded)))))
        (setf (symbol-function 'whistler/loader:map-update) orig-update
              (symbol-function 'whistler/loader:map-lookup) orig-lookup)))))

(test typed-struct-key-helpers
  "Struct-key helpers should use generated key codecs."
  (let ((whistler::*struct-defs* (make-hash-table :test 'equal)))
    (eval-whistler "(defstruct flow-key
                      (src u32)
                      (dst u32))")
    (let* ((map-info (whistler/loader::make-map-info
                      :name "flows" :key-size 8 :value-size 8))
           (key-rec (whistler::make-flow-key-record :src 1 :dst 2))
           (encoded-key (whistler::encode-flow-key key-rec))
           (orig-delete (symbol-function 'whistler/loader:map-delete))
           (orig-next (symbol-function 'whistler/loader:map-get-next-key)))
      (unwind-protect
           (progn
             (setf (symbol-function 'whistler/loader:map-delete)
                   (lambda (info key-bytes)
                     (is (eq map-info info))
                     (is (equalp encoded-key key-bytes))
                     :deleted))
             (is (eq :deleted
                     (whistler/loader:map-delete-struct
                      map-info key-rec 'whistler::flow-key)))
             (setf (symbol-function 'whistler/loader:map-get-next-key)
                   (lambda (info key-bytes)
                     (is (eq map-info info))
                     (is (equalp encoded-key key-bytes))
                     encoded-key))
             (let ((decoded (whistler/loader:map-get-next-key-struct
                             map-info 'whistler::flow-key key-rec)))
               (is (= 1 (whistler::flow-key-record-src decoded)))
               (is (= 2 (whistler::flow-key-record-dst decoded)))))
        (setf (symbol-function 'whistler/loader:map-delete) orig-delete
              (symbol-function 'whistler/loader:map-get-next-key) orig-next)))))
