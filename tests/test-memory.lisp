(in-package #:whistler/tests)

(in-suite memory-suite)

;;; ========== Load width tests ==========
;;;
;;; Adapted from LLVM test/CodeGen/BPF/load.ll
;;; Each test compiles a load at a specific width and verifies the
;;; emitted BPF opcode matches the expected ldx variant.

(test load-u8-emits-ldxb
  "Loading u8 should emit ldxb (opcode 0x71)"
  (let ((bytes (w-body "(let ((key 0))
                          (declare (type u32 key))
                          (let ((p (map-lookup m key)))
                            (declare (type u64 p))
                            (when p
                              (return (load u8 p 0))))
                          (return 0))"
                       :maps '((m :type :array :key-size 4
                                  :value-size 8 :max-entries 1)))))
    (is (has-opcode-p bytes +ldxb+)
        "Expected ldxb (0x71) for u8 load")))

(test load-u16-emits-ldxh
  "Loading u16 should emit ldxh (opcode 0x69)"
  (let ((bytes (w-body "(let ((key 0))
                          (declare (type u32 key))
                          (let ((p (map-lookup m key)))
                            (declare (type u64 p))
                            (when p
                              (return (load u16 p 0))))
                          (return 0))"
                       :maps '((m :type :array :key-size 4
                                  :value-size 8 :max-entries 1)))))
    (is (has-opcode-p bytes +ldxh+)
        "Expected ldxh (0x69) for u16 load")))

(test load-u32-emits-ldxw
  "Loading u32 should emit ldxw (opcode 0x61)"
  (let ((bytes (w-body "(let ((x (ctx-load u32 0)))
                          (declare (type u32 x))
                          (return x))")))
    (is (has-opcode-p bytes +ldxw+)
        "Expected ldxw (0x61) for u32 load")))

(test load-u64-emits-ldxdw
  "Loading u64 should emit ldxdw (opcode 0x79)"
  (let ((bytes (w-body "(let ((key 0))
                          (declare (type u32 key))
                          (let ((p (map-lookup m key)))
                            (declare (type u64 p))
                            (when p
                              (return (load u64 p 0))))
                          (return 0))"
                       :maps '((m :type :array :key-size 4
                                  :value-size 8 :max-entries 1)))))
    (is (has-opcode-p bytes +ldxdw+)
        "Expected ldxdw (0x79) for u64 load")))

(test load-with-offset
  "Loading with non-zero offset encodes the offset correctly"
  (let ((bytes (w-body "(let ((x (ctx-load u32 16)))
                          (declare (type u32 x))
                          (return x))")))
    (let ((idx (find-opcode bytes +ldxw+)))
      (is (not (null idx)) "Expected ldxw instruction")
      (when idx
        (is (= 16 (nth-insn-off bytes idx))
            "Expected offset 16 in ldxw instruction")))))

;;; ========== Store width tests ==========
;;;
;;; Adapted from LLVM test/CodeGen/BPF/store_imm.ll
;;; Store tests use map-lookup-ptr to get a writable pointer.

(test store-u32-emits-stw
  "Storing u32 should emit stxw (0x63) or stw (0x62)"
  (let ((bytes (w-body "(let ((key 0))
                          (declare (type u32 key))
                          (let ((p (map-lookup my-map key)))
                            (declare (type u64 p))
                            (when p
                              (store u32 p 0 12345)))
                          (return 0))"
                       :maps '((my-map :type :array :key-size 4
                                       :value-size 8 :max-entries 1)))))
    (is (or (has-opcode-p bytes +stxw+)
            (has-opcode-p bytes +stw+))
        "Expected stxw (0x63) or stw (0x62) for u32 store")))

(test store-u64-emits-stdw
  "Storing u64 should emit stxdw (0x7b) or stdw (0x7a)"
  (let ((bytes (w-body "(let ((key 0))
                          (declare (type u32 key))
                          (let ((p (map-lookup my-map key)))
                            (declare (type u64 p))
                            (when p
                              (store u64 p 0 99)))
                          (return 0))"
                       :maps '((my-map :type :array :key-size 4
                                       :value-size 8 :max-entries 1)))))
    (is (or (has-opcode-p bytes +stxdw+)
            (has-opcode-p bytes +stdw+))
        "Expected stxdw (0x7b) or stdw (0x7a) for u64 store")))

;;; ========== Map value dereference width tests ==========
;;;
;;; These test the getmap macro fix — map value loads must match
;;; the map's declared :value-size, not hardcode u64.

(test getmap-u32-value-emits-ldxw
  "getmap on a :value-size 4 map should load with ldxw, not ldxdw"
  (let ((bytes (w-body "(return (getmap cnt 0))"
                       :maps '((cnt :type :array :key-size 4
                                    :value-size 4 :max-entries 1)))))
    (is (not (has-opcode-p bytes +ldxdw+))
        "Should NOT contain ldxdw for a 32-bit map value")
    (is (has-opcode-p bytes +ldxw+)
        "Expected ldxw (0x61) for 32-bit map value dereference")))

(test getmap-u64-value-emits-ldxdw
  "getmap on a :value-size 8 map should load with ldxdw"
  (let ((bytes (w-body "(return (getmap cnt 0))"
                       :maps '((cnt :type :array :key-size 4
                                    :value-size 8 :max-entries 1)))))
    (is (has-opcode-p bytes +ldxdw+)
        "Expected ldxdw (0x79) for 64-bit map value dereference")))

(test getmap-u16-value-emits-ldxh
  "getmap on a :value-size 2 map should load with ldxh"
  (let ((bytes (w-body "(return (getmap cnt 0))"
                       :maps '((cnt :type :array :key-size 4
                                    :value-size 2 :max-entries 1)))))
    (is (has-opcode-p bytes +ldxh+)
        "Expected ldxh (0x69) for 16-bit map value dereference")))

(test getmap-u8-value-emits-ldxb
  "getmap on a :value-size 1 map should load with ldxb"
  (let ((bytes (w-body "(return (getmap cnt 0))"
                       :maps '((cnt :type :array :key-size 4
                                    :value-size 1 :max-entries 1)))))
    (is (has-opcode-p bytes +ldxb+)
        "Expected ldxb (0x71) for 8-bit map value dereference")))

;;; ========== kernel-load tests (issue #18) ==========
;;;
;;; kernel-load emits probe-read-kernel (helper #113) into a stack
;;; buffer, then loads the result.  This is the safe path for kernel
;;; pointers that the BPF verifier won't trust for direct dereference.

(test kernel-load-emits-probe-read-kernel
  "kernel-load should emit probe_read_kernel (helper 113)"
  (let ((bytes (w-body "(let ((task (get-current-task)))
                          (return (kernel-load u32 task 2772)))")))
    (let ((call-count 0))
      (let ((n (/ (length bytes) 8)))
        (loop for i below n
              when (and (= +jmp-call+ (nth-insn-opcode bytes i))
                        (= 113 (nth-insn-imm bytes i)))
                do (cl:incf call-count)))
      (is (> call-count 0)
          "Expected call to helper 113 (probe_read_kernel)"))))

(test kernel-load-u64-emits-dw-load
  "kernel-load u64 should load the result as a 64-bit value"
  (let ((bytes (w-body "(let ((task (get-current-task)))
                          (return (kernel-load u64 task 0)))")))
    (is (has-opcode-p bytes +ldxdw+)
        "Expected ldxdw for kernel-load u64")))
