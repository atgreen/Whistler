(in-package #:whistler/tests)

(in-suite memory-suite)

;;; ========== Load width tests ==========
;;;
;;; Adapted from LLVM test/CodeGen/BPF/load.ll
;;; Each test compiles a load at a specific width and verifies the
;;; emitted BPF opcode matches the expected ldx variant.

(test load-u8-emits-ldxb
  "Loading u8 should emit ldxb (opcode 0x71)"
  (let ((bytes (w-body "(let ((x u8 (ctx-load u8 0)))
                          (return x))")))
    (is (has-opcode-p bytes +ldxb+)
        "Expected ldxb (0x71) for u8 load")))

(test load-u16-emits-ldxh
  "Loading u16 should emit ldxh (opcode 0x69)"
  (let ((bytes (w-body "(let ((x u16 (ctx-load u16 0)))
                          (return x))")))
    (is (has-opcode-p bytes +ldxh+)
        "Expected ldxh (0x69) for u16 load")))

(test load-u32-emits-ldxw
  "Loading u32 should emit ldxw (opcode 0x61)"
  (let ((bytes (w-body "(let ((x u32 (ctx-load u32 0)))
                          (return x))")))
    (is (has-opcode-p bytes +ldxw+)
        "Expected ldxw (0x61) for u32 load")))

(test load-u64-emits-ldxdw
  "Loading u64 should emit ldxdw (opcode 0x79)"
  (let ((bytes (w-body "(let ((x u64 (ctx-load u64 0)))
                          (return x))")))
    (is (has-opcode-p bytes +ldxdw+)
        "Expected ldxdw (0x79) for u64 load")))

(test load-with-offset
  "Loading with non-zero offset encodes the offset correctly"
  (let ((bytes (w-body "(let ((x u32 (ctx-load u32 16)))
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
  (let ((bytes (w-body "(let ((key u32 0))
                          (let ((p u64 (map-lookup my-map key)))
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
  (let ((bytes (w-body "(let ((key u32 0))
                          (let ((p u64 (map-lookup my-map key)))
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
