(in-package #:whistler/tests)

(in-suite atomics-suite)

;;; ========== Atomic add width tests ==========
;;;
;;; Adapted from LLVM test/CodeGen/BPF/atomics.ll and xadd.ll
;;; BPF atomic add uses opcode 0xc3 (32-bit) or 0xdb (64-bit).

(test atomic-add-u64-emits-dw
  "atomic-add on a u64 value should emit 64-bit atomic (opcode 0xdb)"
  (let ((bytes (w-body "(let ((key u32 0))
                          (when-let ((p u64 (map-lookup cnt key)))
                            (atomic-add p 0 1))
                          (return 0))"
                       :maps '((cnt :type :array :key-size 4
                                    :value-size 8 :max-entries 1)))))
    (is (has-opcode-p bytes +atomic-dw+)
        "Expected 64-bit atomic (0xdb) for u64 atomic-add")))

(test atomic-add-u32-emits-w
  "atomic-add with u32 type should emit 32-bit atomic (opcode 0xc3)"
  (let ((bytes (w-body "(let ((key u32 0))
                          (when-let ((p u64 (map-lookup cnt key)))
                            (atomic-add p 0 1 u32))
                          (return 0))"
                       :maps '((cnt :type :array :key-size 4
                                    :value-size 4 :max-entries 1)))))
    (is (has-opcode-p bytes +atomic-w+)
        "Expected 32-bit atomic (0xc3) for u32 atomic-add")))

(test atomic-add-default-is-u64
  "atomic-add without explicit type should default to 64-bit"
  (let ((bytes (w-body "(let ((key u32 0))
                          (when-let ((p u64 (map-lookup cnt key)))
                            (atomic-add p 0 1))
                          (return 0))"
                       :maps '((cnt :type :array :key-size 4
                                    :value-size 8 :max-entries 1)))))
    (is (has-opcode-p bytes +atomic-dw+)
        "Default atomic-add should be 64-bit")
    (is (not (has-opcode-p bytes +atomic-w+))
        "Default atomic-add should NOT contain 32-bit atomic")))

;;; ========== incf-map width tests ==========
;;;
;;; incf-map is the surface macro that expands to atomic-add.
;;; It should derive the atomic width from the map's :value-size.

(test incf-map-u64-value
  "incf-map on :value-size 8 should use 64-bit atomic"
  (let ((bytes (w-body "(incf-map cnt 0)
                        (return 0)"
                       :maps '((cnt :type :array :key-size 4
                                    :value-size 8 :max-entries 1)))))
    (is (has-opcode-p bytes +atomic-dw+)
        "Expected 64-bit atomic for :value-size 8 incf-map")))

(test incf-map-u32-value
  "incf-map on :value-size 4 should use 32-bit atomic"
  (let ((bytes (w-body "(incf-map cnt 0)
                        (return 0)"
                       :maps '((cnt :type :array :key-size 4
                                    :value-size 4 :max-entries 1)))))
    (is (has-opcode-p bytes +atomic-w+)
        "Expected 32-bit atomic for :value-size 4 incf-map")
    (is (not (has-opcode-p bytes +atomic-dw+))
        "Should NOT contain 64-bit atomic for 32-bit map values")))

(test incf-map-hash-u32-value
  "incf-map on a hash map with :value-size 4 should use 32-bit atomic"
  (let ((bytes (w-body "(incf-map cnt 0)
                        (return 0)"
                       :maps '((cnt :type :hash :key-size 4
                                    :value-size 4 :max-entries 256)))))
    ;; Hash map path: lookup, if found -> atomic-add, else -> map-update
    (is (has-opcode-p bytes +atomic-w+)
        "Expected 32-bit atomic in hash map incf-map path")))
