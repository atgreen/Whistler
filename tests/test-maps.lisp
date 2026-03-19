(in-package #:whistler/tests)

(in-suite maps-suite)

;;; ========== Map lookup ==========

(test map-lookup-array
  "Array map lookup should emit map_lookup_elem helper call"
  (let ((bytes (w-body "(let ((key 0))
                          (declare (type u32 key))
                          (let ((val (map-lookup m key)))
                            (declare (type u64 val))
                            (if val (return 1) (return 0))))"
                       :maps '((m :type :array :key-size 4
                                   :value-size 8 :max-entries 1)))))
    (is (has-opcode-p bytes +jmp-call+))
    (let ((idx (find-opcode bytes +jmp-call+)))
      (when idx
        (is (= 1 (nth-insn-imm bytes idx))
            "Should call helper 1 (map_lookup_elem)")))))

(test map-lookup-hash
  "Hash map lookup should also emit map_lookup_elem"
  (let ((bytes (w-body "(let ((key 0))
                          (declare (type u32 key))
                          (let ((val (map-lookup m key)))
                            (declare (type u64 val))
                            (if val (return 1) (return 0))))"
                       :maps '((m :type :hash :key-size 4
                                   :value-size 8 :max-entries 256)))))
    (is (has-opcode-p bytes +jmp-call+))))

;;; ========== Map update ==========

(test map-update-emits-helper-2
  "map-update should emit map_update_elem (helper 2)"
  (let ((bytes (w-body "(let ((key 0)
                              (val 42))
                          (declare (type u32 key) (type u64 val))
                          (map-update m key val 0)
                          (return 0))"
                       :maps '((m :type :hash :key-size 4
                                   :value-size 8 :max-entries 256)))))
    ;; Find call to helper 2
    (let ((call-count 0))
      (let ((n (/ (length bytes) 8)))
        (loop for i below n
              when (and (= +jmp-call+ (nth-insn-opcode bytes i))
                        (= 2 (nth-insn-imm bytes i)))
                do (cl:incf call-count)))
      (is (> call-count 0)
          "Should call helper 2 (map_update_elem)"))))

;;; ========== Map delete ==========

(test map-delete-emits-helper-3
  "map-delete should emit map_delete_elem (helper 3)"
  (let ((bytes (w-body "(let ((key 0))
                          (declare (type u32 key))
                          (map-delete m key)
                          (return 0))"
                       :maps '((m :type :hash :key-size 4
                                   :value-size 8 :max-entries 256)))))
    (let ((call-count 0))
      (let ((n (/ (length bytes) 8)))
        (loop for i below n
              when (and (= +jmp-call+ (nth-insn-opcode bytes i))
                        (= 3 (nth-insn-imm bytes i)))
                do (cl:incf call-count)))
      (is (> call-count 0)
          "Should call helper 3 (map_delete_elem)"))))

;;; ========== Surface macros: setmap, remmap ==========

(test setmap-compiles
  "setmap should compile to map-update"
  (let ((bytes (w-body "(setmap m 0 42)
                        (return 0)"
                       :maps '((m :type :hash :key-size 4
                                   :value-size 8 :max-entries 256)))))
    (is (has-opcode-p bytes +jmp-call+)
        "setmap should emit a helper call")))

(test remmap-compiles
  "remmap should compile to map-delete"
  (let ((bytes (w-body "(remmap m 0)
                        (return 0)"
                       :maps '((m :type :hash :key-size 4
                                   :value-size 8 :max-entries 256)))))
    (is (has-opcode-p bytes +jmp-call+)
        "remmap should emit a helper call")))

;;; ========== Map type variants ==========

(test percpu-array-compiles
  "percpu-array map should compile"
  (let ((bytes (w-body "(let ((key 0))
                          (declare (type u32 key))
                          (let ((val (map-lookup m key)))
                            (declare (type u64 val))
                            (if val (return 1) (return 0))))"
                       :maps '((m :type :percpu-array :key-size 4
                                   :value-size 8 :max-entries 4)))))
    (is (has-opcode-p bytes +jmp-call+))))

(test percpu-hash-compiles
  "percpu-hash map should compile"
  (let ((bytes (w-body "(let ((key 0))
                          (declare (type u32 key))
                          (let ((val (map-lookup m key)))
                            (declare (type u64 val))
                            (if val (return 1) (return 0))))"
                       :maps '((m :type :percpu-hash :key-size 4
                                   :value-size 8 :max-entries 256)))))
    (is (has-opcode-p bytes +jmp-call+))))
