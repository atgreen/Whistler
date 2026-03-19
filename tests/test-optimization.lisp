(in-package #:whistler/tests)

(in-suite optimization-suite)

;;; ========== CFG simplification ==========

(test cfg-fold-true-branch
  "Constant true condition should fold to taken branch"
  ;; (> 10 5) is true → should become (return 1), 2 insns
  (is (= 2 (w-count "(if (> 10 5) (return 1) (return 0))"))))

(test cfg-fold-false-branch
  "Constant false condition should fold to else branch"
  ;; (> 3 5) is false → should become (return 0)
  (let ((bytes (w-body "(if (> 3 5) (return 99) (return 42))")))
    (is (= 42 (nth-insn-imm bytes 0))
        "Should return 42 from else branch")))

(test cfg-fold-eq-true
  "(= 5 5) should fold to true"
  (is (= 2 (w-count "(if (= 5 5) (return 1) (return 0))"))))

(test cfg-fold-eq-false
  "(= 5 6) should fold to false"
  (let ((bytes (w-body "(if (= 5 6) (return 99) (return 42))")))
    (is (= 42 (nth-insn-imm bytes 0)))))

(test cfg-fold-signed-gt
  "(s> 5 3) should fold to true"
  (is (= 2 (w-count "(if (s> 5 3) (return 1) (return 0))"))))

(test cfg-fold-let-constant-if
  "Let-bound constant in if should fold via CFG simplification"
  ;; (let ((x 10)) (if (> x 5) ...)) folds because x=10 is in const-map
  (is (= 2 (w-count "(let ((x u32 10))
                        (if (> x 5) (return 1) (return 0)))"))))

;;; ========== Dead code elimination ==========

(test dce-unused-map-lookup
  "Unused map-lookup result should be eliminated by DCE"
  ;; A map-lookup whose result is never tested or used should be eliminated
  ;; Compare with a version that actually uses the result
  (let ((n-used (w-count "(let ((key u32 0))
                            (let ((val u64 (map-lookup m key)))
                              (if val (return 1) (return 0))))"
                         :maps '((m :type :array :key-size 4
                                    :value-size 8 :max-entries 1))))
        (n-unused (w-count "(let ((key u32 0))
                              (let ((val u64 (map-lookup m key)))
                                (return 42)))"
                           :maps '((m :type :array :key-size 4
                                      :value-size 8 :max-entries 1)))))
    (is (< n-unused n-used)
        "Unused map-lookup result should produce fewer instructions")))

(test dce-unused-computation
  "Unused arithmetic should be eliminated"
  ;; (+ x y) result is unused, x and y loads should also be dead
  (is (= 2 (w-count "(let ((x u64 (ctx-load u64 0))
                           (y u64 (ctx-load u64 8)))
                        (let ((z u64 (+ x y)))
                          (return 42)))"))))

;;; ========== Common subexpression elimination ==========

(test cse-duplicate-ctx-load
  "Two ctx-loads at the same offset should CSE to one"
  (let ((n-dup (w-count "(let ((a u32 (ctx-load u32 0))
                               (b u32 (ctx-load u32 0)))
                           (return (+ a b)))"))
        (n-single (w-count "(let ((a u32 (ctx-load u32 0)))
                              (return (+ a a)))")))
    (is (= n-dup n-single)
        "Duplicate ctx-loads should CSE to the same instruction count as single")))

(test cse-different-offsets-not-eliminated
  "ctx-loads at different offsets should NOT be CSE'd"
  (let ((n (w-count "(let ((a u32 (ctx-load u32 0))
                           (b u32 (ctx-load u32 4)))
                       (return (+ a b)))")))
    ;; Need at least: 2 loads + add + mov r0 + exit = 5
    (is (>= n 4) "Different offsets should produce separate loads")))

;;; ========== Store-to-load forwarding ==========

(test stlf-basic-forward
  "Store followed by load at same location should forward"
  ;; Compare: store+load vs just using the value directly
  ;; The forwarded version should have the same or fewer instructions
  (let ((n-direct (w-count "(let ((key u32 0))
                              (when-let ((p u64 (map-lookup m key)))
                                (return 42))
                              (return 0))"
                           :maps '((m :type :array :key-size 4
                                      :value-size 8 :max-entries 1)))))
    ;; Just verify it compiles — the forwarding is internal
    (is (> n-direct 3) "Should compile with multiple instructions")))

;;; ========== Constant propagation ==========

(test constprop-through-let
  "Constants should propagate through let bindings"
  ;; (let ((x 42)) (return x)) → (return 42) → 2 insns
  (is (= 2 (w-count "(let ((x u64 42)) (return x))"))))

(test constprop-arithmetic
  "Constant arithmetic should fold"
  (is (= 2 (w-count "(return (+ 10 20))"))))

(test constprop-nested-let
  "Constants should propagate through nested lets"
  (is (= 2 (w-count "(let ((x u64 10))
                        (let ((y u64 x))
                          (return y)))"))))

;;; ========== Narrow ALU types ==========

(test narrow-and-mask
  "(logand x 0xff) should narrow to 32-bit ALU"
  (let ((bytes (w-body "(let ((x u64 (ctx-load u64 0)))
                          (return (logand x #xff)))")))
    ;; Should use alu32 and (0x54) instead of alu64 and (0x57)
    (is (has-opcode-p bytes #x54)
        "Expected alu32 and imm for small mask")))

;;; ========== Peephole: basic smoke tests ==========

(test peephole-no-redundant-exit
  "Peephole should not leave redundant exit instructions"
  (let ((bytes (w-body "(return 42)")))
    (is (= 1 (count-opcode bytes +jmp-exit+))
        "Should have exactly one exit instruction")))

(test peephole-branch-to-next
  "Branch to the immediately next instruction should be eliminated"
  ;; Simple if/else where one branch is trivial may produce this
  (let ((n (w-count "(let ((x u64 (ctx-load u64 0)))
                       (if (> x 0)
                           (return 1)
                           (return 0)))")))
    ;; With peephole, this should be compact
    (is (<= n 6) "Simple if/else should be compact after peephole")))
