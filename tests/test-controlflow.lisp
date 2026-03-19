(in-package #:whistler/tests)

(in-suite controlflow-suite)

;;; ========== dotimes loop ==========

(test dotimes-compiles
  "dotimes loop should compile to a bounded loop"
  (let ((n (w-count "(let ((sum 0))
                       (declare (type u64 sum))
                       (dotimes (i 4)
                         (setf sum (+ sum 1)))
                       (return sum))")))
    (is (> n 4) "dotimes should produce loop instructions")))

(test dotimes-has-branch-back
  "dotimes should produce a backward branch (loop)"
  (let ((bytes (w-body "(let ((sum 0))
                          (declare (type u64 sum))
                          (dotimes (i 4)
                            (setf sum (+ sum 1)))
                          (return sum))")))
    ;; There should be a jlt or jge for the loop bound check
    (is (or (has-opcode-p bytes +jmp-jlt-imm+)
            (has-opcode-p bytes +jmp-jge-imm+)
            (has-opcode-p bytes +jmp-jlt-reg+)
            (has-opcode-p bytes +jmp-jge-reg+))
        "Expected a comparison instruction for loop bound")))

;;; ========== log2 intrinsic ==========

(test log2-intrinsic
  "log2 should emit unrolled binary search (15 instructions)"
  ;; log2 expands to: mov result,0 + 4×(jlt+rsh+add) + 1×jlt + 1×add = 15
  (let ((n (w-count "(let ((x (ctx-load u64 0)))
                       (declare (type u64 x))
                       (return (log2 x)))")))
    ;; ctx-load + log2 (15) + exit = at least 17
    (is (>= n 17) "log2 should produce at least 17 instructions")))

;;; ========== cast ==========

(test cast-u32-to-u64
  "cast should compile without error"
  (let ((n (w-count "(let ((x (ctx-load u32 0)))
                       (declare (type u32 x))
                       (return (cast u64 x)))")))
    (is (> n 1) "cast should produce instructions")))

(test cast-u64-to-u32
  "Narrowing cast should compile"
  (let ((n (w-count "(let ((x (ctx-load u64 0)))
                       (declare (type u64 x))
                       (return (cast u32 x)))")))
    (is (> n 1) "narrowing cast should produce instructions")))

;;; ========== logical operators ==========

(test logical-and
  "(and a b) should short-circuit — returns 0 if a is 0, else b"
  (let ((n (w-count "(let ((x (ctx-load u64 0))
                           (y (ctx-load u64 8)))
                       (declare (type u64 x) (type u64 y))
                       (if (and (> x 0) (> y 0))
                           (return 1)
                           (return 0)))")))
    (is (> n 4) "and should produce multiple branch instructions")))

(test logical-or
  "(or a b) should short-circuit — returns non-zero if either is non-zero"
  (let ((n (w-count "(let ((x (ctx-load u64 0))
                           (y (ctx-load u64 8)))
                       (declare (type u64 x) (type u64 y))
                       (if (or (> x 10) (> y 10))
                           (return 1)
                           (return 0)))")))
    (is (> n 4) "or should produce multiple branch instructions")))

(test logical-not
  "(not x) should negate a boolean"
  (let ((n (w-count "(let ((x (ctx-load u64 0)))
                       (declare (type u64 x))
                       (if (not (= x 0))
                           (return 1)
                           (return 0)))")))
    (is (> n 2) "not should produce instructions")))

;;; ========== if-let ==========

(test if-let-compiles
  "if-let should compile both branches"
  (let ((n (w-count "(let ((key 0))
                       (declare (type u32 key))
                       (if-let (v (map-lookup m key))
                         (return 1)
                         (return 0)))"
                    :maps '((m :type :array :key-size 4
                               :value-size 8 :max-entries 1)))))
    (is (> n 5) "if-let should produce lookup + branch + returns")))

;;; ========== when-let ==========

(test when-let-basic
  "when-let should compile lookup + conditional body"
  (let ((n (w-count "(let ((key 0))
                       (declare (type u32 key))
                       (when-let ((v u64 (map-lookup m key)))
                         (return v))
                       (return 0))"
                    :maps '((m :type :array :key-size 4
                               :value-size 8 :max-entries 1)))))
    (is (> n 5) "when-let should produce several instructions")))

;;; ========== case ==========

(test case-dispatch
  "case should compile multi-way dispatch"
  (let ((n (w-count "(let ((x (ctx-load u32 0)))
                       (declare (type u32 x))
                       (case x
                         (1 (return 10))
                         (2 (return 20))
                         (3 (return 30))
                         (t (return 0))))")))
    ;; case produces multiple comparisons + branches
    (is (> n 6) "case should produce multiple comparison chains")))

;;; ========== cond ==========

(test cond-compiles
  "cond should compile multi-clause conditional"
  (let ((n (w-count "(let ((x (ctx-load u64 0)))
                       (declare (type u64 x))
                       (cond
                         ((> x 100) (return 3))
                         ((> x 50)  (return 2))
                         ((> x 0)   (return 1))
                         (t         (return 0))))")))
    (is (> n 6) "cond should produce multiple branches")))
