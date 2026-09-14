;;; test-differential.lisp — Differential fuzzing: emitted BPF vs direct evaluation
;;;
;;; Generates random scalar expressions over helper-call results, compiles
;;; them through the full pipeline, executes the emitted BPF in the test
;;; interpreter with stubbed call results, and compares against direct
;;; evaluation of the same expression. This is the only oracle that
;;; catches silent wrong-value miscompiles — the kernel verifier accepts
;;; scalar corruption without complaint (see whistler-snx, whistler-dtx).
;;;
;;; Deterministic: a fixed xorshift64 seed makes every run identical, so
;;; a failure reproduces. On failure the report prints the expression,
;;; leaf values, expected and actual results — paste the expression into
;;; a defprog to debug.

(in-package #:whistler/tests)

(def-suite differential-suite
  :description "Differential fuzzing of scalar codegen against direct evaluation"
  :in whistler-suite)

(in-suite differential-suite)

(defvar *fuzz-state* 0)

(defun fuzz-seed (seed)
  (setf *fuzz-state* (ldb (byte 64 0) (logior seed 1))))

(defun fuzz-next ()
  "xorshift64 — deterministic, portable PRNG."
  (let ((x *fuzz-state*))
    (setf x (ldb (byte 64 0) (logxor x (ash x 13))))
    (setf x (logxor x (ash x -7)))
    (setf x (ldb (byte 64 0) (logxor x (ash x 17))))
    (setf *fuzz-state* x)))

(defun fuzz-int (n)
  (mod (fuzz-next) n))

(defparameter *fuzz-binops* '(+ - * logand logior logxor))
(defparameter *fuzz-cmp-ops* '(> < >= <= = /=))

(defun gen-scalar-expr (leaves depth)
  "Generate a random expression tree over the symbols in LEAVES using
   64-bit binops, constant shifts, and if-expressions over unsigned
   comparisons (exercising branch emission and phi moves). Leaves are
   sometimes integer literals, so comparisons can become compile-time
   constant — driving simplify-cfg's constant-branch folding and
   trivial-phi collapse (the issue #42 machinery)."
  (if (or (zerop depth) (< (fuzz-int 100) 25))
      (if (< (fuzz-int 100) 30)
          ;; Small constants collide often (making constant compares and
          ;; equal phi arms likely); occasional large ones stress
          ;; immediates.
          (if (< (fuzz-int 100) 80)
              (fuzz-int 4)
              (fuzz-int (expt 2 32)))
          (elt leaves (fuzz-int (length leaves))))
      (case (fuzz-int 10)
        (6 (list 'ash (gen-scalar-expr leaves (1- depth)) (+ 1 (fuzz-int 31))))
        (7 (list (intern ">>" '#:whistler)
                 (gen-scalar-expr leaves (1- depth)) (+ 1 (fuzz-int 31))))
        ((8 9)
         (list 'if
               (list (elt *fuzz-cmp-ops* (fuzz-int (length *fuzz-cmp-ops*)))
                     (gen-scalar-expr leaves (1- depth))
                     (gen-scalar-expr leaves (1- depth)))
               (gen-scalar-expr leaves (1- depth))
               (gen-scalar-expr leaves (1- depth))))
        (t (list (elt *fuzz-binops* (fuzz-int (length *fuzz-binops*)))
                 (gen-scalar-expr leaves (1- depth))
                 (gen-scalar-expr leaves (1- depth)))))))

(defun eval-scalar-expr (expr env)
  "Directly evaluate EXPR with 64-bit wraparound semantics. ENV is an
   alist of leaf symbol → value."
  (cond
    ((symbolp expr) (cdr (assoc expr env)))
    ((integerp expr) expr)
    (t (let ((op (first expr)))
         (ldb (byte 64 0)
              (cond
                ((eq op 'ash)
                 (ash (eval-scalar-expr (second expr) env) (third expr)))
                ((string= (symbol-name op) ">>")
                 (ash (eval-scalar-expr (second expr) env) (- (third expr))))
                ((string= (symbol-name op) "CAST")
                 (ldb (byte (cast-type-bits (second expr)) 0)
                      (eval-scalar-expr (third expr) env)))
                ((eq op 'if)
                 (let* ((cmp (second expr))
                        (a (eval-scalar-expr (second cmp) env))
                        (b (eval-scalar-expr (third cmp) env))
                        (taken (ecase (first cmp)
                                 (> (> a b)) (< (< a b))
                                 (>= (>= a b)) (<= (<= a b))
                                 (= (= a b)) (/= (/= a b)))))
                   (eval-scalar-expr (if taken (third expr) (fourth expr)) env)))
                (t (let ((a (eval-scalar-expr (second expr) env))
                         (b (eval-scalar-expr (third expr) env)))
                     (ecase op
                       (+ (+ a b)) (- (- a b)) (* (* a b))
                       (logand (logand a b))
                       (logior (logior a b))
                       (logxor (logxor a b)))))))))))

(defun fuzz-one-case (n-leaves depth)
  "Build one random program, compile it, interpret the emitted BPF, and
   return (values ok expr leaf-values expected actual)."
  (let* ((leaves (loop for i from 1 to n-leaves
                       collect (intern (format nil "X~D" i) '#:whistler)))
         (leaf-values (loop repeat n-leaves collect (fuzz-int (expt 2 32))))
         (expr (gen-scalar-expr leaves depth))
         (body `((let ,(loop for l in leaves
                             collect `(,l (,(intern "GET-PRANDOM-U32" '#:whistler))))
                   (declare (type ,(intern "U64" '#:whistler) ,@leaves))
                   (return ,expr))))
         (expected (eval-scalar-expr expr (mapcar #'cons leaves leaf-values)))
         (bytes (compile-insn-bytes body))
         (actual (interpret-scalar-bpf bytes (copy-list leaf-values))))
    (values (eql expected actual) expr leaf-values expected actual)))

(test differential-scalar-fuzz
  "Random scalar expressions: emitted BPF must compute the same value as
   direct evaluation. Exercises ALU emission, register pressure, and
   spill reloads (6 leaves live across 6 helper calls force a spill)."
  (fuzz-seed 20260907)
  (let ((failures '()))
    (dotimes (i 160)
      ;; Cycle leaf counts 1-6 so both the spill-free and spilling
      ;; regalloc paths are exercised; depth 2-4.
      (let ((n-leaves (+ 1 (mod i 6)))
            (depth (+ 2 (fuzz-int 3))))
        (multiple-value-bind (ok expr leaf-values expected actual)
            (handler-case (fuzz-one-case n-leaves depth)
              (error (e)
                (values nil (format nil "case ~D signalled: ~A" i e)
                        nil nil nil)))
          (unless ok
            (push (list i expr leaf-values expected actual) failures)))))
    (is (null failures)
        (format nil "~D differential failure(s), first: case ~{~D expr=~S leaves=~S expected=~S actual=~S~}"
                (length failures) (first (last failures))))))

;;; ========== Loops (whistler-2m0.2) ==========
;;;
;;; Everything above is one straight line of blocks, so nothing here ever
;;; built a back edge. A loop is a different shape: lower-dotimes opens a
;;; phi at the header for *every* in-scope variable, live ranges span the
;;; body, and the peephole passes meet a jump target that sits behind
;;; them rather than ahead. Those are the parts no straight-line case can
;;; reach.
;;;
;;; The generated shape is an accumulator:
;;;
;;;     (let ((acc <init>))
;;;       (declare (type u64 acc))
;;;       (dotimes (i <n>) (setf acc <step>))
;;;       (return acc))
;;;
;;; <step> may read acc and the loop counter as well as the leaves, so
;;; the value has to survive the back edge to come out right.

(defun fuzz-loop-spec (leaves depth)
  "Describe one accumulator loop: how many turns, what ACC starts at,
   and what it becomes each turn."
  (let ((acc (intern "ACC" '#:whistler))
        (idx (intern "I" '#:whistler)))
    (list :acc acc
          :idx idx
          :count (+ 1 (fuzz-int 4))
          :init (gen-scalar-expr leaves depth)
          ;; ACC and the counter join the leaves, so the body can depend
          ;; on the previous turn — the whole point of the back edge.
          :step (gen-scalar-expr (list* acc idx leaves) depth))))

(defun loop-spec-body (spec)
  "Render SPEC as the body forms of a defprog."
  (destructuring-bind (&key acc idx count init step) spec
    `((let ((,acc ,init))
        (declare (type ,(intern "U64" '#:whistler) ,acc))
        (dotimes (,idx ,count)
          (setf ,acc ,step))
        (return ,acc)))))

(defun eval-loop-spec (spec env)
  "Evaluate SPEC the obvious way, to compare the compiler against."
  (destructuring-bind (&key acc idx count init step) spec
    (let ((value (eval-scalar-expr init env)))
      (dotimes (turn count value)
        (setf value (eval-scalar-expr
                     step
                     (list* (cons acc value) (cons idx turn) env)))))))

(defun fuzz-one-loop-case (n-leaves depth)
  "Build one random loop program, compile it, interpret the emitted BPF,
   and return (values ok spec leaf-values expected actual)."
  (let* ((leaves (loop for i from 1 to n-leaves
                       collect (intern (format nil "X~D" i) '#:whistler)))
         (leaf-values (loop repeat n-leaves collect (fuzz-int (expt 2 32))))
         (spec (fuzz-loop-spec leaves depth))
         (body `((let ,(loop for l in leaves
                             collect `(,l (,(intern "GET-PRANDOM-U32" '#:whistler))))
                   (declare (type ,(intern "U64" '#:whistler) ,@leaves))
                   ,@(loop-spec-body spec))))
         (expected (eval-loop-spec spec (mapcar #'cons leaves leaf-values)))
         (bytes (compile-insn-bytes body))
         (actual (interpret-scalar-bpf bytes (copy-list leaf-values))))
    (values (eql expected actual) spec leaf-values expected actual)))

(test differential-loop-fuzz
  "Random accumulator loops: the value carried across the back edge must
   survive phi insertion, register allocation and the peephole passes."
  (fuzz-seed 20260914)
  (let ((failures '()))
    (dotimes (i 120)
      (let ((n-leaves (+ 1 (mod i 4)))
            (depth (+ 1 (fuzz-int 3))))
        (multiple-value-bind (ok spec leaf-values expected actual)
            (handler-case (fuzz-one-loop-case n-leaves depth)
              (error (e)
                (values nil (format nil "case ~D signalled: ~A" i e)
                        nil nil nil)))
          (unless ok
            (push (list i spec leaf-values expected actual) failures)))))
    (is (null failures)
        (format nil "~D loop differential failure(s), first: case ~{~D spec=~S leaves=~S expected=~S actual=~S~}"
                (length failures) (first (last failures))))))

;;; ========== Stack memory (whistler-2m0.2) ==========
;;;
;;; Scalars and loops never leave registers. These programs allocate a
;;; stack buffer, store into it at mixed widths and offsets, then read
;;; it back — which is what drives the stack-address folding, the
;;; store/load elimination and load/load forwarding passes, and the
;;; narrowing that decides a store's width. A store that overlaps an
;;; earlier one has to win on exactly the bytes it covers, so the oracle
;;; models the buffer byte by byte rather than slot by slot.

(defparameter *fuzz-buffer-size* 32)
(defparameter *fuzz-widths* '(1 2 4 8))

(defun width-type (width)
  (intern (ecase width (1 "U8") (2 "U16") (4 "U32") (8 "U64")) '#:whistler))

(defun fuzz-offset (width)
  "A naturally aligned offset with room for a WIDTH-byte access."
  (* width (fuzz-int (floor *fuzz-buffer-size* width))))

(defun gen-memory-spec (leaves depth)
  "Describe a program that fills a stack buffer and then reads it."
  (let ((stores (loop repeat (+ 1 (fuzz-int 4))
                      for width = (elt *fuzz-widths* (fuzz-int 4))
                      collect (list :width width
                                    :offset (fuzz-offset width)
                                    :value (gen-scalar-expr leaves depth))))
        (loads (loop repeat (+ 1 (fuzz-int 3))
                     for width = (elt *fuzz-widths* (fuzz-int 4))
                     collect (list :width width :offset (fuzz-offset width)))))
    (list :stores stores :loads loads)))

(defun memory-spec-body (spec leaves)
  (destructuring-bind (&key stores loads) spec
    (let ((buf (intern "BUF" '#:whistler)))
      `((let ((,buf (,(intern "STRUCT-ALLOC" '#:whistler) ,*fuzz-buffer-size*)))
          ,@(loop for s in stores
                  collect `(,(intern "STORE" '#:whistler)
                            ,(width-type (getf s :width))
                            ,buf ,(getf s :offset) ,(getf s :value)))
          (return ,(let ((terms (loop for l in loads
                                      collect `(,(intern "LOAD" '#:whistler)
                                                ,(width-type (getf l :width))
                                                ,buf ,(getf l :offset)))))
                     ;; Combine the loads (and a leaf, when there is one)
                     ;; so every one of them reaches the result.
                     (reduce (lambda (a b) (list '+ a b))
                             (if leaves (cons (first leaves) terms) terms)))))))))

(defun eval-memory-spec (spec leaves env)
  (destructuring-bind (&key stores loads) spec
    (let ((buffer (make-array *fuzz-buffer-size* :initial-element 0)))
      (dolist (s stores)
        (let ((value (eval-scalar-expr (getf s :value) env)))
          (dotimes (k (getf s :width))
            (setf (aref buffer (+ (getf s :offset) k))
                  (ldb (byte 8 (* 8 k)) value)))))
      (let ((values (loop for l in loads
                          collect (let ((v 0))
                                    (dotimes (k (getf l :width) v)
                                      (setf (ldb (byte 8 (* 8 k)) v)
                                            (aref buffer (+ (getf l :offset) k))))))))
        (ldb (byte 64 0)
             (reduce #'+ (if leaves
                             (cons (cdr (assoc (first leaves) env)) values)
                             values)))))))

(defun fuzz-one-memory-case (n-leaves depth)
  (let* ((leaves (loop for i from 1 to n-leaves
                       collect (intern (format nil "X~D" i) '#:whistler)))
         (leaf-values (loop repeat n-leaves collect (fuzz-int (expt 2 32))))
         (spec (gen-memory-spec leaves depth))
         (env (mapcar #'cons leaves leaf-values))
         (body `((let ,(loop for l in leaves
                             collect `(,l (,(intern "GET-PRANDOM-U32" '#:whistler))))
                   (declare (type ,(intern "U64" '#:whistler) ,@leaves))
                   ,@(memory-spec-body spec leaves))))
         (expected (eval-memory-spec spec leaves env))
         (bytes (compile-insn-bytes body))
         (actual (interpret-scalar-bpf bytes (copy-list leaf-values))))
    (values (eql expected actual) spec leaf-values expected actual)))

(test differential-memory-fuzz
  "Stack stores and loads at mixed widths and offsets: what comes back
   out must be what the overlapping stores actually left behind."
  (fuzz-seed 20260915)
  (let ((failures '()))
    (dotimes (i 120)
      ;; At least one leaf: gen-scalar-expr picks from this list.
      (let ((n-leaves (+ 1 (mod i 3)))
            (depth (+ 1 (fuzz-int 3))))
        (multiple-value-bind (ok spec leaf-values expected actual)
            (handler-case (fuzz-one-memory-case n-leaves depth)
              (error (e)
                (values nil (format nil "case ~D signalled: ~A" i e)
                        nil nil nil)))
          (unless ok
            (push (list i spec leaf-values expected actual) failures)))))
    (is (null failures)
        (format nil "~D memory differential failure(s), first: case ~{~D spec=~S leaves=~S expected=~S actual=~S~}"
                (length failures) (first (last failures))))))

;;; ========== Casts and 32-bit arithmetic (whistler-2m0.2) ==========
;;;
;;; The scalar generator reaches alu32 only indirectly, through
;;; narrow-alu-types deciding an operation fits in 32 bits — which is
;;; how the lsh32 and mul32 narrowing bugs were caught. What it never
;;; produces is an explicit (cast uN ...), where the truncation is asked
;;; for rather than inferred, and where a narrower type flows back into
;;; the surrounding arithmetic.

(defparameter *fuzz-cast-bits* '(8 16 32 64))

(defun cast-type-symbol (bits)
  (intern (ecase bits (8 "U8") (16 "U16") (32 "U32") (64 "U64")) '#:whistler))

(defun cast-type-bits (type-symbol)
  (let ((name (symbol-name type-symbol)))
    (cond ((string= name "U8") 8)
          ((string= name "U16") 16)
          ((string= name "U32") 32)
          (t 64))))

(defun gen-cast-expr (leaves depth)
  "A scalar expression with (cast uN ...) nodes threaded through it."
  (if (or (zerop depth) (< (fuzz-int 100) 30))
      (gen-scalar-expr leaves (max 0 (1- depth)))
      (case (fuzz-int 6)
        ((0 1 2)
         (list (intern "CAST" '#:whistler)
               (cast-type-symbol (elt *fuzz-cast-bits* (fuzz-int 4)))
               (gen-cast-expr leaves (1- depth))))
        (3 (list 'ash (gen-cast-expr leaves (1- depth)) (+ 1 (fuzz-int 31))))
        (4 (list (intern ">>" '#:whistler)
                 (gen-cast-expr leaves (1- depth)) (+ 1 (fuzz-int 31))))
        (t (list (elt *fuzz-binops* (fuzz-int (length *fuzz-binops*)))
                 (gen-cast-expr leaves (1- depth))
                 (gen-cast-expr leaves (1- depth)))))))

(defun fuzz-one-cast-case (n-leaves depth)
  (let* ((leaves (loop for i from 1 to n-leaves
                       collect (intern (format nil "X~D" i) '#:whistler)))
         (leaf-values (loop repeat n-leaves collect (fuzz-int (expt 2 32))))
         (expr (gen-cast-expr leaves depth))
         (body `((let ,(loop for l in leaves
                             collect `(,l (,(intern "GET-PRANDOM-U32" '#:whistler))))
                   (declare (type ,(intern "U64" '#:whistler) ,@leaves))
                   (return ,expr))))
         (expected (eval-scalar-expr expr (mapcar #'cons leaves leaf-values)))
         (bytes (compile-insn-bytes body))
         (actual (interpret-scalar-bpf bytes (copy-list leaf-values))))
    (values (eql expected actual) expr leaf-values expected actual)))

(test differential-cast-fuzz
  "Explicit casts: the value must be truncated where the program says
   so, whatever width the compiler decides to compute in."
  (fuzz-seed 20260916)
  (let ((failures '()))
    (dotimes (i 140)
      (let ((n-leaves (+ 1 (mod i 4)))
            (depth (+ 2 (fuzz-int 3))))
        (multiple-value-bind (ok expr leaf-values expected actual)
            (handler-case (fuzz-one-cast-case n-leaves depth)
              (error (e)
                (values nil (format nil "case ~D signalled: ~A" i e)
                        nil nil nil)))
          (unless ok
            (push (list i expr leaf-values expected actual) failures)))))
    (is (null failures)
        (format nil "~D cast differential failure(s), first: case ~{~D expr=~S leaves=~S expected=~S actual=~S~}"
                (length failures) (first (last failures))))))
