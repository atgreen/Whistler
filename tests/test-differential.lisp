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

(defun gen-scalar-expr (leaves depth)
  "Generate a random expression tree over the symbols in LEAVES using
   64-bit binops and constant shifts."
  (if (or (zerop depth) (< (fuzz-int 100) 25))
      (elt leaves (fuzz-int (length leaves)))
      (case (fuzz-int 8)
        (6 (list 'ash (gen-scalar-expr leaves (1- depth)) (+ 1 (fuzz-int 31))))
        (7 (list (intern ">>" '#:whistler)
                 (gen-scalar-expr leaves (1- depth)) (+ 1 (fuzz-int 31))))
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
    (dotimes (i 120)
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
