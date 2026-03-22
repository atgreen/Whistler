;;; sccp.lisp — Sparse Conditional Constant Propagation
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Propagates constants through PHIs and along executable edges only.
;;; Collapses macro-generated control flow where flag/option values are known.

(in-package #:whistler/ir)

;;; ========== Lattice ==========

(defconstant +sccp-top+ :top)      ; unknown / not yet reached
(defconstant +sccp-bottom+ :bottom) ; overdefined / non-constant

(defun sccp-meet (a b)
  "Lattice meet: top ∧ x = x, const ∧ const = const (if equal) or bottom."
  (cond
    ((eq a +sccp-top+) b)
    ((eq b +sccp-top+) a)
    ((eq a +sccp-bottom+) +sccp-bottom+)
    ((eq b +sccp-bottom+) +sccp-bottom+)
    ((eql a b) a)
    (t +sccp-bottom+)))

(defun sccp-eval-alu (op lhs rhs)
  "Evaluate an ALU op on constant values. Returns result or nil."
  (handler-case
      (let ((result (cl:case op
                      (:add (+ lhs rhs))
                      (:sub (- lhs rhs))
                      (:mul (* lhs rhs))
                      (:div (if (zerop rhs) nil (truncate lhs rhs)))
                      (:mod (if (zerop rhs) nil (mod lhs rhs)))
                      (:and (logand lhs rhs))
                      (:or  (logior lhs rhs))
                      (:xor (logxor lhs rhs))
                      (:lsh (ash lhs rhs))
                      (:rsh (ash lhs (- rhs)))
                      (:arsh (ash lhs (- rhs)))
                      (t nil))))
        (when result (logand result #xFFFFFFFFFFFFFFFF)))
    (error () nil)))

;;; ========== Main SCCP pass ==========

(defun sccp (prog)
  "Sparse Conditional Constant Propagation.
   Propagates constants through PHIs, folds constant branches,
   and removes unreachable blocks. Modifies PROG in place."
  (compute-cfg-edges prog)
  (let ((blocks (ir-program-blocks prog))
        (entry-label (ir-program-entry prog))
        (lattice (make-hash-table))          ; vreg → value | :top | :bottom
        (exec-edges (make-hash-table :test 'equal)) ; (from . to) → t
        (exec-blocks (make-hash-table))      ; label → t
        (def-map (make-hash-table))          ; vreg → ir-insn
        (use-map (make-hash-table))          ; vreg → list of ir-insn
        (block-map (make-hash-table))        ; label → block
        (cfg-worklist '())
        (ssa-worklist '()))

    ;; Build maps
    (dolist (block blocks)
      (setf (gethash (basic-block-label block) block-map) block)
      (dolist (insn (basic-block-insns block))
        (when (ir-insn-dst insn)
          (setf (gethash (ir-insn-dst insn) def-map) insn)
          (setf (gethash (ir-insn-dst insn) lattice) +sccp-top+))
        (dolist (arg (ir-insn-args insn))
          (when (integerp arg)
            (push insn (gethash arg use-map))))))

    ;; Seed entry block
    (setf (gethash entry-label exec-blocks) t)
    (let ((entry-block (gethash entry-label block-map)))
      (when entry-block (push entry-block cfg-worklist)))

    ;; Helpers
    (labels
        ((lat-val (arg)
           (cond
             ((and (consp arg) (eq (car arg) :imm)) (second arg))
             ((integerp arg) (gethash arg lattice +sccp-top+))
             (t +sccp-bottom+)))

         (eval-insn (insn)
           (let ((op (ir-insn-op insn))
                 (args (ir-insn-args insn)))
             (cond
               ((and (eq op :mov)
                     (consp (first args)) (eq (car (first args)) :imm))
                (second (first args)))
               ((and (eq op :mov) (integerp (first args)))
                (lat-val (first args)))
               ((and (member op '(:add :sub :mul :div :mod
                                  :and :or :xor :lsh :rsh :arsh))
                     (= (length args) 2))
                (let ((l (lat-val (first args)))
                      (r (lat-val (second args))))
                  (cond
                    ((or (eq l +sccp-top+) (eq r +sccp-top+)) +sccp-top+)
                    ((or (eq l +sccp-bottom+) (eq r +sccp-bottom+)) +sccp-bottom+)
                    (t (or (sccp-eval-alu op l r) +sccp-bottom+)))))
               ((eq op :phi)
                (let ((result +sccp-top+))
                  (dolist (arg args)
                    (when (and (consp arg) (integerp (first arg))
                               (consp (second arg)) (eq (car (second arg)) :label))
                      (let ((src-label (cadr (second arg))))
                        (when (gethash src-label exec-blocks)
                          (setf result (sccp-meet result (lat-val (first arg))))))))
                  result))
               (t +sccp-bottom+))))

         (update-vreg (vreg new-val)
           (let ((old (gethash vreg lattice +sccp-top+)))
             (unless (eql old new-val)
               (setf (gethash vreg lattice) new-val)
               (dolist (use (gethash vreg use-map))
                 (push use ssa-worklist)))))

         (mark-edge (from to)
           (let ((key (cons from to)))
             (unless (gethash key exec-edges)
               (setf (gethash key exec-edges) t)
               (let ((target (gethash to block-map)))
                 (when target
                   (unless (gethash to exec-blocks)
                     (setf (gethash to exec-blocks) t)
                     (push target cfg-worklist))
                   (dolist (insn (basic-block-insns target))
                     (when (eq (ir-insn-op insn) :phi)
                       (push insn ssa-worklist))))))))

         (process-block (block)
           (dolist (insn (basic-block-insns block))
             (when (ir-insn-dst insn)
               (update-vreg (ir-insn-dst insn) (eval-insn insn))))
           ;; Handle terminator
           (let ((term (car (last (basic-block-insns block)))))
             (when term
               (cl:case (ir-insn-op term)
                 (:br
                  (let ((target (cadr (first (ir-insn-args term)))))
                    (when target (mark-edge (basic-block-label block) target))))
                 (:br-cond
                  (let* ((args (ir-insn-args term))
                         (cmp-op (second (first args)))
                         (lhs (lat-val (second args)))
                         (rhs (lat-val (third args)))
                         (then-label (cadr (fourth args)))
                         (else-label (cadr (fifth args))))
                    (cond
                      ((and (numberp lhs) (numberp rhs))
                       (if (evaluate-cmp cmp-op lhs rhs)
                           (when then-label (mark-edge (basic-block-label block) then-label))
                           (when else-label (mark-edge (basic-block-label block) else-label))))
                      (t
                       (when then-label (mark-edge (basic-block-label block) then-label))
                       (when else-label (mark-edge (basic-block-label block) else-label)))))))))))

      ;; === Solve ===
      (loop while (or cfg-worklist ssa-worklist) do
        (loop while cfg-worklist do (process-block (pop cfg-worklist)))
        (loop while ssa-worklist do
          (let* ((insn (pop ssa-worklist))
                 (dst (ir-insn-dst insn)))
            (when dst (update-vreg dst (eval-insn insn)))))))

    ;; === Rewrite ===

    ;; 1. Replace constant vreg operands with (:imm N)
    (dolist (block blocks)
      (when (gethash (basic-block-label block) exec-blocks)
        (dolist (insn (basic-block-insns block))
          (let ((op (ir-insn-op insn)))
            (when (member op '(:add :sub :mul :div :mod
                               :and :or :xor :lsh :rsh :arsh))
              (when (and (= (length (ir-insn-args insn)) 2)
                         (integerp (second (ir-insn-args insn))))
                (let ((val (gethash (second (ir-insn-args insn)) lattice +sccp-bottom+)))
                  (when (and (numberp val) (typep val '(signed-byte 32)))
                    (setf (second (ir-insn-args insn)) `(:imm ,val))))))
            (when (member op '(:br-cond :cmp))
              (when (and (>= (length (ir-insn-args insn)) 3)
                         (integerp (third (ir-insn-args insn))))
                (let ((val (gethash (third (ir-insn-args insn)) lattice +sccp-bottom+)))
                  (when (and (numberp val) (typep val '(signed-byte 32)))
                    (setf (third (ir-insn-args insn)) `(:imm ,val))))))))))

    ;; 2. Fold constant branches
    (dolist (block blocks)
      (when (gethash (basic-block-label block) exec-blocks)
        (let ((term (car (last (basic-block-insns block)))))
          (when (and term (eq (ir-insn-op term) :br-cond))
            (let* ((args (ir-insn-args term))
                   (lhs (let ((a (second args)))
                           (cond ((integerp a) (gethash a lattice +sccp-bottom+))
                                 ((and (consp a) (eq (car a) :imm)) (second a))
                                 (t +sccp-bottom+))))
                   (rhs (let ((a (third args)))
                           (cond ((integerp a) (gethash a lattice +sccp-bottom+))
                                 ((and (consp a) (eq (car a) :imm)) (second a))
                                 (t +sccp-bottom+))))
                   (cmp-op (second (first args))))
              (when (and (numberp lhs) (numberp rhs))
                (let ((target (if (evaluate-cmp cmp-op lhs rhs)
                                  (fourth args) (fifth args))))
                  (setf (ir-insn-op term) :br)
                  (setf (ir-insn-args term) (list target)))))))))

    ;; Note: block removal is left to simplify-cfg / dead-code-elimination
    ;; to avoid issues with implicit fall-through edges in loop structures.
    prog))
