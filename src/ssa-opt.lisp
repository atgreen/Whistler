;;; -*- Mode: Lisp -*-
;;;
;;; Copyright (c) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; SPDX-License-Identifier: MIT

;;; ssa-opt.lisp — SSA optimization passes
;;;
;;; Each pass transforms an ir-program in place.

(in-package #:whistler/ir)

;;; ========== Copy propagation ==========
;;;
;;; For every %b = mov %a (vreg-to-vreg copy), replace all uses of %b
;;; with %a, then delete the mov. Handles chains transitively.

(defun copy-propagation (prog)
  "Propagate vreg-to-vreg copies. Returns modified prog."
  (let ((copies (make-hash-table)))  ; vreg → replacement vreg
    ;; Phase 1: collect all copy instructions
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        (when (and (eq (ir-insn-op insn) :mov)
                   (ir-insn-dst insn)
                   (let ((arg (first (ir-insn-args insn))))
                     (integerp arg)))
          ;; %dst = mov %src  (vreg-to-vreg)
          (setf (gethash (ir-insn-dst insn) copies)
                (first (ir-insn-args insn))))))

    ;; Resolve chains: if %a → %b → %c, resolve %a → %c
    (let ((resolved (make-hash-table)))
      (labels ((resolve (vreg)
                 (or (gethash vreg resolved)
                     (let ((target (gethash vreg copies)))
                       (if target
                           (let ((final (resolve target)))
                             (setf (gethash vreg resolved) final)
                             final)
                           (progn
                             (setf (gethash vreg resolved) vreg)
                             vreg))))))
        ;; Resolve all entries
        (maphash (lambda (k v) (declare (ignore v)) (resolve k)) copies)

        ;; Phase 2: replace uses
        (dolist (block (ir-program-blocks prog))
          (dolist (insn (basic-block-insns block))
            (setf (ir-insn-args insn)
                  (subst-vreg-args (ir-insn-args insn) resolved))))

        ;; Phase 3: delete copy instructions (now dead)
        (dolist (block (ir-program-blocks prog))
          (setf (basic-block-insns block)
                (remove-if (lambda (insn)
                             (and (eq (ir-insn-op insn) :mov)
                                  (ir-insn-dst insn)
                                  (let ((arg (first (ir-insn-args insn))))
                                    (integerp arg))
                                  ;; Only remove if dst was in our copy set
                                  (gethash (ir-insn-dst insn) copies)))
                           (basic-block-insns block)))))))
  prog)

(defun subst-vreg-args (args resolved)
  "Replace vreg references in an argument list using the resolved table."
  (mapcar (lambda (arg)
            (cond
              ;; Plain vreg
              ((integerp arg)
               (or (gethash arg resolved) arg))
              ;; Phi arg: (vreg (:label ...))
              ((and (consp arg) (integerp (first arg)))
               (cons (or (gethash (first arg) resolved) (first arg))
                     (rest arg)))
              (t arg)))
          args))

;;; ========== Dead code elimination ==========
;;;
;;; Mark-sweep: start from side-effecting instructions, walk use-def
;;; chains backwards marking all producers as live.

(defun dead-code-elimination (prog)
  "Remove instructions whose results are never used. Returns modified prog."
  (let ((live (make-hash-table :test #'eq))  ; insn object → t
        (def-map (make-hash-table))           ; vreg → ir-insn
        (all-insns '()))

    ;; Build def map and collect all instructions
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        (push insn all-insns)
        (when (ir-insn-dst insn)
          (setf (gethash (ir-insn-dst insn) def-map) insn))))

    ;; Mark phase: start from side-effecting instructions
    (let ((worklist '()))
      (dolist (insn all-insns)
        (when (ir-insn-side-effect-p insn)
          (push insn worklist)))

      ;; Walk backwards through use-def chains
      (loop while worklist do
        (let ((insn (pop worklist)))
          (unless (gethash insn live)
            (setf (gethash insn live) t)
            ;; Mark all vregs used by this instruction
            (dolist (vreg (ir-insn-all-vreg-uses insn))
              (let ((def-insn (gethash vreg def-map)))
                (when (and def-insn (not (gethash def-insn live)))
                  (push def-insn worklist))))))))

    ;; Sweep: remove unmarked instructions
    (dolist (block (ir-program-blocks prog))
      (setf (basic-block-insns block)
            (remove-if (lambda (insn)
                         (not (gethash insn live)))
                       (basic-block-insns block)))))
  prog)

(defun ir-insn-all-vreg-uses (insn)
  "Return all vreg numbers referenced in instruction args (including phi args)."
  (let ((vregs '()))
    (dolist (arg (ir-insn-args insn))
      (cond
        ((integerp arg) (push arg vregs))
        ;; Phi operand: (vreg (:label ...))
        ((and (consp arg) (integerp (first arg)))
         (push (first arg) vregs))))
    vregs))

;;; ========== Constant propagation ==========
;;;
;;; For %v = mov (:imm N), replace uses of %v with (:imm N) in positions
;;; that can accept immediates (br-cond rhs, ALU rhs, cmp rhs).

(defun constant-propagation (prog)
  "Propagate constant immediates into instructions that accept them."
  (let ((constants (make-hash-table)))  ; vreg → (:imm N)
    ;; Phase 1: collect all constant definitions
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        (when (and (eq (ir-insn-op insn) :mov)
                   (ir-insn-dst insn)
                   (let ((arg (first (ir-insn-args insn))))
                     (and (consp arg) (eq (car arg) :imm))))
          (setf (gethash (ir-insn-dst insn) constants)
                (first (ir-insn-args insn))))))

    ;; Phase 2: propagate into ALU rhs, br-cond rhs, cmp rhs
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        (let ((op (ir-insn-op insn))
              (args (ir-insn-args insn)))
          (cond
            ;; ALU ops: (lhs rhs) - propagate rhs if it's a constant
            ((member op '(:add :sub :mul :div :mod :and :or :xor :lsh :rsh :arsh))
             (when (and (= (length args) 2)
                        (integerp (second args)))
               (let ((imm (gethash (second args) constants)))
                 (when (and imm (typep (second imm) '(signed-byte 32)))
                   (setf (second (ir-insn-args insn)) imm)))))

            ;; br-cond: ((:cmp op) lhs rhs (:label then) (:label else))
            ;; propagate rhs (3rd arg)
            ((eq op :br-cond)
             (when (and (>= (length args) 3)
                        (integerp (third args)))
               (let ((imm (gethash (third args) constants)))
                 (when (and imm (typep (second imm) '(signed-byte 32)))
                   (setf (third (ir-insn-args insn)) imm)))))

            ;; cmp: ((:cmp op) lhs rhs) - propagate rhs
            ((eq op :cmp)
             (when (and (>= (length args) 3)
                        (integerp (third args)))
               (let ((imm (gethash (third args) constants)))
                 (when (and imm (typep (second imm) '(signed-byte 32)))
                   (setf (third (ir-insn-args insn)) imm)))))

            ;; map-update/map-update-ptr: propagate flags (4th arg)
            ((member op '(:map-update :map-update-ptr))
             (when (and (>= (length args) 4)
                        (integerp (fourth args)))
               (let ((imm (gethash (fourth args) constants)))
                 (when imm
                   (setf (fourth (ir-insn-args insn)) imm)))))

            ;; map-lookup/map-delete: propagate key (2nd arg) for st-mem
            ((member op '(:map-lookup :map-delete))
             (when (and (>= (length args) 2)
                        (integerp (second args)))
               (let ((imm (gethash (second args) constants)))
                 (when (and imm (typep (second imm) '(signed-byte 32)))
                   (setf (second (ir-insn-args insn)) imm))))))))))
  prog)

;;; ========== Dead destination elimination ==========
;;;
;;; For side-effecting instructions (calls, stores) whose result vreg
;;; is never used, set dst to nil to avoid emitting dead result saves.

(defun dead-destination-elimination (prog)
  "Null out dst for side-effecting instructions whose results are unused."
  (let ((used-vregs (make-hash-table)))
    ;; Collect all vreg uses
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        (dolist (vreg (ir-insn-all-vreg-uses insn))
          (setf (gethash vreg used-vregs) t))))
    ;; Null out unused destinations on side-effecting instructions
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        (when (and (ir-insn-dst insn)
                   (ir-insn-side-effect-p insn)
                   (not (gethash (ir-insn-dst insn) used-vregs)))
          (setf (ir-insn-dst insn) nil)))))
  prog)

(defun compute-dominators (prog)
  "Compute immediate dominators for all blocks. Returns hash table: label → dominator label.
   Entry block dominates itself."
  (let* ((blocks (ir-program-blocks prog))
         (entry-label (basic-block-label (first blocks)))
         (dom (make-hash-table))    ; label → set of dominator labels
         (all-labels '())
         (pred-map (make-hash-table)))  ; label → list of predecessor labels
    ;; Collect all labels
    (dolist (b blocks) (push (basic-block-label b) all-labels))
    (setf all-labels (nreverse all-labels))
    ;; Build predecessor map from branch targets
    (dolist (b blocks)
      (let ((term (car (last (basic-block-insns b)))))
        (when term
          (dolist (arg (ir-insn-args term))
            (when (and (consp arg) (eq (car arg) :label))
              (push (basic-block-label b) (gethash (second arg) pred-map)))))))
    ;; Initialize: entry dominated only by itself, others by all
    (setf (gethash entry-label dom) (list entry-label))
    (dolist (label all-labels)
      (unless (eq label entry-label)
        (setf (gethash label dom) (copy-list all-labels))))
    ;; Iterate until stable
    (let ((changed t))
      (loop while changed do
        (setf changed nil)
        (dolist (label all-labels)
          (unless (eq label entry-label)
            (let ((new-dom nil))
              ;; Intersect dominators of all predecessors
              (let ((preds (gethash label pred-map)))
                (when preds
                  (setf new-dom (copy-list (gethash (first preds) dom)))
                  (dolist (pred (rest preds))
                    (setf new-dom (intersection new-dom (gethash pred dom))))))
              ;; Add self
              (pushnew label new-dom)
              ;; Check for change
              (unless (and (= (length new-dom) (length (gethash label dom)))
                           (null (set-difference new-dom (gethash label dom))))
                (setf (gethash label dom) new-dom)
                (setf changed t)))))))
    dom))

(defun dominates-p (dom-map dominator-label target-label)
  "Does DOMINATOR-LABEL dominate TARGET-LABEL?"
  (member dominator-label (gethash target-label dom-map)))

;;; ========== Load hoisting ==========
;;;
;;; When a LOAD from a map pointer is followed by a CALL (with other insns
;;; between), and the LOAD's source vreg is the map-lookup result, hoist
;;; the LOAD before the CALL. This shortens the pointer's live range so it
;;; doesn't need a callee-saved register.

(defun hoist-loads-before-calls (prog)
  "Hoist LOAD instructions before CALL instructions when safe.
   Only hoists across helper calls that don't invalidate pointers.
   The pointer vreg must not be the call's result, and must be
   defined before the call."
  (dolist (block (ir-program-blocks prog))
    (let ((insns (basic-block-insns block)))
      (let ((new-insns (copy-list insns))
            (changed nil))
        (loop for i from 0 below (1- (length new-insns))
              do (let ((call-insn (nth i new-insns)))
                   (when (and (eq (ir-insn-op call-insn) :call)
                              (not (helper-invalidates-p call-insn
                                                         :invalidates-packet-ptrs)))
                     (loop for j from (1+ i) below (length new-insns)
                           for load-insn = (nth j new-insns)
                           do (when (eq (ir-insn-op load-insn) :load)
                                (let ((ptr-vreg (first (ir-insn-args load-insn)))
                                      (call-dst (ir-insn-dst call-insn)))
                                  (when (and (integerp ptr-vreg)
                                             (or (null call-dst)
                                                 (/= ptr-vreg call-dst)))
                                    (setf new-insns (remove load-insn new-insns :count 1))
                                    (setf new-insns
                                          (append (subseq new-insns 0 i)
                                                  (list load-insn)
                                                  (nthcdr i new-insns)))
                                    (setf changed t)
                                    (return))))
                              (when (ir-insn-side-effect-p load-insn)
                                (return))))))
        (when changed
          (setf (basic-block-insns block) new-insns)))))
  prog)

;;; ========== Tracepoint return elision ==========
;;;
;;; For tracepoint/kprobe/raw_tp programs, the return value is ignored
;;; by the kernel. Remove the value operand from RET instructions so
;;; DCE can eliminate dead return-value setup code.

(defun elide-tracepoint-return (prog)
  "For tracepoint/kprobe programs, the kernel ignores the return value.
   However, the BPF verifier still requires R0 to be set before exit.
   Keep ret args intact so the emitter generates mov r0, val; exit."
  ;; No-op: previously cleared ret args, but that caused verifier
  ;; failures (R0 !read_ok) when helper calls clobbered R0 before exit.
  prog)

;;; ========== Context load analysis ==========
;;;
;;; When all ctx-load instructions occur before any side-effecting instruction
;;; (calls, stores), the ctx pointer in R1 is still live and we can use it
;;; directly instead of saving to R6. This frees R6 for general allocation.

(defparameter *force-save-ctx* nil
  "When true, disable the ctx-loads-early optimization and keep ctx in R6.")

(defun ctx-loads-early-p (prog)
  "Can we keep ctx in R1 instead of saving to R6?
   True when all ctx-loads are either in the entry block (before any
   side-effecting instruction) or are rematerializable from the entry
   block's ctx-loads. Checks conservatively: all ctx-loads must be
   in the entry block before any side effect, AND the ctx vreg must
   not be used as a direct argument to any helper call (since calls
   clobber R1-R5)."
  (when *force-save-ctx*
    (return-from ctx-loads-early-p nil))
  ;; Find the ctx vreg
  (let ((ctx-vreg nil))
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        (when (eq (ir-insn-op insn) :arg0)
          (setf ctx-vreg (ir-insn-dst insn)))))
    ;; If ctx-vreg is passed as a direct argument to any helper call,
    ;; it MUST be saved to R6 because helper calls clobber R1-R5.
    (when ctx-vreg
      (dolist (block (ir-program-blocks prog))
        (dolist (insn (basic-block-insns block))
          (when (eq (ir-insn-op insn) :call)
            ;; Check if ctx-vreg is among the call arguments
            ;; Args format: ((:helper N) arg1 arg2 ...) — skip the helper id
            (dolist (arg (rest (ir-insn-args insn)))
              (when (and (integerp arg) (eql arg ctx-vreg))
                (return-from ctx-loads-early-p nil)))))))
    ;; Strategy: check if all ctx-loads are in the entry block before barriers
    (let ((entry-block (first (ir-program-blocks prog)))
          (seen-barrier nil)
          (entry-ok t))
      ;; Check entry block
      (dolist (insn (basic-block-insns entry-block))
        (when (and seen-barrier (member (ir-insn-op insn) '(:ctx-load :ctx-store)))
          (setf entry-ok nil))
        (when (ir-insn-side-effect-p insn)
          (setf seen-barrier t)))
      ;; Check non-entry blocks: any ctx-load/ctx-store disqualifies
      (dolist (block (rest (ir-program-blocks prog)))
        (dolist (insn (basic-block-insns block))
          (when (member (ir-insn-op insn) '(:ctx-load :ctx-store))
            (return-from ctx-loads-early-p nil))))
      entry-ok)))

;;; ========== PHI-branch threading ==========
;;;
;;; When a block B has:
;;;   %phi = PHI (v1 from P1) (v2 from P2) ...
;;;   br-cond :jne %phi (:imm 0) THEN ELSE
;;;
;;; For each PHI input:
;;;   - Constant 0 → redirect predecessor to jump to ELSE directly
;;;   - Constant non-zero → redirect predecessor to jump to THEN directly
;;;   - CMP result → replace predecessor's terminator with a direct br-cond
;;;     using the CMP's operands, skipping the boolean materialization

(defun phi-branch-threading (prog)
  "Thread branches through PHI nodes to eliminate boolean materialization."
  (let ((def-map (make-hash-table))
        (const-map (make-hash-table))
        (changed nil))
    ;; Build def map and constant map
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        (when (ir-insn-dst insn)
          (setf (gethash (ir-insn-dst insn) def-map) insn))
        (when (and (eq (ir-insn-op insn) :mov)
                   (ir-insn-dst insn)
                   (let ((arg (first (ir-insn-args insn))))
                     (and (consp arg) (eq (car arg) :imm))))
          (setf (gethash (ir-insn-dst insn) const-map)
                (second (first (ir-insn-args insn)))))))

    ;; Find blocks with PHI → br-cond :jne %phi 0 pattern
    (dolist (block (ir-program-blocks prog))
      (let ((terminator (car (last (basic-block-insns block)))))
        (when (and terminator (eq (ir-insn-op terminator) :br-cond))
          (let ((args (ir-insn-args terminator)))
            (when (and (equal (first args) '(:cmp :jne))
                       (integerp (second args))
                       (equal (third args) '(:imm 0)))
              (let ((phi-insn (find-if
                               (lambda (insn)
                                 (and (eq (ir-insn-op insn) :phi)
                                      (eql (ir-insn-dst insn) (second args))))
                               (basic-block-insns block)))
                    (then-label (fourth args))
                    (else-label (fifth args)))
                (when phi-insn
                  ;; Copy args list: threading mutates it via removal
                  (dolist (phi-arg (copy-list (ir-insn-args phi-insn)))
                    (when (and (consp phi-arg) (integerp (first phi-arg)))
                      (phi-thread-one-input prog block phi-insn phi-arg
                                            then-label else-label
                                            def-map const-map
                                            (lambda () (setf changed t))))))))))))

    (when changed
      (eliminate-unreachable-blocks prog)
      (dead-code-elimination prog)))
  prog)

(defun eliminate-unreachable-blocks (prog)
  "Remove basic blocks that are not reachable from any predecessor."
  (let ((reachable (make-hash-table))
        (entry-label (basic-block-label (first (ir-program-blocks prog)))))
    ;; Mark entry block
    (setf (gethash entry-label reachable) t)
    ;; Mark all jump/branch targets
    (dolist (block (ir-program-blocks prog))
      (when (gethash (basic-block-label block) reachable)
        (dolist (insn (basic-block-insns block))
          (dolist (arg (ir-insn-args insn))
            (when (and (consp arg) (eq (car arg) :label))
              (setf (gethash (second arg) reachable) t))))))
    ;; Iterate until stable (handles chains)
    (let ((changed t))
      (loop while changed do
        (setf changed nil)
        (dolist (block (ir-program-blocks prog))
          (when (and (gethash (basic-block-label block) reachable))
            (dolist (insn (basic-block-insns block))
              (dolist (arg (ir-insn-args insn))
                (when (and (consp arg) (eq (car arg) :label)
                           (not (gethash (second arg) reachable)))
                  (setf (gethash (second arg) reachable) t)
                  (setf changed t))))))))
    ;; Remove unreachable blocks
    (setf (ir-program-blocks prog)
          (remove-if-not (lambda (block)
                           (gethash (basic-block-label block) reachable))
                         (ir-program-blocks prog))))
  prog)

(defun ensure-label-form (x)
  "Ensure X is in (:label sym) form. If already wrapped, return as-is.
   If a bare symbol, wrap it."
  (if (and (consp x) (eq (car x) :label))
      x
      (list :label x)))

(defun phi-thread-one-input (prog block phi-insn phi-arg then-label else-label
                             def-map const-map on-change)
  "Thread one PHI input: redirect predecessor to skip the PHI+branch block."
  (let* ((val-vreg (first phi-arg))
         (from-label (second (second phi-arg)))
         (pred-block (ir-find-block prog from-label))
         (const-val (gethash val-vreg const-map))
         (def-insn (gethash val-vreg def-map))
         ;; Normalize labels to (:label sym) form
         (then-label (ensure-label-form then-label))
         (else-label (ensure-label-form else-label)))
    (when pred-block
      (let ((pred-term (car (last (basic-block-insns pred-block)))))
        (when (and pred-term
                   (eq (ir-insn-op pred-term) :br)
                   (equal (first (ir-insn-args pred-term))
                          (list :label (basic-block-label block))))
          (cond
            ;; Constant value → redirect to then or else directly
            (const-val
             (setf (ir-insn-args pred-term)
                   (list (if (zerop const-val) else-label then-label)))
             ;; Remove this input from the PHI so downstream passes
             ;; (simplify-cfg merge) see the correct input count.
             (setf (ir-insn-args phi-insn)
                   (remove phi-arg (ir-insn-args phi-insn) :test #'equal))
             (funcall on-change))

            ;; CMP result → replace br with direct br-cond
            ((and def-insn (eq (ir-insn-op def-insn) :cmp))
             (setf (ir-insn-op pred-term) :br-cond)
             (setf (ir-insn-args pred-term)
                   (list (first (ir-insn-args def-insn))
                         (second (ir-insn-args def-insn))
                         (third (ir-insn-args def-insn))
                         then-label
                         else-label))
             ;; Remove this input from the PHI
             (setf (ir-insn-args phi-insn)
                   (remove phi-arg (ir-insn-args phi-insn) :test #'equal))
             (funcall on-change))))))))

;;; ========== Bitmask check fusion ==========
;;;
;;; Recognizes the pattern:
;;;   Block A: %m = AND %x M;  br-cond :jne %m 0 B FAIL
;;;   Block B: %n = AND %x N;  br-cond :jeq %n 0 SUCCESS FAIL
;;;
;;; Where both ANDs use the same source vreg %x, and both failure
;;; paths go to FAIL. This is the compiled form of:
;;;   (and (logand x M) (not (logand x N)))
;;;
;;; Transforms to:
;;;   Block A: %m = AND %x (M|N);  br-cond :jeq %m (:imm M) SUCCESS FAIL
;;; Block B becomes dead.

(defun bitmask-check-fusion (prog)
  "Fuse sequential AND+branch checks on the same source into a combined bitmask check."
  (let ((def-map (make-hash-table))
        (changed nil))
    ;; Build def map
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        (when (ir-insn-dst insn)
          (setf (gethash (ir-insn-dst insn) def-map) insn))))

    (dolist (block-a (ir-program-blocks prog))
      (let ((term-a (car (last (basic-block-insns block-a)))))
        ;; Block A ends with: br-cond :jne %m (:imm 0) B FAIL
        (when (and term-a
                   (eq (ir-insn-op term-a) :br-cond)
                   (equal (first (ir-insn-args term-a)) '(:cmp :jne))
                   (integerp (second (ir-insn-args term-a)))
                   (equal (third (ir-insn-args term-a)) '(:imm 0)))
          (let* ((m-vreg (second (ir-insn-args term-a)))
                 (then-label-a (second (fourth (ir-insn-args term-a))))
                 (fail-label-a (second (fifth (ir-insn-args term-a))))
                 (m-def (gethash m-vreg def-map))
                 (block-b (ir-find-block prog then-label-a)))
            ;; %m must be AND %x (:imm M)
            (when (and m-def
                       (eq (ir-insn-op m-def) :and)
                       (= (length (ir-insn-args m-def)) 2)
                       (integerp (first (ir-insn-args m-def)))
                       (let ((rhs (second (ir-insn-args m-def))))
                         (and (consp rhs) (eq (car rhs) :imm))))
              (let ((x-vreg (first (ir-insn-args m-def)))
                    (m-val (second (second (ir-insn-args m-def)))))
                ;; Block B must end with: br-cond :jeq %n (:imm 0) SUCCESS FAIL
                ;; and must not contain any side-effecting instructions
                ;; (other than the terminator) that would be lost when skipped
                (when (and block-b
                          (not (some (lambda (insn)
                                       (and (ir-insn-side-effect-p insn)
                                            (not (eq insn (car (last (basic-block-insns block-b)))))))
                                     (basic-block-insns block-b))))
                  (let ((term-b (car (last (basic-block-insns block-b)))))
                    (when (and term-b
                               (eq (ir-insn-op term-b) :br-cond)
                               (equal (first (ir-insn-args term-b)) '(:cmp :jeq))
                               (integerp (second (ir-insn-args term-b)))
                               (equal (third (ir-insn-args term-b)) '(:imm 0)))
                      (let* ((n-vreg (second (ir-insn-args term-b)))
                             (success-label (fourth (ir-insn-args term-b)))
                             (fail-label-b (second (fifth (ir-insn-args term-b))))
                             (n-def (gethash n-vreg def-map)))
                        ;; %n must be AND %x (:imm N) with SAME source vreg
                        (when (and n-def
                                   (eq (ir-insn-op n-def) :and)
                                   (= (length (ir-insn-args n-def)) 2)
                                   (integerp (first (ir-insn-args n-def)))
                                   (= (first (ir-insn-args n-def)) x-vreg)
                                   (let ((rhs (second (ir-insn-args n-def))))
                                     (and (consp rhs) (eq (car rhs) :imm))))
                          (let ((n-val (second (second (ir-insn-args n-def)))))
                            ;; Both failure paths must go to the same place
                            ;; FAIL-A must reach FAIL-B (either equal, or
                            ;; FAIL-A is a block that just jumps to FAIL-B)
                            (when (or (eq fail-label-a fail-label-b)
                                      (let ((fail-block (ir-find-block prog fail-label-a)))
                                        (and fail-block
                                             (= (length (basic-block-insns fail-block)) 1)
                                             (let ((fi (first (basic-block-insns fail-block))))
                                               (and (eq (ir-insn-op fi) :br)
                                                    (eq (second (first (ir-insn-args fi)))
                                                        fail-label-b))))))
                              ;; Transform!
                              ;; Change AND %x M → AND %x (M|N)
                              (setf (second (ir-insn-args m-def))
                                    (list :imm (logior m-val n-val)))
                              ;; Change br-cond :jne %m 0 B FAIL →
                              ;;        br-cond :jeq %m (:imm M) SUCCESS FAIL-B
                              (setf (ir-insn-args term-a)
                                    (list '(:cmp :jeq)
                                          m-vreg
                                          (list :imm m-val)
                                          success-label
                                          (list :label fail-label-b)))
                              (setf changed t))))))))))))))

    (when changed
      (eliminate-unreachable-blocks prog)
      (dead-code-elimination prog)))
  prog)

;;; ========== Constant offset folding ==========
;;;
;;; When a :load or :ctx-load uses a pointer computed by :add with an
;;; immediate offset, fold the add's offset into the load's offset and
;;; use the add's base directly. This eliminates runtime pointer
;;; arithmetic for packet field accesses.
;;;
;;; Chains are handled: if %ip = add %data 14 and %tcp = add %ip 20,
;;; then (load %tcp 13 u8) folds to (load %data 47 u8).

(defun fold-constant-offsets (prog)
  "Fold add-immediate chains into load/ctx-load/store offsets and into
   other add-immediate instructions (collapsing multi-step pointer arithmetic)."
  (let ((def-map (make-hash-table))
        (changed nil))
    ;; Build def map
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        (when (ir-insn-dst insn)
          (setf (gethash (ir-insn-dst insn) def-map) insn))))

    ;; For each load/ctx-load/store, chase the pointer through add-immediate chains
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        ;; Case 1: load/ctx-load/store/ctx-store — fold add chain into offset
        (when (member (ir-insn-op insn) '(:load :ctx-load :store :ctx-store))
          (let ((ptr-vreg (first (ir-insn-args insn)))
                (load-off (second (second (ir-insn-args insn))))  ; from (:imm N)
                (accumulated 0))
            ;; Chase the pointer through add-immediate chain
            (loop
              (let ((def (and (integerp ptr-vreg) (gethash ptr-vreg def-map))))
                (if (and def
                         (eq (ir-insn-op def) :add)
                         (= (length (ir-insn-args def)) 2)
                         (integerp (first (ir-insn-args def)))
                         (let ((rhs (second (ir-insn-args def))))
                           (and (consp rhs) (eq (car rhs) :imm))))
                    ;; This pointer comes from: %ptr = add %base (:imm C)
                    (let ((base-vreg (first (ir-insn-args def)))
                          (add-off (second (second (ir-insn-args def)))))
                      (incf accumulated add-off)
                      (setf ptr-vreg base-vreg))
                    ;; Not an add-immediate — stop chasing
                    (return))))
            ;; If we accumulated any offset, rewrite the instruction
            (when (plusp accumulated)
              (let ((new-off (+ load-off accumulated)))
                ;; Only fold if the result fits in a signed 16-bit offset
                ;; (BPF load/store instructions use 16-bit offset field)
                (when (typep new-off '(signed-byte 16))
                  (setf (first (ir-insn-args insn)) ptr-vreg)
                  (setf (second (ir-insn-args insn)) (list :imm new-off))
                  (setf changed t))))))
        ;; Case 2: add with immediate rhs — fold the lhs if it's also add-imm
        (when (and (eq (ir-insn-op insn) :add)
                   (= (length (ir-insn-args insn)) 2)
                   (integerp (first (ir-insn-args insn)))
                   (let ((rhs (second (ir-insn-args insn))))
                     (and (consp rhs) (eq (car rhs) :imm))))
          (let ((lhs-vreg (first (ir-insn-args insn)))
                (this-off (second (second (ir-insn-args insn))))
                (accumulated 0))
            (loop
              (let ((def (and (integerp lhs-vreg) (gethash lhs-vreg def-map))))
                (if (and def
                         (eq (ir-insn-op def) :add)
                         (= (length (ir-insn-args def)) 2)
                         (integerp (first (ir-insn-args def)))
                         (let ((rhs (second (ir-insn-args def))))
                           (and (consp rhs) (eq (car rhs) :imm))))
                    (let ((base-vreg (first (ir-insn-args def)))
                          (add-off (second (second (ir-insn-args def)))))
                      (incf accumulated add-off)
                      (setf lhs-vreg base-vreg))
                    (return))))
            (when (plusp accumulated)
              (let ((new-off (+ this-off accumulated)))
                (when (typep new-off '(signed-byte 32))
                  (setf (first (ir-insn-args insn)) lhs-vreg)
                  (setf (second (ir-insn-args insn)) (list :imm new-off))
                  (setf changed t))))))))

    ;; Dead adds will be cleaned up by DCE
    (when changed
      (dead-code-elimination prog)))
  prog)

;;; ========== Type narrowing ==========
;;;
;;; Narrows ALU instruction types from u64 to u32 when the result
;;; provably fits in 32 bits. This enables ALU32 emission, saving
;;; instructions (no need for explicit 16/32-bit masking after ALU32 ops).

(defun narrow-alu-types (prog)
  "Narrow ALU types based on operation semantics and operand types.
   Runs after constant propagation so immediates are visible."
  ;; Build vreg → defining-insn map
  (let ((def-map (make-hash-table)))
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        (when (ir-insn-dst insn)
          (setf (gethash (ir-insn-dst insn) def-map) insn))))

    ;; Walk all instructions and narrow types
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        (let ((op (ir-insn-op insn))
              (args (ir-insn-args insn)))
          (when (and (ir-insn-type insn)
                     (string= (string-upcase (string (ir-insn-type insn))) "U64"))
            (cond
              ;; (logand x MASK) where MASK fits in 32 bits → u32
              ((eq op :and)
               (let ((rhs-imm (and (consp (second args))
                                   (eq (first (second args)) :imm)
                                   (second (second args)))))
                 (when (and rhs-imm (typep rhs-imm '(unsigned-byte 32)))
                   (setf (ir-insn-type insn) 'u32))))

              ;; (>> x N) where N >= 32 can't happen in BPF, but
              ;; (>> x N) where x is u32 → still u32
              ;; (>> x 16) on any value → result fits in 48 bits, which is still u64
              ;; BUT if x is u32, (>> x N) → u32
              ((eq op :rsh)
               (let ((lhs (first args)))
                 (when (and (integerp lhs)
                            (let ((def (gethash lhs def-map)))
                              (and def (ir-insn-type def)
                                   (narrow-type-p (ir-insn-type def)))))
                   (setf (ir-insn-type insn) 'u32))))

              ;; (xor x MASK), (or x MASK) → u32 if both operands are u32
              ;; Note: add/sub are NOT narrowed because carry bits may exceed
              ;; 32 bits (e.g., checksum folding). Use explicit (cast u32 ...)
              ;; in source if 32-bit add is desired.
              ((member op '(:xor :or :mul))
               (when (both-operands-narrow-p args def-map)
                 (setf (ir-insn-type insn) 'u32)))

              ;; (mod x y), (div x y) → u32 if both operands u32
              ((member op '(:mod :div))
               (when (both-operands-narrow-p args def-map)
                 (setf (ir-insn-type insn) 'u32)))

              ;; (lsh x N) — stays wide unless x is narrow and shift is small
              ((eq op :lsh)
               (let ((lhs (first args))
                     (rhs-imm (and (consp (second args))
                                   (eq (first (second args)) :imm)
                                   (second (second args)))))
                 (when (and rhs-imm (<= rhs-imm 16)
                            (integerp lhs)
                            (let ((def (gethash lhs def-map)))
                              (and def (ir-insn-type def)
                                   (narrow-type-p (ir-insn-type def)))))
                   (setf (ir-insn-type insn) 'u32))))))))))
  prog)

(defun narrow-type-p (type)
  "Is TYPE 32-bit or narrower?"
  (when type
    (let ((name (string-upcase (string type))))
      (or (string= name "U8")  (string= name "I8")
          (string= name "U16") (string= name "I16")
          (string= name "U32") (string= name "I32")))))

(defun operand-narrow-p (arg def-map)
  "Is operand ARG a 32-bit-or-narrower value?"
  (cond
    ;; Immediate constant
    ((and (consp arg) (eq (first arg) :imm))
     (let ((v (second arg)))
       (typep v '(unsigned-byte 32))))
    ;; Virtual register — check its defining instruction's type
    ((integerp arg)
     (let ((def (gethash arg def-map)))
       (and def (ir-insn-type def) (narrow-type-p (ir-insn-type def)))))
    (t nil)))

(defun both-operands-narrow-p (args def-map)
  "Are both operands in ARGS 32-bit or narrower?"
  (and (>= (length args) 2)
       (operand-narrow-p (first args) def-map)
       (operand-narrow-p (second args) def-map)))

;;; ========== Dead store elimination ==========
;;;
;;; Within each basic block, if a :store to (ptr-vreg, offset) is followed
;;; by another :store to the same (ptr-vreg, offset) with the same or larger
;;; type, and no intervening instruction reads that memory (loads from same
;;; ptr, calls that might read it, or escapes), the first store is dead.

(defun store-byte-size (insn)
  "Return the byte size of a :store instruction."
  (let ((type-arg (fourth (ir-insn-args insn))))
    (when (and (consp type-arg) (eq (first type-arg) :type))
      (let ((name (string-upcase (string (second type-arg)))))
        (cond
          ((or (string= name "U8")  (string= name "I8"))  1)
          ((or (string= name "U16") (string= name "I16")) 2)
          ((or (string= name "U32") (string= name "I32")) 4)
          (t 8))))))

(defun store-key (insn)
  "Return (ptr-vreg . offset) for a :store instruction, or NIL."
  (when (eq (ir-insn-op insn) :store)
    (let ((ptr (first (ir-insn-args insn)))
          (off-arg (second (ir-insn-args insn))))
      (when (and (integerp ptr) (consp off-arg) (eq (first off-arg) :imm))
        (cons ptr (second off-arg))))))

(defun insn-reads-memory-p (insn ptr-vreg)
  "Does INSN potentially read memory pointed to by PTR-VREG?"
  (let ((op (ir-insn-op insn)))
    (or
     ;; Loads from the same pointer
     (and (eq op :load)
          (eql (first (ir-insn-args insn)) ptr-vreg))
     ;; Atomic ops read + write
     (and (eq op :atomic-add)
          (eql (first (ir-insn-args insn)) ptr-vreg))
     ;; Map ops that pass the pointer — the helper reads the memory
     (and (member op '(:map-lookup-ptr :map-update-ptr :map-delete-ptr))
          (member ptr-vreg (rest (ir-insn-args insn))))
     ;; Any call could read memory (conservative)
     (call-like-op-p op))))

(defun dead-store-elimination (prog)
  "Eliminate stores that are overwritten before being read.
   Uses byte-level coverage tracking per pointer so that multiple smaller
   stores can together kill a larger zero-init store.
   Works within each basic block. Returns modified prog."
  (dolist (block (ir-program-blocks prog))
    (let ((dead '())
          ;; Per pointer-vreg: list of (insn off size . covered-bitvec)
          ;; covered-bitvec tracks which bytes of this store have been
          ;; overwritten by subsequent stores
          (pending-by-ptr (make-hash-table)))
      ;; Forward scan
      (dolist (insn (basic-block-insns block))
        (let ((key (store-key insn)))
          (cond
            (key
             (let* ((ptr (car key))
                    (off (cdr key))
                    (size (store-byte-size insn))
                    (existing (gethash ptr pending-by-ptr)))
               ;; Mark bytes [off, off+size) as covered in all pending stores
               ;; for this pointer. If a pending store is fully covered, it's dead.
               (let ((new-existing '()))
                 (dolist (entry existing)
                   (destructuring-bind (pend-insn pend-off pend-size . bv) entry
                     ;; Mark overlapping bytes as covered
                     (loop for i from (max 0 (- off pend-off))
                           below (min pend-size (- (+ off size) pend-off))
                           when (>= i 0)
                           do (setf (aref bv i) 1))
                     ;; Check if fully covered
                     (if (every (lambda (b) (= b 1)) bv)
                         (push pend-insn dead)
                         (push entry new-existing))))
                 ;; Add this store as pending
                 (push (list* insn off size
                              (make-array size :element-type 'bit :initial-element 0))
                       new-existing)
                 (setf (gethash ptr pending-by-ptr) new-existing))))
            ;; Not a store
            (t
             ;; Flush pending stores for pointers read by this insn
             (let ((to-clear '()))
               (maphash (lambda (ptr entries)
                          (declare (ignore entries))
                          (when (insn-reads-memory-p insn ptr)
                            (push ptr to-clear)))
                        pending-by-ptr)
               (dolist (ptr to-clear)
                 (remhash ptr pending-by-ptr)))
             ;; Branch/ret ends the block — flush all
             (when (member (ir-insn-op insn) '(:br :br-cond :ret))
               (clrhash pending-by-ptr))))))
      ;; Remove dead stores
      (when dead
        (setf (basic-block-insns block)
              (remove-if (lambda (insn) (member insn dead :test #'eq))
                         (basic-block-insns block))))))
  prog)

;;; ========== Live-range splitting ==========
;;;
;;; SSA-to-SSA transform that splits call-spanning vregs by inserting
;;; reload instructions after calls.  This shortens intervals so they
;;; fit in caller-saved registers, freeing callee-saved registers for
;;; values that truly need them (or for map-fd caching).
;;;
;;; A vreg is "reloadable" if its defining instruction can be cheaply
;;; re-executed after a call:
;;;   - mov (:imm N)            — constant, always reloadable
;;;   - ctx-load TYPE OFF       — reloadable when ctx itself spans calls
;;;   - load TYPE base OFF      — reloadable when base itself spans calls
;;;   - add base (:imm N)       — reloadable when base spans calls
;;;
;;; The pass inserts fresh vregs with copies of the defining instruction
;;; after each call that interrupts the vreg's live range, then rewrites
;;; subsequent uses (up to the next call or block boundary) to use the
;;; fresh vreg.  Phi operands in successor blocks are also patched.

;; call-like-op-p is now in ir.lisp (shared with regalloc.lisp)

(defun base-vreg-pointer-kind (vreg vreg-defs)
  "Classify the pointer kind of VREG based on its defining instruction.
   Returns :packet, :map-value, :stack, or NIL (unknown)."
  (let ((def-insn (gethash vreg vreg-defs)))
    (when def-insn
      (case (ir-insn-op def-insn)
        ;; ctx-load produces packet pointers (data, data_end)
        (:ctx-load :packet)
        ;; map-lookup and map-lookup-ptr produce map value pointers
        ((:map-lookup :map-lookup-ptr) :map-value)
        ;; stack-addr and struct-alloc produce stack pointers
        ((:stack-addr :struct-alloc) :stack)
        ;; add with imm offset inherits kind from its base
        (:add (let ((args (ir-insn-args def-insn)))
                (when (and (= (length args) 2)
                           (integerp (first args))
                           (consp (second args))
                           (eq (car (second args)) :imm))
                  (base-vreg-pointer-kind (first args) vreg-defs))))
        ;; mov from another vreg inherits kind
        (:mov (let ((args (ir-insn-args def-insn)))
                (when (and (= (length args) 1)
                           (integerp (first args)))
                  (base-vreg-pointer-kind (first args) vreg-defs))))
        (otherwise nil)))))

(defun pointer-kind-to-effect (kind)
  "Map a pointer kind to the helper-effect that would invalidate it."
  (case kind
    (:packet :invalidates-packet-ptrs)
    (:map-value :invalidates-map-value-ptrs)
    (:stack :invalidates-stack-addrs)
    (otherwise nil)))

(defun reloadable-after-call-p (insn call-insn call-spanning-vregs vreg-defs)
  "Can INSN be safely re-executed after CALL-INSN?
   Checks both that the instruction is cheap to re-execute and that
   the specific call does not invalidate the pointer kind involved."
  (case (ir-insn-op insn)
    ;; mov (:imm N) — always safe, no pointer dependency
    (:mov
     (let ((args (ir-insn-args insn)))
       (and (= (length args) 1)
            (consp (first args))
            (eq (car (first args)) :imm))))
    ;; ctx-load base off — safe when the ctx pointer itself spans calls and
    ;; the specific helper does not invalidate packet pointers.
    ;; This is mainly useful for reloading data/data_end after safe helpers.
    (:ctx-load
     (let ((args (ir-insn-args insn)))
       (and (>= (length args) 2)
            (integerp (first args))
            (gethash (first args) call-spanning-vregs)
            (not (helper-invalidates-p call-insn :invalidates-packet-ptrs)))))
    ;; load type base off — safe if base spans calls AND call
    ;; does not invalidate the base's pointer kind
    (:load
     (let ((args (ir-insn-args insn)))
       (and (>= (length args) 2)
            (integerp (first args))
            (gethash (first args) call-spanning-vregs)
            (let* ((base (first args))
                   (kind (base-vreg-pointer-kind base vreg-defs))
                   (effect (pointer-kind-to-effect kind)))
              ;; If kind is unknown, refuse (conservative)
              (and kind
                   (or (null effect)
                       (not (helper-invalidates-p call-insn effect))))))))
    ;; add base (:imm N) — same safety model as load
    (:add
     (let ((args (ir-insn-args insn)))
       (and (= (length args) 2)
            (integerp (first args))
            (consp (second args))
            (eq (car (second args)) :imm)
            (gethash (first args) call-spanning-vregs)
            (let* ((base (first args))
                   (kind (base-vreg-pointer-kind base vreg-defs))
                   (effect (pointer-kind-to-effect kind)))
              (and kind
                   (or (null effect)
                       (not (helper-invalidates-p call-insn effect))))))))
    ;; stack-addr — always safe (R10 immutable, no helper touches stack layout)
    (:stack-addr t)
    (otherwise nil)))

(defun reloadable-insn-p (insn call-spanning-vregs &optional vreg-defs)
  "Can INSN be cheaply re-executed after a call?
   When VREG-DEFS is provided, also checks pointer-kind safety.
   Without VREG-DEFS, uses the legacy liveness-only check."
  (if vreg-defs
      ;; With vreg-defs we can't check against a specific call here,
      ;; but we can verify the instruction is structurally reloadable
      ;; and its base pointer kind is known.  Per-call safety is checked
      ;; by reloadable-after-call-p at split points.
      (case (ir-insn-op insn)
        (:mov (let ((args (ir-insn-args insn)))
                (and (= (length args) 1)
                     (consp (first args))
                     (eq (car (first args)) :imm))))
        (:ctx-load (let ((args (ir-insn-args insn)))
                     (and (>= (length args) 2)
                          (integerp (first args))
                          (gethash (first args) call-spanning-vregs))))
        (:load (let ((args (ir-insn-args insn)))
                 (and (>= (length args) 2)
                      (integerp (first args))
                      (gethash (first args) call-spanning-vregs)
                      (base-vreg-pointer-kind (first args) vreg-defs))))
        (:add (let ((args (ir-insn-args insn)))
                (and (= (length args) 2)
                     (integerp (first args))
                     (consp (second args))
                     (eq (car (second args)) :imm)
                     (gethash (first args) call-spanning-vregs)
                     (base-vreg-pointer-kind (first args) vreg-defs))))
        (:stack-addr t)
        (otherwise nil))
      ;; Legacy path: no vreg-defs, use liveness-only check
      (case (ir-insn-op insn)
        (:mov (let ((args (ir-insn-args insn)))
                (and (= (length args) 1)
                     (consp (first args))
                     (eq (car (first args)) :imm))))
        (:ctx-load (let ((args (ir-insn-args insn)))
                     (and (>= (length args) 2)
                          (integerp (first args))
                          (gethash (first args) call-spanning-vregs))))
        (:load (let ((args (ir-insn-args insn)))
                 (and (>= (length args) 2)
                      (integerp (first args))
                      (gethash (first args) call-spanning-vregs))))
        (:add (let ((args (ir-insn-args insn)))
                (and (= (length args) 2)
                     (integerp (first args))
                     (consp (second args))
                     (eq (car (second args)) :imm)
                     (gethash (first args) call-spanning-vregs))))
        (:stack-addr t)
        (otherwise nil))))

(defun split-live-ranges (prog)
  "Split call-spanning vregs that are reloadable.
   Inserts reload instructions after calls, rewrites subsequent uses.
   Uses per-block availability tracking to avoid wasteful reloads at
   block boundaries where no call has intervened."
  ;; Phase 0: compute successor and predecessor lists from branch instructions
  (dolist (block (ir-program-blocks prog))
    (setf (basic-block-succs block) nil)
    (setf (basic-block-preds block) nil))
  (dolist (block (ir-program-blocks prog))
    (let ((last-insn (car (last (basic-block-insns block)))))
      (when last-insn
        (dolist (arg (ir-insn-args last-insn))
          (when (and (consp arg) (eq (car arg) :label))
            (pushnew (cadr arg) (basic-block-succs block))))))
    (dolist (succ-label (basic-block-succs block))
      (let ((succ (ir-find-block prog succ-label)))
        (when succ
          (pushnew (basic-block-label block)
                   (basic-block-preds succ))))))

  ;; Phase 1: collect definitions
  (let ((def-insn (make-hash-table))       ; vreg → ir-insn
        (call-spanning (make-hash-table))) ; vreg → t
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        (when (ir-insn-dst insn)
          (unless (gethash (ir-insn-dst insn) def-insn)
            (setf (gethash (ir-insn-dst insn) def-insn) insn)))))

    ;; Phase 2: identify call-spanning vregs
    (let ((def-pos (make-hash-table))
          (last-use (make-hash-table))
          (call-positions '())
          (pos 0))
      (dolist (block (ir-program-blocks prog))
        (dolist (insn (basic-block-insns block))
          (when (ir-insn-dst insn)
            (unless (gethash (ir-insn-dst insn) def-pos)
              (setf (gethash (ir-insn-dst insn) def-pos) pos)))
          (dolist (vreg (ir-insn-all-vreg-uses insn))
            (setf (gethash vreg last-use) pos))
          (when (call-like-op-p (ir-insn-op insn))
            (push pos call-positions))
          (incf pos)))
      (setf call-positions (nreverse call-positions))
      (maphash (lambda (vreg dpos)
                 (let ((end (gethash vreg last-use)))
                   (when (and end
                              (some (lambda (cp)
                                      (and (> cp dpos) (< cp end)))
                                    call-positions))
                     (setf (gethash vreg call-spanning) t))))
               def-pos))

    ;; Phase 3: find reloadable candidates, with profitability check
    ;; Only split when callee-saved pressure is high enough that splitting
    ;; prevents spills or frees registers for caching.
    (let ((candidates (make-hash-table))  ; vreg → t
          (non-reloadable-count 0)
          (callee-saved-count 4))         ; R6-R9; adjusted below if ctx needs save
      ;; Count non-reloadable call-spanning vregs
      (maphash (lambda (vreg _)
                 (declare (ignore _))
                 (let ((insn (gethash vreg def-insn)))
                   (if (and insn (reloadable-insn-p insn call-spanning def-insn))
                       (setf (gethash vreg candidates) t)
                       (incf non-reloadable-count))))
               call-spanning)
      ;; Check if ctx needs a callee-saved register (reduces available count)
      (let ((ctx-early (ctx-loads-early-p prog)))
        (unless ctx-early
          ;; ctx-load/ctx-store present and not early → R6 reserved, only 3 callee-saved
          (when (some (lambda (block)
                        (some (lambda (insn) (member (ir-insn-op insn) '(:ctx-load :ctx-store)))
                              (basic-block-insns block)))
                      (ir-program-blocks prog))
            (setf callee-saved-count 3))))
      ;; Only split if non-reloadable count >= callee-saved capacity
      ;; (otherwise there's no callee-saved pressure to relieve)
      (when (< non-reloadable-count callee-saved-count)
        (clrhash candidates))

      ;; Phase 4: availability-aware splitting
      ;;
      ;; For each candidate V, track whether V's register value is
      ;; "available" (valid) or "dirty" (clobbered by a call) at each
      ;; block's entry.  Propagate availability forward through the CFG.
      ;;
      ;; available_at_exit[B][V] = true iff V's value is valid when B exits
      ;;   - Set true when V is defined or reloaded in B (and no call follows)
      ;;   - Set false when a call occurs in B after V's def/reload
      ;;
      ;; available_at_entry[B][V] = true iff ALL predecessors of B have
      ;;   available_at_exit[pred][V] = true
      ;;
      ;; We only reload when V is used and NOT available.
      (when (plusp (hash-table-count candidates))
        (let ((available-at-exit (make-hash-table)))  ; block-label → hash(vreg → t)

          ;; Forward pass: compute availability and do splitting
          ;; Blocks are in RPO-ish order (Whistler linearizes in dominance order)
          (dolist (block (ir-program-blocks prog))
            (let* ((label (basic-block-label block))
                   ;; Compute entry availability: a candidate is available
                   ;; if ALL predecessors have it available at exit
                   (entry-avail (make-hash-table))
                   (new-insns '())
                   (rewrites (make-hash-table))  ; vreg → fresh-vreg
                   (any-split nil))

              ;; Merge predecessor availability
              (let ((preds (basic-block-preds block)))
                (cond
                  ;; No predecessors (entry block): candidates not yet available
                  ;; (they'll become available at their def point)
                  ((null preds) nil)
                  ;; Single predecessor: inherit directly
                  ((null (cdr preds))
                   (let ((pred-avail (gethash (car preds) available-at-exit)))
                     (when pred-avail
                       (maphash (lambda (v val)
                                  (when val (setf (gethash v entry-avail) t)))
                                pred-avail))))
                  ;; Multiple predecessors: intersect (available only if ALL have it)
                  (t
                   (let ((first-avail (gethash (car preds) available-at-exit)))
                     (when first-avail
                       (maphash (lambda (v val)
                                  (when (and val
                                             (every (lambda (p)
                                                      (let ((pa (gethash p available-at-exit)))
                                                        (and pa (gethash v pa))))
                                                    (cdr preds)))
                                    (setf (gethash v entry-avail) t)))
                                first-avail))))))

              ;; Current availability state (mutable during block walk)
              (let ((avail (make-hash-table)))
                (maphash (lambda (v val)
                           (when val (setf (gethash v avail) t)))
                         entry-avail)

                ;; Walk instructions
                (dolist (insn (basic-block-insns block))
                  ;; If this instruction defines a candidate, it becomes available
                  (when (and (ir-insn-dst insn)
                             (gethash (ir-insn-dst insn) candidates))
                    (setf (gethash (ir-insn-dst insn) avail) t)
                    (remhash (ir-insn-dst insn) rewrites))

                  (cond
                    ;; Call: apply rewrites, emit, then invalidate all candidates
                    ((call-like-op-p (ir-insn-op insn))
                     (when (plusp (hash-table-count rewrites))
                       (setf (ir-insn-args insn)
                             (rewrite-args (ir-insn-args insn) rewrites)))
                     (push insn new-insns)
                     ;; Mark candidates as unavailable when their reload
                     ;; IS safe after this call.  This triggers a reload at
                     ;; the next use, shortening the live range and freeing
                     ;; callee-saved registers.  Candidates whose reload
                     ;; would be UNSAFE (call invalidates their pointer kind)
                     ;; must stay available — they need the callee-saved reg.
                     (let ((to-invalidate '()))
                       (maphash (lambda (v _) (declare (ignore _))
                                  (let ((cand-insn (gethash v def-insn)))
                                    (when (and cand-insn
                                               (reloadable-after-call-p
                                                cand-insn insn call-spanning def-insn))
                                      (push v to-invalidate))))
                                avail)
                       (dolist (v to-invalidate)
                         (remhash v avail)))
                     ;; Same for rewrites
                     (let ((rw-invalid '()))
                       (maphash (lambda (v _) (declare (ignore _))
                                  (let ((cand-insn (gethash v def-insn)))
                                    (when (and cand-insn
                                               (reloadable-after-call-p
                                                cand-insn insn call-spanning def-insn))
                                      (push v rw-invalid))))
                                rewrites)
                       (dolist (v rw-invalid)
                         (remhash v rewrites))))

                    ;; Non-call: check for uses of unavailable candidates
                    (t
                     (let ((to-reload '()))
                       (dolist (vreg (ir-insn-all-vreg-uses insn))
                         (when (and (gethash vreg candidates)
                                    (not (gethash vreg avail))
                                    (not (gethash vreg rewrites)))
                           (pushnew vreg to-reload)))

                       ;; Insert reloads
                       (dolist (orig-vreg to-reload)
                         (let* ((orig-insn (gethash orig-vreg def-insn))
                                (fresh (ir-fresh-vreg prog))
                                (reload (make-ir-insn
                                         :op (ir-insn-op orig-insn)
                                         :dst fresh
                                         :args (rewrite-args
                                                (copy-list (ir-insn-args orig-insn))
                                                rewrites)
                                         :type (ir-insn-type orig-insn))))
                           (setf (gethash orig-vreg rewrites) fresh)
                           (setf (gethash orig-vreg avail) t)
                           (push reload new-insns)
                           (setf any-split t)))

                       ;; Rewrite args and emit
                       (when (plusp (hash-table-count rewrites))
                         (setf (ir-insn-args insn)
                               (rewrite-args (ir-insn-args insn) rewrites)))
                       (push insn new-insns)))))

                ;; Record exit availability
                (let ((exit-avail (make-hash-table)))
                  ;; Candidates with rewrites: the rewritten vreg is available
                  ;; but the ORIGINAL candidate is what we track
                  (maphash (lambda (v _) (declare (ignore _))
                             (setf (gethash v exit-avail) t))
                           avail)
                  (maphash (lambda (v _) (declare (ignore _))
                             (setf (gethash v exit-avail) t))
                           rewrites)
                  (setf (gethash label available-at-exit) exit-avail)))

              ;; Fix phi args in successor blocks
              (when any-split
                (dolist (succ-label (basic-block-succs block))
                  (let ((succ (ir-find-block prog succ-label)))
                    (when succ
                      (dolist (insn (basic-block-insns succ))
                        (when (eq (ir-insn-op insn) :phi)
                          (setf (ir-insn-args insn)
                                (rewrite-phi-args (ir-insn-args insn)
                                                  label
                                                  rewrites))))))))

              (when any-split
                (setf (basic-block-insns block) (nreverse new-insns)))))))))
  prog)

(defun rewrite-args (args rewrites)
  "Rewrite vreg references in ARGS using REWRITES hash table."
  (mapcar (lambda (arg)
            (cond
              ;; Plain vreg
              ((and (integerp arg) (gethash arg rewrites))
               (gethash arg rewrites))
              ;; Phi operand: (vreg (:label L))
              ((and (consp arg) (integerp (first arg))
                    (gethash (first arg) rewrites))
               (cons (gethash (first arg) rewrites) (rest arg)))
              (t arg)))
          args))

(defun rewrite-phi-args (args from-label rewrites)
  "Rewrite phi args that arrive from FROM-LABEL using REWRITES."
  (mapcar (lambda (arg)
            (if (and (consp arg)
                     (integerp (first arg))
                     (consp (second arg))
                     (eq (car (second arg)) :label)
                     (eq (cadr (second arg)) from-label)
                     (gethash (first arg) rewrites))
                (cons (gethash (first arg) rewrites) (rest arg))
                arg))
          args))

;;; ========== Byte-swap comparison folding ==========
;;;
;;; When a bswap result is compared against a constant, fold the swap
;;; into the constant and compare against the raw (unswapped) value:
;;;   %x = load u16 ptr off
;;;   %y = bswap16 %x
;;;   br-cond (jeq %y (:imm 9999)) → br-cond (jeq %x (:imm 0x0F27))
;;; The dead bswap is then removed by DCE.

(defun bswap16-const (n)
  "Byte-swap a 16-bit constant."
  (logior (ash (logand n #xff) 8)
          (logand (ash n -8) #xff)))

(defun bswap32-const (n)
  "Byte-swap a 32-bit constant."
  (logior (ash (logand n #xff) 24)
          (ash (logand (ash n -8) #xff) 16)
          (ash (logand (ash n -16) #xff) 8)
          (logand (ash n -24) #xff)))

(defun try-fold-bswap-operand (args operand-idx other-idx defs const-vals)
  "If args[operand-idx] is a bswap result and args[other-idx] is a constant,
   fold the swap into the constant. Returns T if folded."
  (let* ((operand (nth operand-idx args))
         (other (nth other-idx args)))
    (when (and (integerp operand) (gethash operand defs))
      (let* ((def (gethash operand defs))
             (op (ir-insn-op def)))
        (when (member op '(:bswap16 :bswap32 :bswap64))
          (let ((const-val (cond
                             ((and (consp other) (eq (car other) :imm))
                              (second other))
                             ((and (integerp other) (gethash other const-vals))
                              (gethash other const-vals))
                             (t nil))))
            (when const-val
              (let ((swapped (ecase op
                               (:bswap16 (bswap16-const const-val))
                               (:bswap32 (bswap32-const const-val))
                               (:bswap64 const-val)))
                    (pre-bswap (first (ir-insn-args def))))
                (setf (nth operand-idx args) pre-bswap)
                (setf (nth other-idx args) `(:imm ,swapped))
                t))))))))

(defun fold-bswap-comparisons (prog)
  "Fold byte-swap operations into comparison constants."
  (let ((defs (make-hash-table))
        (const-vals (make-hash-table))
        (changed nil))
    ;; Build def map and constant map
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        (when (ir-insn-dst insn)
          (setf (gethash (ir-insn-dst insn) defs) insn))
        (when (and (eq (ir-insn-op insn) :mov)
                   (ir-insn-dst insn))
          (let ((a (first (ir-insn-args insn))))
            (when (and (consp a) (eq (car a) :imm))
              (setf (gethash (ir-insn-dst insn) const-vals)
                    (second a)))))))
    ;; Scan for comparisons with bswap operands
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        (when (member (ir-insn-op insn) '(:br-cond :cmp))
          (let ((args (ir-insn-args insn)))
            ;; args = ((:cmp OP) lhs rhs ...) — lhs is index 1, rhs is index 2
            (when (or (try-fold-bswap-operand args 1 2 defs const-vals)
                      (try-fold-bswap-operand args 2 1 defs const-vals))
              (setf changed t))))))
    ;; Run DCE to clean up dead bswap instructions
    (when changed
      (dead-code-elimination prog))
    prog))

;;; ========== CFG simplification ==========
;;;
;;; Generic control-flow graph simplification: fold constant branches,
;;; merge jump-only blocks, merge linear chains. Unlocks more DCE and
;;; eliminates phis that constant/copy propagation cannot reach.

(defun compute-cfg-edges (prog)
  "Recompute basic-block succs/preds from branch instructions."
  (dolist (block (ir-program-blocks prog))
    (setf (basic-block-succs block) nil)
    (setf (basic-block-preds block) nil))
  (dolist (block (ir-program-blocks prog))
    (let ((last-insn (car (last (basic-block-insns block)))))
      (when last-insn
        (dolist (arg (ir-insn-args last-insn))
          (when (and (consp arg) (eq (car arg) :label))
            (pushnew (cadr arg) (basic-block-succs block))))))
    (dolist (succ-label (basic-block-succs block))
      (let ((succ (ir-find-block prog succ-label)))
        (when succ
          (pushnew (basic-block-label block)
                   (basic-block-preds succ)))))))

(defun evaluate-cmp (op lhs rhs)
  "Evaluate BPF comparison OP on integer values LHS and RHS."
  (let ((sl (if (logbitp 63 lhs) (- lhs (ash 1 64)) lhs))
        (sr (if (logbitp 63 rhs) (- rhs (ash 1 64)) rhs)))
    (ecase op
      (:jeq  (= lhs rhs))
      (:jne  (/= lhs rhs))
      (:jgt  (> lhs rhs))
      (:jge  (>= lhs rhs))
      (:jlt  (< lhs rhs))
      (:jle  (<= lhs rhs))
      (:jsgt (> sl sr))
      (:jsge (>= sl sr))
      (:jslt (< sl sr))
      (:jsle (<= sl sr)))))

(defun resolve-const (val const-map)
  "If VAL is (:imm N), return N. If VAL is a vreg in CONST-MAP, return its value. Else nil."
  (cond
    ((and (consp val) (eq (car val) :imm)) (second val))
    ((and (integerp val) (gethash val const-map)) (gethash val const-map))
    (t nil)))

(defun simplify-cfg (prog)
  "Simplify CFG: fold constant branches, merge jump-only blocks, merge linear chains."
  (let ((const-map (make-hash-table)))
    (let ((changed t)
          (any-change nil))
      (loop while changed do
        (setf changed nil)

        ;; Rebuild const-map each iteration (blocks may have changed)
        (clrhash const-map)
        (dolist (block (ir-program-blocks prog))
          (dolist (insn (basic-block-insns block))
            (when (and (eq (ir-insn-op insn) :mov)
                       (ir-insn-dst insn)
                       (let ((arg (first (ir-insn-args insn))))
                         (and (consp arg) (eq (car arg) :imm))))
              (setf (gethash (ir-insn-dst insn) const-map)
                    (second (first (ir-insn-args insn)))))))

        (compute-cfg-edges prog)

        ;; Sub-pass A: Fold constant branches
        (dolist (block (ir-program-blocks prog))
          (let ((term (car (last (basic-block-insns block)))))
            (when (and term (eq (ir-insn-op term) :br-cond))
              (let* ((args (ir-insn-args term))
                     (cmp-op (second (first args)))
                     (lhs-val (resolve-const (second args) const-map))
                     (rhs-val (resolve-const (third args) const-map))
                     (then-label (fourth args))
                     (else-label (fifth args)))
                (when (and lhs-val rhs-val cmp-op then-label else-label)
                  (let ((target (if (evaluate-cmp cmp-op lhs-val rhs-val)
                                    then-label else-label)))
                    (setf (ir-insn-op term) :br)
                    (setf (ir-insn-args term) (list target))
                    (setf changed t)))))))

        ;; Sub-pass B: Merge jump-only blocks
        ;; A block with only a :br (no other instructions) can be bypassed
        (dolist (block (ir-program-blocks prog))
          (let ((insns (basic-block-insns block)))
            (when (and (= 1 (length insns))
                       (eq (ir-insn-op (first insns)) :br)
                       ;; Don't remove entry block
                       (not (eq (basic-block-label block)
                                (ir-program-entry prog))))
              (let* ((target-label (second (first (ir-insn-args (first insns)))))
                     (target-block (ir-find-block prog target-label))
                     (block-label (basic-block-label block)))
                (when target-block
                  ;; Redirect all predecessors to target
                  (dolist (pred-label (basic-block-preds block))
                    (let ((pred (ir-find-block prog pred-label)))
                      (when pred
                        (let ((pred-term (car (last (basic-block-insns pred)))))
                          (when pred-term
                            (setf (ir-insn-args pred-term)
                                  (mapcar (lambda (arg)
                                            (if (and (consp arg) (eq (car arg) :label)
                                                     (eq (second arg) block-label))
                                                (list :label target-label)
                                                arg))
                                          (ir-insn-args pred-term))))))))
                  ;; Update PHIs in target: replace (:label block) with pred labels
                  (dolist (insn (basic-block-insns target-block))
                    (when (eq (ir-insn-op insn) :phi)
                      (let ((new-args '()))
                        (dolist (phi-arg (ir-insn-args insn))
                          (if (and (consp phi-arg)
                                   (consp (second phi-arg))
                                   (eq (car (second phi-arg)) :label)
                                   (eq (second (second phi-arg)) block-label))
                              ;; Expand to one entry per predecessor
                              (dolist (pred-label (basic-block-preds block))
                                (push (list (first phi-arg) (list :label pred-label))
                                      new-args))
                              (push phi-arg new-args)))
                        (setf (ir-insn-args insn) (nreverse new-args)))))
                  (setf changed t))))))

        ;; Sub-pass C: Merge linear chains
        ;; If A's only successor is B (via :br), and B's only predecessor is A
        (compute-cfg-edges prog)
        (dolist (block (ir-program-blocks prog))
          (when (and (= 1 (length (basic-block-succs block)))
                     (let ((term (car (last (basic-block-insns block)))))
                       (and term (eq (ir-insn-op term) :br))))
            (let* ((succ-label (first (basic-block-succs block)))
                   (succ (ir-find-block prog succ-label)))
              (when (and succ
                         (= 1 (length (basic-block-preds succ)))
                         ;; Don't merge entry into nothing
                         (not (eq succ block)))
                ;; Build substitution map from trivial PHIs
                (let ((subst-map (make-hash-table)))
                  (dolist (insn (basic-block-insns succ))
                    (when (and (eq (ir-insn-op insn) :phi)
                               (= 1 (length (ir-insn-args insn))))
                      (let ((incoming-vreg (first (first (ir-insn-args insn)))))
                        (setf (gethash (ir-insn-dst insn) subst-map) incoming-vreg))))
                  ;; Remove A's terminator :br
                  (setf (basic-block-insns block)
                        (butlast (basic-block-insns block)))
                  ;; Append B's non-phi instructions to A, substituting PHI values
                  (dolist (insn (basic-block-insns succ))
                    (unless (eq (ir-insn-op insn) :phi)
                      (when (> (hash-table-count subst-map) 0)
                        (setf (ir-insn-args insn)
                              (subst-vreg-args (ir-insn-args insn) subst-map))
                        (when (and (ir-insn-dst insn)
                                   (gethash (ir-insn-dst insn) subst-map))
                          ;; Should not happen but be safe
                          (remhash (ir-insn-dst insn) subst-map)))
                      (setf (basic-block-insns block)
                            (append (basic-block-insns block) (list insn)))))
                  ;; Apply PHI substitutions across all blocks
                  (when (> (hash-table-count subst-map) 0)
                    (dolist (b (ir-program-blocks prog))
                      (dolist (insn (basic-block-insns b))
                        (setf (ir-insn-args insn)
                              (subst-vreg-args (ir-insn-args insn) subst-map)))))
                  ;; Remove B from program
                  (setf (ir-program-blocks prog)
                        (remove succ (ir-program-blocks prog)))
                  (setf changed t))))))

        ;; Sub-pass D: Remove unreachable blocks
        (when changed
          (eliminate-unreachable-blocks prog)
          (setf any-change t)))

      (when any-change
        (dead-code-elimination prog))))
  prog)

;;; ========== Common subexpression elimination ==========
;;;
;;; Intra-block CSE: eliminate redundant pure computations by replacing
;;; duplicate instructions with references to the first occurrence.

(defun cse-pure-op-p (op)
  "Is OP a pure operation eligible for CSE?"
  (member op '(:mov :add :sub :mul :div :mod
               :and :or :xor :lsh :rsh :arsh :neg
               :bswap16 :bswap32 :bswap64 :cast)))

(defun cse-memory-op-p (op)
  "Is OP a memory-reading operation that can be CSE'd but must be
   invalidated on stores/calls?"
  (member op '(:load :ctx-load)))

(defun cse-key (insn)
  "Return a CSE key for INSN, or NIL if not CSE-able."
  (let ((op (ir-insn-op insn)))
    (when (or (cse-pure-op-p op) (cse-memory-op-p op))
      (list* op (ir-insn-type insn) (ir-insn-args insn)))))

(defun eliminate-common-subexpressions (prog)
  "Eliminate redundant pure computations within basic blocks."
  (let ((subst-map (make-hash-table))
        (any-change nil))
    (dolist (block (ir-program-blocks prog))
      (let ((table (make-hash-table :test #'equal))
            (new-insns '()))
        (dolist (insn (basic-block-insns block))
          (let ((key (cse-key insn)))
            (cond
              ;; CSE-able instruction with a known equivalent
              ((and key (ir-insn-dst insn) (gethash key table))
               (setf (gethash (ir-insn-dst insn) subst-map) (gethash key table))
               (setf any-change t))
              ;; CSE-able instruction, first occurrence
              ((and key (ir-insn-dst insn))
               (setf (gethash key table) (ir-insn-dst insn))
               (push insn new-insns))
              (t
               ;; Side-effect or call-like → invalidate memory CSE entries
               (when (or (ir-insn-side-effect-p insn) (call-like-op-p (ir-insn-op insn)))
                 ;; Remove memory-sensitive entries from the table
                 (let ((to-remove '()))
                   (maphash (lambda (k v)
                              (declare (ignore v))
                              (when (cse-memory-op-p (car k))
                                (push k to-remove)))
                            table)
                   (dolist (k to-remove)
                     (remhash k table))))
               (push insn new-insns)))))
        (setf (basic-block-insns block) (nreverse new-insns))))
    ;; Apply substitutions globally
    (when any-change
      (dolist (block (ir-program-blocks prog))
        (dolist (insn (basic-block-insns block))
          (setf (ir-insn-args insn)
                (subst-vreg-args (ir-insn-args insn) subst-map))))
      (dead-code-elimination prog)))
  prog)

;;; ========== Store-to-load forwarding ==========
;;;
;;; Intra-block: when a store to (ptr, offset, type) is followed by a load
;;; from the same location with the same type and no intervening aliasing
;;; store or call, replace the load with the stored value.

(defun forward-stores-to-loads (prog)
  "Forward stored values to subsequent loads from the same location."
  (let ((any-change nil))
    (dolist (block (ir-program-blocks prog))
      ;; pending: (ptr-vreg . offset) → (val-vreg . type-kw)
      (let ((pending (make-hash-table :test #'equal)))
        (dolist (insn (basic-block-insns block))
          (let ((op (ir-insn-op insn)))
            (cond
              ;; Store: record and invalidate same-ptr entries
              ((eq op :store)
               (let* ((args (ir-insn-args insn))
                      (ptr (first args))
                      (off (and (consp (second args)) (eq (car (second args)) :imm)
                                (second (second args))))
                      (val (third args))
                      (type-arg (fourth args))
                      (type-kw (and (consp type-arg) (eq (car type-arg) :type)
                                    (second type-arg))))
                 (when (and (integerp ptr) off (integerp val) type-kw)
                   ;; Invalidate all entries for this ptr
                   (let ((to-remove '()))
                     (maphash (lambda (k v)
                                (declare (ignore v))
                                (when (eql (car k) ptr)
                                  (push k to-remove)))
                              pending)
                     (dolist (k to-remove)
                       (remhash k pending)))
                   ;; Record this store
                   (setf (gethash (cons ptr off) pending) (cons val type-kw)))))

              ;; Load: check for forwarding opportunity
              ((eq op :load)
               (let* ((args (ir-insn-args insn))
                      (ptr (first args))
                      (off (and (consp (second args)) (eq (car (second args)) :imm)
                                (second (second args))))
                      (type-arg (third args))
                      (type-kw (and (consp type-arg) (eq (car type-arg) :type)
                                    (second type-arg))))
                 (when (and (integerp ptr) off type-kw)
                   (let ((entry (gethash (cons ptr off) pending)))
                     (when (and entry
                                (eq type-kw (cdr entry)))
                       ;; Forward: replace load with mov from stored value
                       (setf (ir-insn-op insn) :mov)
                       (setf (ir-insn-args insn) (list (car entry)))
                       (setf any-change t))))))

              ;; Call-like ops: invalidate all pending stores
              ((call-like-op-p op)
               (clrhash pending))

              ;; Atomic-add: invalidate entries for this ptr
              ((eq op :atomic-add)
               (let ((ptr (first (ir-insn-args insn))))
                 (when (integerp ptr)
                   (let ((to-remove '()))
                     (maphash (lambda (k v)
                                (declare (ignore v))
                                (when (eql (car k) ptr)
                                  (push k to-remove)))
                              pending)
                     (dolist (k to-remove)
                       (remhash k pending)))))))))))
    (when any-change
      (dead-code-elimination prog)))
  prog)

;;; ========== Loop-invariant code motion ==========
;;;
;;; Detect natural loops, identify loop-invariant instructions, and hoist
;;; them to the loop preheader. This targets the dotimes lowering pattern
;;; (src/lower.lisp:840) and any similar CFG loops with back-edges.

(defun find-natural-loops (prog dom-map)
  "Find natural loops in PROG. Returns a list of plists:
   (:header LABEL :blocks (labels...) :preheader LABEL)."
  ;; Collect back-edges: (B → H) where H dominates B
  (let ((back-edges (make-hash-table)))  ; header → list of back-edge sources
    (dolist (block (ir-program-blocks prog))
      (dolist (succ-label (basic-block-succs block))
        (when (dominates-p dom-map succ-label (basic-block-label block))
          (push (basic-block-label block) (gethash succ-label back-edges)))))

    ;; Build a loop for each header with back-edges
    (let ((loops '()))
      (maphash
       (lambda (header sources)
         ;; Compute loop body via reverse DFS from back-edge sources to header
         (let ((body (make-hash-table)))
           (setf (gethash header body) t)
           (let ((worklist (copy-list sources)))
             (dolist (s sources) (setf (gethash s body) t))
             (loop while worklist do
               (let ((n (pop worklist)))
                 (dolist (pred-label (basic-block-preds
                                      (ir-find-block prog n)))
                   (unless (gethash pred-label body)
                     (setf (gethash pred-label body) t)
                     (push pred-label worklist))))))
           ;; Find preheader: unique predecessor of header NOT in loop
           (let ((header-block (ir-find-block prog header))
                 (preheader nil))
             (dolist (pred-label (basic-block-preds header-block))
               (unless (gethash pred-label body)
                 (if preheader
                     (setf preheader :multiple)  ; more than one non-loop pred
                     (setf preheader pred-label))))
             ;; Only process loops with a unique preheader
             (when (and preheader (not (eq preheader :multiple)))
               (let ((block-labels '()))
                 (maphash (lambda (k v) (declare (ignore v)) (push k block-labels)) body)
                 (push (list :header header :blocks block-labels :preheader preheader)
                       loops))))))
       back-edges)
      loops)))

(defun licm-hoistable-p (insn)
  "Can this instruction type be hoisted out of a loop?"
  (let ((op (ir-insn-op insn)))
    (and (ir-insn-dst insn)                 ; must produce a value
         (not (ir-insn-side-effect-p insn))
         (not (call-like-op-p op))
         (not (eq op :phi))
         ;; Whitelist of hoistable ops
         (member op '(:mov :add :sub :mul :div :mod
                      :and :or :xor :lsh :rsh :arsh :neg
                      :bswap16 :bswap32 :bswap64 :cast
                      :ctx-load :map-fd)))))

(defun find-loop-invariant-insns (prog loop-info)
  "Find instructions in LOOP-INFO that are loop-invariant.
   Returns an ordered list of ir-insn objects safe to hoist."
  (let* ((loop-blocks (getf loop-info :blocks))
         (loop-block-set (make-hash-table))
         (loop-defs (make-hash-table))    ; vreg → t if defined in loop
         (invariant (make-hash-table :test #'eq))  ; insn → t
         ;; Check if any call in the loop invalidates pointers
         (has-invalidating-call nil))

    ;; Build loop block set
    (dolist (lbl loop-blocks) (setf (gethash lbl loop-block-set) t))

    ;; Collect all defs in loop and check for invalidating calls
    (dolist (lbl loop-blocks)
      (let ((block (ir-find-block prog lbl)))
        (when block
          (dolist (insn (basic-block-insns block))
            (when (ir-insn-dst insn)
              (setf (gethash (ir-insn-dst insn) loop-defs) t))
            (when (and (call-like-op-p (ir-insn-op insn))
                       (or (helper-invalidates-p insn :invalidates-packet-ptrs)
                           (helper-invalidates-p insn :invalidates-map-value-ptrs)))
              (setf has-invalidating-call t))))))

    ;; Fixed-point: mark invariant instructions
    (let ((changed t))
      (loop while changed do
        (setf changed nil)
        (dolist (lbl loop-blocks)
          (let ((block (ir-find-block prog lbl)))
            (when block
              (dolist (insn (basic-block-insns block))
                (when (and (not (gethash insn invariant))
                           (licm-hoistable-p insn)
                           ;; Don't hoist ctx-load if calls invalidate pointers
                           (not (and (eq (ir-insn-op insn) :ctx-load)
                                     has-invalidating-call)))
                  ;; Check all vreg operands are defined outside loop or invariant
                  (let ((all-ok t))
                    (dolist (arg (ir-insn-args insn))
                      (when (and (integerp arg)           ; vreg reference
                                 (gethash arg loop-defs)  ; defined in loop
                                 ;; Check if defined by an invariant insn
                                 (not (let ((def-ok nil))
                                        (dolist (lbl2 loop-blocks)
                                          (let ((b2 (ir-find-block prog lbl2)))
                                            (when b2
                                              (dolist (i2 (basic-block-insns b2))
                                                (when (and (eql (ir-insn-dst i2) arg)
                                                           (gethash i2 invariant))
                                                  (setf def-ok t))))))
                                        def-ok)))
                        (setf all-ok nil)))
                    (when all-ok
                      (setf (gethash insn invariant) t)
                      (setf changed t))))))))))

    ;; Collect invariant insns in program order (preserves data deps)
    (let ((result '()))
      (dolist (lbl loop-blocks)
        (let ((block (ir-find-block prog lbl)))
          (when block
            (dolist (insn (basic-block-insns block))
              (when (gethash insn invariant)
                (push insn result))))))
      (nreverse result))))

(defun hoist-to-preheader (prog preheader-label insns-to-hoist)
  "Move INSNS-TO-HOIST into the preheader block, just before its terminator."
  (let ((preheader (ir-find-block prog preheader-label)))
    (when (and preheader insns-to-hoist)
      ;; Remove hoisted instructions from their original blocks
      (let ((hoist-set (make-hash-table :test #'eq)))
        (dolist (insn insns-to-hoist) (setf (gethash insn hoist-set) t))
        (dolist (block (ir-program-blocks prog))
          (setf (basic-block-insns block)
                (remove-if (lambda (i) (gethash i hoist-set))
                           (basic-block-insns block)))))
      ;; Insert before the terminator of the preheader
      (let ((insns (basic-block-insns preheader)))
        (if (null insns)
            (setf (basic-block-insns preheader) (copy-list insns-to-hoist))
            (let ((before-term (butlast insns))
                  (term (last insns)))
              (setf (basic-block-insns preheader)
                    (append before-term insns-to-hoist term))))))))

(defun loop-invariant-code-motion (prog)
  "Hoist loop-invariant instructions to loop preheaders."
  (compute-cfg-edges prog)
  (let ((dom-map (compute-dominators prog)))
    (let ((loops (find-natural-loops prog dom-map)))
      (dolist (loop-info loops)
        (let ((invariants (find-loop-invariant-insns prog loop-info)))
          (when invariants
            (hoist-to-preheader prog (getf loop-info :preheader) invariants))))))
  prog)

;;; ========== Trivial phi elimination ==========
;;;
;;; After CFG simplification removes edges and merges blocks, some PHI nodes
;;; become trivial: all inputs are the same vreg, or only one predecessor
;;; remains. Replace them with a simple substitution.

(defun eliminate-trivial-phis (prog)
  "Replace trivial PHI nodes (all inputs same, or single predecessor) with substitutions."
  (let ((subst-map (make-hash-table))
        (any-change nil))
    ;; Find trivial phis
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        (when (and (eq (ir-insn-op insn) :phi) (ir-insn-dst insn))
          (let ((args (ir-insn-args insn)))
            (when args
              ;; Extract the vreg from each phi arg: (vreg (:label from))
              (let* ((first-vreg (first (first args)))
                     (all-same (every (lambda (a) (eql (first a) first-vreg)) (rest args))))
                (when (or all-same (= 1 (length args)))
                  ;; All inputs are the same vreg — phi is trivial
                  (setf (gethash (ir-insn-dst insn) subst-map) first-vreg)
                  (setf any-change t))))))))
    ;; Apply substitutions and remove trivial phis
    (when any-change
      ;; Resolve chains: if A→B and B→C, resolve A→C
      (let ((changed t))
        (loop while changed do
          (setf changed nil)
          (maphash (lambda (k v)
                     (let ((target (gethash v subst-map)))
                       (when (and target (not (eql target v)))
                         (setf (gethash k subst-map) target)
                         (setf changed t))))
                   subst-map)))
      ;; Substitute all uses
      (dolist (block (ir-program-blocks prog))
        (dolist (insn (basic-block-insns block))
          (setf (ir-insn-args insn)
                (subst-vreg-args (ir-insn-args insn) subst-map))))
      ;; Remove the trivial phi instructions
      (dolist (block (ir-program-blocks prog))
        (setf (basic-block-insns block)
              (remove-if (lambda (insn)
                           (and (eq (ir-insn-op insn) :phi)
                                (ir-insn-dst insn)
                                (gethash (ir-insn-dst insn) subst-map)))
                         (basic-block-insns block)))))
  prog))

;;; ========== Redundant branch cleanup ==========
;;;
;;; After optimizations, br-cond may have both targets equal, or br may
;;; jump to the immediately next block. Clean these up so DCE can remove
;;; dead comparison operands.

(defun cleanup-redundant-branches (prog)
  "Replace br-cond with identical targets with unconditional br."
  (let ((any-change nil))
    (dolist (block (ir-program-blocks prog))
      (let ((term (car (last (basic-block-insns block)))))
        (when (and term (eq (ir-insn-op term) :br-cond))
          (let* ((args (ir-insn-args term))
                 (then-label (fourth args))
                 (else-label (fifth args)))
            ;; Both targets the same → unconditional branch
            (when (equal then-label else-label)
              (setf (ir-insn-op term) :br)
              (setf (ir-insn-args term) (list then-label))
              (setf any-change t))))))
    (when any-change
      (dead-code-elimination prog)))
  prog)

;;; ========== Run all SSA optimizations ==========

(defun canonicalize-ir (prog)
  "Run cheap canonicalization passes to fixed point."
  (let ((prev-insn-count -1))
    (loop for iteration below 5  ; safety bound
          for insn-count = (loop for b in (ir-program-blocks prog)
                                 sum (length (basic-block-insns b)))
          while (/= insn-count prev-insn-count)
          do (setf prev-insn-count insn-count)
             (copy-propagation prog)
             (constant-propagation prog)
             (eliminate-trivial-phis prog)
             (simplify-cfg prog)
             (dead-code-elimination prog)))
  prog)

(defun optimize-ir (prog)
  "Run all SSA optimization passes on PROG. Returns modified prog."
  ;; Phase 1: Canonicalize to fixed point
  (canonicalize-ir prog)

  ;; Phase 2: Domain-specific folds (run once)
  (fold-bswap-comparisons prog)
  (fold-constant-offsets prog)
  (elide-tracepoint-return prog)

  ;; Phase 3: Loop and memory optimizations
  (loop-invariant-code-motion prog)
  (eliminate-common-subexpressions prog)
  (forward-stores-to-loads prog)

  ;; Phase 3b: SCCP is currently disabled.
  ;; Its PHI handling is not loop-aware enough and folds loop-header
  ;; branches incorrectly in nested loops, producing malformed CFGs.
  ;; Re-enable after fixing SCCP to reason over executable edges rather
  ;; than just executable predecessor blocks.
  ;; (sccp prog)

  ;; Phase 4: Clean up after transformations
  (dead-code-elimination prog)
  (dead-destination-elimination prog)
  (dead-store-elimination prog)

  ;; Phase 5: Cross-block fusions and rewrites
  (hoist-loads-before-calls prog)
  (phi-branch-threading prog)
  (bitmask-check-fusion prog)
  (cleanup-redundant-branches prog)

  ;; Phase 6: Final canonicalization after fusions
  (canonicalize-ir prog)

  ;; Phase 7: Backend preparation
  (narrow-alu-types prog)
  (split-live-ranges prog)
  prog)
