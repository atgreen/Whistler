;;; -*- Mode: Lisp -*-
;;;
;;; Copyright (c) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; SPDX-License-Identifier: MIT

;;; lower.lisp — Lower macro-expanded s-expressions to SSA IR
;;;
;;; Translates Whistler surface forms into SSA IR instructions with
;;; virtual registers and basic blocks.

(in-package #:whistler/ir)

;;; Lowering context

(defstruct lower-ctx
  (prog nil)          ; ir-program being built
  (block nil)         ; current basic-block
  (env '())           ; ((name type vreg) ...) variable bindings
  (maps '())          ; ((name . bpf-map) ...) map definitions
  (next-id 0))        ; instruction sequence counter

(defun ctx-emit (ctx op dst args &optional type)
  "Emit an IR instruction into the current block."
  (let ((insn (make-ir-insn :op op :dst dst :args args :type type
                            :id (lower-ctx-next-id ctx))))
    (incf (lower-ctx-next-id ctx))
    (bb-emit (lower-ctx-block ctx) insn)
    dst))

(defun ctx-fresh-vreg (ctx &optional type)
  "Allocate a fresh virtual register."
  (declare (ignore type))
  (ir-fresh-vreg (lower-ctx-prog ctx)))

(defun ctx-switch-block (ctx new-block)
  "Switch emission to a new basic block."
  (ir-add-block (lower-ctx-prog ctx) new-block)
  (setf (lower-ctx-block ctx) new-block))

(defun ctx-lookup-var (ctx name)
  "Look up variable. Returns (type . vreg) or nil."
  (let ((entry (assoc (symbol-name name) (lower-ctx-env ctx)
                      :key (lambda (x) (symbol-name x))
                      :test #'string=)))
    (when entry (cdr entry))))

(defun ctx-bind-var (ctx name type vreg)
  (push (cons name (cons type vreg)) (lower-ctx-env ctx)))

(defun ctx-update-var (ctx name new-vreg)
  "Update the vreg for an existing variable (for setf in SSA)."
  (let ((entry (assoc (symbol-name name) (lower-ctx-env ctx)
                      :key (lambda (x) (symbol-name x))
                      :test #'string=)))
    (when entry
      (setf (cddr entry) new-vreg))))

;;; Symbol comparison — delegate to whistler/compiler
(defun sym= (a b) (whistler/compiler:sym= a b))

;;; ALU / jump op mapping (returns keyword for IR)

(defun ir-alu-op (sym)
  (when (symbolp sym)
    (let ((name (symbol-name sym)))
      (cond
        ((string= name "+")     :add)
        ((string= name "-")     :sub)
        ((string= name "*")     :mul)
        ((string= name "/")     :div)
        ((string= name "MOD")   :mod)
        ((string= name "LOGIOR") :or)  ((string= name "BIT-OR")  :or)
        ((string= name "LOGAND") :and) ((string= name "BIT-AND") :and)
        ((string= name "LOGXOR") :xor) ((string= name "BIT-XOR") :xor)
        ((string= name "<<")    :lsh)  ((string= name "ASH-LEFT")  :lsh)
        ((string= name ">>")    :rsh)  ((string= name "ASH-RIGHT") :rsh)
        ((string= name ">>>")   :arsh) ((string= name "ASH-RIGHT-SIGNED") :arsh)))))

(defun ir-jmp-op (sym)
  (when (symbolp sym)
    (let ((name (symbol-name sym)))
      (cond
        ((string= name "=")    :jeq)
        ((string= name "/=")   :jne)
        ((string= name ">")    :jgt)
        ((string= name ">=")   :jge)
        ((string= name "<")    :jlt)
        ((string= name "<=")   :jle)
        ((string= name "S>")   :jsgt)
        ((string= name "S>=")  :jsge)
        ((string= name "S<")   :jslt)
        ((string= name "S<=")  :jsle)))))

(defun ir-invert-jmp (op)
  (ecase op
    (:jeq :jne) (:jne :jeq)
    (:jgt :jle) (:jge :jlt) (:jlt :jge) (:jle :jgt)
    (:jsgt :jsle) (:jsge :jslt) (:jslt :jsge) (:jsle :jsgt)))

;;; Size info
(defun ir-type-bytes (type-kw)
  (let ((name (string-upcase (string type-kw))))
    (cond
      ((or (string= name "U8")  (string= name "I8"))  1)
      ((or (string= name "U16") (string= name "I16")) 2)
      ((or (string= name "U32") (string= name "I32")) 4)
      ((or (string= name "U64") (string= name "I64")) 8)
      (t 8))))

;;; Builtin constants, helpers, and forms — from whistler/compiler (single source of truth)
(defun ir-builtin-helper-p (sym)
  "Return the helper ID if SYM names a known BPF helper, or NIL."
  (whistler/compiler:builtin-helper-p sym))

;;; ========== Main lowering entry point ==========

(defun lower-program (section license maps body)
  "Lower a Whistler program to SSA IR.
   MAPS: list of bpf-map structs.
   BODY: list of macro-expanded, constant-folded s-expressions."
  (let* ((prog (make-ir-program :section section :license license
                                :maps maps :next-vreg 0))
         (entry-label (ir-fresh-label prog "entry"))
         (entry-block (make-basic-block :label entry-label))
         (ctx (make-lower-ctx :prog prog :block entry-block)))
    (setf (ir-program-entry prog) entry-label)
    (ir-add-block prog entry-block)

    ;; Map index for map lookups
    (dolist (m maps)
      (push (cons (whistler/compiler:bpf-map-name m) m) (lower-ctx-maps ctx)))

    ;; Emit ctx save: %ctx = arg0 (R1 on entry)
    (let ((ctx-vreg (ctx-fresh-vreg ctx)))
      (ctx-emit ctx :arg0 ctx-vreg '() 'u64)
      (ctx-bind-var ctx (intern "%%CTX" (find-package '#:whistler/ir)) 'u64 ctx-vreg))

    ;; Lower body
    (let ((result nil))
      (dolist (form body)
        (setf result (lower-expr ctx form)))

      ;; Ensure terminator
      (unless (bb-terminator-p (lower-ctx-block ctx))
        (let ((zero (ctx-fresh-vreg ctx)))
          (ctx-emit ctx :mov zero (list '(:imm 0)) 'u64)
          (ctx-emit ctx :ret nil (list zero)))))

    prog))

;;; ========== Expression lowering ==========

(defun lower-expr (ctx form)
  "Lower FORM, returning the vreg holding the result (or nil for void)."
  (cond
    ((null form)
     (let ((v (ctx-fresh-vreg ctx)))
       (ctx-emit ctx :mov v (list `(:imm 0)) 'u64)
       v))

    ((integerp form)
     (let ((v (ctx-fresh-vreg ctx)))
       (ctx-emit ctx :mov v (list `(:imm ,form)) 'u64)
       v))

    ((symbolp form)
     (lower-symbol ctx form))

    ((consp form)
     (lower-form ctx form))

    (t (whistler/compiler:whistler-error
        :what (format nil "cannot compile expression: ~s" form)
        :expected "an integer, symbol, or (form ...) expression"
        :hint "strings, floats, and other CL literals are not available in BPF"))))

(defun lower-symbol (ctx sym)
  "Lower a symbol reference — variable or constant."
  (let ((const (assoc (symbol-name sym) whistler/compiler:*builtin-constants*
                      :test #'string=)))
    (cond
      (const
       (let ((v (ctx-fresh-vreg ctx)))
         (ctx-emit ctx :mov v (list `(:imm ,(cdr const))) 'u64)
         v))
      ;; CL constant
      ((and (boundp sym) (constantp sym) (integerp (symbol-value sym)))
       (let ((v (ctx-fresh-vreg ctx)))
         (ctx-emit ctx :mov v (list `(:imm ,(symbol-value sym))) 'u64)
         v))
      (t
       (let ((binding (ctx-lookup-var ctx sym)))
         (unless binding
           (let ((env-vars (remove-if (lambda (n) (search "%%" (symbol-name n)))
                                       (mapcar #'car (lower-ctx-env ctx)))))
             (whistler/compiler:whistler-error
              :what (format nil "unbound variable: ~a" sym)
              :expected "a variable bound by LET, LET*, DOTIMES, or a builtin constant"
              :hint (if env-vars
                        (format nil "variables in scope: ~{~a~^, ~}" env-vars)
                        "no variables are in scope here"))))
         (cdr binding))))))  ; return the vreg directly

;;; ========== Compound form lowering ==========

(defun lower-form (ctx form)
  (let ((head (car form))
        (args (cdr form)))
    (cond
      ((sym= head 'progn)
       (let ((result nil))
         (dolist (expr args) (setf result (lower-expr ctx expr)))
         result))

      ((sym= head 'let)
       (lower-let ctx (first args) (rest args)))

      ((sym= head 'let*)
       (lower-let* ctx (first args) (rest args)))

      ((sym= head 'if)
       (lower-if ctx (first args) (second args) (third args)))

      ((sym= head 'return)
       (let ((val (if args (lower-expr ctx (first args))
                      (let ((v (ctx-fresh-vreg ctx)))
                        (ctx-emit ctx :mov v (list '(:imm 0)) 'u64)
                        v))))
         (ctx-emit ctx :ret nil (list val))
         nil))

      ;; CL ash: (ash value count) — left shift if count > 0, right if < 0
      ((sym= head 'ash)
       (let ((count (second args)))
         (unless (integerp count)
           (whistler/compiler:whistler-error
            :what (format nil "non-constant shift count: ~a" count)
            :where (format nil "(ash ~a ~a)" (first args) count)
            :expected "a compile-time constant integer"
            :hint "BPF requires constant shift amounts. Use (<< val N) or (>> val N) with a literal."))
         (cond
           ((>= count 0)
            (lower-alu ctx '<< (list (first args) count)))
           (t
            (lower-alu ctx '>> (list (first args) (- count)))))))

      ((ir-alu-op head)
       (lower-alu ctx head args))

      ((ir-jmp-op head)
       (lower-cmp ctx head (first args) (second args)))

      ((sym= head 'load)
       (lower-load ctx args))

      ((sym= head 'core-load)
       (lower-core-load ctx args))

      ((sym= head 'store)
       (lower-store ctx args))

      ((sym= head 'core-store)
       (lower-core-store ctx args))

      ((sym= head 'atomic-add)
       (lower-atomic-add ctx args))

      ((sym= head 'map-lookup)
       (lower-map-lookup ctx (first args) (second args)))

      ((sym= head 'map-lookup-ptr)
       (lower-map-lookup-ptr ctx (first args) (second args)))

      ((sym= head 'map-update)
       (lower-map-update ctx (first args) (second args) (third args)
                         (or (fourth args) 0)))

      ((sym= head 'map-delete)
       (lower-map-delete ctx (first args) (second args)))

      ((sym= head 'map-update-ptr)
       (lower-map-update-ptr ctx (first args) (second args) (third args)
                             (or (fourth args) 0)))

      ((sym= head 'map-delete-ptr)
       (lower-map-delete-ptr ctx (first args) (second args)))

      ;; Ring buffer operations (first arg is map name)
      ((sym= head 'ringbuf-output)
       (lower-ringbuf-output ctx (first args) (second args) (third args) (fourth args)))

      ((sym= head 'ringbuf-reserve)
       (lower-ringbuf-reserve ctx (first args) (second args) (third args)))

      ((sym= head 'ringbuf-submit)
       (lower-ringbuf-submit ctx (first args) (second args)))

      ((sym= head 'ringbuf-discard)
       (lower-ringbuf-discard ctx (first args) (second args)))

      ((sym= head 'ctx)
       (lower-ctx-load ctx (first args) (second args)))

      ((sym= head 'ctx-load)
       (warn "ctx-load is deprecated; use (ctx TYPE OFFSET) instead")
       (lower-ctx-load ctx (first args) (second args)))

      ((sym= head 'tail-call)
       (lower-tail-call ctx (first args) (second args)))

      ((sym= head 'core-ctx-load)
       (lower-core-ctx-load ctx args))

      ((sym= head '%ctx-set)
       ;; Internal form emitted by (setf (ctx ...) ...) expansion
       (lower-ctx-store ctx (first args) (second args) (third args)))

      ((sym= head 'ctx-store)
       (warn "ctx-store is deprecated; use (setf (ctx TYPE OFFSET) VALUE) instead")
       (lower-ctx-store ctx (first args) (second args) (third args)))

      ((sym= head 'ctx-ptr)
       ;; Return the raw context pointer (R1) for passing to helpers
       (cdr (ctx-lookup-var ctx (intern "%%CTX" (find-package '#:whistler/ir)))))

      ((sym= head 'setf)
       ;; CL-style multi-pair setf: (setf place1 val1 place2 val2 ...)
       (let ((pairs args)
             (result nil))
         (loop while pairs do
           (unless (cdr pairs)
             (whistler/compiler:whistler-error
              :what "odd number of arguments to setf"
              :where (format nil "(setf ~{~s~^ ~})" args)
              :expected "(setf place value ...) with paired arguments"))
           (setf result (lower-setf ctx (first pairs) (second pairs)))
           (setf pairs (cddr pairs)))
         result))

      ((sym= head 'stack-addr)
       (lower-stack-addr ctx (first args)))

      ((sym= head 'struct-alloc)
       (lower-struct-alloc ctx (first args)))

      ((sym= head 'when)
       (lower-if ctx (first args) (cons 'progn (rest args)) nil))

      ((sym= head 'unless)
       (lower-if ctx (first args) nil (cons 'progn (rest args))))

      ((sym= head 'cond)
       (lower-cond ctx args))

      ((sym= head 'and)
       (lower-and ctx args))

      ((sym= head 'or)
       (lower-or ctx args))

      ((sym= head 'not)
       (lower-not ctx (first args)))

      ((sym= head 'log2)
       (lower-log2 ctx (first args)))

      ((sym= head 'dotimes)
       (lower-dotimes ctx (first args) (rest args)))

      ((sym= head 'cast)
       (lower-cast ctx (first args) (second args)))

      ((or (sym= head 'ntohs) (sym= head 'htons))
       (let ((v (lower-expr ctx (first args)))
             (dst (ctx-fresh-vreg ctx)))
         (ctx-emit ctx :bswap16 dst (list v) 'u16)
         dst))

      ((or (sym= head 'ntohl) (sym= head 'htonl))
       (let ((v (lower-expr ctx (first args)))
             (dst (ctx-fresh-vreg ctx)))
         (ctx-emit ctx :bswap32 dst (list v) 'u32)
         dst))

      ((or (sym= head 'ntohll) (sym= head 'htonll))
       (let ((v (lower-expr ctx (first args)))
             (dst (ctx-fresh-vreg ctx)))
         (ctx-emit ctx :bswap64 dst (list v) 'u64)
         dst))

      ;; (helper-name arg1 arg2 ...) — BPF helper call in function position
      ((ir-builtin-helper-p head)
       (lower-helper-call ctx head args))

      (t (whistler/compiler:whistler-error
          :what (format nil "unknown form: ~a" head)
          :where (format nil "(~a ...)" head)
          :expected "a Whistler builtin (let, if, when, dotimes, ...), arithmetic op (+, -, *, ...), comparison (=, >, <, ...), or BPF helper (probe-read-user, ktime-get-ns, ...)"
          :hint (if (member (symbol-name head)
                            '("FORMAT" "PRINT" "LOOP" "MAPCAR" "FUNCALL" "APPLY"
                              "CONCATENATE" "STRING" "LIST" "CONS" "MAKE-ARRAY")
                            :test #'string=)
                    (format nil "CL function ~a is not available in BPF programs" head)
                    (format nil "check spelling, or ensure the macro/form is defined before compilation")))))))

;;; ========== Let bindings ==========

(defun bpf-type-sym-p (sym) (whistler/compiler:bpf-type-p sym))

(defun infer-expr-type (form)
  "Infer BPF type from a macro-expanded s-expression.
   Returns a type symbol (u8, u16, u32, u64) or nil for default u64."
  (cond
    ((integerp form) nil)   ; default to u64 — ssa-opt narrows later
    ((symbolp form) nil)    ; variable ref — type comes from binding
    ((atom form) nil)
    (t
     (let ((head (car form)))
       (cond
         ;; (load TYPE ...) / (core-load TYPE ...)
         ((or (sym= head 'load) (sym= head 'core-load))
          (cadr form))
         ;; (ctx-load TYPE ...) / (core-ctx-load TYPE ...)
         ((or (sym= head 'ctx-load) (sym= head 'core-ctx-load))
          (cadr form))
         ;; (cast TYPE ...)
         ((sym= head 'cast) (cadr form))
         ;; Byte swap → known widths
         ((or (sym= head 'ntohs) (sym= head 'htons)) 'u16)
         ((or (sym= head 'ntohl) (sym= head 'htonl)) 'u32)
         ((or (sym= head 'ntohll) (sym= head 'htonll)) 'u64)
         ;; Helper calls with known return types
         ((sym= head 'get-prandom-u32) 'u32)
         ((sym= head 'get-smp-processor-id) 'u32)
         ;; Default — u64 is safe for everything else
         (t nil))))))

(defun parse-let-binding (binding)
  "Parse a let binding, supporting both (var type init), (var type), and (var init).
   Returns (values var type init) where type may be nil (infer) and init may be nil."
  (cond
    ;; 3-element: (var type init) — explicit type
    ((and (consp binding) (cddr binding))
     (values (first binding) (second binding) (third binding)))
    ;; 2-element: (var X) — X is either a type or an init
    ((and (consp binding) (cdr binding))
     (if (bpf-type-sym-p (second binding))
         ;; (var type) — typed, no init
         (values (first binding) (second binding) nil)
         ;; (var init) — infer type from init
         (values (first binding) (infer-expr-type (second binding)) (second binding))))
    ;; 1-element: (var) — default u64, zero init
    (t (values (first binding) nil nil))))

(defun extract-type-declarations (body)
  "Extract type declarations from the start of BODY.
   Returns (values type-alist remaining-body) where type-alist maps
   variable names to declared types: ((var . type) ...)."
  (let ((type-alist '())
        (remaining body))
    (loop while (and remaining
                     (consp (first remaining))
                     (sym= (car (first remaining)) 'declare))
          do (dolist (decl (cdr (first remaining)))
               (when (and (consp decl)
                          (sym= (car decl) 'type)
                          (>= (length decl) 3))
                 ;; (type TYPE var1 var2 ...)
                 (let ((type (second decl)))
                   (dolist (var (cddr decl))
                     (push (cons var type) type-alist)))))
             (setf remaining (rest remaining)))
    (values type-alist remaining)))

(defun lower-one-binding (ctx var parsed-type declared-type init)
  "Lower a single let/let* binding. Returns (var type vreg)."
  (let ((type (or parsed-type declared-type 'u64)))
    (if init
        (if (integerp init)
            (let ((vreg (ctx-fresh-vreg ctx)))
              (ctx-emit ctx :mov vreg (list `(:imm ,init)) type)
              (list var type vreg))
            (let ((vreg (lower-expr ctx init)))
              (list var type vreg)))
        (let ((vreg (ctx-fresh-vreg ctx)))
          (ctx-emit ctx :mov vreg (list '(:imm 0)) type)
          (list var type vreg)))))

(defun validate-let-bindings (bindings form-name)
  "Check let/let* bindings for common mistakes."
  (when (and bindings (symbolp (first bindings)))
    (whistler/compiler:whistler-error
     :what (format nil "malformed ~a bindings" form-name)
     :where (format nil "(~a (~{~s~^ ~}) ...)" form-name bindings)
     :expected (format nil "(~a ((var init) ...) body...)" form-name)
     :hint (format nil "note the double parentheses: (~a ((~a ...)) ...)"
                   form-name (first bindings))))
  (dolist (b bindings)
    (when (and (consp b) (not (symbolp (first b))))
      (whistler/compiler:whistler-error
       :what (format nil "invalid variable name in ~a binding: ~s" form-name (first b))
       :where (format nil "~s" b)
       :expected "a symbol as the variable name"))))

(defun lower-let (ctx bindings body)
  "Lower CL-style let: evaluate all inits before binding any variables."
  (validate-let-bindings bindings "let")
  (multiple-value-bind (type-decls actual-body) (extract-type-declarations body)
    (let ((saved-env (lower-ctx-env ctx)))
      ;; Phase 1: lower all init expressions in the CURRENT environment
      (let ((lowered (mapcar (lambda (binding)
                               (multiple-value-bind (var parsed-type init)
                                   (parse-let-binding binding)
                                 (let ((declared (cdr (assoc (symbol-name var) type-decls
                                                             :key #'symbol-name
                                                             :test #'string=))))
                                   (lower-one-binding ctx var parsed-type declared init))))
                             bindings)))
        ;; Phase 2: bind all variables at once
        (dolist (entry lowered)
          (destructuring-bind (var type vreg) entry
            (ctx-bind-var ctx var type vreg))))
      (let ((result nil))
        (dolist (form actual-body)
          (setf result (lower-expr ctx form)))
        (setf (lower-ctx-env ctx) saved-env)
        result))))

(defun lower-let* (ctx bindings body)
  "Lower CL-style let*: evaluate and bind each variable sequentially."
  (validate-let-bindings bindings "let*")
  (multiple-value-bind (type-decls actual-body) (extract-type-declarations body)
    (let ((saved-env (lower-ctx-env ctx)))
      (dolist (binding bindings)
        (multiple-value-bind (var parsed-type init) (parse-let-binding binding)
          (let ((declared (cdr (assoc (symbol-name var) type-decls
                                       :key #'symbol-name :test #'string=))))
            (destructuring-bind (v type vreg)
                (lower-one-binding ctx var parsed-type declared init)
              (ctx-bind-var ctx v type vreg)))))
      (let ((result nil))
        (dolist (form actual-body)
          (setf result (lower-expr ctx form)))
        (setf (lower-ctx-env ctx) saved-env)
        result))))

;;; ========== Conditional branch emission ==========

(defun emit-test-branch (ctx test then-label else-label)
  "Emit branch(es) for TEST, jumping to THEN-LABEL when true, ELSE-LABEL
   when false.  Short-circuits (or ...) and (and ...) into multi-way
   branches instead of materializing a boolean."
  (cond
    ;; (or a b ...) — jump to then if ANY condition is true
    ((and (consp test) (sym= (car test) 'or))
     (let ((clauses (cdr test)))
       (if (null clauses)
           ;; (or) is false
           (ctx-emit ctx :br nil (list `(:label ,else-label)))
           (loop for (clause . rest) on clauses
                 do (if rest
                        ;; Not the last clause: true → then, false → try next
                        (let ((next-label (ir-fresh-label (lower-ctx-prog ctx) "or_next")))
                          (emit-test-branch ctx clause then-label next-label)
                          (let ((next-block (make-basic-block :label next-label)))
                            (ctx-switch-block ctx next-block)))
                        ;; Last clause: true → then, false → else
                        (emit-test-branch ctx clause then-label else-label))))))

    ;; (and a b ...) — jump to else if ANY condition is false
    ((and (consp test) (sym= (car test) 'and))
     (let ((clauses (cdr test)))
       (if (null clauses)
           ;; (and) is true
           (ctx-emit ctx :br nil (list `(:label ,then-label)))
           (loop for (clause . rest) on clauses
                 do (if rest
                        ;; Not the last clause: true → try next, false → else
                        (let ((next-label (ir-fresh-label (lower-ctx-prog ctx) "and_next")))
                          (emit-test-branch ctx clause next-label else-label)
                          (let ((next-block (make-basic-block :label next-label)))
                            (ctx-switch-block ctx next-block)))
                        ;; Last clause: true → then, false → else
                        (emit-test-branch ctx clause then-label else-label))))))

    ;; (not x) — swap then/else
    ((and (consp test) (sym= (car test) 'not))
     (emit-test-branch ctx (second test) else-label then-label))

    ;; Direct comparison: (= x y), (/= x y), etc.
    ((and (consp test) (ir-jmp-op (car test)))
     (let* ((jmp-op (ir-jmp-op (car test)))
            (lhs (lower-expr ctx (second test)))
            (rhs (lower-expr ctx (third test))))
       (ctx-emit ctx :br-cond nil
                 (list `(:cmp ,jmp-op) lhs rhs
                       `(:label ,then-label) `(:label ,else-label)))))

    ;; General expression: evaluate and branch on non-zero
    (t
     (let ((test-vreg (lower-expr ctx test)))
       (ctx-emit ctx :br-cond nil
                 (list '(:cmp :jne) test-vreg `(:imm 0)
                       `(:label ,then-label) `(:label ,else-label)))))))

;;; ========== If ==========

(defun lower-if (ctx test then-form else-form)
  (let* ((prog (lower-ctx-prog ctx))
         (then-label (ir-fresh-label prog "then"))
         (else-label (ir-fresh-label prog "else"))
         (join-label (ir-fresh-label prog "join"))
         ;; Snapshot env before branches to detect setf'd variables
         (pre-env (mapcar (lambda (e) (list (car e) (cadr e) (cddr e)))
                          (lower-ctx-env ctx))))

    ;; Emit conditional branch — short-circuit or/and when used as a test
    (emit-test-branch ctx test then-label else-label)

    ;; Then block
    (let ((then-block (make-basic-block :label then-label)))
      (ctx-switch-block ctx then-block)
      (let ((then-val (when then-form (lower-expr ctx then-form))))
        (let ((then-exit-block (basic-block-label (lower-ctx-block ctx)))
              (then-needs-br (not (bb-terminator-p (lower-ctx-block ctx))))
              ;; Capture env after then-branch
              (then-env (mapcar (lambda (e) (list (car e) (cadr e) (cddr e)))
                                (lower-ctx-env ctx))))

          ;; Restore env to pre-branch state for else
          (dolist (pre pre-env)
            (let ((entry (assoc (first pre) (lower-ctx-env ctx)
                                :test (lambda (a b)
                                        (string= (symbol-name a)
                                                 (symbol-name b))))))
              (when entry (setf (cddr entry) (third pre)))))

          ;; Else block
          (let ((else-block (make-basic-block :label else-label)))
            (ctx-switch-block ctx else-block)
            (let ((else-val (when else-form (lower-expr ctx else-form))))
              (let ((else-exit-block (basic-block-label (lower-ctx-block ctx)))
                    (else-needs-br (not (bb-terminator-p (lower-ctx-block ctx))))
                    (else-env (mapcar (lambda (e) (list (car e) (cadr e) (cddr e)))
                                     (lower-ctx-env ctx))))

                (cond
                  ((and (not then-needs-br) (not else-needs-br))
                   nil)
                  (t
                   (when then-needs-br
                     (let ((tb (ir-find-block prog then-exit-block)))
                       (bb-emit tb (make-ir-insn :op :br :args (list `(:label ,join-label))))))
                   (when else-needs-br
                     (ctx-emit ctx :br nil (list `(:label ,join-label))))

                   (let ((join-block (make-basic-block :label join-label)))
                     (ctx-switch-block ctx join-block)

                     ;; Insert phis for variables modified in either branch
                     (dolist (pre pre-env)
                       (let* ((vname (first pre))
                              (pre-vreg (third pre))
                              (then-entry (find (symbol-name vname) then-env
                                                :key (lambda (e) (symbol-name (first e)))
                                                :test #'string=))
                              (else-entry (find (symbol-name vname) else-env
                                                :key (lambda (e) (symbol-name (first e)))
                                                :test #'string=))
                              (then-vreg (when then-entry (third then-entry)))
                              (else-vreg (when else-entry (third else-entry))))
                         (when (and then-vreg else-vreg
                                    (or (not (eql then-vreg pre-vreg))
                                        (not (eql else-vreg pre-vreg))))
                           (let ((phi-vr (ctx-fresh-vreg ctx)))
                             (ctx-emit ctx :phi phi-vr
                                       (list (list (if then-needs-br then-vreg pre-vreg)
                                                   `(:label ,then-exit-block))
                                             (list (if else-needs-br else-vreg pre-vreg)
                                                   `(:label ,else-exit-block)))
                                       (second pre))
                             ;; Update env to use the merged phi
                             (let ((env-entry (assoc vname (lower-ctx-env ctx)
                                                     :test (lambda (a b)
                                                             (string= (symbol-name a)
                                                                      (symbol-name b))))))
                               (when env-entry
                                 (setf (cddr env-entry) phi-vr)))))))

                     ;; Result phi for the if-expression value
                     (if (and then-val else-val then-needs-br else-needs-br)
                         (let ((phi-vreg (ctx-fresh-vreg ctx)))
                           (ctx-emit ctx :phi phi-vreg
                                     (list (list then-val `(:label ,then-exit-block))
                                           (list else-val `(:label ,else-exit-block))))
                           phi-vreg)
                         (or then-val else-val)))))))))))))

;;; ========== ALU ==========

(defun vreg-type-in-env (ctx vreg)
  "Look up the type of a vreg by searching the environment bindings."
  (dolist (entry (lower-ctx-env ctx))
    (when (and (consp entry) (consp (cdr entry))
               (eql (cddr entry) vreg))
      (return (cadr entry))))
  ;; Check if defined by an IR instruction with a type
  (dolist (block (ir-program-blocks (lower-ctx-prog ctx)))
    (dolist (insn (basic-block-insns block))
      (when (and (ir-insn-dst insn) (eql (ir-insn-dst insn) vreg)
                 (ir-insn-type insn))
        (return-from vreg-type-in-env (ir-insn-type insn)))))
  nil)

(defun type-width (type-kw)
  "Return bit width for a type keyword, or 64 if unknown."
  (if (null type-kw) 64
      (let ((name (string-upcase (string type-kw))))
        (cond
          ((or (string= name "U8")  (string= name "I8"))  8)
          ((or (string= name "U16") (string= name "I16")) 16)
          ((or (string= name "U32") (string= name "I32")) 32)
          (t 64)))))

(defun narrowest-type (t1 t2)
  "Return the wider of two types (the result of an ALU op on both).
   If both are <= 32 bits, return u32."
  (let ((w1 (type-width t1))
        (w2 (type-width t2)))
    (if (<= (max w1 w2) 32) 'u32 'u64)))

(defun infer-alu-type (ctx ir-op lhs-vreg rhs-vreg)
  "Infer the result type of an ALU operation from its operands.
   Only narrows for ops that can't overflow their input width.
   Add/sub are kept at u64 since carry bits may exceed input width."
  (let ((t1 (vreg-type-in-env ctx lhs-vreg))
        (t2 (vreg-type-in-env ctx rhs-vreg)))
    ;; For bit ops and shifts, result width = max input width
    ;; For add/sub, result can overflow → keep u64
    (if (member ir-op '(:and :or :xor :rsh :arsh :mod))
        (narrowest-type t1 t2)
        'u64)))

(defun check-alu-constant-args (op ir-op args)
  "Check for compile-time-detectable arithmetic errors."
  ;; Division or modulo by constant zero
  (when (and (member ir-op '(:div :mod))
             (= (length args) 2)
             (let ((rhs (second args)))
               (or (eql rhs 0)
                   (and (symbolp rhs) (boundp rhs) (constantp rhs)
                        (eql (symbol-value rhs) 0)))))
    (whistler/compiler:whistler-error
     :what (format nil "~a by zero" (if (eq ir-op :div) "division" "modulo"))
     :where (format nil "(~a ~a ~a)" op (first args) (second args))
     :expected "a non-zero divisor"
     :hint "BPF division by zero causes a verifier rejection or runtime exception"))
  ;; Shift by >= 64 bits
  (when (and (member ir-op '(:lsh :rsh :arsh))
             (= (length args) 2)
             (let ((rhs (second args)))
               (or (and (integerp rhs) (>= rhs 64))
                   (and (symbolp rhs) (boundp rhs) (constantp rhs)
                        (integerp (symbol-value rhs))
                        (>= (symbol-value rhs) 64)))))
    (let ((amt (let ((rhs (second args)))
                 (if (integerp rhs) rhs (symbol-value rhs)))))
      (whistler/compiler:whistler-error
       :what (format nil "shift amount ~d >= 64 bits" amt)
       :where (format nil "(~a ~a ~a)" op (first args) (second args))
       :expected "a shift amount between 0 and 63"
       :hint "BPF operates on 64-bit registers; shifting by 64+ is undefined"))))

(defun lower-alu (ctx op args)
  (let ((ir-op (ir-alu-op op)))
    (check-alu-constant-args op ir-op args)
    (cond
      ;; Unary neg
      ((and (sym= op '-) (= (length args) 1))
       (let ((v (lower-expr ctx (first args)))
             (dst (ctx-fresh-vreg ctx)))
         (ctx-emit ctx :neg dst (list v) 'u64)
         dst))
      ;; Binary
      ((= (length args) 2)
       (let* ((lhs (lower-expr ctx (first args)))
              (rhs (lower-expr ctx (second args)))
              (dst (ctx-fresh-vreg ctx))
              (result-type (infer-alu-type ctx ir-op lhs rhs)))
         (ctx-emit ctx ir-op dst (list lhs rhs) result-type)
         dst))
      ;; N-ary: fold left
      ((> (length args) 2)
       (let ((acc (lower-expr ctx (first args))))
         (dolist (arg (rest args))
           (let* ((rhs (lower-expr ctx arg))
                  (dst (ctx-fresh-vreg ctx))
                  (result-type (infer-alu-type ctx ir-op acc rhs)))
             (ctx-emit ctx ir-op dst (list acc rhs) result-type)
             (setf acc dst)))
         acc))
      (t (whistler/compiler:whistler-error
          :what (format nil "~a requires at least 1 argument" op)
          :where (format nil "(~a)" op)
          :expected (format nil "(~a x) or (~a x y ...)" op op))))))

;;; ========== Comparison ==========

(defun lower-cmp (ctx op lhs rhs)
  "Lower comparison to a value (0 or 1)."
  (let* ((jmp-op (ir-jmp-op op))
         (lhs-v (lower-expr ctx lhs))
         (rhs-v (lower-expr ctx rhs))
         (dst (ctx-fresh-vreg ctx)))
    (ctx-emit ctx :cmp dst (list `(:cmp ,jmp-op) lhs-v rhs-v) 'u64)
    dst))

;;; ========== Load / Store / Atomic ==========

;;; ========== Compile-time validation helpers ==========

(defun check-unchecked-map-ptr (ptr-form op-name)
  "Error at compile time if PTR-FORM is a bare map-lookup, which returns a
   potentially-null pointer that the BPF verifier requires a null check for."
  (when (and (consp ptr-form)
             (member (car ptr-form) '(map-lookup map-lookup-ptr)
                     :test #'sym=))
    (whistler/compiler:whistler-error
     :what (format nil "map-lookup result used directly in ~a without null check" op-name)
     :expected "a null-checked pointer (BPF verifier requires it)"
     :hint (format nil "use (when-let ((p ~a)) (~a ...p...)) to guard the pointer"
                   ptr-form op-name))))

(defun ctx-map-type (ctx map-name)
  "Look up the integer map type for MAP-NAME from the lowering context, or nil."
  (let ((entry (assoc map-name (lower-ctx-maps ctx)
                      :test (lambda (a b) (string= (symbol-name a) (symbol-name b))))))
    (when entry
      (whistler/compiler:bpf-map-type (cdr entry)))))

(defun check-map-type-is (ctx map-name expected-type expected-name op-name)
  "Error if MAP-NAME's type doesn't match EXPECTED-TYPE."
  (let ((actual (ctx-map-type ctx map-name)))
    (when (and actual (/= actual expected-type))
      (whistler/compiler:whistler-error
       :what (format nil "~a requires a ~a map, but ~a is not" op-name expected-name map-name)
       :expected (format nil "(defmap ~a :type :~a ...)" map-name
                         (string-downcase expected-name))
       :hint (format nil "~a only works with :type :~a maps"
                     op-name (string-downcase expected-name))))))

(defun check-map-type-is-not (ctx map-name forbidden-type forbidden-name op-name)
  "Error if MAP-NAME's type matches FORBIDDEN-TYPE."
  (let ((actual (ctx-map-type ctx map-name)))
    (when (and actual (= actual forbidden-type))
      (whistler/compiler:whistler-error
       :what (format nil "~a does not work with ~a maps" op-name forbidden-name)
       :expected (format nil "a hash, array, or other key/value map")
       :hint (format nil "~a maps use ringbuf-reserve/ringbuf-submit instead" forbidden-name)))))

(defun lower-load (ctx args)
  (unless (<= 2 (length args) 3)
    (whistler/compiler:whistler-error
     :what (format nil "load expects 2-3 arguments, got ~d" (length args))
     :expected "(load type ptr [offset])"
     :hint "example: (load u32 ptr 0)"))
  (check-unchecked-map-ptr (second args) "load")
  (let* ((type-kw (first args))
         (ptr (lower-expr ctx (second args)))
         (off (or (third args) 0))
         (dst (ctx-fresh-vreg ctx)))
    (ctx-emit ctx :load dst (list ptr `(:imm ,off) `(:type ,type-kw)) type-kw)
    dst))

(defun lower-store (ctx args)
  (unless (= (length args) 4)
    (whistler/compiler:whistler-error
     :what (format nil "store expects 4 arguments, got ~d" (length args))
     :expected "(store type ptr offset value)"
     :hint "example: (store u32 ptr 0 val)"))
  (check-unchecked-map-ptr (second args) "store")
  (let* ((type-kw (first args))
         (ptr (lower-expr ctx (second args)))
         (off (or (third args) 0))
         (val (lower-expr ctx (fourth args))))
    (ctx-emit ctx :store nil (list ptr `(:imm ,off) val `(:type ,type-kw)))
    nil))

;;; ========== CO-RE annotated Load / Store / Ctx-load ==========

(defun lower-core-load (ctx args)
  "Lower (core-load TYPE ptr OFFSET STRUCT-NAME FIELD-NAME).
   Delegates to load logic but appends a (:core ...) tag to args."
  (let* ((type-kw (first args))
         (ptr (lower-expr ctx (second args)))
         (off (or (third args) 0))
         (struct-name (fourth args))
         (field-name (fifth args))
         (dst (ctx-fresh-vreg ctx)))
    (ctx-emit ctx :load dst
              (list ptr `(:imm ,off) `(:type ,type-kw)
                    `(:core ,struct-name ,field-name))
              type-kw)
    dst))

(defun lower-core-store (ctx args)
  "Lower (core-store TYPE ptr OFFSET val STRUCT-NAME FIELD-NAME).
   Delegates to store logic but appends a (:core ...) tag to args."
  (let* ((type-kw (first args))
         (ptr (lower-expr ctx (second args)))
         (off (or (third args) 0))
         (val (lower-expr ctx (fourth args)))
         (struct-name (fifth args))
         (field-name (sixth args)))
    (ctx-emit ctx :store nil
              (list ptr `(:imm ,off) val `(:type ,type-kw)
                    `(:core ,struct-name ,field-name)))
    nil))

(defun lower-core-ctx-load (ctx args)
  "Lower (core-ctx-load TYPE OFFSET STRUCT-NAME FIELD-NAME).
   Delegates to ctx-load logic but appends a (:core ...) tag to args."
  (let* ((type-kw (first args))
         (offset (second args))
         (struct-name (third args))
         (field-name (fourth args))
         (ctx-vreg (cdr (ctx-lookup-var ctx
                          (intern "%%CTX" (find-package '#:whistler/ir)))))
         (dst (ctx-fresh-vreg ctx)))
    (ctx-emit ctx :ctx-load dst
              (list ctx-vreg `(:imm ,offset) `(:type ,type-kw)
                    `(:core ,struct-name ,field-name))
              type-kw)
    dst))

(defun lower-atomic-add (ctx args)
  (unless (<= 3 (length args) 4)
    (whistler/compiler:whistler-error
     :what (format nil "atomic-add expects 3-4 arguments, got ~d" (length args))
     :expected "(atomic-add ptr offset value [type])"
     :hint "example: (atomic-add ptr 0 1) or (atomic-add ptr 0 1 u32)"))
  (when (and (consp (first args))
             (member (car (first args)) '(map-lookup map-lookup-ptr)
                     :test #'sym=))
    (whistler/compiler:whistler-error
     :what "map-lookup result used directly in atomic-add without null check"
     :expected "a null-checked pointer (BPF verifier requires it)"
     :hint "use (when-let ((p (map-lookup map key))) (atomic-add p 0 val)) or (incf (getmap map key))"))
  (let* ((type-kw (or (fourth args) 'u64))
         (type-size (cl:case type-kw (u8 1) (u16 2) (u32 4) (u64 8) (t 8)))
         (ptr (lower-expr ctx (first args)))
         (off (second args))
         (val (lower-expr ctx (third args))))
    (when (and (integerp off) (not (zerop (mod off type-size))))
      (whistler/compiler:whistler-error
       :what (format nil "atomic-add offset ~d is not aligned to ~d-byte ~a boundary"
                     off type-size type-kw)
       :expected (format nil "offset divisible by ~d" type-size)))
    (ctx-emit ctx :atomic-add nil (list ptr `(:imm ,off) val `(:type ,type-kw)))
    nil))

;;; ========== Map operations ==========

(defun struct-alloc-expr-p (expr)
  "Return T if EXPR is a struct-alloc form (make-NAME from defstruct)."
  (and (consp expr)
       (symbolp (car expr))
       (let ((name (symbol-name (car expr))))
         (and (> (length name) 5)
              (string= (subseq name 0 5) "MAKE-")))))

(defun lower-map-lookup (ctx map-name key-expr)
  (check-map-type-is-not ctx map-name whistler/bpf:+bpf-map-type-ringbuf+
                         "ringbuf" "map-lookup")
  (check-map-type-is-not ctx map-name whistler/bpf:+bpf-map-type-prog-array+
                         "prog-array" "map-lookup")
  ;; Auto-redirect to map-lookup-ptr when key is a struct pointer
  (when (struct-alloc-expr-p key-expr)
    (return-from lower-map-lookup
      (lower-map-lookup-ptr ctx map-name key-expr)))
  (let ((key-vreg (lower-expr ctx key-expr))
        (dst (ctx-fresh-vreg ctx)))
    (ctx-emit ctx :map-lookup dst (list `(:map ,map-name) key-vreg) 'u64)
    dst))

(defun lower-map-update (ctx map-name key-expr val-expr flags)
  ;; Auto-redirect to map-update-ptr when key or value is a struct pointer
  (when (or (struct-alloc-expr-p key-expr) (struct-alloc-expr-p val-expr))
    (return-from lower-map-update
      (lower-map-update-ptr ctx map-name
                            key-expr val-expr flags)))
  (let ((key-vreg (lower-expr ctx key-expr))
        (val-vreg (lower-expr ctx val-expr))
        (flags-vreg (lower-expr ctx flags))
        (dst (ctx-fresh-vreg ctx)))
    (ctx-emit ctx :map-update dst (list `(:map ,map-name) key-vreg val-vreg flags-vreg) 'u64)
    dst))

(defun lower-map-delete (ctx map-name key-expr)
  ;; Auto-redirect to map-delete-ptr when key is a struct pointer
  (when (struct-alloc-expr-p key-expr)
    (return-from lower-map-delete
      (lower-map-delete-ptr ctx map-name key-expr)))
  (let ((key-vreg (lower-expr ctx key-expr))
        (dst (ctx-fresh-vreg ctx)))
    (ctx-emit ctx :map-delete dst (list `(:map ,map-name) key-vreg) 'u64)
    dst))

(defun lower-map-lookup-ptr (ctx map-name ptr-expr)
  "Lower map-lookup-ptr: key is already a pointer to stack data."
  (let ((ptr-vreg (lower-expr ctx ptr-expr))
        (dst (ctx-fresh-vreg ctx)))
    (ctx-emit ctx :map-lookup-ptr dst (list `(:map ,map-name) ptr-vreg) 'u64)
    dst))

;;; ========== Struct allocation ==========

(defun lower-map-update-ptr (ctx map-name ptr-expr val-expr flags)
  "Lower map-update-ptr: key is already a pointer to stack data."
  (let ((ptr-vreg (lower-expr ctx ptr-expr))
        (val-vreg (lower-expr ctx val-expr))
        (flags-vreg (lower-expr ctx flags))
        (dst (ctx-fresh-vreg ctx)))
    (ctx-emit ctx :map-update-ptr dst
              (list `(:map ,map-name) ptr-vreg val-vreg flags-vreg) 'u64)
    dst))

(defun lower-map-delete-ptr (ctx map-name ptr-expr)
  "Lower map-delete-ptr: key is already a pointer to stack data."
  (let ((ptr-vreg (lower-expr ctx ptr-expr))
        (dst (ctx-fresh-vreg ctx)))
    (ctx-emit ctx :map-delete-ptr dst (list `(:map ,map-name) ptr-vreg) 'u64)
    dst))

;;; ========== Ring buffer operations ==========

(defun lower-ringbuf-output (ctx map-name data-expr size-expr flags-expr)
  "Lower (ringbuf-output map data size flags): copy data to ring buffer."
  (check-map-type-is ctx map-name whistler/bpf:+bpf-map-type-ringbuf+
                     "ringbuf" "ringbuf-output")
  (let ((data-vreg (lower-expr ctx data-expr))
        (size-vreg (lower-expr ctx size-expr))
        (flags-vreg (lower-expr ctx flags-expr))
        (dst (ctx-fresh-vreg ctx)))
    (ctx-emit ctx :ringbuf-output dst
              (list `(:map ,map-name) data-vreg size-vreg flags-vreg) 'u64)
    dst))

(defun lower-ringbuf-reserve (ctx map-name size-expr flags-expr)
  "Lower (ringbuf-reserve map size flags): reserve space in a ring buffer."
  (check-map-type-is ctx map-name whistler/bpf:+bpf-map-type-ringbuf+
                     "ringbuf" "ringbuf-reserve")
  (let ((size-vreg (lower-expr ctx size-expr))
        (flags-vreg (lower-expr ctx flags-expr))
        (dst (ctx-fresh-vreg ctx)))
    (ctx-emit ctx :ringbuf-reserve dst
              (list `(:map ,map-name) size-vreg flags-vreg) 'u64)
    dst))

(defun lower-ringbuf-submit (ctx data-expr flags-expr)
  "Lower (ringbuf-submit data flags): submit a reserved ring buffer record."
  (let ((data-vreg (lower-expr ctx data-expr))
        (flags-vreg (lower-expr ctx flags-expr))
        (dst (ctx-fresh-vreg ctx)))
    (ctx-emit ctx :ringbuf-submit dst (list data-vreg flags-vreg) 'u64)
    dst))

(defun lower-ringbuf-discard (ctx data-expr flags-expr)
  "Lower (ringbuf-discard data flags): discard a reserved ring buffer record."
  (let ((data-vreg (lower-expr ctx data-expr))
        (flags-vreg (lower-expr ctx flags-expr))
        (dst (ctx-fresh-vreg ctx)))
    (ctx-emit ctx :ringbuf-discard dst (list data-vreg flags-vreg) 'u64)
    dst))

(defun lower-struct-alloc (ctx size)
  "Lower (struct-alloc SIZE): allocate SIZE bytes on stack, emit explicit
   zero stores (which DSE can later eliminate), return pointer."
  (let ((dst (ctx-fresh-vreg ctx)))
    (ctx-emit ctx :struct-alloc dst (list `(:imm ,size)) 'u64)
    ;; Emit explicit zero stores instead of zeroing inside emit-struct-alloc-insn.
    ;; DSE will remove any that are overwritten before being read.
    ;; Uses (:imm 0) as the value so emit can use st-mem (immediate store).
    (let ((pos 0))
      (loop while (< pos size)
            do (let ((remaining (- size pos)))
                 (cond
                   ((>= remaining 8)
                    (ctx-emit ctx :store nil
                              (list dst `(:imm ,pos) '(:imm 0) '(:type u64)))
                    (incf pos 8))
                   ((>= remaining 4)
                    (ctx-emit ctx :store nil
                              (list dst `(:imm ,pos) '(:imm 0) '(:type u32)))
                    (incf pos 4))
                   ((>= remaining 2)
                    (ctx-emit ctx :store nil
                              (list dst `(:imm ,pos) '(:imm 0) '(:type u16)))
                    (incf pos 2))
                   (t
                    (ctx-emit ctx :store nil
                              (list dst `(:imm ,pos) '(:imm 0) '(:type u8)))
                    (incf pos 1))))))
    dst))

;;; ========== Tail call ==========

(defun lower-tail-call (ctx map-name index-expr)
  "Lower (tail-call MAP INDEX). Emits bpf_tail_call(ctx, map, index).
   If the tail call succeeds, execution transfers to the target program.
   If it fails (bad index, no program loaded), execution continues."
  (check-map-type-is ctx map-name whistler/bpf:+bpf-map-type-prog-array+
                     "prog-array" "tail-call")
  (let ((idx-vreg (lower-expr ctx index-expr))
        (ctx-vreg (cdr (ctx-lookup-var ctx (intern "%%CTX" (find-package '#:whistler/ir)))))
        (dst (ctx-fresh-vreg ctx)))
    (ctx-emit ctx :tail-call dst
              (list `(:map ,map-name) ctx-vreg idx-vreg) 'u64)
    dst))

;;; ========== Helper calls ==========

;; Helper arguments that are pointer positions (1-indexed): arg N is a pointer.
;; probe-read(dst, size, src), probe-read-user(dst, size, src), etc.
(defparameter *helper-pointer-args*
  '(("PROBE-READ" 1 3) ("PROBE-READ-USER" 1 3)
    ("PROBE-READ-STR" 1 3) ("PROBE-READ-USER-STR" 1 3)))

(defun check-narrow-pointer-args (ctx helper-name args arg-vregs)
  "Error when a narrow type (u8, u16) flows into a pointer-position argument."
  (let ((ptr-positions (cdr (assoc (symbol-name helper-name) *helper-pointer-args*
                                    :test #'string=))))
    (when ptr-positions
      (loop for vreg in arg-vregs
            for arg in args
            for pos from 1
            when (member pos ptr-positions)
            do (let ((type (vreg-type-in-env ctx vreg)))
                 (when (and type (member (symbol-name type) '("U8" "U16") :test #'string=))
                   (let ((bits (if (string= (symbol-name type) "U8") 8 16)))
                     (whistler/compiler:whistler-error
                      :what (format nil "narrow type ~a passed as pointer to ~a" type helper-name)
                      :where (format nil "(~a ~{~s~^ ~})" helper-name args)
                      :expected "a u64 pointer value"
                      :hint (format nil "~a values are 0-~d, not valid pointers — use (load u64 ...) to read a full-width pointer"
                                    type (1- (ash 1 bits)))))))))))


(defun lower-helper-call (ctx helper-name args)
  (let ((func-id (cdr (assoc (symbol-name helper-name) whistler/compiler:*builtin-helpers*
                              :test #'string=))))
    (unless func-id
      (whistler/compiler:whistler-error
       :what (format nil "unknown BPF helper: ~a" helper-name)
       :where (format nil "(~a ...)" helper-name)
       :expected "a known BPF helper function"
       :hint (format nil "known helpers: ~{~a~^, ~}"
                     (mapcar #'car whistler/compiler:*builtin-helpers*))))
    ;; Check argument count
    (let ((expected-count (cdr (assoc (symbol-name helper-name)
                                      whistler/compiler:*helper-arg-counts*
                                      :test #'string=))))
      (when (and expected-count (/= (length args) expected-count))
        (whistler/compiler:whistler-error
         :what (format nil "~a expects ~d argument~:p, got ~d"
                       helper-name expected-count (length args))
         :where (format nil "(~a~{ ~s~})" helper-name args)
         :expected (format nil "(~a~{~* ARG~})" helper-name
                           (make-list expected-count)))))
    ;; Check probe-read size argument (arg 2) against 512-byte stack limit
    (when (and (member (symbol-name helper-name)
                       '("PROBE-READ-KERNEL" "PROBE-READ-USER"
                         "PROBE-READ" "PROBE-READ-STR" "PROBE-READ-USER-STR")
                       :test #'string=)
               (>= (length args) 2))
      (let ((size-arg (second args)))
        (when (and (integerp size-arg) (> size-arg 512))
          (whistler/compiler:whistler-error
           :what (format nil "~a size ~d exceeds 512-byte BPF stack limit"
                         helper-name size-arg)
           :where (format nil "(~a ... ~d ...)" helper-name size-arg)
           :expected "a size <= 512 bytes"
           :hint "BPF programs have a 512-byte stack; probe reads must fit within it"))))
    (let ((arg-vregs (mapcar (lambda (a) (lower-expr ctx a)) args))
          (dst (ctx-fresh-vreg ctx)))
      (check-narrow-pointer-args ctx helper-name args arg-vregs)
      (ctx-emit ctx :call dst (cons `(:helper ,func-id) arg-vregs) 'u64)
      dst)))

;;; ========== Context load ==========

;;; Context struct layouts for compile-time validation.
;;; Each entry: (offset size-bytes type-kw pointer-p)
;;; pointer-p indicates the field holds a pointer (packet data, packet end, etc.)
;;; that the verifier will track — arithmetic on these is restricted.

(defparameter *xdp-ctx-fields*
  '((0  4 u32 :pkt)         ; data       — packet pointer
    (4  4 u32 :pkt-end)     ; data_end   — packet end pointer
    (8  4 u32 :scalar)      ; data_meta
    (12 4 u32 :scalar)      ; ingress_ifindex
    (16 4 u32 :scalar))     ; rx_queue_index
  "xdp_md context fields: (offset size type pointer-kind)")

(defparameter *skb-ctx-fields*
  '((76 4 u32 :pkt)         ; data       — packet pointer
    (80 4 u32 :pkt-end))    ; data_end   — packet end pointer
  "Commonly accessed __sk_buff context fields for TC programs.")

(defun section-to-ctx-fields (section)
  "Return the context field layout for the given section, or NIL if unknown."
  (cond
    ((or (string= section "xdp")
         (and (> (length section) 4)
              (string= (subseq section 0 4) "xdp/")))
     *xdp-ctx-fields*)
    ((or (string= section "tc")
         (and (> (length section) 3)
              (string= (subseq section 0 3) "tc/"))
         (string= section "classifier"))
     *skb-ctx-fields*)
    ;; kprobe/uprobe: pt_regs — all u64 fields, don't restrict
    ;; tracepoint: variable layout, don't restrict
    ;; cgroup: __sk_buff or bpf_sock, partial coverage
    (t nil)))

(defun ctx-field-lookup (fields offset)
  "Find the field at OFFSET in FIELDS. Returns (offset size type pointer-kind) or NIL."
  (find offset fields :key #'first))

(defun validate-ctx-load (ctx type-kw offset)
  "Validate a ctx-load against the known context struct layout.
   Signals a compile-time error for invalid access widths.
   Returns the pointer kind (:pkt, :pkt-end, :scalar) or NIL if unknown."
  (let* ((section (ir-program-section (lower-ctx-prog ctx)))
         (fields (section-to-ctx-fields section)))
    (when fields
      (let ((field (ctx-field-lookup fields offset)))
        (cond
          ;; Unknown offset — warn but allow (context structs may have fields we don't track)
          ((null field) nil)
          ;; Access size mismatch
          ((/= (whistler/compiler:bpf-type-size type-kw)
                (second field))
           (whistler/compiler:whistler-error
            :what (format nil "ctx-load ~a at offset ~d: wrong access size" type-kw offset)
            :expected (format nil "~a (~d bytes) — the context field at this offset is ~d bytes wide"
                              (third field) (second field) (second field))
            :hint (format nil "use (ctx-load ~a ~d) instead" (third field) offset)))
          ;; Valid — return pointer kind
          (t (fourth field)))))))

(defun lower-ctx-load (ctx type-kw offset)
  (validate-ctx-load ctx type-kw offset)
  (let ((ctx-vreg (cdr (ctx-lookup-var ctx (intern "%%CTX" (find-package '#:whistler/ir)))))
        (dst (ctx-fresh-vreg ctx)))
    (ctx-emit ctx :ctx-load dst (list ctx-vreg `(:imm ,offset) `(:type ,type-kw)) type-kw)
    dst))

(defun lower-ctx-store (ctx type-kw offset value-form)
  "Lower (ctx-store TYPE OFFSET VALUE) — write a value to a BPF context field."
  (let ((ctx-vreg (cdr (ctx-lookup-var ctx (intern "%%CTX" (find-package '#:whistler/ir)))))
        (val-vreg (lower-expr ctx value-form)))
    (ctx-emit ctx :ctx-store nil (list ctx-vreg `(:imm ,offset) val-vreg `(:type ,type-kw)))
    nil))

;;; ========== Setf ==========

(defun lower-setf (ctx place expr)
  (cond
    ;; Compound place: (setf (ctx TYPE OFFSET) VALUE)
    ((and (consp place) (sym= (car place) 'ctx))
     (lower-ctx-store ctx (first (cdr place)) (second (cdr place)) expr)
     nil)
    ;; Simple variable
    (t
     (let ((new-vreg (lower-expr ctx expr)))
       ;; SSA: update the variable to point to the new vreg
       (ctx-update-var ctx place new-vreg)
       new-vreg))))

;;; ========== Stack-addr ==========

(defun lower-stack-addr (ctx var-name)
  "Lower (stack-addr VAR) — get a pointer to a variable's stack location."
  (let ((binding (ctx-lookup-var ctx var-name)))
    (unless binding
      (whistler/compiler:whistler-error
       :what (format nil "unbound variable in stack-addr: ~a" var-name)
       :where (format nil "(stack-addr ~a)" var-name)
       :expected "a variable bound by LET or LET*"))
    (let ((vreg (cdr binding))
          (dst (ctx-fresh-vreg ctx)))
      (ctx-emit ctx :stack-addr dst (list vreg) 'u64)
      dst)))

;;; ========== Log2 intrinsic ==========

(defun lower-log2 (ctx expr)
  (let ((val (lower-expr ctx expr))
        (dst (ctx-fresh-vreg ctx)))
    (ctx-emit ctx :log2 dst (list val) 'u64)
    dst))

;;; ========== Dotimes ==========

(defun lower-dotimes (ctx var-spec body)
  (destructuring-bind (var count) var-spec
    (let ((n (cond ((integerp count) count)
                   ((and (symbolp count) (boundp count) (constantp count))
                    (symbol-value count))
                   (t (whistler/compiler:whistler-error
                       :what (format nil "non-constant loop count: ~a" count)
                       :where (format nil "(dotimes (~a ~a) ...)" var count)
                       :expected "a compile-time constant integer or defconstant symbol"
                       :hint "the BPF verifier requires a known upper bound for all loops")))))
      (when (and (integerp n) (< n 0))
        (whistler/compiler:whistler-error
         :what (format nil "negative loop count: ~d" n)
         :where (format nil "(dotimes (~a ~a) ...)" var count)
         :expected "a non-negative integer"
         :hint "BPF loops require count >= 0"))
      (let* ((prog (lower-ctx-prog ctx))
             (saved-env (copy-list (lower-ctx-env ctx)))
             (header-label (ir-fresh-label prog "loop_hdr"))
             (body-label (ir-fresh-label prog "loop_body"))
             (exit-label (ir-fresh-label prog "loop_exit"))
             (init-vreg (ctx-fresh-vreg ctx))
             (init-block-label (basic-block-label (lower-ctx-block ctx)))
             (ctx-sym (intern "%%CTX" (find-package '#:whistler/ir)))
             (loop-phis '()))
        (ctx-emit ctx :mov init-vreg (list '(:imm 0)) 'u64)
        (ctx-emit ctx :br nil (list `(:label ,header-label)))

        ;; Header block
        (let ((header-block (make-basic-block :label header-label)))
          (ctx-switch-block ctx header-block)

          ;; Phi for loop counter
          (let ((phi-vreg (ctx-fresh-vreg ctx)))
            (ctx-emit ctx :phi phi-vreg
                      (list (list init-vreg `(:label ,init-block-label))))
            (ctx-bind-var ctx var 'u64 phi-vreg)

            ;; Pre-insert phis for ALL in-scope variables (except counter and %%CTX).
            ;; This is the standard SSA approach: create phis eagerly before the
            ;; body so the body naturally uses the phi vregs through the env.
            ;; DCE removes unused ones later.
            (let ((n-vreg (ctx-fresh-vreg ctx)))
              (dolist (entry (lower-ctx-env ctx))
                (let ((vname (car entry))
                      (vtype (cadr entry))
                      (vvreg (cddr entry)))
                  (unless (or (string= (symbol-name vname) (symbol-name var))
                              (eq vname ctx-sym))
                    (let ((lphi (ctx-fresh-vreg ctx)))
                      (ctx-emit ctx :phi lphi
                                (list (list vvreg `(:label ,init-block-label)))
                                vtype)
                      (setf (cddr entry) lphi)
                      (push (list vname lphi vvreg vtype) loop-phis)))))

              ;; Bounds check
              (ctx-emit ctx :mov n-vreg (list `(:imm ,n)) 'u64)
              (ctx-emit ctx :br-cond nil
                        (list '(:cmp :jge) phi-vreg n-vreg
                              `(:label ,exit-label) `(:label ,body-label)))

              ;; Body block
              (let ((body-block (make-basic-block :label body-label)))
                (declare (ignore body-block))
                (ctx-switch-block ctx (make-basic-block :label body-label))
                (dolist (form body)
                  (lower-expr ctx form))

                ;; Fill back-edges for all loop-carried phis
                (let ((back-lbl (basic-block-label (lower-ctx-block ctx))))
                  ;; Variable phis
                  (dolist (lp loop-phis)
                    (let* ((vname (first lp))
                           (phi-vr (second lp))
                           (env-entry (assoc vname (lower-ctx-env ctx)
                                             :test (lambda (a b)
                                                     (string= (symbol-name a)
                                                              (symbol-name b)))))
                           (body-vr (when env-entry (cddr env-entry)))
                           (phi-insn (find-if
                                      (lambda (i)
                                        (and (eq (ir-insn-op i) :phi)
                                             (eql (ir-insn-dst i) phi-vr)))
                                      (basic-block-insns header-block))))
                      (when (and phi-insn body-vr)
                        (setf (ir-insn-args phi-insn)
                              (list (first (ir-insn-args phi-insn))
                                    (list body-vr `(:label ,back-lbl)))))))

                  ;; Increment counter and fill counter phi back-edge
                  (let* ((inc-vreg (ctx-fresh-vreg ctx)))
                    (ctx-emit ctx :add inc-vreg (list phi-vreg '(:imm 1)) 'u64)
                    (let ((ctr-phi (first (basic-block-insns header-block))))
                      (setf (ir-insn-args ctr-phi)
                            (list (first (ir-insn-args ctr-phi))
                                  (list inc-vreg `(:label ,back-lbl))))))
                  (ctx-emit ctx :br nil (list `(:label ,header-label))))))))

        ;; Exit block
        (let ((exit-block (make-basic-block :label exit-label)))
          (ctx-switch-block ctx exit-block))
        ;; Restore the outer scope, but keep loop-carried values for variables
        ;; that survive the loop.  At loop exit those values are the header phis.
        (setf (lower-ctx-env ctx) saved-env)
        (dolist (lp loop-phis)
          (let* ((vname (first lp))
                 (phi-vr (second lp))
                 (env-entry (assoc vname (lower-ctx-env ctx)
                                   :test (lambda (a b)
                                           (string= (symbol-name a)
                                                    (symbol-name b))))))
            (when env-entry
              (setf (cddr env-entry) phi-vr))))
        nil))))

;;; ========== Cast ==========

(defun lower-cast (ctx type-kw expr)
  (let ((v (lower-expr ctx expr))
        (dst (ctx-fresh-vreg ctx)))
    (ctx-emit ctx :cast dst (list v `(:type ,type-kw)) type-kw)
    dst))

;;; ========== Cond ==========

(defun lower-cond (ctx clauses)
  (if (null clauses)
      (let ((v (ctx-fresh-vreg ctx)))
        (ctx-emit ctx :mov v (list '(:imm 0)) 'u64)
        v)
      (let* ((clause (first clauses))
             (test (first clause))
             (body (rest clause)))
        (if (or (eq test t) (sym= test 't))
            (let ((result nil))
              (dolist (expr body) (setf result (lower-expr ctx expr)))
              result)
            (lower-if ctx test
                      (if (= (length body) 1) (first body) (cons 'progn body))
                      (if (rest clauses) (cons 'cond (rest clauses)) nil))))))

;;; ========== And / Or ==========

(defun lower-and (ctx args)
  (if (null args)
      (let ((v (ctx-fresh-vreg ctx)))
        (ctx-emit ctx :mov v (list '(:imm 1)) 'u64)
        v)
      (if (= (length args) 1)
          (lower-expr ctx (first args))
          ;; Desugar: (and a b c) → (if a (and b c) 0)
          (lower-if ctx (first args)
                    (if (= (length (rest args)) 1)
                        (second args)
                        (cons 'and (rest args)))
                    0))))

(defun lower-or (ctx args)
  (if (null args)
      (let ((v (ctx-fresh-vreg ctx)))
        (ctx-emit ctx :mov v (list '(:imm 0)) 'u64)
        v)
      (if (= (length args) 1)
          (lower-expr ctx (first args))
          ;; Desugar: (or a b) → (let ((tmp a)) (if tmp tmp (or b ...)))
          ;; Simplified: just use if with the first arg
          (lower-if ctx (first args)
                    (first args)  ; then: re-evaluate (ok since it's a var or const)
                    (if (= (length (rest args)) 1)
                        (second args)
                        (cons 'or (rest args)))))))

;;; ========== Not ==========

(defun lower-not (ctx expr)
  (let* ((v (lower-expr ctx expr))
         (dst (ctx-fresh-vreg ctx)))
    (ctx-emit ctx :cmp dst (list '(:cmp :jeq) v `(:imm 0)) 'u64)
    dst))
