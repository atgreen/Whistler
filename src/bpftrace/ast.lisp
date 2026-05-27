;;; ast.lisp — parse tree → typed AST
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; The iparse output is a tree of (:tag child ...) nodes that mirrors
;;; the grammar one-to-one. This file normalises it into the AST that
;;; codegen.lisp dispatches on:
;;;
;;;   (:script (probe …))
;;;   (:probe :specs (spec …) :predicate expr|nil :body (stmt …))
;;;
;;; spec   = (:begin) | (:end)
;;;        | (:kprobe FUNC) | (:kretprobe FUNC)
;;;        | (:tracepoint CATEGORY EVENT)
;;;        | (:interval :unit (:s|:ms|:us|:hz) :count N)
;;;
;;; stmt   = (:if  :cond expr :then (stmt …) :else (stmt …))
;;;        | (:assign :lhs lhs :op KW :rhs expr)
;;;        | (:incdec :lhs lhs :op (:inc|:dec))
;;;        | (:expr expr)
;;;
;;; lhs    = (:map  :name NAME :keys (expr …))    ; @m or @m[k,…]
;;;        | (:var  NAME)                          ; $x
;;;
;;; expr   = (:int N) | (:str "…") | (:bool BOOL)
;;;        | (:var NAME) | (:map :name NAME :keys (expr …))
;;;        | (:builtin :pid|:tid|:uid|…)
;;;        | (:arg N) | (:args) | (:retval) | (:comm) | (:probe-name) | (:func)
;;;        | (:bin :op KW :lhs e :rhs e)
;;;        | (:un  :op KW :arg e)
;;;        | (:tern :cond e :then e :else e)
;;;        | (:call :name NAME :args (e …))
;;;        | (:field :base e :name NAME)   ; both .x and ->x
;;;        | (:index :base e :keys (e …))

(in-package #:whistler/bpftrace)

;;; ========== Utilities ==========

(defun tag-of (node) (and (consp node) (first node)))
(defun children-of (node) (and (consp node) (rest node)))

(defun first-tagged (node tag)
  "Return the first child of NODE whose tag is TAG, or NIL."
  (find-if (lambda (c) (and (consp c) (eq (tag-of c) tag)))
           (children-of node)))

(defun all-tagged (node tag)
  "All children of NODE whose tag is TAG."
  (remove-if-not (lambda (c) (and (consp c) (eq (tag-of c) tag)))
                 (children-of node)))

(defun text-of (node)
  "Concatenate all string children of NODE — used for nodes like :IDENT
   that wrap a single literal string."
  (let ((parts (remove-if-not #'stringp (children-of node))))
    (if (= (length parts) 1) (first parts)
        (apply #'concatenate 'string parts))))

(define-condition bpftrace-unsupported (error)
  ((feature :initarg :feature :reader bpftrace-unsupported-feature))
  (:report (lambda (c s)
             (format s "bpftrace feature not yet supported: ~A"
                     (bpftrace-unsupported-feature c)))))

(defun unsupported (fmt &rest args)
  (error 'bpftrace-unsupported :feature (apply #'format nil fmt args)))

;;; ========== Operator string → keyword ==========

(defun op->kw (s)
  (cond ((string= s "+")   :+)
        ((string= s "-")   :-)
        ((string= s "*")   :*)
        ((string= s "/")   :/)
        ((string= s "%")   :%)
        ((string= s "==")  :==)
        ((string= s "!=")  :!=)
        ((string= s "<")   :<)
        ((string= s ">")   :>)
        ((string= s "<=")  :<=)
        ((string= s ">=")  :>=)
        ((string= s "&&")  :&&)
        ((string= s "||")  :\|\|)
        ((string= s "&")   :&)
        ((string= s "|")   :\|)
        ((string= s "^")   :^)
        ((string= s "<<")  :<<)
        ((string= s ">>")  :>>)
        ((string= s "!")   :!)
        ((string= s "~")   :~)
        ((string= s "=")   :=)
        ((string= s "+=")  :+=)
        ((string= s "-=")  :-=)
        ((string= s "*=")  :*=)
        ((string= s "/=")  :/=)
        ((string= s "%=")  :%=)
        ((string= s "|=")  :\|=)
        ((string= s "&=")  :&=)
        ((string= s "^=")  :^=)
        (t (unsupported "operator ~S" s))))

;;; ========== Main entry ==========

(defun normalize (raw)
  "Convert the iparse parse tree RAW into the typed AST."
  (assert (eq (tag-of raw) :script) (raw) "expected :SCRIPT root, got ~S" (tag-of raw))
  (cons :script (mapcar #'norm-probe (all-tagged raw :probe))))

;;; ========== Probes ==========

(defun norm-probe (node)
  (let* ((specs-node (first-tagged node :probe-specs))
         (pred-node  (first-tagged node :predicate))
         (block-node (first-tagged node :block))
         (specs      (mapcar #'norm-probe-spec (all-tagged specs-node :probe-spec)))
         (predicate  (when pred-node
                       (norm-expr (first (remove-if-not #'consp (children-of pred-node))))))
         (body       (norm-block block-node)))
    (list :probe :specs specs :predicate predicate :body body)))

(defun norm-probe-spec (node)
  ;; (:PROBE-SPEC (:KPROBE-SPEC …)) — find the first child that is a tagged list.
  (let ((inner (find-if #'consp (children-of node))))
    (ecase (tag-of inner)
      (:begin-spec      '(:begin))
      (:end-spec        '(:end))
      (:kprobe-spec     (list :kprobe (text-of (first-tagged inner :ident))))
      (:kretprobe-spec  (list :kretprobe (text-of (first-tagged inner :ident))))
      (:uprobe-spec
       (list :uprobe
             (text-of (first-tagged inner :upath))
             (text-of (first-tagged inner :ident))))
      (:uretprobe-spec
       (list :uretprobe
             (text-of (first-tagged inner :upath))
             (text-of (first-tagged inner :ident))))
      (:tracepoint-spec
       (let ((idents (all-tagged inner :ident)))
         (list :tracepoint (text-of (first idents)) (text-of (second idents)))))
      (:interval-spec
       (let* ((unit-node (first-tagged inner :interval-unit))
              (unit-str  (text-of unit-node))
              (count-node (first-tagged inner :integer)))
         (list :interval
               :unit (intern (string-upcase unit-str) :keyword)
               :count (parse-integer (text-of count-node)))))
      (:profile-spec
       (let* ((unit-node (first-tagged inner :interval-unit))
              (unit-str  (text-of unit-node))
              (count-node (first-tagged inner :integer)))
         (list :profile
               :unit (intern (string-upcase unit-str) :keyword)
               :count (parse-integer (text-of count-node))))))))

;;; ========== Statements ==========

(defun norm-block (node)
  (when node
    (let ((stmts-node (first-tagged node :statements)))
      (when stmts-node
        (mapcar #'norm-statement (all-tagged stmts-node :statement))))))

(defun norm-statement (node)
  (let ((inner (first (remove-if-not #'consp (children-of node)))))
    (ecase (tag-of inner)
      (:if-stmt      (norm-if inner))
      (:assign-stmt  (norm-assign inner))
      (:expr-stmt    (list :expr (norm-expr-or-expr-wrapped
                                  (first (remove-if-not #'consp (children-of inner)))))))))

(defun norm-expr-or-expr-wrapped (node)
  "Accept either a bare expression-precedence node or an :EXPR wrapper."
  (if (eq (tag-of node) :expr)
      (norm-expr-or-expr-wrapped (first (remove-if-not #'consp (children-of node))))
      (norm-expr node)))

(defun norm-if (node)
  (let* ((children (children-of node))
         (consed   (remove-if-not #'consp children))
         (cond-expr (norm-expr-or-expr-wrapped (first consed)))
         (then-blk (norm-block (second consed)))
         (else-blk (norm-block (third consed))))
    (list :if :cond cond-expr :then then-blk :else else-blk)))

(defun norm-assign (node)
  (let* ((kids   (children-of node))
         (lhs    (norm-lhs (find-if (lambda (c) (and (consp c) (eq (tag-of c) :lhs))) kids)))
         (op-node (or (find-if (lambda (c) (and (consp c) (eq (tag-of c) :assign-op))) kids)
                      (find-if (lambda (c) (and (consp c) (eq (tag-of c) :incdec-op))) kids))))
    (if (eq (tag-of op-node) :incdec-op)
        (list :incdec :lhs lhs
              :op (if (string= (text-of op-node) "++") :inc :dec))
        (let ((rhs-node (find-if (lambda (c)
                                   (and (consp c)
                                        (member (tag-of c)
                                                '(:expr :ternary :lor :land :bor :bxor
                                                  :band :eq :rel :shift :add :mul
                                                  :unary :postfix :primary))))
                                 kids)))
          (list :assign :lhs lhs :op (op->kw (text-of op-node))
                :rhs (norm-expr-or-expr-wrapped rhs-node))))))

(defun norm-lhs (node)
  (let ((inner (first (remove-if-not #'consp (children-of node)))))
    (ecase (tag-of inner)
      (:map-access (norm-map-access inner))
      (:scalar-var (list :var (text-of (first-tagged inner :ident)))))))

;;; ========== Expressions ==========
;;;
;;; Each precedence rule yields either a single child (no op) or a
;;; chain like (rule "op" rule "op" rule …). We left-fold the chain
;;; into a (:bin :op …) tree.

(defun norm-expr (node) (norm-ternary node))

(defun chain (node make-bin)
  "Left-fold a precedence-chain node: children are operands interleaved
   with operator strings. MAKE-BIN is called with (op lhs rhs)."
  (let* ((kids (children-of node))
         (operands (remove-if-not #'consp kids))
         (ops      (remove-if-not #'stringp kids)))
    (if (= (length operands) 1)
        (norm-expr-dispatch (first operands))
        (reduce (lambda (acc rhs-pair)
                  (funcall make-bin (car rhs-pair) acc (cdr rhs-pair)))
                (loop for op in ops
                      for rhs in (rest operands)
                      collect (cons (op->kw op) (norm-expr-dispatch rhs)))
                :initial-value (norm-expr-dispatch (first operands))))))

(defun mk-bin (op lhs rhs) (list :bin :op op :lhs lhs :rhs rhs))

(defun norm-ternary (node)
  (let* ((kids (children-of node))
         (consed (remove-if-not #'consp kids)))
    (case (length consed)
      (1 (norm-expr-dispatch (first consed)))
      (3 (list :tern
               :cond (norm-expr-dispatch (first consed))
               :then (norm-expr-dispatch (second consed))
               :else (norm-expr-dispatch (third consed))))
      (t (error "malformed ternary: ~S" node)))))

(defun norm-expr-dispatch (node)
  (case (tag-of node)
    (:expr     (norm-expr-or-expr-wrapped node))
    (:ternary  (norm-ternary node))
    (:lor      (chain node #'mk-bin))
    (:land     (chain node #'mk-bin))
    (:bor      (chain node #'mk-bin))
    (:bxor     (chain node #'mk-bin))
    (:band     (chain node #'mk-bin))
    (:eq       (chain node #'mk-bin))
    (:rel      (chain node #'mk-bin))
    (:shift    (chain node #'mk-bin))
    (:add      (chain node #'mk-bin))
    (:mul      (chain node #'mk-bin))
    (:unary    (norm-unary node))
    (:postfix  (norm-postfix node))
    (:primary  (norm-primary node))
    (:parens
     (norm-expr-dispatch (first (remove-if-not #'consp (children-of node)))))
    (t (norm-primary node))))

(defun norm-unary (node)
  (let* ((kids (children-of node))
         (op-node (find-if (lambda (c) (and (consp c) (eq (tag-of c) :unary-op))) kids))
         (arg-node (find-if (lambda (c)
                              (and (consp c) (not (eq (tag-of c) :unary-op))))
                            kids)))
    (if op-node
        (list :un :op (op->kw (text-of op-node))
              :arg (norm-expr-dispatch arg-node))
        (norm-expr-dispatch arg-node))))

(defun norm-postfix (node)
  (let* ((kids (children-of node))
         (consed (remove-if-not #'consp kids))
         (base  (norm-expr-dispatch (first consed)))
         (tails (rest consed)))
    (reduce (lambda (acc tail-wrapper)
              ;; tail-wrapper is (:postfix-tail (:field-access …)) — unwrap.
              (let ((inner (if (eq (tag-of tail-wrapper) :postfix-tail)
                               (find-if #'consp (children-of tail-wrapper))
                               tail-wrapper)))
                (ecase (tag-of inner)
                  (:field-access (list :field :base acc
                                       :name (text-of (first-tagged inner :ident))))
                  (:arrow-access (list :field :base acc
                                       :name (text-of (first-tagged inner :ident))))
                  (:index-access (list :index :base acc
                                       :keys (mapcar #'norm-expr-dispatch
                                                     (remove-if-not
                                                      #'consp
                                                      (children-of inner))))))))
            tails :initial-value base)))

(defun norm-primary (node)
  (let ((inner (or (first (remove-if-not #'consp (children-of node)))
                   node)))
    (case (tag-of inner)
      (:parens       (norm-expr-dispatch
                      (first (remove-if-not #'consp (children-of inner)))))
      (:func-call    (norm-call inner))
      (:map-access   (norm-map-access inner))
      (:map-anon     (list :map :name nil :keys nil))
      (:scalar-var   (list :var (text-of (first-tagged inner :ident))))
      (:builtin      (norm-builtin inner))
      (:builtin-name (norm-builtin inner)) ; if parens stripped
      (:string-lit   (list :str (strip-quotes (text-of inner))))
      (:hex-int      (list :int (parse-integer (text-of inner) :start 2 :radix 16)))
      (:integer      (list :int (parse-integer (text-of inner))))
      (t (error "unexpected primary: ~S" inner)))))

(defun strip-quotes (s)
  ;; remove surrounding ""s and decode \n \t \\ \" — minimal
  (let* ((mid (subseq s 1 (1- (length s))))
         (out (make-array 0 :element-type 'character :fill-pointer 0 :adjustable t))
         (i 0)
         (n (length mid)))
    (loop while (< i n)
          for c = (char mid i)
          do (cond
               ((and (char= c #\\) (< (1+ i) n))
                (let ((nx (char mid (1+ i))))
                  (vector-push-extend
                   (case nx
                     (#\n #\Newline) (#\t #\Tab) (#\r #\Return)
                     (#\\ #\\) (#\" #\") (#\0 (code-char 0))
                     (t nx))
                   out))
                (incf i 2))
               (t (vector-push-extend c out) (incf i))))
    (coerce out 'simple-string)))

(defun norm-call (node)
  (let* ((name-node (find-if (lambda (c) (and (consp c) (eq (tag-of c) :ident)))
                             (children-of node)))
         (args-node (find-if (lambda (c) (and (consp c) (eq (tag-of c) :arg-list)))
                             (children-of node)))
         (args      (when args-node
                      (mapcar #'norm-expr-dispatch
                              (remove-if-not #'consp (children-of args-node))))))
    (list :call :name (text-of name-node) :args args)))

(defun norm-map-access (node)
  (let* ((kids (children-of node))
         (consed (remove-if-not #'consp kids))
         (ident (find-if (lambda (c) (eq (tag-of c) :ident)) consed))
         (keys-node (find-if (lambda (c) (eq (tag-of c) :map-keys)) consed))
         (key-exprs (when keys-node
                      (remove-if-not #'consp (children-of keys-node)))))
    (list :map
          :name (when ident (text-of ident))
          :keys (mapcar #'norm-expr-or-expr-wrapped key-exprs))))

(defun norm-builtin (node)
  (let* ((name-node (or (first-tagged node :builtin-name) node))
         (name (text-of name-node)))
    (cond
      ((string= name "retval")  '(:retval))
      ((string= name "args")    '(:args))
      ((string= name "comm")    '(:comm))
      ((string= name "probe")   '(:probe-name))
      ((string= name "func")    '(:func))
      ((string= name "kstack")  '(:kstack))
      ((string= name "ustack")  '(:ustack))
      ((and (>= (length name) 4) (string= (subseq name 0 3) "arg")
            (digit-char-p (char name 3)))
       (list :arg (parse-integer (subseq name 3))))
      (t (list :builtin (intern (string-upcase name) :keyword))))))
