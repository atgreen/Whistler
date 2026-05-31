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
;;;        | (:while :cond expr :body (stmt …))
;;;        | (:for   :var NAME :start expr :end expr :body (stmt …))
;;;        | (:break) | (:continue)
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

;;; ========== struct-decl normalization ==========

(defun ctype-size (name star-count)
  "Byte-width of a C primitive `type-name' with STAR-COUNT pointer
   stars. Pointers are 8 bytes (we target 64-bit kernels). Returns
   NIL for an unrecognised name so the caller can decide what to do."
  (cond
    ((> star-count 0) 8)
    ((or (string= name "char") (string= name "uint8") (string= name "int8")
         (string= name "u8")   (string= name "s8")   (string= name "bool")
         (string= name "uint8_t") (string= name "int8_t"))
     1)
    ((or (string= name "short") (string= name "uint16") (string= name "int16")
         (string= name "u16")   (string= name "s16")
         (string= name "uint16_t") (string= name "int16_t"))
     2)
    ((or (string= name "int")    (string= name "uint32") (string= name "int32")
         (string= name "u32")    (string= name "s32")    (string= name "unsigned")
         (string= name "uint32_t") (string= name "int32_t"))
     4)
    ((or (string= name "long")   (string= name "uint64") (string= name "int64")
         (string= name "u64")    (string= name "s64")    (string= name "size_t")
         (string= name "ssize_t") (string= name "ptrdiff_t")
         (string= name "uint64_t") (string= name "int64_t"))
     8)
    (t nil)))

(defun count-star-children (node)
  "Number of literal `*' tokens in NODE's children — iparse keeps
   un-tagged terminal strings, so a field-type with N stars has N
   `*' atoms in its child list."
  (loop for c in (children-of node)
        count (and (stringp c) (string= c "*"))))

(defun field-type-info (ftype-node)
  "Extract (TYPE-NAME-STRING STAR-COUNT) from a :field-type subtree.
   The subtree's child is :struct-ref, :struct-embed, or :plain-type.
   For struct-ref / struct-embed we report `struct N' and pointer
   star count from the trailing stars; for plain-type we use the
   type-name atom plus stars. The size-and-name view is enough for
   the codegen — we don't try to walk embedded struct layouts here."
  (let* ((inner (find-if #'consp (children-of ftype-node))))
    (case (tag-of inner)
      (:plain-type
       (let* ((name-node (first-tagged inner :type-name))
              (name      (text-of (first-tagged name-node :ident)))
              (stars     (count-star-children inner)))
         (values name stars)))
      (:struct-ref
       (let* ((name (text-of (first-tagged inner :ident)))
              (stars (count-star-children inner)))
         (values (concatenate 'string "struct " name) stars)))
      (:struct-embed
       (let ((name (text-of (first-tagged inner :ident))))
         (values (concatenate 'string "struct " name) 0))))))

(defun norm-struct-decl (node)
  "Parse a `struct NAME { fields… };' top-level decl into an entry on
   *script-struct-decls*. Fields are walked in order, byte-aligned
   to their element width (a simplified C natural-alignment model
   that's correct for power-of-two scalar widths). The total struct
   size pads up to the largest field width."
  (let* ((name (text-of (first-tagged node :ident)))
         (raw-fields (all-tagged node :struct-field))
         (offset 0)
         (max-align 1)
         (fields nil))
    (dolist (f raw-fields)
      (let* ((ftype-node (first-tagged f :field-type))
             (ident-node (first-tagged f :ident))
             (arr-nodes  (all-tagged f :field-array-suffix))
             (arr-dims   (when arr-nodes
                           (mapcar (lambda (n)
                                     (parse-integer
                                      (text-of (first-tagged n :integer))))
                                   arr-nodes)))
             ;; Total element count for size purposes. For a scalar
             ;; field (no `[N]'), arr-dims is NIL and arr-len is NIL.
             (arr-len    (and arr-dims (reduce #'* arr-dims))))
        (multiple-value-bind (type-str stars) (field-type-info ftype-node)
          ;; Strip a leading `struct ' for the size lookup — plain
          ;; `int', `char' etc. resolve directly; bare struct types
          ;; we can't size precisely without nested-layout work, so
          ;; we record a size of 0 (and the codegen will refuse
          ;; field access on it).
          (let* ((base-name (if (and (>= (length type-str) 7)
                                     (string= type-str "struct " :end1 7))
                                (subseq type-str 7)
                                type-str))
                 (base-size (or (ctype-size base-name stars) 0))
                 ;; Natural alignment up to element width.
                 (align     (max 1 base-size))
                 (aligned   (if (zerop align) offset
                                (* align (ceiling offset align))))
                 (slot-size (* base-size (or arr-len 1))))
            ;; 7th slot (STARS) preserves the pointer indirection
            ;; count so `*((struct C*)e).z[i]' can size the deref
            ;; from the underlying base type rather than the pointer
            ;; itself.
            (push (list (text-of ident-node)
                        base-size aligned arr-len type-str arr-dims
                        stars)
                  fields)
            (setf offset (+ aligned slot-size))
            (setf max-align (max max-align align))))))
    (let* ((total-size (if (zerop max-align)
                           offset
                           (* max-align (ceiling offset max-align))))
           (entry (list* name total-size (nreverse fields))))
      (push entry *script-struct-decls*))))

(defun norm-enum-decl (node)
  "Parse an `enum [NAME] { K1 [= V1], K2, … };' top-level decl into
   entries on *script-enum-values*. Members without `= N' follow C
   auto-increment: first auto = 0, subsequent auto = previous + 1.
   Hex literals (0xFF) and decimals both accepted; we strip the
   leading 0x and parse with the explicit radix."
  (let ((members-node (first-tagged node :enum-members)))
    (unless members-node (return-from norm-enum-decl nil))
    (loop with auto = 0
          for m in (all-tagged members-node :enum-member)
          for name = (text-of (first-tagged m :ident))
          for hex  = (first-tagged m :hex-int)
          for dec  = (first-tagged m :integer)
          for value = (cond
                        (hex (parse-integer (text-of hex)
                                            :start 2 :radix 16))
                        (dec (parse-integer (text-of dec)))
                        (t auto))
          do (pushnew (cons name value) *script-enum-values*
                      :test #'equal :key #'car)
             (setf auto (1+ value)))))

(defun resolve-unroll-count (expr-node)
  "Resolve unroll(N)'s count argument at AST time. Accepts a literal
   integer (`unroll(10)') or a `$N' positional (`unroll($1)') — the
   latter looks up *positional-args* and parses the argv token. Any
   other shape returns NIL so the caller can error."
  (cond
    ((not expr-node) nil)
    ;; A bare integer parse-tree node — `unroll(10)'.
    ((and (consp expr-node)
          (find-if (lambda (c)
                     (and (consp c) (eq (tag-of c) :integer)))
                   (children-of expr-node)
                   :key (constantly nil)))
     nil)
    (t
     ;; Normalize the expr and inspect the resulting AST.
     (let ((normalized (norm-expr-dispatch expr-node)))
       (cond
         ((and (consp normalized) (eq (first normalized) :int))
          (second normalized))
         ((and (consp normalized) (eq (first normalized) :positional))
          (let* ((n   (second normalized))
                 (tok (and (boundp '*positional-args*)
                           (nth (1- n) (symbol-value '*positional-args*)))))
            (and tok (parse-integer tok :junk-allowed t))))
         (t nil))))))

;;; ========== Main entry ==========

(defun parse-config-body (body)
  "Split a config-block body string into an alist of (NAME . VALUE)
   pairs. Entries are KEY=VALUE separated by `;' or newlines; surrounding
   whitespace is trimmed. bpftrace docs say `BPFTRACE_FOO', `FOO',
   and `foo' are equivalent — we downcase NAME and drop any leading
   `bpftrace_' prefix so the runtime only has to look one form up."
  (let ((out nil))
    (dolist (raw (loop with acc = nil and start = 0
                       for i from 0 below (length body)
                       when (or (char= (char body i) #\;)
                                (char= (char body i) #\newline))
                         do (push (subseq body start i) acc)
                            (setf start (1+ i))
                       finally (push (subseq body start) acc)
                               (return (nreverse acc))))
      (let* ((s (string-trim '(#\Space #\Tab #\Newline #\Return) raw))
             (eq (position #\= s)))
        (when (and (plusp (length s)) eq)
          (let* ((k (string-downcase
                     (string-trim '(#\Space #\Tab) (subseq s 0 eq))))
                 (v (string-trim '(#\Space #\Tab) (subseq s (1+ eq))))
                 (k* (if (and (> (length k) 9)
                              (string= k "bpftrace_" :end1 9))
                         (subseq k 9)
                         k)))
            (push (cons k* v) out)))))
    (nreverse out)))

(defvar *script-config* nil
  "Alist of (KEY . VALUE-STRING) pairs collected from any `config = {…}'
   block(s) in the current script. Bound by NORMALIZE so codegen and
   compile-script can pick the values up.")

(defvar *script-struct-decls* nil
  "Alist mapping struct names declared at script top-level (`struct
   NAME { … };') to their parsed body. Each entry is
     (NAME . ((FIELD-NAME ELT-SIZE OFFSET ARRAY-LEN-OR-NIL TYPE-STRING) …))
   where ELT-SIZE is the per-element byte width, OFFSET is the byte
   offset of the field within the struct, and ARRAY-LEN is the array
   length when the field was declared `T x[N]' (NIL for scalar). TYPE-
   STRING is the raw type token for diagnostics. Codegen consults
   this before falling back to vmlinux BTF in lower-struct-pointer-
   field, offsetof, and sizeof. Bound by NORMALIZE.")

(defvar *script-enum-values* nil
  "Alist mapping bare enum-member names (`ONE', `TWO', …) declared at
   script top-level via `enum [NAME] { … };' to their integer value.
   Members without explicit values follow C's auto-increment rule:
   first auto = 0, subsequent auto = previous + 1. Codegen's
   resolve-constant consults this before failing with `unknown
   identifier'. Bound by NORMALIZE.")

(defun normalize (raw)
  "Convert the iparse parse tree RAW into the typed AST, then apply
   post-parse rewrites (auto-prepend pid to ustack-keyed maps).
   Top-level forms may be probes or function definitions; both are
   collected into the (:script ...) list. Config blocks contribute to
   *script-config* rather than the script body."
  (assert (eq (tag-of raw) :script) (raw) "expected :SCRIPT root, got ~S" (tag-of raw))
  (setf *script-config* nil)
  (setf *script-struct-decls* nil)
  (setf *script-enum-values* nil)
  (rewrite-ustack-pids
   (cons :script
         (loop for top in (all-tagged raw :top-form)
               for inner = (find-if #'consp (children-of top))
               for result = (case (tag-of inner)
                              (:probe        (norm-probe inner))
                              (:function     (norm-function inner))
                              (:macro-decl   (norm-macro inner))
                              (:config-block
                               (let* ((body-node (first-tagged inner :config-body))
                                      (body (and body-node (text-of body-node))))
                                 (when body
                                   (setf *script-config*
                                         (append *script-config*
                                                 (parse-config-body body)))))
                               nil)
                              (:struct-decl
                               (norm-struct-decl inner)
                               nil)
                              (:enum-decl
                               (norm-enum-decl inner)
                               nil)
                              (:union-decl   nil)  ; accept-and-ignore
                              (:import-decl  nil)  ; accept-and-ignore
                              (:map-decl     nil)  ; accept-and-ignore
                              (t (error "unexpected top-form: ~S"
                                        (tag-of inner))))
               when result collect it))))

(defun norm-function (node)
  "Convert a function definition into (:function :name … :params (…) :body (…)).
   Function params are always written `$name'; we store them as \"$name\"
   to match the substitution dispatch in codegen.lisp."
  (let* ((name-node  (first-tagged node :ident))
         (params-node (first-tagged node :param-list))
         (block-node  (first-tagged node :block))
         (params (when params-node
                   (loop for p in (all-tagged params-node :param)
                         collect (concatenate 'string "$"
                                              (text-of (first-tagged p :ident)))))))
    (list :function
          :name (text-of name-node)
          :params params
          :body (norm-block block-node))))

(defun norm-macro (node)
  "Convert a `macro NAME(params) { body }' declaration into the same
   shape as :function so the codegen can reuse the user-fn inline path.
   Each param is rendered with its sigil — \"$name\", \"@name\", or
   bare \"name\" — so substitute-vars can dispatch unambiguously:
   `$name' params match (:var NAME) only, bare `name' params match
   (:constant NAME) / (:builtin :NAME), and `@name' params match
   (:map :name NAME …)."
  (let* ((name-node   (first-tagged node :ident))
         (params-node (first-tagged node :macro-param-list))
         (block-node  (first-tagged node :block))
         (params
           (when params-node
             (loop for p in (all-tagged params-node :macro-param)
                   for ident = (text-of (first-tagged p :ident))
                   for raw   = (text-of p)
                   for sigil = (cond ((zerop (length raw)) #\Space)
                                     ((char= (char raw 0) #\@) #\@)
                                     ((char= (char raw 0) #\$) #\$)
                                     (t nil))
                   collect (case sigil
                             (#\@ (concatenate 'string "@" ident))
                             (#\$ (concatenate 'string "$" ident))
                             (t   ident))))))
    (list :macro
          :name (text-of name-node)
          :params params
          :body (norm-block block-node))))

;;; ========== Post-parse: auto-prepend pid to ustack keys ==========
;;;
;;; bpftrace's `@[ustack]++' is only useful when paired with a pid —
;;; symbolisation needs to know which process produced the stack, and
;;; in a multi-pid system different processes have different memory
;;; maps. We silently rewrite any @-map access whose :keys contain
;;; :ustack without :pid/:tid into @[pid, …]: the user gets per-process
;;; symbolised output without having to remember the convention.

(defun ustack-key-p (k) (and (consp k) (eq (first k) :ustack)))
(defun pid-or-tid-key-p (k)
  (and (consp k) (eq (first k) :builtin)
       (member (second k) '(:pid :tid))))

(defun rewrite-map-keys (keys)
  "If KEYS contain :ustack and don't already include :pid/:tid,
   prepend (:builtin :pid). Otherwise return as-is."
  (if (and (some #'ustack-key-p keys)
           (not (some #'pid-or-tid-key-p keys)))
      (cons '(:builtin :pid) keys)
      keys))

(defun rewrite-ustack-pids (form)
  "Walk FORM recursively; for every :map node with naked :ustack
   keys, auto-prepend (:builtin :pid)."
  (cond
    ((not (consp form)) form)
    ((eq (first form) :map)
     (let ((new-keys (rewrite-map-keys (getf (cdr form) :keys))))
       (list* :map
              :name (getf (cdr form) :name)
              :keys (mapcar #'rewrite-ustack-pids new-keys)
              (loop for (k v) on (cdr form) by #'cddr
                    unless (member k '(:name :keys))
                      append (list k v)))))
    (t (mapcar #'rewrite-ustack-pids form))))

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
      (:bench-spec
       ;; Accept the syntax; treat as a BEGIN-style userspace probe
       ;; until the real --mode bench runner lands. The body
       ;; still compiles through gen-kernel-prog so most scripts
       ;; advance past parse and emit instructions.
       (list :begin))
      (:rawtracepoint-spec
       ;; rawtracepoint:NAME attaches via BPF_PROG_TYPE_RAW_TRACEPOINT —
       ;; a different program type and load path from kprobes. Silently
       ;; routing through :kprobe would attach to a kprobe-shaped slot
       ;; that doesn't exist for the named tracepoint, mis-instrumenting
       ;; or failing opaquely. Reject until the raw-tp loader lands.
       (unsupported "rawtracepoint probes are not yet supported"))
      (:kprobe-spec
       ;; `kprobe:[MODULE:]NAME[+OFFSET]'. Until module routing and
       ;; offset attachment are implemented, reject both forms instead
       ;; of silently dropping them — attaching the wrong symbol or
       ;; missing an intended offset is worse than refusing the script.
       (let ((idents (all-tagged inner :glob-ident)))
         (when (> (length idents) 1)
           (unsupported "kprobe: module qualifier ~S not yet supported"
                        (text-of (first idents))))
         (when (first-tagged inner :kprobe-offset)
           (unsupported "kprobe: `+OFFSET' suffix not yet supported"))
         (list :kprobe (text-of (first idents)))))
      (:kretprobe-spec
       (let ((idents (all-tagged inner :glob-ident)))
         (when (> (length idents) 1)
           (unsupported "kretprobe: module qualifier ~S not yet supported"
                        (text-of (first idents))))
         (list :kretprobe (text-of (first idents)))))
      ;; kfunc[:MODULE]:funcname — the optional module qualifier routes
      ;; the BTF lookup to that module's BTF blob instead of vmlinux.
      ;; Until that's wired in, reject rather than silently bind to the
      ;; vmlinux symbol of the same name.
      (:kfunc-spec
       (let ((idents (all-tagged inner :ident)))
         (when (> (length idents) 1)
           (unsupported "kfunc: module qualifier ~S not yet supported"
                        (text-of (first idents))))
         (list :kfunc (text-of (first idents)))))
      (:kretfunc-spec
       (let ((idents (all-tagged inner :ident)))
         (when (> (length idents) 1)
           (unsupported "kretfunc: module qualifier ~S not yet supported"
                        (text-of (first idents))))
         (list :kretfunc (text-of (first idents)))))
      (:uprobe-spec
       (list :uprobe
             (text-of (first-tagged inner :upath))
             (text-of (first-tagged inner :ident))))
      (:uretprobe-spec
       (list :uretprobe
             (text-of (first-tagged inner :upath))
             (text-of (first-tagged inner :ident))))
      (:tracepoint-spec
       (let ((idents (all-tagged inner :glob-ident)))
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
               :count (parse-integer (text-of count-node)))))
      (:self-spec
       ;; self:signal:SIGNAME — userspace-only probe. Carry the
       ;; signal name verbatim ("SIGUSR1" etc.); runtime resolves
       ;; the int via SB-POSIX:SIGUSR1 / friends.
       (list :self :signal (text-of (first-tagged inner :ident)))))))

;;; ========== Statements ==========

(defun norm-block (node)
  (when node
    (let ((stmts-node (first-tagged node :statements)))
      (when stmts-node
        (loop for s in (all-tagged stmts-node :statement)
              for normalized = (norm-statement s)
              if (and (consp normalized) (eq (first normalized) :seq))
                append (rest normalized)
              else
                collect normalized)))))

(defun norm-statement (node)
  (let ((inner (first (remove-if-not #'consp (children-of node)))))
    (ecase (tag-of inner)
      (:if-stmt      (norm-if inner))
      (:while-stmt
       (let* ((kids (remove-if-not #'consp (children-of inner)))
              (cond-expr (norm-expr-or-expr-wrapped (first kids)))
              (body      (norm-block (second kids))))
         (list :while :cond cond-expr :body body)))
      (:unroll-stmt
       ;; Compile-time loop unroller: emit the body N times. N must
       ;; be a literal integer or a `$1' positional resolved at norm
       ;; time against *positional-args*. Returns a `(:seq …)' sentinel
       ;; that norm-block splices into the surrounding list.
       (let* ((expr-node  (first (loop for c in (children-of inner)
                                       when (and (consp c)
                                                 (not (member (tag-of c)
                                                              '(:block))))
                                         collect c)))
              (n          (resolve-unroll-count expr-node))
              (block-node (first-tagged inner :block))
              (body       (norm-block block-node)))
         (unless n
           (error "unroll(N): N must be a literal integer or $N positional"))
         (cons :seq
               (loop repeat n append (copy-tree body)))))
      (:for-stmt
       (let* ((ident-node (first-tagged inner :ident))
              (name       (text-of ident-node))
              (block-node (first-tagged inner :block))
              (iter-node  (first-tagged inner :for-iter)))
         (cond
           ;; `for $kv : @m { … }' — map iteration. The for-iter
           ;; alternative produced a single :map-access child.
           ((and iter-node
                 (let ((kids (children-of iter-node)))
                   (and kids (= 1 (length kids))
                        (eq (tag-of (first kids)) :map-access))))
            ;; Use :over (not :map) for the iterated map AST — the
            ;; downstream expand-tuple-vars walker matches `:map' as
            ;; a node tag and would mis-fire on this plist key.
            (list :for-each
                  :var name
                  :over (norm-map-access (first (children-of iter-node)))
                  :body (norm-block block-node)))
           ;; Range form `for $i : start..end { … }'.
           (t
            (let ((exprs (loop for c in (and iter-node (children-of iter-node))
                               when (and (consp c)
                                         (not (member (tag-of c)
                                                      '(:ident :block))))
                                 collect c)))
              (list :for
                    :var name
                    :start (norm-expr-or-expr-wrapped (first exprs))
                    :end   (norm-expr-or-expr-wrapped (second exprs))
                    :body  (norm-block block-node)))))))
      (:break-stmt    '(:break))
      (:continue-stmt '(:continue))
      (:let-stmt
       ;; let $x;             → no-op (drop)
       ;; let $x : TYPE;      → no-op (drop the type annotation)
       ;; let $x = expr;      → (:assign (:var "x") := expr)
       ;; let $x : TYPE = expr; → ditto, type annotation dropped.
       (let* ((ident-node (first-tagged inner :ident))
              (name       (text-of ident-node))
              (rhs        (find-if (lambda (c)
                                     (and (consp c)
                                          (not (member (tag-of c)
                                                       '(:ident :let-type
                                                         :let-type-prim)))))
                                   (children-of inner))))
         (cond
           (rhs (list :assign
                      :lhs (list :var name)
                      :op  :=
                      :rhs (norm-expr-or-expr-wrapped rhs)))
           (t (list :let-noop)))))
      (:return-stmt
       (let ((expr-node (find-if (lambda (c) (and (consp c)
                                                  (not (eq (tag-of c) :ident))))
                                 (children-of inner))))
         (list :return :expr (when expr-node
                               (norm-expr-or-expr-wrapped expr-node)))))
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
      (:scalar-var (list :var (text-of (first-tagged inner :ident))))
      (:wildcard-lhs (list :discard)))))

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
         (prefix-node (find-if (lambda (c)
                                 (and (consp c) (eq (tag-of c) :prefix-incdec)))
                               kids))
         (arg-node (find-if (lambda (c)
                              (and (consp c)
                                   (not (member (tag-of c)
                                                '(:unary-op :prefix-incdec)))))
                            kids)))
    (cond
      (prefix-node
       (list :incdec-expr :lhs (norm-expr-dispatch arg-node)
             :op (if (string= (text-of prefix-node) "++") :inc :dec)
             :form :pre))
      (op-node
       (list :un :op (op->kw (text-of op-node))
             :arg (norm-expr-dispatch arg-node)))
      (t (norm-expr-dispatch arg-node)))))

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
                  (:field-access
                   ;; .ident or .NUMBER (tuple-component access).
                   (let ((idx (first-tagged inner :tuple-index)))
                     (list :field :base acc
                           :name (text-of (or idx
                                              (first-tagged inner :ident))))))
                  (:arrow-access (list :field :base acc
                                       :name (text-of (first-tagged inner :ident))))
                  (:index-access (list :index :base acc
                                       :keys (mapcar #'norm-expr-dispatch
                                                     (remove-if-not
                                                      #'consp
                                                      (children-of inner)))))
                  (:postfix-incdec
                   (list :incdec-expr :lhs acc :op
                         (if (string= (text-of inner) "++") :inc :dec)
                         :form :post)))))
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
      (:scalar-var
       (let ((pos-node (first-tagged inner :positional-var)))
         (if pos-node
             (list :positional (parse-integer (text-of pos-node)))
             (list :var (text-of (first-tagged inner :ident))))))
      (:block-expr
       ;; { stmt; stmt; ... expr } — collect leading statements,
       ;; take the trailing unterminated expr as the block's value.
       ;; Codegen lowers this to a `(progn stmts… final)' form.
       (let* ((pres  (all-tagged inner :block-expr-pre))
              (stmts (mapcar (lambda (p)
                               (norm-statement (first-tagged p :statement)))
                             pres))
              (final-expr-node (first-tagged inner :expr)))
         (list :block-expr
               :stmts (remove nil stmts)
               :final (norm-expr-or-expr-wrapped final-expr-node))))
      (:builtin      (norm-builtin inner))
      (:builtin-name (norm-builtin inner)) ; if parens stripped
      (:cast
       (let* ((type-name (text-of (first-tagged inner :ident)))
              (sub-primary (find-if (lambda (c)
                                      (and (consp c)
                                           (not (eq (tag-of c) :ident))))
                                    (children-of inner))))
         (list :cast :type type-name
               :expr (norm-expr-dispatch sub-primary))))
      (:primitive-cast
       ;; (uint64)x, (int)x, (int8)x — preserved as `:int-cast' so
       ;; width-sensitive ops (bswap, sizeof imprecision) can peek
       ;; at the type. All values are u64 in the IR; lower-expr
       ;; just lowers the inner expr.
       (let* ((type (text-of (first-tagged inner :int-type-name)))
              (sub  (find-if (lambda (c)
                               (and (consp c)
                                    (not (eq (tag-of c) :int-type-name))))
                             (children-of inner))))
         (list :int-cast :type type :expr (norm-expr-dispatch sub))))
      (:enum-cast
       ;; `(enum NAME)EXPR' — preserved as an :enum-cast so the
       ;; printf-arg-type path can emit an :enum-typed slot. lower-
       ;; expr just lowers the inner expression (value flows as u64).
       (let* ((name (text-of (first-tagged inner :ident)))
              (sub  (find-if (lambda (c)
                               (and (consp c)
                                    (not (eq (tag-of c) :ident))))
                             (children-of inner))))
         (list :enum-cast :name name :expr (norm-expr-dispatch sub))))
      (:primitive-pointer-cast
       ;; (int32 *)x — the element type IS load-bearing: codegen needs
       ;; it to size `$v[i]' reads. We preserve it as :prim-ptr-cast
       ;; so the `:assign' lowering can record the element type on $v
       ;; in *var-types*, and `:index' lowering can consult it later.
       (let* ((type-name (text-of (first-tagged inner :int-type-name)))
              (sub (find-if (lambda (c)
                              (and (consp c)
                                   (not (eq (tag-of c) :int-type-name))))
                            (children-of inner))))
         (list :prim-ptr-cast :elt-type type-name
               :expr (norm-expr-dispatch sub))))
      (:int-array-cast
       ;; `(int8[N])X' / `(int8[])X' — reinterpret X's u64 value as a
       ;; little-endian byte array of element type INT-TYPE and length
       ;; N (or, when N is omitted, sizeof(int-type) elements covering
       ;; the natural width of X). Codegen needs (elt-type, length)
       ;; so subscript reads pull the right byte.
       (let* ((type-name (text-of (first-tagged inner :int-type-name)))
              (int-node  (first-tagged inner :integer))
              (len       (when int-node
                           (parse-integer (text-of int-node))))
              (sub (find-if (lambda (c)
                              (and (consp c)
                                   (not (member (tag-of c)
                                                '(:int-type-name :integer)))))
                            (children-of inner))))
         (list :int-array-cast :elt-type type-name :len len
               :expr (norm-expr-dispatch sub))))
      (:constant     (list :constant
                           (text-of (first-tagged inner :ident))))
      (:string-lit   (list :str (strip-quotes (text-of inner))))
      (:tuple
       (list :tuple
             :items (mapcar #'norm-expr-or-expr-wrapped
                            (remove-if-not
                             (lambda (c)
                               (and (consp c) (not (eq (tag-of c) :ident))))
                             (children-of inner)))))
      (:offsetof-expr
       (let* ((idents (mapcar #'text-of (all-tagged inner :ident))))
         (list :offsetof :struct (first idents) :field (second idents))))
      (:sizeof-expr
       ;; Grammar wraps the inner alternative as either :sizeof-struct
       ;; (with the `struct' keyword consumed), :sizeof-type, or
       ;; :sizeof-value (any expression). For the value form we
       ;; fold to 8 (all values are u64 in our IR) at AST time.
       (let* ((value-node (first-tagged inner :sizeof-value)))
         (if value-node
             (list :int 8)
             (let* ((sub  (or (first-tagged inner :sizeof-struct)
                              (first-tagged inner :sizeof-type)))
                    (ident (and sub (text-of (first-tagged sub :ident)))))
               (list :sizeof :name ident
                     :struct-p (and sub (eq (tag-of sub) :sizeof-struct)))))))
      (:hex-int      (list :int (parse-integer (text-of inner) :start 2 :radix 16)))
      (:integer      (list :int (parse-integer-with-exp (text-of inner))))
      (:duration-literal
       ;; `100ms', `5us', `1s', `1ns' → integer nanoseconds.
       (let* ((n (parse-integer-with-exp
                  (text-of (first-tagged inner :integer))))
              (unit (text-of (first-tagged inner :duration-unit))))
         (list :int (* n (cond ((string= unit "ns")  1)
                               ((string= unit "us")  1000)
                               ((string= unit "ms")  1000000)
                               ((string= unit "s")   1000000000))))))
      (t (error "unexpected primary: ~S" inner)))))

(defun parse-integer-with-exp (s)
  "Parse \"NNNN\" or \"NNNNeMM\" as an integer (mantissa × 10^MM)."
  (let ((e (or (position #\e s) (position #\E s))))
    (if e
        (* (parse-integer s :end e)
           (expt 10 (parse-integer s :start (1+ e))))
        (parse-integer s))))

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
      ((string= name "pcomm")   '(:pcomm))
      ((string= name "probe")   '(:probe-name))
      ((string= name "func")    '(:func))
      ((string= name "curtask") '(:curtask))
      ((string= name "kstack")  '(:kstack))
      ((string= name "ustack")  '(:ustack))
      ((and (>= (length name) 4) (string= (subseq name 0 3) "arg")
            (digit-char-p (char name 3)))
       (list :arg (parse-integer (subseq name 3))))
      (t (list :builtin (intern (string-upcase name) :keyword))))))
