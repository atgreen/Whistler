;;; codegen.lisp — AST → Whistler forms
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Two passes:
;;;   1. INFER-MAPS walks every probe body, classifies each `@name` by
;;;      how it's written, and assembles a map-info table.
;;;   2. GEN-PROBE emits a (whistler:defprog …) form per kernel probe.
;;;
;;; BEGIN, END and interval probes don't compile to BPF — they run
;;; userspace-only and are returned in the :user-probes plist key so
;;; the runtime can fire them at the right time.

(in-package #:whistler/bpftrace)

;;; ========== Symbols & names ==========

(defun w-sym (name)
  "Intern NAME into the WHISTLER package, dashes for underscores."
  (intern (string-upcase (substitute #\- #\_ name)) :whistler))

(defun var-sym (name)
  "Intern a $-variable name (used inside defprog bodies)."
  (intern (string-upcase (concatenate 'string "$" name)) :whistler))

;;; ========== Map inference ==========

(defstruct minfo
  name             ; whistler symbol (defmap name)
  raw-name         ; original bpftrace name or NIL for anonymous
  kind             ; :counter | :scalar | :hist | :lhist
  key-size         ; bytes (set by inference; 0 if scalar-only)
  value-size       ; bytes
  max-entries
  key-builtin      ; hint for printing; :pid / :arg / NIL
  key-types        ; for composite keys: list of one keyword per slot
                   ;   (e.g. (:pid :ustack) for @[pid, ustack]).
                   ;   NIL for scalar single-slot keys.
  keyed-p          ; T iff any access used [keys]. Scalar-only `@m =`
                   ;   maps stay NIL so the printer skips the `[…]`.
  value-string-p   ; T when the value slot is a NUL-padded string of
                   ;   `value-size' bytes (set by inference from a
                   ;   string-typed RHS — :str / :func / :probe-name).
  value-struct     ; struct name (string) when the map stores a struct
                   ;   pointer — `@m[k] = (struct sk_buff *)x' lets us
                   ;   propagate the type to `\$v = @m[k]` reads.
  value-ntop-p     ; T when the value slot is a 17-byte ntop record
                   ;   (1 family + 16 address bytes). Triggered by
                   ;   `@m[k] = ntop(…)' inference.
  hist-params)     ; for :lhist, the list (MIN MAX STEP); NIL otherwise.

(defun builtin-size (kw)
  (case kw
    ((:pid :tid :uid :gid :cpu) 4)
    (t 8)))

(defvar *tp-field-sizes* nil
  "Hash table FIELD-NAME (string) → byte size, populated once per
   generate() from every tracepoint format file referenced by the
   script. NIL outside generate().")

(defun load-tracepoint-field-sizes (script)
  "Walk SCRIPT, parse each referenced tracepoint format file, and
   build *TP-FIELD-SIZES*: name → (size . array-size). Skips silently
   if a format file can't be read — the caller falls back to a
   default size. array-size > 0 marks a char[]/u8[]-style field."
  (let ((table (make-hash-table :test 'equal)))
    (dolist (probe (script-probes script))
      (dolist (spec (getf (cdr probe) :specs))
        (when (eq (first spec) :tracepoint)
          (let* ((cat (substitute #\_ #\- (second spec)))
                 (event (substitute #\_ #\- (third spec)))
                 (path (ignore-errors
                        (whistler::find-tracepoint-format-path cat event))))
            (when path
              (dolist (field (ignore-errors
                              (whistler::parse-tracepoint-format
                               (namestring path))))
                (destructuring-bind (c-name _off size _signed array) field
                  (declare (ignore _off _signed))
                  (setf (gethash c-name table)
                        (cons size (or array 0))))))))))
    table))

(defun tp-field-size (name)
  "Tracepoint args.FIELD width in bytes, or NIL if unknown."
  (let ((cell (and *tp-field-sizes* (gethash name *tp-field-sizes*))))
    (cond
      ((consp cell) (car cell))
      ((integerp cell) cell)
      (t nil))))

(defun tp-array-size (name)
  "If tracepoint args.FIELD is an array, return its element count;
   otherwise 0 / NIL."
  (let ((cell (and *tp-field-sizes* (gethash name *tp-field-sizes*))))
    (cond ((consp cell) (cdr cell)) (t 0))))

(defun str-key-size (expr)
  "Size (in bytes) of a str()/kstr() call when used as a map key —
   the explicit second arg, or +bt-str-default-len+ when omitted."
  (let* ((args (getf (cdr expr) :args))
         (n    (when (and (cdr args) (eq (first (second args)) :int))
                 (second (second args)))))
    (or n +bt-str-default-len+)))

(defconstant +bt-func-name-key-len+ 64
  "Fixed slot width for a `func' or `probe' builtin used as a map
   key. The biggest kernel function name in /proc/kallsyms tends to
   sit comfortably under 64 bytes; bpftrace itself uses the same
   default.")

(defun expr-size (expr)
  "Best-effort byte-size for EXPR when used as a map key. Must match
   what the lowering will store on the stack — a mismatch trips the
   BPF verifier with `invalid read from stack`."
  (case (first expr)
    (:int     8)
    (:builtin (builtin-size (second expr)))
    (:arg     8)
    (:retval  8)
    (:var     8)
    (:bin     8)
    (:comm    16)
    (:func        +bt-func-name-key-len+)
    (:probe-name  +bt-func-name-key-len+)
    (:kstack  4)
    (:ustack  4)
    (:call
     (cond
       ((or (str-call-p expr) (kstr-call-p expr)) (str-key-size expr))
       (t 8)))
    (:field
     (let ((name (getf (cdr expr) :name)))
       (cond
         ;; tracepoint args->FIELD: look up the real size from the
         ;; tracefs format file we parsed in load-tracepoint-field-sizes.
         ((and (consp (getf (cdr expr) :base))
               (eq (first (getf (cdr expr) :base)) :args)
               (tp-field-size name)))
         ;; Unknown: default to 4 (most sched/syscalls fields are u32).
         (t 4))))
    (t        8)))

(defun size->type (size)
  "Whistler integer type symbol for a 1/2/4/8-byte slot."
  (ecase size
    (1 (intern "U8"  :whistler))
    (2 (intern "U16" :whistler))
    (4 (intern "U32" :whistler))
    (8 (intern "U64" :whistler))))

(defun align-up (n alignment)
  (* alignment (ceiling n alignment)))

(defun composite-key-layout (keys)
  "Plan the on-stack layout for a composite map key. Every component
   takes a full u64 slot (zero-extending narrower types), giving total
   = 8*N bytes. This is wasteful but has three nice properties:

     * The buffer is always > 8 bytes for N ≥ 2, which trips whistler's
       struct-key-map-p test (`key-size > 8`) so getmap / setmap /
       remmap / incf-map auto-dispatch to map-lookup-ptr et al.
     * Every byte is initialized (BPF zero-extends u32/u16 stores into
       u64 registers), so the verifier won't reject the buffer for
       containing uninitialized bytes.
     * Two probes referencing the same composite key produce byte-
       identical layouts, so lookups match writes.

   Returns (values LAYOUT TOTAL-BYTES). Each layout entry is
   (OFFSET SIZE TYPE-SYM EXPR) — SIZE is 8 for plain values, 16 for
   `comm' (the only string-typed key today; the kernel fills the 16
   bytes via bpf_get_current_comm)."
  (let ((u64 (size->type 8))
        (u8  (size->type 1))
        (offset 0))
    (values
     (loop for e in keys
           for size = (cond
                        ((eq (first e) :comm) +bt-comm-len+)
                        ((or (eq (first e) :func)
                             (eq (first e) :probe-name))
                         +bt-func-name-key-len+)
                        ((or (str-call-p e) (kstr-call-p e))
                         (str-key-size e))
                        (t 8))
           for type = (cond
                        ((eq (first e) :comm) u8)
                        ((or (eq (first e) :func)
                             (eq (first e) :probe-name)) u8)
                        ((or (str-call-p e) (kstr-call-p e)) u8)
                        (t u64))
           collect (list offset size type e)
           do (incf offset size))
     offset)))

(defun key-hint (expr)
  (case (first expr)
    (:builtin (second expr))
    (:arg     :arg)
    (:retval  :retval)
    (:comm    :comm)
    (:func        :str)
    (:probe-name  :str)
    (:kstack  :kstack)
    (:ustack  :ustack)
    (:call    (cond ((or (str-call-p expr) (kstr-call-p expr)) :str)
                    (t nil)))
    (t        nil)))

(defun infer-maps (script)
  "Return a hash table RAW-NAME (or \"@\") → MINFO."
  (let ((table (make-hash-table :test 'equal)))
    (labels ((ensure (mref)
               (let* ((raw (getf (cdr mref) :name))
                      (key (or raw "@")))
                 (or (gethash key table)
                     (setf (gethash key table)
                           (make-minfo :name (w-sym (or raw "at"))
                                       :raw-name raw
                                       :kind :counter
                                       :key-size 0
                                       :value-size 8
                                       :max-entries 1024)))))
             (note-keys (mref)
               (let ((info (ensure mref))
                     (keys (getf (cdr mref) :keys)))
                 (when keys
                   (setf (minfo-keyed-p info) t)
                   ;; A single scalar key follows with-key's scalar
                   ;; path — the lowering stores it at its natural
                   ;; width via map-update (`expr-size'). Composite
                   ;; or string-typed keys (comm/str/kstr) go through
                   ;; the struct-key path where every slot is u64
                   ;; (or a wider byte buffer), so use the layout total.
                   (let ((total
                           (if (and (= (length keys) 1)
                                    (not (keys-need-ptr-ops-p keys)))
                               (expr-size (first keys))
                               (multiple-value-bind (_layout total)
                                   (composite-key-layout keys)
                                 (declare (ignore _layout))
                                 total))))
                     (setf (minfo-key-size info)
                           (max (minfo-key-size info) total)))
                   ;; Single-key: store the hint so the printer renders
                   ;; comm as ASCII, pid as bare decimal, etc.
                   (when (and (null (minfo-key-builtin info))
                              (= (length keys) 1))
                     (setf (minfo-key-builtin info) (key-hint (first keys))))
                   ;; Composite: track per-slot hints so the printer
                   ;; can dispatch on individual slots.
                   (when (and (null (minfo-key-types info))
                              (> (length keys) 1))
                     (setf (minfo-key-types info)
                           (mapcar #'key-hint keys))))))
             (note-rhs (mref rhs)
               (let ((info (ensure mref)))
                 (cond
                   ;; `@m[k] = (struct X *)expr' — remember the value
                   ;; type so a later `\$v = @m[k]' can flow X into
                   ;; *var-types* for chained field access.
                   ((and (consp rhs) (eq (first rhs) :cast))
                    (setf (minfo-value-struct info)
                          (getf (cdr rhs) :type)))
                   ;; `@m[k] = :str LITERAL' — direct string literal
                   ;; RHS. Size to hold the literal plus a NUL byte.
                   ((and (consp rhs) (eq (first rhs) :str))
                    (let* ((bytes (sb-ext:string-to-octets
                                   (second rhs) :external-format :utf-8))
                           (need (1+ (length bytes))))
                      (setf (minfo-kind info) :scalar
                            (minfo-value-string-p info) t
                            (minfo-value-size info)
                            (max (minfo-value-size info) need
                                 +bt-func-name-key-len+))))
                   ;; `@m[k] = func' / `= probe' — rewrite-self-refs
                   ;; will turn these into :str at lower time, but
                   ;; infer-maps runs first and needs to mark the
                   ;; value slot as a string so the right write path
                   ;; gets taken.
                   ((and (consp rhs)
                         (or (eq (first rhs) :func)
                             (eq (first rhs) :probe-name)))
                    (setf (minfo-kind info) :scalar
                          (minfo-value-string-p info) t
                          (minfo-value-size info)
                          (max (minfo-value-size info)
                               +bt-func-name-key-len+)))
                   ;; `@m[k] = comm' — store the current task's
                   ;; TASK_COMM_LEN-byte name. Same string-slot
                   ;; machinery as the :str case.
                   ((and (consp rhs) (eq (first rhs) :comm))
                    (setf (minfo-kind info) :scalar
                          (minfo-value-string-p info) t
                          (minfo-value-size info)
                          (max (minfo-value-size info) +bt-comm-len+)))
                   ;; `@m[k] = ntop(…)' — 17-byte family+address slot.
                   ;; The value-ntop-p flag drives a special read path
                   ;; that surfaces in printf as :ipv-any.
                   ((and (consp rhs) (eq (first rhs) :call)
                         (stringp (getf (cdr rhs) :name))
                         (string= (getf (cdr rhs) :name) "ntop"))
                    (setf (minfo-kind info) :scalar
                          (minfo-value-ntop-p info) t
                          (minfo-value-size info)
                          (max (minfo-value-size info)
                               +bt-ntop-slot-size+)))
                   ((and (consp rhs) (eq (first rhs) :call))
                    (let ((fn (getf (cdr rhs) :name)))
                      (cond
                        ((string= fn "count")
                         (setf (minfo-kind info) :counter))
                        ((string= fn "hist")
                         (setf (minfo-kind info) :hist
                               (minfo-key-size info) 4
                               (minfo-max-entries info) 64))
                        ((string= fn "lhist")
                         (let* ((args (getf (cdr rhs) :args))
                                (literal (lambda (n)
                                           (let ((a (nth n args)))
                                             (cond
                                               ((and a (eq (first a) :int)) (second a))
                                               (t (unsupported
                                                   "lhist() requires literal min/max/step (got ~S)" a))))))
                                (lo  (funcall literal 1))
                                (hi  (funcall literal 2))
                                (st  (funcall literal 3))
                                (n   (max 1 (floor (- hi lo) st))))
                           (setf (minfo-kind info) :lhist
                                 (minfo-key-size info) 4
                                 (minfo-max-entries info) (+ n 2)
                                 (minfo-hist-params info) (list lo hi st))))
                        ((string= fn "sum")
                         (setf (minfo-kind info) :sum))
                        ((string= fn "min")
                         (setf (minfo-kind info) :min
                               (minfo-value-size info) 16))
                        ((string= fn "max")
                         (setf (minfo-kind info) :max
                               (minfo-value-size info) 16))
                        ((string= fn "avg")
                         (setf (minfo-kind info) :avg
                               (minfo-value-size info) 16))
                        ((string= fn "stats")
                         (setf (minfo-kind info) :stats
                               (minfo-value-size info) 16)))))
                   (t (when (eq (minfo-kind info) :counter)
                        (setf (minfo-kind info) :scalar)))))))
      (labels
          ((scan-stmt (stmt)
             (case (first stmt)
               (:assign
                (let ((lhs (getf (cdr stmt) :lhs))
                      (rhs (getf (cdr stmt) :rhs)))
                  (when (eq (first lhs) :map)
                    (note-keys lhs)
                    (note-rhs lhs rhs))))
               (:incdec
                (let ((lhs (getf (cdr stmt) :lhs)))
                  (when (eq (first lhs) :map)
                    (note-keys lhs)
                    (setf (minfo-kind (ensure lhs)) :counter))))
               (:expr
                (let ((e (second stmt)))
                  (when (and (consp e) (eq (first e) :call)
                             (member (getf (cdr e) :name)
                                     '("delete" "clear" "zero")
                                     :test #'string=))
                    (let* ((args (getf (cdr e) :args))
                           (mref (first args)))
                      (when (and (consp mref) (eq (first mref) :map))
                        (cond
                          ((and (string= (getf (cdr e) :name) "delete")
                                (>= (length args) 2))
                           (note-keys
                            (list :map :name (getf (cdr mref) :name)
                                  :keys (rest args))))
                          (t (note-keys mref))))))))
               ;; Recurse into compound statements so map references
               ;; nested under if/while still get inferred.
               (:if
                (mapc #'scan-stmt (getf (cdr stmt) :then))
                (mapc #'scan-stmt (getf (cdr stmt) :else)))
               (:while
                (mapc #'scan-stmt (getf (cdr stmt) :body))))))
        (dolist (probe (script-probes script))
          (let ((body (getf (cdr probe) :body))
                (pred (getf (cdr probe) :predicate)))
            (when pred (when (eq (first pred) :map) (note-keys pred)))
            (mapc #'scan-stmt body))))
      ;; Histogram maps with no explicit user key always have 4-byte key.
      (loop for info being the hash-values of table
            when (or (eq (minfo-kind info) :hist)
                     (eq (minfo-kind info) :lhist))
              do (setf (minfo-key-size info) 4))
      table)))

;;; ========== Defmap forms ==========

(defun gen-defmap (info)
  (let ((mtype (case (minfo-kind info)
                 ((:hist :lhist)           :percpu-array)
                 ;; sum/min/max/avg use percpu-hash so concurrent
                 ;; updates from different CPUs don't race (no atomics
                 ;; needed; userspace reduces across CPUs at print time).
                 ((:sum :avg :stats :min :max) :percpu-hash)
                 (t                        :hash))))
    `(whistler:defmap ,(minfo-name info)
       :type ,mtype
       :key-size ,(cond ((eq mtype :percpu-array) 4)
                        (t (max 1 (minfo-key-size info))))
       :value-size ,(minfo-value-size info)
       :max-entries ,(or (minfo-max-entries info)
                         (if (eq mtype :percpu-array) 64 1024)))))

;;; ========== Expression lowering ==========

(defvar *probe-spec* nil)

(defvar *var-types* nil
  "Per-probe alist VAR-NAME → STRUCT-NAME. Populated from `$v =
   (struct X *)EXPR' assignments so later `$v.field' accesses can
   walk BTF for the right offsets without seeing the cast again.")

(defvar *tuple-vars* nil
  "Per-probe alist VAR-NAME → list-of-component-AST-nodes. Populated
   from `\$v = (e1, e2, …)' assignments so later \`@m[\$v]' accesses
   can expand into composite-key form \`@m[e1, e2, …]'.")

(defvar *ntop-vars* nil
  "Per-probe list of VAR-NAME strings whose value comes from `ntop(…)'.
   ntop conjures `a string typed value' that needs runtime-formatted
   v4/v6 rendering; we back the var with a 17-byte stack slot (1
   family byte + 16 address bytes) so the assignment can write either
   family and the matching `printf(\"%s\", \$v)' can emit the slot.")

(defvar *comm-vars* nil
  "Per-probe list of VAR-NAME strings whose value comes from `comm'
   or from a string-valued map. Each is backed by a TASK_COMM_LEN
   byte stack slot — \`printf(\"%s\", \$v)' copies the bytes directly,
   and comparisons against a string literal use byte-by-byte equality
   (same path as the existing bare-`comm' compare).")

(defvar *string-set-buf* nil
  "Per-probe scratch buffer symbol shared across all
   `gen-string-set' calls in the same probe. The BPF stack frame
   caps at 512 bytes, so populating a `\@reason' lookup table with
   8 × 64-byte literals (writeback.bt) would blow the budget if
   each gen-string-set allocated its own slot. Reusing one buffer
   means the writes overwrite a single 64-byte stack region.")

(defvar *string-set-buf-size* 0
  "Width of the buffer named by *string-set-buf*; equal to the
   largest string-typed value-size of any map referenced from the
   current probe. Sized at gen-kernel-prog setup time.")

(defconstant +bt-ntop-slot-size+ 17
  "1 byte family + 16 bytes address — covers both AF_INET and AF_INET6.")
(defvar *map-table* nil)

(defun lower-expr (expr)
  (ecase (first expr)
    (:int        (second expr))
    (:str        (second expr))
    (:offsetof
     (let* ((struct-name (getf (cdr expr) :struct))
            (field-name  (getf (cdr expr) :field))
            (vmbtf (whistler:ensure-vmlinux-btf))
            (tid (whistler:btf-find-struct vmbtf struct-name))
            (fields (and tid (whistler:btf-struct-fields vmbtf tid)))
            (cell (find field-name fields :test #'string= :key #'first)))
       (unless cell
         (unsupported "offsetof(struct ~A, ~A): no such field"
                      struct-name field-name))
       (third cell)))
    (:var        (var-sym (second expr)))
    (:builtin
     ;; bpftrace allows a zero-arg `macro' to be referenced bare —
     ;; `sysname' (no parens) means `sysname()'. If the name is a
     ;; registered macro/fn, inline it; otherwise fall through to
     ;; the builtin table.
     (let ((sname (string-downcase (symbol-name (second expr)))))
       (cond ((find-user-function sname)
              (inline-user-call sname nil))
             (t (lower-builtin (second expr))))))
    (:curtask    '(whistler::get-current-task))
    ;; A bare cast (no following ->) — just compute the underlying
    ;; expression. The type annotation is informational; meaningful
    ;; cast use is inside a (field :base (:cast …) :name ...) form,
    ;; which lower-field handles.
    (:cast       (lower-expr (getf (cdr expr) :expr)))
    (:constant   (or (resolve-constant (second expr))
                     ;; bpftrace allows zero-arg `macro' to be called
                     ;; bare — `sysname' (no parens) means `sysname()'.
                     ;; A bare lowercase ident that didn't resolve to
                     ;; a constant may still be a registered macro.
                     (and (find-user-function (second expr))
                          (inline-user-call (second expr) nil))
                     (unsupported "unknown identifier `~A' — not in BTF enums or curated #define table"
                                  (second expr))))
    (:arg        (lower-arg (second expr)))
    (:retval     (lower-retval))
    (:comm       (unsupported "comm only usable as printf arg or @map[comm] key"))
    (:kstack     `(whistler::get-stackid (whistler::ctx-ptr) ,*stacks-map-name* 0))
    ;; BPF_F_USER_STACK = 1 << 8 — flag tells the kernel to walk the
    ;; userspace stack of the current task instead of the kernel one.
    (:ustack     `(whistler::get-stackid (whistler::ctx-ptr) ,*stacks-map-name*
                                         ,(ash 1 8)))
    (:args       (unsupported "args without ->field"))
    (:probe-name (unsupported "probe builtin"))
    (:func       (unsupported "func builtin"))
    (:bin        (lower-bin expr))
    (:un         (lower-un expr))
    (:tern       (lower-tern expr))
    (:call       (lower-call expr))
    (:field      (lower-field expr))
    (:index      (unsupported "array indexing outside @maps"))
    (:map        (lower-map-read expr))))

;;; ========== Script top-form helpers ==========

(defun script-probes (script)
  "(rest script) filtered to :probe nodes — strips out :function defs."
  (remove-if-not (lambda (f) (and (consp f) (eq (first f) :probe)))
                 (rest script)))

(defun script-functions (script)
  "All inlineable user definitions — :function (`fn`) and :macro
   (`macro`). Both expand at call sites; macros additionally accept
   `@map'-prefixed parameters."
  (remove-if-not (lambda (f) (and (consp f)
                                  (or (eq (first f) :function)
                                      (eq (first f) :macro))))
                 (rest script)))

(defvar *user-functions* nil
  "Per-generate() alist NAME → (:params (…) :body (…)). User-defined
   `fn' definitions; lower-call inlines each call site.")

(defun find-user-function (name)
  (cdr (assoc name *user-functions* :test #'string=)))

;;; ========== Symbolic constants ==========
;;;
;;; bpftrace scripts routinely reference identifiers like AF_INET or
;;; O_RDONLY. We resolve them at codegen time from two sources:
;;;
;;;   1. Kernel BTF — every BTF_KIND_ENUM / ENUM64 member is interned
;;;      as a (name . value) pair on first access. Covers IPPROTO_*,
;;;      TCP_*, and the modern enum-ified families that the kernel has
;;;      moved over to BTF.
;;;
;;;   2. A curated table of POSIX/Linux #define constants that are
;;;      *not* in BTF (most of these live in libc/system headers as
;;;      preprocessor macros, not enums). Tiny — ~200 entries cover
;;;      what scripts in the wild actually reach for.

(defparameter *curated-constants*
  '(;; Socket address families
    ("AF_UNSPEC" . 0)  ("AF_UNIX" . 1)
    ("AF_INET" . 2)    ("AF_INET6" . 10)
    ("AF_NETLINK" . 16) ("AF_PACKET" . 17)
    ;; IPPROTO
    ("IPPROTO_IP" . 0) ("IPPROTO_ICMP" . 1) ("IPPROTO_TCP" . 6)
    ("IPPROTO_UDP" . 17) ("IPPROTO_IPV6" . 41) ("IPPROTO_ICMPV6" . 58)
    ;; open(2) flags
    ("O_RDONLY" . 0) ("O_WRONLY" . 1) ("O_RDWR" . 2)
    ("O_CREAT" . #x40) ("O_EXCL" . #x80) ("O_TRUNC" . #x200)
    ("O_APPEND" . #x400) ("O_NONBLOCK" . #x800) ("O_DIRECTORY" . #x10000)
    ("O_CLOEXEC" . #x80000) ("O_PATH" . #x200000)
    ;; mmap protection / flags
    ("PROT_NONE" . 0) ("PROT_READ" . 1) ("PROT_WRITE" . 2) ("PROT_EXEC" . 4)
    ("MAP_SHARED" . 1) ("MAP_PRIVATE" . 2) ("MAP_ANONYMOUS" . #x20)
    ;; mode bits (S_IF*)
    ("S_IFMT"  . #xf000) ("S_IFSOCK" . #xc000) ("S_IFLNK" . #xa000)
    ("S_IFREG" . #x8000) ("S_IFBLK" . #x6000) ("S_IFDIR" . #x4000)
    ("S_IFCHR" . #x2000) ("S_IFIFO" . #x1000)
    ("S_IRWXU" . #o0700) ("S_IRUSR" . #o0400) ("S_IWUSR" . #o0200) ("S_IXUSR" . #o0100)
    ("S_IRWXG" . #o0070) ("S_IRGRP" . #o0040) ("S_IWGRP" . #o0020) ("S_IXGRP" . #o0010)
    ("S_IRWXO" . #o0007) ("S_IROTH" . #o0004) ("S_IWOTH" . #o0002) ("S_IXOTH" . #o0001)
    ;; BPF map types / flags also surface in scripts
    ("BPF_ANY" . 0) ("BPF_NOEXIST" . 1) ("BPF_EXIST" . 2)
    ;; PERF/clock
    ("CLOCK_REALTIME" . 0) ("CLOCK_MONOTONIC" . 1) ("CLOCK_BOOTTIME" . 7))
  "Linux constants commonly referenced in bpftrace scripts that don't
   appear in kernel BTF (they're #defines, not enums).")

(defvar *constant-cache* nil
  "Lazily-populated hash table mapping name → integer. First lookup
   builds it from BTF enums + the curated table.")

(defun constants-table ()
  (or *constant-cache*
      (setf *constant-cache*
            (let ((tbl (handler-case (whistler:btf-enum-values
                                      (whistler:ensure-vmlinux-btf))
                         (error () (make-hash-table :test 'equal)))))
              ;; Curated entries override BTF only on conflict — order
              ;; lets us pin values for portability.
              (dolist (e *curated-constants*)
                (setf (gethash (car e) tbl) (cdr e)))
              tbl))))

(defun resolve-constant (name)
  "Look NAME up in (1) the script's own #define directives, then
   (2) BTF enums + the curated table. Returns the integer value or NIL."
  (or (cdr (assoc name *user-cpp-defines* :test #'string=))
      (gethash name (constants-table))))

(defun lower-builtin (kw)
  (case kw
    (:pid    `(whistler::ash (whistler::get-current-pid-tgid) -32))
    (:tid    `(whistler::logand (whistler::get-current-pid-tgid) #xffffffff))
    (:ppid   (lower-ppid-builtin))
    (:uid    `(whistler::logand (whistler::get-current-uid-gid)  #xffffffff))
    (:gid    `(whistler::ash (whistler::get-current-uid-gid)  -32))
    ;; Match bpftrace: `nsecs` is CLOCK_BOOTTIME (continues counting
    ;; while the machine is suspended), not CLOCK_MONOTONIC. Without
    ;; this, a laptop that slept for an hour shows latencies offset by
    ;; an hour vs the real bpftrace tool.
    (:nsecs  '(whistler::ktime-get-boot-ns))
    (:cpu    '(whistler::get-smp-processor-id))
    (:cgroup '(whistler::get-current-cgroup-id))
    (:rand   '(whistler::get-prandom-u32))
    ;; bpftrace `elapsed' = current nsecs - script-start nsecs.
    ;; The hidden array map is populated by userspace before attach
    ;; (see runtime.lisp's session bring-up).
    (:elapsed
     `(whistler::- (whistler::ktime-get-boot-ns)
                   (whistler:getmap ,*elapsed-map-name* 0)))
    (t       (unsupported "builtin ~A" kw))))

(defun lower-pcomm-into-record (rec off size)
  "Emit the kernel-side reads that fill REC[OFF..OFF+SIZE) with the
   parent task's `comm' (TASK_COMM_LEN bytes). Walks
   current_task → real_parent (pointer field), then probe-reads the
   comm[] member directly into the printf record."
  (let* ((vmbtf (whistler:ensure-vmlinux-btf))
         (tid (whistler:btf-find-struct vmbtf "task_struct"))
         (fields (and tid (whistler:btf-struct-fields vmbtf tid)))
         (rp (find "real_parent" fields :test #'string= :key #'first))
         (co (find "comm"        fields :test #'string= :key #'first))
         (rp-off (and rp (third rp)))
         (co-off (and co (third co)))
         (parent (gensym "PPARENT")))
    (unless (and rp-off co-off)
      (unsupported "pcomm: vmlinux BTF missing task_struct.real_parent/comm"))
    `(let ((,parent (whistler::struct-alloc 8)))
       (whistler::probe-read-kernel
        ,parent 8 (whistler::+ (whistler::get-current-task) ,rp-off))
       (whistler::probe-read-kernel
        (+ ,rec ,off) ,size
        (whistler::+ (whistler::load whistler::u64 ,parent 0) ,co-off)))))

(defun lower-ppid-builtin ()
  "Parent PID — walk `current_task->real_parent->tgid'. real_parent
   is a `struct task_struct *' so we probe-read the pointer field
   (8 bytes), then probe-read tgid (4 bytes) from that pointer."
  (let* ((vmbtf (whistler:ensure-vmlinux-btf))
         (task-id (whistler:btf-find-struct vmbtf "task_struct"))
         (fields (and task-id
                      (whistler:btf-struct-fields vmbtf task-id)))
         (rp (find "real_parent" fields :test #'string= :key #'first))
         (tg (find "tgid"        fields :test #'string= :key #'first))
         (rp-off (and rp (third rp)))
         (tg-off (and tg (third tg)))
         (parent (gensym "PARENT"))
         (out    (gensym "PPID")))
    (unless (and rp-off tg-off)
      (unsupported "ppid: vmlinux BTF missing task_struct.real_parent/tgid"))
    `(let* ((,parent (whistler::struct-alloc 8)))
       (whistler::probe-read-kernel
        ,parent 8 (whistler::+ (whistler::get-current-task) ,rp-off))
       (let* ((,out (whistler::struct-alloc 4)))
         (whistler::probe-read-kernel
          ,out 4 (whistler::+ (whistler::load whistler::u64 ,parent 0) ,tg-off))
         (whistler::load whistler::u32 ,out 0)))))

(defun lower-arg (n)
  (ecase (first *probe-spec*)
    ((:kprobe :uprobe)
     (case n
       (0 '(whistler:pt-regs-parm1)) (1 '(whistler:pt-regs-parm2))
       (2 '(whistler:pt-regs-parm3)) (3 '(whistler:pt-regs-parm4))
       (4 '(whistler:pt-regs-parm5)) (5 '(whistler:pt-regs-parm6))
       (t (unsupported "arg~D — only arg0..arg5 are wired up" n))))
    ((:kretprobe :uretprobe)
     (unsupported "arg~D in ret-probe — retval is the only accessor" n))
    ;; In fentry / fexit programs the ctx is `__u64 ctx[N]` where
    ;; ctx[i] is the i-th argument to the traced function. Direct
    ;; ctx-load — no pt_regs indirection.
    ((:kfunc :kretfunc)
     `(whistler::ctx ,(intern "U64" :whistler) ,(* n 8)))
    (:tracepoint (unsupported "tracepoint arg~D — use args->field" n))))

(defun lower-retval ()
  (ecase (first *probe-spec*)
    ((:kretprobe :uretprobe) '(whistler:pt-regs-ret))
    (:kretfunc
     ;; In fexit, retval lives at ctx[nargs]. Look up nargs in the
     ;; kernel BTF so the offset matches the target function's true
     ;; signature.
     (let* ((fname (second *probe-spec*))
            (vmbtf (whistler:ensure-vmlinux-btf)))
       (multiple-value-bind (id nargs) (whistler:btf-find-func vmbtf fname)
         (declare (ignore id))
         (unless nargs
           (unsupported "kretfunc:~A — function not found in vmlinux BTF" fname))
         `(whistler::ctx ,(intern "U64" :whistler) ,(* nargs 8)))))))

(defun comm-string-comparison (op raw-lhs raw-rhs)
  "Handle string-equality comparisons against a `comm'-typed value:
   either bare `comm == \"literal\"' (compares to get_current_comm)
   or `\$v == \"literal\"' / `\"literal\" == \$v' where \$v is in
   *comm-vars* (compares to \$v's 16-byte slot). Returns NIL if the
   operands don't fit either shape."
  (labels ((str? (e) (and (consp e) (eq (first e) :str) (second e)))
           (comm-or-var-slot (e)
             (cond
               ;; Bare `comm' — synthesise a fresh slot and fill from
               ;; bpf_get_current_comm. Returns (BUF-BIND TIP) where
               ;; BUF-BIND is the (let …) wrapper and TIP is the buf sym.
               ((and (consp e) (eq (first e) :comm))
                (let ((b (gensym "CMBUF")))
                  (values b `(progn (whistler::get-current-comm
                                     ,b ,+bt-comm-len+)))))
               ;; \$v in *comm-vars* — its symbol IS the slot pointer.
               ((and (consp e) (eq (first e) :var)
                     (member (second e) *comm-vars* :test #'string-equal))
                (values (var-sym (second e)) nil)))))
    (multiple-value-bind (lhs-buf lhs-init) (comm-or-var-slot raw-lhs)
      (declare (ignore lhs-init))
      (multiple-value-bind (rhs-buf rhs-init) (comm-or-var-slot raw-rhs)
        (declare (ignore rhs-init))
        (let* ((slot (or lhs-buf rhs-buf))
               (lit  (or (and lhs-buf (str? raw-rhs))
                         (and rhs-buf (str? raw-lhs)))))
          (when (and slot lit)
            (let* ((bytes (sb-ext:string-to-octets lit :external-format :utf-8))
                   (n     (length bytes))
                   (clauses
                     (loop for i from 0 below (min n +bt-comm-len+)
                           collect `(whistler::= (whistler::load
                                                  ,(intern "U8" :whistler)
                                                  ,slot ,i)
                                                 ,(aref bytes i))))
                   (nul-check
                     (when (< n +bt-comm-len+)
                       `(whistler::= (whistler::load ,(intern "U8" :whistler)
                                                     ,slot ,n)
                                     0)))
                   (all-eq `(whistler::and ,@clauses ,@(and nul-check (list nul-check)))))
              (if (or (and (consp raw-lhs) (eq (first raw-lhs) :comm))
                      (and (consp raw-rhs) (eq (first raw-rhs) :comm)))
                  ;; bare-comm: synthesise the slot.
                  `(let ((,slot (whistler::struct-alloc ,+bt-comm-len+)))
                     (whistler::get-current-comm ,slot ,+bt-comm-len+)
                     ,(if (eq op :!=) `(whistler::not ,all-eq) all-eq))
                  ;; \$v slot: just compare in place.
                  (if (eq op :!=) `(whistler::not ,all-eq) all-eq)))))))))

(defun lower-bin (expr)
  (let* ((op  (getf (cdr expr) :op))
         (raw-lhs (getf (cdr expr) :lhs))
         (raw-rhs (getf (cdr expr) :rhs)))
    ;; Special case: comm == / != "literal".
    (when (member op '(:== :!=))
      (let ((cmp (comm-string-comparison op raw-lhs raw-rhs)))
        (when cmp (return-from lower-bin cmp))))
    (let ((lhs (lower-expr raw-lhs))
          (rhs (lower-expr raw-rhs)))
      (ecase op
        (:+    `(whistler::+ ,lhs ,rhs))
        (:-    `(whistler::- ,lhs ,rhs))
        (:*    `(whistler::* ,lhs ,rhs))
        (:/    `(whistler::/ ,lhs ,rhs))
        (:%    `(whistler::mod ,lhs ,rhs))
        (:==   `(whistler::= ,lhs ,rhs))
        (:!=   `(whistler::/= ,lhs ,rhs))
        (:<    `(whistler::< ,lhs ,rhs))
        (:>    `(whistler::> ,lhs ,rhs))
        (:<=   `(whistler::<= ,lhs ,rhs))
        (:>=   `(whistler::>= ,lhs ,rhs))
        (:&&   `(whistler::and ,lhs ,rhs))
        (:\|\| `(whistler::or ,lhs ,rhs))
        (:&    `(whistler::logand ,lhs ,rhs))
        (:\|   `(whistler::logior ,lhs ,rhs))
        (:^    `(whistler::logxor ,lhs ,rhs))
        (:<<   `(whistler::ash ,lhs ,rhs))
        (:>>   `(whistler::>> ,lhs ,rhs))))))

(defun lower-un (expr)
  (let ((op  (getf (cdr expr) :op))
        (arg (lower-expr (getf (cdr expr) :arg))))
    (ecase op
      (:!  `(whistler::if ,arg 0 1))
      (:-  `(whistler::- 0 ,arg))
      (:~  `(whistler::logxor ,arg #xffffffffffffffff))
      ;; *EXPR — u64 pointer deref via bpf_probe_read_kernel into a
      ;; stack slot; matches bpftrace's *kaddr(SYM) pattern.
      (:*
       (let ((scratch (gensym "DEREF")))
         `(let ((,scratch (whistler::struct-alloc 8)))
            (whistler::probe-read-kernel ,scratch 8 ,arg)
            (whistler::load ,(intern "U64" :whistler) ,scratch 0)))))))

(defun lower-tern (expr)
  `(whistler::if ,(lower-expr (getf (cdr expr) :cond))
                      ,(lower-expr (getf (cdr expr) :then))
                      ,(lower-expr (getf (cdr expr) :else))))

(defparameter *exit-map-name* (intern "--BT-EXIT--" :whistler)
  "Hidden array map used as a kernel→user `exit()` flag.")

(defparameter *print-map-name* (intern "--BT-PRINT--" :whistler)
  "Hidden ringbuf map used to ferry kernel-side `async actions' back
   to the userspace runtime: printf, print(@m), clear(@m), time, etc.
   Every record starts with the same 8-byte header — a u32 tag and
   a u32 id — so a single ring consumer can dispatch all of them.")

(defparameter *stacks-map-name* (intern "--BT-STACKS--" :whistler)
  "Hidden BPF_MAP_TYPE_STACK_TRACE map. Each entry is an array of
   u64 instruction pointers — the kernel stack at the moment
   `kstack' fired. Looked up by stack-id (u32) at print time.")

(defparameter *elapsed-map-name* (intern "--BT-ELAPSED--" :whistler)
  "Hidden 1-entry array map holding CLOCK_BOOTTIME nanoseconds at
   script-start. Populated by the userspace runtime BEFORE any probe
   attaches; `elapsed' lowers to `(- nsecs (getmap … 0))'.")

(defconstant +bt-stack-depth+ 32
  "Frames captured per kstack entry. Value-size = 8 * depth = 256.")

;;; Tag values must match those decoded in runtime.lisp.
(defconstant +bt-tag-printf+    0)
(defconstant +bt-tag-print-map+ 1)
(defconstant +bt-tag-clear-map+ 2)
(defconstant +bt-tag-time+      3)
(defconstant +bt-tag-cat+       4)
(defconstant +bt-tag-join+      5)
(defconstant +bt-join-argnum+   16
  "Maximum NULL-terminated string array entries `join()' captures.
   Matches bpftrace's default.")
(defconstant +bt-join-argsize+  128
  "Max bytes per join() string slot.")

(defvar *printf-table* nil
  "Per-generate() list of (ID FMT-STRING ARG-TYPES) entries.
   ARG-TYPES is a list of :int or :string, one per format-string
   arg. Runtime decodes records by walking this list.")

(defvar *printf-id-counter* 0
  "Per-generate() counter for unique printf record IDs.")

(defvar *map-id-table* nil
  "Per-generate() alist mapping `whistler symbol' → integer id for
   the map-id field on print-map / clear-map records.")

(defun lower-call (expr)
  (let ((name (getf (cdr expr) :name)))
    (cond
      ((string= name "count") (unsupported "count() must be on the RHS of @map = …"))
      ((string= name "hist")  (unsupported "hist() must be on the RHS of @map = …"))
      ((string= name "lhist") (unsupported "lhist() — Phase 1 ships hist() only"))
      ((string= name "exit")
       ;; Set the exit flag the userspace print loop polls every tick.
       `(setf (whistler:getmap ,*exit-map-name* 0) 1))
      ((string= name "printf") (lower-printf (getf (cdr expr) :args)))
      ((string= name "print")  (lower-async-map +bt-tag-print-map+
                                                (getf (cdr expr) :args)
                                                "print"))
      ((string= name "clear")  (lower-async-map +bt-tag-clear-map+
                                                (getf (cdr expr) :args)
                                                "clear"))
      ((string= name "zero")   0)
      ((string= name "time")   (lower-async-time
                                (getf (cdr expr) :args)))
      ((string= name "cat")    (lower-async-cat
                                (getf (cdr expr) :args)))
      ((string= name "join")   (lower-async-join
                                (getf (cdr expr) :args)))
      ((string= name "delete") 0)           ; lower-expr-stmt handles the real call
      ((string= name "reg")    (lower-reg-call (getf (cdr expr) :args)))
      ((string= name "kaddr")  (lower-kaddr-call (getf (cdr expr) :args)))
      ((string= name "has_key") (lower-has-key-call (getf (cdr expr) :args)))
      ;; `bswap(x)' — byte-swap. bpftrace's bswap on a u16/u32 reverses
      ;; the byte order. We pick the width from key context; for the
      ;; common `bswap(\$port)' (a u16 from skc_dport) the 16-bit
      ;; version is what we need. Use the 16-bit swap pattern that
      ;; works for u16 values; higher bytes pass through if any are set.
      ((string= name "bswap")
       (let ((x (gensym "BSWAP")))
         `(let ((,x ,(lower-expr (first (getf (cdr expr) :args)))))
            (whistler::logior
             (whistler::ash (whistler::logand ,x #xff) 8)
             (whistler::ash (whistler::logand ,x #xff00) -8)))))
      ;; `getopt(NAME, DEFAULT, HELP)' — bpftrace's CLI-flag accessor.
      ;; whistler bpftrace doesn't expose user options, so this always
      ;; returns the default value (the second argument).
      ((string= name "getopt")
       (lower-expr (or (second (getf (cdr expr) :args))
                       '(:int 0))))
      ;; User-defined `fn' — inline the body, substituting the
      ;; formal parameters with the actual argument expressions.
      ((find-user-function name)
       (inline-user-call name (getf (cdr expr) :args)))
      (t (unsupported "function ~A" name)))))

(defun inline-user-call (name args)
  "Inline a call to user-defined function NAME. Each (:var \"param\")
   in the body is rewritten to the matching argument expression at
   AST level, then the body is lowered as a Whistler form. For
   macro params written `@name', the matching argument must itself
   be an @-map; the body's references to `@name' are renamed (keys
   preserved) to point at the actual map."
  (let* ((fn      (find-user-function name))
         (params  (getf fn :params))
         (body    (getf fn :body))
         (subs    (and params (mapcar #'cons params args))))
    (unless (= (length params) (length args))
      (unsupported "fn ~A expects ~D arg~:p, got ~D"
                   name (length params) (length args)))
    ;; Validate @-params: matching arg must be an @-map reference.
    (loop for (p . a) in subs
          when (and (plusp (length p)) (char= (char p 0) #\@))
            do (unless (and (consp a) (eq (first a) :map))
                 (unsupported "macro ~A: param ~A wants an @-map, got ~S"
                              name p a)))
    (let* ((body* (mapcar (lambda (s) (substitute-vars s subs)) body))
           (forms (mapcar #'lower-fn-stmt body*)))
      ;; Single trailing :return → its expression IS the result.
      ;; Multiple forms → wrap in progn; the last form's value wins.
      (cond
        ((null forms) 0)
        ((= (length forms) 1) (first forms))
        (t `(progn ,@forms))))))

(defun substitute-vars (form subs)
  "Walk FORM (an AST), substituting parameter references:
     * `$name'  → matches (:var NAME); replaced wholesale.
     * bare `name' (macro param without sigil) → matches both
       (:var NAME) AND (:builtin :NAME); replaced wholesale.
     * `@name'  → matches (:map :name NAME …); :name is rewritten to
       the actual map's name and :keys is preserved from the body."
  (cond
    ((not (consp form)) form)
    ((and (eq (first form) :var) (stringp (second form)))
     (let ((cell (assoc (second form) subs :test #'string=)))
       (cond (cell (cdr cell))
             (t form))))
    ;; Bare-name macro params: (:builtin :NAME) keyword form.
    ((and (eq (first form) :builtin) (keywordp (second form)))
     (let* ((sname (string-downcase (symbol-name (second form))))
            (cell  (assoc sname subs :test #'string=)))
       (cond (cell (cdr cell))
             (t form))))
    ;; Bare-name macro params: (:constant "name") string form
    ;; (lowercase idents that didn't match a builtin name).
    ((and (eq (first form) :constant) (stringp (second form)))
     (let ((cell (assoc (second form) subs :test #'string=)))
       (cond (cell (cdr cell))
             (t form))))
    ((and (eq (first form) :map) (stringp (getf (cdr form) :name)))
     (let* ((local (getf (cdr form) :name))
            (cell  (assoc (concatenate 'string "@" local) subs
                          :test #'string=)))
       (if cell
           (list :map :name (getf (cdr (cdr cell)) :name)
                 :keys (mapcar (lambda (k) (substitute-vars k subs))
                               (getf (cdr form) :keys)))
           (cons (substitute-vars (first form) subs)
                 (substitute-vars (rest form)  subs)))))
    (t (cons (substitute-vars (first form) subs)
             (substitute-vars (rest form)  subs)))))

(defun lower-fn-stmt (stmt)
  "Lower a single statement inside a user-fn body. :return forms
   evaluate to their expression's value; other statements lower as
   usual."
  (cond
    ((and (consp stmt) (eq (first stmt) :return))
     (let ((e (getf (cdr stmt) :expr)))
       (if e (lower-expr e) 0)))
    (t (lower-stmt stmt))))

(defparameter *reg-aliases*
  ;; Map bpftrace reg() names to the pt-regs keyword the protocols.lisp
  ;; table indexes by. bpftrace accepts the conventional register names
  ;; (rax → ax etc); whistler's pt_regs table uses the short form.
  '(("ip" . :ip) ("rip" . :ip) ("pc" . :ip)
    ("sp" . :sp) ("rsp" . :sp)
    ("bp" . :bp) ("rbp" . :bp)
    ("ax" . :ax) ("rax" . :ax) ("eax" . :ax)
    ("bx" . :bx) ("rbx" . :bx) ("ebx" . :bx)
    ("cx" . :cx) ("rcx" . :cx) ("ecx" . :cx)
    ("dx" . :dx) ("rdx" . :dx) ("edx" . :dx)
    ("si" . :si) ("rsi" . :si) ("esi" . :si)
    ("di" . :di) ("rdi" . :di) ("edi" . :di)
    ("r8"  . :r8)  ("r9"  . :r9)  ("r10" . :r10) ("r11" . :r11)
    ("r12" . :r12) ("r13" . :r13) ("r14" . :r14) ("r15" . :r15)))

(defvar *kallsyms-addr-cache* nil
  "Lazy hash-table NAME → ADDR built from /proc/kallsyms. NIL until
   the first kaddr() call asks for one.")

(defun load-kallsyms-addrs ()
  "Build NAME → ADDR from /proc/kallsyms. When kptr_restrict zeros
   the table for unprivileged readers, fall back to the readable
   /boot/System.map-<uname-r> file. System.map carries the same
   absolute symbol addresses as the loaded kernel image (modulo
   KASLR), so kaddr() resolves correctly on systems without
   CAP_SYS_ADMIN at compile time."
  (labels ((parse-stream (s)
             (loop with tbl = (make-hash-table :test 'equal)
                   for line = (read-line s nil nil)
                   while line
                   for sp1 = (position #\Space line)
                   for sp2 = (and sp1 (position #\Space line :start (1+ sp1)))
                   when (and sp1 sp2)
                     do (let* ((addr (parse-integer line :end sp1 :radix 16
                                                          :junk-allowed t))
                               (tail (subseq line (1+ sp2)))
                               (sp3 (position #\Space tail))
                               (name (if sp3 (subseq tail 0 sp3) tail)))
                          (when (and addr (plusp addr) (plusp (length name)))
                            (setf (gethash name tbl) addr)))
                   finally (return tbl)))
           (read-or-nil (path)
             (handler-case
                 (with-open-file (s path :direction :input) (parse-stream s))
               (error () nil))))
    (or (let ((tbl (read-or-nil "/proc/kallsyms")))
          (and tbl (plusp (hash-table-count tbl)) tbl))
        ;; Try /boot/System.map-<release>, the package-installed image map.
        (let* ((release (string-trim
                         '(#\Newline #\Space)
                         (with-output-to-string (out)
                           (handler-case
                               (sb-ext:run-program "/usr/bin/uname" '("-r")
                                                   :output out :wait t)
                             (error () nil)))))
               (path (and (plusp (length release))
                          (concatenate 'string "/boot/System.map-" release))))
          (and path (read-or-nil path)))
        (make-hash-table :test 'equal))))

(defun lower-kaddr-call (args)
  "Lower kaddr(\"name\") to the integer address of kernel symbol NAME,
   looked up in /proc/kallsyms at compile time. Requires the lookup
   to succeed — running without root or with kptr_restrict typically
   gives back zeroed addresses and we fail with a clear message."
  (unless (and args (= (length args) 1) (eq (first (first args)) :str))
    (unsupported "kaddr() needs exactly one string-literal argument"))
  (unless *kallsyms-addr-cache*
    (setf *kallsyms-addr-cache* (load-kallsyms-addrs)))
  (let* ((name (second (first args)))
         (addr (gethash name *kallsyms-addr-cache*)))
    (unless addr
      (unsupported "kaddr(~S) — symbol not found in /proc/kallsyms ~
                    (need CAP_SYS_ADMIN to see non-zero addresses)"
                   name))
    addr))

(defun lower-has-key-call (args)
  "Lower `has_key(@map, key…)' to 1 if `bpf_map_lookup_elem' returns
   a non-null pointer, 0 otherwise. Accepts one or more key arguments
   — composite keys (`has_key(@m, k1, k2)') flow through the same
   struct-key path as @m[k1, k2] reads."
  (unless (>= (length args) 2)
    (unsupported "has_key needs at least (@map, key)"))
  (let* ((mref (first args))
         (keys (rest args)))
    (unless (and (consp mref) (eq (first mref) :map))
      (unsupported "has_key first arg must be a @map reference"))
    (let* ((mname-string (getf (cdr mref) :name))
           (info  (or (gethash mname-string *map-table*)
                      (unsupported "has_key: unknown map @~A" mname-string)))
           (mname (minfo-name info))
           (p     (gensym "P"))
           (k     (gensym "K"))
           (ptr-p (keys-need-ptr-ops-p keys)))
      (cond
        (ptr-p
         (with-key keys
           (lambda (kp)
             `(whistler::if (whistler::map-lookup-ptr ,mname ,kp) 1 0))))
        (t
         `(let* ((,k whistler::u64 ,(lower-expr (first keys))))
            (whistler::if (whistler::map-lookup ,mname ,k) 1 0)))))))

(defun lower-reg-call (args)
  "Lower reg(\"name\") to a (ctx u64 OFFSET) load against pt_regs."
  (unless (and args (= (length args) 1) (eq (first (first args)) :str))
    (unsupported "reg() needs exactly one string argument"))
  (let* ((name (second (first args)))
         (key  (cdr (assoc name *reg-aliases* :test #'string=))))
    (unless key
      (unsupported "reg(~S) — unknown register name" name))
    (let ((off (cdr (assoc key (whistler::pt-regs-offsets)))))
      (unless off
        (unsupported "reg(~S) — register not available on this arch" name))
      `(whistler::ctx ,(intern "U64" :whistler) ,off))))

(defun intern-map-id (mref)
  "Assign / look up a stable integer id for the given @map reference."
  (let* ((info (or (gethash (or (getf (cdr mref) :name) "@") *map-table*)
                   (unsupported "unknown map @~A in async action"
                                (getf (cdr mref) :name))))
         (sym (minfo-name info))
         (cell (assoc sym *map-id-table*)))
    (if cell (cdr cell)
        (let ((id (1+ (length *map-id-table*))))
          (push (cons sym id) *map-id-table*)
          id))))

(defun lower-async-map (tag args op-name)
  "Emit a tagged ringbuf record asking userspace to print/clear/zero
   the named map. ARGS must be one @map reference."
  (unless (and args (= (length args) 1) (eq (first (first args)) :map))
    (unsupported "~A() needs a single @map argument" op-name))
  (let* ((mref (first args))
         (map-id (intern-map-id mref))
         (rec (gensym "REC")))
    `(whistler:with-ringbuf (,rec ,*print-map-name* 8)
       (whistler::store ,(intern "U32" :whistler) ,rec 0 ,tag)
       (whistler::store ,(intern "U32" :whistler) ,rec 4 ,map-id))))

(defvar *time-format-table* nil
  "Per-generate() alist (ID . FMT-STRING). Each time(FMT) call gets
   an ID; the kernel emits (tag, id) and userspace looks the format
   up to strftime it.")

(defvar *cat-paths-table* nil
  "Per-generate() alist (ID . PATH). cat(PATH) registers the path
   under a unique ID; the kernel emits (tag, id) and userspace
   reads the file and dumps its contents at print-loop time.")

(defun lower-async-join (args)
  "Emit a tagged ringbuf record capturing up to +bt-join-argnum+
   strings from a NULL-terminated argv-style pointer array. Each
   slot is +bt-join-argsize+ bytes wide (NUL-padded); userspace
   stops at the first empty entry and prints the rest space-joined."
  (unless (= 1 (length args))
    (unsupported "join() takes exactly one arg (a pointer to argv)"))
  (let* ((ptr  (lower-expr (first args)))
         (rec  (gensym "REC"))
         (p    (gensym "P"))
         (size (+ 8 (* +bt-join-argnum+ +bt-join-argsize+)))
         (str-helper (intern "PROBE-READ-USER-STR" :whistler)))
    `(whistler:with-ringbuf (,rec ,*print-map-name* ,size)
       (whistler::store ,(intern "U32" :whistler) ,rec 0 ,+bt-tag-join+)
       (whistler::store ,(intern "U32" :whistler) ,rec 4 0)
       (let ((,p ,ptr))
         ,@(loop for i below +bt-join-argnum+
                 for arg-off = (+ 8 (* i +bt-join-argsize+))
                 for ptr-tmp = (gensym "ARGV")
                 collect `(let ((,ptr-tmp (whistler::struct-alloc 8)))
                            (whistler::probe-read-kernel
                             ,ptr-tmp 8 (whistler::+ ,p ,(* i 8)))
                            (,str-helper
                             (whistler::+ ,rec ,arg-off)
                             ,+bt-join-argsize+
                             (whistler::load whistler::u64 ,ptr-tmp 0))))))))

(defun lower-async-cat (args)
  "Emit a tagged ringbuf record asking userspace to read and dump
   the contents of the file named in PATH-ARG."
  (unless (and (= (length args) 1)
               (consp (first args))
               (eq (first (first args)) :str))
    (unsupported "cat() arg must be a string literal path"))
  (let* ((path (second (first args)))
         (id (1+ (length *cat-paths-table*)))
         (rec (gensym "REC")))
    (push (cons id path) *cat-paths-table*)
    `(whistler:with-ringbuf (,rec ,*print-map-name* 8)
       (whistler::store ,(intern "U32" :whistler) ,rec 0 ,+bt-tag-cat+)
       (whistler::store ,(intern "U32" :whistler) ,rec 4 ,id))))

(defun lower-async-time (args)
  "Emit a tagged ringbuf record asking userspace to stamp the current
   wall-clock time. With no args, uses bpftrace's default
   `%H:%M:%S\\n'. With one string-literal arg, that strftime format
   is interned and looked up at print time."
  (let ((fmt (cond
               ((null args) "%H:%M:%S~%")
               ((and (= (length args) 1)
                     (eq (first (first args)) :str))
                (second (first args)))
               (t (unsupported "time() arg must be a string literal"))))
        (id (1+ (length *time-format-table*)))
        (rec (gensym "REC")))
    (push (cons id fmt) *time-format-table*)
    `(whistler:with-ringbuf (,rec ,*print-map-name* 8)
       (whistler::store ,(intern "U32" :whistler) ,rec 0 ,+bt-tag-time+)
       (whistler::store ,(intern "U32" :whistler) ,rec 4 ,id))))

(defconstant +bt-comm-len+ 16
  "Bytes of `comm' the kernel writes via bpf_get_current_comm.")

(defconstant +bt-buf-max-len+ 64
  "Cap on bpftrace buf(ptr, len) capture, matching bpftrace's default
   max_strlen. Records reserve a fixed (4 + +bt-buf-max-len+) bytes;
   the actual byte count is the leading u32.")

(defconstant +bt-str-default-len+ 64
  "Default buffer size used by str(ptr) — matches bpftrace's default.")

(defun named-call-p (expr name)
  "T when EXPR is a (:call :name NAME :args …) form."
  (and (consp expr)
       (eq (first expr) :call)
       (let ((n (getf (cdr expr) :name)))
         (and (stringp n) (string= n name)))))

(defun str-call-p  (expr) (named-call-p expr "str"))
(defun kstr-call-p (expr) (named-call-p expr "kstr"))

(defun printf-arg-type (expr)
  "Classify a printf arg into one of:
     :int                  8 bytes, u64 in record
     (:string . SIZE)      SIZE bytes, NUL-terminated string slot
     :ksym                 8 bytes, kernel address (kallsyms-resolved)
     :usym                 16 bytes, pid_tgid + user address (symbolizer)
     :ipv-any              17 bytes, family byte + 16 address bytes
                           (a `\$v = ntop(…)' var referenced here)"
  (cond
    ((eq (first expr) :comm)
     (cons :string +bt-comm-len+))
    ;; pcomm — parent task's TASK_COMM_LEN-byte comm. Same slot width
    ;; as comm; the kernel side walks real_parent before copying.
    ((eq (first expr) :pcomm)
     (cons :string +bt-comm-len+))
    ;; A `\$v' whose latest assignment came from ntop(…) — the var
    ;; holds a pointer to its per-probe 17-byte slot.
    ((and (eq (first expr) :var)
          (member (second expr) *ntop-vars* :test #'string-equal))
     :ipv-any)
    ;; A `\$v' backed by a 16-byte comm slot — same as a bare-comm
    ;; reference for printf purposes.
    ((and (eq (first expr) :var)
          (member (second expr) *comm-vars* :test #'string-equal))
     (cons :string +bt-comm-len+))
    ;; A field chain whose leaf is a fixed-size byte array
    ;; (e.g. `gendisk.disk_name' as `char[32]'). printf treats it
    ;; as a NUL-padded string of the array's byte size.
    ((eq (first expr) :field)
     (cond
       ;; `args.FIELD' where the tracepoint format declared FIELD as
       ;; an array — render as a string slot sized to the array.
       ((let ((base (getf (cdr expr) :base))
              (name (getf (cdr expr) :name))
              (sz   *tp-field-sizes*))
          (and (consp base) (eq (first base) :args)
               sz (gethash name sz)
               (let ((array-size (tp-array-size name)))
                 (and array-size (plusp array-size)))))
        (cons :string (tp-array-size (getf (cdr expr) :name))))
       (t
        (multiple-value-bind (_ptr size kind) (analyze-chain expr)
          (declare (ignore _ptr))
          (if (and (eq kind :array) (plusp (or size 0)))
              (cons :string size)
              :int)))))
    ;; @m[k] where m's value slot is a NUL-padded string — the value
    ;; lookup returns a pointer to value-size bytes the printf
    ;; record-emitter copies wholesale.
    ((and (eq (first expr) :map)
          (let ((info (and *map-table*
                           (gethash (getf (cdr expr) :name) *map-table*))))
            (and info (minfo-value-string-p info))))
     (let ((info (gethash (getf (cdr expr) :name) *map-table*)))
       (cons :string (minfo-value-size info))))
    ((or (str-call-p expr) (kstr-call-p expr))
     (let* ((args (getf (cdr expr) :args))
            (n    (when (and (cdr args) (eq (first (second args)) :int))
                    (second (second args)))))
       (cons :string (or n +bt-str-default-len+))))
    ;; A bare string literal (produced by rewrite-self-refs for
    ;; probe/func, or by the user writing printf("x", "y")) lands as
    ;; a fixed-size NUL-padded slot just long enough to hold it.
    ((eq (first expr) :str)
     (let* ((s (second expr))
            (len (1+ (length (sb-ext:string-to-octets s :external-format :utf-8)))))
       (cons :string len)))
    ((named-call-p expr "ksym") :ksym)
    ((named-call-p expr "usym") :usym)
    ((named-call-p expr "ntop") (ntop-arg-type expr))
    ;; cgroup_path(cgrp_id) — bpftrace returns the v2 cgroup path
    ;; for the given id by scanning /sys/fs/cgroup at print time.
    ;; The wire format is just the u64 id; userspace formats.
    ((named-call-p expr "cgroup_path") :cgroup-path)
    ;; buf(ptr, len) — raw byte buffer, capped at +bt-buf-max-len+
    ;; bytes. Wire format is u32 actual-len followed by that many
    ;; bytes (zero-padded to the cap so the record stays a fixed
    ;; size). printf's %r format renders the bytes as an escaped
    ;; string in userspace.
    ((named-call-p expr "buf") :buf)
    ((named-call-p expr "strftime")
     ;; Register the format string and emit a (:strftime . ID) slot.
     ;; The wire format is just the u64 timestamp; the runtime looks
     ;; up FMT by id at print time, like time(FMT).
     (let* ((args (getf (cdr expr) :args))
            (fmt  (and args
                       (eq (first (first args)) :str)
                       (second (first args))))
            (id   (1+ (length *time-format-table*))))
       (unless fmt
         (unsupported "strftime() format arg must be a string literal"))
       (push (cons id fmt) *time-format-table*)
       (cons :strftime id)))
    (t :int)))

(defun ntop-arg-type (expr)
  "Decide whether an ntop(...) call produces an IPv4 (4-byte) or
   IPv6 (16-byte) slot. Single-arg form is always v4. Two-arg form
   inspects the family literal — accepts both the bare integer
   (e.g. 2 / 10) and the symbolic constant (AF_INET / AF_INET6)."
  (let* ((args (getf (cdr expr) :args))
         (first (first args))
         (af    (when (cdr args)
                  (case (first first)
                    (:int      (second first))
                    (:constant (resolve-constant (second first)))))))
    (cond
      ((null af)         :ipv4)
      ((eql af 2)        :ipv4)
      ((eql af 10)       :ipv6)
      (t                 :ipv4))))

(defun printf-arg-size (arg-type)
  (cond
    ((eq arg-type :int)  8)
    ((eq arg-type :ksym) 8)
    ((eq arg-type :usym) 16)
    ((eq arg-type :ipv4) 4)
    ((eq arg-type :ipv6) 16)
    ((eq arg-type :ipv-any) +bt-ntop-slot-size+)
    ((eq arg-type :cgroup-path) 8)
    ((eq arg-type :buf) (+ 4 +bt-buf-max-len+))
    ((and (consp arg-type) (eq (car arg-type) :string))   (cdr arg-type))
    ((and (consp arg-type) (eq (car arg-type) :strftime)) 8)  ; just the u64 timestamp
    (t (error "printf-arg-size: unrecognised ~A" arg-type))))

(defun lower-printf (args)
  "Lower a bpftrace `printf(\"FMT\", arg…)` to a ringbuf-submit using
   the unified async-action protocol.

   Record layout (all little-endian):
     0:  u32 tag = +bt-tag-printf+
     4:  u32 id  (index into the printf-table)
     8+: per-arg payloads — u64 for :int args, 16 bytes for :string

   At codegen time we register (id fmt-string arg-types) in
   *PRINTF-TABLE*, which the runtime gets via :printf-table in the
   generate() plist. The runtime ring-consumer reads the tag, then
   the id, then walks ARG-TYPES to decode each payload."
  (unless args
    (unsupported "printf() with no format string"))
  (let ((fmt (first args)))
    (unless (eq (first fmt) :str)
      (unsupported "printf() format must be a string literal"))
    (let* ((fmt-str    (second fmt))
           (extra-args (rest args))
           (arg-types  (mapcar #'printf-arg-type extra-args))
           (id         (incf *printf-id-counter*))
           ;; Per-arg offsets — header (8) + cumulative arg sizes
           (offsets    (let ((o 8))
                         (loop for ty in arg-types
                               collect o
                               do (incf o (printf-arg-size ty)))))
           (total-size (+ 8 (loop for ty in arg-types sum (printf-arg-size ty))))
           (rec        (gensym "REC")))
      (push (list id fmt-str arg-types) *printf-table*)
      `(whistler:with-ringbuf (,rec ,*print-map-name* ,total-size)
         (whistler::store ,(intern "U32" :whistler) ,rec 0 ,+bt-tag-printf+)
         (whistler::store ,(intern "U32" :whistler) ,rec 4 ,id)
         ,@(loop for arg in extra-args
                 for ty  in arg-types
                 for off in offsets
                 collect (lower-printf-arg arg ty rec off))))))

(defun lower-printf-arg (arg ty rec off)
  "Emit the kernel-side store that fills RECORD slot at OFFSET with ARG."
  (cond
    ((eq ty :int)
     `(whistler::store ,(intern "U64" :whistler) ,rec ,off ,(lower-expr arg)))
    ((eq ty :ksym)
     ;; Just stash the raw u64 address. Userspace will run it through
     ;; /proc/kallsyms at decode time.
     (let ((addr (lower-expr (first (getf (cdr arg) :args)))))
       `(whistler::store ,(intern "U64" :whistler) ,rec ,off ,addr)))
    ((eq ty :usym)
     ;; 16-byte slot: pid_tgid then address. Capturing pid in-kernel
     ;; ties the symbol lookup to the right process's address space.
     (let ((addr (lower-expr (first (getf (cdr arg) :args)))))
       `(progn
          (whistler::store ,(intern "U64" :whistler) ,rec ,off
                           (whistler::get-current-pid-tgid))
          (whistler::store ,(intern "U64" :whistler) ,rec (+ ,off 8) ,addr))))
    ((eq ty :ipv4)
     ;; Single u32 store. The userspace decoder reads the 4 bytes in
     ;; network-byte-order, matching bpftrace's contract that the
     ;; input is already __be32.
     (let* ((args (getf (cdr arg) :args))
            (addr-expr (lower-expr (if (cdr args) (second args) (first args)))))
       `(whistler::store ,(intern "U32" :whistler) ,rec ,off ,addr-expr)))
    ((and (consp ty) (eq (car ty) :strftime))
     ;; Store the timestamp as a u64; the format-id is implicit in
     ;; the printf-table's per-arg type list.
     (let* ((args (getf (cdr arg) :args))
            (ts-expr (lower-expr (second args))))
       `(whistler::store ,(intern "U64" :whistler) ,rec ,off ,ts-expr)))
    ((eq ty :ipv6)
     ;; 16 bytes copied from a pointer in user/kernel memory.
     (let* ((args (getf (cdr arg) :args))
            (ptr  (lower-expr (second args))))
       `(whistler::probe-read-kernel (+ ,rec ,off) 16 ,ptr)))
    ((eq ty :buf)
     ;; Lay out: u32 len + +bt-buf-max-len+ bytes from PTR. Cap len
     ;; at +bt-buf-max-len+ so the kernel-side probe-read doesn't
     ;; exceed the slot. We can't pass a runtime length to
     ;; probe-read-kernel safely, so we always read the cap and let
     ;; userspace truncate to the recorded length.
     (let* ((args (getf (cdr arg) :args))
            (ptr  (lower-expr (first args)))
            (len  (lower-expr (second args)))
            (lvar (gensym "BLEN")))
       `(let ((,lvar ,len))
          (whistler::store ,(intern "U32" :whistler) ,rec ,off
                           (whistler::if (whistler::> ,lvar ,+bt-buf-max-len+)
                                         ,+bt-buf-max-len+
                                         ,lvar))
          (whistler::probe-read-kernel
           (+ ,rec ,off 4) ,+bt-buf-max-len+ ,ptr))))
    ((eq ty :cgroup-path)
     ;; Store the u64 cgroup id; userspace looks the path up by
     ;; scanning /sys/fs/cgroup at decode time.
     (let ((cgid (lower-expr (first (getf (cdr arg) :args)))))
       `(whistler::store ,(intern "U64" :whistler) ,rec ,off ,cgid)))
    ((eq ty :ipv-any)
     ;; ARG is a `\$v' that points at its 17-byte ntop slot. Copy the
     ;; whole slot (1 byte family + 16 bytes address) into the record.
     (let ((src (lower-expr arg))
           (i   (gensym "I")))
       `(whistler::dotimes (,i ,+bt-ntop-slot-size+)
          (whistler::store
           whistler::u8 ,rec (+ ,off ,i)
           (whistler::load whistler::u8 ,src ,i)))))
    ((and (consp ty) (eq (car ty) :string))
     (let ((size (cdr ty)))
       (cond
         ((eq (first arg) :comm)
          `(whistler::get-current-comm (+ ,rec ,off) ,size))
         ((eq (first arg) :pcomm)
          (lower-pcomm-into-record rec off size))
         ((str-call-p arg)
          (let* ((args (getf (cdr arg) :args))
                 (ptr  (lower-expr (first args)))
                 (helper (intern "PROBE-READ-USER-STR" :whistler)))
            `(,helper (+ ,rec ,off) ,size ,ptr)))
         ((kstr-call-p arg)
          (let* ((args (getf (cdr arg) :args))
                 (ptr  (lower-expr (first args))))
            `(,(intern "PROBE-READ-KERNEL-STR" :whistler)
              (+ ,rec ,off) ,size ,ptr)))
         ;; Literal string — emit byte-stores. Used for probe/func
         ;; rewrites and any printf("…", "literal") form.
         ((eq (first arg) :str)
          (lower-printf-string-literal rec off (second arg) size))
         ;; A \$v in *comm-vars* — copy SIZE bytes from \$v's slot
         ;; into the record.
         ((and (eq (first arg) :var)
               (member (second arg) *comm-vars* :test #'string-equal))
          (let ((src (lower-expr arg))
                (i   (gensym "I")))
            `(whistler::dotimes (,i ,size)
               (whistler::store whistler::u8 ,rec (+ ,off ,i)
                                (whistler::load whistler::u8 ,src ,i)))))
         ;; A field-chain whose leaf is a char[] / u8[] array — emit
         ;; one probe_read_kernel of SIZE bytes from the chain's
         ;; computed pointer.
         ((eq (first arg) :field)
          `(whistler::probe-read-kernel
            (+ ,rec ,off) ,size ,(lower-chain-as-ptr arg)))
         ;; @m[k] on a string-valued map — look up the entry, then
         ;; copy SIZE bytes from the value pointer into the record.
         ;; Missing key (NULL pointer) → leave the slot untouched
         ;; (init was zero, so the userspace decoder sees an empty
         ;; string).
         ((eq (first arg) :map)
          (let* ((info (gethash (getf (cdr arg) :name) *map-table*))
                 (mname (minfo-name info))
                 (keys  (getf (cdr arg) :keys))
                 (p     (gensym "P"))
                 (ptr-p (keys-need-ptr-ops-p keys)))
            (if ptr-p
                (with-key keys
                  (lambda (k)
                    `(whistler:if-let
                         (,p (whistler::map-lookup-ptr ,mname ,k))
                       (whistler::probe-read-kernel
                        (+ ,rec ,off) ,size ,p)
                       0)))
                (let ((tmpk (gensym "K")))
                  `(let* ((,tmpk whistler::u64 ,(lower-expr (first keys))))
                     (whistler:if-let
                         (,p (whistler::map-lookup ,mname ,tmpk))
                       (whistler::probe-read-kernel
                        (+ ,rec ,off) ,size ,p)
                       0)))))))))))

(defun lower-printf-string-literal (rec off text size)
  "Emit the kernel-side stores that lay TEXT (UTF-8) into the SIZE-byte
   record slot at OFF, NUL-padding the tail."
  (let* ((bytes (sb-ext:string-to-octets text :external-format :utf-8))
         (n     (length bytes))
         (stores '()))
    (dotimes (i n)
      (push `(whistler::store ,(intern "U8" :whistler)
                              ,rec (+ ,off ,i) ,(aref bytes i))
            stores))
    (loop for i from n below size do
      (push `(whistler::store ,(intern "U8" :whistler)
                              ,rec (+ ,off ,i) 0)
            stores))
    `(progn ,@(nreverse stores))))


(defun lower-field (expr)
  (let ((base (getf (cdr expr) :base))
        (name (getf (cdr expr) :name)))
    (cond
      ((and (consp base) (eq (first base) :args))
       (lower-args-field name))
      ((and (consp base) (eq (first base) :curtask))
       (lower-struct-pointer-field "task_struct" name
                                   '(whistler::get-current-task)))
      ;; ((struct NAME *)EXPR)->FIELD — when the cast directly wraps a
      ;; plain value (not another field-chain), use the cast type as
      ;; the struct for this single-hop access. A cast wrapping a
      ;; field-chain (e.g. `(struct cgroup *)$memcg.css.cgroup') is
      ;; just a type annotation for the chain's result — falls through
      ;; to the :field-chain handler below.
      ((and (consp base) (eq (first base) :cast)
            (not (and (consp (getf (cdr base) :expr))
                      (eq (first (getf (cdr base) :expr)) :field))))
       (lower-struct-pointer-field (getf (cdr base) :type) name
                                   (lower-expr (getf (cdr base) :expr))))
      ;; $var with a recorded cast type — `$sk = (struct sock *)retval;'
      ;; then `$sk.field' (single hop).
      ((and (consp base) (eq (first base) :var)
            (assoc (second base) *var-types* :test #'string=))
       (lower-struct-pointer-field
        (cdr (assoc (second base) *var-types* :test #'string=))
        name (lower-expr base)))
      ;; Chained field access — e.g. `$sk.__sk_common.skc_family'.
      ;; Also catches a :cast whose :expr is itself a field-chain: the
      ;; cast's type only annotates the chain's result, so we descend
      ;; past the cast to find the chain's true root.
      ((or (and (consp base) (eq (first base) :field))
           (and (consp base) (eq (first base) :cast)
                (consp (getf (cdr base) :expr))
                (eq (first (getf (cdr base) :expr)) :field)))
       (multiple-value-bind (root struct-name names)
           (collect-field-chain expr)
         (cond
           ((and root struct-name)
            (lower-chained-field (root-ptr-form root) struct-name names))
           (t (unsupported "field access .~A on non-args expressions"
                           name)))))
      (t (unsupported "field access .~A on non-args expressions" name)))))

(defun root-ptr-form (root-ast)
  "Lower the root of a field-chain — either a $var, a :cast, or
   :curtask — to a pointer expression."
  (cond
    ((eq (first root-ast) :curtask) '(whistler::get-current-task))
    ((eq (first root-ast) :cast)    (lower-expr (getf (cdr root-ast) :expr)))
    (t                              (lower-expr root-ast))))

(defun collect-field-chain (expr)
  "Walk a (possibly nested) :field expression to its root. Returns
   (values ROOT-AST ROOT-STRUCT-NAME FIELD-NAMES). Casts encountered
   in the chain are unwrapped — but the *outermost* enclosing cast
   stays as the chain's struct hint when nothing better is upstream,
   so `(struct bio *)arg1.bi_bdev.bd_disk.disk_name' walks against
   struct bio."
  (let ((cast-hint nil))
    (labels ((walk (e)
               (cond
                 ((and (consp e) (eq (first e) :field))
                  (multiple-value-bind (r rs names) (walk (getf (cdr e) :base))
                    (values r rs (append names (list (getf (cdr e) :name))))))
                 ;; Mid-chain cast: remember its type as a fallback
                 ;; hint, then descend into the cast's value.
                 ((and (consp e) (eq (first e) :cast))
                  (setf cast-hint (or cast-hint (getf (cdr e) :type)))
                  (walk (getf (cdr e) :expr)))
                 (t (values e nil nil)))))
      (multiple-value-bind (root _rs names) (walk expr)
        (declare (ignore _rs))
        (let ((struct-name
                (cond
                  ((and (consp root) (eq (first root) :curtask))
                   "task_struct")
                  ((and (consp root) (eq (first root) :var))
                   (or (cdr (assoc (second root) *var-types* :test #'string=))
                       cast-hint))
                  (t cast-hint))))
          (if struct-name
              (values root struct-name names)
              (values nil nil nil)))))))

(defun lower-chained-field (root-ptr-form root-struct-name chain)
  "Walk BTF for each name in CHAIN, summing offsets through embedded
   structs/unions until a scalar leaf. Mid-chain pointer fields are
   handled by emitting a probe_read_kernel of the pointer value
   into a scratch slot, then continuing the walk from the loaded
   pointer with offset reset to 0.

   Emits a single combined probe_read_kernel per pointer-free
   segment of the chain — embedded struct/union hops sum offsets
   in place, so e.g. \`\$sk.__sk_common.skc_family' is still one
   read while \`\$cgrp.kn.id' becomes two reads."
  (let* ((vmbtf (whistler:ensure-vmlinux-btf))
         (current-tid (whistler:btf-find-struct vmbtf root-struct-name))
         (cur-ptr root-ptr-form)   ; base pointer for the current segment
         (segment-offset 0)          ; offset within this segment
         (deref-bindings nil)        ; list of (sym init) pairs for the wrap
         (final-size nil)
         (final-type nil))
    (unless current-tid
      (unsupported "field walk: struct ~A not in vmlinux BTF" root-struct-name))
    (labels ((leaf? (name) (string= name (car (last chain))))
             (start-new-segment-by-deref ()
               "Open a new segment from `*deref-of-current-pointer*':
                allocate a u64 scratch, probe-read 8 bytes at the
                current segment's tail offset, replace cur-ptr with
                a fresh name that names the loaded pointer."
               (let ((scratch (gensym "DEREF"))
                     (ptrvar  (gensym "PTR")))
                 (push (list scratch `(whistler::struct-alloc 8)) deref-bindings)
                 (push (list ptrvar
                             `(progn
                                (whistler::probe-read-kernel
                                 ,scratch 8 (whistler::+ ,cur-ptr ,segment-offset))
                                (whistler::load whistler::u64 ,scratch 0)))
                       deref-bindings)
                 (setf cur-ptr ptrvar
                       segment-offset 0))))
      (dolist (fname chain)
        (let* ((fields (whistler:btf-struct-fields vmbtf current-tid))
               (cell   (find fname fields :test #'string= :key #'first)))
          (unless cell
            (unsupported "->~A: no such field on current struct" fname))
          (let ((bpf-type (second cell))
                (offset   (third cell))
                (size     (fourth cell))
                (sub-name (fifth cell))
                (sub-tid  (sixth cell)))
            (incf segment-offset offset)
            (cond
              ;; Embedded struct/union — keep walking by type-id, no
              ;; new probe-read needed.
              ((and (null bpf-type) sub-name (not (leaf? fname)))
               (setf current-tid sub-tid))
              ;; Pointer-typed field, not at leaf — dereference and
              ;; continue from the pointed-to struct.
              ((and (eql size 8) (stringp sub-name) (string= sub-name "ptr")
                    (not (leaf? fname)))
               (let ((target (whistler:btf-ptr-target-type-id vmbtf sub-tid)))
                 (unless target
                   (unsupported "->~A: can't follow pointer (no target type)"
                                fname))
                 (start-new-segment-by-deref)
                 (setf current-tid target)))
              ;; Scalar leaf.
              ((and (leaf? fname) (member size '(1 2 4 8)))
               (setf final-size size)
               (setf final-type (case size
                                  (1 (intern "U8"  :whistler))
                                  (2 (intern "U16" :whistler))
                                  (4 (intern "U32" :whistler))
                                  (8 (intern "U64" :whistler)))))
              (t (unsupported
                  "field chain ~{.~A~} — leaf must be a 1/2/4/8 byte scalar"
                  chain)))))))
    ;; Emit the final segment's leaf read.
    (let* ((scratch (gensym "F"))
           (read    `(let ((,scratch (whistler::struct-alloc ,final-size)))
                       (whistler::probe-read-kernel
                        ,scratch ,final-size
                        (whistler::+ ,cur-ptr ,segment-offset))
                       (whistler::load ,final-type ,scratch 0))))
      (if deref-bindings
          `(let* ,(reverse deref-bindings) ,read)
          read))))

(defun lower-struct-pointer-field (struct-name field-name ptr-form)
  "Generate the kernel-side read for STRUCT-NAME pointer pointed to by
   PTR-FORM, returning the value of FIELD-NAME. Uses kernel BTF for
   the field's offset and size. Scalar fields (1/2/4/8 bytes) only —
   nested struct fields require a chained-cast follow-on."
  (let ((vmbtf (whistler:ensure-vmlinux-btf)))
    (multiple-value-bind (type-id rec)
        (whistler:btf-find-struct vmbtf struct-name)
      (declare (ignore rec))
      (unless type-id
        (unsupported "->~A: struct ~A not found in vmlinux BTF"
                     field-name struct-name))
      (let* ((fields (whistler:btf-struct-fields vmbtf type-id))
             (cell   (find field-name fields :test #'string= :key #'first)))
        (unless cell
          (unsupported "->~A: struct ~A has no such field"
                       field-name struct-name))
        (let ((offset (third cell))
              (size   (fourth cell)))
          (unless (member size '(1 2 4 8))
            (unsupported "->~A: field is ~D bytes; only scalar (1/2/4/8) fields are wired up"
                         field-name size))
          (let ((scratch (gensym "FIELD"))
                (type-sym (case size
                            (1 (intern "U8"  :whistler))
                            (2 (intern "U16" :whistler))
                            (4 (intern "U32" :whistler))
                            (8 (intern "U64" :whistler)))))
            `(let ((,scratch (whistler::struct-alloc ,size)))
               (whistler::probe-read-kernel
                ,scratch ,size
                (whistler::+ ,ptr-form ,offset))
               (whistler::load ,type-sym ,scratch 0))))))))

(defun lower-args-field (name)
  "Lower args->NAME based on the current probe type. Tracepoints use
   the deftracepoint-generated tp-NAME accessor; fentry/fexit
   programs read the named arg directly out of the ctx array using
   the offset BTF gives us."
  (case (first *probe-spec*)
    ((:kfunc :kretfunc)
     (let* ((fname  (second *probe-spec*))
            (vmbtf  (whistler:ensure-vmlinux-btf))
            (params (whistler:btf-func-params vmbtf fname))
            (cell   (assoc name params :test #'string=)))
       (unless cell
         (unsupported "args->~A: ~A has no such parameter (have: ~{~A~^, ~})"
                      name fname (mapcar #'car params)))
       `(whistler::ctx ,(intern "U64" :whistler) ,(cdr cell))))
    (t (list (w-sym (concatenate 'string "tp-" name))))))

(defun store-key-component (buf offset type expr)
  "Emit the kernel form that fills (buf+offset, size-of-type) with EXPR's
   value. String-typed slots (comm / str / kstr / literal from
   func/probe rewrite) fill the buffer via their helper or via byte
   stores; everything else is a plain typed store."
  (cond
    ((eq (first expr) :comm)
     `(whistler::get-current-comm (+ ,buf ,offset) ,+bt-comm-len+))
    ((or (str-call-p expr) (kstr-call-p expr))
     (let* ((args (getf (cdr expr) :args))
            (ptr  (lower-expr (first args)))
            (size (str-key-size expr))
            (helper (if (str-call-p expr)
                        (intern "PROBE-READ-USER-STR"   :whistler)
                        (intern "PROBE-READ-KERNEL-STR" :whistler))))
       ;; Zero the slot first so any bytes past the str()'s NUL stay
       ;; defined — the BPF verifier rejects a map_update whose key
       ;; buffer has uninitialised bytes.
       `(progn
          (whistler::memset ,buf ,offset 0 ,size)
          (,helper (+ ,buf ,offset) ,size ,ptr))))
    ((eq (first expr) :str)
     ;; A string-literal key — produced by the func/probe rewrite.
     ;; The slot is fixed-width +bt-func-name-key-len+; write the
     ;; bytes plus NUL-pad to the full width.
     (lower-printf-string-literal buf offset (second expr)
                                  +bt-func-name-key-len+))
    (t `(whistler::store ,type ,buf ,offset ,(lower-expr expr)))))

(defun with-key (keys body-fn)
  "Run BODY-FN with the form to use as a map key. For an empty key
   list, BODY-FN gets 0. For a scalar 8-byte key, BODY-FN gets the
   bare expression. For composite keys, or for any key whose layout
   exceeds 8 bytes (e.g. a single `comm' key), wraps in a let* that
   stack-allocates the key buffer, fills it, and passes the pointer
   to BODY-FN. The map's declared :key-size > 8 then trips whistler's
   struct-key-map-p test which auto-dispatches to -ptr map ops."
  (cond
    ((null keys)
     (funcall body-fn 0))
    ((and (= (length keys) 1)
          (not (keys-need-ptr-ops-p keys)))
     (funcall body-fn (lower-expr (first keys))))
    (t
     (multiple-value-bind (layout total) (composite-key-layout keys)
       (let ((k (gensym "K")))
         `(let* ((,k ,(intern "U64" :whistler)
                  (whistler::struct-alloc ,total)))
            ,@(loop for entry in layout
                    for (offset _size type expr) = entry
                    collect (store-key-component k offset type expr))
            ,(funcall body-fn k)))))))

(defun lower-key-form (keys)
  "Single-value form for scalar key callers (hist bucket lookup, etc.).
   For composite keys, prefer WITH-KEY which builds the stack buffer."
  (cond
    ((null keys)         0)
    ((= (length keys) 1) (lower-expr (first keys)))
    (t (unsupported "composite keys cannot appear in this position"))))

(defun lower-map-read (expr)
  (let* ((info (or (gethash (or (getf (cdr expr) :name) "@") *map-table*)
                   (unsupported "unknown map @~A" (getf (cdr expr) :name))))
         (mname (minfo-name info))
         (keys  (getf (cdr expr) :keys)))
    (with-key keys
      (lambda (k) `(whistler:getmap ,mname ,k)))))

;;; ========== Statement lowering ==========

(defun collect-vars (stmts)
  "Collect every $var name written or read inside STMTS. Returns a list
   of (canonical) symbols suitable for binding."
  (let ((seen (make-hash-table :test 'equal)))
    (labels ((walk (form)
               (when (consp form)
                 (case (first form)
                   (:var (setf (gethash (second form) seen) t))
                   (:bin   (walk (getf (cdr form) :lhs))
                           (walk (getf (cdr form) :rhs)))
                   (:un    (walk (getf (cdr form) :arg)))
                   (:tern  (walk (getf (cdr form) :cond))
                           (walk (getf (cdr form) :then))
                           (walk (getf (cdr form) :else)))
                   (:call  (dolist (a (getf (cdr form) :args)) (walk a)))
                   (:field (walk (getf (cdr form) :base)))
                   (:index (walk (getf (cdr form) :base))
                           (dolist (k (getf (cdr form) :keys)) (walk k)))
                   (:map   (dolist (k (getf (cdr form) :keys)) (walk k)))))))
      (labels ((walk-stmt (s)
                 (case (first s)
                   (:if      (walk (getf (cdr s) :cond))
                             (mapc #'walk-stmt (getf (cdr s) :then))
                             (mapc #'walk-stmt (getf (cdr s) :else)))
                   (:assign  (walk (getf (cdr s) :rhs))
                             (let ((lhs (getf (cdr s) :lhs)))
                               (when (eq (first lhs) :var)
                                 (setf (gethash (second lhs) seen) t))
                               (walk lhs)))
                   (:incdec  (walk (getf (cdr s) :lhs)))
                   (:expr    (walk (second s))))))
        (mapc #'walk-stmt stmts))
      (loop for k being the hash-keys of seen collect (var-sym k)))))

(defun lower-stmts (stmts)
  (mapcar #'lower-stmt stmts))

(defconstant +bt-max-loop-iters+ 64
  "Upper bound on bpftrace `while' iterations. The BPF verifier
   requires a static iteration cap; we hard-code 64 — bpftrace's
   default is similar.")

(defun lower-stmt (stmt)
  (ecase (first stmt)
    (:if        (lower-if stmt))
    (:while     (lower-while stmt))
    (:assign    (lower-assign stmt))
    (:incdec    (lower-incdec stmt))
    (:expr      (lower-expr-stmt stmt))
    (:let-noop  0)  ; bare `let $x;' — declaration, no work to do
    (:return
     ;; bpftrace lets `return;' at probe-body scope mean `skip the
     ;; rest of this probe invocation'. The kernel ignores the
     ;; tracepoint/kprobe return value, so emitting (whistler::return 0)
     ;; is harmless and matches user intent.
     `(whistler::return 0))))

(defun lower-while (stmt)
  "Lower a bpftrace `while (cond) { body }' to a bounded dotimes:

       (dotimes (k +bt-max-loop-iters+)
         (when cond
           body…))

   The BPF verifier requires a static loop bound; once `cond' goes
   false the body is skipped on every remaining iteration. Simple
   and verifier-friendly; bpf_loop()-style early termination is a
   future optimisation."
  (let* ((cond-expr (getf (cdr stmt) :cond))
         (body      (getf (cdr stmt) :body))
         (k         (gensym "WHILE-K")))
    `(whistler::dotimes (,k ,+bt-max-loop-iters+)
       (whistler::when ,(lower-expr cond-expr)
         ,@(lower-stmts body)))))

(defun lower-if (stmt)
  (let ((c (lower-expr (getf (cdr stmt) :cond)))
        (then (lower-stmts (getf (cdr stmt) :then)))
        (else (lower-stmts (getf (cdr stmt) :else))))
    (if else
        `(whistler::if ,c (progn ,@then) (progn ,@else))
        `(when ,c ,@then))))

(defun lower-assign (stmt)
  (let* ((lhs (getf (cdr stmt) :lhs))
         (op  (getf (cdr stmt) :op))
         (rhs (getf (cdr stmt) :rhs)))
    (ecase (first lhs)
      (:var
       (let ((sym (var-sym (second lhs))))
         (cond
           ;; `$v = ntop(…)' on a tracked ntop-var — write the
           ;; family byte + address bytes into $v's pre-allocated
           ;; 17-byte slot. $v itself stays a pointer for the
           ;; duration of the probe.
           ((and (eq op :=)
                 (consp rhs) (eq (first rhs) :call)
                 (stringp (getf (cdr rhs) :name))
                 (string= (getf (cdr rhs) :name) "ntop")
                 (member (second lhs) *ntop-vars* :test #'string-equal))
            (lower-ntop-assign sym (getf (cdr rhs) :args)))
           ;; `$v = @m[k]' on an ntop-typed $v whose map's value is
           ;; an ntop record — copy the 17 bytes from the map slot
           ;; into $v's buffer instead of overwriting the pointer.
           ((and (eq op :=)
                 (consp rhs) (eq (first rhs) :map)
                 (member (second lhs) *ntop-vars* :test #'string-equal))
            (lower-ntop-map-copy sym rhs))
           ;; `$v = comm' — write TASK_COMM_LEN bytes into $v's
           ;; 16-byte slot via bpf_get_current_comm.
           ((and (eq op :=)
                 (consp rhs) (eq (first rhs) :comm)
                 (member (second lhs) *comm-vars* :test #'string-equal))
            `(whistler::get-current-comm ,sym ,+bt-comm-len+))
           ;; `$v = @m[k]' on a comm-typed $v whose map's value is a
           ;; string slot — copy the bytes into $v's buffer.
           ((and (eq op :=)
                 (consp rhs) (eq (first rhs) :map)
                 (member (second lhs) *comm-vars* :test #'string-equal))
            (lower-string-map-copy sym rhs))
           (t
            (ecase op
              (:=  `(setf ,sym ,(lower-expr rhs)))
              (:+= `(whistler:incf ,sym ,(lower-expr rhs)))
              (:-= `(whistler:decf ,sym ,(lower-expr rhs))))))))
      (:map (lower-map-assign lhs op rhs)))))

(defun analyze-chain (expr)
  "If EXPR is a recognisable field chain, return (values PTR-FORM
   LEAF-SIZE LEAF-KIND) where PTR-FORM is a Whistler expression
   pointing at the leaf, LEAF-SIZE is its byte size, and LEAF-KIND
   is :scalar or :array. Walks by raw BTF type-id at each hop and
   inserts probe_read_kernel deref bindings whenever a mid-chain
   pointer field is crossed — so chains like
   `(struct bio *)arg1.bi_bdev.bd_disk.disk_name' (two pointer hops
   ending in a char[]) round-trip into a let* that yields the
   correct leaf-pointer."
  (when (and (consp expr) (eq (first expr) :field))
    (multiple-value-bind (root struct-name names)
        (collect-field-chain expr)
      (when (and root struct-name)
        (let* ((vmbtf (whistler:ensure-vmlinux-btf))
               (current-tid (whistler:btf-find-struct vmbtf struct-name))
               (cur-ptr (root-ptr-form root))
               (segment-offset 0)
               (deref-bindings nil)
               (leaf-size nil)
               (leaf-kind nil))
          (unless current-tid
            (unsupported "chain: struct ~A not in vmlinux BTF" struct-name))
          (labels ((start-new-segment-by-deref ()
                     (let ((scratch (gensym "DEREF"))
                           (ptrvar  (gensym "PTR")))
                       (push (list scratch `(whistler::struct-alloc 8))
                             deref-bindings)
                       (push (list ptrvar
                                   `(progn
                                      (whistler::probe-read-kernel
                                       ,scratch 8
                                       (whistler::+ ,cur-ptr ,segment-offset))
                                      (whistler::load whistler::u64 ,scratch 0)))
                             deref-bindings)
                       (setf cur-ptr ptrvar
                             segment-offset 0))))
            (loop for (fname . rest) on names
                  for last? = (null rest)
                  do (let* ((fields (whistler:btf-struct-fields vmbtf current-tid))
                            (cell (find fname fields :test #'string= :key #'first)))
                       (unless cell
                         (unsupported "chain ~A: no such field" fname))
                       (incf segment-offset (third cell))
                       (cond
                         (last?
                          (cond
                            ((and (null (second cell))
                                  (stringp (fifth cell))
                                  (string= (fifth cell) "array"))
                             (multiple-value-bind (_etype nelems esize)
                                 (whistler:btf-resolve-array vmbtf (sixth cell))
                               (declare (ignore _etype))
                               (setf leaf-size (* (or nelems 0) (or esize 0))))
                             (setf leaf-kind :array))
                            (t
                             (setf leaf-size (fourth cell))
                             (setf leaf-kind :scalar))))
                         ;; Mid-chain pointer field — deref and continue.
                         ((and (eql (fourth cell) 8)
                               (stringp (fifth cell))
                               (string= (fifth cell) "ptr"))
                          (let ((target (whistler:btf-ptr-target-type-id
                                         vmbtf (sixth cell))))
                            (unless target
                              (unsupported "chain ~A: pointer target unknown"
                                           fname))
                            (start-new-segment-by-deref)
                            (setf current-tid target)))
                         ;; Mid-chain embedded struct/union.
                         (t (setf current-tid (sixth cell)))))))
          (let ((ptr `(whistler::+ ,cur-ptr ,segment-offset)))
            (values (if deref-bindings
                        `(let* ,(reverse deref-bindings) ,ptr)
                        ptr)
                    leaf-size leaf-kind)))))))

(defun lower-string-map-copy (slot-sym map-expr)
  "Lower `\$v = @m[k]' where \$v is comm-typed and m's value slot is
   a string. Looks up the map, copies the bytes into SLOT-SYM's
   buffer; missing key leaves the slot at its (zero) init."
  (let* ((mname-string (getf (cdr map-expr) :name))
         (info  (or (gethash mname-string *map-table*)
                    (unsupported "unknown map @~A" mname-string)))
         (mname (minfo-name info))
         (vsize (minfo-value-size info))
         (keys  (getf (cdr map-expr) :keys))
         (p     (gensym "P"))
         (i     (gensym "I"))
         (ptr-p (keys-need-ptr-ops-p keys)))
    (flet ((copy-body (kform)
             `(whistler:if-let
                  (,p (whistler::map-lookup-ptr ,mname ,kform))
                (whistler::dotimes (,i ,vsize)
                  (whistler::store
                   whistler::u8 ,slot-sym ,i
                   (whistler::load whistler::u8 ,p ,i)))
                0)))
      (if ptr-p
          (with-key keys #'copy-body)
          (let ((tmpk (gensym "K")))
            `(let* ((,tmpk whistler::u64 ,(lower-expr (first keys))))
               ,(copy-body `(whistler::stack-addr ,tmpk))))))))

(defun lower-ntop-map-copy (slot-sym map-expr)
  "Lower `\$v = @m[k]' where \$v is ntop-typed and m's value slot is
   an ntop record. Looks up the map entry, then copies its 17 bytes
   into SLOT-SYM's buffer; a missing key zeros the slot."
  (let* ((mname-string (getf (cdr map-expr) :name))
         (info  (or (gethash mname-string *map-table*)
                    (unsupported "unknown map @~A" mname-string)))
         (mname (minfo-name info))
         (keys  (getf (cdr map-expr) :keys))
         (p     (gensym "P"))
         (i     (gensym "I"))
         (ptr-p (keys-need-ptr-ops-p keys)))
    (flet ((copy-body (kform)
             `(whistler:if-let
                  (,p (whistler::map-lookup-ptr ,mname ,kform))
                (whistler::dotimes (,i ,+bt-ntop-slot-size+)
                  (whistler::store
                   whistler::u8 ,slot-sym ,i
                   (whistler::load whistler::u8 ,p ,i)))
                0)))
      (if ptr-p
          (with-key keys #'copy-body)
          (let ((tmpk (gensym "K")))
            `(let* ((,tmpk whistler::u64 ,(lower-expr (first keys))))
               ,(copy-body `(whistler::stack-addr ,tmpk))))))))

(defun lower-chain-as-ptr (expr)
  "Pointer-only chain resolution (no final read). Used by ntop's
   v6 path where the address argument is a buried u8[16] array."
  (multiple-value-bind (ptr _size _kind) (analyze-chain expr)
    (declare (ignore _size _kind))
    (or ptr (lower-expr expr))))

(defun lower-ntop-assign (slot-sym ntop-args)
  "Lower `$v = ntop(EXPR)' or `$v = ntop(FAMILY, EXPR)' into stores
   on SLOT-SYM's pre-allocated 17-byte buffer: family at byte 0,
   address bytes at 1..(N). v4 (1 arg, or AF_INET) → 4-byte u32
   store. v6 (AF_INET6 family) → probe_read_kernel of 16 bytes from
   the pointer arg."
  (let* ((family-literal
           (and (cdr ntop-args)
                (let ((fa (first ntop-args)))
                  (case (first fa)
                    (:int      (second fa))
                    (:constant (resolve-constant (second fa)))))))
         (addr-expr
           (if (cdr ntop-args) (second ntop-args) (first ntop-args)))
         ;; If no explicit family but the addr-expr is a chain ending
         ;; in a 16-byte array (u8[16]), bpftrace's convention is v6
         ;; — match that behavior.
         (chain-info (and (null family-literal)
                          (multiple-value-list (analyze-chain addr-expr))))
         (chain-kind (third chain-info))
         (chain-size (second chain-info))
         (chain-ptr  (first chain-info)))
    (cond
      ;; Two-arg ntop(AF_INET6, ptr) — IPv6, explicit.
      ((eql family-literal 10)
       `(progn
          (whistler::store whistler::u8 ,slot-sym 0 10)
          (whistler::probe-read-kernel
           (whistler::+ ,slot-sym 1) 16 ,(lower-chain-as-ptr addr-expr))))
      ;; One-arg ntop(CHAIN.u8[16]) — IPv6, inferred from leaf shape.
      ((and (eq chain-kind :array) (eql chain-size 16))
       `(progn
          (whistler::store whistler::u8 ,slot-sym 0 10)
          (whistler::probe-read-kernel
           (whistler::+ ,slot-sym 1) 16 ,chain-ptr)))
      ;; One-arg ntop(u32) or two-arg ntop(AF_INET, u32) — IPv4.
      ((or (null family-literal) (eql family-literal 2))
       `(progn
          (whistler::store whistler::u8 ,slot-sym 0 2)
          (whistler::store whistler::u32 ,slot-sym 1
                           ,(lower-expr addr-expr))
          ;; Zero the trailing 12 bytes so userspace dispatch on the
          ;; family byte alone is safe even without re-clearing.
          ,@(loop for off from 5 below +bt-ntop-slot-size+
                  collect `(whistler::store whistler::u8 ,slot-sym ,off 0))))
      (t
       (unsupported "ntop() with non-literal family — only AF_INET/AF_INET6")))))

(defun lower-map-assign (mref op rhs)
  (let* ((info (or (gethash (or (getf (cdr mref) :name) "@") *map-table*)
                   (error "internal: missing map ~A" (getf (cdr mref) :name))))
         (mname (minfo-name info))
         (keys  (getf (cdr mref) :keys)))
    (cond
      ((and (consp rhs) (eq (first rhs) :call))
       (let ((fn (getf (cdr rhs) :name)))
         (cond
           ((string= fn "count")
            (with-key keys
              (lambda (k) `(whistler:incf (whistler:getmap ,mname ,k)))))
           ((string= fn "sum")
            (gen-sum-update mname keys
                            (lower-expr (first (getf (cdr rhs) :args)))))
           ((string= fn "min")
            (gen-min-max-update mname keys
                                (lower-expr (first (getf (cdr rhs) :args)))
                                :min))
           ((string= fn "max")
            (gen-min-max-update mname keys
                                (lower-expr (first (getf (cdr rhs) :args)))
                                :max))
           ((string= fn "avg")
            (gen-avg-update mname keys
                            (lower-expr (first (getf (cdr rhs) :args)))))
           ;; stats(x) shares avg's (count, sum) wire format; the
           ;; runtime reducer is the only thing that differs.
           ((string= fn "stats")
            (gen-avg-update mname keys
                            (lower-expr (first (getf (cdr rhs) :args)))))
           ((string= fn "hist")
            (when (rest keys)
              (unsupported "@m[k1,…] = hist(x) — per-key histograms not yet supported"))
            (gen-hist-update mname (lower-expr (first (getf (cdr rhs) :args)))))
           ((string= fn "lhist")
            (when (rest keys)
              (unsupported "@m[k1,…] = lhist(x,…) — per-key lhist not yet supported"))
            (let* ((args (getf (cdr rhs) :args))
                   (value-form (lower-expr (first args)))
                   (params (minfo-hist-params info)))
              (unless params
                (unsupported "internal: lhist info missing params"))
              (destructuring-bind (lo hi step) params
                (gen-lhist-update mname value-form lo hi step))))
           ;; `@m[k] = ntop(…)' — value slot stores 17 bytes
           ;; (family + address). See gen-ntop-set for the layout.
           ((and (string= fn "ntop") (minfo-value-ntop-p info))
            (gen-ntop-set info keys (getf (cdr rhs) :args)))
           (t (gen-scalar-set mname keys (lower-expr rhs) op)))))
      ;; `@m[k] = "literal"' or `= func' (already rewritten to :str).
      ;; The value slot is value-size bytes wide; lay out the literal
      ;; and NUL-pad. Uses map-update-ptr via with-key's struct path
      ;; (key gets the struct-key treatment via the now-wide map info).
      ((and (consp rhs) (eq (first rhs) :str)
            (minfo-value-string-p info))
       (gen-string-set info keys (second rhs)))
      ;; `@m[k] = comm' — stash bpf_get_current_comm() into the value
      ;; slot. The map's value-size was set to TASK_COMM_LEN at
      ;; inference time.
      ((and (consp rhs) (eq (first rhs) :comm)
            (minfo-value-string-p info))
       (gen-comm-set info keys))
      ;; `@m[k] = ntop(…)' — write a 17-byte family+address record
      ;; into the value slot, using the same encoding as the $var-ntop
      ;; path so :ipv-any printf reads transparently.
      ((and (consp rhs) (eq (first rhs) :call)
            (stringp (getf (cdr rhs) :name))
            (string= (getf (cdr rhs) :name) "ntop")
            (minfo-value-ntop-p info))
       (gen-ntop-set info keys (getf (cdr rhs) :args)))
      (t (gen-scalar-set mname keys (lower-expr rhs) op)))))

(defun gen-ntop-set (info keys ntop-args)
  "Store an ntop(…) result as @MNAME[KEYS]'s value: reuse the same
   17-byte layout (1 family + 16 addr) as the \$var-ntop path, then
   map_update_elem with the buffer pointer."
  (let* ((mname (minfo-name info))
         (vsize (minfo-value-size info))
         (buf   (gensym "VBUF"))
         (tmpk  (gensym "K"))
         (ptr-p (keys-need-ptr-ops-p keys)))
    (with-key keys
      (lambda (k)
        (let ((write `(progn
                        ,(lower-ntop-assign buf ntop-args)
                        (whistler::map-update-ptr
                         ,mname ,(if ptr-p k `(whistler::stack-addr ,tmpk))
                         ,buf 0))))
          (if ptr-p
              `(let ((,buf (whistler::struct-alloc ,vsize)))
                 ,write)
              `(let* ((,tmpk whistler::u64 ,k)
                      (,buf (whistler::struct-alloc ,vsize)))
                 ,write)))))))

(defun gen-comm-set (info keys)
  "Store the current task's TASK_COMM_LEN bytes as @MNAME[KEYS]'s
   value. Uses bpf_get_current_comm into a stack-allocated buffer
   then map_update_elem."
  (let* ((mname (minfo-name info))
         (vsize (minfo-value-size info))
         (buf   (gensym "VBUF"))
         (tmpk  (gensym "K"))
         (ptr-p (keys-need-ptr-ops-p keys)))
    (with-key keys
      (lambda (k)
        (if ptr-p
            `(let ((,buf (whistler::struct-alloc ,vsize)))
               (whistler::get-current-comm ,buf ,vsize)
               (whistler::map-update-ptr ,mname ,k ,buf 0))
            `(let* ((,tmpk whistler::u64 ,k)
                    (,buf (whistler::struct-alloc ,vsize)))
               (whistler::get-current-comm ,buf ,vsize)
               (whistler::map-update-ptr
                ,mname (whistler::stack-addr ,tmpk) ,buf 0)))))))

(defun gen-string-set (info keys literal)
  "Store LITERAL as the NUL-padded contents of @MNAME[KEYS]. Reuses
   the per-probe shared *string-set-buf* (allocated once in the
   prologue) so a BEGIN block initialising N entries doesn't bloat
   the stack by N × value-size."
  (let* ((mname (minfo-name info))
         (vsize (minfo-value-size info))
         (buf   *string-set-buf*)
         (tmpk  (gensym "K"))
         (ptr-p (keys-need-ptr-ops-p keys)))
    (unless buf
      (unsupported "internal: gen-string-set called outside a probe scope"))
    (with-key keys
      (lambda (k)
        (if ptr-p
            `(progn
               ,(lower-printf-string-literal buf 0 literal vsize)
               (whistler::map-update-ptr ,mname ,k ,buf 0))
            `(let* ((,tmpk whistler::u64 ,k))
               ,(lower-printf-string-literal buf 0 literal vsize)
               (whistler::map-update-ptr
                ,mname (whistler::stack-addr ,tmpk) ,buf 0)))))))

(defun gen-sum-update (mname keys value-form)
  "sum(x): incf the percpu-hash entry by x. The per-CPU storage means
   each CPU has its own bucket — no atomics needed."
  (with-key keys
    (lambda (k)
      `(whistler:incf (whistler:getmap ,mname ,k) ,value-form))))

(defun keys-need-ptr-ops-p (keys)
  "T iff the keys form requires the kernel -ptr map ops (whistler's
   struct-key path). Triggered by composite keys or by a single
   string-typed key (`comm', `str(…)', `kstr(…)', `func', `probe').
   All of these produce a stack buffer pointer rather than a u64."
  (or (> (length keys) 1)
      (and (= (length keys) 1)
           (let ((k (first keys)))
             (or (eq (first k) :comm)
                 (eq (first k) :func)
                 (eq (first k) :probe-name)
                 (str-call-p k)
                 (kstr-call-p k))))))

(defun gen-percpu-struct-update (mname keys value-form &key on-existing on-init)
  "Common scaffolding for sum/avg/min/max — all of which use a percpu
   map with a struct value (16 bytes). The kernel side needs:
     * map-lookup-ptr to find the per-CPU entry
     * map-update-ptr to create one on first call
   …and BOTH require pointer args, even when the user wrote a scalar
   key like `@m[pid]`. We bind the lowered key into a let so its
   stack slot has a stable address (`stack-addr`); the value-side is
   already a struct-alloc'd pointer.

   ON-EXISTING and ON-INIT each receive (p-symbol v-symbol init-symbol)
   and return the body form for that branch."
  (let* ((v    (gensym "V"))
         (p    (gensym "P"))
         (init (gensym "INIT"))
         (ptr-p (keys-need-ptr-ops-p keys)))
    (with-key keys
      (lambda (k)
        (let ((tmp-key (gensym "K")))
          ;; For struct-key (already a pointer): use k directly.
          ;; For scalar key: bind to a stack variable so stack-addr works.
          (if ptr-p
              `(let* ((,v ,value-form))
                 (whistler:if-let (,p (whistler::map-lookup-ptr ,mname ,k))
                   ,(funcall on-existing p v init)
                   (let ((,init (whistler::struct-alloc 16)))
                     ,(funcall on-init p v init)
                     (whistler::map-update-ptr ,mname ,k ,init 0))))
              `(let* ((,v ,value-form)
                      (,tmp-key whistler::u64 ,k))
                 (whistler:if-let
                     (,p (whistler::map-lookup-ptr
                          ,mname (whistler::stack-addr ,tmp-key)))
                   ,(funcall on-existing p v init)
                   (let ((,init (whistler::struct-alloc 16)))
                     ,(funcall on-init p v init)
                     (whistler::map-update-ptr
                      ,mname (whistler::stack-addr ,tmp-key) ,init 0))))))))))

(defun gen-min-max-update (mname keys value-form mode)
  "min(x) / max(x): per-CPU 16-byte slot {value u64, is_set u64}."
  (let ((cur (gensym "CUR")))
    (gen-percpu-struct-update
     mname keys value-form
     :on-existing
     (lambda (p v _init)
       (declare (ignore _init))
       `(let ((,cur (whistler::load whistler::u64 ,p 0))
              (set  (whistler::load whistler::u64 ,p 8)))
          (when (or (= set 0)
                    ,(if (eq mode :min)
                         `(< ,v ,cur)
                         `(> ,v ,cur)))
            (whistler::store whistler::u64 ,p 0 ,v)
            (whistler::store whistler::u64 ,p 8 1))))
     :on-init
     (lambda (_p v init)
       (declare (ignore _p))
       `(progn
          (whistler::store whistler::u64 ,init 0 ,v)
          (whistler::store whistler::u64 ,init 8 1))))))

(defun gen-avg-update (mname keys value-form)
  "avg(x): per-CPU 16-byte slot {count u64, sum u64}."
  (gen-percpu-struct-update
   mname keys value-form
   :on-existing
   (lambda (p v _init)
     (declare (ignore _init))
     `(progn
        (whistler::atomic-add ,p 0 1)
        (whistler::atomic-add ,p 8 ,v)))
   :on-init
   (lambda (_p v init)
     (declare (ignore _p))
     `(progn
        (whistler::store whistler::u64 ,init 0 1)
        (whistler::store whistler::u64 ,init 8 ,v)))))

(defun gen-scalar-set (mname keys value op)
  (with-key keys
    (lambda (k)
      (ecase op
        (:=  `(setf (whistler:getmap ,mname ,k) ,value))
        (:+= `(whistler:incf (whistler:getmap ,mname ,k) ,value))
        (:-= `(whistler:decf (whistler:getmap ,mname ,k) ,value))))))

(defun gen-hist-update (mname value-form)
  (let ((val  (gensym "V"))
        (slot (gensym "S"))
        (p    (gensym "P")))
    `(let* ((,val ,value-form)
                    (,slot (whistler::log2 ,val)))
       (when (whistler::>= ,slot 64) (setf ,slot 63))
       (whistler:when-let ((,p (whistler::map-lookup ,mname ,slot)))
         (whistler::atomic-add ,p 0 1)))))

(defun gen-lhist-update (mname value-form lo hi step)
  "Linear histogram update. Buckets:
     0          → underflow (value < LO)
     1..N       → [LO + (i-1)*STEP, LO + i*STEP)
     N+1        → overflow  (value >= HI)
   where N = (HI - LO) / STEP."
  (let* ((n    (max 1 (floor (- hi lo) step)))
         (over (+ n 1))
         (val  (gensym "V"))
         (slot (gensym "S"))
         (p    (gensym "P")))
    `(let* ((,val ,value-form)
            (,slot (cond
                     ((whistler::< ,val ,lo) 0)
                     ((whistler::>= ,val ,hi) ,over)
                     (t (whistler::+ 1 (whistler::/ (whistler::- ,val ,lo) ,step))))))
       (whistler:when-let ((,p (whistler::map-lookup ,mname ,slot)))
         (whistler::atomic-add ,p 0 1)))))

(defun lower-incdec (stmt)
  (let* ((lhs   (getf (cdr stmt) :lhs))
         (op    (getf (cdr stmt) :op))
         (info  (or (gethash (or (getf (cdr lhs) :name) "@") *map-table*)
                    (error "internal: missing map ~A" (getf (cdr lhs) :name))))
         (mname (minfo-name info))
         (keys  (getf (cdr lhs) :keys)))
    (with-key keys
      (lambda (k)
        (ecase op
          (:inc `(whistler:incf (whistler:getmap ,mname ,k)))
          (:dec `(whistler:decf (whistler:getmap ,mname ,k))))))))

(defun lower-expr-stmt (stmt)
  (let ((e (second stmt)))
    (cond
      ((and (consp e) (eq (first e) :call)
            (string= (getf (cdr e) :name) "delete"))
       ;; Two forms:
       ;;   delete(@m[k])    -- one arg, the map-access
       ;;   delete(@m, k)    -- two args, map ref + key (newer bpftrace)
       (let* ((args (getf (cdr e) :args))
              (mref (first args))
              (keys (cond
                      ((= (length args) 1)         (getf (cdr mref) :keys))
                      ((>= (length args) 2)        (rest args))))
              (info (or (gethash (or (getf (cdr mref) :name) "@") *map-table*)
                        (error "internal: delete of unknown @map")))
              (mname (minfo-name info)))
         (with-key keys
           (lambda (k) `(whistler:remmap ,mname ,k)))))
      ;; zero() — kernel-side no-op; Phase 3 just skips it.
      ((and (consp e) (eq (first e) :call)
            (string= (getf (cdr e) :name) "zero"))
       0)
      ;; everything else — printf, exit, print, clear, time, ... —
      ;; goes through lower-call, which emits the right ringbuf or
      ;; flag-map op.
      (t (lower-expr e)))))

;;; ========== Probe lowering ==========

(defparameter *kernel-spec-tags*
  '(:kprobe :kretprobe :uprobe :uretprobe
    :kfunc :kretfunc
    :tracepoint :begin :end :interval :profile))

(defun interval-period-ns (spec)
  "Convert an :interval probe spec to a period in nanoseconds.
   (:interval :unit :S :count 1)   → 1_000_000_000
   (:interval :unit :MS :count 5)  → 5_000_000
   (:interval :unit :US :count 50) → 50_000
   (:interval :unit :HZ :count 99) → 1_000_000_000 / 99"
  (let ((unit  (getf (cdr spec) :unit))
        (count (getf (cdr spec) :count)))
    (ecase unit
      (:s  (* count 1000000000))
      (:ms (* count 1000000))
      (:us (* count 1000))
      (:hz (floor 1000000000 count)))))

(defun spec->section (spec)
  (ecase (first spec)
    (:kprobe     (let ((target (second spec)))
                   (cond ((find #\* target)
                          (values :kprobe
                                  (format nil "kprobe.multi/~A" target)))
                         (t (values :kprobe
                                    (format nil "kprobe/~A" target))))))
    (:kretprobe  (let ((target (second spec)))
                   (cond ((find #\* target)
                          (values :kretprobe
                                  (format nil "kretprobe.multi/~A" target)))
                         (t (values :kretprobe
                                    (format nil "kretprobe/~A" target))))))
    ;; kfunc / kretfunc → BPF_PROG_TYPE_TRACING with fentry / fexit
    ;; expected-attach-type. The section name carries the target
    ;; function so the loader can resolve its BTF func ID at load
    ;; time.
    (:kfunc      (values :tracing      (format nil "fentry/~A" (second spec))))
    (:kretfunc   (values :tracing      (format nil "fexit/~A"  (second spec))))
    (:uprobe     (values :uprobe
                         (format nil "uprobe/~A:~A" (second spec) (third spec))))
    (:uretprobe  (values :uretprobe
                         (format nil "uretprobe/~A:~A" (second spec) (third spec))))
    (:tracepoint (values :tracepoint
                         (format nil "tracepoint/~A/~A" (second spec) (third spec))))
    ;; BEGIN/END compile to SYSCALL programs invoked once via
    ;; BPF_PROG_TEST_RUN. The "test_run/" prefix flags them so the
    ;; runtime skips the attach path.
    (:begin      (values :kprobe (format nil "test_run/begin_~D"
                                         (incf *test-run-counter*))))
    (:end        (values :kprobe (format nil "test_run/end_~D"
                                         (incf *test-run-counter*))))
    ;; interval probes attach to a periodic SOFTWARE/CPU_CLOCK perf
    ;; event; the period (in ns) is encoded in the section name so the
    ;; runtime can parse it back when wiring up the perf timer.
    (:interval   (values :kprobe (format nil "interval/period_~D"
                                         (interval-period-ns spec))))
    ;; profile:hz:N attaches to a freq-mode PERF_TYPE_SOFTWARE event
    ;; per-CPU at N samples/sec. Section encodes the frequency in Hz.
    (:profile    (values :kprobe (format nil "profile/freq_~D"
                                         (profile-freq-hz spec))))))

(defun profile-freq-hz (spec)
  "Convert a :profile probe spec to a frequency in hertz. Phase 4
   only supports `profile:hz:N'; other units don't really make sense
   for sampling (would need period mode)."
  (let ((unit  (getf (cdr spec) :unit))
        (count (getf (cdr spec) :count)))
    (unless (eq unit :hz)
      (unsupported "profile:~A:~D — Phase 4 supports profile:hz:N only"
                   unit count))
    count))

(defvar *test-run-counter* 0
  "Per-generate() counter used to keep BEGIN/END section names unique.")

(defun gen-probe-forms (probe index)
  "Return ((kernel-form …) (user-spec …)) for PROBE — multiple specs
   may share a body, so we emit one defprog per kernel spec and one
   user-side entry per user spec."
  (let* ((specs (getf (cdr probe) :specs))
         (pred  (getf (cdr probe) :predicate))
         (body  (getf (cdr probe) :body))
         (kernel-forms nil)
         (user-specs nil))
    (loop for spec in specs
          for sub from 0
          do (cond
               ((member (first spec) *kernel-spec-tags*)
                (push (gen-kernel-prog spec pred body index sub) kernel-forms))
               (t (push (list :spec spec :body body) user-specs))))
    (values (nreverse kernel-forms) (nreverse user-specs))))

(defun probe-func-name (spec)
  "Return the function name a probe spec attaches to, or NIL when the
   spec has no `func` (BEGIN/END/interval/profile)."
  (case (first spec)
    ((:kprobe :kretprobe :kfunc :kretfunc) (second spec))
    ((:uprobe :uretprobe)                  (third spec))
    (:tracepoint                           (format nil "~A:~A"
                                                   (second spec) (third spec)))
    (t                                     nil)))

(defun rewrite-self-refs (form probe-string func-string)
  "Walk FORM (an AST). Inside printf calls, inside map keys, and as
   the RHS of `@m[k] = func/probe' map assignments, rewrite
   (:PROBE-NAME) and (:FUNC) to (:str …) so they flow through the
   string-slot machinery. Outside those contexts they stay as the
   original builtin nodes."
  (labels ((rewrite-leaf (arg)
             (cond
               ((not (consp arg)) arg)
               ((and (eq (first arg) :probe-name) (null (rest arg)))
                (list :str probe-string))
               ((and (eq (first arg) :func) (null (rest arg)))
                (cond
                  (func-string (list :str func-string))
                  (t (unsupported "`func' is undefined for this probe type"))))
               (t (cons (rewrite-leaf (first arg))
                        (rewrite-leaf (rest arg))))))
           (walk (f)
             (cond
               ((not (consp f)) f)
               ;; printf(...) — rewrite within its args list.
               ((and (eq (first f) :call)
                     (let ((n (getf (cdr f) :name)))
                       (and (stringp n) (string= n "printf"))))
                (list :call :name "printf"
                      :args (mapcar #'rewrite-leaf (getf (cdr f) :args))))
               ;; @m[key…] — rewrite within its keys list.
               ((and (eq (first f) :map) (getf (cdr f) :keys))
                (loop for (k v) on (cdr f) by #'cddr
                      append (list k (if (eq k :keys)
                                         (mapcar #'rewrite-leaf v)
                                         v))
                        into rest
                      finally (return (cons :map rest))))
               ;; @m[k] = func/probe — rewrite the RHS so the map's
               ;; value slot gets the literal section name as a string.
               ((and (eq (first f) :assign)
                     (let ((lhs (getf (cdr f) :lhs)))
                       (and (consp lhs) (eq (first lhs) :map))))
                (list :assign
                      :lhs (walk (getf (cdr f) :lhs))
                      :op  (getf (cdr f) :op)
                      :rhs (rewrite-leaf (getf (cdr f) :rhs))))
               (t (cons (walk (first f)) (walk (rest f)))))))
    (walk form)))

(defun infer-tuple-vars (stmts)
  "Walk STMTS for `\$v = (e1, e2, …)' assignments and return an
   alist mapping VAR-NAME → COMPONENT-LIST. Used to expand
   later \`@m[\$v]' references into composite-key form."
  (let ((acc nil))
    (labels ((maybe-record (lhs rhs)
               (when (and (consp lhs) (eq (first lhs) :var)
                          (consp rhs) (eq (first rhs) :tuple))
                 (push (cons (second lhs) (getf (cdr rhs) :items)) acc)))
             (walk (s)
               (case (first s)
                 (:assign (maybe-record (getf (cdr s) :lhs)
                                        (getf (cdr s) :rhs)))
                 (:if     (mapc #'walk (getf (cdr s) :then))
                          (mapc #'walk (getf (cdr s) :else)))
                 (:while  (mapc #'walk (getf (cdr s) :body))))))
      (mapc #'walk stmts))
    acc))

(defun expand-tuple-vars-script (script)
  "Apply expand-tuple-vars per probe (each has its own *tuple-vars*).
   Returns a new script with all `\$v = (e1, e2, …)' uses inlined
   to composite-key form."
  (cons (first script)
        (mapcar
         (lambda (form)
           (cond
             ((and (consp form) (eq (first form) :probe))
              (let* ((body (getf (cdr form) :body))
                     (pred (getf (cdr form) :predicate))
                     (*tuple-vars* (infer-tuple-vars body))
                     (body* (expand-tuple-vars body))
                     (pred* (when pred (expand-tuple-vars pred))))
                (loop for (k v) on (cdr form) by #'cddr
                      append (list k (cond ((eq k :body) body*)
                                           ((eq k :predicate) pred*)
                                           (t v)))
                        into rest
                      finally (return (cons :probe rest)))))
             (t form)))
         (rest script))))

(defun drop-tuple-assignments (stmts)
  "Drop \`\$v = (:tuple …)' statements from a body — the var is
   implicit (callers reach the components directly via expand-tuple-vars)."
  (mapcar
   (lambda (s)
     (cond
       ((and (eq (first s) :assign)
             (let ((rhs (getf (cdr s) :rhs)))
               (and (consp rhs) (eq (first rhs) :tuple))))
        '(:let-noop))
       ((eq (first s) :if)
        (list :if
              :cond (getf (cdr s) :cond)
              :then (drop-tuple-assignments (getf (cdr s) :then))
              :else (drop-tuple-assignments (getf (cdr s) :else))))
       ((eq (first s) :while)
        (list :while
              :cond (getf (cdr s) :cond)
              :body (drop-tuple-assignments (getf (cdr s) :body))))
       (t s)))
   stmts))

(defun expand-tuple-vars (form)
  "Substitute tuple-var references in @m[\$v] / delete(@m, \$v) /
   has_key(@m, \$v) shapes — replace \$v with its component list.
   Also flattens any inline `(:tuple :items …)' literal that appears
   in those same key positions, so `has_key(@m, (a, b))' becomes
   `has_key(@m, a, b)' without a name detour."
  (labels ((tuple-items (k)
             (cond
               ((and (consp k) (eq (first k) :var))
                (cdr (assoc (second k) *tuple-vars* :test #'string=)))
               ((and (consp k) (eq (first k) :tuple))
                (getf (cdr k) :items))))
           (expand-keys (keys)
             (mapcan (lambda (k)
                       (or (tuple-items k) (list k)))
                     keys))
           (walk (f)
             (cond
               ((not (consp f)) f)
               ;; @m[ keys ] — flatten tuple-var key into components.
               ((and (eq (first f) :map) (getf (cdr f) :keys))
                (loop for (k v) on (cdr f) by #'cddr
                      append (list k (cond ((eq k :keys) (expand-keys v))
                                           (t v)))
                        into rest
                      finally (return (cons :map rest))))
               ;; delete(@m, $v[, …]) / has_key(@m, $v) — keys are in
               ;; positional args 1+.
               ((and (eq (first f) :call)
                     (member (getf (cdr f) :name) '("delete" "has_key")
                             :test #'string=))
                (let* ((args (getf (cdr f) :args))
                       (head (first args))
                       (rest (rest args)))
                  (list :call
                        :name (getf (cdr f) :name)
                        :args (cons (walk head) (expand-keys rest)))))
               (t (cons (walk (first f)) (walk (rest f)))))))
    (walk form)))

(defun infer-comm-vars (stmts)
  "Return a list of var-name strings whose value comes from `comm'
   or from a string-valued map. Walks if/while bodies."
  (let ((acc nil))
    (labels ((string-map-read-p (e)
               (and (consp e) (eq (first e) :map)
                    (let ((info (and *map-table*
                                     (gethash (getf (cdr e) :name)
                                              *map-table*))))
                      (and info (minfo-value-string-p info)))))
             (maybe-record (lhs rhs)
               (when (and (consp lhs) (eq (first lhs) :var)
                          (or (and (consp rhs) (eq (first rhs) :comm))
                              (string-map-read-p rhs)))
                 (pushnew (second lhs) acc :test #'string=)))
             (walk (s)
               (case (first s)
                 (:assign (maybe-record (getf (cdr s) :lhs)
                                        (getf (cdr s) :rhs)))
                 (:if     (mapc #'walk (getf (cdr s) :then))
                          (mapc #'walk (getf (cdr s) :else)))
                 (:while  (mapc #'walk (getf (cdr s) :body))))))
      (mapc #'walk stmts))
    acc))

(defun infer-ntop-vars (stmts)
  "Return a list of var-name strings that hold an `ntop(…)' result.
   Walks the body — including nested if/while — recording any
   `\$v = ntop(...)' assignment AND any `\$v = @m[k]' where @m's
   value slot was marked value-ntop-p by infer-maps."
  (let ((acc nil))
    (labels ((ntop-call-p (e)
               (and (consp e) (eq (first e) :call)
                    (stringp (getf (cdr e) :name))
                    (string= (getf (cdr e) :name) "ntop")))
             (ntop-map-read-p (e)
               (and (consp e) (eq (first e) :map)
                    (let ((info (and *map-table*
                                     (gethash (getf (cdr e) :name)
                                              *map-table*))))
                      (and info (minfo-value-ntop-p info)))))
             (maybe-record (lhs rhs)
               (when (and (consp lhs) (eq (first lhs) :var)
                          (or (ntop-call-p rhs) (ntop-map-read-p rhs)))
                 (pushnew (second lhs) acc :test #'string=)))
             (walk (s)
               (case (first s)
                 (:assign (maybe-record (getf (cdr s) :lhs)
                                        (getf (cdr s) :rhs)))
                 (:if     (mapc #'walk (getf (cdr s) :then))
                          (mapc #'walk (getf (cdr s) :else)))
                 (:while  (mapc #'walk (getf (cdr s) :body))))))
      (mapc #'walk stmts))
    acc))

(defun infer-var-types (stmts)
  "Walk STMTS for `$v = (struct X *)EXPR' (or any RHS that contains
   a cast at its outermost reachable position) and return an alist
   (\"v\" . \"X\"). Also propagates types through map reads:
   `$v = @m[k]' picks up @m's value-struct (set when the map was
   first assigned a cast RHS), letting `$v.field' walks work
   transparently across an in-kernel `stash + retrieve' hop."
  (let ((acc nil))
    (labels ((rhs-cast-type (rhs)
               (cond
                 ((not (consp rhs)) nil)
                 ((eq (first rhs) :cast) (getf (cdr rhs) :type))
                 ((eq (first rhs) :field)
                  (rhs-cast-type (getf (cdr rhs) :base)))
                 ;; `$v = @m[k]' — inherit the map's value-struct.
                 ((eq (first rhs) :map)
                  (let ((info (and *map-table*
                                   (gethash (getf (cdr rhs) :name)
                                            *map-table*))))
                    (and info (minfo-value-struct info))))
                 (t nil)))
             (maybe-record (lhs rhs)
               (when (and (consp lhs) (eq (first lhs) :var))
                 (let ((ty (rhs-cast-type rhs)))
                   (when ty
                     (push (cons (second lhs) ty) acc)))))
             (walk (s)
               (case (first s)
                 (:assign (maybe-record (getf (cdr s) :lhs)
                                        (getf (cdr s) :rhs)))
                 (:if     (mapc #'walk (getf (cdr s) :then))
                          (mapc #'walk (getf (cdr s) :else)))
                 (:while  (mapc #'walk (getf (cdr s) :body))))))
      (mapc #'walk stmts))
    acc))

(defun probe-string-buf-size (body)
  "Walk BODY for `@m[k] = :str / :func / :probe-name / :comm' map
   assignments and return the largest value-size of any string-typed
   target map. Zero means no buffer needed."
  (let ((m 0))
    (labels ((maybe-bump (lhs rhs)
               (when (and (consp lhs) (eq (first lhs) :map)
                          (consp rhs)
                          (member (first rhs)
                                  '(:str :func :probe-name :comm)))
                 (let ((info (and *map-table*
                                  (gethash (getf (cdr lhs) :name)
                                           *map-table*))))
                   (when info
                     (setf m (max m (minfo-value-size info)))))))
             (walk (s)
               (case (first s)
                 (:assign (maybe-bump (getf (cdr s) :lhs)
                                      (getf (cdr s) :rhs)))
                 (:if     (mapc #'walk (getf (cdr s) :then))
                          (mapc #'walk (getf (cdr s) :else)))
                 (:while  (mapc #'walk (getf (cdr s) :body))))))
      (mapc #'walk body))
    m))

(defun gen-kernel-prog (spec pred body index sub)
  (multiple-value-bind (ptype section) (spec->section spec)
    (let* ((*probe-spec* spec)
           (*var-types*  (infer-var-types body))
           (*ntop-vars*  (infer-ntop-vars body))
           (*comm-vars*  (infer-comm-vars body))
           (*tuple-vars* (infer-tuple-vars body))
           (probe-str (format nil "~A" section))
           (func-str  (probe-func-name spec))
           (body      (rewrite-self-refs body probe-str func-str))
           (pred      (when pred (rewrite-self-refs pred probe-str func-str)))
           (body      (expand-tuple-vars body))
           (body      (drop-tuple-assignments body))
           (pred      (when pred (expand-tuple-vars pred)))
           ;; One shared scratch buffer for all string-valued map
           ;; writes in this probe (writeback.bt has 8, would blow
           ;; the 512-byte BPF stack if each got its own slot).
           (*string-set-buf-size* (probe-string-buf-size body))
           (*string-set-buf*
             (when (plusp *string-set-buf-size*) (gensym "STRBUF")))
           (prog-name (intern (format nil "BT-PROBE-~D-~D" index sub) :whistler))
           (vars      (collect-vars body))
           (body-forms (lower-stmts body))
           (pred-form (when pred (lower-expr pred)))
           (gated (if pred-form
                      `((when ,pred-form ,@body-forms))
                      body-forms))
           ;; Initialise each var. ntop-typed vars get a pointer to a
           ;; 17-byte slot, comm-typed vars get a 16-byte slot,
           ;; everything else starts 0.
           (var-inits
             (loop for v in vars
                   for name = (symbol-name v)
                   for as-bt = (and (> (length name) 1)
                                    (char= (char name 0) #\$)
                                    (subseq name 1))
                   for is-ntop = (and as-bt
                                      (member as-bt *ntop-vars*
                                              :test #'string-equal))
                   for is-comm = (and as-bt
                                      (member as-bt *comm-vars*
                                              :test #'string-equal))
                   collect (cond
                             (is-ntop `(,v (whistler::struct-alloc
                                            ,+bt-ntop-slot-size+)))
                             (is-comm `(,v (whistler::struct-alloc
                                            ,+bt-comm-len+)))
                             (t `(,v 0)))))
           ;; Prepend the shared string buffer to the bindings if used.
           (var-inits (if *string-set-buf*
                          (cons `(,*string-set-buf*
                                  (whistler::struct-alloc
                                   ,*string-set-buf-size*))
                                var-inits)
                          var-inits))
           (with-vars (if var-inits
                          `((let* ,var-inits ,@gated 0))
                          (append gated '(0)))))
      `(whistler:defprog ,prog-name
           (:type ,ptype :section ,section :license "GPL")
         ,@with-vars))))

(defun collect-tracepoint-fields (script)
  "Walk SCRIPT and return ((CAT EVENT) . (FIELD …)) entries —
   one per unique tracepoint, with the union of args->FIELD names
   referenced by any probe attached to it. Used to emit a single
   (deftracepoint …) at the top so common field macros aren't
   redefined per probe."
  (let ((table (make-hash-table :test 'equal)))
    (labels ((collect-fields (form acc)
               (cond
                 ((not (consp form)) acc)
                 ((and (eq (first form) :field)
                       (consp (getf (cdr form) :base))
                       (eq (first (getf (cdr form) :base)) :args))
                  (cons (getf (cdr form) :name)
                        ;; Field nodes can still contain nested args->X if
                        ;; someone wrote args->a.b — recurse to be safe.
                        (reduce (lambda (a x) (collect-fields x a))
                                (rest form) :initial-value acc)))
                 (t
                  ;; Walk every child whether or not the head is a keyword:
                  ;; the keys list of a :map is a plain list of nodes that
                  ;; itself isn't tagged, so reduce over the *whole* form
                  ;; including head — recurse on every cons cell.
                  (reduce (lambda (a x) (collect-fields x a))
                          form :initial-value acc)))))
      (dolist (probe (script-probes script))
        (let ((body (getf (cdr probe) :body)))
          (dolist (spec (getf (cdr probe) :specs))
            (when (eq (first spec) :tracepoint)
              (let* ((key (list (second spec) (third spec)))
                     (cur (gethash key table))
                     (here (reduce (lambda (a s) (collect-fields s a))
                                   body :initial-value nil)))
                (setf (gethash key table)
                      (remove-duplicates (append cur here) :test #'string=))))))))
    (loop for k being the hash-keys of table
          using (hash-value v)
          collect (cons k v))))

(defun gen-deftracepoint-preamble (script)
  "Emit one (deftracepoint …) per unique tracepoint. To avoid
   `redefining TP-X' warnings when the same field name (e.g. `pid')
   appears in several tracepoints, every field name is emitted into
   exactly one deftracepoint — the first tracepoint that references
   it. This is safe as long as same-named fields share offsets across
   the tracepoints involved (true for the sched_/syscalls_/block_
   families that share a common prefix layout)."
  (let ((emitted-fields (make-hash-table :test 'equal)))
    (loop for entry in (collect-tracepoint-fields script)
          for (cat event) = (car entry)
          for fields      = (cdr entry)
          for new-fields  = (loop for f in fields
                                  unless (gethash f emitted-fields)
                                    collect (progn
                                              (setf (gethash f emitted-fields) t)
                                              f))
          ;; Skip when this tracepoint contributes no new field names.
          ;; whistler:deftracepoint with no fields means "import them
          ;; all", which would re-define the same tp-X macros and
          ;; trigger redefinition warnings.
          when new-fields
            collect `(whistler:deftracepoint
                         ,(intern (format nil "~A/~A"
                                          (string-upcase cat)
                                          (substitute #\- #\_ (string-upcase event)))
                                  :whistler)
                       ,@(mapcar (lambda (f) (w-sym f)) new-fields)))))

;;; ========== Public entry ==========

(defun script-uses-elapsed-p (script)
  "T iff the script references the `elapsed' builtin anywhere — gates
   creation of the hidden script-start nsecs map."
  (labels ((walk (form)
             (cond
               ((not (consp form)) nil)
               ((and (eq (first form) :builtin) (eq (second form) :elapsed))
                t)
               (t (some #'walk form)))))
    (some (lambda (probe) (walk (getf (cdr probe) :body)))
          (script-probes script))))

(defun script-uses-exit-p (script)
  "Walk SCRIPT and return T if any call to `exit()` appears anywhere
   in any probe body. Used to decide whether to inject the hidden
   __bt-exit__ flag map."
  (labels ((walk (form)
             (cond
               ((not (consp form)) nil)
               ((and (eq (first form) :call)
                     (string= (getf (cdr form) :name) "exit"))
                t)
               (t (some #'walk form)))))
    (some (lambda (probe) (walk (getf (cdr probe) :body)))
          (script-probes script))))

(defun script-uses-printf-p (script)
  "T iff the script calls any function that emits a bt-print record
   (printf, print, clear, time) — gates injection of the bt-print
   ringbuf map."
  (labels ((walk (form)
             (cond
               ((not (consp form)) nil)
               ((and (eq (first form) :call)
                     (member (getf (cdr form) :name)
                             '("printf" "print" "clear" "time")
                             :test #'string=))
                t)
               (t (some #'walk form)))))
    (some (lambda (probe) (walk (getf (cdr probe) :body)))
          (script-probes script))))

(defun script-uses-kstack-p (script)
  "T iff `kstack' or `ustack' appears anywhere — gates injection of
   the hidden bt-stacks stack-trace map (shared by both)."
  (labels ((walk (form)
             (cond
               ((not (consp form)) nil)
               ((or (eq (first form) :kstack) (eq (first form) :ustack)) t)
               (t (some #'walk form)))))
    (some (lambda (probe) (walk (getf (cdr probe) :body)))
          (script-probes script))))

(defun generate (script)
  "Translate normalised SCRIPT to a plist:
     :maps          (defmap forms)
     :progs         (defprog/preamble forms, one per kernel probe)
     :user-probes   (list of (:spec … :body …) for BEGIN/END/interval)
     :info          (raw-name :name :kind :key-builtin :key-size :value-size :max-entries)
     :exit-map      symbol of the hidden bt-exit map, if exit() is used
     :print-map     symbol of the hidden bt-print ringbuf, if printf() is used
     :printf-table  ((id fmt-string nargs) …) for ringbuf-record decoding"
  (let* ((*tp-field-sizes* (load-tracepoint-field-sizes script))
         (*test-run-counter* 0)
         (*printf-table* nil)
         (*printf-id-counter* 0)
         (*time-format-table* nil)
         (*cat-paths-table* nil)
         (*map-id-table* nil)
         (*user-functions* (loop for fn in (script-functions script)
                                 collect (cons (getf (cdr fn) :name)
                                               (cdr fn))))
         ;; Expand tuple-var references BEFORE infer-maps so the map's
         ;; key-size lands at the composite total, not at 8 (the size
         ;; of the var alias).
         (script    (expand-tuple-vars-script script))
         (map-table (infer-maps script))
         (*map-table* map-table)
         (maps      (loop for info being the hash-values of map-table
                          collect (gen-defmap info)))
         (uses-exit (script-uses-exit-p script))
         (uses-printf (script-uses-printf-p script))
         (uses-kstack (script-uses-kstack-p script))
         (uses-elapsed (script-uses-elapsed-p script))
         (exit-map-form
           (when uses-exit
             `(whistler:defmap ,*exit-map-name*
                :type :array :key-size 4 :value-size 1 :max-entries 1)))
         (print-map-form
           (when uses-printf
             `(whistler:defmap ,*print-map-name*
                :type :ringbuf :max-entries 262144)))
         (stacks-map-form
           (when uses-kstack
             `(whistler:defmap ,*stacks-map-name*
                :type :stack-trace
                :key-size 4
                :value-size ,(* 8 +bt-stack-depth+)
                :max-entries 4096)))
         (elapsed-map-form
           (when uses-elapsed
             `(whistler:defmap ,*elapsed-map-name*
                :type :array :key-size 4 :value-size 8 :max-entries 1)))
         (probes    nil)
         (user      nil)
         (tp-preamble (gen-deftracepoint-preamble script)))
    (loop for probe in (script-probes script)
          for i from 0
          do (multiple-value-bind (kforms us) (gen-probe-forms probe i)
               (setf probes (append probes kforms)
                     user   (append user us))))
    (list :maps (append (when exit-map-form    (list exit-map-form))
                        (when print-map-form   (list print-map-form))
                        (when stacks-map-form  (list stacks-map-form))
                        (when elapsed-map-form (list elapsed-map-form))
                        maps)
          :progs (append tp-preamble probes)
          :user-probes user
          :exit-map (when uses-exit *exit-map-name*)
          :print-map (when uses-printf *print-map-name*)
          :stacks-map (when uses-kstack *stacks-map-name*)
          :elapsed-map (when uses-elapsed *elapsed-map-name*)
          :stack-depth +bt-stack-depth+
          :printf-table (reverse *printf-table*)
          :time-format-table (reverse *time-format-table*)
          :cat-paths-table (reverse *cat-paths-table*)
          :map-id-table (reverse *map-id-table*)
          :info (loop for raw being the hash-keys of map-table
                      using (hash-value info)
                      collect (list (or raw "@")
                                    :name (minfo-name info)
                                    :kind (minfo-kind info)
                                    :key-builtin (minfo-key-builtin info)
                                    :key-types (minfo-key-types info)
                                    :key-size (minfo-key-size info)
                                    :key-parts (if (> (minfo-key-size info) 8)
                                                   (/ (minfo-key-size info) 8)
                                                   1)
                                    :keyed-p (minfo-keyed-p info)
                                    :value-size (minfo-value-size info)
                                    :max-entries (minfo-max-entries info)
                                    :hist-params (minfo-hist-params info))))))
