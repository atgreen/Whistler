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
  value-array-p    ; T when the value slot holds the bytes of an in-
                   ;   script-struct array field. value-size is the
                   ;   total array width; lower-map-assign emits a
                   ;   probe-read into a stack buffer + map-update-ptr.
  value-ptr-elt-size ; Set when the map's value is a typed pointer
                   ;   stored from a `(T *)' cast — records sizeof(T).
                   ;   Lower-index reads `@m[k][i]' as probe-read of
                   ;   that many bytes at base+i*size.
  value-array-elt-size ; When value-array-p is T, this is sizeof(elt)
                   ;   so `@m[k][i]' subscripts the value buffer
                   ;   with a sized load.
  key-array-elt-size ; When the (single) map key is an in-script-struct
                   ;   array field, sizeof(elt). The userspace printer
                   ;   uses this with key-array-len to render keys as
                   ;   `[v1,v2,…]' matching bpftrace's array-key style.
  key-array-len    ; Number of elements in the array key when set.
  needs-len-counter-p ; T when any `len(@m)' in the script targets
                   ;   this map. Triggers emission of a `__len_NAME'
                   ;   sidecar (1-entry percpu-array u64) and the
                   ;   incf/decf injection on update/delete sites.
  hist-params)     ; for :lhist, the list (MIN MAX STEP); NIL otherwise.

(defun builtin-size (kw)
  (case kw
    ((:pid :tid :uid :gid :cpu) 4)
    (t 8)))

(defvar *tp-field-sizes* nil
  "Hash table FIELD-NAME (string) → (SIZE ARRAY-SIZE C-TYPE-STRING),
   populated once per generate() from every tracepoint format file
   referenced by the script. C-TYPE-STRING is the raw declaration
   text (e.g. \"struct __kernel_timespec *\") — used to flow the
   pointed-to struct through @map[k] = args.FIELD assignments.
   NIL outside generate().")

(defvar *tp-format-unreadable-paths* nil
  "List of tracepoint format-file paths the codegen couldn't open
   when populating *tp-field-sizes*. Used by lower-field's `non-
   args expressions' error path to surface a permissions hint when
   the field access depended on a type we couldn't resolve.")

(defun load-tracepoint-field-sizes (script)
  "Walk SCRIPT, parse each referenced tracepoint format file, and
   build *TP-FIELD-SIZES*. Skips when a format file can't be read,
   but pushes the path onto *tp-format-unreadable-paths* so we can
   surface a clearer error downstream — `field access on non-args
   expressions' is misleading when the real cause is `couldn't read
   /sys/kernel/tracing/events/…/format'."
  (let ((table (make-hash-table :test 'equal)))
    (dolist (probe (script-probes script))
      (dolist (spec (getf (cdr probe) :specs))
        (when (eq (first spec) :tracepoint)
          (let* ((cat (substitute #\_ #\- (second spec)))
                 (event (substitute #\_ #\- (third spec)))
                 (path (ignore-errors
                        (whistler::find-tracepoint-format-path cat event))))
            (cond
              (path
               (let ((fields (ignore-errors
                              (whistler::parse-tracepoint-format
                               (namestring path)))))
                 (cond
                   (fields
                    (dolist (field fields)
                      (destructuring-bind (c-name _off size _signed array
                                           &optional (c-type ""))
                          field
                        (declare (ignore _off _signed))
                        (setf (gethash c-name table)
                              (list size (or array 0) c-type)))))
                   (t (pushnew (namestring path) *tp-format-unreadable-paths*
                               :test #'string=)))))
              (t (pushnew (format nil "/sys/kernel/tracing/events/~A/~A/format"
                                  cat event)
                          *tp-format-unreadable-paths*
                          :test #'string=)))))))
    table))

(defun tp-field-size (name)
  "Tracepoint args.FIELD width in bytes, or NIL if unknown."
  (let ((cell (and *tp-field-sizes* (gethash name *tp-field-sizes*))))
    (cond
      ((consp cell) (first cell))
      ((integerp cell) cell)
      (t nil))))

(defun tp-array-size (name)
  "If tracepoint args.FIELD is an array, return its element count;
   otherwise 0 / NIL."
  (let ((cell (and *tp-field-sizes* (gethash name *tp-field-sizes*))))
    (cond ((consp cell) (second cell)) (t 0))))

(defun tp-field-struct-pointer (name)
  "If tracepoint args.FIELD's C type is `struct X *' (or `union X *'),
   return X as a string. NIL otherwise — used by infer-maps to attach
   value-struct to maps populated from struct-pointer tracepoint args."
  (let* ((cell (and *tp-field-sizes* (gethash name *tp-field-sizes*)))
         (c-type (and (consp cell) (third cell))))
    (when (stringp c-type)
      (let* ((trimmed (string-trim '(#\Space) c-type))
             (star (position #\* trimmed)))
        (when star
          (let* ((head (string-trim '(#\Space) (subseq trimmed 0 star)))
                 (prefix (cond
                           ((and (>= (length head) 7)
                                 (string= head "struct " :end1 7))
                            (subseq head 7))
                           ((and (>= (length head) 6)
                                 (string= head "union " :end1 6))
                            (subseq head 6))
                           (t nil))))
            (when prefix
              (string-trim '(#\Space) prefix))))))))

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
    ;; A string literal that was the result of rewrite-self-refs
    ;; folding `func' / `probe' into a fixed slot. Same width as the
    ;; original :func/:probe-name so the composite-key layout and
    ;; store-key-component agree on slot size.
    (:str         +bt-func-name-key-len+)
    (:kstack  4)
    (:ustack  4)
    (:call
     (cond
       ((or (str-call-p expr) (kstr-call-p expr)) (str-key-size expr))
       (t 8)))
    (:args   (or (bare-args-byte-width) 8))
    (:field
     (let ((name (getf (cdr expr) :name)))
       (cond
         ;; tracepoint args->FIELD: look up the real size from the
         ;; tracefs format file we parsed in load-tracepoint-field-sizes.
         ((and (consp (getf (cdr expr) :base))
               (eq (first (getf (cdr expr) :base)) :args)
               (tp-field-size name)))
         ;; In-script struct array field: `(struct A *)e.x' where x
         ;; is `int x[4]' has total size 16. Used as key/value width.
         ((multiple-value-bind (_b sz _o len) (array-field-meta expr)
            (declare (ignore _b _o))
            (and sz len (* sz len))))
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
           for af-meta = (and (eq (first e) :field) (multiple-value-list
                                                     (array-field-meta e)))
           for size = (cond
                        ((eq (first e) :comm) +bt-comm-len+)
                        ((or (eq (first e) :func)
                             (eq (first e) :probe-name))
                         +bt-func-name-key-len+)
                        ;; A literal string key (from func/probe rewrite)
                        ;; occupies a func-name-sized slot, NUL-padded.
                        ((eq (first e) :str) +bt-func-name-key-len+)
                        ((or (str-call-p e) (kstr-call-p e))
                         (str-key-size e))
                        ;; In-script struct array field — width is
                        ;; ELT-SIZE × ARR-LEN.
                        ((and af-meta (first af-meta))
                         (* (second af-meta) (fourth af-meta)))
                        ;; Bare `args' under fentry/fexit: param-count × 8.
                        ((and (eq (first e) :args) (bare-args-byte-width)))
                        (t 8))
           for type = (cond
                        ((eq (first e) :comm) u8)
                        ((or (eq (first e) :func)
                             (eq (first e) :probe-name)) u8)
                        ((eq (first e) :str) u8)
                        ((or (str-call-p e) (kstr-call-p e)) u8)
                        ((and af-meta (first af-meta)) u8)
                        ((and (eq (first e) :args) (bare-args-byte-width)) u8)
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
                    ((named-call-p expr "syscall_name") :syscall-name)
                    ((named-call-p expr "signal_name")  :signal-name)
                    (t nil)))
    (t        nil)))

(declaim (special *probe-spec*))

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
                                       :max-entries
                                       (script-max-map-keys 1024))))))
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
                   ;; Single-key that's an in-script-struct array
                   ;; field: record the array shape so the printer
                   ;; can render the key as `[v1,v2,…]'.
                   (when (= (length keys) 1)
                     (multiple-value-bind (_b sz _o len)
                         (array-field-meta (first keys))
                       (declare (ignore _b _o))
                       (when (and sz len)
                         (setf (minfo-key-array-elt-size info) sz
                               (minfo-key-array-len info) len))))
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
                   ;; `@m[k] = (T *)expr' — value is a typed pointer.
                   ;; Stash sizeof(T) on the minfo so later
                   ;; `@m[k][i]' reads emit a sized probe-read.
                   ((and (consp rhs) (eq (first rhs) :prim-ptr-cast))
                    (let ((sz (prim-ptr-elt-size (getf (cdr rhs) :elt-type))))
                      (when sz
                        (setf (minfo-value-ptr-elt-size info) sz))))
                   ;; `@m[k] = args.FIELD' where the tracepoint format
                   ;; declares FIELD as `struct X *' — propagate X
                   ;; into value-struct so `$v = @m[k]; $v.field' works
                   ;; without the user writing an explicit cast.
                   ;; naptime.bt's `@rqtp[tid] = args.rqtp; $t.tv_sec'
                   ;; idiom relies on this.
                   ((and (consp rhs) (eq (first rhs) :field)
                         (consp (getf (cdr rhs) :base))
                         (eq (first (getf (cdr rhs) :base)) :args))
                    (let ((sname (tp-field-struct-pointer
                                  (getf (cdr rhs) :name))))
                      (when (and sname (null (minfo-value-struct info)))
                        (setf (minfo-value-struct info) sname))))
                   ;; `@m = args' / `@m[k] = args' — value is the raw
                   ;; concatenated param bytes (fentry/fexit: param-
                   ;; count × 8). Treat as a wide-byte value: track
                   ;; the size, mark needs-ptr-ops via wide value-size.
                   ((and (consp rhs) (eq (first rhs) :args)
                         (bare-args-byte-width))
                    (let ((w (bare-args-byte-width)))
                      (setf (minfo-kind info) :scalar
                            (minfo-value-array-p info) t
                            (minfo-value-array-elt-size info) 1
                            (minfo-value-size info)
                            (max (minfo-value-size info) w))))
                   ;; `@m[k] = (struct X *)e.arrfield' — array-field
                   ;; flow. Map's value-size becomes total array bytes,
                   ;; mark value-array-p so lower-map-assign dispatches
                   ;; to the probe-read-into-buffer path.
                   ((and (consp rhs) (eq (first rhs) :field)
                         (multiple-value-bind (_b sz _o len)
                             (array-field-meta rhs)
                           (declare (ignore _b _o))
                           (and sz len)))
                    (multiple-value-bind (_b sz _o len) (array-field-meta rhs)
                      (declare (ignore _b _o))
                      (setf (minfo-kind info) :scalar
                            (minfo-value-array-p info) t
                            (minfo-value-array-elt-size info) sz
                            (minfo-value-size info)
                            (max (minfo-value-size info) (* sz len)))))
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
                   ;; `@m[k] = str(ptr)' / `kstr(ptr)' — probe-read a
                   ;; NUL-terminated string into the value slot. Size
                   ;; from the optional second arg, else default len.
                   ((and (consp rhs) (eq (first rhs) :call)
                         (or (str-call-p rhs) (kstr-call-p rhs)))
                    (setf (minfo-kind info) :scalar
                          (minfo-value-string-p info) t
                          (minfo-value-size info)
                          (max (minfo-value-size info)
                               (str-key-size rhs))))
                   ((and (consp rhs) (eq (first rhs) :call))
                    (let ((fn (getf (cdr rhs) :name)))
                      (cond
                        ((string= fn "count")
                         (setf (minfo-kind info) :counter))
                        ((string= fn "hist")
                         ;; Don't touch key-size / max-entries — the
                         ;; later hist-sizing loop overwrites them
                         ;; once it knows whether the map is keyed.
                         (setf (minfo-kind info) :hist))
                        ((string= fn "lhist")
                         (let* ((args (getf (cdr rhs) :args))
                                (literal (lambda (n)
                                           (let ((a (nth n args)))
                                             (cond
                                               ((and a (eq (first a) :int)) (second a))
                                               (t (unsupported
                                                   "lhist() requires literal min/max/step (got ~S)" a)))))))
                           (setf (minfo-kind info) :lhist
                                 (minfo-hist-params info)
                                 (list (funcall literal 1)
                                       (funcall literal 2)
                                       (funcall literal 3)))))
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
          ((note-len-target (e)
             ;; Walk E for any `len(@m)' call; flag every map argument
             ;; so a `__len_NAME' sidecar counter map gets emitted.
             (cond
               ((not (consp e)) nil)
               ((and (eq (first e) :call)
                     (string= (getf (cdr e) :name) "len")
                     (let ((arg (first (getf (cdr e) :args))))
                       (and (consp arg) (eq (first arg) :map))))
                (setf (minfo-needs-len-counter-p
                       (ensure (first (getf (cdr e) :args))))
                      t))
               (t (some #'note-len-target e))))
           (scan-stmt (stmt)
             (note-len-target stmt)
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
               ;; nested under if/while/for still get inferred.
               (:if
                (mapc #'scan-stmt (getf (cdr stmt) :then))
                (mapc #'scan-stmt (getf (cdr stmt) :else)))
               (:while
                (mapc #'scan-stmt (getf (cdr stmt) :body)))
               (:for
                (mapc #'scan-stmt (getf (cdr stmt) :body))))))
        (dolist (probe (script-probes script))
          (let* ((body (getf (cdr probe) :body))
                 (pred (getf (cdr probe) :predicate))
                 ;; The probe's first spec determines the args layout
                 ;; for any `args' use inside the body. Bind it as a
                 ;; dynvar so note-rhs / note-keys can size `@m = args'
                 ;; or `@m[args]' from BTF without re-reaching into the
                 ;; probe shape themselves.
                 (*probe-spec* (first (getf (cdr probe) :specs))))
            (when pred (when (eq (first pred) :map) (note-keys pred)))
            (mapc #'scan-stmt body)))
        ;; Also walk macro/fn bodies so map references inside
        ;; them (e.g. `@paths[k] = str(p)' in opensnoop's getcwd
        ;; macro) tag the value slot — the macro inliner runs at
        ;; lower time, after this pass.
        (dolist (defn (script-functions script))
          (mapc #'scan-stmt (getf (cdr defn) :body))))
      ;; Histogram maps: the bucket index is always a u32 slot.
      ;;   * Non-keyed (`@m = hist(x)') uses a percpu-array keyed by
      ;;     bucket only — key-size = 4, max-entries = 64 (log2) or
      ;;     N+2 (lhist).
      ;;   * Keyed (`@m[k] = hist(x)') uses a percpu-hash whose key
      ;;     is the user-key bytes followed by a u32 bucket — that's
      ;;     the user-key-size we already computed + 4. max-entries
      ;;     scales to fit many user-keys; we pick a generous default.
      (loop for info being the hash-values of table
            when (or (eq (minfo-kind info) :hist)
                     (eq (minfo-kind info) :lhist))
              do (let ((bucket-count
                         (if (eq (minfo-kind info) :hist)
                             64
                             (let* ((params (minfo-hist-params info)))
                               (+ 2 (max 1 (floor (- (second params)
                                                     (first params))
                                                  (third params))))))))
                   (cond
                     ((minfo-keyed-p info)
                      ;; Compound key = user-key bytes + u32 bucket.
                      ;; max-entries is bucket-count × an arbitrary
                      ;; user-key cap (1024 distinct keys).
                      (setf (minfo-key-size info)
                            (+ (minfo-key-size info) 4)
                            (minfo-max-entries info)
                            (* bucket-count 1024)))
                     (t
                      (setf (minfo-key-size info) 4
                            (minfo-max-entries info) bucket-count)))))
      table)))

;;; ========== Defmap forms ==========

(defun gen-defmap (info)
  (let* ((kind (minfo-kind info))
         (mtype (cond
                  ;; Keyed hist/lhist needs a hash map — different
                  ;; user-keys cohabit a single map, distinguished by
                  ;; the user-key bytes in front of the bucket index.
                  ((and (or (eq kind :hist) (eq kind :lhist))
                        (minfo-keyed-p info))
                   :percpu-hash)
                  ;; Non-keyed hist/lhist stays the pre-allocated
                  ;; percpu-array indexed by bucket.
                  ((or (eq kind :hist) (eq kind :lhist)) :percpu-array)
                  ;; sum/min/max/avg use percpu-hash so concurrent
                  ;; updates from different CPUs don't race (no atomics
                  ;; needed; userspace reduces across CPUs at print time).
                  ((member kind '(:sum :avg :stats :min :max)) :percpu-hash)
                  (t :hash))))
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

(defvar *str-vars* nil
  "Per-probe alist VAR-NAME → BUFFER-SIZE for vars assigned from a
   `str(…)' or `kstr(…)' call (or from reading a string-valued map
   slot). Each is backed by a BUFFER-SIZE-byte stack slot so
   probe-read-{user,kernel}-str can populate it and \`printf(\"%s\",
   \$v)' can emit the bytes. Indexing (`\$v[i]') reads u8 at offset
   i from the buffer.")

(defvar *var-ptr-elt-types* nil
  "Per-probe alist VAR-NAME → (TYPE-NAME-STRING ELT-SIZE-BYTES) for
   vars assigned from a `:prim-ptr-cast' — e.g. `$a = (int32 *) arg0'
   records `(\"$a\" . (\"int32\" 4))'. lower-index consults this so
   `$a[i]' emits a probe-read of ELT-SIZE bytes at base + i*ELT-SIZE.
   Distinct from *var-types* (struct names) so the existing
   struct-pointer code paths aren't disturbed.")

(defvar *var-array-types* nil
  "Per-probe alist VAR-NAME → (ELT-SIZE ARR-LEN) for vars assigned
   from a map whose value-array-p is set — e.g. `$x = @a[0]' where
   @a's value-size is `N*ELT-SIZE'. The var is backed by an inline
   `N*ELT-SIZE' stack buffer; the assignment fills it from the map,
   and `$x[i]' loads ELT-SIZE bytes at offset i*ELT-SIZE.")

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

(defvar *shared-key-buf* nil
  "Per-probe shared 8-byte stack buffer reused as the scalar map-key
   temporary across all gen-string-set calls in the same probe. A
   BEGIN block initialising N entries (capable.bt has 41) would
   otherwise allocate N × 8 bytes of single-use key buffers and blow
   the 512-byte stack frame.

   Important: this is a `struct-alloc' buffer, not a `let*'-bound
   u64. The emitter's key cache (emit-key-to-stack) records `this
   stack slot holds const N' when a u64 var with a known init value
   appears as a stack-addr target — and subsequent map-lookups for
   the same constant key reuse that slot WITHOUT re-storing the
   value. A `let*'-bound u64 reused here would silently corrupt
   readers: the slot holds whatever we last wrote (e.g. 40) but the
   cache still claims it holds 0, so @m[0] reads return the @m[40]
   entry. struct-alloc sidesteps the cache entirely.")

(defvar *shared-key-buf-used* nil
  "Set to T whenever a gen-*-set call lowers to use *shared-key-buf*
   so the prologue knows to allocate it.")

;;; ========== Per-CPU scratch map ==========
;;;
;;; The BPF stack frame is capped at 512 bytes. Non-trivial bpftrace
;;; tools (opensnoop's sys_exit with for-loop, multiple str() $vars,
;;; chained struct walks) blow that budget if every `struct-alloc' goes
;;; to the stack. We mirror what bpftrace + libbpf do: spill anything
;;; over a small threshold into a per-CPU BPF_MAP_TYPE_PERCPU_ARRAY,
;;; max_entries=1, value_size = max-probe-need bytes. Per-CPU storage
;;; means no contention; a single map_lookup at probe entry returns the
;;; CPU-local buffer pointer and every spilled alloc becomes
;;; `(+ scratch-base compile-time-offset)'.

(defvar +bt-scratch-threshold+ 32
  "struct-alloc requests larger than this go to the per-CPU scratch
   map rather than the BPF stack. Matches bpftrace's on_stack_limit
   default and gives us roughly the same stack/scratch split. Rebound
   by `generate' from `config = { on_stack_limit = N }' when set.")

(defvar *bt-scratch-map-name* (intern "--BT-SCRATCH--" :whistler)
  "Symbol naming the auto-defined per-CPU scratch array map.")

(defvar *scratch-allocations* nil
  "Per-probe alist of (TAG . SIZE) for every large struct-alloc
   the rewriter intercepted in this probe. Populated by
   rewrite-large-struct-allocs, consumed by the layout step that
   assigns each TAG an offset within the per-CPU scratch buffer.")

(defvar *scratch-base-sym* nil
  "Per-probe gensym bound at probe entry to the result of looking up
   the scratch map's per-CPU slot. NIL outside a probe or when no
   spilled allocs were rewritten.")

(defvar *max-scratch-bytes* 0
  "Per-generate() maximum of `(probe-scratch-bytes …)' across all
   probes. Sets the auto-defined scratch map's value-size.")

(defun rewrite-large-struct-allocs (form)
  "Walk a lowered probe body. Replace each (whistler::struct-alloc N)
   with N > +bt-scratch-threshold+ by a marker (:bt-scratch-slot TAG N)
   for later offset-substitution, and record (TAG . N) into
   *scratch-allocations*. Small struct-allocs pass through unchanged
   and continue to use the BPF stack."
  (cond
    ((not (consp form)) form)
    ((and (eq (first form) (intern "STRUCT-ALLOC" :whistler))
          (integerp (second form))
          (> (second form) +bt-scratch-threshold+))
     (let ((tag (gensym "BT-SCR-"))
           (size (second form)))
       (push (cons tag size) *scratch-allocations*)
       (list :bt-scratch-slot tag size)))
    (t (cons (rewrite-large-struct-allocs (first form))
             (rewrite-large-struct-allocs (rest form))))))

(defun substitute-scratch-offsets (form offsets)
  "Walk FORM and replace each (:bt-scratch-slot TAG SIZE) marker with
   (whistler::+ *scratch-base-sym* OFFSET) using OFFSETS, an alist
   (TAG . OFFSET) computed once per probe after rewriting."
  (cond
    ((not (consp form)) form)
    ((and (eq (first form) :bt-scratch-slot)
          (assoc (second form) offsets))
     `(whistler::+ ,*scratch-base-sym*
                   ,(cdr (assoc (second form) offsets))))
    (t (cons (substitute-scratch-offsets (first form) offsets)
             (substitute-scratch-offsets (rest form) offsets)))))

(defun assign-scratch-offsets (allocations)
  "Lay each (TAG . SIZE) out back-to-back. Returns (offsets-alist
   total-bytes). Order is preserved so identical bodies get identical
   layouts — easier on the diff and on the BPF verifier's cache."
  (let ((offsets nil) (off 0))
    (dolist (pair (reverse allocations))
      (push (cons (car pair) off) offsets)
      (incf off (cdr pair)))
    (values (nreverse offsets) off)))

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
            (user-entry  (assoc struct-name *script-struct-decls*
                                :test #'string=)))
       (cond
         (user-entry
          (let ((cell (find field-name (cddr user-entry)
                            :test #'string= :key #'first)))
            (unless cell
              (unsupported "offsetof(struct ~A, ~A): no such field in in-script decl"
                           struct-name field-name))
            (third cell)))
         (t
          (let* ((vmbtf (whistler:ensure-vmlinux-btf))
                 (tid (whistler:btf-find-struct vmbtf struct-name))
                 (fields (and tid (whistler:btf-struct-fields vmbtf tid)))
                 (cell (find field-name fields :test #'string= :key #'first)))
            (unless cell
              (unsupported "offsetof(struct ~A, ~A): no such field"
                           struct-name field-name))
            (third cell))))))
    (:sizeof
     (let* ((name      (getf (cdr expr) :name))
            (struct-p  (getf (cdr expr) :struct-p)))
       (cond
         (struct-p
          (let ((user-entry (assoc name *script-struct-decls*
                                   :test #'string=)))
            (cond
              (user-entry (second user-entry))
              (t (let* ((vmbtf (whistler:ensure-vmlinux-btf))
                        (tid (whistler:btf-find-struct vmbtf name)))
                   (unless tid
                     (unsupported "sizeof(struct ~A): not in vmlinux BTF" name))
                   (whistler:btf-struct-size vmbtf tid))))))
         (t
          (or (cdr (assoc (string-downcase name)
                          '(("u8"  . 1) ("u16" . 2) ("u32" . 4) ("u64" . 8)
                            ("int8" . 1) ("int16" . 2) ("int32" . 4)
                            ("int64" . 8)
                            ("int"   . 4) ("uint"   . 4)
                            ("long"  . 8) ("ulong"  . 8)
                            ("char"  . 1) ("uchar"  . 1)
                            ("short" . 2) ("ushort" . 2))
                          :test #'string=))
              (unsupported "sizeof(~A): unrecognised primitive type" name))))))
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
    ;; Bare primitive-pointer cast — `((int32 *) arg0)' in expression
    ;; position with no subscript. The element type matters at index
    ;; sites (lower-index); here the result is just the underlying
    ;; pointer value, which we hand back as a u64.
    (:prim-ptr-cast (lower-expr (getf (cdr expr) :expr)))
    ;; Plain `(int8)x' / `(uint32)x' integer cast. The IR is all u64,
    ;; so we just lower the inner expression. Width-aware ops like
    ;; bswap peek at this node before reaching here.
    (:int-cast      (lower-expr (getf (cdr expr) :expr)))
    ;; Positional CLI parameter — `$1', `$2', …. Resolved from
    ;; *positional-args* at compile time. Numeric tokens lower to
    ;; their integer value; non-numeric tokens become 0 (matching
    ;; bpftrace's documented behaviour for non-int $N reads when
    ;; the use site is an integer context). Missing index also 0.
    (:positional
     (let* ((n   (second expr))
            (val (nth (1- n) *positional-args*)))
       (or (and val (parse-integer val :junk-allowed t))
           0)))
    ;; `{ stmt; stmt; … expr }' — bpftrace 0.22+ block expression.
    ;; Lower to a CL `progn' that runs the statements for their
    ;; side effects and returns the trailing expr's value. Useful
    ;; for `if ({ let $a = …; $a })' / `let $x = { … ; … }' shapes.
    (:block-expr
     (let ((stmts (getf (cdr expr) :stmts))
           (final (getf (cdr expr) :final)))
       `(progn
          ,@(mapcar #'lower-stmt stmts)
          ,(lower-expr final))))
    (:constant   (or (resolve-constant (second expr))
                     ;; bpftrace allows zero-arg `macro' to be called
                     ;; bare — `sysname' (no parens) means `sysname()'.
                     ;; A bare lowercase ident that didn't resolve to
                     ;; a constant may still be a registered macro.
                     (and (find-user-function (second expr))
                          (inline-user-call (second expr) nil))
                     ;; `usermode' — bpftrace builtin returning 1 in
                     ;; user-context probes (uprobe/uretprobe/USDT),
                     ;; 0 otherwise. Resolved at compile time from the
                     ;; active probe spec.
                     (and (string= (second expr) "usermode")
                          (if (member (first *probe-spec*)
                                      '(:uprobe :uretprobe :usdt))
                              1 0))
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
    (:args       (lower-bare-args))
    (:probe-name (unsupported "probe builtin"))
    (:func       (unsupported "func builtin"))
    (:incdec-expr (lower-incdec-expr expr))
    (:bin        (lower-bin expr))
    (:un         (lower-un expr))
    (:tern       (lower-tern expr))
    (:call       (lower-call expr))
    (:field      (lower-field expr))
    (:index      (lower-index expr))
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
   (2) script-level enum decl members, then (3) BTF enums + the
   curated table. Returns the integer value or NIL."
  (or (cdr (assoc name *user-cpp-defines* :test #'string=))
      (cdr (assoc name *script-enum-values* :test #'string=))
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

(defun lower-fail (args)
  "fail(\"FMT\", LITERAL…) — compile-time static assert. If every arg
   is a literal we format the message now and signal an error so the
   build halts (matching bpftrace's semantics). With non-literal
   args we route to runtime errorf instead."
  (unless args
    (unsupported "fail() with no message"))
  (let ((fmt (first args)))
    (unless (eq (first fmt) :str)
      (unsupported "fail() format must be a string literal"))
    (let* ((fmt-str (second fmt))
           (extras  (rest args))
           (literal-p (every (lambda (a)
                               (and (consp a)
                                    (member (first a) '(:int :str))))
                             extras)))
      (cond
        (literal-p
         (let ((msg (apply #'format nil
                           (substitute-c-printf-to-cl fmt-str)
                           (mapcar (lambda (a)
                                     (if (eq (first a) :str) (second a) (second a)))
                                   extras))))
           (whistler/compiler:whistler-error :what (format nil "fail(): ~A" msg))))
        (t
         (lower-printf args :stream :stderr :fn-name "fail"))))))

(defun substitute-c-printf-to-cl (fmt)
  "Translate the subset of C printf directives we actually use
   (%d / %u / %x / %s) to CL FORMAT directives, so the compile-time
   `fail()' formatter can render literal args without involving the
   runtime decoder."
  (with-output-to-string (out)
    (loop with i = 0 with n = (length fmt)
          while (< i n)
          do (let ((c (char fmt i)))
               (cond
                 ((char= c #\%)
                  (let ((j (1+ i)))
                    ;; skip flags/width/precision
                    (loop while (and (< j n)
                                     (find (char fmt j) "-+0123456789. l"))
                          do (incf j))
                    (when (< j n)
                      (case (char fmt j)
                        ((#\d #\i #\u) (write-string "~D" out))
                        ((#\x #\X)     (write-string "~X" out))
                        ((#\s)         (write-string "~A" out))
                        ((#\%)         (write-string "%" out))
                        (t (write-string "%?" out)))
                      (setf i (1+ j)))))
                 ((char= c #\~) (write-string "~~" out) (incf i))
                 (t (write-char c out) (incf i)))))))

(defun lower-cgroupid (args)
  "Resolve cgroupid(\"/sys/fs/cgroup/PATH\") at compile time by stat'ing
   the directory and emitting its inode number as a literal."
  (unless (and (= (length args) 1)
               (consp (first args))
               (eq (first (first args)) :str))
    (unsupported "cgroupid(): arg must be a string literal path"))
  (let* ((path (second (first args)))
         (stat (ignore-errors (sb-posix:stat path))))
    (unless stat
      (unsupported "cgroupid(): could not stat ~S" path))
    (sb-posix:stat-ino stat)))

(defun parse-ipv4 (s)
  "Parse `1.2.3.4' → list of 4 octets, or NIL on bad input."
  (let ((parts (loop with acc = nil
                     with cur = ""
                     for c across s
                     do (cond
                          ((char= c #\.)
                           (push cur acc) (setf cur ""))
                          (t (setf cur (concatenate 'string cur (string c)))))
                     finally (push cur acc) (return (nreverse acc)))))
    (when (= (length parts) 4)
      (let ((nums (mapcar (lambda (p) (parse-integer p :junk-allowed nil))
                          parts)))
        (when (every (lambda (n) (and (integerp n) (<= 0 n 255))) nums)
          nums)))))

(defun parse-ipv6 (s)
  "Parse a textual IPv6 address (`::1', `2001:db8::1', …) into 16
   bytes. Returns NIL on bad input. Compresses one `::' run; raises
   on malformed double-compress."
  (let ((dblcol (search "::" s)))
    (labels ((groups (sub)
               (when (zerop (length sub)) (return-from groups nil))
               (let (parts (cur ""))
                 (loop for c across sub
                       do (cond
                            ((char= c #\:)
                             (push cur parts) (setf cur ""))
                            (t (setf cur (concatenate 'string cur (string c))))))
                 (push cur parts)
                 (mapcar (lambda (g) (parse-integer g :radix 16 :junk-allowed nil))
                         (nreverse parts)))))
      (let* ((head (when dblcol (groups (subseq s 0 dblcol))))
             (tail (when dblcol (groups (subseq s (+ dblcol 2)))))
             (flat (cond
                     ((null dblcol) (groups s))
                     (t (let ((zero-count (- 8 (+ (length head) (length tail)))))
                          (and (>= zero-count 0)
                               (append head (make-list zero-count :initial-element 0)
                                       tail)))))))
        (when (and flat (= (length flat) 8)
                   (every (lambda (g) (and (integerp g) (<= 0 g #xffff))) flat))
          ;; 8 u16 → 16 bytes big-endian.
          (loop for g in flat
                append (list (ash g -8) (logand g #xff))))))))

(defun lower-pton (args)
  "Lower `pton(\"1.2.3.4\")' or `pton(\"::1\")' to a struct-alloc
   buffer pre-filled with the parsed bytes. Returns a pointer."
  (unless (and (= (length args) 1)
               (consp (first args))
               (eq (first (first args)) :str))
    (unsupported "pton(): arg must be a string literal"))
  (let* ((text (second (first args)))
         (v4   (parse-ipv4 text))
         (v6   (unless v4 (parse-ipv6 text)))
         (bytes (or v4 v6))
         (size  (length bytes))
         (buf   (gensym "PTON")))
    (unless bytes
      (unsupported "pton(): could not parse ~S as IPv4 or IPv6" text))
    `(let ((,buf (whistler::struct-alloc ,size)))
       ,@(loop for b in bytes for i from 0
               collect `(whistler::store whistler::u8 ,buf ,i ,b))
       ,buf)))

(defun ast-literal-p (expr)
  "True when EXPR is a compile-time literal — an :int, :str, or a
   :constant whose name is in the curated/BTF table."
  (and (consp expr)
       (member (first expr) '(:int :str :constant))))

(defun ast-matches-type-p (expr type-name)
  "Best-effort compile-time type predicate. Returns T when EXPR's
   shape matches TYPE-NAME (one of \"is_str\" / \"is_ptr\" /
   \"is_array\" / \"is_integer\" / \"is_unsigned_integer\"). The
   shape rules below cover the cases user macros typically need;
   non-trivial typed expressions fall through to NIL rather than
   guess wrong."
  (let ((kind
          (cond
            ((and (consp expr) (eq (first expr) :int))      :integer)
            ((and (consp expr) (eq (first expr) :str))      :str)
            ((and (consp expr) (eq (first expr) :comm))     :str)
            ((and (consp expr) (eq (first expr) :pcomm))    :str)
            ((and (consp expr) (eq (first expr) :func))     :str)
            ((and (consp expr) (eq (first expr) :probe-name)) :str)
            ;; A :var typed as a comm/str slot is a string.
            ((and (consp expr) (eq (first expr) :var)
                  (or (member (second expr) *comm-vars* :test #'string-equal)
                      (assoc (second expr) *str-vars* :test #'string-equal)))
             :str)
            ;; A :var typed as a struct ptr is a pointer.
            ((and (consp expr) (eq (first expr) :var)
                  (assoc (second expr) *var-types* :test #'string-equal))
             :ptr)
            ;; bare $var with no special typing defaults to integer.
            ((and (consp expr) (eq (first expr) :var)) :integer)
            ((and (consp expr) (eq (first expr) :builtin)) :integer)
            ((and (consp expr) (eq (first expr) :arg))    :integer)
            ((and (consp expr) (eq (first expr) :retval)) :integer)
            ((and (consp expr) (eq (first expr) :bin))    :integer)
            (t nil))))
    (cond
      ((string= type-name "is_str")     (eq kind :str))
      ((string= type-name "is_ptr")     (eq kind :ptr))
      ((string= type-name "is_array")   nil)  ;; no first-class arrays
      ((string= type-name "is_integer") (eq kind :integer))
      ((string= type-name "is_unsigned_integer") (eq kind :integer))
      (t nil))))

(defun lower-static-assert (args)
  "static_assert(cond, msg) — compile-time predicate. We only know
   `cond' at compile time when it's a literal integer / bool; in
   that case false → whistler-error, true → no-op. Non-literal
   cond falls through to runtime assert()."
  (unless (= (length args) 2)
    (unsupported "static_assert() takes (cond, msg)"))
  (let ((c (first args))
        (m (second args)))
    (cond
      ((and (consp c) (eq (first c) :int))
       (cond
         ((zerop (second c))
          (whistler/compiler:whistler-error
           :what (format nil "static_assert: ~A"
                          (if (and (consp m) (eq (first m) :str))
                              (second m)
                              "assertion failed"))))
         (t 0)))
      ((and (consp c) (eq (first c) :constant)
            (member (second c) '("false" "0") :test #'string=))
       (whistler/compiler:whistler-error
        :what (format nil "static_assert: ~A"
                       (if (and (consp m) (eq (first m) :str))
                           (second m)
                           "assertion failed"))))
      ;; Truthy literal-shaped cond → no-op.
      ((and (consp c) (member (first c) '(:int :constant))) 0)
      ;; Non-literal — punt to runtime assert.
      (t (lower-assert args)))))

(defun lower-assert (args)
  "assert(cond, msg) — bpftrace's stdlib macro. Reduces to
   `if (!cond) { errorf(\"assert failed: %s\", msg); exit(1); }'."
  (unless (= (length args) 2)
    (unsupported "assert() takes (cond, msg)"))
  (let* ((cond-expr (first args))
         (msg-arg   (second args))
         (cond-form (lower-expr cond-expr)))
    `(whistler::unless ,cond-form
       ,(lower-printf (list (list :str (concatenate 'string
                                                    "assert failed: %s"
                                                    (string #\Newline)))
                            msg-arg)
                      :stream :stderr :fn-name "assert")
       ,(lower-call '(:call :name "exit" :args ())))))

(defun string-var-buf-size (var-name)
  "Return the maximum byte width of a $var-backed string slot, or NIL
   when VAR-NAME isn't string-typed."
  (cond
    ((assoc var-name *str-vars* :test #'string-equal)
     (cdr (assoc var-name *str-vars* :test #'string-equal)))
    ((member var-name *comm-vars* :test #'string-equal)
     +bt-comm-len+)
    (t nil)))

(defun lower-len (args)
  "len(s) for a string-typed $var or `comm' / `pcomm' — walk the
   slot byte-by-byte until the first NUL, return the offset. For
   `len(@m)' (a map ref), reads the sidecar counter map that
   infer-maps tagged the map with."
  (unless (= (length args) 1)
    (unsupported "len() takes one argument"))
  (let ((arg (first args)))
    ;; Map form: `len(@m)' — read the sidecar counter.
    (when (and (consp arg) (eq (first arg) :map))
      (let* ((info (or (gethash (or (getf (cdr arg) :name) "@") *map-table*)
                       (unsupported "len(): unknown map @~A"
                                    (getf (cdr arg) :name)))))
        (unless (minfo-needs-len-counter-p info)
          ;; Should be set by infer-maps; if not, the script slipped
          ;; past our walker.
          (unsupported "len(@~A): internal — sidecar counter not registered"
                       (or (minfo-raw-name info) "")))
        (return-from lower-len
          `(whistler:getmap ,(len-counter-sym info) 0)))))
  (let* ((arg (first args))
         (cap (cond
                ((eq (first arg) :comm)  +bt-comm-len+)
                ((eq (first arg) :pcomm) +bt-comm-len+)
                ((and (eq (first arg) :var)
                      (string-var-buf-size (second arg))))
                (t (unsupported
                    "len(): arg must be `comm', `pcomm', a string-typed $var, or `@m'"))))
         (buf-form
           (cond
             ((eq (first arg) :comm)
              (let ((b (gensym "COMMBUF")))
                `(let ((,b (whistler::struct-alloc ,+bt-comm-len+)))
                   (whistler::get-current-comm ,b ,+bt-comm-len+)
                   ,b)))
             ((eq (first arg) :pcomm)
              (let ((b (gensym "PCOMMBUF")))
                `(let ((,b (whistler::struct-alloc ,+bt-comm-len+)))
                   ,(lower-pcomm-into-record b 0 +bt-comm-len+)
                   ,b)))
             (t (var-sym (second arg)))))
         (buf (gensym "BUF"))
         (acc (gensym "LEN")))
    `(let* ((,buf ,buf-form)
            (,acc whistler::u64 0))
       ;; Unrolled scan: for each byte, only advance the counter
       ;; while no NUL has been seen yet. The branchless accumulator
       ;; lets the verifier prove termination without a loop.
       ,@(loop for i below cap
               for done = (gensym "DONE")
               collect
               `(let ((,done (whistler::!=
                              (whistler::load whistler::u8 ,buf ,i) 0)))
                  (whistler:incf ,acc (whistler::logand ,done 1))))
       ,acc)))

(defun lower-strcontains (args)
  "strcontains(haystack, needle): returns non-zero if NEEDLE (a string
   literal) is found anywhere in HAYSTACK. Implemented as N − len +1
   strncmp-style probes at increasing offsets, OR'd together."
  (unless (= (length args) 2)
    (unsupported "strcontains() takes (haystack, needle)"))
  (let ((haystack (first args))
        (needle   (second args)))
    (unless (and (consp needle) (eq (first needle) :str))
      (unsupported "strcontains(): needle must be a string literal"))
    ;; Literal haystack short-circuit: both args known at compile
    ;; time, fold the search and return a constant 0/1.
    (when (and (consp haystack) (eq (first haystack) :str))
      (let ((h (second haystack))
            (n (second needle)))
        (return-from lower-strcontains
          (if (search n h) 1 0))))
    (let* ((bytes (sb-ext:string-to-octets (second needle)
                                            :external-format :utf-8))
           (nlen  (length bytes))
           (hay-cap (cond
                      ((eq (first haystack) :comm)  +bt-comm-len+)
                      ((eq (first haystack) :pcomm) +bt-comm-len+)
                      ((and (eq (first haystack) :var)
                            (string-var-buf-size (second haystack))))
                      (t (unsupported
                          "strcontains(): haystack must be `comm', `pcomm', or a string $var"))))
           (buf-form
             (cond
               ((eq (first haystack) :comm)
                (let ((b (gensym "COMMBUF")))
                  `(let ((,b (whistler::struct-alloc ,+bt-comm-len+)))
                     (whistler::get-current-comm ,b ,+bt-comm-len+)
                     ,b)))
               (t (var-sym (second haystack)))))
           (buf (gensym "BUF"))
           (hit (gensym "HIT")))
      `(let* ((,buf ,buf-form)
              (,hit whistler::u64 0))
         ;; For each candidate start position, OR together the per-byte
         ;; XORs. The position matched iff the accumulator is 0. We
         ;; flip that into a hit bit and OR it into the global flag.
         ,@(loop for start from 0 to (max 0 (- hay-cap nlen))
                 for acc = (gensym "ACC")
                 collect
                 `(let ((,acc whistler::u64 0))
                    ,@(loop for k below nlen
                            collect
                            `(whistler:incf
                              ,acc
                              (whistler::logxor
                               (whistler::load whistler::u8 ,buf ,(+ start k))
                               ,(aref bytes k))))
                    (when (whistler::= ,acc 0)
                      (whistler:incf ,hit 1))))
         ,hit))))

(defun lower-find (args)
  "find(@map, key, $var) — bpftrace's stdlib map-lookup-with-default
   pattern. Reduces to `(has_key(@m, k) ? ($var = @m[k]) : 0; …)'
   except we want to return 1 / 0 explicitly. Today's contract:
   * exactly three arguments,
   * first is an @map ref,
   * third is a bare $var lvalue."
  (unless (= 3 (length args))
    (unsupported "find() takes (@map, key, $var)"))
  (let ((mref (first args))
        (key  (second args))
        (var  (third args)))
    (unless (and (consp mref) (eq (first mref) :map))
      (unsupported "find(): first arg must be an @map reference"))
    (unless (and (consp var) (eq (first var) :var))
      (unsupported "find(): third arg must be a $var lvalue"))
    (let* ((var-sym (var-sym (second var)))
           (map-info (or (gethash (getf (cdr mref) :name) *map-table*)
                         (unsupported "find(): unknown map @~A"
                                      (getf (cdr mref) :name))))
           (mname (minfo-name map-info))
           (k     (lower-expr key)))
      `(whistler:if-let ((,(gensym "FPTR")
                          (whistler::map-lookup ,mname ,k)))
         (progn (setf ,var-sym (whistler:getmap ,mname ,k)) 1)
         0))))

(defun lower-strstr (args)
  "strstr(haystack, needle) — like strcontains but returns the
   1-based byte offset of the first match, or 0 if not found.
   bpftrace's stdlib returns 0 for `not found' (vs C strstr's NULL);
   we mirror that for predicate use (`if (strstr(s, t)) …')."
  (unless (= (length args) 2)
    (unsupported "strstr() takes (haystack, needle)"))
  (let ((haystack (first args))
        (needle   (second args)))
    (unless (and (consp needle) (eq (first needle) :str))
      (unsupported "strstr(): needle must be a string literal"))
    ;; Literal-haystack short-circuit: fold to 1-based position
    ;; (matching bpftrace's strstr return) or 0 when not found.
    (when (and (consp haystack) (eq (first haystack) :str))
      (let* ((h (second haystack))
             (n (second needle))
             (p (search n h)))
        (return-from lower-strstr (if p (1+ p) 0))))
    (let* ((bytes (sb-ext:string-to-octets (second needle)
                                            :external-format :utf-8))
           (nlen  (length bytes))
           (hay-cap (cond
                      ((eq (first haystack) :comm)  +bt-comm-len+)
                      ((eq (first haystack) :pcomm) +bt-comm-len+)
                      ((and (eq (first haystack) :var)
                            (string-var-buf-size (second haystack))))
                      (t (unsupported
                          "strstr(): haystack must be `comm', `pcomm', or a string $var"))))
           (buf-form
             (cond
               ((eq (first haystack) :comm)
                (let ((b (gensym "COMMBUF")))
                  `(let ((,b (whistler::struct-alloc ,+bt-comm-len+)))
                     (whistler::get-current-comm ,b ,+bt-comm-len+)
                     ,b)))
               (t (var-sym (second haystack)))))
           (buf (gensym "BUF"))
           (pos (gensym "POS")))
      `(let* ((,buf ,buf-form)
              (,pos whistler::u64 0))
         ;; First-match scan. We sweep candidate starts; the first
         ;; one whose XOR-accumulator is zero stamps its (1-based)
         ;; offset into POS. Subsequent matches are ignored because
         ;; POS is already non-zero.
         ,@(loop for start from 0 to (max 0 (- hay-cap nlen))
                 for acc = (gensym "ACC")
                 collect
                 `(let ((,acc whistler::u64 0))
                    ,@(loop for k below nlen
                            collect
                            `(whistler:incf
                              ,acc
                              (whistler::logxor
                               (whistler::load whistler::u8 ,buf ,(+ start k))
                               ,(aref bytes k))))
                    (when (whistler::logand (whistler::= ,acc 0)
                                            (whistler::= ,pos 0))
                      (setf ,pos ,(1+ start)))))
         ,pos))))

(defun lower-strncmp (args)
  "Lower `strncmp(s1, s2, n)' to an inline byte-by-byte compare.
   Returns 0 when the first N bytes of S1 equal S2; non-zero
   otherwise. Constraints today:
     * S2 must be a string literal — its bytes are baked in.
     * N must be a literal integer.
     * S1 must be `comm', `pcomm', or a $var that's already a
       string/comm slot pointer (see *str-vars* / *comm-vars*)."
  (unless (= (length args) 3)
    (unsupported "strncmp() takes exactly (s1, s2, n)"))
  (let ((s1 (first args))
        (s2 (second args))
        (n  (third args)))
    (unless (and (consp s2) (eq (first s2) :str))
      (unsupported "strncmp(): second arg must be a string literal"))
    (unless (and (consp n) (eq (first n) :int))
      (unsupported "strncmp(): third arg must be a literal int"))
    (let* ((literal (second s2))
           (limit   (second n))
           (bytes   (sb-ext:string-to-octets literal :external-format :utf-8))
           (cmp-len (min limit (length bytes)))
           (acc     (gensym "ACC"))
           (buf     (gensym "BUF"))
           (s1-ptr-form
             (cond
               ((eq (first s1) :comm)
                ;; comm needs a fresh copy via get_current_comm; no
                ;; bare pointer is exposed in expression context.
                (let ((b (gensym "COMM")))
                  `(let ((,b (whistler::struct-alloc ,+bt-comm-len+)))
                     (whistler::get-current-comm ,b ,+bt-comm-len+)
                     ,b)))
               ((and (eq (first s1) :var)
                     (or (member (second s1) *comm-vars* :test #'string-equal)
                         (assoc (second s1) *str-vars* :test #'string-equal)))
                (var-sym (second s1)))
               (t
                (unsupported
                 "strncmp(): first arg must be `comm', `pcomm', or a string-typed $var")))))
      `(let* ((,buf ,s1-ptr-form)
              (,acc whistler::u64 0))
         ;; OR-accumulate per-byte XOR: result is 0 iff every byte
         ;; pair matched. We compare across CMP-LEN bytes; any extra
         ;; LIMIT > literal length expects S1[i] = 0, which is the
         ;; convention C strncmp follows after the literal NUL.
         ,@(loop for i below cmp-len
                 collect `(whistler:incf ,acc
                                         (whistler::logxor
                                          (whistler::load whistler::u8 ,buf ,i)
                                          ,(aref bytes i))))
         ,@(loop for i from cmp-len below limit
                 collect `(whistler:incf ,acc
                                         (whistler::load whistler::u8 ,buf ,i)))
         ,acc))))

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
    ;; let*-bind dst-ptr and src-ptr so each gets a stable surface vreg.
    ;; Without this staging, the verifier rejects naptime.bt's printf:
    ;; the codegen for the inline `(+ rec off)' dst expression and the
    ;; size constant 16 both land in R1 across the helper call setup,
    ;; clobbering the dst pointer before bpf_probe_read_kernel runs.
    (let ((dst-ptr (gensym "PCOMM-DST"))
          (src-ptr (gensym "PCOMM-SRC")))
      `(let ((,parent (whistler::struct-alloc 8)))
         (whistler::probe-read-kernel
          ,parent 8 (whistler::+ (whistler::get-current-task) ,rp-off))
         (let* ((,dst-ptr (whistler::+ ,rec ,off))
                (,src-ptr (whistler::+ (whistler::load whistler::u64 ,parent 0)
                                       ,co-off)))
           (whistler::probe-read-kernel ,dst-ptr ,size ,src-ptr))))))

(defun lower-current-task-int-field (field-name size-bytes load-type)
  "probe-read a scalar field SIZE-BYTES wide off current_task,
   returning the LOAD-TYPE value. Used for leader_tid (which is just
   the current task's `tgid')."
  (let* ((vmbtf (whistler:ensure-vmlinux-btf))
         (task-id (whistler:btf-find-struct vmbtf "task_struct"))
         (fields (and task-id (whistler:btf-struct-fields vmbtf task-id)))
         (cell (find field-name fields :test #'string= :key #'first))
         (off (and cell (third cell)))
         (buf (gensym "TBUF")))
    (unless off
      (unsupported "leader_tid: vmlinux BTF missing task_struct.~A" field-name))
    `(let ((,buf (whistler::struct-alloc ,size-bytes)))
       (whistler::probe-read-kernel
        ,buf ,size-bytes
        (whistler::+ (whistler::get-current-task) ,off))
       (whistler::load ,(intern (symbol-name load-type) :whistler) ,buf 0))))

(defun lower-leader-comm ()
  "Walk current_task→group_leader and copy its TASK_COMM_LEN-byte
   comm[] into a fresh stack buffer; return that buffer pointer."
  (let* ((vmbtf (whistler:ensure-vmlinux-btf))
         (task-id (whistler:btf-find-struct vmbtf "task_struct"))
         (fields (and task-id (whistler:btf-struct-fields vmbtf task-id)))
         (gl (find "group_leader" fields :test #'string= :key #'first))
         (co (find "comm"         fields :test #'string= :key #'first))
         (gl-off (and gl (third gl)))
         (co-off (and co (third co)))
         (leader (gensym "LEADER"))
         (buf    (gensym "LCOMM")))
    (unless (and gl-off co-off)
      (unsupported "leader_comm: vmlinux BTF missing task_struct.group_leader/comm"))
    `(let* ((,leader (whistler::struct-alloc 8))
            (,buf    (whistler::struct-alloc ,+bt-comm-len+)))
       (whistler::probe-read-kernel
        ,leader 8 (whistler::+ (whistler::get-current-task) ,gl-off))
       (whistler::probe-read-kernel
        ,buf ,+bt-comm-len+
        (whistler::+ (whistler::load whistler::u64 ,leader 0) ,co-off))
       ,buf)))

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
       (t (lower-arg-overflow n))))
    ((:kretprobe :uretprobe)
     (unsupported "arg~D in ret-probe — retval is the only accessor" n))
    ;; In fentry / fexit programs the ctx is `__u64 ctx[N]` where
    ;; ctx[i] is the i-th argument to the traced function. Direct
    ;; ctx-load — no pt_regs indirection.
    ((:kfunc :kretfunc)
     `(whistler::ctx ,(intern "U64" :whistler) ,(* n 8)))
    (:tracepoint (unsupported "tracepoint arg~D — use args->field" n))))

(defun lower-arg-overflow (n)
  "Args 6+ (or 8+ on arm64) live on the kernel stack, not in pt_regs
   registers. On x86-64 the System V ABI puts arg7+ at *(rsp + (n-5)*8)
   — the kprobe fires before the function prologue, so pt_regs.rsp
   still points at the return address with the stack-passed args
   following. Read them via probe-read-kernel."
  (cond
    #+arm64
    ((= n 6) '(whistler:pt-regs-parm7))
    #+arm64
    ((= n 7) '(whistler:pt-regs-parm8))
    (t
     (let* ((sp #+x86-64 152 #+arm64 248
                #-(or x86-64 arm64)
                (unsupported "arg~D on unsupported architecture" n))
            ;; Off-by-one: arg6 (index 6) is at sp+8, arg7 at sp+16, …
            ;; on x86-64 (first 6 args in regs, rsp[0]=ret addr).
            ;; On arm64, x0..x7 are regs, arg8 (index 8) is at sp+0,
            ;; arg9 at sp+8, … — but we route arg6/arg7 to parm7/parm8
            ;; above, so arm64 only lands here for index >= 8.
            (stack-off #+x86-64 (* (- n 5) 8)
                       #+arm64  (* (- n 8) 8))
            (buf (gensym "ARGSTK")))
       `(let ((,buf (whistler::struct-alloc 8)))
          (whistler::probe-read-kernel
           ,buf 8 (whistler::+ (whistler::ctx whistler::u64 ,sp) ,stack-off))
          (whistler::load whistler::u64 ,buf 0))))))

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

(defun lower-array-compare (op lhs-expr rhs-expr)
  "Lower `$a.x == $b.x' / `$a.x != $b.x' where both sides are in-
   script struct array fields. Probe-reads both arrays into stack
   buffers, XOR-accumulates byte-by-byte, returns 1 / 0. The sizes
   must match — if they don't we just return inequality (matches
   bpftrace's `arrays of different sizes are never equal' rule)."
  (multiple-value-bind (lbase lsz loff llen) (array-field-meta lhs-expr)
    (multiple-value-bind (rbase rsz roff rlen) (array-field-meta rhs-expr)
      (let ((lbytes (* lsz llen))
            (rbytes (* rsz rlen)))
        (cond
          ((/= lbytes rbytes) (if (eq op :==) 0 1))
          (t
           (let ((lbuf (gensym "ABUF"))
                 (rbuf (gensym "ABUF"))
                 (acc  (gensym "ACC"))
                 (helper (pick-probe-read-fn)))
             `(let* ((,lbuf (whistler::struct-alloc ,lbytes))
                     (,rbuf (whistler::struct-alloc ,lbytes))
                     (,acc  whistler::u64 0))
                (,helper ,lbuf ,lbytes
                         (whistler::+ ,(lower-expr lbase) ,loff))
                (,helper ,rbuf ,lbytes
                         (whistler::+ ,(lower-expr rbase) ,roff))
                ,@(loop for i below lbytes
                        collect `(whistler:incf
                                  ,acc
                                  (whistler::logxor
                                   (whistler::load whistler::u8 ,lbuf ,i)
                                   (whistler::load whistler::u8 ,rbuf ,i))))
                ,(if (eq op :==)
                     `(whistler::if (whistler::= ,acc 0) 1 0)
                     `(whistler::if (whistler::= ,acc 0) 0 1)))))))
      )))

(defun lower-bin (expr)
  (let* ((op  (getf (cdr expr) :op))
         (raw-lhs (getf (cdr expr) :lhs))
         (raw-rhs (getf (cdr expr) :rhs)))
    ;; Special case: comm == / != "literal".
    (when (member op '(:== :!=))
      (let ((cmp (comm-string-comparison op raw-lhs raw-rhs)))
        (when cmp (return-from lower-bin cmp))))
    ;; Special case: array-field == / != array-field. Read both into
    ;; buffers, XOR-accumulate per byte, return (acc == 0) for ==.
    (when (and (member op '(:== :!=))
               (array-field-meta raw-lhs)
               (array-field-meta raw-rhs))
      (return-from lower-bin (lower-array-compare op raw-lhs raw-rhs)))
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

(defun len-counter-sym (info)
  "Symbol for the `len(@m)' sidecar counter map. Built off the
   user map's whistler symbol so naming collisions can't happen."
  (intern (concatenate 'string "__LEN_"
                       (symbol-name (minfo-name info)))
          :whistler))

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
(defconstant +bt-tag-system+    6)
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
      ((string= name "lhist") (unsupported "lhist() must be on the RHS of @map = …"))
      ((string= name "exit")
       ;; Set the exit flag the userspace print loop polls every tick.
       `(setf (whistler:getmap ,*exit-map-name* 0) 1))
      ((string= name "printf") (lower-printf (getf (cdr expr) :args)))
      ;; errorf("fmt", …) — same as printf() but the userspace decoder
      ;; routes the line to *error-output* (stderr).
      ((string= name "errorf")
       (lower-printf (getf (cdr expr) :args)
                     :stream :stderr :fn-name "errorf"))
      ;; warnf("fmt", …) — same as errorf but the userspace decoder
      ;; prepends `WARNING: ' so it matches bpftrace's render.
      ((string= name "warnf")
       (lower-printf (getf (cdr expr) :args)
                     :stream :stderr-warning :fn-name "warnf"))
      ;; fail("fmt", …) — compile-time static-assert. bpftrace
      ;; evaluates the literal args at compile time and aborts the
      ;; build with the message. We do the same when every arg is
      ;; a literal; otherwise we punt to runtime errorf so the user
      ;; still sees a message in dev workflows.
      ((string= name "fail") (lower-fail (getf (cdr expr) :args)))
      ((string= name "print")
       (let ((args (getf (cdr expr) :args)))
         (cond
           ;; print(@map[, top[, div]]) — original async-map path.
           ((and args (consp (first args)) (eq (first (first args)) :map))
            (lower-async-map +bt-tag-print-map+ args "print"))
           ;; print(non-map) — bpftrace allows print(VAL) for any
           ;; scalar/string. We route through printf with an inferred
           ;; format, appending a newline (bpftrace's `print' always
           ;; terminates the line).
           (t (lower-print-value args)))))
      ((string= name "clear")  (lower-async-map +bt-tag-clear-map+
                                                (getf (cdr expr) :args)
                                                "clear"))
      ((string= name "zero")   0)
      ((string= name "time")   (lower-async-time
                                (getf (cdr expr) :args)))
      ((string= name "cat")    (lower-async-cat
                                (getf (cdr expr) :args)))
      ;; system("cmd") — async event. The literal command is interned
      ;; under an id; userspace runs it via the shell at decode time.
      ((string= name "system") (lower-async-system
                                (getf (cdr expr) :args)))
      ((string= name "join")   (lower-async-join
                                (getf (cdr expr) :args)))
      ;; ustack() / kstack() called as functions with an optional
      ;; depth arg — bpftrace's `printf("%s", ustack(1))' style. The
      ;; depth hint is informational (we capture a fixed-depth trace
      ;; via bpf_get_stackid regardless), so we dispatch to the same
      ;; helpers as the bare-builtin form.
      ((string= name "ustack")
       `(whistler::get-stackid (whistler::ctx-ptr) ,*stacks-map-name*
                                ,(ash 1 8)))
      ((string= name "kstack")
       `(whistler::get-stackid (whistler::ctx-ptr) ,*stacks-map-name* 0))
      ;; `nsecs(CLOCK)' — bpftrace 0.22+ accepts an optional clock
      ;; selector. We don't yet thread the clock through, so just
      ;; emit the same ktime-ns the bare-builtin form would.
      ((string= name "nsecs")
       '(whistler::ktime-ns))
      ((string= name "delete") 0)           ; lower-expr-stmt handles the real call
      ((string= name "reg")    (lower-reg-call (getf (cdr expr) :args)))
      ((string= name "kaddr")  (lower-kaddr-call (getf (cdr expr) :args)))
      ((string= name "percpu_kaddr")
       (lower-percpu-kaddr-call (getf (cdr expr) :args)))
      ((string= name "has_key") (lower-has-key-call (getf (cdr expr) :args)))
      ;; `bswap(x)' — byte-swap. bpftrace's bswap on a u16/u32 reverses
      ;; the byte order. We pick the width from key context; for the
      ;; common `bswap(\$port)' (a u16 from skc_dport) the 16-bit
      ;; version is what we need. Use the 16-bit swap pattern that
      ;; works for u16 values; higher bytes pass through if any are set.
      ((string= name "bswap")
       (lower-bswap (first (getf (cdr expr) :args))))
      ;; `getopt(NAME, DEFAULT, HELP)' — bpftrace's CLI-flag accessor.
      ;; If NAME was passed via `whistler bpftrace script.bt -- --NAME[=V]'
      ;; the parsed value lands in whistler/bpftrace:*named-params*, and
      ;; we emit an integer literal for it. Otherwise we lower DEFAULT
      ;; (which the bpftrace stdlib seeds as `false' / int / string).
      ;; Only bool and int variants are supported today; string defaults
      ;; without a CLI override still flow through unchanged.
      ((string= name "getopt")
       (let* ((args     (getf (cdr expr) :args))
              (opt-name (and (consp (first args))
                             (eq (first (first args)) :str)
                             (second (first args))))
              (default  (or (second args) '(:int 0)))
              (provided (and opt-name *named-params*
                             (assoc opt-name *named-params* :test #'string=))))
         (cond
           ((null provided)
            (lower-expr default))
           ;; Bool-shaped default: false/true via :constant, or :bool
           ;; literal if the parser ever emits one. Bare `--name' → 1,
           ;; `--name=true`/`--name=1` → 1, `--name=false`/`--name=0` → 0.
           ((or (and (consp default) (eq (first default) :constant)
                     (or (string= (second default) "false")
                         (string= (second default) "true")))
                (and (consp default) (eq (first default) :bool)))
            (let* ((raw (cdr provided))
                   (v (cond
                        ((or (null raw) (string= raw "")) 1)
                        ((member raw '("1" "true") :test #'string=) 1)
                        ((member raw '("0" "false") :test #'string=) 0)
                        (t (unsupported "getopt(~S, bool): unrecognised value ~S"
                                        opt-name raw)))))
              v))
           ;; Int-shaped default.
           ((and (consp default) (eq (first default) :int))
            (or (parse-integer (or (cdr provided) "") :junk-allowed t)
                (unsupported "getopt(~S, int): could not parse value ~S as integer"
                             opt-name (cdr provided))))
           (t
            (unsupported "getopt(~S): CLI override only supported for bool / int defaults"
                         opt-name)))))
      ;; `syscall_name(N)' — bpftrace returns a string; we instead pass
      ;; the syscall number through unchanged and let the userspace
      ;; print path map it to a name via the :syscall-name key-hint
      ;; (see key-hint / format-key). Works for the common usage
      ;; `@m[syscall_name(args.id)] = count()' but not as a printf %s
      ;; arg — that needs kernel-side string-table lookup.
      ((string= name "syscall_name")
       (lower-expr (first (getf (cdr expr) :args))))
      ;; `signal_name(N)' — same pattern: passes N (the signal number)
      ;; through and tags the key column for userspace rendering.
      ((string= name "signal_name")
       (lower-expr (first (getf (cdr expr) :args))))
      ;; `kptr(p)' / `uptr(p)' — bpftrace uses these to annotate
      ;; pointers as kernel- or user-space for its type checker. We
      ;; don't carry the kind/user-vs-kernel distinction in our type
      ;; system, so they're identity passes.
      ((or (string= name "kptr") (string= name "uptr"))
       (lower-expr (first (getf (cdr expr) :args))))
      ((string= name "strncmp") (lower-strncmp (getf (cdr expr) :args)))
      ;; assert(cond, msg) — runtime check. When cond is falsy, route
      ;; the message through errorf and flip the exit flag.
      ((string= name "assert")
       (lower-assert (getf (cdr expr) :args)))
      ((string= name "len")     (lower-len     (getf (cdr expr) :args)))
      ((string= name "strcontains")
       (lower-strcontains (getf (cdr expr) :args)))
      ((string= name "strstr")
       (lower-strstr (getf (cdr expr) :args)))
      ;; find(@map, key, $var) — when KEY is in @MAP, copy the
      ;; value into $VAR and return 1; otherwise return 0 (and
      ;; leave $VAR unchanged). bpftrace's stdlib macro pulls the
      ;; same behavior together via has_key + the map's lookup.
      ((string= name "find")
       (lower-find (getf (cdr expr) :args)))
      ;; jiffies() — kernel helper #118. Monotonic u64.
      ((and (string= name "jiffies") (null (getf (cdr expr) :args)))
       '(whistler::jiffies64))
      ;; is_err(ptr) — IS_ERR-style check: pointers in the
      ;; [-4095, 0) range encode an errno. Inline as
      ;; `ptr < 0 && ptr >= -4095'.
      ((and (string= name "is_err") (= 1 (length (getf (cdr expr) :args))))
       (let ((p (gensym "P")))
         `(let ((,p ,(lower-expr (first (getf (cdr expr) :args)))))
            (whistler::logand (whistler::< ,p 0)
                              (whistler::>= ,p -4095)))))
      ;; static_assert(cond, msg) — bpftrace's compile-time check.
      ;; Folds to fail() when cond is a literal-false expression.
      ((string= name "static_assert")
       (lower-static-assert (getf (cdr expr) :args)))
      ;; assert_str(exp) — compile-time check that EXP has string
      ;; type. bpftrace's stdlib spelling expands to nested ifs over
      ;; is_str / is_ptr; for us it folds straight to a 0 (no-op) or
      ;; whistler-error so the build halts early.
      ((string= name "assert_str")
       (cond
         ((/= 1 (length (getf (cdr expr) :args)))
          (unsupported "assert_str() takes one argument"))
         ((ast-matches-type-p (first (getf (cdr expr) :args)) "is_str") 0)
         (t (whistler/compiler:whistler-error
             :what (format nil
                           "assert_str: expression ~S is not a string"
                           (first (getf (cdr expr) :args)))))))
      ;; cpid() / has_cpid() — child PID from `-c CMD'. Resolved
      ;; at codegen time from whistler/bpftrace:*child-cpid*, which
      ;; the CLI binds before compile-script runs.
      ((and (string= name "cpid") (null (getf (cdr expr) :args)))
       (or *child-cpid* 0))
      ((and (string= name "has_cpid") (null (getf (cdr expr) :args)))
       (if *child-cpid* 1 0))
      ;; leader_tid() — TID of the thread-group leader. Same as the
      ;; current task's `tgid' field for the no-arg form.
      ((and (string= name "leader_tid") (null (getf (cdr expr) :args)))
       (lower-current-task-int-field "tgid" 4 'u32))
      ;; leader_comm() — emit a comm-style buffer holding the group
      ;; leader's TASK_COMM_LEN bytes. Walks
      ;; `current_task->group_leader->comm'.
      ((and (string= name "leader_comm") (null (getf (cdr expr) :args)))
       (lower-leader-comm))
      ;; Compile-time type predicates from bpftrace's meta.bt. Each
      ;; folds to a 0/1 integer literal based on the argument's AST
      ;; shape, so generic macros can dispatch with `if comptime'.
      ((string= name "is_literal")
       (if (= 1 (length (getf (cdr expr) :args)))
           (if (ast-literal-p (first (getf (cdr expr) :args))) 1 0)
           (unsupported "is_literal() takes one argument")))
      ((or (string= name "is_str") (string= name "is_ptr")
           (string= name "is_array") (string= name "is_integer")
           (string= name "is_unsigned_integer"))
       (if (= 1 (length (getf (cdr expr) :args)))
           (if (ast-matches-type-p (first (getf (cdr expr) :args)) name) 1 0)
           (unsupported "~A() takes one argument" name)))
      ((string= name "pton")    (lower-pton (getf (cdr expr) :args)))
      ;; cgroupid("/sys/fs/cgroup/PATH") — compile-time stat() of
      ;; the cgroup directory; emits its inode number as a literal.
      ;; Used for `kprobe:foo /cgroup == cgroupid("/sys/fs/cgroup/my")/'
      ;; filtering. bpftrace mirrors this contract exactly.
      ((string= name "cgroupid") (lower-cgroupid (getf (cdr expr) :args)))
      ;; socket_cookie(sk) — kernel helper #46. Stable per-socket
      ;; identifier; survives across CPUs and reuse so it's safer
      ;; than a sock-pointer key.
      ((string= name "socket_cookie")
       `(whistler::get-socket-cookie
         ,(lower-expr (first (getf (cdr expr) :args)))))
      ;; signal(N) — bpf_send_signal. Sends the given signal to the
      ;; current task. Returns 0 on success.
      ((string= name "signal")
       `(whistler::send-signal
         ,(lower-expr (first (getf (cdr expr) :args)))))
      ;; override(retval) — bpf_override_return. Replaces the
      ;; kprobed function's return value. Requires the target
      ;; function to be marked CONFIG_FUNCTION_ERROR_INJECTION.
      ;; Only valid inside kprobe (not kretprobe).
      ((string= name "override")
       `(whistler::override-return
         (whistler::ctx-ptr)
         ,(lower-expr (first (getf (cdr expr) :args)))))
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
    (let* ((body* (mapcar (lambda (s) (substitute-vars s subs)) body)))
      ;; Macro bodies aren't visible to the per-probe inference pass —
      ;; type/ntop/comm/tuple-var maps were built before macros were
      ;; expanded. Extend the dynamic vars in place so $vars assigned
      ;; in the macro body (e.g. `$dentry = curtask.fs.pwd.dentry;')
      ;; are typed before their .field uses lower. Pushed to the
      ;; *front* so the macro's bindings shadow any earlier ones.
      (let ((new-types  (infer-var-types body*))
            (new-tuples (infer-tuple-vars body*))
            (new-ntop   (infer-ntop-vars body*))
            (new-comm   (infer-comm-vars body*))
            (new-str    (infer-str-vars body*)))
        (when new-types  (setf *var-types*  (append new-types  *var-types*)))
        (when new-tuples (setf *tuple-vars* (append new-tuples *tuple-vars*)))
        (when new-ntop   (setf *ntop-vars*  (append new-ntop   *ntop-vars*)))
        (when new-comm   (setf *comm-vars*  (append new-comm   *comm-vars*)))
        (when new-str    (setf *str-vars*   (append new-str    *str-vars*))))
      (let ((forms (mapcar #'lower-fn-stmt body*)))
        ;; Single trailing :return → its expression IS the result.
        ;; Multiple forms → wrap in progn; the last form's value wins.
        (cond
          ((null forms) 0)
          ((= (length forms) 1) (first forms))
          (t `(progn ,@forms)))))))

(defun substitute-vars (form subs)
  "Walk FORM (an AST), substituting parameter references. SUBS is an
   alist keyed by the param's sigilled name:
     * `$name' param ←→ (:var NAME)
     * bare `name' param ←→ (:constant NAME) or (:builtin :NAME)
     * `@name' param ←→ (:map :name NAME …) — :name is rewritten to
       the actual map's name and :keys is preserved from the body.
   No conflation: `$ret' and bare `ret' look up under different keys
   so a macro body can keep them distinct."
  (cond
    ((not (consp form)) form)
    ((and (eq (first form) :var) (stringp (second form)))
     (let ((cell (assoc (concatenate 'string "$" (second form))
                        subs :test #'string=)))
       (cond (cell (cdr cell))
             (t form))))
    ((and (eq (first form) :builtin) (keywordp (second form)))
     (let* ((sname (string-downcase (symbol-name (second form))))
            (cell  (assoc sname subs :test #'string=)))
       (cond (cell (cdr cell))
             (t form))))
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

(defun lower-percpu-kaddr-call (args)
  "Lower percpu_kaddr(\"name\") or percpu_kaddr(\"name\", cpu) — looks
   up the per-CPU symbol in /proc/kallsyms then calls
   bpf_per_cpu_ptr(ptr, cpu) to materialise the per-CPU instance's
   address. With no CPU arg, defaults to the current CPU."
  (unless (and args (consp (first args))
               (eq (first (first args)) :str)
               (or (= 1 (length args)) (= 2 (length args))))
    (unsupported "percpu_kaddr() takes (\"name\" [, cpu])"))
  (unless *kallsyms-addr-cache*
    (setf *kallsyms-addr-cache* (load-kallsyms-addrs)))
  (let* ((name (second (first args)))
         (addr (gethash name *kallsyms-addr-cache*))
         (cpu  (if (cdr args)
                   (lower-expr (second args))
                   '(whistler::get-smp-processor-id))))
    (unless addr
      (unsupported "percpu_kaddr(~S) — symbol not found in /proc/kallsyms"
                   name))
    `(whistler::per-cpu-ptr ,addr ,cpu)))

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
   the named map. ARGS is one @map reference, plus (for print only)
   optional TOP and DIV — `print(@m, 10)' shows the top 10 entries,
   `print(@m, 10, 1000)' additionally divides each value by 1000.
   Clear and zero accept only the single @map form."
  (unless (and args (consp (first args)) (eq (first (first args)) :map))
    (unsupported "~A() needs an @map as its first argument" op-name))
  (let* ((mref (first args))
         (extras (rest args))
         (map-id (intern-map-id mref))
         (rec (gensym "REC"))
         (u32 (intern "U32" :whistler)))
    (cond
      ;; print(@m), print(@m, N), print(@m, N, D) — 16-byte record so
      ;; the kernel side can attach top/div without a second tag.
      ((string= op-name "print")
       (when (> (length extras) 2)
         (unsupported "print() takes at most 3 args: @map, top, div"))
       (let ((top (or (first extras) '(:int 0)))
             (div (or (second extras) '(:int 0))))
         `(whistler:with-ringbuf (,rec ,*print-map-name* 16)
            (whistler::store ,u32 ,rec 0 ,tag)
            (whistler::store ,u32 ,rec 4 ,map-id)
            (whistler::store ,u32 ,rec 8 ,(lower-expr top))
            (whistler::store ,u32 ,rec 12 ,(lower-expr div)))))
      ;; clear / zero — still single-arg.
      (t
       (when extras
         (unsupported "~A() takes a single @map argument" op-name))
       `(whistler:with-ringbuf (,rec ,*print-map-name* 8)
          (whistler::store ,u32 ,rec 0 ,tag)
          (whistler::store ,u32 ,rec 4 ,map-id))))))

(defvar *time-format-table* nil
  "Per-generate() alist (ID . FMT-STRING). Each time(FMT) call gets
   an ID; the kernel emits (tag, id) and userspace looks the format
   up to strftime it.")

(defvar *system-cmds-table* nil
  "Per-generate() alist (ID . COMMAND-STRING). Each system() call
   registers under a unique ID; the kernel emits (tag, id) and
   userspace runs the command at print-loop time via SB-EXT:RUN-PROGRAM.")

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

(defun lower-async-system (args)
  "Emit a tagged ringbuf record asking userspace to spawn the literal
   command. Only literal commands today — matches what bpftrace
   itself supports."
  (unless (and (= (length args) 1)
               (consp (first args))
               (eq (first (first args)) :str))
    (unsupported "system() arg must be a string literal command"))
  (let* ((cmd (second (first args)))
         (id (1+ (length *system-cmds-table*)))
         (rec (gensym "REC")))
    (push (cons id cmd) *system-cmds-table*)
    `(whistler:with-ringbuf (,rec ,*print-map-name* 8)
       (whistler::store ,(intern "U32" :whistler) ,rec 0 ,+bt-tag-system+)
       (whistler::store ,(intern "U32" :whistler) ,rec 4 ,id))))

(defun lower-async-time (args)
  "Emit a tagged ringbuf record asking userspace to stamp the current
   wall-clock time. With no args, uses bpftrace's default
   `%H:%M:%S\\n'. With one string-literal arg, that strftime format
   is interned and looked up at print time."
  (let ((fmt (cond
               ((null args) (format nil "%H:%M:%S~%"))
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

(defvar +bt-str-default-len+ 64
  "Default buffer size used by str(ptr) — matches bpftrace's default.
   Rebound by `generate' from the script's `config = { max_strlen = N }'
   when present.")

(defun script-config-int (key default)
  "Look KEY up in *script-config* and parse the value as an integer.
   Returns DEFAULT when the key is absent or the value is unparseable."
  (let* ((pair (assoc key *script-config* :test #'string=))
         (n    (and pair (parse-integer (cdr pair) :junk-allowed t))))
    (or n default)))

(defun script-config-string (key default)
  "Return KEY's value from *script-config* as a trimmed string, or
   DEFAULT when absent."
  (let ((pair (assoc key *script-config* :test #'string=)))
    (if pair
        (string-trim '(#\Space #\Tab) (cdr pair))
        default)))

(defun script-max-map-keys (default)
  "Effective default max-entries for hash maps. Honors
   `config = { max_map_keys = N }'."
  (script-config-int "max_map_keys" default))

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
    ;; `strerror(errno-expr)' — kernel emits the integer; userspace
    ;; runs it through strerror(3) at print time.
    ((named-call-p expr "strerror") :strerror)
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
    ;; macaddr(ptr) — wire format is 6 raw bytes. Userspace renders
    ;; them as `xx:xx:xx:xx:xx:xx'.
    ((named-call-p expr "macaddr") :macaddr)
    ;; path(struct path *) — uses bpf_d_path to write the path bytes
    ;; into a NUL-padded buffer; userspace renders the result.
    ((named-call-p expr "path") (cons :string +bt-str-default-len+))
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
    ((eq arg-type :macaddr) 6)
    ((eq arg-type :buf) (+ 4 +bt-buf-max-len+))
    ((eq arg-type :strerror) 4)  ; the errno as u32; userspace strerror(3)s it
    ((and (consp arg-type) (eq (car arg-type) :string))   (cdr arg-type))
    ((and (consp arg-type) (eq (car arg-type) :strftime)) 8)  ; just the u64 timestamp
    (t (error "printf-arg-size: unrecognised ~A" arg-type))))

(defun lower-print-value (args)
  "Lower `print(VAL)' where VAL isn't an @map — bpftrace allows print()
   on any scalar / string / tuple. We synthesize a printf(FMT, VAL…)
   where FMT is inferred from VAL's syntactic shape and always ends
   in `\\n' (bpftrace's `print' is line-terminated). Tuples format as
   `(elem1, elem2, …)' with `%d' for ints / `%s' for strings. Nested
   tuples flatten into the format: `(1, (2, X))' → `(%d, (%d, %s))'
   with the three leaves as printf args."
  (unless (and args (= (length args) 1))
    (unsupported "print() takes one argument (a value or @map)"))
  (let* ((val (first args))
         (tag (and (consp val) (first val))))
    (cond
      ((eq tag :str)
       (lower-printf (list (list :str (concatenate 'string "%s"
                                                   (string #\Newline)))
                           val)))
      ((eq tag :tuple)
       (multiple-value-bind (fmt-fragment leaves) (tuple-printf-shape val)
         (lower-printf (cons (list :str
                                   (concatenate 'string fmt-fragment
                                                (string #\Newline)))
                             leaves))))
      ;; Default: numeric. Covers $vars, int literals, arithmetic,
      ;; builtins like pid/tid/cpu, etc. The runtime decoder treats
      ;; the payload as u64.
      (t
       (lower-printf (list (list :str (concatenate 'string "%d"
                                                   (string #\Newline)))
                           val))))))

(defun tuple-elem-printf-spec (elem)
  "Pick a printf %-spec for a tuple element. String-typed elements use
   `%s'; bool-typed elements use `%B' (rendered as `true' / `false'
   in userspace); everything else falls back to `%d'."
  (cond
    ((and (consp elem) (eq (first elem) :str))  "%s")
    ((or (and (consp elem) (eq (first elem) :constant)
              (or (string= (second elem) "true")
                  (string= (second elem) "false")))
         (and (consp elem) (eq (first elem) :int-cast)
              (string= (getf (cdr elem) :type) "bool")))
     "%B")
    (t  "%d")))

(defun tuple-printf-shape (tuple)
  "Walk a (possibly nested) tuple AST and return (values FMT-STRING
   LEAF-LIST). The format renders the tuple's nested shape with `(',
   `)' and `, ', plugging in `%d' / `%s' per leaf — and LEAF-LIST is
   the flat list of leaf ASTs in left-to-right order, ready to pass
   to lower-printf as the post-format args."
  (let ((leaves nil))
    (labels ((walk (e)
               (cond
                 ((and (consp e) (eq (first e) :tuple))
                  (let* ((items (getf (cdr e) :items))
                         (parts (mapcar #'walk items)))
                    (format nil "(~{~A~^, ~})" parts)))
                 (t
                  (push e leaves)
                  (tuple-elem-printf-spec e)))))
      (let ((fmt (walk tuple)))
        (values fmt (nreverse leaves))))))

(defun lower-printf (args &key (stream :stdout) (fn-name "printf"))
  "Lower a bpftrace `printf(\"FMT\", arg…)` to a ringbuf-submit using
   the unified async-action protocol. STREAM picks where the
   userspace decoder routes the formatted line — :stdout (default),
   :stderr (for errorf / warnf), or :stderr-prefixed (warnf prepends
   `WARNING: ').

   Record layout (all little-endian):
     0:  u32 tag = +bt-tag-printf+
     4:  u32 id  (index into the printf-table)
     8+: per-arg payloads — u64 for :int args, 16 bytes for :string

   At codegen time we register (id fmt-string arg-types stream) in
   *PRINTF-TABLE*, which the runtime gets via :printf-table in the
   generate() plist. The runtime ring-consumer reads the tag, then
   the id, then walks ARG-TYPES to decode each payload."
  (unless args
    (unsupported "~A() with no format string" fn-name))
  (let ((fmt (first args)))
    (unless (eq (first fmt) :str)
      (unsupported "~A() format must be a string literal" fn-name))
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
      (push (list id fmt-str arg-types stream) *printf-table*)
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
    ((eq ty :strerror)
     ;; Emit the errno as u32. Userspace runs strerror(3) on the
     ;; value at decode time and substitutes the result for %s.
     (let ((errno-expr (lower-expr (first (getf (cdr arg) :args)))))
       `(whistler::store ,(intern "U32" :whistler) ,rec ,off ,errno-expr)))
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
    ((eq ty :macaddr)
     ;; Probe-read 6 bytes from the user-supplied pointer into the
     ;; record slot; userspace's :macaddr renderer formats them.
     (let ((ptr (lower-expr (first (getf (cdr arg) :args)))))
       `(whistler::probe-read-kernel (+ ,rec ,off) 6 ,ptr)))
    ((eq ty :ipv-any)
     ;; ARG is a `\$v' that points at its 17-byte ntop slot. Copy the
     ;; whole slot (16 bytes address + 1 byte family) into the record.
     ;; Uses whistler::memcpy (unrolled wide load/store) — a runtime
     ;; byte-by-byte loop hit a regalloc-induced verifier reject when
     ;; the loop counter and a derived pointer ended up sharing a
     ;; register across iterations.
     `(whistler::memcpy ,rec ,off ,(lower-expr arg) 0 ,+bt-ntop-slot-size+))
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
         ;; path(struct path *) — bpf_d_path(path, buf, sz) writes
         ;; the kernel-resolved path NUL-padded into the record slot.
         ((named-call-p arg "path")
          (let* ((args (getf (cdr arg) :args))
                 (ptr  (lower-expr (first args))))
            `(,(intern "D-PATH" :whistler) ,ptr (+ ,rec ,off) ,size)))
         ;; Literal string — emit byte-stores. Used for probe/func
         ;; rewrites and any printf("…", "literal") form.
         ((eq (first arg) :str)
          (lower-printf-string-literal rec off (second arg) size))
         ;; A \$v in *comm-vars* — copy SIZE bytes from \$v's slot
         ;; into the record.
         ((and (eq (first arg) :var)
               (member (second arg) *comm-vars* :test #'string-equal))
          ;; Unrolled byte copy (whistler::memcpy widens to u64/u32
          ;; chunks at compile time). Avoids the regalloc snag the
          ;; runtime-loop form hit.
          `(whistler::memcpy ,rec ,off ,(lower-expr arg) 0 ,size))
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
         ;;
         ;; Scalar-key path uses the per-probe shared *shared-key-buf*
         ;; via map-lookup-ptr rather than a fresh `(let* ((tmpk u64 …)))'
         ;; + map-lookup. Reason: the OLD pattern made the emit-time
         ;; key cache (emit-key-to-stack) record "this slot holds
         ;; const N" — but gen-string-set's writes through the shared
         ;; buffer leave a stack slot that the cache later mis-routes
         ;; constant-key lookups to. Using map-lookup-ptr sidesteps
         ;; emit-key-to-stack entirely.
         ((eq (first arg) :map)
          (let* ((info (gethash (getf (cdr arg) :name) *map-table*))
                 (mname (minfo-name info))
                 (keys  (getf (cdr arg) :keys))
                 (p     (gensym "P"))
                 (ptr-p (keys-need-ptr-ops-p keys)))
            (cond
              (ptr-p
               (with-key keys
                 (lambda (k)
                   `(whistler:if-let
                        (,p (whistler::map-lookup-ptr ,mname ,k))
                      (whistler::probe-read-kernel
                       (+ ,rec ,off) ,size ,p)
                      0))))
              (t
               (setf *shared-key-buf-used* t)
               `(progn
                  (whistler::store whistler::u64 ,*shared-key-buf* 0
                                   ,(lower-expr (first keys)))
                  (whistler:if-let
                      (,p (whistler::map-lookup-ptr ,mname ,*shared-key-buf*))
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
           (t (field-access-unsupported name)))))
      (t (field-access-unsupported name)))))

(defun field-access-unsupported (name)
  "Signal the generic `field access .NAME on non-args expressions'
   error, but prepend a tracefs-permissions hint when codegen tried
   and failed to read tracepoint format files — that's almost always
   the real root cause (the type of `args.FOO' couldn't be resolved,
   so `$v = @m[k]' has no struct, so `$v.FIELD' can't be lowered)."
  (cond
    (*tp-format-unreadable-paths*
     (unsupported
      "field access .~A on non-args expressions — likely because a ~
       tracepoint format file couldn't be read (need root or ~
       `chmod a+r'):~{~%  ~A~}~%~
       Re-run with sudo, or grant read permission to the format ~
       file(s) above."
      name (reverse *tp-format-unreadable-paths*)))
    (t (unsupported "field access .~A on non-args expressions" name))))

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
              ;; new probe-read needed. Unwrap typedef/const/volatile
              ;; so the next iteration sees the actual struct rec,
              ;; not a const-wrapper whose vlen is 0.
              ((and (null bpf-type) sub-name (not (leaf? fname)))
               (setf current-tid
                     (or (whistler:btf-member-raw-type-id vmbtf sub-tid)
                         sub-tid)))
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
   PTR-FORM, returning the value of FIELD-NAME. Tries in-script
   struct decls first (parsed at AST time into *script-struct-decls*),
   then falls back to vmlinux BTF. Scalar fields (1/2/4/8 bytes) only
   — array members and nested struct fields aren't wired up here."
  (let ((user-entry (assoc struct-name *script-struct-decls*
                           :test #'string=)))
    (cond
      ;; In-script struct: entry shape is (NAME TOTAL-SIZE FIELDS…).
      (user-entry
       (let* ((fields (cddr user-entry))
              (cell   (find field-name fields :test #'string= :key #'first)))
         (unless cell
           (unsupported "->~A: in-script struct ~A has no such field"
                        field-name struct-name))
         (let* ((size    (second cell))
                (offset  (third cell))
                (arr-len (fourth cell)))
           (when arr-len
             (unsupported "->~A: in-script struct ~A field is an array (~D × ~D); ~
                          whole-array access not wired up yet"
                          field-name struct-name arr-len size))
           (unless (member size '(1 2 4 8))
             (unsupported "->~A: in-script struct ~A field is ~D bytes; ~
                          only scalar (1/2/4/8) fields are wired up"
                          field-name struct-name size))
           (emit-struct-field-read size offset ptr-form (pick-probe-read-fn)))))
      (t
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
               (emit-struct-field-read
                size offset ptr-form
                (intern "PROBE-READ-KERNEL" :whistler))))))))))

(defun emit-struct-field-read (size offset ptr-form helper)
  "Build a `(let ((scratch struct-alloc)) helper … load)' triple that
   reads a SIZE-byte scalar field at OFFSET from PTR-FORM via HELPER
   (probe-read-user or probe-read-kernel)."
  (let ((scratch (gensym "FIELD"))
        (type-sym (case size
                    (1 (intern "U8"  :whistler))
                    (2 (intern "U16" :whistler))
                    (4 (intern "U32" :whistler))
                    (8 (intern "U64" :whistler)))))
    `(let ((,scratch (whistler::struct-alloc ,size)))
       (,helper ,scratch ,size (whistler::+ ,ptr-form ,offset))
       (whistler::load ,type-sym ,scratch 0))))

(defun bare-args-byte-width ()
  "Total bytes for `args' (no field) under the active probe. fentry/
   fexit walks BTF params; each param is 8 bytes in the ctx layout
   (one u64 register slot). NIL when we can't determine the count
   (tracepoint args layout varies per event and we don't reduce it
   to a fixed width — those scripts already need args.FIELD)."
  (case (first *probe-spec*)
    ((:kfunc :kretfunc)
     (let* ((fname  (second *probe-spec*))
            (vmbtf  (whistler:ensure-vmlinux-btf))
            (params (whistler:btf-func-params vmbtf fname)))
       (* 8 (length params))))))

(defun lower-bswap (arg-expr)
  "Lower `bswap(EXPR)' with width dispatched from the syntactic shape
   of EXPR. `bswap((int8)X)' is the identity; `(int16)' swaps 2
   bytes; `(int32)' / `(int64)' swap 4 / 8 bytes. Plain `bswap(X)'
   (no cast) defaults to a 16-bit swap, preserving the historical
   behaviour the existing tools rely on (`bswap(\$port)' on u16
   from skc_dport)."
  (let ((width (bswap-width-from-cast arg-expr)))
    (case width
      (1 (lower-expr (strip-bswap-cast arg-expr)))
      (2 (let ((x (gensym "BSWAP")))
           `(let ((,x ,(lower-expr (strip-bswap-cast arg-expr))))
              (whistler::logior
               (whistler::ash (whistler::logand ,x #xff) 8)
               (whistler::ash (whistler::logand ,x #xff00) -8)))))
      (4 (let ((x (gensym "BSWAP")))
           `(let ((,x ,(lower-expr (strip-bswap-cast arg-expr))))
              (whistler::logior
               (whistler::logior
                (whistler::ash (whistler::logand ,x #xff)       24)
                (whistler::ash (whistler::logand ,x #xff00)      8))
               (whistler::logior
                (whistler::ash (whistler::logand ,x #xff0000)   -8)
                (whistler::ash (whistler::logand ,x #xff000000) -24))))))
      (8 (let ((x (gensym "BSWAP")))
           `(let ((,x ,(lower-expr (strip-bswap-cast arg-expr))))
              (whistler::logior
               (whistler::logior
                (whistler::logior
                 (whistler::ash (whistler::logand ,x #xff)              56)
                 (whistler::ash (whistler::logand ,x #xff00)            40))
                (whistler::logior
                 (whistler::ash (whistler::logand ,x #xff0000)          24)
                 (whistler::ash (whistler::logand ,x #xff000000)         8)))
               (whistler::logior
                (whistler::logior
                 (whistler::ash (whistler::logand ,x #xff00000000)        -8)
                 (whistler::ash (whistler::logand ,x #xff0000000000)     -24))
                (whistler::logior
                 (whistler::ash (whistler::logand ,x #xff000000000000)   -40)
                 (whistler::ash (whistler::logand ,x #xff00000000000000) -56))))))))))

(defun bswap-width-from-cast (expr)
  "Return the byte width of bswap's arg based on its primitive cast
   wrapper. `(int8)X' / `(uint8)X' → 1, `(int16)/(uint16)' → 2,
   `(int32)/(uint32)' → 4, `(int64)/(uint64)/(int)/(uint)' → 8.
   No cast defaults to 2 (legacy bpftrace tool compat)."
  (cond
    ((not (and (consp expr) (eq (first expr) :int-cast))) 2)
    (t (let ((type (getf (cdr expr) :type)))
         (cond
           ((or (string= type "int8")  (string= type "uint8")) 1)
           ((or (string= type "int16") (string= type "uint16")) 2)
           ((or (string= type "int32") (string= type "uint32")) 4)
           (t 8))))))

(defun strip-bswap-cast (expr)
  "Unwrap an int-cast wrapper so lower-expr sees the underlying
   value — the cast's width was already consumed by
   bswap-width-from-cast."
  (if (and (consp expr) (eq (first expr) :int-cast))
      (getf (cdr expr) :expr)
      expr))

(defun lower-bare-args ()
  "Lower `args' (used without `->field') to a stack buffer holding
   the concatenated raw param values. fentry / fexit only — each
   param is one u64 ctx slot, so the buffer is param-count × 8.
   Returns the buffer pointer; downstream sites (map keys / values /
   printf args) treat it like a sized byte buffer."
  (let ((width (bare-args-byte-width)))
    (unless width
      (unsupported "args without ->field is only supported in fentry/fexit"))
    (case (first *probe-spec*)
      ((:kfunc :kretfunc)
       (let* ((fname  (second *probe-spec*))
              (vmbtf  (whistler:ensure-vmlinux-btf))
              (params (whistler:btf-func-params vmbtf fname))
              (buf    (gensym "ARGSBUF")))
         `(let ((,buf (whistler::struct-alloc ,width)))
            ,@(loop for (_n . off) in params
                    for slot from 0
                    collect `(whistler::store ,(intern "U64" :whistler)
                                              ,buf ,(* slot 8)
                                              (whistler::ctx ,(intern "U64" :whistler)
                                                              ,off)))
            ,buf))))))

(defun lower-args-field (name)
  "Lower args->NAME based on the current probe type. Tracepoints
   read the field directly from the kernel-provided ctx using the
   per-tracepoint format file — every tracepoint's args layout is
   unique (e.g. sys_enter_open has filename at offset 16 but
   sys_enter_openat at offset 24, with dfd occupying 16). A shared
   `tp-NAME' macro across tracepoints would silently load from the
   wrong offset; resolving per-probe via *probe-spec* fixes that.
   fentry/fexit programs walk BTF for their named params."
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
    (:tracepoint
     (let* ((cat   (second *probe-spec*))
            (event (third  *probe-spec*))
            (path  (ignore-errors
                    (whistler::find-tracepoint-format-path cat event)))
            (fields (when path
                      (ignore-errors
                       (whistler::parse-tracepoint-format (namestring path)))))
            (c-name (substitute #\_ #\- name))
            (field (find c-name fields :key #'first :test #'string=)))
       (cond
         (field
          (destructuring-bind (c-name offset size signed-p array-size
                               &optional c-type) field
            (declare (ignore c-name c-type))
            (let ((type (whistler::tracepoint-type size signed-p array-size)))
              (cond
                (type `(whistler::ctx ,type ,offset))
                ((plusp array-size)
                 `(whistler::+ (whistler::ctx-ptr) ,offset))
                (t (unsupported "args.~A: unrecognised field shape" name))))))
         ;; Format file not readable at compile time — fall back to
         ;; the shared `(tp-NAME)' macro that gen-deftracepoint-preamble
         ;; emits. The deftracepoint expansion at load time reads the
         ;; format file (which the loader is running as root for) and
         ;; defines the macro. This path silently mis-handles cases
         ;; where multiple tracepoints in the same script share a
         ;; field name with differing offsets (e.g. sys_enter_open /
         ;; sys_enter_openat both define `filename') — only the first
         ;; tracepoint's offset wins. We rely on compile-time format
         ;; access (the path above) to handle that correctly.
         (t (list (w-sym (concatenate 'string "tp-" name)))))))
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
    ;; In-script struct array-field key — probe-read the array bytes
    ;; directly into the slot. The composite-key-layout sized the
    ;; slot to ELT-SIZE × ARR-LEN bytes already.
    ((multiple-value-bind (b s o l) (array-field-meta expr)
       (declare (ignore b s o l))
       (array-field-meta expr))
     (multiple-value-bind (base-ast elt-size field-off arr-len)
         (array-field-meta expr)
       `(,(pick-probe-read-fn)
         (whistler::+ ,buf ,offset)
         ,(* elt-size arr-len)
         (whistler::+ ,(lower-expr base-ast) ,field-off))))
    ;; Bare `args' (fentry/fexit) — emit the lower-bare-args buffer
    ;; and memcpy its contents into the key slot. lower-bare-args
    ;; returns a fresh stack buffer; copy its WIDTH bytes into the
    ;; pre-allocated key slot.
    ((and (eq (first expr) :args) (bare-args-byte-width))
     (let ((tmp (gensym "ASRC"))
           (width (bare-args-byte-width)))
       `(let ((,tmp ,(lower-bare-args)))
          (whistler::memcpy ,buf ,offset ,tmp 0 ,width))))
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

(defun lower-index (expr)
  "Lower `BASE[KEY]' for shapes other than @-maps:
     * \$strvar[i] → u8 load at byte i of the str-buffer.
     * \$ntopvar[i] → u8 load at byte i of the ntop record.
     * \$commvar[i] → u8 load at byte i of the comm slot.
   `\"foo\"[i]' lowers to the i'th character of the literal."
  (let ((base (getf (cdr expr) :base))
        (keys (getf (cdr expr) :keys)))
    (unless (= 1 (length keys))
      (unsupported "indexed access requires a single integer key"))
    (let ((idx (first keys)))
      (cond
        ((and (consp base) (eq (first base) :str)
              (consp idx)  (eq (first idx) :int))
         ;; Literal string index — fold to the character's code.
         (let ((s (second base)) (i (second idx)))
           (if (and (>= i 0) (< i (length s)))
               (char-code (char s i))
               0)))
        ((and (consp base) (eq (first base) :var)
              (assoc (second base) *str-vars* :test #'string-equal))
         `(whistler::load ,(intern "U8" :whistler)
                          ,(var-sym (second base))
                          ,(lower-expr idx)))
        ((and (consp base) (eq (first base) :var)
              (member (second base) *comm-vars* :test #'string-equal))
         `(whistler::load ,(intern "U8" :whistler)
                          ,(var-sym (second base))
                          ,(lower-expr idx)))
        ((and (consp base) (eq (first base) :var)
              (member (second base) *ntop-vars* :test #'string-equal))
         `(whistler::load ,(intern "U8" :whistler)
                          ,(var-sym (second base))
                          ,(lower-expr idx)))
        ;; `$x[i]' where `$x' is backed by an inline whole-array
        ;; buffer (filled via memcpy from a map whose value was a
        ;; struct array field). Just read ELT-SIZE bytes at offset
        ;; i*ELT-SIZE — no probe-read needed; the bytes are already
        ;; in our stack buffer.
        ((and (consp base) (eq (first base) :var)
              (assoc (second base) *var-array-types* :test #'string=))
         (let* ((cell  (cdr (assoc (second base) *var-array-types*
                                   :test #'string=)))
                (sz    (first cell))
                (type-sym (case sz
                            (1 (intern "U8"  :whistler))
                            (2 (intern "U16" :whistler))
                            (4 (intern "U32" :whistler))
                            (8 (intern "U64" :whistler)))))
           `(whistler::load ,type-sym
                            ,(var-sym (second base))
                            (whistler::* ,(lower-expr idx) ,sz))))
        ;; `$a[i]' where `$a' was assigned from a primitive-pointer
        ;; cast (`$a = (int32 *) arg0'). Read sizeof(elt) bytes at
        ;; `$a + i * sizeof(elt)' via probe-read-user/kernel.
        ((and (consp base) (eq (first base) :var)
              (assoc (second base) *var-ptr-elt-types* :test #'string=))
         (let* ((cell  (cdr (assoc (second base) *var-ptr-elt-types*
                                   :test #'string=)))
                (sz    (second cell)))
           (lower-ptr-index (lower-expr base) (lower-expr idx) sz)))
        ;; `((int32 *) EXPR)[i]' — direct subscript on a bare
        ;; primitive-pointer cast, no intermediate var.
        ((and (consp base) (eq (first base) :prim-ptr-cast))
         (let ((sz (prim-ptr-elt-size (getf (cdr base) :elt-type))))
           (unless sz
             (unsupported "primitive-pointer cast: unknown element type ~A"
                          (getf (cdr base) :elt-type)))
           (lower-ptr-index (lower-expr (getf (cdr base) :expr))
                            (lower-expr idx) sz)))
        ;; `args.FIELD[i]' — subscript on a tracepoint args field.
        ;; The field is typically a pointer-to-array (`char ** argv'),
        ;; so its value is an 8-byte userspace pointer; the i'th
        ;; element is 8 bytes at base+i*8 probed from userspace.
        ((and (consp base) (eq (first base) :field)
              (consp (getf (cdr base) :base))
              (eq (first (getf (cdr base) :base)) :args))
         (let* ((scratch (gensym "ARGIX"))
                (idx-form (lower-expr idx))
                (base-form (lower-args-field (getf (cdr base) :name))))
           `(let ((,scratch (whistler::struct-alloc 8)))
              (whistler::probe-read-user
               ,scratch 8
               (whistler::+ ,base-form (whistler::* ,idx-form 8)))
              (whistler::load whistler::u64 ,scratch 0))))
        ;; `@m[k][i]' where @m's value was stored from a primitive-
        ;; pointer cast (`@m[k] = (int32 *) X'). Read sizeof(elt)
        ;; bytes at `@m[k] + i * sizeof(elt)' via probe-read. The
        ;; map-read returns the stored u64 (the pointer); we then
        ;; subscript through it.
        ((and (consp base) (eq (first base) :map)
              (let* ((nm   (or (getf (cdr base) :name) "@"))
                     (info (and *map-table* (gethash nm *map-table*))))
                (and info (minfo-value-ptr-elt-size info))))
         (let* ((nm   (or (getf (cdr base) :name) "@"))
                (info (gethash nm *map-table*))
                (sz   (minfo-value-ptr-elt-size info)))
           (lower-ptr-index (lower-expr base) (lower-expr idx) sz)))
        ;; `@m[k][i]' where @m's value is a whole array (set via
        ;; `@m[k] = (struct A *)e.x'). The map-lookup-ptr returns a
        ;; pointer to the on-map buffer holding the array bytes; load
        ;; the i'th element directly (no probe-read — it's already in
        ;; kernel memory).
        ((and (consp base) (eq (first base) :map)
              (let* ((nm   (or (getf (cdr base) :name) "@"))
                     (info (and *map-table* (gethash nm *map-table*))))
                (and info (minfo-value-array-p info)
                     (minfo-value-array-elt-size info))))
         (let* ((nm   (or (getf (cdr base) :name) "@"))
                (info (gethash nm *map-table*))
                (sz   (minfo-value-array-elt-size info))
                (type-sym (case sz
                            (1 (intern "U8"  :whistler))
                            (2 (intern "U16" :whistler))
                            (4 (intern "U32" :whistler))
                            (8 (intern "U64" :whistler)))))
           `(whistler::load ,type-sym
                            ,(lower-map-value-ptr base)
                            (whistler::* ,(lower-expr idx) ,sz))))
        ;; `$a.field[i][j]…' — multi-dim index chain on an in-script
        ;; struct array field. Walk the chain, multiply each index
        ;; by the inner-dim stride, then probe-read ELT-SIZE bytes at
        ;; struct+field-off+sum.
        ((multi-dim-array-subscript-p expr)
         (lower-multi-dim-array-subscript expr))
        ;; `$a.field[i]' or `(struct X *)e.field[i]' — element access
        ;; on an array field of an in-script struct. The struct
        ;; pointer + field offset + i * sizeof(elt) gives the address;
        ;; probe-read sizeof(elt) bytes there.
        ((and (consp base) (eq (first base) :field)
              (array-field-lookup base))
         (multiple-value-bind (ptr-form elt-size field-off arr-len)
             (array-field-lookup base)
           (when (and (consp idx) (eq (first idx) :int))
             (let ((i (second idx)))
               (when (or (minusp i) (>= i arr-len))
                 (unsupported
                  "ERROR: the index ~D is out of bounds for array of size ~D"
                  i arr-len))))
           (lower-ptr-index `(whistler::+ ,ptr-form ,field-off)
                            (lower-expr idx) elt-size)))
        (t (unsupported "array indexing outside @maps"))))))

(defun array-field-dims (field-expr)
  "Return the parsed dim-list (e.g. (2 2) for `int y[2][2]') of an
   in-script-struct array field, or NIL if FIELD-EXPR isn't one."
  (unless (and (consp field-expr) (eq (first field-expr) :field))
    (return-from array-field-dims nil))
  (let* ((base (getf (cdr field-expr) :base))
         (name (getf (cdr field-expr) :name))
         (struct-name
           (cond
             ((and (consp base) (eq (first base) :var))
              (cdr (assoc (second base) *var-types* :test #'string=)))
             ((and (consp base) (eq (first base) :cast))
              (getf (cdr base) :type)))))
    (when struct-name
      (let* ((entry (assoc struct-name *script-struct-decls* :test #'string=))
             (cell  (and entry (find name (cddr entry)
                                     :test #'string= :key #'first))))
        (and cell (sixth cell))))))

(defun array-field-meta (field-expr)
  "Pure-AST lookup of array-field metadata: returns (values BASE-AST
   ELT-SIZE FIELD-OFFSET ARR-LEN) when FIELD-EXPR is `$var.field' /
   `(struct X *)e.field' and the field is an in-script struct array,
   else NIL. Unlike ARRAY-FIELD-LOOKUP, doesn't call LOWER-EXPR — so
   safe to call from infer-maps / expr-size at AST time. Tag-guarded
   so callers can pass any expr; non-`:field' inputs return NIL."
  (unless (and (consp field-expr) (eq (first field-expr) :field))
    (return-from array-field-meta nil))
  (let ((base (getf (cdr field-expr) :base))
        (name (getf (cdr field-expr) :name)))
    (let ((struct-name
            (cond
              ((and (consp base) (eq (first base) :var))
               (cdr (assoc (second base) *var-types* :test #'string=)))
              ((and (consp base) (eq (first base) :cast))
               (getf (cdr base) :type)))))
      (unless struct-name (return-from array-field-meta nil))
      (let* ((entry (assoc struct-name *script-struct-decls* :test #'string=))
             (cell  (and entry (find name (cddr entry)
                                     :test #'string= :key #'first)))
             (elt-size (and cell (second cell)))
             (offset   (and cell (third cell)))
             (arr-len  (and cell (fourth cell))))
        (when (and cell arr-len (member elt-size '(1 2 4 8)))
          (values base elt-size offset arr-len))))))

(defun array-field-lookup (field-expr)
  "If FIELD-EXPR is a `:field' AST whose base is a $var typed to an
   in-script struct and whose named field is declared as an array
   (T x[N]), return (values BASE-PTR-FORM ELT-SIZE FIELD-OFFSET ARR-LEN).
   Returns NIL when the lookup doesn't match — caller decides whether
   to error or try another rule."
  (multiple-value-bind (base elt-size offset arr-len)
      (array-field-meta field-expr)
    (when base (values (lower-expr base) elt-size offset arr-len))))

(defun walk-index-chain (expr)
  "Walk a chain of nested `:index' ASTs to find the underlying root.
   Returns (values ROOT-EXPR KEY-LIST-IN-SOURCE-ORDER) — for
   `field[a][b]', KEY-LIST is `(a b)'. The traversal descends
   outer-to-inner (`[b]'-first), pushing each key onto a list head;
   the resulting list is already in source order."
  (let (keys)
    (labels ((walk (e)
               (cond
                 ((and (consp e) (eq (first e) :index))
                  (let ((sub-keys (getf (cdr e) :keys)))
                    (when sub-keys
                      (push (first sub-keys) keys)))
                  (walk (getf (cdr e) :base)))
                 (t e))))
      (let ((root (walk expr)))
        (values root keys)))))

(defun multi-dim-array-subscript-p (expr)
  "T when EXPR is `field[i][j]…' with EXACTLY as many subscripts as
   the field's declared dims (so the result is a single element).
   Returns NIL if the chain is partial — leave those to the simpler
   single-subscript rule."
  (multiple-value-bind (root keys) (walk-index-chain expr)
    (and (consp root) (eq (first root) :field)
         (let ((dims (array-field-dims root)))
           (and dims (= (length dims) (length keys)) (> (length dims) 1))))))

(defun lower-multi-dim-array-subscript (expr)
  "Lower `field[i1][i2]…' to a sized probe-read at
   struct+field-off + sum(ik * stride_k). Strides come from the
   field's recorded dim list."
  (multiple-value-bind (root keys) (walk-index-chain expr)
    (multiple-value-bind (base-ast elt-size field-off _len)
        (array-field-meta root)
      (declare (ignore _len))
      (let* ((dims (array-field-dims root))
             ;; Stride for dim k = elt-size × product(dims[k+1..]).
             (strides (loop for i below (length dims)
                            collect (* elt-size
                                       (apply #'* (subseq dims (1+ i))))))
             (offset-form
               (reduce (lambda (acc pair)
                         `(whistler::+ ,acc
                            (whistler::* ,(first pair) ,(second pair))))
                       (mapcar #'list (mapcar #'lower-expr keys) strides)
                       :initial-value field-off))
             (scratch (gensym "MDIDX"))
             (helper (pick-probe-read-fn))
             (type-sym (case elt-size
                         (1 (intern "U8"  :whistler))
                         (2 (intern "U16" :whistler))
                         (4 (intern "U32" :whistler))
                         (8 (intern "U64" :whistler)))))
        `(let ((,scratch (whistler::struct-alloc ,elt-size)))
           (,helper ,scratch ,elt-size
                    (whistler::+ ,(lower-expr base-ast) ,offset-form))
           (whistler::load ,type-sym ,scratch 0))))))

(defun lower-ptr-index (ptr-form idx-form elt-size)
  "Emit a typed-pointer subscript read: probe-read ELT-SIZE bytes at
   PTR-FORM + IDX-FORM * ELT-SIZE into a scratch buffer, then load
   the value back as a uN. Used for `$a[i]' where `$a' is a typed
   primitive-pointer var (e.g. `(int32 *)') and the same shape on
   bare casts like `((int32 *) arg0)[0]'."
  (let ((scratch (gensym "PTRIDX"))
        (helper  (pick-probe-read-fn))
        (type-sym (case elt-size
                    (1 (intern "U8"  :whistler))
                    (2 (intern "U16" :whistler))
                    (4 (intern "U32" :whistler))
                    (8 (intern "U64" :whistler)))))
    `(let ((,scratch (whistler::struct-alloc ,elt-size)))
       (,helper
        ,scratch ,elt-size
        (whistler::+ ,ptr-form (whistler::* ,idx-form ,elt-size)))
       (whistler::load ,type-sym ,scratch 0))))

(defun lower-map-read (expr)
  (let* ((info (or (gethash (or (getf (cdr expr) :name) "@") *map-table*)
                   (unsupported "unknown map @~A" (getf (cdr expr) :name))))
         (mname (minfo-name info))
         (keys  (getf (cdr expr) :keys)))
    (with-key keys
      (lambda (k) `(whistler:getmap ,mname ,k)))))

(defun lower-map-value-ptr (map-expr)
  "Return a kernel-side form evaluating to a pointer to MAP-EXPR's
   value slot (not the scalar value). Used by lower-index when the
   map's value-array-p is set — `@m[k][i]' needs to subscript the
   on-map buffer directly. NIL on missing lookup is left to BPF-side
   handling; the caller can wrap in a null check if needed."
  (let* ((info (or (gethash (or (getf (cdr map-expr) :name) "@") *map-table*)
                   (unsupported "unknown map @~A in value-ptr lookup"
                                (getf (cdr map-expr) :name))))
         (mname (minfo-name info))
         (keys  (getf (cdr map-expr) :keys)))
    (with-key keys
      (lambda (k) `(whistler::map-lookup-ptr ,mname ,k)))))

;;; ========== Statement lowering ==========

(defun collect-vars (stmts)
  "Collect every $var name written or read inside STMTS — including
   $vars defined inside user macros/functions transitively reachable
   via calls. Returns a list of (canonical) symbols suitable for
   binding at probe scope. Macros aren't hygienic in bpftrace: a
   $tmp inside a macro and a $tmp at the call site share the same
   binding, so we collect all of them up-front."
  (let ((seen (make-hash-table :test 'equal))
        (visited-fns (make-hash-table :test 'equal)))
    (labels ((collect-call-body (name)
               (let ((fn (find-user-function name)))
                 (when (and fn (not (gethash name visited-fns)))
                   (setf (gethash name visited-fns) t)
                   ;; Skip the fn's own $-prefixed param names —
                   ;; those are substituted at inline time, not
                   ;; real local vars.
                   (let ((skip (loop for p in (getf fn :params)
                                     when (and (plusp (length p))
                                               (char= (char p 0) #\$))
                                       collect (subseq p 1))))
                     (let ((sub-seen seen))
                       (mapc (lambda (s) (walk-stmt s sub-seen skip))
                             (getf fn :body)))))))
             (walk (form skip)
               (when (consp form)
                 (case (first form)
                   (:var (let ((name (second form)))
                           (unless (member name skip :test #'string=)
                             (setf (gethash name seen) t))))
                   (:bin   (walk (getf (cdr form) :lhs) skip)
                           (walk (getf (cdr form) :rhs) skip))
                   (:un    (walk (getf (cdr form) :arg) skip))
                   (:tern  (walk (getf (cdr form) :cond) skip)
                           (walk (getf (cdr form) :then) skip)
                           (walk (getf (cdr form) :else) skip))
                   (:call  (dolist (a (getf (cdr form) :args))
                             (walk a skip))
                           (collect-call-body (getf (cdr form) :name)))
                   (:field (walk (getf (cdr form) :base) skip))
                   (:index (walk (getf (cdr form) :base) skip)
                           (dolist (k (getf (cdr form) :keys))
                             (walk k skip)))
                   (:map   (dolist (k (getf (cdr form) :keys))
                             (walk k skip)))
                   ;; `{ stmt; stmt; … expr }' — descend into the
                   ;; embedded statements (each contributes its own
                   ;; var defs) plus the trailing expression.
                   (:block-expr
                    (mapc (lambda (s) (walk-stmt s seen skip))
                          (getf (cdr form) :stmts))
                    (walk (getf (cdr form) :final) skip))
                   ;; `$x++' / `++$x' / `@m[k]++' used as an expr.
                   ;; The LHS is a place expr — descend so the var
                   ;; (or map's key sub-exprs) get collected.
                   (:incdec-expr
                    (walk (getf (cdr form) :lhs) skip)))))
             (walk-stmt (s _seen skip)
               (declare (ignore _seen))
               (case (first s)
                 (:if      (walk (getf (cdr s) :cond) skip)
                           (mapc (lambda (x) (walk-stmt x seen skip))
                                 (getf (cdr s) :then))
                           (mapc (lambda (x) (walk-stmt x seen skip))
                                 (getf (cdr s) :else)))
                 (:while   (walk (getf (cdr s) :cond) skip)
                           (mapc (lambda (x) (walk-stmt x seen skip))
                                 (getf (cdr s) :body)))
                 (:for     (walk (getf (cdr s) :start) skip)
                           (walk (getf (cdr s) :end) skip)
                           (mapc (lambda (x) (walk-stmt x seen skip))
                                 (getf (cdr s) :body)))
                 (:assign  (walk (getf (cdr s) :rhs) skip)
                           (let ((lhs (getf (cdr s) :lhs)))
                             (when (eq (first lhs) :var)
                               (let ((name (second lhs)))
                                 (unless (member name skip :test #'string=)
                                   (setf (gethash name seen) t))))
                             (walk lhs skip)))
                 (:incdec  (walk (getf (cdr s) :lhs) skip))
                 (:expr    (walk (second s) skip)))))
      (mapc (lambda (s) (walk-stmt s seen nil)) stmts))
    (loop for k being the hash-keys of seen collect (var-sym k))))

(defvar *loop-break-bf* nil
  "Gensym for the innermost loop's break flag, or NIL outside any loop.
   Set inside lower-for / lower-while; read by lower-break.")

(defvar *loop-break-cf* nil
  "Gensym for the innermost loop's continue flag, or NIL outside any loop.
   Set inside lower-for / lower-while; read by lower-continue AND by
   lower-stmts to wrap each statement so the rest of an iteration
   short-circuits once break/continue fires.")

(defun lower-stmts (stmts)
  "Lower each STMT. When inside a loop (signalled by *LOOP-BREAK-CF*),
   wrap each result in `(unless cf …)' so statements after a break or
   continue in the same lexical scope are skipped within an iteration."
  (let ((cf *loop-break-cf*))
    (if cf
        (mapcar (lambda (s) `(whistler::unless ,cf ,(lower-stmt s))) stmts)
        (mapcar #'lower-stmt stmts))))

(defconstant +bt-max-loop-iters+ 64
  "Upper bound on bpftrace `while' iterations. The BPF verifier
   requires a static iteration cap; we hard-code 64 — bpftrace's
   default is similar.")

(defun lower-stmt (stmt)
  (ecase (first stmt)
    (:if        (lower-if stmt))
    (:while     (lower-while stmt))
    (:for       (lower-for stmt))
    (:break     (lower-break stmt))
    (:continue  (lower-continue stmt))
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

       (let* ((bf 0))
         (dotimes (k +bt-max-loop-iters+)
           (unless bf
             (let* ((cf 0))
               (when cond
                 stmt1-wrapped …)))))

   The BPF verifier requires a static loop bound; once `cond' goes
   false the body is skipped on every remaining iteration. The
   bf/cf flags carry break/continue: `break' sets both, `continue'
   sets cf; lower-stmts wraps each body statement with `(unless cf
   …)' so subsequent statements in the same iteration short-circuit."
  (let* ((cond-expr (getf (cdr stmt) :cond))
         (body      (getf (cdr stmt) :body))
         (k         (gensym "WHILE-K"))
         (bf        (gensym "WHILE-BF"))
         (cf        (gensym "WHILE-CF")))
    (let* ((*loop-break-bf* bf)
           (*loop-break-cf* cf)
           (body-forms (lower-stmts body))
           (cond-form  (lower-expr cond-expr)))
      `(whistler::let* ((,bf 0))
         (whistler::dotimes (,k ,+bt-max-loop-iters+)
           (whistler::unless ,bf
             (whistler::let* ((,cf 0))
               (whistler::when ,cond-form
                 ,@body-forms))))))))

(defun lower-for (stmt)
  "Lower a bpftrace `for $v : start..end { body }' to a bounded dotimes.

   Shape:
       (let* ((bf 0))
         (dotimes (k +bt-max-loop-iters+)
           (unless bf
             (let* ((cf 0)
                    ($v (+ start k)))
               (when (< $v end)
                 stmt1-wrapped …)))))

   $v is loop-scoped via the inner let*; it shadows any probe-scope
   binding of the same name. start/end are evaluated once per
   iteration — bpftrace's semantics — but the verifier-required
   static upper bound caps total iterations at +bt-max-loop-iters+."
  (let* ((vname     (getf (cdr stmt) :var))
         (start     (getf (cdr stmt) :start))
         (end       (getf (cdr stmt) :end))
         (body      (getf (cdr stmt) :body))
         (k         (gensym "FOR-K"))
         (bf        (gensym "FOR-BF"))
         (cf        (gensym "FOR-CF"))
         (var-sym   (var-sym vname)))
    (let* ((*loop-break-bf* bf)
           (*loop-break-cf* cf)
           (body-forms (lower-stmts body))
           (start-form (lower-expr start))
           (end-form   (lower-expr end)))
      `(whistler::let* ((,bf 0))
         (whistler::dotimes (,k ,+bt-max-loop-iters+)
           (whistler::unless ,bf
             (whistler::let* ((,cf 0)
                              (,var-sym (whistler::+ ,start-form ,k)))
               (whistler::when (whistler::< ,var-sym ,end-form)
                 ,@body-forms))))))))

(defun lower-break (stmt)
  (declare (ignore stmt))
  (unless *loop-break-bf*
    (unsupported "`break' outside of a loop"))
  ;; Set both flags: bf stops further iterations, cf skips the rest
  ;; of the current one.
  `(whistler::setf ,*loop-break-bf* 1 ,*loop-break-cf* 1))

(defun lower-continue (stmt)
  (declare (ignore stmt))
  (unless *loop-break-cf*
    (unsupported "`continue' outside of a loop"))
  `(whistler::setf ,*loop-break-cf* 1))

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
      (:discard
       ;; `_ = EXPR' — evaluate EXPR for side effects, discard value.
       ;; Useful as `_ = { …; … };' to invoke a block expression at
       ;; statement level when its result isn't wanted.
       (lower-expr rhs))
      (:var
       (let ((sym (var-sym (second lhs))))
         (cond
           ;; `$v = @m[k]' on a $v tracked as an array-var (its map's
           ;; value is a whole array): copy the N×elt-size bytes from
           ;; the map slot via map-lookup-ptr + memcpy. The var itself
           ;; is the buffer; lower-index reads element bytes off it.
           ((and (eq op :=)
                 (consp rhs) (eq (first rhs) :map)
                 (assoc (second lhs) *var-array-types* :test #'string=))
            (let* ((cell  (cdr (assoc (second lhs) *var-array-types*
                                      :test #'string=)))
                   (sz    (first cell))
                   (len   (second cell))
                   (total (* sz len))
                   (ptr   (gensym "MP")))
              `(let ((,ptr ,(lower-map-value-ptr rhs)))
                 (whistler::when ,ptr
                   (whistler::memcpy ,sym 0 ,ptr 0 ,total)))))
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
           ;; `$v = str(ptr[, len])' / `kstr(ptr[, len])' on a str-typed
           ;; $v — probe-read the NUL-terminated string from ptr into
           ;; $v's pre-allocated buffer. str() goes through user-str;
           ;; kstr() through kernel-str.
           ((and (eq op :=)
                 (consp rhs) (eq (first rhs) :call)
                 (or (str-call-p rhs) (kstr-call-p rhs))
                 (assoc (second lhs) *str-vars* :test #'string-equal))
            (let* ((entry  (assoc (second lhs) *str-vars*
                                  :test #'string-equal))
                   (size   (cdr entry))
                   (args   (getf (cdr rhs) :args))
                   (src    (lower-expr (first args)))
                   (helper (if (str-call-p rhs)
                               (intern "PROBE-READ-USER-STR" :whistler)
                               (intern "PROBE-READ-KERNEL-STR" :whistler))))
              `(,helper ,sym ,size ,src)))
           ;; `$v = "literal"' on a str-typed $v — emit byte-stores
           ;; that lay the literal (NUL-padded) into $v's buffer.
           ;; rewrite-self-refs lands `$v = func' / `$v = probe' here
           ;; after folding the per-probe name into a :str literal.
           ((and (eq op :=)
                 (consp rhs) (eq (first rhs) :str)
                 (assoc (second lhs) *str-vars* :test #'string-equal))
            (let* ((entry (assoc (second lhs) *str-vars*
                                 :test #'string-equal))
                   (size  (cdr entry)))
              (lower-printf-string-literal sym 0 (second rhs) size)))
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
                (whistler::memcpy ,slot-sym 0 ,p 0 ,vsize)
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
                (whistler::memcpy ,slot-sym 0 ,p 0 ,+bt-ntop-slot-size+)
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
   on SLOT-SYM's pre-allocated 17-byte buffer. Layout: bytes 0..15
   are the address (v4 left-aligned in the low 4 bytes; v6 fills
   the whole 16), byte 16 is the AF_* family. Putting the address
   at offset 0 keeps u32 / u64 stores naturally aligned, which the
   BPF verifier requires."
  (let* ((family-literal
           (and (cdr ntop-args)
                (let ((fa (first ntop-args)))
                  (case (first fa)
                    (:int      (second fa))
                    (:constant (resolve-constant (second fa)))))))
         (addr-expr
           (if (cdr ntop-args) (second ntop-args) (first ntop-args)))
         (chain-info (and (null family-literal)
                          (multiple-value-list (analyze-chain addr-expr))))
         (chain-kind (third chain-info))
         (chain-size (second chain-info))
         (chain-ptr  (first chain-info)))
    (cond
      ((eql family-literal 10)
       `(progn
          (whistler::probe-read-kernel
           ,slot-sym 16 ,(lower-chain-as-ptr addr-expr))
          (whistler::store whistler::u8 ,slot-sym 16 10)))
      ((and (eq chain-kind :array) (eql chain-size 16))
       `(progn
          (whistler::probe-read-kernel ,slot-sym 16 ,chain-ptr)
          (whistler::store whistler::u8 ,slot-sym 16 10)))
      ;; Single-arg form (no family) — implicit AF_INET, addr is a u32.
      ((null (cdr ntop-args))
       `(progn
          (whistler::store whistler::u32 ,slot-sym 0
                           ,(lower-expr addr-expr))
          ,@(loop for off from 4 below 16
                  collect `(whistler::store whistler::u8 ,slot-sym ,off 0))
          (whistler::store whistler::u8 ,slot-sym 16 2)))
      ;; Literal AF_INET — store the u32 and zero-pad.
      ((eql family-literal 2)
       `(progn
          (whistler::store whistler::u32 ,slot-sym 0
                           ,(lower-expr addr-expr))
          ,@(loop for off from 4 below 16
                  collect `(whistler::store whistler::u8 ,slot-sym ,off 0))
          (whistler::store whistler::u8 ,slot-sym 16 2)))
      ;; Runtime family — emit a branch. Both arms assume ADDR-EXPR
      ;; lowers to a pointer to up to 16 bytes (the v6 max); the
      ;; v4 arm probes only the low 4 and zero-pads the rest.
      (t
       (let ((fam (gensym "FAM")))
         `(let ((,fam ,(lower-expr (first ntop-args))))
            (if (whistler::= ,fam 2)
                (progn
                  (whistler::probe-read-kernel
                   ,slot-sym 4 ,(lower-chain-as-ptr addr-expr))
                  ,@(loop for off from 4 below 16
                          collect `(whistler::store whistler::u8 ,slot-sym ,off 0)))
                (whistler::probe-read-kernel
                 ,slot-sym 16 ,(lower-chain-as-ptr addr-expr)))
            (whistler::store whistler::u8 ,slot-sym 16 ,fam)))))))

(defun maybe-bump-len-counter (info op delta)
  "Returns a Lisp form to bump (or no-op) the len(@m) sidecar
   counter for INFO. Plain `=' that touches a single key adds 1; the
   `:+=' / `:-=' arms don't change entry count. DELTA is the signed
   delta to apply (+1 on assign, -1 on delete). NIL when the map
   doesn't have a sidecar."
  (when (and (minfo-needs-len-counter-p info)
             (or (eq op :=) (eq op :delete)))
    (let ((sym (len-counter-sym info)))
      (if (plusp delta)
          `(whistler:incf (whistler:getmap ,sym 0) ,delta)
          `(whistler:decf (whistler:getmap ,sym 0) ,(- delta))))))

(defun wrap-with-len-counter (info op form)
  "When INFO is a `len(@m)'-targeted map and OP changes the entry
   count, append a counter-bump after FORM and wrap in `progn'."
  (let ((bump (maybe-bump-len-counter info op 1)))
    (if bump `(progn ,form ,bump) form)))

(defun lower-map-assign (mref op rhs)
  (let* ((info (or (gethash (or (getf (cdr mref) :name) "@") *map-table*)
                   (error "internal: missing map ~A" (getf (cdr mref) :name))))
         (mname (minfo-name info))
         (keys  (getf (cdr mref) :keys)))
    (wrap-with-len-counter info op
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
            (gen-hist-update mname keys
                             (lower-expr (first (getf (cdr rhs) :args)))
                             info))
           ((string= fn "lhist")
            (let* ((args (getf (cdr rhs) :args))
                   (value-form (lower-expr (first args)))
                   (params (minfo-hist-params info)))
              (unless params
                (unsupported "internal: lhist info missing params"))
              (destructuring-bind (lo hi step) params
                (gen-lhist-update mname keys value-form lo hi step info))))
           ;; `@m[k] = ntop(…)' — value slot stores 17 bytes
           ;; (family + address). See gen-ntop-set for the layout.
           ((and (string= fn "ntop") (minfo-value-ntop-p info))
            (gen-ntop-set info keys (getf (cdr rhs) :args)))
           ;; `@m[k] = str(ptr[, len])' / `kstr(...)' — probe-read
           ;; a NUL-terminated string into the map's string slot.
           ((and (or (string= fn "str") (string= fn "kstr"))
                 (minfo-value-string-p info))
            (gen-str-set info keys
                         (first (getf (cdr rhs) :args))
                         (string= fn "str")))
           (t (gen-scalar-set mname keys (lower-expr rhs) op
                              :ptr-elt-size (minfo-value-ptr-elt-size info))))))
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
      ;; `@m[k] = args' (fentry/fexit) — the value is a freshly-
      ;; allocated buffer of param-count × 8 bytes. lower-bare-args
      ;; already emits the buffer + writes; route the resulting
      ;; pointer through map-update-ptr.
      ((and (consp rhs) (eq (first rhs) :args)
            (minfo-value-array-p info))
       (let ((aval  (gensym "AVAL"))
             (tmpk  (gensym "K"))
             (mname (minfo-name info))
             (ptr-p (keys-need-ptr-ops-p keys)))
         (with-key keys
           (lambda (k)
             (if ptr-p
                 `(let ((,aval ,(lower-bare-args)))
                    (whistler::map-update-ptr ,mname ,k ,aval 0))
                 `(let* ((,tmpk whistler::u64 ,k)
                         (,aval ,(lower-bare-args)))
                    (whistler::map-update-ptr
                     ,mname (whistler::stack-addr ,tmpk) ,aval 0)))))))
      ;; `@m[k] = (struct A *)e.arrfield' — whole-array assignment.
      ;; Probe-read N×sizeof(elt) bytes from struct+field-off into a
      ;; stack buffer, then map-update-ptr.
      ((and (consp rhs) (eq (first rhs) :field)
            (minfo-value-array-p info)
            (array-field-meta rhs))
       (multiple-value-bind (base-ast _sz _off _len)
           (array-field-meta rhs)
         (declare (ignore _sz _off _len))
         (multiple-value-bind (_b sz off len) (array-field-meta rhs)
           (declare (ignore _b))
           (gen-array-field-set info keys
                                (lower-expr base-ast)
                                (* sz len) off))))
      ;; `@m[k] = ntop(…)' — write a 17-byte family+address record
      ;; into the value slot, using the same encoding as the $var-ntop
      ;; path so :ipv-any printf reads transparently.
      ((and (consp rhs) (eq (first rhs) :call)
            (stringp (getf (cdr rhs) :name))
            (string= (getf (cdr rhs) :name) "ntop")
            (minfo-value-ntop-p info))
       (gen-ntop-set info keys (getf (cdr rhs) :args)))
      (t (gen-scalar-set mname keys (lower-expr rhs) op
                         :ptr-elt-size (minfo-value-ptr-elt-size info)))))))

(defun gen-str-set (info keys ptr-expr user-p)
  "Store the NUL-terminated string at PTR-EXPR as @MNAME[KEYS]'s
   value. Allocates a value-size scratch buffer, probe-reads into
   it (user or kernel variant by USER-P), then map_update_elem."
  (let* ((mname  (minfo-name info))
         (vsize  (minfo-value-size info))
         (buf    (gensym "VBUF"))
         (tmpk   (gensym "K"))
         (ptr-p  (keys-need-ptr-ops-p keys))
         (helper (if user-p
                     (intern "PROBE-READ-USER-STR" :whistler)
                     (intern "PROBE-READ-KERNEL-STR" :whistler))))
    (with-key keys
      (lambda (k)
        (let ((src (lower-expr ptr-expr)))
          (if ptr-p
              `(let ((,buf (whistler::struct-alloc ,vsize)))
                 (,helper ,buf ,vsize ,src)
                 (whistler::map-update-ptr ,mname ,k ,buf 0))
              `(let* ((,tmpk whistler::u64 ,k)
                      (,buf (whistler::struct-alloc ,vsize)))
                 (,helper ,buf ,vsize ,src)
                 (whistler::map-update-ptr
                  ,mname (whistler::stack-addr ,tmpk) ,buf 0))))))))

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

(defun gen-array-field-set (info keys struct-ptr-form total-bytes field-offset)
  "Store the TOTAL-BYTES bytes at (STRUCT-PTR-FORM + FIELD-OFFSET) into
   the value slot of @MNAME[KEYS]. Used for `@m = (struct A *)e.x'
   where x is a fixed-size array field. Allocates a value-sized
   scratch buffer, probe-reads the array bytes in via the right user/
   kernel helper, then map-update-ptr."
  (let* ((mname (minfo-name info))
         (buf   (gensym "AVAL"))
         (tmpk  (gensym "K"))
         (ptr-p (keys-need-ptr-ops-p keys))
         (helper (pick-probe-read-fn)))
    (with-key keys
      (lambda (k)
        (if ptr-p
            `(let ((,buf (whistler::struct-alloc ,total-bytes)))
               (,helper ,buf ,total-bytes
                        (whistler::+ ,struct-ptr-form ,field-offset))
               (whistler::map-update-ptr ,mname ,k ,buf 0))
            `(let* ((,tmpk whistler::u64 ,k)
                    (,buf (whistler::struct-alloc ,total-bytes)))
               (,helper ,buf ,total-bytes
                        (whistler::+ ,struct-ptr-form ,field-offset))
               (whistler::map-update-ptr
                ,mname (whistler::stack-addr ,tmpk) ,buf 0)))))))

(defun gen-string-set (info keys literal)
  "Store LITERAL as the NUL-padded contents of @MNAME[KEYS]. Reuses
   the per-probe shared *string-set-buf* (allocated once in the
   prologue) so a BEGIN block initialising N entries doesn't bloat
   the stack by N × value-size. Scalar keys also reuse the shared
   *shared-key-slot*: N × 8-byte one-shot key buffers (capable.bt's
   41-entry @cap init) collapse to a single 8-byte slot."
  (let* ((mname (minfo-name info))
         (vsize (minfo-value-size info))
         (buf   *string-set-buf*)
         (ptr-p (keys-need-ptr-ops-p keys)))
    (unless buf
      (unsupported "internal: gen-string-set called outside a probe scope"))
    (with-key keys
      (lambda (k)
        (cond
          (ptr-p
           `(progn
              ,(lower-printf-string-literal buf 0 literal vsize)
              (whistler::map-update-ptr ,mname ,k ,buf 0)))
          (t
           (setf *shared-key-buf-used* t)
           `(progn
              (whistler::store whistler::u64 ,*shared-key-buf* 0 ,k)
              ,(lower-printf-string-literal buf 0 literal vsize)
              (whistler::map-update-ptr
               ,mname ,*shared-key-buf* ,buf 0))))))))

(defun gen-sum-update (mname keys value-form)
  "sum(x): incf the percpu-hash entry by x. The per-CPU storage means
   each CPU has its own bucket — no atomics needed."
  (with-key keys
    (lambda (k)
      `(whistler:incf (whistler:getmap ,mname ,k) ,value-form))))

(defun keys-need-ptr-ops-p (keys)
  "T iff the keys form requires the kernel -ptr map ops (whistler's
   struct-key path). Triggered by composite keys or by a single
   string-typed key (`comm', `str(…)', `kstr(…)', `func', `probe',
   or a bare :str literal — the latter is what rewrite-self-refs
   produces for `@[func]' / `@[probe]' inside map keys, so the
   downstream path needs to recognise it the same way), or by a
   single in-script struct array-field key (its byte width exceeds
   the 8-byte scalar key path)."
  (or (> (length keys) 1)
      (and (= (length keys) 1)
           (let ((k (first keys)))
             (or (eq (first k) :comm)
                 (eq (first k) :func)
                 (eq (first k) :probe-name)
                 (eq (first k) :str)
                 (str-call-p k)
                 (kstr-call-p k)
                 (and (eq (first k) :field) (array-field-meta k))
                 (and (eq (first k) :args) (bare-args-byte-width)))))))

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

(defun gen-scalar-set (mname keys value op &key ptr-elt-size)
  "Generate a kernel-side update for `@m[k] OP VALUE'. PTR-ELT-SIZE,
   when set, scales the delta for `+=' / `-=' by sizeof(T) — matching
   C/bpftrace pointer arithmetic on typed pointers. Plain `=' is
   never scaled (it writes the raw address)."
  (let ((delta (if (and ptr-elt-size (or (eq op :+=) (eq op :-=)))
                   `(whistler::* ,value ,ptr-elt-size)
                   value)))
    (with-key keys
      (lambda (k)
        (ecase op
          (:=  `(setf (whistler:getmap ,mname ,k) ,delta))
          (:+= `(whistler:incf (whistler:getmap ,mname ,k) ,delta))
          (:-= `(whistler:decf (whistler:getmap ,mname ,k) ,delta)))))))

(defun gen-hist-update (mname keys value-form &optional info)
  "log2 histogram update. KEYS is the surface key list — empty for
   non-keyed (the original percpu-array-indexed-by-bucket form), or
   one user-key for the new compound-key percpu-hash form."
  (let ((val  (gensym "V"))
        (slot (gensym "S"))
        (p    (gensym "P")))
    (cond
      ;; Non-keyed: original percpu-array path.
      ((null keys)
       `(let* ((,val ,value-form)
               (,slot (whistler::log2 ,val)))
          (when (whistler::>= ,slot 64) (setf ,slot 63))
          (whistler:when-let ((,p (whistler::map-lookup ,mname ,slot)))
            (whistler::atomic-add ,p 0 1))))
      ((= 1 (length keys))
       (gen-hist-update-keyed mname info keys value-form :log2))
      (t
       (unsupported "@m[k1, k2, …] = hist(x) — composite user-keys not yet supported")))))

(defun gen-lhist-update (mname keys value-form lo hi step &optional info)
  "Linear histogram update. KEYS shape mirrors gen-hist-update.
   Buckets:
     0      → underflow (value < LO)
     1..N   → [LO + (i-1)*STEP, LO + i*STEP)
     N+1    → overflow  (value >= HI)
   where N = (HI - LO) / STEP."
  (let* ((n    (max 1 (floor (- hi lo) step)))
         (over (+ n 1))
         (val  (gensym "V"))
         (slot (gensym "S"))
         (p    (gensym "P"))
         (bucket-form `(cond
                         ((whistler::< ,val ,lo) 0)
                         ((whistler::>= ,val ,hi) ,over)
                         (t (whistler::+ 1
                                         (whistler::/ (whistler::- ,val ,lo)
                                                      ,step))))))
    (cond
      ((null keys)
       `(let* ((,val ,value-form)
               (,slot ,bucket-form))
          (whistler:when-let ((,p (whistler::map-lookup ,mname ,slot)))
            (whistler::atomic-add ,p 0 1))))
      ((= 1 (length keys))
       (gen-hist-update-keyed mname info keys value-form
                              (list :linear lo hi step over)))
      (t
       (unsupported "@m[k1, k2, …] = lhist(x,…) — composite user-keys not yet supported")))))

(defun gen-hist-update-keyed (mname info keys value-form mode)
  "Emit a keyed hist/lhist update. The map is a percpu-hash whose
   key is USER-KEY-BYTES followed by a u32 bucket index. MODE is
   either :log2 (the hist() shape) or (:linear LO HI STEP OVER)
   for lhist(). incf-map's struct-key-map-p path handles the
   create-if-missing semantics for us."
  (let* ((user-key (first keys))
         (user-key-size (or (and info (- (minfo-key-size info) 4))
                            (expr-size user-key)))
         (total (+ user-key-size 4))
         (val   (gensym "V"))
         (slot  (gensym "S"))
         (kbuf  (gensym "KBUF"))
         (bucket
           (ecase (if (consp mode) (first mode) mode)
             (:log2
              `(let ((,slot (whistler::log2 ,val)))
                 (when (whistler::>= ,slot 64) (setf ,slot 63))
                 ,slot))
             (:linear
              (destructuring-bind (lo hi step over) (rest mode)
                `(cond
                   ((whistler::< ,val ,lo) 0)
                   ((whistler::>= ,val ,hi) ,over)
                   (t (whistler::+ 1
                                   (whistler::/ (whistler::- ,val ,lo)
                                                ,step)))))))))
    `(let* ((,val ,value-form)
            (,slot ,bucket)
            (,kbuf (whistler::struct-alloc ,total)))
       ,(emit-key-bytes kbuf 0 user-key user-key-size)
       (whistler::store whistler::u32 ,kbuf ,user-key-size ,slot)
       (whistler:incf-map ,mname ,kbuf))))

(defun emit-key-bytes (buf offset key-expr key-size)
  "Emit stores that copy KEY-EXPR's bytes into BUF starting at OFFSET.
   For comm/str/composite-shaped keys we'd need a byte-copy; for the
   single-key hist case we currently support only scalar u64-ish keys."
  (let ((store-type (case key-size
                      (1 (intern "U8"  :whistler))
                      (2 (intern "U16" :whistler))
                      (4 (intern "U32" :whistler))
                      (t (intern "U64" :whistler)))))
    `(whistler::store ,store-type ,buf ,offset ,(lower-expr key-expr))))

(defun lower-incdec-expr (expr)
  "Lower `$x++' / `++$x' / `@m[k]++' / `++@m[k]' used as an expression
   (e.g. inside a printf arg). The statement variant `$x++;' already
   has a handler in lower-incdec; this version preserves the value
   for the surrounding expression. Postfix returns the pre-increment
   value via `prog1'; prefix returns the post-increment value."
  (let* ((lhs  (getf (cdr expr) :lhs))
         (op   (getf (cdr expr) :op))
         (form (getf (cdr expr) :form)))
    (ecase (first lhs)
      (:var
       (let ((sym (var-sym (second lhs))))
         (ecase form
           (:post
            (let ((tmp (gensym "POST")))
              `(let ((,tmp ,sym))
                 (setq ,sym ,(if (eq op :inc)
                                 `(whistler::+ ,sym 1)
                                 `(whistler::- ,sym 1)))
                 ,tmp)))
           (:pre
            `(progn
               (setq ,sym ,(if (eq op :inc)
                               `(whistler::+ ,sym 1)
                               `(whistler::- ,sym 1)))
               ,sym)))))
      (:map
       (let* ((info  (or (gethash (or (getf (cdr lhs) :name) "@") *map-table*)
                         (error "internal: missing map ~A" (getf (cdr lhs) :name))))
              (mname (minfo-name info))
              (keys  (getf (cdr lhs) :keys))
              (step  (or (minfo-value-ptr-elt-size info) 1)))
         (with-key keys
           (lambda (k)
             (let ((read-form `(whistler:getmap ,mname ,k))
                   (update (if (eq op :inc)
                               `(whistler:incf (whistler:getmap ,mname ,k) ,step)
                               `(whistler:decf (whistler:getmap ,mname ,k) ,step))))
               (ecase form
                 (:post (let ((tmp (gensym "POST")))
                          `(let ((,tmp ,read-form))
                             ,update
                             ,tmp)))
                 (:pre  `(progn ,update ,read-form)))))))))))

(defun lower-incdec (stmt)
  "Lower `$x++' / `$x--' / `++$x' / `--$x' / `@m[k]++' etc. Statement-
   level only — semantics are identical for prefix and postfix when
   the result is discarded. Maps walk through getmap/incf/decf; scalar
   vars expand to a plain `$x = $x ± 1' since they're bound as IR
   locals, not via the map machinery."
  (let* ((lhs  (getf (cdr stmt) :lhs))
         (op   (getf (cdr stmt) :op))
         (kind (first lhs)))
    (ecase kind
      (:map
       (let* ((info  (or (gethash (or (getf (cdr lhs) :name) "@") *map-table*)
                         (error "internal: missing map ~A" (getf (cdr lhs) :name))))
              (mname (minfo-name info))
              (keys  (getf (cdr lhs) :keys))
              ;; Pointer arithmetic: when the map's value is a typed
              ;; pointer (set from an earlier `(T *)' cast), step by
              ;; sizeof(T) instead of 1.
              (step  (or (minfo-value-ptr-elt-size info) 1)))
         (with-key keys
           (lambda (k)
             (ecase op
               (:inc `(whistler:incf (whistler:getmap ,mname ,k) ,step))
               (:dec `(whistler:decf (whistler:getmap ,mname ,k) ,step)))))))
      (:var
       (let ((sym (var-sym (second lhs))))
         (ecase op
           (:inc `(setq ,sym (whistler::+ ,sym 1)))
           (:dec `(setq ,sym (whistler::- ,sym 1)))))))))

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
              (mname (minfo-name info))
              (bump (maybe-bump-len-counter info :delete -1)))
         (with-key keys
           (lambda (k)
             (if bump
                 `(progn (whistler:remmap ,mname ,k) ,bump)
                 `(whistler:remmap ,mname ,k))))))
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
    ;; profile:hz:N → freq mode (N samples/sec/CPU); profile:s/ms/us:N
    ;; → period mode (one sample every N units/CPU). The unit is
    ;; encoded in the section name so the runtime can pick the right
    ;; perf-event attach call.
    (:profile    (values :kprobe (profile-section-name spec)))))

(defun profile-section-name (spec)
  "Encode a :profile probe spec into a section name. `profile:hz:N'
   uses freq mode and lands as `profile/freq_N'; `profile:s:N',
   `profile:ms:N', `profile:us:N' use period mode and land as
   `profile/period_NS' where NS is the period in nanoseconds."
  (let ((unit  (getf (cdr spec) :unit))
        (count (getf (cdr spec) :count)))
    (case unit
      (:hz (format nil "profile/freq_~D" count))
      (:s  (format nil "profile/period_~D" (* count 1000000000)))
      (:ms (format nil "profile/period_~D" (* count 1000000)))
      (:us (format nil "profile/period_~D" (* count 1000)))
      (t   (unsupported "profile:~A:~D — unit must be hz, s, ms, or us"
                        unit count)))))

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
               ;; $v = func/probe — rewrite RHS to a :str literal so
               ;; the var ends up holding the per-probe section name
               ;; in its pre-allocated buffer. infer-str-vars already
               ;; reserved the buffer; lower-assign's :str-into-var
               ;; branch handles the actual byte-stores.
               ((and (eq (first f) :assign)
                     (let ((lhs (getf (cdr f) :lhs)))
                       (and (consp lhs) (eq (first lhs) :var))))
                (list :assign
                      :lhs (walk (getf (cdr f) :lhs))
                      :op  (getf (cdr f) :op)
                      :rhs (rewrite-leaf (getf (cdr f) :rhs))))
               (t (cons (walk (first f)) (walk (rest f)))))))
    (walk form)))

(defun prim-ptr-elt-size (type-name)
  "Byte-width of a primitive-pointer cast's element type. Returns
   NIL for an unrecognised name so the caller can fall through to
   the generic `array indexing outside @maps' error."
  (cond
    ((or (string= type-name "uint8") (string= type-name "int8")
         (string= type-name "bool"))
     1)
    ((or (string= type-name "uint16") (string= type-name "int16")) 2)
    ((or (string= type-name "uint32") (string= type-name "int32")) 4)
    ((or (string= type-name "uint64") (string= type-name "int64")
         (string= type-name "uint")   (string= type-name "int"))
     8)
    (t nil)))

(defun pick-probe-read-fn ()
  "Pick probe-read-user vs probe-read-kernel based on the active
   probe type. uprobe/uretprobe/USDT contexts point at userspace
   memory; everything else (kprobe, kfunc, tracepoint, …) at kernel
   memory."
  (case (first *probe-spec*)
    ((:uprobe :uretprobe :usdt)
     (intern "PROBE-READ-USER" :whistler))
    (t
     (intern "PROBE-READ-KERNEL" :whistler))))

(defun infer-var-array-types (stmts)
  "Walk STMTS for `$v = @m[k]' where @m's minfo carries value-array-p
   (set by infer-maps when the script stored a whole-array field as
   the map's value). Returns an alist (VAR-NAME . (ELT-SIZE ARR-LEN))
   so the var binding can allocate a backing buffer and lower-index
   on the var can load typed bytes from it."
  (let ((acc nil))
    (labels ((maybe-record (lhs rhs)
               (when (and (consp lhs) (eq (first lhs) :var)
                          (consp rhs) (eq (first rhs) :map)
                          *map-table*)
                 (let* ((nm (or (getf (cdr rhs) :name) "@"))
                        (info (gethash nm *map-table*))
                        (sz (and info (minfo-value-array-elt-size info)))
                        (vs (and info (minfo-value-size info))))
                   (when (and sz vs (minfo-value-array-p info))
                     (push (cons (second lhs) (list sz (/ vs sz))) acc)))))
             (walk (s)
               (case (first s)
                 (:assign (maybe-record (getf (cdr s) :lhs)
                                        (getf (cdr s) :rhs)))
                 (:if     (mapc #'walk (getf (cdr s) :then))
                          (mapc #'walk (getf (cdr s) :else)))
                 (:while  (mapc #'walk (getf (cdr s) :body)))
                 (:for    (mapc #'walk (getf (cdr s) :body))))))
      (mapc #'walk stmts))
    acc))

(defun infer-var-ptr-elt-types (stmts)
  "Walk STMTS for `$v = (T *) EXPR' assignments and return an alist
   (VAR-NAME . (TYPE-NAME ELT-SIZE)). RHS may also be:
     * a parens-wrapped cast (normalize already strips :parens);
     * a `:map' read whose minfo carries value-ptr-elt-size — the map
       was previously stored from a `(T *)' cast, so flow that into
       the var too (`$x = @m[k]; $x[0]' should subscript-read).
   Returns the alist of recordings."
  (let ((acc nil))
    (labels ((rhs-ptr-elt-size (rhs)
               (cond
                 ((and (consp rhs) (eq (first rhs) :prim-ptr-cast))
                  (list (getf (cdr rhs) :elt-type)
                        (prim-ptr-elt-size (getf (cdr rhs) :elt-type))))
                 ((and (consp rhs) (eq (first rhs) :map)
                       *map-table*)
                  (let* ((nm (or (getf (cdr rhs) :name) "@"))
                         (info (gethash nm *map-table*))
                         (sz (and info (minfo-value-ptr-elt-size info))))
                    (when sz (list "u" sz))))))
             (maybe-record (lhs rhs)
               (when (and (consp lhs) (eq (first lhs) :var))
                 (let ((cell (rhs-ptr-elt-size rhs)))
                   (when (and cell (second cell))
                     (push (cons (second lhs) cell) acc)))))
             (walk (s)
               (case (first s)
                 (:assign (maybe-record (getf (cdr s) :lhs)
                                        (getf (cdr s) :rhs)))
                 (:if     (mapc #'walk (getf (cdr s) :then))
                          (mapc #'walk (getf (cdr s) :else)))
                 (:while  (mapc #'walk (getf (cdr s) :body)))
                 (:for    (mapc #'walk (getf (cdr s) :body))))))
      (mapc #'walk stmts))
    acc))

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
                 (:while  (mapc #'walk (getf (cdr s) :body)))
                 (:for    (mapc #'walk (getf (cdr s) :body))))))
      (mapc #'walk stmts))
    acc))

(defun fold-getopt-expr (expr)
  "If EXPR is `(:call :name \"getopt\" :args ((:str NAME) DEFAULT …))'
   resolve it against *named-params*. With a :str DEFAULT, returns a
   :str literal (override or default). With :int / :constant defaults
   we leave the call alone — those are handled by lower-call's
   integer/bool path. Returns EXPR unchanged when no fold applies."
  (cond
    ((not (and (consp expr) (eq (first expr) :call)
               (stringp (getf (cdr expr) :name))
               (string= (getf (cdr expr) :name) "getopt")))
     expr)
    (t
     (let* ((args     (getf (cdr expr) :args))
            (opt-name (and (consp (first args))
                           (eq (first (first args)) :str)
                           (second (first args))))
            (default  (second args))
            (provided (and opt-name *named-params*
                           (assoc opt-name *named-params* :test #'string=))))
       (cond
         ;; Only fold when the default is a :str literal.
         ((not (and (consp default) (eq (first default) :str))) expr)
         ;; CLI override present → emit the user's value as :str.
         (provided `(:str ,(cdr provided)))
         ;; No override → resolve to the literal default.
         (t default))))))

(defun fold-getopt (form)
  "Walk FORM recursively, replacing eligible getopt(NAME, DEFAULT)
   calls with their resolved :str literals."
  (cond
    ((not (consp form)) form)
    (t
     (let ((folded (fold-getopt-expr form)))
       (if (eq folded form)
           (cons (fold-getopt (first form)) (fold-getopt (rest form)))
           folded)))))

(defparameter *no-arg-builtin-aliases*
  ;; bpftrace's stdlib defines `comm()`, `pid()`, etc. as no-arg
  ;; macros that resolve to the equivalent bare builtin. Map the
  ;; call form back to the AST node shape that lower-expr expects
  ;; so downstream paths (printf %s, @m[comm], lower-builtin) all
  ;; pick them up automatically.
  '(("comm" :comm)        ("pcomm" :pcomm)
    ("pid" :builtin :pid) ("tid" :builtin :tid)
    ("uid" :builtin :uid) ("gid" :builtin :gid)
    ("ppid" :builtin :ppid)
    ("nsecs" :builtin :nsecs) ("cpu" :builtin :cpu)
    ("cgroup" :builtin :cgroup) ("rand" :builtin :rand)
    ("elapsed" :builtin :elapsed)
    ("func" :func) ("probe" :probe-name)
    ("retval" :retval) ("curtask" :curtask)
    ("args" :args)))

(defun fold-stdlib-aliases-expr (expr)
  "Rewrite `(:call :name NAME :args ())' to the matching builtin AST
   node when NAME is one of *no-arg-builtin-aliases*."
  (cond
    ((not (and (consp expr) (eq (first expr) :call)
               (stringp (getf (cdr expr) :name))
               (null (getf (cdr expr) :args))))
     expr)
    (t
     (let ((mapping (assoc (getf (cdr expr) :name)
                           *no-arg-builtin-aliases* :test #'string=)))
       (cond
         ((null mapping) expr)
         ;; Two-element mapping → bare-keyword node like `(:comm)'.
         ((= (length mapping) 2) (list (second mapping)))
         ;; Three-element mapping → (:builtin :KW) node.
         (t (list (second mapping) (third mapping))))))))

(defun fold-stdlib-aliases (form)
  (cond
    ((not (consp form)) form)
    (t
     (let ((folded (fold-stdlib-aliases-expr form)))
       (if (eq folded form)
           (cons (fold-stdlib-aliases (first form))
                 (fold-stdlib-aliases (rest form)))
           folded)))))

(defun fold-stdlib-aliases-script (script)
  (cons (first script)
        (mapcar (lambda (form)
                  (if (consp form) (fold-stdlib-aliases form) form))
                (rest script))))

(defun fold-getopt-script (script)
  "Apply fold-getopt to every probe / macro / function body so the
   resolved :str literals reach infer-* and rewrite-self-refs."
  (cons (first script)
        (mapcar (lambda (form)
                  (if (consp form) (fold-getopt form) form))
                (rest script))))

(defun expand-tuple-vars-script (script)
  "Apply expand-tuple-vars per top-form (probes AND user macros/fns).
   Each form has its own *tuple-vars* derived from its body. Macros
   need the same expansion since they're inlined at lower time;
   without it, a `let \$key = (…)' inside a macro and the matching
   `@m[\$key]' a few lines down would never collapse to composite-key
   form."
  (flet ((expand-body-form (form body-key drop-assigns)
           (let* ((body (getf (cdr form) body-key))
                  (pred (getf (cdr form) :predicate))
                  (*tuple-vars* (infer-tuple-vars body))
                  (body* (expand-tuple-vars body))
                  (body* (if drop-assigns
                             (drop-tuple-assignments body*)
                             body*))
                  (pred* (when pred (expand-tuple-vars pred))))
             (loop for (k v) on (cdr form) by #'cddr
                   append (list k (cond ((eq k body-key) body*)
                                        ((eq k :predicate) pred*)
                                        (t v)))
                     into rest
                   finally (return (cons (first form) rest))))))
    (cons (first script)
          (mapcar
           (lambda (form)
             (cond
               ((and (consp form) (eq (first form) :probe))
                (expand-body-form form :body nil))
               ((and (consp form)
                     (member (first form) '(:macro :function)))
                ;; Drop tuple-assigns from macros now — there's no
                ;; gen-kernel-prog pass for them, so without it the
                ;; assignment survives into the inlined body and
                ;; trips lower-assign on `\$v = (:tuple …)'.
                (expand-body-form form :body t))
               (t form)))
           (rest script)))))

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
       ((eq (first s) :for)
        (list :for
              :var (getf (cdr s) :var)
              :start (getf (cdr s) :start)
              :end (getf (cdr s) :end)
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

(defun walk-stmts-with-macros (stmts walk-fn)
  "Apply WALK-FN to every statement in STMTS and to every statement
   in every user-fn/macro body transitively reachable via :call.
   Used by the per-probe inference passes so $vars defined inside a
   macro (e.g. opensnoop's `$path = str(@filename[tid])' in
   sys_exit) are seen at probe scope before lowering. Each macro
   is visited at most once per top-level call to avoid infinite
   recursion on mutually-recursive definitions."
  (let ((visited (make-hash-table :test 'equal)))
    (labels ((scan-call (form)
               (when (and (consp form) (eq (first form) :call))
                 (let ((name (getf (cdr form) :name)))
                   (when (and name (not (gethash name visited)))
                     (let ((fn (find-user-function name)))
                       (when fn
                         (setf (gethash name visited) t)
                         (mapc #'walk-and-recurse (getf fn :body))))))))
             (scan-expr (e)
               (when (consp e)
                 (scan-call e)
                 (mapc (lambda (x) (when (consp x) (scan-expr x))) (rest e))))
             (walk-and-recurse (s)
               (funcall walk-fn s)
               (case (first s)
                 (:if (mapc #'walk-and-recurse (getf (cdr s) :then))
                      (mapc #'walk-and-recurse (getf (cdr s) :else)))
                 (:while (mapc #'walk-and-recurse (getf (cdr s) :body)))
                 (:for   (mapc #'walk-and-recurse (getf (cdr s) :body))))
               ;; Sniff expressions for embedded user-fn calls so a
               ;; bare `(:expr (:call name args))' or an assignment
               ;; whose RHS calls a user fn pulls in that body too.
               (case (first s)
                 (:expr   (scan-expr (second s)))
                 (:assign (scan-expr (getf (cdr s) :rhs))))))
      (mapc #'walk-and-recurse stmts))))

(defun infer-str-vars (stmts)
  "Return an alist (VAR-NAME . SIZE) of $vars assigned from a string-
   typed RHS: `str(ptr [,n])', `kstr(ptr [,n])', `func', or
   `probe'. SIZE picks the right buffer width: str()'s explicit
   second arg (or +bt-str-default-len+), or +bt-func-name-key-len+
   for func / probe. Scans into user-fn / macro bodies via
   walk-stmts-with-macros so $vars defined inside a called macro
   get sized at probe scope before lowering."
  (let ((acc nil))
    (flet ((maybe-record (s)
             (when (eq (first s) :assign)
               (let* ((lhs (getf (cdr s) :lhs))
                      (rhs (getf (cdr s) :rhs))
                      (sz (cond
                            ((and (consp rhs) (eq (first rhs) :call)
                                  (or (str-call-p rhs) (kstr-call-p rhs)))
                             (str-key-size rhs))
                            ;; `$v = func' / `$v = probe' — fold the
                            ;; per-probe name into a fixed-width slot.
                            ;; rewrite-self-refs will later convert the
                            ;; RHS to a :str literal that hits
                            ;; lower-assign's :str-into-var branch.
                            ((and (consp rhs)
                                  (or (eq (first rhs) :func)
                                      (eq (first rhs) :probe-name)))
                             +bt-func-name-key-len+)
                            ;; `$v = "literal"' — produced by
                            ;; fold-getopt when the default is a :str.
                            ;; Size to the bigger of the literal width
                            ;; or the default str() length so longer
                            ;; CLI overrides also fit.
                            ((and (consp rhs) (eq (first rhs) :str))
                             (max +bt-str-default-len+
                                  (1+ (length (second rhs))))))))
                 (when (and sz (consp lhs) (eq (first lhs) :var))
                   (let ((entry (assoc (second lhs) acc :test #'string=)))
                     (if entry
                         (setf (cdr entry) (max (cdr entry) sz))
                         (push (cons (second lhs) sz) acc))))))))
      (walk-stmts-with-macros stmts #'maybe-record))
    acc))

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
                 (:while  (mapc #'walk (getf (cdr s) :body)))
                 (:for    (mapc #'walk (getf (cdr s) :body))))))
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
                 (:while  (mapc #'walk (getf (cdr s) :body)))
                 (:for    (mapc #'walk (getf (cdr s) :body))))))
      (mapc #'walk stmts))
    acc))

(defun field-chain-leaf-struct (rhs known-types)
  "If RHS is a (possibly chained) :field expression whose root is
   :curtask or a :var with a known struct type, walk the chain
   through vmlinux BTF and return the struct name of the leaf
   field's pointer target — e.g. `curtask.fs.pwd.mnt' → \"vfsmount\".
   Returns NIL for any chain we can't fully resolve, the leaf isn't
   a pointer-to-struct, or vmlinux BTF is unavailable. KNOWN-TYPES
   is the accumulator from infer-var-types so far."
  (unless (and (consp rhs) (eq (first rhs) :field)) (return-from field-chain-leaf-struct nil))
  (let ((names nil) (root nil))
    (labels ((walk (e)
               (cond
                 ((and (consp e) (eq (first e) :field))
                  (push (getf (cdr e) :name) names)
                  (walk (getf (cdr e) :base)))
                 (t (setf root e)))))
      (walk rhs))
    (let ((root-struct
            (cond
              ((and (consp root) (eq (first root) :curtask)) "task_struct")
              ((and (consp root) (eq (first root) :var))
               (cdr (assoc (second root) known-types :test #'string=))))))
      (unless root-struct (return-from field-chain-leaf-struct nil))
      (let* ((vmbtf (ignore-errors (whistler:ensure-vmlinux-btf)))
             (current-tid (and vmbtf
                               (whistler:btf-find-struct vmbtf root-struct))))
        (unless current-tid (return-from field-chain-leaf-struct nil))
        (loop for (fname . rest) on names
              for is-leaf = (null rest)
              do (let* ((fields (whistler:btf-struct-fields vmbtf current-tid))
                        (cell   (find fname fields :test #'string= :key #'first)))
                   (unless cell (return-from field-chain-leaf-struct nil))
                   (let ((bpf-type (second cell))
                         (size     (fourth cell))
                         (sub-name (fifth cell))
                         (sub-tid  (sixth cell)))
                     (cond
                       (is-leaf
                        (when (and (eql size 8) (stringp sub-name)
                                   (string= sub-name "ptr"))
                          (let ((target (whistler:btf-ptr-target-type-id
                                         vmbtf sub-tid)))
                            (return-from field-chain-leaf-struct
                              (and target (whistler:btf-type-name vmbtf target))))))
                       ;; Embedded struct/union — keep walking.
                       ((and (null bpf-type) sub-name
                             (not (and (stringp sub-name)
                                       (string= sub-name "ptr"))))
                        (setf current-tid
                              (or (whistler:btf-member-raw-type-id
                                   vmbtf sub-tid)
                                  sub-tid)))
                       ;; Mid-chain pointer — follow to its target.
                       ((and (eql size 8) (stringp sub-name)
                             (string= sub-name "ptr"))
                        (let ((target (whistler:btf-ptr-target-type-id
                                       vmbtf sub-tid)))
                          (unless target
                            (return-from field-chain-leaf-struct nil))
                          (setf current-tid target)))
                       (t (return-from field-chain-leaf-struct nil)))))
              finally (return nil))))))

(defun infer-var-types (stmts)
  "Walk STMTS and return an alist (VAR-NAME . STRUCT-NAME) recording
   the struct type of each `$v' that was assigned from:
     * `(struct X *)EXPR'                — explicit cast
     * `@m[k]'                            — typed map read
     * `curtask.…' or `$typed.…'         — BTF-resolved field chain
                                           whose leaf is a pointer
     * `$other'                           — another already-typed var
   The chain case is what makes `$dentry = curtask.fs.pwd.dentry; …
   $dentry.d_parent' walk correctly across the `$v = chain; $v.field'
   stash pattern bpftrace scripts lean on."
  (let ((acc nil))
    (labels ((rhs-cast-type (rhs)
               (cond
                 ((not (consp rhs)) nil)
                 ((eq (first rhs) :cast) (getf (cdr rhs) :type))
                 ((eq (first rhs) :field)
                  (or (field-chain-leaf-struct rhs acc)
                      ;; Fallback: if the chain wraps an inner cast we
                      ;; should still see that as the type — preserves
                      ;; the old behaviour for `((struct X *)e).f'.
                      (rhs-cast-type (getf (cdr rhs) :base))))
                 ((eq (first rhs) :map)
                  (let ((info (and *map-table*
                                   (gethash (getf (cdr rhs) :name)
                                            *map-table*))))
                    (and info (minfo-value-struct info))))
                 ((eq (first rhs) :var)
                  (cdr (assoc (second rhs) acc :test #'string=)))
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
                 (:while  (mapc #'walk (getf (cdr s) :body)))
                 (:for    (mapc #'walk (getf (cdr s) :body))))))
      (mapc #'walk stmts))
    acc))

(defun probe-spec-display (spec)
  "User-visible probe name as bpftrace surfaces it: `BEGIN', `END',
   `kprobe:vfs_open', `tracepoint:syscalls:sys_enter_open',
   `uprobe:/lib/libc.so:malloc', etc. Distinct from the internal
   BPF section name (`test_run/begin_1', etc.) which we route to
   the kernel."
  (case (first spec)
    (:begin       "BEGIN")
    (:end         "END")
    (:kprobe      (format nil "kprobe:~A" (second spec)))
    (:kretprobe   (format nil "kretprobe:~A" (second spec)))
    (:kfunc       (format nil "kfunc:~A" (second spec)))
    (:kretfunc    (format nil "kretfunc:~A" (second spec)))
    (:uprobe      (format nil "uprobe:~A:~A" (second spec) (third spec)))
    (:uretprobe   (format nil "uretprobe:~A:~A" (second spec) (third spec)))
    (:tracepoint  (format nil "tracepoint:~A:~A" (second spec) (third spec)))
    (:profile     (format nil "profile:~A:~A" (second spec) (third spec)))
    (:interval    (format nil "interval:~A:~A" (second spec) (third spec)))
    (t            (format nil "~A" (first spec)))))

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
                 (:while  (mapc #'walk (getf (cdr s) :body)))
                 (:for    (mapc #'walk (getf (cdr s) :body))))))
      (mapc #'walk body))
    m))

(defun gen-kernel-prog (spec pred body index sub)
  (multiple-value-bind (ptype section) (spec->section spec)
    (let* ((*probe-spec* spec)
           (*var-types*  (infer-var-types body))
           (*var-ptr-elt-types* (infer-var-ptr-elt-types body))
           (*var-array-types*   (infer-var-array-types body))
           (*ntop-vars*  (infer-ntop-vars body))
           (*comm-vars*  (infer-comm-vars body))
           (*str-vars*   (infer-str-vars body))
           (*tuple-vars* (infer-tuple-vars body))
           (probe-str (probe-spec-display spec))
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
           ;; One shared 8-byte struct-alloc buffer for the scalar key
           ;; passed to map_update_elem from gen-string-set. Lower-stmts
           ;; sets *shared-key-buf-used* when any gen-string-set call
           ;; lowers. Buffer (not u64 var) — see *shared-key-buf*'s
           ;; docstring.
           (*shared-key-buf* (gensym "SHARED-KEY-BUF"))
           (*shared-key-buf-used* nil)
           (*scratch-allocations* nil)
           (*scratch-base-sym* (gensym "BT-SCRATCH-BASE"))
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
                   for str-size = (and as-bt
                                       (cdr (assoc as-bt *str-vars*
                                                   :test #'string-equal)))
                   for array-cell = (and as-bt
                                         (cdr (assoc as-bt *var-array-types*
                                                     :test #'string=)))
                   collect (cond
                             (is-ntop `(,v (whistler::struct-alloc
                                            ,+bt-ntop-slot-size+)))
                             (is-comm `(,v (whistler::struct-alloc
                                            ,+bt-comm-len+)))
                             (str-size `(,v (whistler::struct-alloc
                                             ,str-size)))
                             (array-cell `(,v (whistler::struct-alloc
                                               ,(* (first array-cell)
                                                   (second array-cell)))))
                             (t `(,v 0)))))
           ;; Prepend the shared key buffer (struct-alloc 8) if any
           ;; gen-string-set call elected to reuse it. *string-set-buf*
           ;; goes in AFTER this, so it binds FIRST in let* order — the
           ;; large *string-set-buf* alloc gets rewritten to live in
           ;; per-CPU scratch (BT-SCRATCH-BASE + offset), and we need
           ;; that scratch-base value to settle into a stable vreg
           ;; before the smaller SHARED-KEY-BUF stack alloc starts
           ;; clobbering R1. If we bound SHARED-KEY-BUF first, the
           ;; struct-alloc 8 register sequence drops the scratch base
           ;; before *string-set-buf* could capture it, and downstream
           ;; STRBUF references collapse onto SHARED-KEY-BUF's stack
           ;; slot (BPF verifier rejects: "invalid write to stack").
           (var-inits (if *shared-key-buf-used*
                          (cons `(,*shared-key-buf*
                                  (whistler::struct-alloc 8))
                                var-inits)
                          var-inits))
           ;; Prepend the shared string buffer to the bindings if used.
           (var-inits (if *string-set-buf*
                          (cons `(,*string-set-buf*
                                  (whistler::struct-alloc
                                   ,*string-set-buf-size*))
                                var-inits)
                          var-inits))
           ;; Spill large struct-allocs to the per-CPU scratch map.
           ;; rewrite traverses everything we've already lowered (body
           ;; AND var-inits), pulling alloc sites into
           ;; *scratch-allocations*; we then assign each a fixed
           ;; offset within the per-CPU buffer and wrap the body in
           ;; a let* that pins the map-lookup result. The whole
           ;; gated body is wrapped in a single when-let so a NULL
           ;; lookup (verifier wants us to handle it; per-CPU array
           ;; key=0 can't actually fail) short-circuits cleanly.
           (var-inits  (rewrite-large-struct-allocs var-inits))
           (gated      (rewrite-large-struct-allocs gated)))
      (multiple-value-bind (offsets total)
          (assign-scratch-offsets *scratch-allocations*)
        (setf var-inits (substitute-scratch-offsets var-inits offsets))
        (setf gated     (substitute-scratch-offsets gated     offsets))
        (when (plusp total)
          (setf *max-scratch-bytes* (max *max-scratch-bytes* total)))
        (let* ((with-vars (if var-inits
                              `((let* ,var-inits ,@gated 0))
                              (append gated '(0))))
               (with-scratch
                 (cond
                   ((zerop total) with-vars)
                   (t `((whistler:when-let
                            ((,*scratch-base-sym*
                              (whistler::map-lookup ,*bt-scratch-map-name* 0)))
                          ,@with-vars))))))
          `(whistler:defprog ,prog-name
               (:type ,ptype :section ,section :license "GPL")
             ,@with-scratch))))))

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
   — printf / print / clear / zero / time / cat / system / errorf /
   warnf / join / strftime. All of these route through the same
   ringbuf, so any of them gates injection of the bt-print map.
   Walks user-defined macros / functions too — `macro x() { printf … }'
   called from a probe still needs the bt-print map injected."
  (labels ((walk (form)
             (cond
               ((not (consp form)) nil)
               ((and (eq (first form) :call)
                     (member (getf (cdr form) :name)
                             '("printf" "print" "clear" "zero" "time"
                               "cat" "system" "errorf" "warnf" "join"
                               "strftime")
                             :test #'string=))
                t)
               (t (some #'walk form)))))
    (or (some (lambda (probe) (walk (getf (cdr probe) :body)))
              (script-probes script))
        (some (lambda (form)
                (and (consp form)
                     (member (first form) '(:function :macro))
                     (walk (getf (cdr form) :body))))
              (rest script)))))

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
  (let* ((*tp-format-unreadable-paths* nil)
         (*tp-field-sizes* (load-tracepoint-field-sizes script))
         ;; Honor `config = { max_strlen = N }' for the duration of
         ;; this generate(). Reverts when the let* unwinds.
         (+bt-str-default-len+
           (script-config-int "max_strlen" +bt-str-default-len+))
         ;; `config = { on_stack_limit = N }' — overrides the
         ;; struct-alloc → scratch spill threshold.
         (+bt-scratch-threshold+
           (script-config-int "on_stack_limit" +bt-scratch-threshold+))
         (*test-run-counter* 0)
         (*printf-table* nil)
         (*printf-id-counter* 0)
         (*time-format-table* nil)
         (*cat-paths-table* nil)
         (*system-cmds-table* nil)
         (*map-id-table* nil)
         (*max-scratch-bytes* 0)
         ;; Fold `comm()' / `pid()' / etc. → bare builtins BEFORE the
         ;; rest of the pipeline runs, so downstream code only ever
         ;; sees the canonical AST shape.
         (script    (fold-stdlib-aliases-script script))
         ;; Resolve getopt(name, string-default) calls against
         ;; *named-params* BEFORE tuple expansion / map inference so
         ;; the resulting :str literals flow through the regular
         ;; rewrite-self-refs + lower-assign paths just like any
         ;; other string literal.
         (script    (fold-getopt-script script))
         ;; Expand tuple-var references BEFORE infer-maps so the map's
         ;; key-size lands at the composite total, not at 8 (the size
         ;; of the var alias). expand-tuple-vars-script rewrites
         ;; macro bodies too, so *user-functions* below picks up the
         ;; tuple-expanded versions.
         (script    (expand-tuple-vars-script script))
         (*user-functions* (loop for fn in (script-functions script)
                                 collect (cons (getf (cdr fn) :name)
                                               (cdr fn))))
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
         ;; For every @m that `len(@m)' touches, emit a single-entry
         ;; percpu-array sidecar named `__len_<map>'. The kernel-side
         ;; update/delete sites incf/decf this counter; len(@m) reads
         ;; it.
         (len-counter-map-forms
           (loop for info being the hash-values of map-table
                 when (minfo-needs-len-counter-p info)
                   collect `(whistler:defmap ,(len-counter-sym info)
                              :type :percpu-array
                              :key-size 4 :value-size 8
                              :max-entries 1)))
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
    ;; Per-CPU scratch map (auto-defined when any probe spilled a
    ;; struct-alloc above +bt-scratch-threshold+ to it). Sized to
    ;; the largest per-probe footprint — probes that need less just
    ;; use a prefix of the buffer.
    (let ((scratch-map-form
            (when (plusp *max-scratch-bytes*)
              `(whistler:defmap ,*bt-scratch-map-name*
                 :type :percpu-array
                 :key-size 4
                 :value-size ,*max-scratch-bytes*
                 :max-entries 1))))
    (list :maps (append (when exit-map-form    (list exit-map-form))
                        (when print-map-form   (list print-map-form))
                        (when stacks-map-form  (list stacks-map-form))
                        (when elapsed-map-form (list elapsed-map-form))
                        (when scratch-map-form (list scratch-map-form))
                        len-counter-map-forms
                        maps)
          :progs (append tp-preamble probes)
          :user-probes user
          :config *script-config*
          :exit-map (when uses-exit *exit-map-name*)
          :print-map (when uses-printf *print-map-name*)
          :stacks-map (when uses-kstack *stacks-map-name*)
          :elapsed-map (when uses-elapsed *elapsed-map-name*)
          :stack-depth +bt-stack-depth+
          :printf-table (reverse *printf-table*)
          :time-format-table (reverse *time-format-table*)
          :cat-paths-table (reverse *cat-paths-table*)
          :system-cmds-table (reverse *system-cmds-table*)
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
                                    :key-array-elt-size (minfo-key-array-elt-size info)
                                    :key-array-len (minfo-key-array-len info)
                                    :keyed-p (minfo-keyed-p info)
                                    :value-size (minfo-value-size info)
                                    :max-entries (minfo-max-entries info)
                                    :hist-params (minfo-hist-params info)))))))
