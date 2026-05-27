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
  kind             ; :counter | :scalar | :hist
  key-size         ; bytes (set by inference; 0 if scalar-only)
  value-size       ; bytes
  max-entries
  key-builtin      ; hint for printing; :pid / :arg / NIL
  keyed-p)         ; T iff any access used [keys]. Scalar-only `@m =`
                   ;   maps stay NIL so the printer skips the `[…]`.

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
   build *TP-FIELD-SIZES*. Skips silently if a format file can't be
   read — the caller falls back to a default size."
  (let ((table (make-hash-table :test 'equal)))
    (dolist (probe (rest script))
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
                (destructuring-bind (c-name _off size _signed _array) field
                  (declare (ignore _off _signed _array))
                  (setf (gethash c-name table) size))))))))
    table))

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
    (:field
     (let ((name (getf (cdr expr) :name)))
       (cond
         ;; tracepoint args->FIELD: look up the real size from the
         ;; tracefs format file we parsed in load-tracepoint-field-sizes.
         ((and (consp (getf (cdr expr) :base))
               (eq (first (getf (cdr expr) :base)) :args)
               *tp-field-sizes*
               (gethash name *tp-field-sizes*)))
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
   (OFFSET 8 U64-TYPE-SYM EXPR)."
  (let ((u64 (size->type 8)))
    (values (loop for e in keys
                  for offset from 0 by 8
                  collect (list offset 8 u64 e))
            (* 8 (length keys)))))

(defun key-hint (expr)
  (case (first expr)
    (:builtin (second expr))
    (:arg     :arg)
    (:retval  :retval)
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
                   (multiple-value-bind (_layout total)
                       (composite-key-layout keys)
                     (declare (ignore _layout))
                     (setf (minfo-key-size info)
                           (max (minfo-key-size info) total)))
                   (when (and (null (minfo-key-builtin info))
                              (= (length keys) 1))
                     (setf (minfo-key-builtin info) (key-hint (first keys)))))))
             (note-rhs (mref rhs)
               (let ((info (ensure mref)))
                 (cond
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
                         (setf (minfo-kind info) :hist
                               (minfo-key-size info) 4
                               (minfo-max-entries info) 256)))))
                   (t (when (eq (minfo-kind info) :counter)
                        (setf (minfo-kind info) :scalar)))))))
      (dolist (probe (rest script))
        (let ((body (getf (cdr probe) :body))
              (pred (getf (cdr probe) :predicate)))
          (when pred (when (eq (first pred) :map) (note-keys pred)))
          (dolist (stmt body)
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
                            (or (string= (getf (cdr e) :name) "delete")
                                (string= (getf (cdr e) :name) "clear")
                                (string= (getf (cdr e) :name) "zero"))
                            (consp (first (getf (cdr e) :args)))
                            (eq (first (first (getf (cdr e) :args))) :map))
                   (note-keys (first (getf (cdr e) :args))))))))))
      ;; Histogram maps with no explicit user key always have 4-byte key.
      (loop for info being the hash-values of table
            when (eq (minfo-kind info) :hist)
              do (setf (minfo-key-size info) 4))
      table)))

;;; ========== Defmap forms ==========

(defun gen-defmap (info)
  (let ((mtype (case (minfo-kind info)
                 (:hist :percpu-array)
                 (t     :hash))))
    `(whistler:defmap ,(minfo-name info)
       :type ,mtype
       :key-size ,(if (eq mtype :percpu-array) 4 (max 1 (minfo-key-size info)))
       :value-size ,(minfo-value-size info)
       :max-entries ,(or (minfo-max-entries info)
                         (if (eq mtype :percpu-array) 64 1024)))))

;;; ========== Expression lowering ==========

(defvar *probe-spec* nil)
(defvar *map-table* nil)

(defun lower-expr (expr)
  (ecase (first expr)
    (:int        (second expr))
    (:str        (second expr))
    (:var        (var-sym (second expr)))
    (:builtin    (lower-builtin (second expr)))
    (:arg        (lower-arg (second expr)))
    (:retval     (lower-retval))
    (:comm       (unsupported "comm in expression position"))
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

(defun lower-builtin (kw)
  (case kw
    (:pid    `(whistler::ash (whistler::get-current-pid-tgid) -32))
    (:tid    `(whistler::logand (whistler::get-current-pid-tgid) #xffffffff))
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
    (t       (unsupported "builtin ~A" kw))))

(defun lower-arg (n)
  (ecase (first *probe-spec*)
    (:kprobe
     (case n
       (0 '(whistler:pt-regs-parm1)) (1 '(whistler:pt-regs-parm2))
       (2 '(whistler:pt-regs-parm3)) (3 '(whistler:pt-regs-parm4))
       (4 '(whistler:pt-regs-parm5)) (5 '(whistler:pt-regs-parm6))
       (t (unsupported "arg~D — only arg0..arg5 are wired up" n))))
    (:kretprobe (unsupported "arg~D in kretprobe — retval is the only accessor" n))
    (:tracepoint (unsupported "tracepoint arg~D — use args->field" n))))

(defun lower-retval ()
  (ecase (first *probe-spec*)
    (:kretprobe '(whistler:pt-regs-ret))))

(defun lower-bin (expr)
  (let ((op  (getf (cdr expr) :op))
        (lhs (lower-expr (getf (cdr expr) :lhs)))
        (rhs (lower-expr (getf (cdr expr) :rhs))))
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
      (:>>   `(whistler::>> ,lhs ,rhs)))))

(defun lower-un (expr)
  (let ((op  (getf (cdr expr) :op))
        (arg (lower-expr (getf (cdr expr) :arg))))
    (ecase op
      (:!  `(whistler::if ,arg 0 1))
      (:-  `(whistler::- 0 ,arg))
      (:~  `(whistler::logxor ,arg #xffffffffffffffff)))))

(defun lower-tern (expr)
  `(whistler::if ,(lower-expr (getf (cdr expr) :cond))
                      ,(lower-expr (getf (cdr expr) :then))
                      ,(lower-expr (getf (cdr expr) :else))))

(defparameter *exit-map-name* (intern "--BT-EXIT--" :whistler)
  "Hidden array map used as a kernel→user `exit()` flag.")

(defparameter *print-map-name* (intern "--BT-PRINT--" :whistler)
  "Hidden ringbuf map used to ferry kernel-side printf records back
   to the userspace runtime, which formats and writes them to stdout.")

(defvar *printf-table* nil
  "Per-generate() list of (ID . (FMT-STRING ARG-COUNT)) entries. The
   runtime gets this verbatim and uses ID to recover the format
   string when it pops a record off the ringbuf.")

(defvar *printf-id-counter* 0
  "Per-generate() counter for unique printf event IDs.")

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
      ((string= name "clear") 0)
      ((string= name "zero")  0)
      ((string= name "delete") 0)           ; lower-expr-stmt handles the real call
      (t (unsupported "function ~A" name)))))

(defun lower-printf (args)
  "Lower a bpftrace `printf(\"FMT\", arg1, …)` to a ringbuf-submit.

   Layout of each record:
     offset 0:  u32 event-id  (index into the printf-table)
     offset 4:  u32 nargs     (echoed for the userspace decoder's sanity)
     offset 8+: u64 args …    (every arg widened to 64 bits)

   At codegen time we register (id . (fmt-string nargs)) in
   *PRINTF-TABLE*, which the runtime gets via :printf-table in the
   generate() plist. At runtime, a ring-consumer reads each record,
   recovers the format string by ID, and printf-formats to stdout."
  (unless args
    (unsupported "printf() with no format string"))
  (let ((fmt (first args)))
    (unless (eq (first fmt) :str)
      (unsupported "printf() format must be a string literal"))
    (let* ((fmt-str (second fmt))
           (extra-args (rest args))
           (nargs (length extra-args))
           (id (incf *printf-id-counter*))
           (size (+ 8 (* 8 nargs)))
           (rec (gensym "REC")))
      (push (list id fmt-str nargs) *printf-table*)
      `(whistler:with-ringbuf (,rec ,*print-map-name* ,size)
         (whistler::store ,(intern "U32" :whistler) ,rec 0 ,id)
         (whistler::store ,(intern "U32" :whistler) ,rec 4 ,nargs)
         ,@(loop for a in extra-args
                 for off from 8 by 8
                 collect `(whistler::store ,(intern "U64" :whistler)
                                           ,rec ,off ,(lower-expr a)))))))

(defun lower-field (expr)
  (let ((base (getf (cdr expr) :base))
        (name (getf (cdr expr) :name)))
    (cond
      ((and (consp base) (eq (first base) :args))
       (list (w-sym (concatenate 'string "tp-" name))))
      (t (unsupported "field access .~A on non-args expressions" name)))))

(defun with-key (keys body-fn)
  "Run BODY-FN with the form to use as a map key. For scalar (zero or
   one component) keys, BODY-FN gets the bare integer expression. For
   composite keys, wraps the call in a let* that allocates a stack
   buffer, stores each component at its layout offset, and passes the
   buffer pointer symbol to BODY-FN. The map's declared :key-size (>8
   for composites) triggers whistler's auto-dispatch to -ptr ops."
  (cond
    ((null keys)         (funcall body-fn 0))
    ((= (length keys) 1) (funcall body-fn (lower-expr (first keys))))
    (t
     (multiple-value-bind (layout total) (composite-key-layout keys)
       (let ((k (gensym "K")))
         `(let* ((,k ,(intern "U64" :whistler)
                  (whistler::struct-alloc ,total)))
            ,@(loop for entry in layout
                    for (offset _size type expr) = entry
                    collect `(whistler::store ,type ,k ,offset
                                              ,(lower-expr expr)))
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

(defun lower-stmt (stmt)
  (ecase (first stmt)
    (:if      (lower-if stmt))
    (:assign  (lower-assign stmt))
    (:incdec  (lower-incdec stmt))
    (:expr    (lower-expr-stmt stmt))))

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
         (ecase op
           (:=  `(setf ,sym ,(lower-expr rhs)))
           (:+= `(whistler:incf ,sym ,(lower-expr rhs)))
           (:-= `(whistler:decf ,sym ,(lower-expr rhs))))))
      (:map (lower-map-assign lhs op rhs)))))

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
           ((string= fn "hist")
            (when (rest keys)
              (unsupported "@m[k1,…] = hist(x) — per-key histograms not yet supported"))
            (gen-hist-update mname (lower-expr (first (getf (cdr rhs) :args)))))
           ((string= fn "lhist")
            (unsupported "lhist() — Phase 1 ships hist() only"))
           (t (gen-scalar-set mname keys (lower-expr rhs) op)))))
      (t (gen-scalar-set mname keys (lower-expr rhs) op)))))

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
       (let* ((arg (first (getf (cdr e) :args)))
              (info (or (gethash (or (getf (cdr arg) :name) "@") *map-table*)
                        (error "internal: delete of unknown @map")))
              (mname (minfo-name info)))
         (with-key (getf (cdr arg) :keys)
           (lambda (k) `(whistler:remmap ,mname ,k)))))
      ;; clear/zero/time are userspace-only — kernel side is a no-op.
      ;; (exit and printf are intentionally NOT in this list so lower-call
      ;; handles them: exit sets the bt-exit flag, printf becomes a
      ;; bpf_trace_printk to /sys/kernel/tracing/trace_pipe.)
      ((and (consp e) (eq (first e) :call)
            (member (getf (cdr e) :name)
                    '("clear" "zero" "time")
                    :test #'string=))
       0)
      (t (lower-expr e)))))

;;; ========== Probe lowering ==========

(defparameter *kernel-spec-tags* '(:kprobe :kretprobe :tracepoint :begin :end))

(defun spec->section (spec)
  (ecase (first spec)
    (:kprobe     (values :kprobe       (format nil "kprobe/~A" (second spec))))
    (:kretprobe  (values :kretprobe    (format nil "kretprobe/~A" (second spec))))
    (:tracepoint (values :tracepoint
                         (format nil "tracepoint/~A/~A" (second spec) (third spec))))
    ;; BEGIN/END compile to SYSCALL programs invoked once via
    ;; BPF_PROG_TEST_RUN. The "test_run/" prefix flags them so the
    ;; runtime skips the attach path.
    (:begin      (values :kprobe (format nil "test_run/begin_~D"
                                         (incf *test-run-counter*))))
    (:end        (values :kprobe (format nil "test_run/end_~D"
                                         (incf *test-run-counter*))))))

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

(defun gen-kernel-prog (spec pred body index sub)
  (multiple-value-bind (ptype section) (spec->section spec)
    (let* ((*probe-spec* spec)
           (prog-name (intern (format nil "BT-PROBE-~D-~D" index sub) :whistler))
           (vars      (collect-vars body))
           (body-forms (lower-stmts body))
           (pred-form (when pred (lower-expr pred)))
           (gated (if pred-form
                      `((when ,pred-form ,@body-forms))
                      body-forms))
           (with-vars (if vars
                          `((let* ,(loop for v in vars collect `(,v 0))
                              ,@gated 0))
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
      (dolist (probe (rest script))
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
          (rest script))))

(defun script-uses-printf-p (script)
  "T iff the script calls printf() anywhere — used to decide whether
   to inject the hidden bt-print ringbuf map."
  (labels ((walk (form)
             (cond
               ((not (consp form)) nil)
               ((and (eq (first form) :call)
                     (string= (getf (cdr form) :name) "printf"))
                t)
               (t (some #'walk form)))))
    (some (lambda (probe) (walk (getf (cdr probe) :body)))
          (rest script))))

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
         (map-table (infer-maps script))
         (*map-table* map-table)
         (maps      (loop for info being the hash-values of map-table
                          collect (gen-defmap info)))
         (uses-exit (script-uses-exit-p script))
         (uses-printf (script-uses-printf-p script))
         (exit-map-form
           (when uses-exit
             `(whistler:defmap ,*exit-map-name*
                :type :array :key-size 4 :value-size 1 :max-entries 1)))
         (print-map-form
           (when uses-printf
             ;; max-entries = ringbuf byte capacity (must be a power
             ;; of two ≥ page size). 256 KiB is plenty for one-liners
             ;; and biolatency-class banners.
             `(whistler:defmap ,*print-map-name*
                :type :ringbuf :max-entries 262144)))
         (probes    nil)
         (user      nil)
         (tp-preamble (gen-deftracepoint-preamble script)))
    (loop for probe in (rest script)
          for i from 0
          do (multiple-value-bind (kforms us) (gen-probe-forms probe i)
               (setf probes (append probes kforms)
                     user   (append user us))))
    (list :maps (append (when exit-map-form  (list exit-map-form))
                        (when print-map-form (list print-map-form))
                        maps)
          :progs (append tp-preamble probes)
          :user-probes user
          :exit-map (when uses-exit *exit-map-name*)
          :print-map (when uses-printf *print-map-name*)
          :printf-table (reverse *printf-table*)
          :info (loop for raw being the hash-keys of map-table
                      using (hash-value info)
                      collect (list (or raw "@")
                                    :name (minfo-name info)
                                    :kind (minfo-kind info)
                                    :key-builtin (minfo-key-builtin info)
                                    :key-size (minfo-key-size info)
                                    :key-parts (if (> (minfo-key-size info) 8)
                                                   (/ (minfo-key-size info) 8)
                                                   1)
                                    :keyed-p (minfo-keyed-p info)
                                    :value-size (minfo-value-size info)
                                    :max-entries (minfo-max-entries info))))))
