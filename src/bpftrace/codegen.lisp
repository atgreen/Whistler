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
    (:comm    16)
    (:kstack  4)
    (:ustack  4)
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
   (OFFSET SIZE TYPE-SYM EXPR) — SIZE is 8 for plain values, 16 for
   `comm' (the only string-typed key today; the kernel fills the 16
   bytes via bpf_get_current_comm)."
  (let ((u64 (size->type 8))
        (u8  (size->type 1))
        (offset 0))
    (values
     (loop for e in keys
           for size = (if (eq (first e) :comm) +bt-comm-len+ 8)
           for type = (if (eq (first e) :comm) u8 u64)
           collect (list offset size type e)
           do (incf offset size))
     offset)))

(defun key-hint (expr)
  (case (first expr)
    (:builtin (second expr))
    (:arg     :arg)
    (:retval  :retval)
    (:comm    :comm)
    (:kstack  :kstack)
    (:ustack  :ustack)
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
                   ;; A single non-:comm key follows with-key's scalar
                   ;; path — the lowering stores it at its natural
                   ;; width via map-update (`expr-size'). Composite
                   ;; (or :comm) keys go through the struct-key path
                   ;; where every slot is u64, so use the layout total.
                   (let ((total
                           (if (and (= (length keys) 1)
                                    (not (eq (first (first keys)) :comm)))
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
(defvar *map-table* nil)

(defun lower-expr (expr)
  (ecase (first expr)
    (:int        (second expr))
    (:str        (second expr))
    (:var        (var-sym (second expr)))
    (:builtin    (lower-builtin (second expr)))
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
  "Hidden ringbuf map used to ferry kernel-side `async actions' back
   to the userspace runtime: printf, print(@m), clear(@m), time, etc.
   Every record starts with the same 8-byte header — a u32 tag and
   a u32 id — so a single ring consumer can dispatch all of them.")

(defparameter *stacks-map-name* (intern "--BT-STACKS--" :whistler)
  "Hidden BPF_MAP_TYPE_STACK_TRACE map. Each entry is an array of
   u64 instruction pointers — the kernel stack at the moment
   `kstack' fired. Looked up by stack-id (u32) at print time.")

(defconstant +bt-stack-depth+ 32
  "Frames captured per kstack entry. Value-size = 8 * depth = 256.")

;;; Tag values must match those decoded in runtime.lisp.
(defconstant +bt-tag-printf+    0)
(defconstant +bt-tag-print-map+ 1)
(defconstant +bt-tag-clear-map+ 2)
(defconstant +bt-tag-time+      3)

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
      ((string= name "delete") 0)           ; lower-expr-stmt handles the real call
      ((string= name "reg")    (lower-reg-call (getf (cdr expr) :args)))
      (t (unsupported "function ~A" name)))))

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

(defun lower-async-time (args)
  "Emit a tagged ringbuf record asking userspace to stamp the current
   wall-clock time. bpftrace's time() takes an optional strftime
   format; Phase 3 emits the time only and lets userspace use a
   sensible default."
  (when args
    (unsupported "time() format strings — Phase 3 ships time() bare"))
  (let ((rec (gensym "REC")))
    `(whistler:with-ringbuf (,rec ,*print-map-name* 8)
       (whistler::store ,(intern "U32" :whistler) ,rec 0 ,+bt-tag-time+)
       (whistler::store ,(intern "U32" :whistler) ,rec 4 0))))

(defconstant +bt-comm-len+ 16
  "Bytes of `comm' the kernel writes via bpf_get_current_comm.")

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
     :usym                 16 bytes, pid_tgid + user address (symbolizer)"
  (cond
    ((eq (first expr) :comm)
     (cons :string +bt-comm-len+))
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
    (t :int)))

(defun ntop-arg-type (expr)
  "Decide whether an ntop(...) call produces an IPv4 (4-byte) or
   IPv6 (16-byte) slot. Single-arg form is always v4. Two-arg form
   inspects the family literal (AF_INET=2, AF_INET6=10)."
  (let* ((args (getf (cdr expr) :args))
         (af   (when (and (cdr args) (eq (first (first args)) :int))
                 (second (first args)))))
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
    ((and (consp arg-type) (eq (car arg-type) :string)) (cdr arg-type))
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
    ((eq ty :ipv6)
     ;; 16 bytes copied from a pointer in user/kernel memory.
     (let* ((args (getf (cdr arg) :args))
            (ptr  (lower-expr (second args))))
       `(whistler::probe-read-kernel (+ ,rec ,off) 16 ,ptr)))
    ((and (consp ty) (eq (car ty) :string))
     (let ((size (cdr ty)))
       (cond
         ((eq (first arg) :comm)
          `(whistler::get-current-comm (+ ,rec ,off) ,size))
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
          (lower-printf-string-literal rec off (second arg) size)))))))

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
      (t (unsupported "field access .~A on non-args expressions" name)))))

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
   value. `comm' uses bpf_get_current_comm; everything else is a plain
   store of the lowered expression."
  (if (eq (first expr) :comm)
      `(whistler::get-current-comm (+ ,buf ,offset) ,+bt-comm-len+)
      `(whistler::store ,type ,buf ,offset ,(lower-expr expr))))

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
          (not (eq (first (first keys)) :comm)))
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
           (t (gen-scalar-set mname keys (lower-expr rhs) op)))))
      (t (gen-scalar-set mname keys (lower-expr rhs) op)))))

(defun gen-sum-update (mname keys value-form)
  "sum(x): incf the percpu-hash entry by x. The per-CPU storage means
   each CPU has its own bucket — no atomics needed."
  (with-key keys
    (lambda (k)
      `(whistler:incf (whistler:getmap ,mname ,k) ,value-form))))

(defun keys-need-ptr-ops-p (keys)
  "T iff the keys form requires the kernel -ptr map ops (whistler's
   struct-key path). Triggered by composite keys or a single `comm'
   key — both produce a stack buffer pointer rather than a u64."
  (or (> (length keys) 1)
      (and (= (length keys) 1)
           (eq (first (first keys)) :comm))))

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
       (let* ((arg (first (getf (cdr e) :args)))
              (info (or (gethash (or (getf (cdr arg) :name) "@") *map-table*)
                        (error "internal: delete of unknown @map")))
              (mname (minfo-name info)))
         (with-key (getf (cdr arg) :keys)
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
    (:kprobe     (values :kprobe       (format nil "kprobe/~A" (second spec))))
    (:kretprobe  (values :kretprobe    (format nil "kretprobe/~A" (second spec))))
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
  "Walk FORM (an AST). Inside printf calls, rewrite (:PROBE-NAME) and
   (:FUNC) to (:str ...) so they flow through the printf string-slot
   path. Outside printf they stay as the original builtin nodes —
   using them as a map key, predicate, or arithmetic operand isn't
   supported yet (only string-typed printf args). lower-expr's existing
   :probe-name/:func handlers raise BPFTRACE-UNSUPPORTED for those."
  (labels ((rewrite-printf-arg (arg)
             (cond
               ((not (consp arg)) arg)
               ((and (eq (first arg) :probe-name) (null (rest arg)))
                (list :str probe-string))
               ((and (eq (first arg) :func) (null (rest arg)))
                (cond
                  (func-string (list :str func-string))
                  (t (unsupported "`func' is undefined for this probe type"))))
               ;; Recurse so nested cases (e.g. ksym(reg("ip")) is fine,
               ;; though there's no nested probe/func use case we know
               ;; of) still get processed.
               (t (cons (rewrite-printf-arg (first arg))
                        (rewrite-printf-arg (rest arg))))))
           (walk (f)
             (cond
               ((not (consp f)) f)
               ;; printf(... fmt, args ...) — rewrite each arg only.
               ((and (eq (first f) :call)
                     (let ((n (getf (cdr f) :name)))
                       (and (stringp n) (string= n "printf"))))
                (let* ((args   (getf (cdr f) :args))
                       (new    (mapcar #'rewrite-printf-arg args)))
                  (list :call :name "printf" :args new)))
               (t (cons (walk (first f)) (walk (rest f)))))))
    (walk form)))

(defun gen-kernel-prog (spec pred body index sub)
  (multiple-value-bind (ptype section) (spec->section spec)
    (let* ((*probe-spec* spec)
           (probe-str (format nil "~A" section))
           (func-str  (probe-func-name spec))
           (body      (rewrite-self-refs body probe-str func-str))
           (pred      (when pred (rewrite-self-refs pred probe-str func-str)))
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
          (rest script))))

(defun script-uses-kstack-p (script)
  "T iff `kstack' or `ustack' appears anywhere — gates injection of
   the hidden bt-stacks stack-trace map (shared by both)."
  (labels ((walk (form)
             (cond
               ((not (consp form)) nil)
               ((or (eq (first form) :kstack) (eq (first form) :ustack)) t)
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
         (*map-id-table* nil)
         (map-table (infer-maps script))
         (*map-table* map-table)
         (maps      (loop for info being the hash-values of map-table
                          collect (gen-defmap info)))
         (uses-exit (script-uses-exit-p script))
         (uses-printf (script-uses-printf-p script))
         (uses-kstack (script-uses-kstack-p script))
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
         (probes    nil)
         (user      nil)
         (tp-preamble (gen-deftracepoint-preamble script)))
    (loop for probe in (rest script)
          for i from 0
          do (multiple-value-bind (kforms us) (gen-probe-forms probe i)
               (setf probes (append probes kforms)
                     user   (append user us))))
    (list :maps (append (when exit-map-form    (list exit-map-form))
                        (when print-map-form   (list print-map-form))
                        (when stacks-map-form  (list stacks-map-form))
                        maps)
          :progs (append tp-preamble probes)
          :user-probes user
          :exit-map (when uses-exit *exit-map-name*)
          :print-map (when uses-printf *print-map-name*)
          :stacks-map (when uses-kstack *stacks-map-name*)
          :stack-depth +bt-stack-depth+
          :printf-table (reverse *printf-table*)
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
